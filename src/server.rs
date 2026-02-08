//! HTTP server implementation using hyper.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::db;
use crate::router::{Context, RouteMatch, RouterHandle};

/// Maximum request body size in bytes (1 MB).
const MAX_BODY_SIZE: usize = 1_048_576;

/// Maximum number of concurrent connections.
const MAX_CONNECTIONS: usize = 128;

/// Timeout for reading request headers (slowloris protection).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Shared server state.
pub struct State {
    pub config: Config,
    pub db: Option<db::Handle>,
    pub router: Arc<RouterHandle>,
    pub rate_limiter: Option<Arc<crate::rate_limit::RateLimiter>>,
}

/// Handle to a running server instance.
pub struct Server {
    addr: SocketAddr,
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<crate::Result<()>>,
}

impl Server {
    /// The address the server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Shut down the accept loop and wait for it to finish.
    pub async fn shutdown(self) -> crate::Result<()> {
        let _ = self.shutdown_tx.send(());
        self.task.await.unwrap_or(Ok(()))
    }
}

/// Add security and CORS headers to a response.
fn add_standard_headers(
    response: &mut Response<Full<Bytes>>,
    origin: Option<&str>,
    server_config: &crate::config::Server,
) {
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("Cache-Control", "no-store".parse().unwrap());
    headers.insert(
        "Content-Security-Policy",
        "default-src 'none'".parse().unwrap(),
    );

    // HSTS
    if server_config.hsts {
        headers.insert(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains".parse().unwrap(),
        );
    }

    // CORS
    if let Some(origin) = origin {
        let cors = &server_config.cors_origins;
        if !cors.is_empty() {
            let allowed = cors.iter().any(|o| o == "*") || cors.iter().any(|o| o == origin);

            if allowed {
                headers.insert("Access-Control-Allow-Origin", origin.parse().unwrap());
                headers.insert(
                    "Access-Control-Allow-Methods",
                    "GET, POST, PUT, DELETE, PATCH, OPTIONS".parse().unwrap(),
                );
                headers.insert(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization, X-Request-Id".parse().unwrap(),
                );
                headers.insert("Access-Control-Max-Age", "86400".parse().unwrap());

                // Credentials only when explicitly configured and not wildcard
                if server_config.cors_credentials && !cors.iter().any(|o| o == "*") {
                    headers.insert("Access-Control-Allow-Credentials", "true".parse().unwrap());
                }
            }
        }
    }
}

/// Handle an incoming HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    state: Arc<State>,
    remote_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let start = std::time::Instant::now();
    let (parts, body) = req.into_parts();

    // Generate or propagate request ID
    let request_id = parts
        .headers
        .get("X-Request-Id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| uuid::Uuid::try_parse(s).ok())
        .unwrap_or_else(uuid::Uuid::now_v7);

    // Extract Origin header for CORS before parts are consumed
    let origin = parts
        .headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Rate limiting
    if let Some(ref limiter) = state.rate_limiter {
        let client_ip = parts
            .headers
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
            .unwrap_or_else(|| remote_addr.ip());
        if let Err(retry_after) = limiter.check(client_ip) {
            let mut response = crate::Error::TooManyRequests { retry_after }.into_response();
            response
                .headers_mut()
                .insert("Retry-After", retry_after.to_string().parse().unwrap());
            add_standard_headers(&mut response, origin.as_deref(), &state.config.server());
            response
                .headers_mut()
                .insert("X-Request-Id", request_id.to_string().parse().unwrap());
            return Ok(response);
        }
    }

    // Reject oversized bodies early via Content-Length header
    if let Some(cl) = parts.headers.get(hyper::header::CONTENT_LENGTH) {
        if let Ok(len) = cl.to_str().unwrap_or("0").parse::<usize>() {
            if len > MAX_BODY_SIZE {
                let mut response = Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(r#"{"error":"Payload too large"}"#)))
                    .unwrap();
                add_standard_headers(&mut response, origin.as_deref(), &state.config.server());
                response
                    .headers_mut()
                    .insert("X-Request-Id", request_id.to_string().parse().unwrap());
                return Ok(response);
            }
        }
    }

    // Read body with size limit (fallback for chunked encoding)
    let body_bytes = match BodyExt::collect(Limited::new(body, MAX_BODY_SIZE)).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            let mut response = Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(r#"{"error":"Payload too large"}"#)))
                .unwrap();
            add_standard_headers(&mut response, origin.as_deref(), &state.config.server());
            response
                .headers_mut()
                .insert("X-Request-Id", request_id.to_string().parse().unwrap());
            return Ok(response);
        }
    };

    let method = parts.method.clone();
    let path = parts.uri.path().to_string();

    // Handle OPTIONS preflight
    if method == hyper::Method::OPTIONS {
        let mut response = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Full::new(Bytes::new()))
            .unwrap();
        add_standard_headers(&mut response, origin.as_deref(), &state.config.server());
        response
            .headers_mut()
            .insert("X-Request-Id", request_id.to_string().parse().unwrap());
        let elapsed = start.elapsed();
        info!(
            method = %method,
            path = %path,
            status = 204u16,
            latency_ms = elapsed.as_secs_f64() * 1000.0,
            request_id = %request_id,
            remote_addr = %remote_addr,
            "request completed"
        );
        return Ok(response);
    }

    // Match route
    let mut response = match state.router.match_route(&method, &path) {
        RouteMatch::Matched { handler, params } => {
            let ctx = Context {
                method: parts.method,
                uri: parts.uri,
                headers: parts.headers,
                params,
                body: body_bytes,
                db: state.db.clone(),
                config: state.config.clone(),
                request_id,
                remote_addr,
            };

            // Wrap handler in tokio::spawn to catch panics (F12)
            match tokio::spawn(handler(ctx)).await {
                Ok(Ok(response)) => response,
                Ok(Err(e)) => e.into_response(),
                Err(join_error) => {
                    let panic_msg = if let Ok(reason) = join_error.try_into_panic() {
                        if let Some(s) = reason.downcast_ref::<&str>() {
                            s.to_string()
                        } else if let Some(s) = reason.downcast_ref::<String>() {
                            s.clone()
                        } else {
                            "unknown panic".to_string()
                        }
                    } else {
                        "task cancelled".to_string()
                    };
                    error!(
                        request_id = %request_id,
                        "handler panicked: {panic_msg}"
                    );
                    crate::Error::Internal("handler panicked".to_string()).into_response()
                }
            }
        }
        RouteMatch::MethodNotAllowed => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(r#"{"error":"Method not allowed"}"#)))
            .unwrap(),
        RouteMatch::NotFound => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(r#"{"error":"Not found"}"#)))
            .unwrap(),
    };

    add_standard_headers(&mut response, origin.as_deref(), &state.config.server());
    response
        .headers_mut()
        .insert("X-Request-Id", request_id.to_string().parse().unwrap());
    let elapsed = start.elapsed();
    info!(
        method = %method,
        path = %path,
        status = response.status().as_u16(),
        latency_ms = elapsed.as_secs_f64() * 1000.0,
        request_id = %request_id,
        remote_addr = %remote_addr,
        "request completed"
    );
    Ok(response)
}

/// Bind, start accepting connections, and return a handle.
///
/// The returned [`Server`] exposes the bound address and a
/// [`shutdown`](Server::shutdown) method for graceful termination.
pub async fn start(
    config: Config,
    db: Option<db::Handle>,
    router: Arc<RouterHandle>,
) -> crate::Result<Server> {
    let addr: SocketAddr = format!("{}:{}", config.host(), config.port()).parse()?;
    let listener = TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;

    // Warn if iss/aud are unset (B6)
    crate::auth::warn_missing_claims(&config.auth());

    let drain_timeout_secs = config.server().drain_timeout_secs;

    // Build rate limiter from config (B4)
    let rate_limiter = config.server().rate_limit.as_ref().map(|rl| {
        Arc::new(crate::rate_limit::RateLimiter::new(
            rl.max_requests,
            rl.window_secs,
        ))
    });

    // Spawn periodic cleanup for rate limiter
    if let Some(ref limiter) = rate_limiter {
        let limiter = Arc::clone(limiter);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                limiter.cleanup();
            }
        });
    }

    let state = Arc::new(State {
        config,
        db,
        router,
        rate_limiter,
    });

    info!("Server listening on http://{}", addr);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    let task = tokio::spawn(async move {
        tokio::pin!(shutdown_rx);
        let mut join_set = tokio::task::JoinSet::new();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, remote_addr) = result?;
                    let io = TokioIo::new(stream);

                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let state = Arc::clone(&state);
                            join_set.spawn(async move {
                                let service = service_fn(move |req| {
                                    let state = Arc::clone(&state);
                                    handle_request(req, state, remote_addr)
                                });

                                let mut builder = auto::Builder::new(TokioExecutor::new());
                                builder.http1()
                                    .timer(TokioTimer::new())
                                    .header_read_timeout(HEADER_READ_TIMEOUT);

                                if let Err(e) = builder.serve_connection(io, service).await {
                                    error!("Error serving connection from {}: {}", remote_addr, e);
                                }

                                drop(permit);
                            });
                        }
                        Err(_) => {
                            warn!("Connection limit reached, rejecting {}", remote_addr);
                            join_set.spawn(async move {
                                let service = service_fn(|_req: Request<Incoming>| async {
                                    Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .status(StatusCode::SERVICE_UNAVAILABLE)
                                            .header("Content-Type", "application/json")
                                            .body(Full::new(Bytes::from(
                                                r#"{"error":"Service unavailable"}"#,
                                            )))
                                            .unwrap(),
                                    )
                                });

                                let mut builder = auto::Builder::new(TokioExecutor::new());
                                builder.http1()
                                    .timer(TokioTimer::new())
                                    .header_read_timeout(HEADER_READ_TIMEOUT);

                                let _ = builder.serve_connection(io, service).await;
                            });
                        }
                    }
                }
                // Reap completed tasks from the JoinSet
                Some(result) = join_set.join_next() => {
                    if let Err(e) = result {
                        error!("connection task failed: {e}");
                    }
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }

        // Graceful drain: wait for in-flight tasks to complete (F11)
        let drain_timeout = Duration::from_secs(drain_timeout_secs);
        let drain_result = tokio::time::timeout(drain_timeout, async {
            while let Some(result) = join_set.join_next().await {
                if let Err(e) = result {
                    error!("task failed during drain: {e}");
                }
            }
        })
        .await;

        if drain_result.is_err() {
            warn!("drain timeout reached, aborting remaining tasks");
            join_set.abort_all();
        }

        Ok(())
    });

    Ok(Server {
        addr,
        shutdown_tx,
        task,
    })
}

/// Run the HTTP server.
///
/// Blocks until `ctrl_c` is received, then performs graceful shutdown.
///
/// # Arguments
/// * `config` - Server configuration
/// * `db` - Optional database connection (wrapped in Arc for sharing)
/// * `router` - Router handle with registered routes
pub async fn run(
    config: Config,
    db: Option<db::Handle>,
    router: Arc<RouterHandle>,
) -> crate::Result<()> {
    let server = start(config, db, router).await?;

    // Wait for ctrl_c as default shutdown trigger
    tokio::signal::ctrl_c().await.map_err(crate::Error::Io)?;

    info!("shutdown signal received, draining connections…");
    server.shutdown().await
}
