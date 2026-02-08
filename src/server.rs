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
    pub db: Option<Arc<libsql::Database>>,
    pub router: Arc<RouterHandle>,
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
fn add_standard_headers(response: &mut Response<Full<Bytes>>, origin: Option<&str>) {
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    if let Some(origin) = origin {
        headers.insert(
            "Access-Control-Allow-Origin",
            origin.parse().unwrap(),
        );
    }
}

/// Handle an incoming HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (parts, body) = req.into_parts();

    // Extract Origin header for CORS before parts are consumed
    let origin = parts
        .headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Reject oversized bodies early via Content-Length header
    if let Some(cl) = parts.headers.get(hyper::header::CONTENT_LENGTH) {
        if let Ok(len) = cl.to_str().unwrap_or("0").parse::<usize>() {
            if len > MAX_BODY_SIZE {
                let mut response = Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(
                        r#"{"error":"Payload too large"}"#,
                    )))
                    .unwrap();
                add_standard_headers(&mut response, origin.as_deref());
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
                .body(Full::new(Bytes::from(
                    r#"{"error":"Payload too large"}"#,
                )))
                .unwrap();
            add_standard_headers(&mut response, origin.as_deref());
            return Ok(response);
        }
    };

    let method = &parts.method;
    let path = parts.uri.path().to_string();

    // Match route
    let mut response = match state.router.match_route(method, &path) {
        RouteMatch::Matched { handler, params } => {
            let ctx = Context {
                method: parts.method,
                uri: parts.uri,
                headers: parts.headers,
                params,
                body: body_bytes,
                db: state.db.clone(),
                config: state.config.clone(),
            };

            match handler(ctx).await {
                Ok(response) => response,
                Err(e) => e.into_response(),
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

    add_standard_headers(&mut response, origin.as_deref());
    Ok(response)
}

/// Bind, start accepting connections, and return a handle.
///
/// The returned [`Server`] exposes the bound address and a
/// [`shutdown`](Server::shutdown) method for graceful termination.
pub async fn start(
    config: Config,
    db: Option<Arc<libsql::Database>>,
    router: Arc<RouterHandle>,
) -> crate::Result<Server> {
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;

    let state = Arc::new(State { config, db, router });

    info!("Server listening on http://{}", addr);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    let task = tokio::spawn(async move {
        tokio::pin!(shutdown_rx);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, remote_addr) = result?;
                    let io = TokioIo::new(stream);

                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let state = Arc::clone(&state);
                            tokio::spawn(async move {
                                let service = service_fn(move |req| {
                                    let state = Arc::clone(&state);
                                    handle_request(req, state)
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
                            tokio::spawn(async move {
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
                _ = &mut shutdown_rx => {
                    break;
                }
            }
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
/// # Arguments
/// * `config` - Server configuration
/// * `db` - Optional database connection (wrapped in Arc for sharing)
/// * `router` - Router handle with registered routes
pub async fn run(
    config: Config,
    db: Option<Arc<libsql::Database>>,
    router: Arc<RouterHandle>,
) -> crate::Result<()> {
    let server = start(config, db, router).await?;
    server.task.await.unwrap_or(Ok(()))
}
