//! HTTP server implementation using hyper.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::config::Config;
use crate::router::{Context, RouteMatch, RouterHandle};

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

/// Handle an incoming HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    // Read body upfront
    let (parts, body) = req.into_parts();
    let body_bytes = BodyExt::collect(body)
        .await
        .map_err(|_| ())
        .unwrap_or_default()
        .to_bytes();

    let method = &parts.method;
    let path = parts.uri.path().to_string();

    // Match route
    match state.router.match_route(method, &path) {
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
                Ok(response) => Ok(response),
                Err(e) => Ok(e.into_response()),
            }
        }
        RouteMatch::MethodNotAllowed => Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(r#"{"error":"Method not allowed"}"#)))
            .unwrap()),
        RouteMatch::NotFound => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(r#"{"error":"Not found"}"#)))
            .unwrap()),
    }
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

    let task = tokio::spawn(async move {
        tokio::pin!(shutdown_rx);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, remote_addr) = result?;
                    let io = TokioIo::new(stream);
                    let state = Arc::clone(&state);

                    tokio::spawn(async move {
                        let service = service_fn(move |req| {
                            let state = Arc::clone(&state);
                            handle_request(req, state)
                        });

                        if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                            error!("Error serving connection from {}: {}", remote_addr, e);
                        }
                    });
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
