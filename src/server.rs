//! HTTP server implementation using hyper.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::config::Config;
use crate::router::{Context, RouteMatch, RouterHandle};

/// Shared server state.
pub struct State {
    pub config: Config,
    pub db: Option<Arc<libsql::Database>>,
    pub router: Arc<RouterHandle>,
}

/// Handle an incoming HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Match route
    match state.router.match_route(&method, &path) {
        RouteMatch::Matched { handler, params } => {
            let ctx = Context {
                request: req,
                params,
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
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    let state = Arc::new(State { config, db, router });

    info!("Server listening on http://{}", addr);

    loop {
        let (stream, remote_addr) = listener.accept().await?;
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
}
