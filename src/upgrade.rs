//! WebSocket upgrade types.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::Config;

/// Boxed future for async upgrade handlers.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Context for WebSocket upgrade handlers.
///
/// Similar to [`crate::router::Context`] but without a pre-read body (the
/// connection is being upgraded, not consumed as a normal request).
pub struct Context {
    /// The request URI (includes path and query string).
    pub uri: hyper::Uri,
    /// The request headers.
    pub headers: hyper::http::HeaderMap,
    /// Route parameters (e.g., {id} from path).
    pub params: HashMap<String, String>,
    /// Database handle.
    pub db: Option<crate::db::Handle>,
    /// Server configuration.
    pub config: Config,
    /// Remote address of the connecting client.
    pub remote_addr: std::net::SocketAddr,
}

impl Context {
    /// Get a header value by name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Get a route parameter by name.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(|s| s.as_str())
    }

    /// Get a required route parameter, returning BadRequest if missing.
    pub fn require_param(&self, name: &str) -> crate::Result<&str> {
        self.param(name)
            .ok_or_else(|| crate::Error::BadRequest(format!("Missing parameter: {name}")))
    }

    /// Get the database handle if available.
    pub fn db(&self) -> Option<&crate::db::Handle> {
        self.db.as_ref()
    }

    /// Require database, returning Internal error if not configured.
    pub fn require_db(&self) -> crate::Result<&crate::db::Handle> {
        self.db
            .as_ref()
            .ok_or_else(|| crate::Error::Internal("Database not configured".to_string()))
    }
}

/// Handler for WebSocket upgrade routes.
///
/// Called after the HTTP 101 Switching Protocols response has been sent and the
/// connection has been upgraded. Receives the upgrade context and the raw
/// upgraded connection (wrap with `tokio_tungstenite::WebSocketStream` etc.).
pub type Handler =
    Arc<dyn Fn(Context, hyper::upgrade::Upgraded) -> BoxFuture<'static, ()> + Send + Sync>;
