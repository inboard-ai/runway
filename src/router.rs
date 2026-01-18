//! HTTP routing with matchit.
//!
//! Provides a simple router for registering and dispatching HTTP handlers.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Method, Request};
use crate::config::Config;
use crate::response::HttpResponse;
use crate::Result;

/// Boxed future for async handlers.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Handler context passed to route handlers.
pub struct Context {
    /// The incoming HTTP request.
    pub request: Request<Incoming>,
    /// Route parameters (e.g., {id} from path).
    pub params: HashMap<String, String>,
    /// Database handle (wrapped in Arc for sharing).
    pub db: Arc<libsql::Database>,
    /// Server configuration.
    pub config: Config,
}

impl Context {
    /// Get a route parameter by name.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(|s| s.as_str())
    }

    /// Get a required route parameter, returning BadRequest if missing.
    pub fn require_param(&self, name: &str) -> Result<&str> {
        self.param(name)
            .ok_or_else(|| crate::Error::BadRequest(format!("Missing parameter: {}", name)))
    }

    /// Extract user ID from Authorization header.
    /// Returns None if no valid token is present.
    pub fn user_id(&self) -> Option<String> {
        crate::auth::extract_user_id(&self.request, &self.config.auth).ok()
    }

    /// Require authenticated user, returning Unauthorized if not present.
    pub fn require_user_id(&self) -> Result<String> {
        crate::auth::extract_user_id(&self.request, &self.config.auth)
    }
}

/// Handler function type.
/// Takes a Context and returns a future resolving to a Response.
pub type Handler = Box<dyn Fn(Context) -> BoxFuture<'static, Result<HttpResponse>> + Send + Sync>;

/// A registered route with method-specific handlers.
struct RouteEntry {
    handlers: HashMap<Method, Handler>,
}

/// HTTP router for registering and dispatching requests.
pub struct Router {
    routes: matchit::Router<usize>,
    entries: Vec<RouteEntry>,
}

impl Router {
    /// Create a new router.
    pub fn new() -> Self {
        Self {
            routes: matchit::Router::new(),
            entries: Vec::new(),
        }
    }

    /// Register a handler for a method and path.
    ///
    /// # Example
    /// ```ignore
    /// router.route(Method::GET, "/api/v1/users", |ctx| Box::pin(async move {
    ///     response::ok(&["user1", "user2"])
    /// }));
    /// ```
    pub fn route<F, Fut>(&mut self, method: Method, path: &str, handler: F)
    where
        F: Fn(Context) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HttpResponse>> + Send + 'static,
    {
        // Find or create route entry for this path
        let entry_idx = match self.routes.at(path) {
            Ok(matched) => *matched.value,
            Err(_) => {
                let idx = self.entries.len();
                self.entries.push(RouteEntry {
                    handlers: HashMap::new(),
                });
                self.routes.insert(path, idx).ok();
                idx
            }
        };

        // Add handler for this method
        let boxed: Handler = Box::new(move |ctx| Box::pin(handler(ctx)));
        self.entries[entry_idx].handlers.insert(method, boxed);
    }

    /// Convenience method for GET requests.
    pub fn get<F, Fut>(&mut self, path: &str, handler: F)
    where
        F: Fn(Context) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HttpResponse>> + Send + 'static,
    {
        self.route(Method::GET, path, handler);
    }

    /// Convenience method for POST requests.
    pub fn post<F, Fut>(&mut self, path: &str, handler: F)
    where
        F: Fn(Context) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HttpResponse>> + Send + 'static,
    {
        self.route(Method::POST, path, handler);
    }

    /// Convenience method for PUT requests.
    pub fn put<F, Fut>(&mut self, path: &str, handler: F)
    where
        F: Fn(Context) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HttpResponse>> + Send + 'static,
    {
        self.route(Method::PUT, path, handler);
    }

    /// Convenience method for DELETE requests.
    pub fn delete<F, Fut>(&mut self, path: &str, handler: F)
    where
        F: Fn(Context) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HttpResponse>> + Send + 'static,
    {
        self.route(Method::DELETE, path, handler);
    }

    /// Convenience method for PATCH requests.
    pub fn patch<F, Fut>(&mut self, path: &str, handler: F)
    where
        F: Fn(Context) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HttpResponse>> + Send + 'static,
    {
        self.route(Method::PATCH, path, handler);
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe router handle for use in request handling.
pub struct RouterHandle {
    routes: matchit::Router<usize>,
    entries: Vec<RouteEntry>,
}

impl Router {
    /// Convert to a thread-safe handle for use in request handling.
    pub fn into_handle(self) -> Arc<RouterHandle> {
        Arc::new(RouterHandle {
            routes: self.routes,
            entries: self.entries,
        })
    }
}

/// Result of matching a request to a route.
pub enum RouteMatch<'a> {
    /// Route matched with handler.
    Matched {
        handler: &'a Handler,
        params: HashMap<String, String>,
    },
    /// Path matched but method not allowed.
    MethodNotAllowed,
    /// Path not found.
    NotFound,
}

impl RouterHandle {
    /// Match a request to a route.
    pub fn match_route(&self, method: &Method, path: &str) -> RouteMatch<'_> {
        match self.routes.at(path) {
            Ok(matched) => {
                let entry = &self.entries[*matched.value];

                // Convert params to owned HashMap
                let params: HashMap<String, String> = matched
                    .params
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();

                match entry.handlers.get(method) {
                    Some(handler) => RouteMatch::Matched { handler, params },
                    None => RouteMatch::MethodNotAllowed,
                }
            }
            Err(_) => RouteMatch::NotFound,
        }
    }
}
