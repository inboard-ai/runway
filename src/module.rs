//! Module trait for pluggable API modules.
//!
//! Modules implement the `Module` trait to register their routes with the server.
//!
//! # Example
//!
//! ```ignore
//! use runway::{Module, Router, Result};
//!
//! pub struct HealthModule;
//!
//! impl Module for HealthModule {
//!     fn name(&self) -> &'static str {
//!         "health"
//!     }
//!
//!     fn routes(&self, router: &mut Router) {
//!         router.get("/health", |_ctx| async move {
//!             runway::response::ok(&serde_json::json!({
//!                 "status": "ok"
//!             }))
//!         });
//!     }
//! }
//! ```

use crate::router::Router;

/// A pluggable API module.
///
/// Modules register their routes with the router and can hold their own state.
/// The state is captured in closures when registering routes.
pub trait Module: Send + Sync {
    /// Module name for identification and logging.
    fn name(&self) -> &'static str;

    /// Register routes with the router.
    ///
    /// Modules should register all their routes here. State can be captured
    /// in closures using `Arc` or similar.
    fn routes(&self, router: &mut Router);
}
