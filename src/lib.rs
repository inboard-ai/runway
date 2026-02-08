//! Runway - Generic backend server library for modular API services.
//!
//! Runway provides the infrastructure for building modular HTTP API servers:
//!
//! - **Config**: Layered configuration (file → env → CLI)
//! - **Database**: libsql/Turso abstraction supporting local and remote databases
//! - **Auth**: JWT token creation and validation
//! - **Router**: HTTP routing with path parameters
//! - **Server**: Hyper-based HTTP server
//! - **Module**: Trait for pluggable API modules
//!
//! # Example
//!
//! ```ignore
//! use runway::{Config, ConfigLoader, Module, Router};
//!
//! // Define a module
//! struct MyModule;
//!
//! impl Module for MyModule {
//!     fn name(&self) -> &'static str { "my-module" }
//!
//!     fn routes(&self, router: &mut Router) {
//!         router.get("/api/hello", |ctx| async move {
//!             runway::response::ok(&serde_json::json!({ "message": "Hello!" }))
//!         });
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> runway::Result<()> {
//!     // Load config
//!     let loader = ConfigLoader::new("MYAPP");
//!     let config = loader.load(None, None, None, None, Some("secret"))?;
//!
//!     // Connect to database
//!     let db = runway::db::connect(&config.database.url).await?;
//!
//!     // Build router
//!     let mut router = Router::new();
//!     MyModule.routes(&mut router);
//!
//!     // Run server
//!     runway::server::run(config, db, router.into_handle()).await
//! }
//! ```

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod module;
pub mod openapi;
pub mod operation;
pub mod permission;
pub mod procedure;
pub mod rate_limit;
pub mod response;
pub mod router;
pub mod server;

// Re-export main types at crate root
pub use config::{Config, Loader};
pub use db::Handle as DbHandle;
pub use error::{Error, Result};
pub use module::Module;
pub use openapi::Info;
pub use permission::{Level, level};
pub use procedure::{Empty, Meta, Procedure};
pub use router::{Context, Router};

// Re-export commonly used dependencies for convenience
pub use hyper::Method;
pub use serde_json::json;
