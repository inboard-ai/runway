//! Database connection abstraction.
//!
//! Supports multiple backends:
//! - Local SQLite file: `path/to/db.sqlite` or `file:path` or `sqlite://path`
//! - In-memory: `:memory:`
//! - Remote Turso: `libsql://...` or `https://...` (requires TURSO_AUTH_TOKEN env var)

use std::sync::Arc;

use libsql::{Builder, Connection, Database};

/// Shared database handle, cheap to clone.
///
/// Wraps `Arc<Database>` so callers never deal with `Arc` directly.
/// Implements `Deref<Target = Database>` for transparent field access.
#[derive(Clone)]
pub struct Handle(Arc<Database>);

impl Handle {
    /// Get a connection from the database.
    pub fn connect(&self) -> crate::Result<Connection> {
        Ok(self.0.connect()?)
    }
}

impl std::ops::Deref for Handle {
    type Target = Database;
    fn deref(&self) -> &Database {
        &self.0
    }
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Handle").field(&"Database(...)").finish()
    }
}

/// Connect to the database.
///
/// # URL formats
/// - Local file: `mydata.db`, `file:path/to/db.sqlite`, `sqlite://path`
/// - In-memory: `:memory:`
/// - Remote Turso: `libsql://your-db.turso.io` (requires `TURSO_AUTH_TOKEN` env var)
pub async fn connect(url: &str) -> crate::Result<Handle> {
    let db = if url.starts_with("libsql://") || url.starts_with("https://") {
        // Remote Turso database
        let token = std::env::var("TURSO_AUTH_TOKEN").map_err(|_| {
            crate::Error::Internal("TURSO_AUTH_TOKEN not set for remote database".into())
        })?;
        Builder::new_remote(url.to_string(), token).build().await?
    } else if url == ":memory:" {
        // In-memory database
        Builder::new_local(":memory:").build().await?
    } else {
        // Local file - strip sqlite:// or file: prefix if present
        let path = url
            .strip_prefix("sqlite://")
            .or_else(|| url.strip_prefix("file:"))
            .unwrap_or(url);
        Builder::new_local(path).build().await?
    };

    Ok(Handle(Arc::new(db)))
}

// Re-export commonly used libsql types for convenience
pub use libsql::{Connection as DbConnection, Database as Db, Row, params};
