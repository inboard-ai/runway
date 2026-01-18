//! Database connection abstraction.
//!
//! Supports multiple backends:
//! - Local SQLite file: `path/to/db.sqlite` or `file:path` or `sqlite://path`
//! - In-memory: `:memory:`
//! - Remote Turso: `libsql://...` or `https://...` (requires TURSO_AUTH_TOKEN env var)

use libsql::{Builder, Connection, Database};

/// Connect to the database.
///
/// # URL formats
/// - Local file: `mydata.db`, `file:path/to/db.sqlite`, `sqlite://path`
/// - In-memory: `:memory:`
/// - Remote Turso: `libsql://your-db.turso.io` (requires `TURSO_AUTH_TOKEN` env var)
pub async fn connect(url: &str) -> crate::Result<Database> {
    let db = if url.starts_with("libsql://") || url.starts_with("https://") {
        // Remote Turso database
        let token = std::env::var("TURSO_AUTH_TOKEN")
            .map_err(|_| crate::Error::Internal("TURSO_AUTH_TOKEN not set for remote database".into()))?;
        Builder::new_remote(url.to_string(), token)
            .build()
            .await?
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

    Ok(db)
}

/// Get a connection from the database.
pub fn connection(db: &Database) -> crate::Result<Connection> {
    Ok(db.connect()?)
}

// Re-export commonly used libsql types for convenience
pub use libsql::{params, Connection as DbConnection, Database as Db, Row};
