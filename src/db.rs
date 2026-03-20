//! Database connection abstraction.
//!
//! Re-exports `concourse_db::Handle` as the shared database type across
//! the ecosystem. Provides a `connect()` function that builds the handle
//! from a URL string.

use libsql::Builder;

pub use concourse_db::{Connection, Database, Error as DbError, Handle, Row, Rows, Value, params};

/// Connect to the database.
///
/// # URL formats
/// - Local file: `mydata.db`, `file:path/to/db.sqlite`, `sqlite://path`
/// - In-memory: `:memory:`
/// - Remote Turso: `libsql://your-db.turso.io` (requires `TURSO_AUTH_TOKEN` env var)
pub async fn connect(url: &str) -> crate::Result<Handle> {
    let db = if url.starts_with("libsql://") || url.starts_with("https://") {
        let token = std::env::var("TURSO_AUTH_TOKEN").map_err(|_| {
            crate::Error::Internal("TURSO_AUTH_TOKEN not set for remote database".into())
        })?;
        Builder::new_remote(url.to_string(), token).build().await?
    } else if url == ":memory:" {
        Builder::new_local(":memory:").build().await?
    } else {
        let path = url
            .strip_prefix("sqlite://")
            .or_else(|| url.strip_prefix("file:"))
            .unwrap_or(url);
        Builder::new_local(path).build().await?
    };

    Ok(Handle::new(db))
}
