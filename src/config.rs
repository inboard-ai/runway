//! Configuration loading with layered overrides.
//!
//! Config is loaded in order (each layer overrides the previous):
//! 1. Default values
//! 2. Config file (TOML)
//! 3. Environment variables
//! 4. CLI arguments
//!
//! JWT secret is never read from config files for security - it must come from
//! environment variable or CLI argument.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Error;

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Internal {
    #[serde(default)]
    server: Server,
    #[serde(default)]
    database: Database,
    #[serde(default)]
    auth: Auth,
}

impl Internal {
    pub fn server(&self) -> &Server {
        &self.server
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    pub fn auth(&self) -> &Auth {
        &self.auth
    }

    pub fn host(&self) -> &str {
        &self.server.host
    }

    pub fn port(&self) -> u16 {
        self.server.port
    }
}

/// HTTP server settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub hsts: bool,
    #[serde(default)]
    pub cors_origins: Vec<String>,
    #[serde(default)]
    pub cors_credentials: bool,
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            hsts: false,
            cors_origins: Vec::new(),
            cors_credentials: false,
            drain_timeout_secs: default_drain_timeout_secs(),
            rate_limit: None,
        }
    }
}

fn default_drain_timeout_secs() -> u64 {
    30
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

/// Database connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    #[serde(default = "default_database_url")]
    pub url: String,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            url: default_database_url(),
        }
    }
}

fn default_database_url() -> String {
    "data.db".to_string()
}

/// Authentication settings.
#[derive(Clone, Serialize, Deserialize)]
pub struct Auth {
    /// JWT secret for token signing/verification (HS256).
    /// Must be provided via environment variable or CLI - never from config file.
    #[serde(default)]
    pub jwt_secret: String,

    /// Token expiry in days (default: 1).
    #[serde(default = "default_token_expiry_days")]
    pub token_expiry_days: u32,

    /// Token expiry in hours — overrides `token_expiry_days` when set.
    #[serde(default)]
    pub token_expiry_hours: Option<u32>,

    /// JWT issuer (`iss` claim). Validated on verification when set.
    #[serde(default)]
    pub jwt_issuer: Option<String>,

    /// JWT audience (`aud` claim). Validated on verification when set.
    #[serde(default)]
    pub jwt_audience: Option<String>,

    /// JWT signing algorithm.
    #[serde(default)]
    pub jwt_algorithm: JwtAlgorithm,

    /// Path to private key file (PEM) for RS256/ES256.
    #[serde(default)]
    pub jwt_private_key_path: Option<String>,

    /// Path to public key file (PEM) for RS256/ES256.
    #[serde(default)]
    pub jwt_public_key_path: Option<String>,
}

/// Supported JWT signing algorithms.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub enum JwtAlgorithm {
    #[default]
    HS256,
    RS256,
    ES256,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth")
            .field("jwt_secret", &"[REDACTED]")
            .field("token_expiry_days", &self.token_expiry_days)
            .field("token_expiry_hours", &self.token_expiry_hours)
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("jwt_algorithm", &self.jwt_algorithm)
            .field("jwt_private_key_path", &self.jwt_private_key_path)
            .field("jwt_public_key_path", &self.jwt_public_key_path)
            .finish()
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            jwt_secret: String::new(),
            token_expiry_days: default_token_expiry_days(),
            token_expiry_hours: None,
            jwt_issuer: None,
            jwt_audience: None,
            jwt_algorithm: JwtAlgorithm::default(),
            jwt_private_key_path: None,
            jwt_public_key_path: None,
        }
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum requests per window.
    #[serde(default = "default_rate_limit_max")]
    pub max_requests: u32,
    /// Window duration in seconds.
    #[serde(default = "default_rate_limit_window")]
    pub window_secs: u64,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            max_requests: default_rate_limit_max(),
            window_secs: default_rate_limit_window(),
        }
    }
}

fn default_rate_limit_max() -> u32 {
    100
}

fn default_rate_limit_window() -> u64 {
    60
}

fn default_token_expiry_days() -> u32 {
    1
}

/// Builder for loading configuration with customizable options.
#[derive(Debug, Clone)]
pub struct Loader {
    /// Environment variable prefix (e.g., "MYAPP" -> MYAPP_HOST, MYAPP_PORT)
    pub env_prefix: String,
    /// Name of the JWT secret environment variable (without prefix)
    pub jwt_secret_env: String,
}

impl Default for Loader {
    fn default() -> Self {
        Self {
            env_prefix: "RUNWAY".to_string(),
            jwt_secret_env: "JWT_SECRET".to_string(),
        }
    }
}

impl Loader {
    /// Create a new config loader with the given environment prefix.
    pub fn new(env_prefix: impl Into<String>) -> Self {
        Self {
            env_prefix: env_prefix.into(),
            ..Default::default()
        }
    }

    /// Load configuration from file, environment, and CLI arguments.
    ///
    /// # Arguments
    /// * `config_path` - Optional path to TOML config file
    /// * `cli_host` - CLI override for host
    /// * `cli_port` - CLI override for port
    /// * `cli_database_url` - CLI override for database URL
    /// * `cli_jwt_secret` - CLI override for JWT secret
    pub fn load(
        &self,
        config_path: Option<&Path>,
        cli_host: Option<&str>,
        cli_port: Option<u16>,
        cli_database_url: Option<&str>,
        cli_jwt_secret: Option<&str>,
    ) -> crate::Result<Internal> {
        // Start with file config or defaults
        let mut config: Internal = if let Some(path) = config_path {
            let content = std::fs::read_to_string(path)
                .map_err(|e| Error::Config(format!("Failed to read config file: {e}")))?;
            toml::from_str(&content)
                .map_err(|e| Error::Config(format!("Failed to parse config: {e}")))?
        } else {
            Internal {
                server: Server::default(),
                database: Database::default(),
                auth: Auth::default(),
            }
        };

        // Clear any jwt_secret from config file - security requirement
        config.auth.jwt_secret = String::new();

        // Override with environment variables
        let prefix = &self.env_prefix;

        if let Ok(host) = std::env::var(format!("{prefix}_HOST")) {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var(format!("{prefix}_PORT"))
            && let Ok(p) = port.parse()
        {
            config.server.port = p;
        }
        if let Ok(url) = std::env::var("DATABASE_URL") {
            config.database.url = url;
        }
        if let Ok(secret) = std::env::var(format!("{}_{}", prefix, self.jwt_secret_env)) {
            config.auth.jwt_secret = secret;
        }
        if let Ok(issuer) = std::env::var(format!("{prefix}_JWT_ISSUER")) {
            config.auth.jwt_issuer = Some(issuer);
        }
        if let Ok(audience) = std::env::var(format!("{prefix}_JWT_AUDIENCE")) {
            config.auth.jwt_audience = Some(audience);
        }

        // Override with CLI arguments
        if let Some(host) = cli_host {
            config.server.host = host.to_string();
        }
        if let Some(port) = cli_port {
            config.server.port = port;
        }
        if let Some(url) = cli_database_url {
            config.database.url = url.to_string();
        }
        if let Some(secret) = cli_jwt_secret {
            config.auth.jwt_secret = secret.to_string();
        }

        // Validate required fields
        match config.auth.jwt_algorithm {
            JwtAlgorithm::HS256 => {
                if config.auth.jwt_secret.len() < 32 {
                    return Err(Error::Config(format!(
                        "{}_{} must be at least 32 bytes (set via environment variable or --jwt-secret flag)",
                        prefix, self.jwt_secret_env
                    )));
                }
            }
            JwtAlgorithm::RS256 | JwtAlgorithm::ES256 => {
                if config.auth.jwt_private_key_path.is_none()
                    || config.auth.jwt_public_key_path.is_none()
                {
                    return Err(Error::Config(
                        "jwt_private_key_path and jwt_public_key_path are required for RS256/ES256"
                            .to_string(),
                    ));
                }
            }
        }

        Ok(config)
    }
}

/// Shared, cheaply cloneable config handle.
///
/// Follows the `actix_web::Data<T>` pattern: wraps `Arc<Config>` so callers
/// never deal with `Arc` directly. Implements `Deref<Target = Config>` for
/// transparent field access.
#[derive(Clone)]
pub struct Config(Arc<Internal>);

impl Config {
    /// Wrap an owned `Config` in a shared handle.
    pub fn new(server: Server, database: Database, auth: Auth) -> Self {
        Self(Arc::new(Internal {
            server,
            database,
            auth,
        }))
    }

    /// Check whether two handles point to the same allocation.
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        Arc::ptr_eq(&this.0, &other.0)
    }
}

impl std::ops::Deref for Config {
    type Target = Internal;
    fn deref(&self) -> &Internal {
        &self.0
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_server_config() {
        let server = Server::default();
        assert_eq!(server.host, "127.0.0.1");
        assert_eq!(server.port, 8080);
    }

    #[test]
    fn test_default_auth_config() {
        let auth = Auth::default();
        assert_eq!(auth.token_expiry_days, 1);
        assert!(auth.jwt_secret.is_empty());
        assert!(auth.jwt_issuer.is_none());
        assert!(auth.jwt_audience.is_none());
        assert_eq!(auth.jwt_algorithm, JwtAlgorithm::HS256);
    }

    #[test]
    fn test_load_from_toml_file() {
        // Save and clear DATABASE_URL to avoid env override
        let saved_db_url = std::env::var("DATABASE_URL").ok();
        // SAFETY: Test code, single-threaded
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }

        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[server]
host = "127.0.0.1"
port = 3000

[database]
url = "test.db"

[auth]
token_expiry_days = 7
"#
        )
        .unwrap();

        let loader = Loader::new("TEST");
        let config = loader
            .load(
                Some(file.path()),
                None,
                None,
                None,
                Some("cli_secret_that_is_at_least_32bytes!"),
            )
            .unwrap();

        // Restore DATABASE_URL
        // SAFETY: Test code, single-threaded
        unsafe {
            if let Some(url) = saved_db_url {
                std::env::set_var("DATABASE_URL", url);
            }
        }

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.database.url, "test.db");
        assert_eq!(
            config.auth.jwt_secret,
            "cli_secret_that_is_at_least_32bytes!"
        );
        assert_eq!(config.auth.token_expiry_days, 7);
    }

    #[test]
    fn test_cli_overrides_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[server]
host = "127.0.0.1"
port = 3000

[database]
url = "test.db"
"#
        )
        .unwrap();

        let loader = Loader::new("TEST");
        let config = loader
            .load(
                Some(file.path()),
                Some("0.0.0.0"),
                Some(8080),
                Some("postgres://localhost/db"),
                Some("my_secret_that_is_long_enough_32b"),
            )
            .unwrap();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.database.url, "postgres://localhost/db");
        assert_eq!(config.auth.jwt_secret, "my_secret_that_is_long_enough_32b");
    }

    #[test]
    fn test_missing_jwt_secret_fails() {
        let loader = Loader::new("TEST");
        let result = loader.load(None, None, None, None, None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("JWT_SECRET must be at least 32 bytes")
        );
    }

    #[test]
    fn test_env_override() {
        // Set env vars with our test prefix
        // SAFETY: This is test code running single-threaded
        unsafe {
            std::env::set_var("TESTENV_HOST", "env-host");
            std::env::set_var("TESTENV_PORT", "9999");
            std::env::set_var("TESTENV_JWT_SECRET", "env_secret_that_is_at_least_32bytes!");
        }

        let loader = Loader::new("TESTENV");
        let config = loader.load(None, None, None, None, None).unwrap();

        // Clean up
        // SAFETY: This is test code running single-threaded
        unsafe {
            std::env::remove_var("TESTENV_HOST");
            std::env::remove_var("TESTENV_PORT");
            std::env::remove_var("TESTENV_JWT_SECRET");
        }

        assert_eq!(config.server.host, "env-host");
        assert_eq!(config.server.port, 9999);
        assert_eq!(
            config.auth.jwt_secret,
            "env_secret_that_is_at_least_32bytes!"
        );
    }
}
