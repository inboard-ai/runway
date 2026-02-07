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

use serde::{Deserialize, Serialize};

use crate::Error;

/// Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    #[serde(default)]
    pub database: Database,
    #[serde(default)]
    pub auth: Auth,
}

/// HTTP server settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    /// JWT secret for token signing/verification.
    /// Must be provided via environment variable or CLI - never from config file.
    #[serde(default)]
    pub jwt_secret: String,

    /// Token expiry in days.
    #[serde(default = "default_token_expiry_days")]
    pub token_expiry_days: u32,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            jwt_secret: String::new(),
            token_expiry_days: default_token_expiry_days(),
        }
    }
}

fn default_token_expiry_days() -> u32 {
    30
}

/// Builder for loading configuration with customizable options.
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    /// Environment variable prefix (e.g., "MYAPP" -> MYAPP_HOST, MYAPP_PORT)
    pub env_prefix: String,
    /// Name of the JWT secret environment variable (without prefix)
    pub jwt_secret_env: String,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self {
            env_prefix: "RUNWAY".to_string(),
            jwt_secret_env: "JWT_SECRET".to_string(),
        }
    }
}

impl ConfigLoader {
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
    ) -> crate::Result<Config> {
        // Start with file config or defaults
        let mut config: Config = if let Some(path) = config_path {
            let content = std::fs::read_to_string(path)
                .map_err(|e| Error::Config(format!("Failed to read config file: {e}")))?;
            toml::from_str(&content)
                .map_err(|e| Error::Config(format!("Failed to parse config: {e}")))?
        } else {
            Config {
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
        if config.auth.jwt_secret.is_empty() {
            return Err(Error::Config(format!(
                "{}_{} must be set via environment variable or --jwt-secret flag",
                prefix, self.jwt_secret_env
            )));
        }

        Ok(config)
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
        assert_eq!(server.host, "0.0.0.0");
        assert_eq!(server.port, 8080);
    }

    #[test]
    fn test_default_auth_config() {
        let auth = Auth::default();
        assert_eq!(auth.token_expiry_days, 30);
        assert!(auth.jwt_secret.is_empty());
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

        let loader = ConfigLoader::new("TEST");
        let config = loader
            .load(Some(file.path()), None, None, None, Some("cli_secret"))
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
        assert_eq!(config.auth.jwt_secret, "cli_secret");
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

        let loader = ConfigLoader::new("TEST");
        let config = loader
            .load(
                Some(file.path()),
                Some("0.0.0.0"),
                Some(8080),
                Some("postgres://localhost/db"),
                Some("my_secret"),
            )
            .unwrap();

        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.database.url, "postgres://localhost/db");
        assert_eq!(config.auth.jwt_secret, "my_secret");
    }

    #[test]
    fn test_missing_jwt_secret_fails() {
        let loader = ConfigLoader::new("TEST");
        let result = loader.load(None, None, None, None, None);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("JWT_SECRET must be set"));
    }

    #[test]
    fn test_env_override() {
        // Set env vars with our test prefix
        // SAFETY: This is test code running single-threaded
        unsafe {
            std::env::set_var("TESTENV_HOST", "env-host");
            std::env::set_var("TESTENV_PORT", "9999");
            std::env::set_var("TESTENV_JWT_SECRET", "env_secret");
        }

        let loader = ConfigLoader::new("TESTENV");
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
        assert_eq!(config.auth.jwt_secret, "env_secret");
    }
}
