//! Error types with HTTP status code mapping.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

/// Error type for runway operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Auth errors
    #[error("Unauthorized")]
    Unauthorized,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Token expired")]
    TokenExpired,

    #[error("Forbidden: cannot {action} {resource}")]
    Forbidden { resource: String, action: String },

    // Data errors
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    // Config errors
    #[error("Configuration error: {0}")]
    Config(String),

    // System errors
    #[error("Invalid address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    Database(#[from] libsql::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Map error to HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            // Auth errors -> 401/403
            Error::Unauthorized | Error::InvalidCredentials | Error::TokenExpired => {
                StatusCode::UNAUTHORIZED
            }
            Error::Forbidden { .. } => StatusCode::FORBIDDEN,

            // Data errors -> 4xx
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::BadRequest(_) | Error::AddrParse(_) => StatusCode::BAD_REQUEST,
            Error::Conflict(_) => StatusCode::CONFLICT,

            // Config errors -> 500 (shouldn't happen at runtime)
            Error::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // System errors -> 500
            Error::Io(_)
            | Error::Json(_)
            | Error::Database(_)
            | Error::Jwt(_)
            | Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Convert error into HTTP response.
    pub fn into_response(self) -> Response<Full<Bytes>> {
        let status = self.status_code();
        let body = serde_json::json!({
            "error": self.to_string()
        });

        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }
}

/// Result type alias using runway's Error.
pub type Result<T> = std::result::Result<T, Error>;
