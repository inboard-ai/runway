//! JWT authentication utilities.
//!
//! This module provides JWT token creation and verification.
//! Password hashing is NOT included - that's the responsibility of your IAM module.

use hyper::http::HeaderMap;
use uuid::Uuid;

/// Trait for user types that can be authenticated.
///
/// Implement this trait for your user type to use with IAM.
pub trait User {
    fn id(&self) -> Uuid;
    fn email(&self) -> &str;
    fn password_hash(&self) -> &str;
}
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::config::Auth as AuthConfig;
use crate::error::{Error, Result};

const MIN_SECRET_LENGTH: usize = 32;

fn validate_secret(config: &AuthConfig) -> Result<()> {
    if config.jwt_secret.len() < MIN_SECRET_LENGTH {
        return Err(Error::Config(format!(
            "JWT secret must be at least {MIN_SECRET_LENGTH} bytes"
        )));
    }
    Ok(())
}

/// JWT claims structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (typically user ID)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
}

/// Create a JWT token for a user.
///
/// # Arguments
/// * `config` - Auth configuration with JWT secret and expiry settings
/// * `user_id` - The user ID to encode in the token's `sub` claim
pub fn create_token(config: &AuthConfig, user_id: &str) -> Result<String> {
    validate_secret(config)?;
    let now = jiff::Timestamp::now();
    let hours = config.token_expiry_days as i64 * 24;
    let exp = now + jiff::Span::new().hours(hours);

    let claims = Claims {
        sub: user_id.to_string(),
        exp: exp.as_second(),
        iat: now.as_second(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| Error::Internal(format!("Token creation failed: {e}")))?;

    Ok(token)
}

/// Verify and decode a JWT token.
///
/// # Returns
/// - `Ok(Claims)` if the token is valid
/// - `Err(Error::TokenExpired)` if the token has expired
/// - `Err(Error::Unauthorized)` for any other validation failure
pub fn verify_token(config: &AuthConfig, token: &str) -> Result<Claims> {
    validate_secret(config)?;
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => Error::TokenExpired,
        _ => Error::Unauthorized,
    })?;

    Ok(token_data.claims)
}

/// Extract user ID from the Authorization header.
///
/// Expects a Bearer token in the format: `Authorization: Bearer <token>`
///
/// # Returns
/// - `Ok(user_id)` if the token is valid
/// - `Err(Error::Unauthorized)` if the header is missing or token is invalid
pub fn extract_user_id(headers: &HeaderMap, config: &AuthConfig) -> Result<String> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(Error::Unauthorized)?;

    let token = auth_header
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("bearer "))
        .map(|_| &auth_header[7..])
        .ok_or(Error::Unauthorized)?;

    let claims = verify_token(config, token)?;

    Ok(claims.sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AuthConfig {
        AuthConfig {
            jwt_secret: "test_secret_key_for_testing_32b!!".to_string(),
            token_expiry_days: 30,
        }
    }

    #[test]
    fn test_create_and_verify_token() {
        let config = test_config();
        let user_id = "user-123";

        let token = create_token(&config, user_id).unwrap();
        let claims = verify_token(&config, &token).unwrap();

        assert_eq!(claims.sub, user_id);
    }

    #[test]
    fn test_invalid_token_returns_unauthorized() {
        let config = test_config();

        let result = verify_token(&config, "invalid.token.here");
        assert!(matches!(result, Err(Error::Unauthorized)));
    }

    #[test]
    fn test_wrong_secret_returns_unauthorized() {
        let config = test_config();
        let token = create_token(&config, "user-123").unwrap();

        let wrong_config = AuthConfig {
            jwt_secret: "different_secret_that_is_32bytes!".to_string(),
            token_expiry_days: 30,
        };

        let result = verify_token(&wrong_config, &token);
        assert!(matches!(result, Err(Error::Unauthorized)));
    }

    #[test]
    fn test_token_contains_correct_claims() {
        let config = test_config();
        let user_id = "test-user-456";

        let token = create_token(&config, user_id).unwrap();
        let claims = verify_token(&config, &token).unwrap();

        assert_eq!(claims.sub, user_id);
        assert!(claims.iat > 0);
        assert!(claims.exp > claims.iat);
    }
}
