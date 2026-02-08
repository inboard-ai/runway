//! JWT and authentication security tests.
//!
//! Verifies token signing, algorithm handling, secret strength,
//! and RFC 7235 compliance for Bearer token extraction.

use runway::auth;
use runway::config::Auth as AuthConfig;

/// The JWT layer rejects secrets shorter than 32 bytes.
#[test]
fn accepts_dangerously_short_secret() {
    let config = AuthConfig {
        jwt_secret: "x".to_string(),
        token_expiry_days: 30,
    };
    assert!(
        auth::create_token(&config, "user-1").is_err(),
        "Short secret should be rejected"
    );
}

/// The JWT layer rejects an empty secret.
#[test]
fn empty_secret_accepted_at_jwt_layer() {
    let config = AuthConfig {
        jwt_secret: String::new(),
        token_expiry_days: 1,
    };
    assert!(
        auth::create_token(&config, "admin").is_err(),
        "Empty secret should be rejected"
    );
}

/// `Validation::default()` in jsonwebtoken 9.x restricts to HS256,
/// so a token forged with `"alg":"none"` must be rejected.
#[test]
fn rejects_none_algorithm_token() {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = engine.encode(
        &serde_json::json!({"sub":"admin","exp":9999999999i64,"iat":1700000000}).to_string(),
    );
    let forged = format!("{header}.{payload}.");

    let config = AuthConfig {
        jwt_secret: "real_secret_that_is_at_least_32b!".to_string(),
        token_expiry_days: 30,
    };
    assert!(auth::verify_token(&config, &forged).is_err());
}

/// Rotating the signing key invalidates all outstanding tokens.
/// This is currently the only revocation mechanism available.
#[test]
fn key_rotation_invalidates_old_tokens() {
    let old = AuthConfig {
        jwt_secret: "old_secret_key_production_32byte!".to_string(),
        token_expiry_days: 30,
    };
    let new = AuthConfig {
        jwt_secret: "new_secret_key_production_32byte!".to_string(),
        token_expiry_days: 30,
    };
    let token = auth::create_token(&old, "user-1").unwrap();
    assert!(auth::verify_token(&new, &token).is_err());
}

/// RFC 7235 says the auth-scheme in `Authorization: Bearer <tok>` is
/// case-insensitive. `extract_user_id` now handles this correctly.
#[test]
fn bearer_prefix_is_case_sensitive() {
    let config = AuthConfig {
        jwt_secret: "test_secret_that_is_at_least_32b!".to_string(),
        token_expiry_days: 30,
    };
    let token = auth::create_token(&config, "user-1").unwrap();

    let mut headers = hyper::http::HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("bearer {token}").parse().unwrap(),
    );
    let result = auth::extract_user_id(&headers, &config);
    assert!(
        result.is_ok(),
        "lowercase 'bearer' should be accepted per RFC 7235 case-insensitivity"
    );
}
