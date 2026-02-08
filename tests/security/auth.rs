//! JWT and authentication security tests.
//!
//! Verifies token signing, algorithm handling, secret strength,
//! and RFC 7235 compliance for Bearer token extraction.

use runway::auth;
use runway::config;

/// The JWT layer rejects secrets shorter than 32 bytes.
#[test]
fn accepts_dangerously_short_secret() {
    let cfg = config::Auth {
        jwt_secret: "x".to_string(),
        token_expiry_days: 1,
        ..Default::default()
    };
    assert!(
        auth::create_token(&cfg, "user-1").is_err(),
        "Short secret should be rejected"
    );
}

/// The JWT layer rejects an empty secret.
#[test]
fn empty_secret_accepted_at_jwt_layer() {
    let cfg = config::Auth {
        jwt_secret: String::new(),
        token_expiry_days: 1,
        ..Default::default()
    };
    assert!(
        auth::create_token(&cfg, "admin").is_err(),
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

    let cfg = config::Auth {
        jwt_secret: "real_secret_that_is_at_least_32b!".to_string(),
        ..Default::default()
    };
    assert!(auth::verify_token(&cfg, &forged).is_err());
}

/// Rotating the signing key invalidates all outstanding tokens.
/// This is currently the only revocation mechanism available.
#[test]
fn key_rotation_invalidates_old_tokens() {
    let old = config::Auth {
        jwt_secret: "old_secret_key_production_32byte!".to_string(),
        ..Default::default()
    };
    let new = config::Auth {
        jwt_secret: "new_secret_key_production_32byte!".to_string(),
        ..Default::default()
    };
    let token = auth::create_token(&old, "user-1").unwrap();
    assert!(auth::verify_token(&new, &token).is_err());
}

/// RFC 7235 says the auth-scheme in `Authorization: Bearer <tok>` is
/// case-insensitive. `extract_user_id` now handles this correctly.
#[test]
fn bearer_prefix_is_case_sensitive() {
    let cfg = config::Auth {
        jwt_secret: "test_secret_that_is_at_least_32b!".to_string(),
        ..Default::default()
    };
    let token = auth::create_token(&cfg, "user-1").unwrap();

    let mut headers = hyper::http::HeaderMap::new();
    headers.insert("Authorization", format!("bearer {token}").parse().unwrap());
    let result = auth::extract_user_id(&headers, &cfg);
    assert!(
        result.is_ok(),
        "lowercase 'bearer' should be accepted per RFC 7235 case-insensitivity"
    );
}

// ---------------------------------------------------------------------------
// Phase 2 — B5/B6: issuer, audience, expiry
// ---------------------------------------------------------------------------

/// B6: Token round-trips with iss and aud set.
#[test]
fn token_with_issuer_and_audience() {
    let cfg = config::Auth {
        jwt_secret: "test_secret_that_is_at_least_32b!".to_string(),
        jwt_issuer: Some("runway-test".to_string()),
        jwt_audience: Some("my-app".to_string()),
        ..Default::default()
    };
    let token = auth::create_token(&cfg, "user-1").unwrap();
    let claims = auth::verify_token(&cfg, &token).unwrap();
    assert_eq!(claims.iss.as_deref(), Some("runway-test"));
    assert_eq!(claims.aud.as_deref(), Some("my-app"));
}

/// B6: Wrong audience → Unauthorized.
#[test]
fn token_rejected_with_wrong_audience() {
    let create_cfg = config::Auth {
        jwt_secret: "test_secret_that_is_at_least_32b!".to_string(),
        jwt_audience: Some("app-a".to_string()),
        ..Default::default()
    };
    let verify_cfg = config::Auth {
        jwt_secret: "test_secret_that_is_at_least_32b!".to_string(),
        jwt_audience: Some("app-b".to_string()),
        ..Default::default()
    };
    let token = auth::create_token(&create_cfg, "user-1").unwrap();
    assert!(auth::verify_token(&verify_cfg, &token).is_err());
}

/// B6: Wrong issuer → Unauthorized.
#[test]
fn token_rejected_with_wrong_issuer() {
    let create_cfg = config::Auth {
        jwt_secret: "test_secret_that_is_at_least_32b!".to_string(),
        jwt_issuer: Some("service-a".to_string()),
        ..Default::default()
    };
    let verify_cfg = config::Auth {
        jwt_secret: "test_secret_that_is_at_least_32b!".to_string(),
        jwt_issuer: Some("service-b".to_string()),
        ..Default::default()
    };
    let token = auth::create_token(&create_cfg, "user-1").unwrap();
    assert!(auth::verify_token(&verify_cfg, &token).is_err());
}

/// B6: None/None issuer/audience still works (backward compat).
#[test]
fn backward_compatible_no_issuer_audience() {
    let cfg = config::Auth {
        jwt_secret: "test_secret_that_is_at_least_32b!".to_string(),
        ..Default::default()
    };
    let token = auth::create_token(&cfg, "user-1").unwrap();
    let claims = auth::verify_token(&cfg, &token).unwrap();
    assert_eq!(claims.sub, "user-1");
    assert!(claims.iss.is_none());
    assert!(claims.aud.is_none());
}

// ---------------------------------------------------------------------------
// Phase 4 — B7: Asymmetric JWT
// ---------------------------------------------------------------------------

/// B7: HS256 is default.
#[test]
fn hs256_is_default() {
    let cfg = config::Auth::default();
    assert_eq!(cfg.jwt_algorithm, config::JwtAlgorithm::HS256);
}

/// B7: RS256 create and verify round-trip.
#[test]
fn rs256_create_and_verify() {
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let priv_path = dir.path().join("rsa_private.pem");
    let pub_path = dir.path().join("rsa_public.pem");

    // Generate RSA keypair via openssl
    let status = Command::new("openssl")
        .args(["genrsa", "-out", priv_path.to_str().unwrap(), "2048"])
        .stderr(std::process::Stdio::null())
        .status();
    if status.is_err() || !status.unwrap().success() {
        // openssl not available, skip
        eprintln!("skipping rs256 test: openssl not available");
        return;
    }
    let _ = Command::new("openssl")
        .args([
            "rsa",
            "-in",
            priv_path.to_str().unwrap(),
            "-pubout",
            "-out",
            pub_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();

    let cfg = config::Auth {
        jwt_algorithm: config::JwtAlgorithm::RS256,
        jwt_private_key_path: Some(priv_path.to_str().unwrap().to_string()),
        jwt_public_key_path: Some(pub_path.to_str().unwrap().to_string()),
        ..Default::default()
    };

    let token = auth::create_token(&cfg, "user-rs256").unwrap();
    let claims = auth::verify_token(&cfg, &token).unwrap();
    assert_eq!(claims.sub, "user-rs256");
}

/// B7: ES256 create and verify round-trip.
#[test]
fn es256_create_and_verify() {
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let priv_path = dir.path().join("ec_private.pem");
    let pub_path = dir.path().join("ec_public.pem");

    // Generate EC key in PKCS#8 format (required by jsonwebtoken)
    let status = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-out",
            priv_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status();
    if status.is_err() || !status.unwrap().success() {
        eprintln!("skipping es256 test: openssl not available");
        return;
    }
    let _ = Command::new("openssl")
        .args([
            "pkey",
            "-in",
            priv_path.to_str().unwrap(),
            "-pubout",
            "-out",
            pub_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();

    let cfg = config::Auth {
        jwt_algorithm: config::JwtAlgorithm::ES256,
        jwt_private_key_path: Some(priv_path.to_str().unwrap().to_string()),
        jwt_public_key_path: Some(pub_path.to_str().unwrap().to_string()),
        ..Default::default()
    };

    let token = auth::create_token(&cfg, "user-es256").unwrap();
    let claims = auth::verify_token(&cfg, &token).unwrap();
    assert_eq!(claims.sub, "user-es256");
}

/// B7: Algorithm mismatch is rejected — HS256 token verified with RS256 config.
#[test]
fn algorithm_mismatch_rejected() {
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let priv_path = dir.path().join("rsa_private.pem");
    let pub_path = dir.path().join("rsa_public.pem");

    let status = Command::new("openssl")
        .args(["genrsa", "-out", priv_path.to_str().unwrap(), "2048"])
        .stderr(std::process::Stdio::null())
        .status();
    if status.is_err() || !status.unwrap().success() {
        eprintln!("skipping algorithm_mismatch test: openssl not available");
        return;
    }
    let _ = Command::new("openssl")
        .args([
            "rsa",
            "-in",
            priv_path.to_str().unwrap(),
            "-pubout",
            "-out",
            pub_path.to_str().unwrap(),
        ])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();

    // Create with HS256
    let hs_cfg = config::Auth {
        jwt_secret: "test_secret_that_is_at_least_32b!".to_string(),
        ..Default::default()
    };
    let token = auth::create_token(&hs_cfg, "user-1").unwrap();

    // Try to verify with RS256
    let rs_cfg = config::Auth {
        jwt_algorithm: config::JwtAlgorithm::RS256,
        jwt_public_key_path: Some(pub_path.to_str().unwrap().to_string()),
        jwt_private_key_path: Some(priv_path.to_str().unwrap().to_string()),
        ..Default::default()
    };
    assert!(auth::verify_token(&rs_cfg, &token).is_err());
}
