//! Configuration security tests.
//!
//! Verifies secret handling across config layers and checks for
//! accidental secret exposure through `Debug` and `Clone`.

use runway::config;

/// The config loader correctly strips `jwt_secret` from TOML files
/// before applying environment / CLI overrides.
#[test]
fn jwt_secret_stripped_from_config_file() {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[auth]
jwt_secret = "should_be_stripped"
token_expiry_days = 7
"#
    )
    .unwrap();

    let loader = config::ConfigLoader::new("CFGTEST");
    let config = loader
        .load(
            Some(file.path()),
            None,
            None,
            None,
            Some("cli_override_secret_at_least_32b!"),
        )
        .unwrap();
    assert_eq!(
        config.auth.jwt_secret, "cli_override_secret_at_least_32b!",
        "CLI secret must override file secret"
    );
}

/// `Auth` has a manual `Debug` impl that redacts the JWT secret.
#[test]
fn debug_output_leaks_jwt_secret() {
    let auth = config::Auth {
        jwt_secret: "SUPER_SECRET_VALUE".to_string(),
        ..Default::default()
    };
    let debug_output = format!("{:?}", auth);
    assert!(
        !debug_output.contains("SUPER_SECRET_VALUE"),
        "Debug output should not leak the JWT secret: {debug_output}"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output should contain [REDACTED]: {debug_output}"
    );
}

/// `Config` is wrapped in `SharedConfig` so all requests share the same
/// allocation rather than cloning the secret into every request.
#[test]
fn config_cloned_into_every_request_carries_secret() {
    let cfg = config::SharedConfig::new(runway::Config {
        server: config::Server::default(),
        database: config::Database::default(),
        auth: config::Auth {
            jwt_secret: "secret_in_every_request".to_string(),
            ..Default::default()
        },
    });
    let cloned = cfg.clone();
    assert!(config::SharedConfig::ptr_eq(&cfg, &cloned));
}
