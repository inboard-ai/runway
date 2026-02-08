//! Error information-disclosure tests.
//!
//! `Error::into_response` forwards the full `Display` output to the
//! HTTP client. For internal error variants this leaks implementation
//! details (SQL fragments, file paths, stack context).

use runway::Error;

/// Errors created with `Error::Internal(...)` pass their payload
/// directly into the JSON response body visible to the caller.
#[test]
fn internal_error_leaks_sql() {
    let err = Error::Internal("Failed to query SELECT * FROM users WHERE id = 'x'".into());
    let resp = err.into_response();
    let body = resp.into_body();
    let bytes =
        tokio_test::block_on(http_body_util::BodyExt::collect(body))
            .unwrap()
            .to_bytes();
    let body_str = String::from_utf8_lossy(&bytes);
    assert!(
        !body_str.contains("SELECT"),
        "SQL fragment leaked to client: {body_str}"
    );
    assert!(
        body_str.contains("Internal server error"),
        "Expected generic error message, got: {body_str}"
    );
}

/// `Error::Io` wraps the underlying `std::io::Error` whose message
/// often contains filesystem paths.
#[test]
fn io_error_leaks_paths() {
    let io_err = std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "No such file: /etc/secret/config.toml",
    );
    let err = Error::Io(io_err);
    let resp = err.into_response();
    let body = resp.into_body();
    let bytes =
        tokio_test::block_on(http_body_util::BodyExt::collect(body))
            .unwrap()
            .to_bytes();
    let body_str = String::from_utf8_lossy(&bytes);
    assert!(
        !body_str.contains("/etc/secret"),
        "Filesystem path leaked to client: {body_str}"
    );
    assert!(
        body_str.contains("Internal server error"),
        "Expected generic error message, got: {body_str}"
    );
}
