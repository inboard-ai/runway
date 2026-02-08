//! Response-layer security tests.
//!
//! Covers header-injection vectors in `Content-Disposition` and `Location`,
//! plus the absence of standard security headers.

use bytes::Bytes;
use runway::response;

/// The `binary()` helper interpolates the caller-supplied filename into
/// `Content-Disposition` without escaping quotes. A filename containing
/// `"` can inject arbitrary header parameters.
#[test]
fn content_disposition_injection_via_filename() {
    let malicious_name = r#"evil.txt"; malicious="injected"#;
    let resp = response::binary(
        Bytes::from("data"),
        "application/octet-stream",
        Some(malicious_name),
    );
    let cd = resp
        .headers()
        .get("Content-Disposition")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        !cd.contains("malicious"),
        "Header injection should not succeed: {cd}"
    );
}

/// `redirect()` places its argument into the `Location` header after validation.
#[test]
fn redirect_allows_arbitrary_urls() {
    let resp = response::redirect("https://evil.com/phish").unwrap();
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    assert_eq!(location, "https://evil.com/phish");
}

/// When a `Location` value contains CRLF, `redirect()` returns an `Err`
/// instead of panicking.
#[test]
fn redirect_panics_on_crlf_injection() {
    let result = response::redirect("https://evil.com\r\nX-Injected: true");
    assert!(
        result.is_err(),
        "Expected Err for CRLF injection in redirect location"
    );
}

/// Standard security headers are absent from all JSON responses.
#[test]
fn missing_security_headers() {
    let resp = response::ok(&serde_json::json!({"data": 1})).unwrap();
    let h = resp.headers();
    assert!(h.get("X-Content-Type-Options").is_none());
    assert!(h.get("X-Frame-Options").is_none());
    assert!(h.get("Cache-Control").is_none());
    assert!(h.get("Content-Security-Policy").is_none());
}
