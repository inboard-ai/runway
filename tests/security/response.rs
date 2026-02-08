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
        cd.contains("malicious"),
        "Header injection succeeded: {cd}"
    );
}

/// `redirect()` places its argument directly into the `Location` header
/// with no validation. An attacker-controlled value enables open-redirect.
#[test]
fn redirect_allows_arbitrary_urls() {
    let resp = response::redirect("https://evil.com/phish");
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    assert_eq!(location, "https://evil.com/phish");
}

/// When a `Location` value contains CRLF, hyper's `HeaderValue` rejects
/// it at parse time. Because `redirect()` calls `.unwrap()` on the
/// response builder, this manifests as a panic (server crash) rather
/// than a graceful 400 response.
#[test]
fn redirect_panics_on_crlf_injection() {
    let result = std::panic::catch_unwind(|| {
        response::redirect("https://evil.com\r\nX-Injected: true");
    });
    assert!(
        result.is_err(),
        "Expected panic from invalid header value — server would crash on this input"
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
