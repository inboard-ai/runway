//! Server infrastructure security integration tests.
//!
//! These tests start a real server, send raw TCP traffic, and assert on
//! observable behavior.

use std::net::SocketAddr;

use runway::config::{Auth, Config, Database, RateLimitConfig, Server as ServerConfig};
use runway::server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Start a test server on a random port with `/echo` (POST), `/ping` (GET),
/// and `/panic` (GET) routes using default config (no CORS, no HSTS).
async fn start_test_server() -> server::Server {
    start_test_server_with_config(ServerConfig::default()).await
}

/// Start a test server with a custom `ServerConfig`.
async fn start_test_server_with_config(server_cfg: ServerConfig) -> server::Server {
    let config = Config {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            ..server_cfg
        },
        database: Database {
            url: ":memory:".to_string(),
        },
        auth: Auth {
            jwt_secret: "test-secret-that-is-at-least-32b!".to_string(),
            token_expiry_days: 1,
            ..Default::default()
        },
    };

    let mut router = runway::Router::new();

    router.post("/echo", |ctx| async move {
        let input: serde_json::Value = ctx.json()?;
        runway::response::ok(&serde_json::json!({
            "echoed": input
        }))
    });

    router.get("/ping", |_ctx| async move {
        runway::response::ok(&serde_json::json!({ "pong": true }))
    });

    router.get("/panic", |_ctx| async move {
        panic!("test panic");
    });

    router.get("/slow", |_ctx| async move {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        runway::response::ok(&serde_json::json!({ "slow": true }))
    });

    server::start(config, None, router.into_handle())
        .await
        .expect("failed to start test server")
}

/// Send a raw HTTP/1.1 request with `Connection: close` and read the full response.
async fn raw_request(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).await.expect("failed to connect");
    stream.write_all(payload).await.expect("failed to write");

    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut buf),
    )
    .await;
    buf
}

/// Send a partial request and return the open stream (for slowloris-style tests).
async fn raw_partial_request(addr: SocketAddr, payload: &[u8]) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("failed to connect");
    stream
        .write_all(payload)
        .await
        .expect("failed to write partial request");
    stream
}

// ---------------------------------------------------------------------------
// Existing tests (updated)
// ---------------------------------------------------------------------------

/// The server should reject request bodies larger than a configured maximum.
/// Sends headers declaring a 10 MB Content-Length; the server should reject
/// based on the header alone and return 413 Payload Too Large.
#[tokio::test]
async fn server_rejects_oversized_body() {
    let server = start_test_server().await;
    let addr = server.addr();

    // Send only headers with an oversized Content-Length (no body data)
    let response = raw_request(
        addr,
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10485760\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str.contains("413"),
        "Expected 413 Payload Too Large, got:\n{response_str}"
    );
}

/// The server should limit the number of concurrent connections. Opening 200
/// connections should result in at least one being refused or receiving a 503.
#[tokio::test]
async fn server_rejects_excess_connections() {
    let server = start_test_server().await;
    let addr = server.addr();

    let mut streams = Vec::new();
    let mut refused = 0usize;

    for _ in 0..200 {
        match TcpStream::connect(addr).await {
            Ok(s) => streams.push(s),
            Err(_) => refused += 1,
        }
    }

    // Give the server a moment to accept and categorise all connections
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Try to get a response on each open connection
    let mut service_unavailable = 0usize;
    for mut stream in streams {
        let req = b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        if stream.write_all(req).await.is_ok() {
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
                .await
            {
                Ok(Ok(n)) if n > 0 => {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    if resp.contains("503") {
                        service_unavailable += 1;
                    }
                }
                _ => {}
            }
        }
    }

    server.shutdown().await.unwrap();

    assert!(
        refused + service_unavailable > 0,
        "Expected at least one connection refused or 503, but all 200 were accepted and served"
    );
}

/// The server should close connections that stall during header transmission.
/// This sends a partial HTTP header and then waits — the server should time
/// out and close the connection.
#[tokio::test]
async fn server_closes_slow_connections() {
    let server = start_test_server().await;
    let addr = server.addr();

    // Send partial headers (no \r\n\r\n terminator)
    let mut stream = raw_partial_request(addr, b"GET /ping HTTP/1.1\r\nHost: localhost\r\n").await;

    // Wait 3 seconds — the server should close us by then
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Try to read — if the server closed the connection we get 0 bytes or an error
    let mut buf = vec![0u8; 4096];
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf)).await;

    server.shutdown().await.unwrap();

    match result {
        Ok(Ok(0)) => {}  // Connection closed — good
        Ok(Err(_)) => {} // Read error — also fine
        Ok(Ok(n)) => {
            // Got some data — that's acceptable if it's an error response
            let resp = String::from_utf8_lossy(&buf[..n]);
            assert!(
                resp.contains("408") || resp.contains("timeout"),
                "Expected connection close or 408, got:\n{resp}"
            );
        }
        Err(_) => {
            panic!(
                "Server did not close the slow connection within 5 seconds (slowloris vulnerable)"
            );
        }
    }
}

/// The server should return CORS headers when an Origin header is present
/// and the origin is in the allowlist.
#[tokio::test]
async fn server_returns_cors_headers() {
    let server = start_test_server_with_config(ServerConfig {
        cors_origins: vec!["http://example.com".to_string()],
        ..Default::default()
    })
    .await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nOrigin: http://example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    let response_lower = response_str.to_ascii_lowercase();
    assert!(
        response_lower.contains("access-control-allow-origin"),
        "Expected Access-Control-Allow-Origin header in response:\n{response_str}"
    );
}

/// The server should include standard security headers in every response.
#[tokio::test]
async fn server_returns_security_headers() {
    let server = start_test_server().await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    let response_lower = response_str.to_ascii_lowercase();
    assert!(
        response_lower.contains("x-content-type-options"),
        "Expected X-Content-Type-Options header in response:\n{response_str}"
    );
    assert!(
        response_lower.contains("x-frame-options"),
        "Expected X-Frame-Options header in response:\n{response_str}"
    );
    assert!(
        response_lower.contains("cache-control"),
        "Expected Cache-Control header in response:\n{response_str}"
    );
    assert!(
        response_lower.contains("content-security-policy"),
        "Expected Content-Security-Policy header in response:\n{response_str}"
    );
}

/// The server advertises the `http2` feature in Cargo.toml but only uses
/// `http1::Builder`. It should speak HTTP/2 when a client sends the HTTP/2
/// connection preface.
#[tokio::test]
async fn server_speaks_http2() {
    let server = start_test_server().await;
    let addr = server.addr();

    // HTTP/2 connection preface followed by an empty SETTINGS frame
    let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // SETTINGS frame: length=0, type=0x04, flags=0x00, stream=0
    preface.extend_from_slice(&[0, 0, 0, 0x04, 0x00, 0, 0, 0, 0]);

    let mut stream = TcpStream::connect(addr).await.expect("failed to connect");
    stream
        .write_all(&preface)
        .await
        .expect("failed to write h2 preface");

    let mut buf = vec![0u8; 256];
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf)).await;

    server.shutdown().await.unwrap();

    match result {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
            panic!("Server closed connection or timed out — HTTP/2 not supported");
        }
        Ok(Ok(n)) => {
            let data = &buf[..n];
            // A valid HTTP/2 response starts with a SETTINGS frame:
            // 9-byte frame header where type (byte 3) == 0x04
            assert!(
                n >= 9 && data[3] == 0x04,
                "Expected HTTP/2 SETTINGS frame, got {} bytes: {:?}",
                n,
                &data[..n.min(32)]
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 1 — Observability & input validation (A1, A2, A3, E10)
// ---------------------------------------------------------------------------

/// A1: Server returns an X-Request-Id header with a valid UUID.
#[tokio::test]
async fn server_returns_request_id_header() {
    let server = start_test_server().await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    let response_lower = response_str.to_ascii_lowercase();
    assert!(
        response_lower.contains("x-request-id"),
        "Expected X-Request-Id header in response:\n{response_str}"
    );

    // Extract UUID value
    for line in response_str.lines() {
        if line.to_ascii_lowercase().starts_with("x-request-id:") {
            let value = line.split(':').nth(1).unwrap().trim();
            assert!(
                uuid::Uuid::try_parse(value).is_ok(),
                "X-Request-Id should be a valid UUID, got: {value}"
            );
        }
    }
}

/// A1: Server propagates a valid client-supplied X-Request-Id.
#[tokio::test]
async fn server_propagates_client_request_id() {
    let server = start_test_server().await;
    let addr = server.addr();
    let client_id = "550e8400-e29b-41d4-a716-446655440000";

    let req = format!(
        "GET /ping HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {client_id}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_request(addr, req.as_bytes()).await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str.contains(client_id),
        "Expected server to propagate client X-Request-Id {client_id}, got:\n{response_str}"
    );
}

/// A1: Server ignores an invalid X-Request-Id and generates its own.
#[tokio::test]
async fn server_ignores_invalid_request_id() {
    let server = start_test_server().await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: not-a-uuid\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    // Should have an X-Request-Id but NOT our invalid one
    let response_lower = response_str.to_ascii_lowercase();
    assert!(
        response_lower.contains("x-request-id"),
        "Expected X-Request-Id header in response"
    );
    assert!(
        !response_str.contains("not-a-uuid"),
        "Server should not propagate invalid X-Request-Id"
    );
}

/// E10: POST with wrong Content-Type to a JSON endpoint returns 415.
#[tokio::test]
async fn server_rejects_wrong_content_type() {
    let server = start_test_server().await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"hello\":true}",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str.contains("415"),
        "Expected 415 Unsupported Media Type, got:\n{response_str}"
    );
}

// ---------------------------------------------------------------------------
// Phase 2 — Auth hardening & transport (C8, D9)
// ---------------------------------------------------------------------------

/// D9: Origins not in the allowlist do not get CORS headers.
#[tokio::test]
async fn server_rejects_unlisted_origin() {
    let server = start_test_server_with_config(ServerConfig {
        cors_origins: vec!["http://allowed.com".to_string()],
        ..Default::default()
    })
    .await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nOrigin: http://evil.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        !response_str
            .to_ascii_lowercase()
            .contains("access-control-allow-origin"),
        "Should NOT have CORS headers for unlisted origin:\n{response_str}"
    );
}

/// D9: Matching origin gets reflected.
#[tokio::test]
async fn server_allows_listed_origin() {
    let server = start_test_server_with_config(ServerConfig {
        cors_origins: vec!["http://allowed.com".to_string()],
        ..Default::default()
    })
    .await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nOrigin: http://allowed.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str.contains("http://allowed.com"),
        "Expected reflected origin in CORS header:\n{response_str}"
    );
}

/// D9: OPTIONS preflight returns 204 with CORS headers.
#[tokio::test]
async fn server_handles_options_preflight() {
    let server = start_test_server_with_config(ServerConfig {
        cors_origins: vec!["http://app.com".to_string()],
        ..Default::default()
    })
    .await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"OPTIONS /ping HTTP/1.1\r\nHost: localhost\r\nOrigin: http://app.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str.contains("204"),
        "Expected 204 No Content for OPTIONS preflight, got:\n{response_str}"
    );
    assert!(
        response_str
            .to_ascii_lowercase()
            .contains("access-control-allow-methods"),
        "Expected Access-Control-Allow-Methods in preflight response:\n{response_str}"
    );
}

/// D9: Wildcard `["*"]` allows any origin.
#[tokio::test]
async fn server_wildcard_cors() {
    let server = start_test_server_with_config(ServerConfig {
        cors_origins: vec!["*".to_string()],
        ..Default::default()
    })
    .await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nOrigin: http://anything.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str.contains("http://anything.com"),
        "Expected wildcard CORS to reflect any origin:\n{response_str}"
    );
}

/// C8: HSTS header is present when enabled.
#[tokio::test]
async fn server_returns_hsts_when_enabled() {
    let server = start_test_server_with_config(ServerConfig {
        hsts: true,
        ..Default::default()
    })
    .await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str
            .to_ascii_lowercase()
            .contains("strict-transport-security"),
        "Expected Strict-Transport-Security header when HSTS enabled:\n{response_str}"
    );
}

/// C8: HSTS header absent by default.
#[tokio::test]
async fn server_omits_hsts_by_default() {
    let server = start_test_server().await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        !response_str
            .to_ascii_lowercase()
            .contains("strict-transport-security"),
        "HSTS should not be present by default:\n{response_str}"
    );
}

// ---------------------------------------------------------------------------
// Phase 3 — Reliability & rate limiting (B4, F11, F12)
// ---------------------------------------------------------------------------

/// F12: A handler that panics returns 500, not a connection reset.
#[tokio::test]
async fn server_returns_500_on_handler_panic() {
    let server = start_test_server().await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /panic HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str.contains("500"),
        "Expected 500 on handler panic, got:\n{response_str}"
    );
}

/// F11: In-flight requests complete after shutdown signal.
#[tokio::test]
async fn server_drains_on_shutdown() {
    let server = start_test_server().await;
    let addr = server.addr();

    // Send a request to the slow endpoint
    let mut stream = TcpStream::connect(addr).await.expect("failed to connect");
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("failed to write");

    // Brief delay to ensure the request has been accepted
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Initiate shutdown while the slow request is in-flight
    let shutdown_handle = tokio::spawn(async move { server.shutdown().await });

    // The slow handler should still complete — read the response
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut buf),
    )
    .await;

    let response_str = String::from_utf8_lossy(&buf);
    assert!(
        response_str.contains("200") || response_str.contains("slow"),
        "Expected slow handler to complete during drain, got:\n{response_str}"
    );

    shutdown_handle.await.unwrap().unwrap();
}

/// B4: Rate limiter returns 429 after exceeding the limit.
#[tokio::test]
async fn server_rate_limits_by_ip() {
    let server = start_test_server_with_config(ServerConfig {
        rate_limit: Some(RateLimitConfig {
            max_requests: 3,
            window_secs: 60,
        }),
        ..Default::default()
    })
    .await;
    let addr = server.addr();

    let mut got_429 = false;
    for _ in 0..5 {
        let response = raw_request(
            addr,
            b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        let response_str = String::from_utf8_lossy(&response);
        if response_str.contains("429") {
            got_429 = true;
            assert!(
                response_str.to_ascii_lowercase().contains("retry-after"),
                "429 response should include Retry-After header:\n{response_str}"
            );
            break;
        }
    }

    server.shutdown().await.unwrap();

    assert!(got_429, "Expected at least one 429 Too Many Requests");
}
