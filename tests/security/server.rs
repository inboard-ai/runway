//! Server infrastructure security integration tests.
//!
//! These tests start a real server, send raw TCP traffic, and assert on
//! observable behavior. They are expected to **fail** until the corresponding
//! security mitigations are implemented.

use std::net::SocketAddr;

use runway::config::{Auth, Config, Database, Server as ServerConfig};
use runway::server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Start a test server on a random port with `/echo` (POST) and `/ping` (GET).
async fn start_test_server() -> server::Server {
    let config = Config {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
        },
        database: Database {
            url: ":memory:".to_string(),
        },
        auth: Auth {
            jwt_secret: "test-secret".to_string(),
            token_expiry_days: 1,
        },
    };

    let mut router = runway::Router::new();

    router.post("/echo", |ctx| async move {
        runway::response::ok(&serde_json::json!({
            "echoed": ctx.body.len()
        }))
    });

    router.get("/ping", |_ctx| async move {
        runway::response::ok(&serde_json::json!({ "pong": true }))
    });

    server::start(config, None, router.into_handle())
        .await
        .expect("failed to start test server")
}

/// Send a raw request and read the full response (half-close after write).
async fn raw_request(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("failed to connect");
    stream
        .write_all(payload)
        .await
        .expect("failed to write");
    stream
        .shutdown()
        .await
        .expect("failed to half-close");

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .expect("failed to read response");
    buf
}

/// Send a partial request and return the open stream (for slowloris-style tests).
async fn raw_partial_request(addr: SocketAddr, payload: &[u8]) -> TcpStream {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("failed to connect");
    stream
        .write_all(payload)
        .await
        .expect("failed to write partial request");
    stream
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The server should reject request bodies larger than a configured maximum.
/// Currently the body is collected with no size limit, so this test is expected
/// to fail until `http_body_util::Limited` (or equivalent) is wired in.
#[tokio::test]
async fn server_rejects_oversized_body() {
    let server = start_test_server().await;
    let addr = server.addr();

    // 10 MB body
    let body = vec![b'A'; 10 * 1024 * 1024];
    let header = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );

    let mut payload = header.into_bytes();
    payload.extend_from_slice(&body);

    let response = raw_request(addr, &payload).await;
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

    // Try to get a response on each open connection
    let mut service_unavailable = 0usize;
    for mut stream in streams {
        let req = b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n";
        if stream.write_all(req).await.is_ok() {
            let _ = stream.shutdown().await;
            let mut buf = vec![0u8; 4096];
            if let Ok(n) = stream.read(&mut buf).await {
                let resp = String::from_utf8_lossy(&buf[..n]);
                if resp.contains("503") {
                    service_unavailable += 1;
                }
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
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut buf),
    )
    .await;

    server.shutdown().await.unwrap();

    match result {
        Ok(Ok(0)) => {} // Connection closed — good
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
            panic!("Server did not close the slow connection within 5 seconds (slowloris vulnerable)");
        }
    }
}

/// The server should return CORS headers when an Origin header is present.
#[tokio::test]
async fn server_returns_cors_headers() {
    let server = start_test_server().await;
    let addr = server.addr();

    let response = raw_request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\nOrigin: http://evil.com\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str.contains("Access-Control-Allow-Origin"),
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
        b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await;
    let response_str = String::from_utf8_lossy(&response);

    server.shutdown().await.unwrap();

    assert!(
        response_str.contains("X-Content-Type-Options"),
        "Expected X-Content-Type-Options header in response:\n{response_str}"
    );
    assert!(
        response_str.contains("X-Frame-Options"),
        "Expected X-Frame-Options header in response:\n{response_str}"
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

    let mut stream = TcpStream::connect(addr)
        .await
        .expect("failed to connect");
    stream
        .write_all(&preface)
        .await
        .expect("failed to write h2 preface");

    let mut buf = vec![0u8; 256];
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut buf),
    )
    .await;

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
