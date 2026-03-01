//! SSE example — a producer task pushes messages through a broadcast channel,
//! a runway handler streams them as Server-Sent Events, and a consumer task
//! connects over TCP and prints each event as it arrives.
//!
//! Run: `cargo run --example sse`

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use runway::config;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast;

#[tokio::main]
async fn main() -> runway::Result<()> {
    // -- Channel shared between producer and handler -------------------------
    let (tx, _) = broadcast::channel::<String>(64);
    let tx = Arc::new(tx);

    // -- Router --------------------------------------------------------------
    let mut router = runway::Router::new();

    let tx_handler = Arc::clone(&tx);
    router.get("/sse", move |_ctx| {
        let rx = tx_handler.subscribe();
        async move {
            let stream = async_stream::stream! {
                let mut rx = rx;
                loop {
                    match rx.recv().await {
                        Ok(msg) => yield Ok::<_, Infallible>(msg),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            let notice = format!("event: lag\ndata: skipped {n} messages\n\n");
                            yield Ok(notice);
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            };
            runway::response::sse(stream)
        }
    });

    // -- Server --------------------------------------------------------------
    let config = config::Config::new(
        config::Server {
            host: "127.0.0.1".to_string(),
            port: 0,
            ..Default::default()
        },
        config::Database {
            url: ":memory:".to_string(),
        },
        config::Auth {
            jwt_secret: "example-secret-at-least-32-bytes!".to_string(),
            ..Default::default()
        },
    );

    let server = runway::server::start(config, None, router.into_handle()).await?;
    let addr = server.addr();
    println!("server listening on http://{addr}");

    // -- Producer task -------------------------------------------------------
    let tx_producer = Arc::clone(&tx);
    let producer = tokio::spawn(async move {
        for i in 1..=5 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let event = format!("event: count\ndata: {i}\n\n");
            let _ = tx_producer.send(event);
        }
    });

    // -- Consumer task -------------------------------------------------------
    let consumer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");

        let request = format!("GET /sse HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(request.as_bytes())
            .await
            .expect("write request");

        let mut lines = BufReader::new(reader).lines();
        let mut past_headers = false;
        let mut event_count = 0u32;

        println!("--- SSE events ---");
        while let Ok(Ok(Some(line))) =
            tokio::time::timeout(Duration::from_secs(5), lines.next_line()).await
        {
            // Skip HTTP headers.
            if !past_headers {
                if line.is_empty() {
                    past_headers = true;
                }
                continue;
            }

            // Skip chunked transfer-encoding size markers (hex-only lines).
            if !line.is_empty() && line.chars().all(|c: char| c.is_ascii_hexdigit()) {
                continue;
            }

            // Print SSE fields and count events by "data:" lines.
            if line.starts_with("event:") || line.starts_with("data:") {
                println!("{line}");
                if line.starts_with("data:") {
                    event_count += 1;
                    println!();
                }
            }

            if event_count >= 5 {
                break;
            }
        }
        println!("--- received {event_count} events ---");
    });

    producer.await.expect("producer panic");
    consumer.await.expect("consumer panic");

    server.shutdown().await
}
