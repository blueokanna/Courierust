//! Streaming response demo: the server returns a `Body::Channel` that a
//! producer thread feeds, the client consumes it chunk by chunk.
//! Works over both HTTP/1.1 (chunked) and HTTP/2.
//!
//! Run with `cargo run --example streaming`.

use courierust::courierust_body::Body;
use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig};
use std::time::Duration;

fn main() -> courierust::Result<()> {
    // A server that streams 10 numbered events, one per 50ms.
    let server_cfg = ServerConfig {
        http2: true,
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg)?;
    let addr = server.local_addr()?;
    let _handle = server.serve_background(|_req: Request<Body>| -> Response<Body> {
        let (tx, body) = courierust::courierust_body::channel();
        std::thread::spawn(move || {
            for i in 0..10 {
                if tx
                    .send(courierust::courierust_bytes::Bytes::from(format!(
                        "event {i}\n"
                    )))
                    .is_err()
                {
                    break; // client went away
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let mut resp = Response::with_status(200.into());
        resp.headers.insert(
            courierust::courierust_http::header::HeaderName::from_lowercase("content-type"),
            courierust::courierust_http::header::HeaderValue::from_static("text/event-stream"),
        );
        resp.body = body;
        resp
    })?;

    // HTTP/2 client; consume the stream incrementally. A `Channel` body
    // is a public variant, so we can drain its receiver directly: recv()
    // returns each chunk as it is produced and ends when the producer
    // drops the sender.
    let client_cfg = ClientConfig {
        http2: true,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);
    let resp = client.get(&format!("http://{addr}/events"))?;
    println!("status: {}", resp.status.as_u16());
    println!("content-type: {:?}", resp.headers.get("content-type"));

    let mut count = 0usize;
    if let Body::Channel(rx) = resp.body {
        while let Ok(chunk) = rx.recv() {
            let chunk = chunk?;
            if chunk.is_empty() {
                continue;
            }
            count += 1;
            print!("{}", String::from_utf8_lossy(&chunk));
        }
    }
    println!("received {count} chunks, stream ended cleanly");
    Ok(())
}
