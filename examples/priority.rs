//! RFC 9218 priority demo: two request classes over one HTTP/2
//! connection, showing that a high-urgency stream is scheduled ahead of
//! a backlog of low-urgency work (WUCS anti-starvation).
//!
//! Run with `cargo run --example priority`.

use courierust::body::Body;
use courierust::client::{Client, ClientConfig};
use courierust::h2::priority::Priority;
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::server::{Server, ServerConfig};
use std::time::Instant;

fn main() -> courierust::Result<()> {
    let server_cfg = ServerConfig {
        http2: true,
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg)?;
    let addr = server.local_addr()?;
    let _handle = server.serve_background(|_req: Request<Body>| -> Response<Body> {
        // Slight delay so streams actually interleave on the wire.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut resp = Response::with_status(200.into());
        resp.body = Body::Bytes(courierust::bytes::Bytes::from_static(b"ok"));
        resp
    })?;

    let client_cfg = ClientConfig {
        http2: true,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);
    let url = format!("http://{addr}/bench");

    let low = Priority {
        urgency: 7,
        incremental: false,
    };
    let high = Priority {
        urgency: 0,
        incremental: false,
    };

    // Pile up 32 low-urgency requests in flight...
    let mut lows = Vec::new();
    for _ in 0..32 {
        let c = client.clone();
        let u = url.clone();
        lows.push(std::thread::spawn(move || {
            let req = Request::new(courierust::http::method::Method::GET, "/low");
            let _ = c.execute_priority(&u, req, low);
        }));
    }

    // ...then a single high-urgency request. WUCS must not let the low
    // backlog starve it.
    let start = Instant::now();
    let req = Request::new(courierust::http::method::Method::GET, "/high");
    let resp = client.execute_priority(&url, req, high)?;
    let elapsed = start.elapsed();
    assert_eq!(resp.status.as_u16(), 200);

    for h in lows {
        let _ = h.join();
    }
    println!(
        "high-urgency request completed in {:?} despite 32 low-urgency requests in flight",
        elapsed
    );
    println!("(low urgency = {}, high urgency = {})", low, high);
    Ok(())
}
