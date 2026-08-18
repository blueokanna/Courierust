//! Minimal client + server demo, exactly as shown in the wiki
//! "Getting Started" page. Run with `cargo run --example hello`.

use courierust::body::Body;
use courierust::client::{Client, ClientConfig};
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::server::{Server, ServerConfig};

fn main() -> courierust::Result<()> {
    // --- server ---
    // http2 = true means the same port serves both h2c and HTTP/1.1.
    let server_cfg = ServerConfig {
        http2: true,
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg)?;
    let addr = server.local_addr()?;

    // serve_background returns a handle; the server keeps running while
    // the client below talks to it.
    let _handle = server.serve_background(|req: Request<Body>| -> Response<Body> {
        let mut resp = Response::with_status(200.into());
        resp.headers.insert(
            courierust::http::header::HeaderName::from_lowercase("content-type"),
            courierust::http::header::HeaderValue::from_static("text/plain"),
        );
        let body = req.body.collect().unwrap_or_default();
        resp.body = Body::Bytes(body);
        resp
    })?;

    // --- client ---
    let client_cfg = ClientConfig {
        http2: true,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);

    let resp = client.get(&format!("http://{addr}/hello"))?;
    println!(
        "GET  -> {} {}",
        resp.status.as_u16(),
        resp.body.collect()?.to_str()?
    );

    let resp = client.post(&format!("http://{addr}/echo"), "hello from client")?;
    println!(
        "POST -> {} {}",
        resp.status.as_u16(),
        resp.body.collect()?.to_str()?
    );

    Ok(())
}
