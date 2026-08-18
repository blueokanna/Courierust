//! HTTP/2 (h2c) end-to-end example: a loopback server and client.
//!
//! Run with `cargo run --example diag`.

use courierust::body::Body;
use courierust::client::{Client, ClientConfig};
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::server::{Server, ServerConfig};

fn main() -> courierust::Result<()> {
    let server_cfg = ServerConfig {
        http2: true,
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg)?;
    let addr = server.local_addr()?;
    let _handle = server.serve_background(|req: Request<Body>| -> Response<Body> {
        let body = req.body.collect().unwrap_or_default();
        let mut resp = Response::<Body>::with_status(200.into());
        resp.body = Body::Bytes(body);
        resp
    })?;

    let client_cfg = ClientConfig {
        http2: true,
        ..Default::default()
    };
    let client = Client::with_config(client_cfg);

    let url = format!("http://{addr}/hello");
    let resp = client.get(&url)?;
    println!("GET  {} -> {}", url, resp.status);

    let mut req = Request::new(courierust::http::method::Method::POST, "/echo");
    req.body = Body::Bytes("hello over h2".into());
    let resp = client.execute(&format!("http://{addr}/echo"), req)?;
    let echoed = resp.body.collect()?;
    println!("POST /echo -> {}", echoed.to_str().unwrap_or("<binary>"));

    Ok(())
}
