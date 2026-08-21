//! Redirect-following demo: the client transparently follows 302 (and
//! 301/303, which switch to GET per RFC 9110) up to `max_redirects`.
//!
//! Run with `cargo run --example redirects`.

use courierust::courierust_body::Body;
use courierust::courierust_client::Client;
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig};
use std::sync::Arc;

fn main() -> courierust::Result<()> {
    // A mini "short link" server: /start 302 -> /mid -> /end.
    let server_cfg = ServerConfig::default();
    let server = Server::bind_with_config("127.0.0.1:0", server_cfg)?;
    let addr = server.local_addr()?;
    let base = format!("http://{addr}");

    let routes = Arc::new(vec![
        ("/start".to_string(), "/mid".to_string()),
        ("/mid".to_string(), "/end".to_string()),
    ]);
    let _handle = server.serve_background(move |req: Request<Body>| -> Response<Body> {
        let path = req.uri.as_str();
        let target = routes
            .iter()
            .find(|(from, _)| from == path)
            .map(|(_, t)| t.clone());
        if let Some(next) = target {
            let mut resp = Response::with_status(302.into());
            resp.headers.insert(
                HeaderName::from_lowercase("location"),
                HeaderValue::from_bytes(next.as_bytes()).unwrap(),
            );
            resp
        } else {
            let mut resp = Response::with_status(200.into());
            resp.headers.insert(
                HeaderName::from_lowercase("x-final"),
                HeaderValue::from_static("yes"),
            );
            resp.body = Body::Bytes(courierust::courierust_bytes::Bytes::from_static(b"landed"));
            resp
        }
    })?;

    let client = Client::new();
    let resp = client.get(&format!("{base}/start"))?;
    println!(
        "GET /start -> status={} x-final={:?}",
        resp.status.as_u16(),
        resp.headers.get("x-final")
    );
    println!("final body: {}", resp.body.collect()?.to_str()?);
    Ok(())
}
