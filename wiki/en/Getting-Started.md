# Getting Started

This page gets a client and a server talking over loopback in five minutes.

## 1. Add the dependency

```toml
[dependencies]
courierust = "1.0.0"
```

The default `std` feature pulls in the client, server, pool, and gRPC layers. If you only want the `no_std` protocol core, see [no_std](no_std).

## 2. A one-file hello server + client

Save this as `examples/hello.rs`:

```rust
use courierust::courierust_body::Body;
use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig};

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
            courierust::courierust_http::header::HeaderName::from_lowercase("content-type"),
            courierust::courierust_http::header::HeaderValue::from_static("text/plain"),
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
    println!("GET  -> {} {}", resp.status.as_u16(), resp.body.collect()?.to_str()?);

    let resp = client.post(&format!("http://{addr}/echo"), "hello from client")?;
    println!("POST -> {} {}", resp.status.as_u16(), resp.body.collect()?.to_str()?);

    Ok(())
}
```

Run it:

```bash
cargo run --example hello
```

Expected output (address varies):

```
GET  -> 200 hello
POST -> 200 hello from client
```

## What just happened

- `Server::bind_with_config("127.0.0.1:0", ...)` binds an ephemeral port; `local_addr()` tells you which one.
- The handler is a plain `Fn(Request<Body>) -> Response<Body>`. It echoes whatever body it received.
- `Client::with_config` with `http2: true` uses cleartext HTTP/2 prior knowledge (h2c), so this example has no TLS by design. HTTPS uses the built-in TLS 1.2 + 1.3 path when `ClientConfig::tls` is configured; HTTP/3 uses that TLS path with ALPN `h3` and `ClientConfig::http3: true`.
- `Response::with_status(200.into())` builds an empty 200; fill `.headers` and `.body` as needed.

## Next steps

- [HTTP client](HTTP-Client) — timeouts, redirects, priorities, streaming response bodies
- [HTTP server](HTTP-Server) — streaming responses, thread count, background serving
- [gRPC](gRPC) — unary and streaming RPCs over the same stack
- [Fingerprints](Fingerprints) — make the client *look like* Chrome
