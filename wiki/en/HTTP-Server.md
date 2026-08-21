# HTTP Server

The server accepts connections and submits each one as a job to a **work-stealing thread pool**, so connection handling scales across cores. A handler is just a function — no framework types to implement.

## The handler

A handler is any `Fn(Request<Body>) -> Response<Body> + Send + Sync + 'static`. Closures work out of the box:

```rust
use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;

let handler = |req: Request<Body>| -> Response<Body> {
    let mut resp = Response::with_status(200.into());
    resp.body = Body::Bytes(Bytes::from(format!("path: {}", req.uri.as_str())));
    resp
};
```

For anything non-trivial, use a struct (the fields are your own application state):

```rust
use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use std::sync::Arc;

// `Db` here is your own application type, not something from the crate.
// Handler requires Send + Sync, so Db must satisfy both.
struct App {
    db: Arc<dyn Db>,
}

// Any type implementing the Handler trait works:
impl courierust::courierust_server::Handler for App {
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        match req.uri.as_str() {
            "/health" => Response::with_status(200.into()),
            _ => {
                let mut resp = Response::with_status(404.into());
                resp.body = Body::Bytes(Bytes::from_static(b"not found"));
                resp
            }
        }
    }
}
```

## Configuration

```rust
use courierust::courierust_server::{Server, ServerConfig};
use std::time::Duration;

let cfg = ServerConfig {
    // Serve HTTP/2 (prior knowledge) on the same port as HTTP/1.1.
    http2: true,
    // Worker threads; 0 = logical core count.
    threads: 0,
    read_timeout: Some(Duration::from_secs(120)),
    max_header_list: 1 << 20,
    max_body: 16 * 1024 * 1024,
};
```

## Blocking serve

```rust
let server = Server::bind_with_config("0.0.0.0:8080", cfg)?;
server.serve(app)?; // blocks forever
```

## Background serve (for tests and embedding)

```rust
let server = Server::bind_with_config("127.0.0.1:0", cfg)?;
let addr = server.local_addr()?;      // real bound port
let handle = server.serve_background(app)?;

// ... run tests / do other work ...
// Dropping the handle stops accepting; connections drain.
drop(handle);
```

## Streaming a response body

Return a `Body::Channel` and the server streams it with flow-control backpressure: chunks are only drained from the channel when the connection has send window available, so a slow client cannot balloon memory.

```rust
let handler = |_req: Request<Body>| -> Response<Body> {
    let (tx, body) = courierust::courierust_body::channel();
    std::thread::spawn(move || {
        for i in 0..100 {
            // tx.send blocks if the receiver is dropped; returns Result.
            let _ = tx.send(Bytes::from(format!("event {i}\n")));
        }
        drop(tx); // closing the sender ends the stream
    });
    let mut resp = Response::with_status(200.into());
    resp.body = body;
    resp
};
```

Send an error mid-stream with `tx.fail(err)` — the connection resets that stream with `INTERNAL_ERROR`.

## Notes

- HTTP/1.1 responses without a body get an explicit `Content-Length: 0`; chunked encoding is emitted when the length is unknown.
- `Server::serve` submits each accepted connection as one pool job. A slow request holds a worker until it finishes reading — fine for typical workloads; very long-lived connections may warrant splitting the event loop yourself.
- gRPC servers are a thin layer on this server — see [gRPC](gRPC).
