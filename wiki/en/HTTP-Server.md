# HTTP Server

By default the server runs an **event-driven scheduler**: an accept thread
hands sockets to an event loop that parks idle/partial plain-HTTP
connections on a readiness poller (Winsock `select` / POSIX `poll`), so a
herd of keep-alive / SSE / slow-loris connections consumes **zero**
workers. A ready connection is handed to one of a small set of event
workers, which run an incremental request parser that resumes where it
left off; a slow sender is parked again instead of holding a worker.
TLS and HTTP/2 connections run on the **work-stealing thread pool**, so
connection handling still scales across cores. A handler is just a
function — no framework types to implement.

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
    // Worker threads; 0 = bounded auto sizing (1-8 workers).
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

- The default is the event-driven connection path. It parks incomplete and
  slow plain HTTP/1.1 connections without assigning one worker per socket.
  `max_connections` defaults to 1024; `0` is an explicit unlimited setting.
  `event_driven: false` is a legacy compatibility mode and must be paired
  with a finite `max_connections` in exposed deployments.

- HTTP/1.1 responses without a body get an explicit `Content-Length: 0`; chunked encoding is emitted when the length is unknown.
- The event scheduler is the default on every platform for plain HTTP/1.1: a partial request parks on the poller (zero workers), and connections idle for `ServerConfig::idle_timeout` are reaped. `max_connections` caps the parked population. TLS and HTTP/2 connections run on the blocking pool, bounded by `handshake_timeout` / `h2_idle_timeout`. Setting `event_driven: false` restores the legacy one-pool-job-per-connection model.
- A *synchronous handler* that blocks holds its event worker for as long as it blocks — exactly like any synchronous server. Use a channel body (`Body::Channel`) for streaming so the worker returns promptly.
- gRPC servers are a thin layer on this server — see [gRPC](gRPC).
