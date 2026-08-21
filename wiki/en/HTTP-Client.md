# HTTP Client

The client is multi-core by construction: HTTP/1.1 keep-alive connections are pooled per authority and **sharded per worker thread** (each shard has its own lock), and HTTP/2 connections are distributed across workers and multiplexed. Requests from different threads rarely contend.

## Configuration

```rust
use courierust::courierust_client::{Client, ClientConfig};
use std::time::Duration;

let cfg = ClientConfig {
    // Prefer HTTP/2 (h2c prior knowledge). HTTP/1.1 is used when false.
    http2: true,
    // Max keep-alive (h1) / multiplexed (h2) connections cached per host.
    max_connections_per_host: 4,
    // Timeouts are per-connect / per-read.
    connect_timeout: Some(Duration::from_secs(10)),
    read_timeout: Some(Duration::from_secs(60)),
    // Automatic redirects (301/302/303 switch to GET, per RFC 9110).
    max_redirects: 10,
    // User-Agent sent on requests (None omits it).
    user_agent: Some("my-app/1.0".to_string()),
    // Defensive limits: header list and body size accepted from a peer.
    max_header_list: 1 << 20,
    max_body: 16 * 1024 * 1024,
};

let client = Client::with_config(cfg);
// Client is cheap to clone and shares the pools internally.
let c2 = client.clone();
```

`Client::new()` is the same with all defaults.

## GET

```rust
let resp = client.get("http://127.0.0.1:8080/health")?;
println!("status: {}", resp.status.as_u16());
// Body::collect() blocks until the whole body arrives.
let body = resp.body.collect()?;
println!("body: {}", body.to_str()?);
```

## POST

`post` takes anything that converts into a `Body` — `Bytes`, `Vec<u8>`, `String`, `&'static str`, or `&'static [u8]`:

```rust
let resp = client.post("http://127.0.0.1:8080/submit", "raw text payload")?;
let resp = client.post("http://127.0.0.1:8080/submit", vec![1u8, 2, 3])?;
```

## Request with headers, and inspect the response

```rust
use courierust::courierust_body::Body;
use courierust::courierust_bytes::Bytes;
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::method::Method;
use courierust::courierust_http::request::Request;

let mut req = Request::new(Method::POST, "/api/items?page=2");
req.headers.insert(
    HeaderName::from_lowercase("content-type"),
    HeaderValue::from_static("application/json"),
);
req.headers.insert(
    HeaderName::from_lowercase("authorization"),
    HeaderValue::from_bytes(b"Bearer abc123")?,
);
req.body = Body::Bytes(Bytes::from(r#"{"name":"courierust"}"#));

let resp = client.execute("http://127.0.0.1:8080", req)?;
println!("version: {}", resp.version);
println!("x-request-id: {:?}", resp.headers.get("x-request-id"));
```

Notes:
- The request's `uri` is the **path**; the scheme/host/port come from the URL you pass to `execute`.
- `HeaderName::from_lowercase` is for lowercase static names; `from_bytes` validates and lowercases for you.
- Response headers are order-preserving; `get` returns the first matching field.

## Redirects

Redirects are on by default and capped by `max_redirects`. `301`, `302`, and `303` switch the method to `GET` (RFC 9110); the request body is dropped. Absolute, protocol-relative (`//host/...`), and relative `Location` values are all handled:

```rust
// Follows up to 10 hops automatically; the final response comes back.
let resp = client.get("http://short.example/start")?;
```

## RFC 9218 priorities (HTTP/2)

For HTTP/2 you can attach a priority to each request. The server schedules streams with a WUCS scheduler: urgency `0..=7` (0 = highest), `incremental` for streams that can be consumed as data arrives.

```rust
use courierust::courierust_h2::priority::Priority;

// Parse from the wire format ("u=1, i") or build directly:
let prio = Priority { urgency: 1, incremental: true };

let mut req = Request::new(Method::GET, "/big-download");
let resp = client.execute_priority("http://127.0.0.1:8080", req, prio)?;
```

`Priority` also implements `Default` (urgency 3, non-incremental) and `Display` (`u=3`), and can be parsed with `Priority::parse(b"u=1, i")`.

## Streaming response body (HTTP/2)

A streaming (`Channel`) response body is consumed chunk by chunk with `try_next_chunk` — useful for SSE or long downloads without buffering everything:

```rust
let resp = client.get("http://127.0.0.1:8080/events")?;
let mut body = resp.body;
while let Some(chunk) = body.try_next_chunk()? {
    // chunk: courierust::courierust_bytes::Bytes
    eprintln!("chunk: {} bytes", chunk.len());
}
```

## Error handling

Every fallible call returns `courierust::Result<T>` where the error is `courierust::Error`:

```rust
match client.get("http://127.0.0.1:9/") {
    Ok(resp) => println!("ok: {}", resp.status),
    Err(e) => {
        println!("kind: {:?}", e.kind); // Error.kind is a public field
        println!("message: {}", e);
    }
}
```

`Error` converts into `std::io::Error` (for use with `?` in io-returning code) and carries a public `kind` field for programmatic handling.

## What you should know

- **No TLS.** The built-in connector speaks `http://` only. To use HTTPS, wrap any TLS stream in `courierust::courierust_io::Read`/`io::Write` and drive the codec yourself (see [Fingerprints](Fingerprints) for the ClientHello parameters to hand to your TLS library).
- **Streaming request bodies are HTTP/2-only.** `Client::execute` materializes a `Body::Channel` request body into memory before sending; true upload streaming is a future extension.
