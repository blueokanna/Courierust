# HTTP Client

The client shares bounded pools per authority. HTTP/2 requests are multiplexed by a dedicated driver per connection and assigned by current dispatch reservations; `max_connections_per_host` controls how many independent drivers may be opened under contention. This is connection-aware concurrency, not a promise that one HTTP/2 connection scales linearly with caller threads.

## Configuration

```rust
use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_http::header::HeaderMap;
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
    // Fields added to every request this client initiates. A field on the
    // request itself always wins; a cross-origin redirect drops
    // authorization / proxy-authorization / cookie from either source.
    default_headers: HeaderMap::new(),
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

## Request builder

`Client::request(url, method)` returns a `RequestBuilder`: it builds the same `Request` the hand-written form below sends, and hands it to the same path, so redirects, pools and all three protocols behave identically. `Client::{put, delete, head, patch, options}` are the one-call shorthands.

```rust
use courierust::courierust_http::Method;

let resp = client
    .request("http://127.0.0.1:8080/api/items", Method::POST)
    .query([("page", "2")])          // appended to the URL, percent-encoded
    .form([("name", "widget")])      // body + content-type, urlencoded
    .header("accept", "application/json")
    .basic_auth("user", "secret")    // or .bearer_auth("token")
    .timeout(std::time::Duration::from_secs(5))
    .send()?;
println!("{}", resp.text()?);
```

- `query` / `form` use the WHATWG `application/x-www-form-urlencoded` encoding (`courierust_http::form`): a space becomes `+`, anything outside `A-Za-z0-9*-._` becomes `%XX`.
- `timeout` overrides `ClientConfig::read_timeout` **for this request**: a transport deadline with the same meaning, applied per attempt and restored afterwards, so the connection returns to the pool with the configured value. It applies to h1, h2 and h3 alike.
- `priority` is an RFC 9218 hint: HTTP/2 reads it (it feeds the WUCS scheduler), HTTP/1.1 and HTTP/3 have no field to carry it and send the request unchanged.
- `resp.text()` / `resp.bytes()` consume the body; `text` refuses a body that is not valid UTF-8 rather than substituting U+FFFD.

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

Redirects are on by default and capped by `max_redirects`. `301`, `302`, and `303` switch the method to `GET` (RFC 9110) and drop the request body; `307` and `308` keep both the method and the body, and a body that only existed as a stream (so it cannot be replayed) fails the hop with an explicit error rather than being sent empty. Absolute, protocol-relative (`//host/...`), and relative `Location` values are all handled:

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

- **HTTPS uses the built-in TLS 1.2 + TLS 1.3 implementation when configured.** The default client has `tls: None` and rejects `https://`; provide a `RootStore` through `ClientConfig::tls` or use `Client::with_tls_roots`. There is no bundled CA set. ALPN must agree with `ClientConfig::http2` (`h2` for HTTP/2, `http/1.1` otherwise).
- **HTTP/2 concurrency is connection-policy dependent.** Requests are multiplexed by one driver per connection. Set `max_connections_per_host` above one when independent HTTP/2 drivers are needed for caller-level parallelism; benchmark the full latency tail for the selected value.
- **Streaming request bodies are HTTP/2-only.** `Client::execute` materializes a `Body::Channel` request body into memory before sending; use `execute_h2_stream` for true client-streaming uploads.  
- **The HTTP/1.1 keep-alive pool probes before it reuses.** A pooled connection is checked for liveness first, so a server that closed it while it sat idle costs nothing — nothing is written, which is why even a non-idempotent method is safe on a fresh connection. If a pooled connection dies mid-request, the request is retried exactly once on a fresh connection and only when the method is safe to replay (RFC 9110 §9.2.2: GET/HEAD/OPTIONS/TRACE/PUT/DELETE/PROPFIND) — a `POST` returns the failure instead of risking a second execution.

## WebSocket client

The same client speaks WebSockets — `ws://` and `wss://`, the second through
the crate's own TLS stack — with `ClientConfig` supplying the read deadline:

```rust
use courierust::courierust_client::ClientConfig;
use courierust::courierust_client::ws::WebSocket;

let mut ws = WebSocket::connect("wss://example.com/ws", &ClientConfig::default())?;
ws.send_text("hello")?;
println!("{:?}", ws.read_message()?);   // Event::Text("hello")
ws.close(1000, "done")?;
```

It shares the framing / UTF-8 / close-handshake engine with the server, so
both ends enforce the same rules; the tutorial (options, negotiation,
deployment, honest notes) is [WebSockets](WebSockets).
