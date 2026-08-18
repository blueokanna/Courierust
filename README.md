# Courierust - [中文文档](README.md)

> A self-contained HTTP/1.1 + HTTP/2 + gRPC protocol stack with zero third-party dependencies.

> Hands-on tutorials (English & 中文) live on the [wiki](https://github.com/blueokanna/Courierust/wiki).

The protocol core (`http` / `hpack` / `h2` / `fingerprint` / `crypto` / `bytes` / `io`) compiles under `no_std + alloc` with **no dependencies at all**. The `std` feature (on by default) layers the threaded networking on top: a work-stealing thread pool, TCP adapters, client, server, and gRPC.

None of this wraps an existing library. Frame codecs, HPACK header compression, the stream state machine, flow control, priority scheduling, and fingerprint construction are all implemented from scratch.

## Why

The mainstream Rust HTTP ecosystem (hyper / h2 / h3 and friends) is excellent, but the dependency trees run deep, and things like `no_std` support, core affinity, and "what does this client look like to a server" are left as your problem. This crate is built around three constraints:

- **The protocol layer never touches `std`.** `std` only provides threads, TCP, and clocks.
- **Multi-core is real.** Connection pools are sharded per worker, HTTP/2 connections are spread across workers, and jobs move through a work-stealing scheduler — not one big lock.
- **The wire details are implemented against the RFCs and verified against published test vectors**, not "good enough to pass a smoke test."

## Features

### Protocol core (no_std + alloc, zero deps)

- **HTTP/1.1**: request/response parsing and serialization, keep-alive, chunked transfer, `100-continue` handling.
- **HTTP/2 (RFC 9113)**:
  - Full frame codec (DATA / HEADERS / PRIORITY / RST_STREAM / SETTINGS / PUSH_PROMISE / PING / GOAWAY / WINDOW_UPDATE / CONTINUATION);
  - Per-stream and connection-level flow control, windows advanced per frame;
  - Stream state machine following §5.1 strictly — illegal transitions end in `PROTOCOL_ERROR`;
  - Stream priorities (RFC 9218): parses the `Priority` header and `PRIORITY_UPDATE` frames (type `0x10`), backed by the built-in **WUCS scheduler** (below).
- **HPACK (RFC 7541)**:
  - 61-entry static table + dynamic table + hash-accelerated index lookups;
  - 8-bit two-level table-driven Huffman decode (built at compile time), fast path for short codes;
  - Byte-for-byte verified against the official RFC C.2–C.6 vectors.
- **Fingerprints**:
  - `TlsProfile` describes the parameters of a TLS ClientHello; includes self-contained MD5 / SHA-256 (no deps);
  - **JA3**: `ja3_hash()` produces the standard 32-hex-digit fingerprint, matching the published Chrome record;
  - **JA4**: `ja4()` produces the four-part `t13d1516h2_…` fingerprint, matching the spec example;
  - **Chrome HTTP/2 fingerprint**: SETTINGS entries, initial `WINDOW_UPDATE`, frame order, and header ordering all mirror Chrome behavior, ready to feed to an external TLS layer.

### std networking layer

- **Work-stealing thread pool** (`pool`): per-worker LIFO cache + global FIFO steal queue; jobs can spawn jobs; stealing prefers the worker idle the longest.
- **Client** (`client`):
  - HTTP/1.1 keep-alive connection pool grouped by authority and sharded per worker (per-shard locks instead of a global mutex);
  - HTTP/2 connections also sharded per worker with round-robin distribution and multiplexing;
  - Redirect following (301/302/303 → GET), timeouts, `User-Agent`, etc.
- **Server** (`server`): each accepted connection becomes a pool job, so connection handling scales across cores.
- **gRPC** (`grpc`): HTTP/2 + length-prefixed message framing + `grpc-status` / `grpc-message` handling. Protobuf is deliberately left to you — implement `EncodeMessage` / `DecodeMessage` for your types, or use the raw-bytes API.
- **Streaming bodies** (`body`): channel-backed `Body::Channel` lets handlers push response chunks from another thread.

## The parts that actually took work: multi-core and scheduling

A `no_std` protocol core is a weekend project. Making it pay off across cores is not.

### WUCS — Weighted-Urgency Calendar Scheduler (RFC 9218)

RFC 9218 replaces the old dependency-tree model with 8 urgency levels. We implement it as a calendar scheduler over 8 buckets:

- Each bucket is a **DRR (Deficit Round Robin)** class with a byte quantum, so a busy high-urgency bucket cannot starve lower-urgency traffic (RFC 9218 §10 explicitly requires anti-starvation);
- **Incremental** streams inside a bucket are served round-robin (bandwidth is shared as data arrives); **non-incremental** streams are FIFO by stream ID, matching the RFC's "ascending stream ID" recommendation;
- The per-frame choice is **O(1)**: a fixed 8-bucket scan, no sorting, no heap — cheap enough to run every frame on a hot connection.

A `Priority { urgency, incremental }` can be parsed from the `Priority` header / `PRIORITY_UPDATE` frame, or passed directly via `Client::execute_priority`.

### BCR — Batched Credit Reflow flow control

The naive implementation replies with a `WINDOW_UPDATE` per frame, and control-frame overhead adds up. BCR accumulates received data and returns credit in batches, cutting control frames by roughly an order of magnitude.

### Sharded connection pools

The client pool is not one `HashMap` under a global lock. Each worker holds its own shard; HTTP/2 connections are distributed round-robin across workers. Requests rarely contend across workers, so scaling tracks core count instead of lock contention.

## Quick start

### Client

```rust
use courierust::client::{Client, ClientConfig};

let client = Client::new();

// GET
let resp = client.get("http://127.0.0.1:8080/")?;
println!("status={} body={}", resp.status, String::from_utf8_lossy(&resp.body.collect()?));

// POST
let resp = client.post("http://127.0.0.1:8080/submit", "hello".as_bytes())?;
```

Opt into HTTP/2 (h2c prior knowledge) and set priorities:

```rust
use courierust::h2::priority::Priority;

let mut cfg = ClientConfig::default();
cfg.http2 = true;

let client = Client::with_config(cfg);
let prio = Priority { urgency: 1, incremental: true };
let resp = client.execute_priority("http://127.0.0.1:8080/api", request, prio)?;
```

### Server

```rust
use courierust::server::{Server, ServerConfig};
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::body::Body;

let mut cfg = ServerConfig::default();
cfg.http2 = true; // serves h2c and h1.1 on the same port
let server = Server::bind_with_config("127.0.0.1:8080", cfg)?;

server.serve(|req: Request<Body>| -> Response<Body> {
    let mut resp = Response::with_status(200.into());
    resp.body = Body::Bytes(format!("path: {}", req.uri.as_str()).into());
    resp
})?;
```

### gRPC

```rust
use courierust::grpc::{GrpcClient, GrpcServer};
use courierust::bytes::Bytes;

// Server side: implement Service (or just pass a closure)
let server = GrpcServer::bind("127.0.0.1:50051", |method: &str, req: Bytes| {
    Ok(Bytes::from(format!("echo({method}): {}", String::from_utf8_lossy(&req))))
})?;
let _h = server.serve_background()?;

// Client side
let client = GrpcClient::new("http://127.0.0.1:50051")?;
let reply = client.call("helloworld.Greeter/SayHello", Bytes::from("world"))?;
```

## Fingerprints: making a connection "look like" Chrome

The TLS handshake itself is usually done by an external library, but the fingerprint parameters are yours to control:

```rust
use courierust::fingerprint::{chrome_tls_profile, ja3_hash, ja4, h2::ChromeH2Fingerprint};

let profile = chrome_tls_profile();
assert_eq!(ja3_hash(&profile), "cd08e31494f9531f560d64c695473da9");
assert_eq!(ja4(&profile), "t13d1516h2_8daaf6152771_e5627efa2ab1");

// HTTP/2 side: get a Chrome-shaped SETTINGS / frame order / header order directly
let fp = ChromeH2Fingerprint::chrome();
let mut settings = fp.settings_entries(); // includes WINDOW_UPDATE, MAX_FRAME_SIZE, ...
let ordered = fp.order_headers_chrome(&fields); // reorder headers the way Chrome does
```

## no_std usage

The protocol core does not require `std`:

```toml
[dependencies]
courierust = { version = "0.1", default-features = false }
```

Building with `--no-default-features` compiles only the protocol core, suitable for embedded / kernel contexts. The networking layer needs the `std` feature (the default).

## Honest limitations

Things this crate deliberately does *not* do, so you know before you commit:

- **No built-in TLS.** That is both the price of zero deps and the point: h2c (HTTP/2 over clear TCP with prior knowledge) and HTTP/1.1 work directly; for HTTPS, wrap any TLS stream in the `io::Read` / `io::Write` traits and drive the same codec. `TlsProfile` exists precisely for this — the fingerprint parameters are yours, and the TLS library you choose uses them in its own handshake.
- **No HTTP/3 / QUIC.** Same reason: no external deps means no usable implementation.
- **Streaming request bodies are only reliable over HTTP/2** (h2 frames naturally). Over HTTP/1.1, either send the whole body at once (`Body::Bytes`) or build chunked framing yourself.
- **gRPC does not include protobuf.** You implement the codec traits or wire in your own protobuf-generated code.
- **The server is "one pool job per connection."** A slow request holds a worker until it finishes reading. Fine for most workloads; very long-lived connections may eventually warrant a split event loop.
- Redirects, keep-alive reuse, and friends prioritize correctness over aggressive tuning.

## Layout

```
src/
├── http/        # HTTP/1.1 message model (request/response/headers/URI/status)  [no_std]
├── hpack/       # HPACK: table-driven Huffman + static/dynamic index tables      [no_std]
├── h2/          # HTTP/2 frames, SETTINGS, stream state machine, flow control, WUCS, PRIORITY_UPDATE  [no_std]
├── fingerprint/ # JA3 / JA4 / Chrome HTTP/2 fingerprints                        [no_std]
├── crypto/      # self-contained MD5 / SHA-256 (used by fingerprints)            [no_std]
├── bytes/       # byte buffers (BytesMut)                                        [no_std]
├── io/          # Read/Write traits (no_std flavor)                              [no_std]
├── error/       # unified error type
├── pool/        # work-stealing thread pool                                      [std]
├── net/         # TCP → io trait adapters                                        [std]
├── body/        # streaming response bodies (channel)                            [std]
├── h1/          # HTTP/1.1 on-the-wire codec                                      [std]
├── client/      # h1 pool + h2 driver                                            [std]
├── server/      # work-stealing-pool-backed server                               [std]
└── grpc/        # gRPC framing + status + codec traits                           [std]
```

## Tests

- 49 unit tests: all HPACK RFC vectors (C.2/C.3/C.4/C.6), Huffman encode/decode, frame codec, state machine, flow control, WUCS scheduling, JA3/JA4 comparison against published records, fingerprint parsing.
- 9 integration tests: real loopback TCP round trips for h1/h2, keep-alive reuse, chunked, redirects, h2 concurrent multiplexing, streaming responses, gRPC unary and error status.

```bash
cargo test                 # everything
cargo build --no-default-features   # confirm the core compiles warning-free
```

## License

Apache-2.0.
