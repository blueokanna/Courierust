# Courierust - [中文文档](README_CN.md)

> A self-contained HTTP/1.1 + HTTP/2 + gRPC protocol stack with zero third-party dependencies.

> Hands-on tutorials (English & 中文) live on the [wiki](https://github.com/blueokanna/Courierust/wiki).

The protocol core (`courierust_http` / `courierust_hpack` / `courierust_h2` / `courierust_fingerprint` / `courierust_crypto` / `courierust_bytes` / `courierust_io`) compiles under `no_std + alloc` with **no dependencies at all**. The `std` feature (on by default) layers the threaded networking on top: a work-stealing thread pool, TCP adapters, client, server, and gRPC.

None of this wraps an existing library. Frame codecs, HPACK header compression, the stream state machine, flow control, priority scheduling, and fingerprint construction are all implemented from scratch.

## Why

The mainstream Rust HTTP ecosystem (hyper / h2 / h3 and friends) is excellent, but the dependency trees run deep, and things like `no_std` support, core affinity, and "what does this client look like to a server" are left as your problem. This crate is built around three constraints:

- **The protocol layer never touches `std`.** `std` only provides threads, TCP, and clocks.
- **Multi-core is real — within the model.** Connection pools are sharded per worker, HTTP/2 connections are spread across workers, and jobs move through a work-stealing scheduler — not one big lock. Worker occupancy is **per connection**: a single HTTP/2 connection with many streams (or a slow stream, or SSE) holds exactly one worker, so a connection's streams never multiply worker usage and never block each other. The honest corollary is that a herd of *connections* needs either many workers or the Windows event-driven mode for plain HTTP/1.1 (see Limitations).
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

- **Work-stealing thread pool** (`courierust_pool`): per-worker LIFO cache + global FIFO steal queue; jobs can spawn jobs; stealing prefers the worker idle the longest.
- **Client** (`courierust_client`):
  - HTTP/1.1 keep-alive connection pool grouped by authority and sharded per worker (per-shard locks instead of a global mutex);
  - HTTP/2 connections also sharded per worker with round-robin distribution and multiplexing;
  - Redirect following (301/302/303 → GET), timeouts, `User-Agent`, etc.
- **Server** (`courierust_server`): each accepted connection becomes a pool job, so connection handling scales across cores.
- **gRPC** (`courierust_grpc`): HTTP/2 + length-prefixed message framing + `grpc-status` / `grpc-message` handling, with unary, server-streaming, client-streaming and bidi calls on both sides. `gzip` message compression is implemented from scratch (RFC 1951/1952: full DEFLATE decompression for any producer, fixed-Huffman LZ77 compression) and negotiated per gRPC A6. Deadlines (`grpc-timeout`) are enforced server-side, metadata and interceptors are supported, `dns:///` targets round-robin, and the `grpc.health.v1.Health` service provides `Check` and `Watch`. Protobuf is deliberately left to you — implement `EncodeMessage` / `DecodeMessage` for your types, or use the raw-bytes API.
- **Streaming bodies** (`courierust_body`): channel-backed `Body::Channel` lets handlers push response chunks from another thread.

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
use courierust::courierust_client::{Client, ClientConfig};

let client = Client::new();

// GET
let resp = client.get("http://127.0.0.1:8080/")?;
println!("status={} body={}", resp.status, String::from_utf8_lossy(&resp.body.collect()?));

// POST
let resp = client.post("http://127.0.0.1:8080/submit", "hello".as_bytes())?;
```

Opt into HTTP/2 (h2c prior knowledge) and set priorities:

```rust
use courierust::courierust_h2::priority::Priority;

let mut cfg = ClientConfig::default();
cfg.http2 = true;

let client = Client::with_config(cfg);
let prio = Priority { urgency: 1, incremental: true };
let resp = client.execute_priority("http://127.0.0.1:8080/api", request, prio)?;
```

### Server

```rust
use courierust::courierust_server::{Server, ServerConfig};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_body::Body;

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
use courierust::courierust_grpc::{GrpcClient, GrpcServer};
use courierust::courierust_bytes::Bytes;

// Server side: implement Service (or just pass a closure)
let server = GrpcServer::bind("127.0.0.1:50051", |method: &str, req: Bytes| {
    Ok(Bytes::from(format!("echo({method}): {}", String::from_utf8_lossy(&req))))
})?;
let _h = server.serve_background()?;

// Client side
let client = GrpcClient::new("http://127.0.0.1:50051")?;
let reply = client.call("helloworld.Greeter/SayHello", Bytes::from("world"))?;
```

## HTTPS (built-in TLS 1.3)

Since 0.1, the crate ships a from-scratch, zero-dependency TLS 1.3
implementation (RFC 8446), so `https://` is a first-class capability of
the same client and server:

```rust
use courierust::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
use courierust::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};

// Server: serve HTTPS with your certificate chain + private key.
let identity = courierust::courierust_tls::Identity {
    cert_chain: vec![cert_der],        // leaf first (DER)
    private_key: key_der,              // PKCS#8 or PKCS#1 (DER)
    is_rsa: false,                     // false for Ed25519/ECDSA
};
let server_cfg = ServerConfig {
    http2: true,                        // h2 + HTTP/1.1 over TLS (ALPN)
    tls: Some(ServerTls {
        identity,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    }),
    ..Default::default()
};

// Client: trust your roots and enable TLS.
let mut roots = courierust::courierust_tls::RootStore::new();
roots.add_der(root_der);                // or RootStore::add_pem(...)
let client_cfg = ClientConfig {
    tls: Some(ClientTls {
        roots,
        verify: true,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        now: unix_now_secs,             // for certificate validity checks
    }),
    ..Default::default()
};
let client = Client::with_config(client_cfg);
let resp = client.get("https://example.com/")?;
```

Supported TLS 1.3 profile: `TLS_CHACHA20_POLY1305_SHA256`,
`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`; X25519 key
exchange; RSA-PSS / RSA-PKCS#1 v1.5 / ECDSA P-256 / Ed25519 certificate
signatures; full X.509 chain validation (validity windows, name
chaining, signature verification, basic-constraints / key-usage,
RFC 6125 hostname matching incl. IP SANs, plus a pluggable root store).
Run `cargo run --example https` for a self-signed end-to-end demo.

## Fingerprints: making a connection "look like" Chrome

The TLS handshake parameters are fully yours to control (including via
the built-in TLS layer):

```rust
use courierust::courierust_fingerprint::{chrome_tls_profile, ja3_hash, ja4, h2::ChromeH2Fingerprint};

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

## Limitations

Things this crate deliberately does *not* do, so you know before you commit:

- **No HTTP/3 / QUIC.** No external deps means no usable QUIC implementation (and QUIC needs a userspace UDP stack plus TLS 1.3; the TLS half exists, the transport does not).
- **TLS: no PSK / 0-RTT resumption / session tickets / key update yet, and no mutual TLS.** A full 1-RTT handshake happens every time; NewSessionTicket from a peer is ignored; the server does not request client certificates.
- **Event-driven server is Windows-only and HTTP/1.1-only.** On Windows, `ServerConfig::event_driven` (default on) parks idle plain-HTTP connections on a poller so a small worker pool serves many idle keep-alive / SSE / long-poll connections; TLS and HTTP/2 connections still use the blocking pool model. On non-Windows platforms the per-connection pool model is used.
- **Streaming request bodies are only reliable over HTTP/2** (h2 frames naturally). Over HTTP/1.1, either send the whole body at once (`Body::Bytes`) or build chunked framing yourself.
- **gRPC does not include protobuf, `.proto` code generation, or `grpc.reflection`.** You implement the codec traits or wire in your own protobuf-generated code; reflection needs a protobuf schema inventory, which is external by design.
- **A synchronous handler that blocks for a long time holds a worker** (event-driven or not) — exactly as with any synchronous server; use channel response bodies for streaming. Worker occupancy is **per-connection, not per-stream**: on one HTTP/2 connection, any number of idle streams (SSE / long-poll / gRPC server-streaming) occupy the same single worker, and a slow stream never blocks its connection's other streams — both are covered by integration tests. A large herd of *connections* still needs either many workers or the Windows event-driven mode for plain HTTP/1.1.
- **HTTPS is first-class**: the client and server ship a from-scratch TLS 1.3 implementation; `https://` needs a root store (supply your own — there is no bundled CA set). ALPN is enforced: a client configured for h2 speaking to a server that negotiates `http/1.1` (or vice versa) fails with a clear error instead of a silent protocol mismatch.
- Redirects, keep-alive reuse, and friends prioritize correctness over aggressive tuning.

## Layout

Every public module is prefixed with the crate's name (`courierust_`) so no
module path collides with a third-party crate (e.g. `h2`, `http`, `bytes`,
`grpc`, `tls`):

```
src/
├── courierust_http/        # HTTP/1.1 message model (request/response/headers/URI/status)  [no_std]
├── courierust_hpack/       # HPACK: table-driven Huffman + static/dynamic index tables      [no_std]
├── courierust_h2/          # HTTP/2 frames, SETTINGS, stream state machine, flow control, WUCS, PRIORITY_UPDATE  [no_std]
├── courierust_fingerprint/ # JA3 / JA4 / Chrome HTTP/2 fingerprints                        [no_std]
├── courierust_crypto/      # self-contained MD5 / SHA-256 (used by fingerprints)            [no_std]
├── courierust_bytes/       # byte buffers (BytesMut)                                        [no_std]
├── courierust_io/          # Read/Write traits (no_std flavor)                              [no_std]
├── courierust_error/       # unified error type
├── courierust_pool/        # work-stealing thread pool                                      [std]
├── courierust_net/         # TCP → io trait adapters                                        [std]
├── courierust_body/        # streaming response bodies (channel)                            [std]
├── courierust_h1/          # HTTP/1.1 on-the-wire codec                                      [std]
├── courierust_client/      # h1 pool + h2 driver                                            [std]
├── courierust_server/      # work-stealing-pool-backed server                               [std]
└── courierust_grpc/        # gRPC framing + status + codec traits                           [std]
```

## Benchmarks

The `benches/` package is a self-contained suite (no `criterion` required) that reports throughput and the full latency tail — **P50 / P75 / P90 / P95 / P99** for every case:

- HTTP/1.1 keep-alive, sequential and multi-worker parallel;
- HTTP/2 multiplexing across many workers;
- HTTPS (TLS 1.3 + h2) end to end through the crate's own TLS stack;
- RFC 9218 priority scheduling;
- a concurrency model comparison (idle-connection herd vs. worker pool) and a slow-sender herd benchmark.

```bash
cargo bench --manifest-path benches/Cargo.toml --bench throughput
cargo bench --manifest-path benches/Cargo.toml --bench concurrency
```

Every `RESULT|...` line carries `p50_us` … `p99_us`, and the report script (`scripts/generate_benchmark_report.sh`) turns them into a percentile table. These are loopback measurements; WAN / TLS / real-handler numbers depend on your deployment, which is exactly why the suite reports the full tail rather than a single mean.

## Interop evidence

The `benches` workspace also ships a dedicated **interop validation** suite
(`cargo bench --manifest-path benches/Cargo.toml --bench interop`) that runs
Courierust against the mainstream Rust HTTP stack over real sockets and
asserts correct semantics — not just performance:

- Courierust h1/h2c **client** → hyper h1/h2 **server**: path echo, POST
  echo, keep-alive reuse, and h2 multiplexing (concurrent requests with
  distinct paths must not be cross-wired);
- hyper-util h1/h2c **client** → Courierust **server**, and reqwest
  (blocking, h1 and h2c prior knowledge) → Courierust **server**;
- 1 MiB request/response round-trips over h2c against a real hyper server
  (flow-control window replenishment on both directions) and a slow-reader
  sanity check.

This runs in CI on every PR (`benchmark.yml`), so a real interop regression
fails the pipeline. The mainstream crates are dev-only dependencies of the
bench workspace; the `courierust` library itself stays zero-dependency.

## Tests

- 115 unit tests: all HPACK RFC vectors (C.2/C.3/C.4/C.6), Huffman encode/decode (plus a decode output cap), frame codec, state machine, flow control, WUCS scheduling, JA3/JA4 comparison against published records, fingerprint parsing, TLS 1.3 handshake + RFC 8448 key schedule, X.25519/Ed25519/ECDSA/RSA primitives, and the DEFLATE/gzip codec (round-trips, CRC-32 vectors, corruption rejection, output-cap enforcement, and cross-checked against Python zlib output).
- 37 integration tests: real loopback TCP round trips for h1/h2/HTTPS, keep-alive reuse, chunked, redirects, h2 concurrent multiplexing, streaming responses, large-body flow-control round trips, gRPC unary/server/client/bidi streaming + error status + trailers + deadline enforcement + gzip round-trip, `grpc.health.v1.Health` `Check` + `Watch`, RFC 7540 §3.2 `h2c` Upgrade, TLS trust rejection + malformed-TLS-input survival, ALPN agreement enforcement, and two concurrency proofs (a slow stream does not block its connection's other streams; many idle streams consume one worker, not one per stream).
- 30 hardening tests: hostile-frame inputs (oversized frames, malformed SETTINGS/PING/WINDOW_UPDATE, flow-control window overflow, HPACK header-list and Huffman bombs, truncated/EOS Huffman, pseudo-header ordering, `content-length` mismatches, forbidden `transfer-encoding`/`connection`-specific headers, `SETTINGS_MAX_CONCURRENT_STREAMS` enforcement on both ends, `h2c` liveness: SETTINGS_TIMEOUT and keepalive dead-peer detection).

```bash
cargo test                 # everything
cargo build --no-default-features   # confirm the core compiles warning-free
```

## License

Apache-2.0.
