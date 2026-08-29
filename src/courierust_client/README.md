# courierust_client

The multi-core HTTP client: an HTTP/1.1 keep-alive pool grouped by authority, HTTP/2 connections multiplexed by a dedicated driver thread, and HTTP/3 through the built-in runtime — all over the crate's own TLS when you ask for `https://`.

## The model

- **HTTP/1.1** — a keep-alive pool per authority with bounded reuse. Each connection owns its read/write buffers and a `Scratch`, so steady-state keep-alive requests perform **zero per-request allocation** and zero socket reconfiguration.
- **HTTP/2** — each connection is driven by a dedicated driver thread that serializes wire access while multiplexing streams. Requests arrive over a channel; responses stream back over per-stream channels. `max_connections_per_host` caps live connections per authority; the h2 pool is shared by authority.
- **HTTP/3** — `http3://` (and ALPN `h3`) routes into the H3 runtime's UDP reactor, with pooled connection reuse.
- **TLS** — `https://` is a first-class citizen: `TlsSettings { roots, verify, alpn, now, min_version, max_version }` against the crate's own TLS stack.

## The details that matter

- **Redirects** (301/302/303 → GET) never forward `Authorization` / `Cookie` across origins (RFC 9110 §15.4).
- **Priorities** — `execute_priority(url, req, Priority { urgency, incremental })` drives the WUCS scheduler (see `blogs/01`).
- **Worker occupancy is per connection, not per stream** — a single h2 connection with many streams holds exactly one worker, so streams never multiply worker usage and never block each other.
- **Timeouts** — connect, handshake (TLS), read, and total request timeouts, all configurable.
- **h2c prior knowledge** is opt-in (`cfg.http2 = true`); `h2c` Upgrade is supported on the server side.

## The honest bit

One h2 connection does **not** scale linearly with caller threads — the driver is a single serialization point. The benchmark suite reports this plainly (`h2_connections=1` with N concurrent streams), and the README's guidance is: 4–8 client workers per h2 connection, then add connections, not workers.

## H2 weighted connection selection

When `max_connections_per_host` forces a choice (all connections busy at the cap), the h2 pool picks the connection with the lowest **weighted load**, not merely the fewest concurrent streams:

```
load(c) = active_streams + body_units(c) + ewma_service_ms(c)
```

- `active_streams` — in-flight requests (the dispatch reservation).
- `body_units(c)` — in-flight request-body bytes in 64 KiB units. A connection carrying one 1 MiB upload is weighted ~17 units against a header-only RPC's 1 unit, so a large upload no longer hides behind a low stream count (the selection bug that made one huge body look as cheap as one small RPC).
- `ewma_service_ms(c)` — EWMA of per-request service time (dispatch → response), capped at 10 ms so a single pathological sample cannot pin a connection as permanently slow; the divisor keeps the latency term gentle so selection does not oscillate.

The accounting is exact by construction: `reserve(body_bytes)` and `release(body_bytes)` are paired on every dispatch path (including the driver-gone retry), so a connection returns to `idle` exactly when its last request completes. Idle-first: an idle connection is always preferred for reuse **regardless of its EWMA history** (an idle connection's EWMA only decays on new samples, so a pure weighted-min pick would skip it forever); the latency term only breaks ties among *busy* connections. A streaming (`Body::Channel`) request weighs 0 body units — an honest "unknown size", not a guess. This is a *selection* policy at the connection cap; it does not change the single-connection wire-serialization limit, which is structural.

## Usage

```rust
use courierust::courierust_client::{Client, ClientConfig};

let client = Client::new();
let resp = client.get("http://127.0.0.1:8080/")?;
println!("{}", String::from_utf8_lossy(&resp.body.collect()?));

let resp = client.post("http://127.0.0.1:8080/submit", b"hello")?;
```
