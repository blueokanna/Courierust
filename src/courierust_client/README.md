# courierust_client

The multi-core HTTP client: an HTTP/1.1 keep-alive pool grouped by authority, HTTP/2 connections multiplexed by a dedicated driver thread, and HTTP/3 through the built-in runtime — all over the crate's own TLS when you ask for `https://`.

## The model

- **HTTP/1.1** — a keep-alive pool per authority with bounded reuse. Each connection owns its read/write buffers and a `Scratch`, so steady-state keep-alive requests perform **zero per-request allocation** and zero socket reconfiguration.
- **HTTP/2** — each connection is driven by a dedicated driver thread that serializes wire access while multiplexing streams. Requests arrive over a channel; responses stream back over per-stream channels. `max_connections_per_host` caps live connections per authority; the h2 pool is shared by authority.
- **HTTP/3** — `http3://` (and ALPN `h3`) routes into the H3 runtime's UDP reactor, with pooled connection reuse.
- **WebSocket** — `courierust_client::ws::WebSocket` upgrades over `ws://` or TLS (`wss://`) and exposes `send_text` / `send_binary` / `send_ping` / `read_message` / `close` with subprotocols, an Origin header, a compression preference and a read deadline, all from the same `ClientConfig`. It shares the framing / UTF-8 / close-handshake engine (`courierust_ws`) with the server, so both ends enforce the same rules.
- **TLS** — `https://` is a first-class citizen: `TlsSettings { roots, verify, alpn, now, min_version, max_version }` against the crate's own TLS stack.

## The details that matter

- **Redirects** (301/302/303 → GET) never forward `Authorization` / `Cookie` / `Proxy-Authorization` across origins (RFC 9110 §15.4). The body-less follow-up also drops `Content-Length` / `Content-Type` / `Transfer-Encoding`: a length with no bytes behind it is how a request desynchronises the connection it is written on. A 307/308 that would have to replay the body is **handed back** instead of followed — the body is gone (a streaming body cannot be replayed), so following it would send a different request than the caller wrote.
- **Priorities** — `execute_priority(url, req, Priority { urgency, incremental })` drives the WUCS scheduler (see `blogs/01`).
- **Worker occupancy is per connection, not per stream** — a single h2 connection with many streams holds exactly one worker, so streams never multiply worker usage and never block each other.
- **Timeouts** — connect, handshake (TLS), read, and total request timeouts, all configurable.
- **A WebSocket read deadline is a socket deadline.** `ClientConfig::read_timeout` (60 s by default) is the right liveness mechanism for interactive traffic, but on Windows it is charged on every blocking operation: a 256 KiB WebSocket bulk push runs roughly **2× slower** with it armed. A bulk-transfer client should set `read_timeout: None` and use application-level liveness instead — the server does exactly that (measurements: [`courierust_ws` README](../courierust_ws/README.md)).
- **h2c prior knowledge** is opt-in (`cfg.http2 = true`); `h2c` Upgrade is supported on the server side.
- **Content coding** — `accept_encoding` (default on) offers `gzip, deflate` and decodes the same set, because offering a coding nothing decodes hands the caller bytes that look like garbage. A coding the client has **no decoder for** (say `br`) is passed through byte-for-byte with its `content-encoding` label intact, so the caller can see what it is holding rather than receive data it cannot interpret. A coding the client *does* understand is decoded even if the caller picked its own `accept-encoding` and the server ignored that choice — but the caller's header is never rewritten. Decoding obeys `max_body`, so a compression bomb is an error and not an allocation. Turn the whole feature off with `accept_encoding: false` — offer *and* decode, never one without the other.
- **Forward proxy** — `ClientConfig.proxy = Some("http://user:pass@host:3128")`. `http://` targets go to the proxy in **absolute-form** (RFC 9110 §3.2.2), so the proxy resolves the origin name — which is the reason a client sits behind one. `https://` targets get a `CONNECT` tunnel first, and TLS is then negotiated **end to end with the origin**: the proxy forwards ciphertext and can neither read it nor substitute a certificate. Credentials in the URL become `Proxy-Authorization: Basic …`, sent to the proxy only. Two things are deliberately unsupported and are **errors, not silent fallbacks**: an `https://` proxy (that needs TLS inside TLS, which the transport does not have) and a proxy combined with clear-text h2c or HTTP/3. No environment variable (`HTTP_PROXY`, `NO_PROXY`) is read — configuration this crate cannot see is configuration it cannot be honest about.

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

### Talking to real servers over real `https://`

`Client::new()` installs **no** trust anchors, and neither does `RootStore::new()` — an empty store fails every verification, loudly. That is the right default (a client that silently trusts whatever it can find is a client nobody can reason about), but it means the first `https://` request needs to say where trust comes from:

```rust
use courierust::courierust_client::Client;

// The OS trust store: `ROOT` on Windows, the usual PEM bundles on Unix.
let client = Client::with_system_roots()?;
let resp = client.get("https://example.com/")?;
```

`Client::with_system_roots()` is `TlsSettings::with_system_roots()` plus `http2: true`, so it negotiates `h2` when the server offers it. To add public roots to a client you configured yourself, use `Client::with_tls_roots(roots)` or build the `TlsSettings` directly and keep `verify: true`.
