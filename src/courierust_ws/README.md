# courierust_ws

A complete RFC 6455 WebSocket implementation — framing, masking, UTF-8 validation, the handshake, the close handshake, fragment reassembly, and RFC 7692 `permessage-deflate` — with **zero third-party dependencies**, and a server/client integration that reuses the crate's own TCP/TLS stack.

Everything here is `no_std + alloc` except the pieces that genuinely need a socket (entropy for masking keys, `SharedSink`, the client). The protocol core never allocates per frame except for the message payload the caller receives.

```
frame.rs      wire format: headers, opcodes, masking, sinks (StreamSink, SharedSink, VecSink)
utf8.rs       incremental UTF-8 validation that never copies the message
handshake.rs  the HTTP upgrade: key check, Origin policy, extensions, subprotocol selection
writer.rs     outbound framing + compression decisions, one lock per frame
session.rs    the bidirectional state machine: read, write, limits, close
```

## Why it is fast

Measured against `tungstenite 0.30` on the same machine, same process, same build profile (details, methodology and the full tables are in [`benches/WS_BENCHMARK.md`](../../benches/WS_BENCHMARK.md)):

| operation (64 B) | courierust | tungstenite | |
|---|---:|---:|---|
| encode, server (unmasked) | 5.7 ns | 12.9 ns | 2.3× faster |
| encode, client (masked) | 15.2 ns | 40.0 ns | 2.6× faster |
| mask in place | 2.4 ns | — | 25 GB/s |

| operation (256 KiB) | courierust | tungstenite | |
|---|---:|---:|---|
| encode, client (masked) | 9.5 µs | 90-99 µs | ~10× faster |
| one-way push, server → client | 74 µs | 73 µs | parity |

Four decisions carry most of that:

1. **Masking in 16-byte lanes.** A 4-byte repeating key XORed in a loop cannot vectorize, because the key changes with `i & 3`. Sixteen is a multiple of four, so *every* 16-byte lane starts at the same key phase: the body becomes `lane ^= constant` over one precomputed `u128`, which the compiler turns into wide SIMD, and the tail is the same trick with `u32`. That single observation is the difference between 23 GB/s and 36 GB/s of masking.
2. **Zero-copy payloads on the read path.** A frame header is parsed straight out of the read buffer (`FrameHeader::header_len_hint` avoids a copy even before parsing), and a payload remainder above 8 KiB is read *directly into the message buffer* — no copy through the buffered reader. The mask is applied in place on arrival, fused with the read.
3. **Reusable DEFLATE context.** `MatchFinder` (the 128 KiB hash table and the chain table) lives in the `Deflater` and is reset in time proportional to the message, not to the table. A naive per-message context costs ~40 µs of `memset` before any compression happens, which is more than the compression itself for a small message.
4. **One write per small frame.** Frames up to 64 KiB are coalesced into a staging buffer and written with a single syscall; larger ones stream from the caller's buffer (unmasked) or in windows up to 1 MiB (masked). One syscall is what small-message latency actually responds to.

## Security posture

- **Mask direction is enforced in both directions.** A server fails the connection on an unmasked client frame; a client fails on a masked server frame (§5.1). Getting this backwards is how intermediaries get cache-poisoned.
- **Origin is checked by default.** `OriginPolicy::SameOrigin` is the default: a browser page on another site cannot open an authenticated WebSocket, because the browser will present the session cookies with the upgrade. `OriginPolicy::NoOrigin` is for non-browser clients, `List` for an explicit allow-list, `Any` for a deliberate opt-out.
- **`X-Forwarded-*` is only believed from a proxy you named.** `trusted_proxies: Vec<IpNet>` decides when `X-Forwarded-For` / `X-Forwarded-Proto` may override the peer address; an untrusted header is ignored, so a client cannot spoof its own IP or claim to be on TLS.
- **Strict handshake validation.** Exactly one `Sec-WebSocket-Key` of canonical base64 length, `Sec-WebSocket-Version: 13`, `Connection: Upgrade` as a token list, minimal-length length encodings, control frames never fragmented and never longer than 125 bytes, RSV bits gated on negotiation, close codes validated against the legal sets for each direction.
- **Bounded everything.** `max_frame`, `max_message`, `max_fragments`, `max_send_queue`: a peer cannot make the connection translate a claim into memory, and `permessage-deflate` inflation is bounded by the same message limit (a zip bomb hits 1009, not OOM — tested).
- **The close handshake is enforced, not suggested.** The “nothing after a Close frame” rule (RFC 6455 §5.5.1) lives on a *shared* flag on the connection, so a push from an application thread that races a close is refused with `ErrorKind::Canceled` instead of writing a data frame the peer could fail the connection over. The session's writer and the application's writer on the same socket see the same flag.
- **`Host` is required for HTTP/1.1** (RFC 9112 §3.2), in both server drivers and before any handler or WebSocket policy runs: a request that two hops could disagree about is refused with `400` rather than routed. Missing, duplicated, or empty `Host` all fail closed; `HTTP/1.0` may omit it.
- **A transport failure is not a protocol error.** Only a peer protocol violation or an oversized message is answered with a Close frame (`1002`/`1007`/`1009`); a broken socket is reported to the application as `code = None, clean = false` instead of dressing it up as the peer's fault.
- **Fused and honest limits.** A frame that exceeds a limit fails with 1009 before its bytes are buffered; an invalid text message is rejected at the offset that broke it (1007), with the reason truncated on a UTF-8 boundary.
- **Masking keys from a CSPRNG.** A ChaCha20 stream seeded from platform entropy, one key per frame — not a counter, not a timestamp.

## Deployment: terminate TLS at the proxy

The recommended production shape is a reverse proxy in front, doing TLS (so `wss://`) and, if you want, HTTP/2 or HTTP/3 for everything else:

```nginx
# nginx
location /ws/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;

    # The upgrade handshake itself
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    # Real client address: only trust this from your own proxy.
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Do not buffer frames: it destroys latency and can stall the stream.
    proxy_buffering off;

    # A WebSocket is idle between messages by design; the *application*
    # keepalive (ping_interval) is what keeps it alive, so the proxy
    # timeout must be longer than that.
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
```

With Traefik:

```yaml
http:
  routers:
    ws:
      rule: "Host(`example.com`) && PathPrefix(`/ws`)"
      service: app
      entryPoints: [websecure]
      tls: {}
```

Then configure the server to match:

```rust
let ws = WsConfig {
    origin: OriginPolicy::List(vec!["https://app.example.com".into()]),
    trusted_proxies: vec![IpNet::parse("127.0.0.1/32")?, IpNet::parse("10.0.0.0/8")?],
    ..Default::default()
};
```

Two rules that are easy to get wrong:

- **Keep the proxy's read timeout longer than `ping_interval`.** A proxy that closes an idle WebSocket will drop connections that were perfectly healthy; the Ping/Pong keepalive is what makes the connection look alive in between.
- **Never trust `X-Forwarded-For` without `trusted_proxies`.** With it unset, our `client_ip` is the peer address of the socket (the proxy), which is safe. With it set, only requests arriving from a listed network may override it.

## The honest bits

- **RFC 8441 (WebSocket over HTTP/2) is not implemented.** The client offers **only** `http/1.1` in ALPN — even when `ClientConfig::http2` is `true` — and refuses a connection that ends up on h2 before reading a frame. On the server side, a WebSocket attempt on an *established* h2 connection is a malformed message and is rejected as a **stream error (`PROTOCOL_ERROR`, RFC 9113 §8.1.1)**, in both forms: RFC 8441's extended CONNECT (`:method = CONNECT` with `:protocol = websocket`, an undefined pseudo-header for this stack — exactly the rejection RFC 8441 §3 describes for a peer that never advertised `SETTINGS_ENABLE_CONNECT_PROTOCOL`) and the HTTP/1.1-style `Upgrade: websocket` / `Connection: Upgrade` fields (connection-specific fields, §8.2.2). The connection and its other streams keep working. What never happens is the two failure modes worth naming: a `200` on a request that could not become a WebSocket, and a connection that looks established and carries no frame. Use HTTP/1.1 for WebSockets, as almost everyone does.
- **`permessage-deflate` compresses each message independently.** Context takeover is never used by our encoder, which is always legal (a decoder's window is a superset) and removes the class of bugs where one message's plaintext leaks into another. The cost is a bounded ratio loss on streams of tiny repetitive messages — and it is the reason a server can hold thousands of connections without 32 KiB of sliding window each.
- **`SO_RCVTIMEO` is armed only while idle.** Windows charges for a socket deadline on every blocking operation, including writes: measured, a 256 KiB push loop is ~2× slower with the deadline armed on the sender's socket and ~10× slower with one armed on both ends. Our blocking server therefore arms the deadline only while waiting for the next frame and clears it while a message is being handled (`ping_interval` stays the liveness mechanism). The **client** keeps the deadline from `ClientConfig::read_timeout` for the whole connection, which is the right default for interactive traffic but costs roughly 2× on 256 KiB bulk transfers on Windows — a bulk-transfer client should set `read_timeout: None` and rely on application-level liveness, exactly as the server does. The numbers behind both statements are in [`benches/WS_BENCHMARK.md`](../../benches/WS_BENCHMARK.md).
- **Do not push from inside a reactor callback.** In the event-driven driver a service call runs on the reactor worker; a loop that pushes thousands of messages from `on_message` blocks the reactor that is supposed to drain the send queue, and the queue's bound eventually closes the connection. The supported pattern for fan-out is `WsConn::sender()` (`WsSender`) from another thread, which queues and nudges.
- **`Url` parsing is the caller's job for the `ws://`/`wss://` scheme only.** `normalise_url` maps the scheme to `http`/`https` and nothing else; anything exotic is rejected rather than half-understood.

## Usage

Server:

```rust
use courierust::courierust_server::ws::{WsConn, WsData, WsService, WsUpgradeReply};
use std::sync::Arc;

struct Echo;

impl WsService for Echo {
    fn on_message(&self, conn: &mut WsConn, msg: WsData) {
        match msg {
            WsData::Text(t) => { let _ = conn.send_text(&t); }
            WsData::Binary(b) => { let _ = conn.send_binary(&b); }
        }
    }
    fn on_close(&self, conn: &mut WsConn, code: Option<u16>, clean: bool) {
        eprintln!("closed: code={code:?} clean={clean} path={}", conn.path());
    }
}

struct App;
impl courierust::courierust_server::Handler for App {
    fn handle(&self, _req: courierust::courierust_http::request::Request<
        courierust::courierust_body::Body>) -> courierust::courierust_http::response::Response<
        courierust::courierust_body::Body> {
        courierust::courierust_http::response::Response::text("hello")
    }
    fn websocket(&self, req: &courierust::courierust_http::request::Request<
        courierust::courierust_body::Body>) -> WsUpgradeReply {
        if req.path == "/echo" { WsUpgradeReply::Accept(Arc::new(Echo)) }
        else { WsUpgradeReply::Pass }   // let the HTTP handler answer 404
    }
}
```

Client:

```rust
use courierust::courierust_client::ClientConfig;
use courierust::courierust_client::ws::WebSocket;

let mut ws = WebSocket::connect("wss://example.com/ws", &ClientConfig::default())?;
ws.send_text("hello")?;
for msg in [ws.read_message()?] {
    println!("{msg:?}");
}
ws.close(1000, "done")?;
```

See [`examples/ws_echo.rs`](../../examples/ws_echo.rs) and [`examples/ws_client.rs`](../../examples/ws_client.rs) for runnable versions, and [`tests/ws.rs`](../../tests/ws.rs) for 34 end-to-end tests that exercise the wire protocol against a real socket, including cross-driver push, origin rejection, wss over TLS, and the error codes.

## Where to go next

- Tutorial (both languages): the wiki — [WebSockets](https://github.com/blueokanna/Courierust/wiki/WebSockets) / [WebSocket 使用指南](https://github.com/blueokanna/Courierust/wiki/WebSocket-%E4%BD%BF%E7%94%A8%E6%8C%87%E5%8D%97).
- Runnable demos: `cargo run --example ws_echo` (server + client in one process), `cargo run --example ws_client` (production client options against any endpoint).
- Measurements and honest weaknesses: [`benches/WS_BENCHMARK.md`](../../benches/WS_BENCHMARK.md).
- Server/client integration details: [`../courierust_server/README.md`](../courierust_server/README.md) (the `Handler::websocket` hook and the reactor) and [`../courierust_client/README.md`](../courierust_client/README.md).
