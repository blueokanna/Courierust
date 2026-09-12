# WebSockets

Courierust ships a complete RFC 6455 WebSocket implementation
(`courierust_ws`) plus RFC 7692 `permessage-deflate`, and wires it into the
server and the client you already use. A WebSocket **is** an HTTP/1.1
connection that gets upgraded in place: it shares the port, the handler,
the TLS stack and the event scheduler with plain HTTP — no second
listener, no third-party dependency, no separate runtime.

```
client ── GET /ws  (Upgrade: websocket) ──► Handler::websocket  ── Accept ──► WsService
              │                                                                   │
              └──────────── 101 Switching Protocols ◄───── frames ◄──────────────┘
```

## The server hook

`Handler::websocket` picks the routes this server serves as WebSockets;
returning `Pass` keeps the request on the normal HTTP path (so `/ws` stays
yours and every other path still gets your real handler):

```rust
use courierust::courierust_body::Body;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::ws::{WsConn, WsData, WsService, WsUpgradeReply};
use courierust::courierust_server::{Handler, Server, ServerConfig};
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
        // `code: None` means the transport broke — not the peer's fault.
        eprintln!("closed code={code:?} clean={clean} path={}", conn.path());
    }
}

struct App;

impl Handler for App {
    fn handle(&self, _req: Request<Body>) -> Response<Body> {
        Response::text("plain HTTP still works")
    }

    fn websocket(&self, req: &Request<Body>) -> WsUpgradeReply {
        if req.path == "/ws" {
            WsUpgradeReply::Accept(Arc::new(Echo))
        } else {
            WsUpgradeReply::Pass
        }
    }
}

let server = Server::bind_with_config("127.0.0.1:8080", ServerConfig::default())?;
server.serve(App)?;
```

A `WsService` gets `on_open`, `on_message`, `on_pong`, `on_idle` and
`on_close`; per-connection application state lives on the connection
itself (`conn.set_state(...)` / `conn.with_state(...)`), so you do not need
one `WsService` object per connection.

### Both drivers upgrade in place

`ServerConfig::event_driven` selects the scheduler, and WebSockets work on
either one — with the same policy, because both run the same
`courierust_ws` engine:

| | blocking driver (`event_driven: false`) | event driver (default) |
|---|---|---|
| driving loop | blocking read/write on the connection's own thread | stays in the reactor; read on readable, flush on writable |
| cost of an idle WebSocket | one pool worker | **one poller slot** |
| keepalive | read deadline armed only while waiting for the next frame | `ping_interval` Ping/Pong |
| fan-out from another thread | `WsConn::sender()` | `WsConn::sender()` |

The reactor detail worth knowing: an idle WebSocket holds **no worker**, so
a service with thousands of mostly-idle sockets is bounded by
`max_connections`, not by worker count. The flip side is that a service
callback runs on an event worker — pushing thousands of messages from
inside `on_message` blocks the reactor that would drain them. The supported
fan-out path is `WsConn::sender()` from any thread, which queues the frame
and nudges the reactor.

## The policy: `WsConfig`

```rust
use courierust::courierust_server::ws::{PmDeflatePolicy, WsConfig};
use courierust::courierust_ws::OriginPolicy;

let ws = WsConfig {
    // The default: browsers may only open this socket from the same site,
    // because the browser attaches the session cookies to the upgrade.
    origin: OriginPolicy::SameOrigin,
    // Believe X-Forwarded-For / X-Forwarded-Proto only from your proxy.
    trusted_proxies: vec![],
    subprotocols: vec!["chat.v2".into(), "chat.v1".into()],
    compression: PmDeflatePolicy::default(),
    max_frame: 16 * 1024 * 1024,
    max_message: 16 * 1024 * 1024,
    max_fragments: 0,          // 0 = unlimited
    max_send_queue: 4 * 1024 * 1024,
    read_buffer: 64 * 1024,
    ping_interval: Some(std::time::Duration::from_secs(30)),
    close_timeout: Some(std::time::Duration::from_secs(5)),
    ..Default::default()
};
```

| knob | why it exists |
|---|---|
| `origin` | `SameOrigin` (default) blocks cross-site page → authenticated socket; `NoOrigin` for non-browser clients, `List` for an allow-list, `Any` to opt out deliberately |
| `trusted_proxies` | only these peers may override the client address with `X-Forwarded-For` / `X-Forwarded-Proto` |
| `subprotocols` | server-preference order; the first client offer present here wins |
| `compression` | `permessage-deflate` policy (size thresholds, window bits) |
| `max_frame` / `max_message` / `max_fragments` | bounds a peer cannot talk its way past; violations get 1009/1007/1002 |
| `max_send_queue` | bounds memory when the application pushes faster than the peer reads |
| `read_buffer` | 64 KiB suits media-ish traffic, 16 KiB suits large fleets of mostly-idle sockets |
| `ping_interval` | Ping after this much inbound silence, give up at twice that |
| `close_timeout` | how long to wait for the peer's close echo |

## The client

```rust
use courierust::courierust_client::ClientConfig;
use courierust::courierust_client::ws::WebSocket;

let cfg = ClientConfig::default();          // 60 s read deadline

let mut ws = WebSocket::connect("wss://example.com/ws", &cfg)?;  // TLS is in-crate
ws.send_text("hello")?;
ws.send_binary(&[0u8, 1, 2, 255])?;

loop {
    match ws.read_message()? {
        courierust::courierust_ws::Event::Text(t) => println!("text {t}"),
        courierust::courierust_ws::Event::Binary(b) => println!("binary {} bytes", b.len()),
        courierust::courierust_ws::Event::Ping(_) | courierust::courierust_ws::Event::Pong(_) => continue,
        courierust::courierust_ws::Event::Close(frame) => {
            println!("closed {frame:?}");
            break;
        }
    }
}
ws.close(1000, "done")?;
```

The client speaks `ws://` and `wss://` (the second one rides the crate's own
TLS 1.2/1.3 stack), understands the same subprotocol negotiation, and
carries its own read deadline. `cargo run --example ws_client` runs the
production-shaped version of this against a public echo server or your own
endpoint; `cargo run --example ws_echo` runs a server **and** a client in
one process.

## What is enforced for you

| rule | what happens |
|---|---|
| mask direction (§5.1) | server fails an unmasked client frame; client fails a masked server frame |
| control frames | never fragmented, never longer than 125 bytes |
| length encoding | minimal-length encodings only |
| UTF-8 in text frames | validated incrementally; 1007 at the exact breaking offset |
| RSV bits | rejected unless negotiated |
| close codes | validated against the legal sets for each direction |
| §5.5.1 (nothing after Close) | a shared connection flag refuses racing sends with `ErrorKind::Canceled` |
| limits | 1009 before the bytes are buffered, including inflated `permessage-deflate` bombs |
| handshake | exactly one canonical `Sec-WebSocket-Key`, `Version: 13`, token-list `Connection: Upgrade`, `Host` required on HTTP/1.1 |
| masking keys | ChaCha20 stream from platform entropy, one key per frame |

## Deploying behind a reverse proxy (recommended)

Terminate TLS (and optionally HTTP/2 or HTTP/3) at nginx or Traefik, and
proxy the upgrade to your plain-HTTP listener:

```nginx
location /ws/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;             # buffering frames destroys latency
    proxy_read_timeout 3600s;        # must exceed ping_interval
    proxy_send_timeout 3600s;
}
```

Then tell the server it sits behind that proxy:

```rust
let ws = WsConfig {
    origin: OriginPolicy::List(vec!["https://app.example.com".into()]),
    trusted_proxies: vec![IpNet::parse("127.0.0.1/32")?, IpNet::parse("10.0.0.0/8")?],
    ..Default::default()
};
```

Two mistakes are common enough to name: a proxy `proxy_read_timeout`
**shorter** than `ping_interval` will kill healthy idle sockets, and
`trusted_proxies` left empty while the application reads
`X-Forwarded-For` means you are trusting whatever the client sent.

## Honest notes

- **RFC 8441 (WebSocket over HTTP/2) is not implemented.** The client offers
  **only** `http/1.1` in ALPN — even when `ClientConfig::http2` is `true` — and
  refuses a connection that ends up on h2 before reading a frame. On the server
  side, a WebSocket attempt on an *established* h2 connection is a malformed
  message: a **stream error (`PROTOCOL_ERROR`, RFC 9113 §8.1.1)**, in both
  forms — RFC 8441's extended CONNECT (`:method = CONNECT` with
  `:protocol = websocket`, an undefined pseudo-header here, exactly the
  rejection RFC 8441 §3 defines for a peer that never advertised
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`) and the HTTP/1.1-style
  `Upgrade: websocket` / `Connection: Upgrade` fields (§8.2.2). The connection
  and its other streams keep working. Use HTTP/1.1 for WebSockets;
  `h2_rejects_rfc8441_extended_connect_as_stream_error`,
  `h2_rejects_websocket_upgrade_header_over_h2` and
  `wss_negotiates_http_1_1_against_an_h2_capable_server` are the tests behind
  those three sentences.
- **`permessage-deflate` compresses each message independently** (no
  context takeover). That is always legal, removes the "one message's
  plaintext leaks into another" class of bugs, and is why the server can
  hold thousands of connections without 32 KiB of sliding window each; the
  cost is compression ratio on streams of tiny repetitive messages.
- **On Windows, a socket deadline is not free.** The blocking driver arms
  the read deadline only while idle; a client that keeps
  `read_timeout` armed pays roughly 2× on 256 KiB bulk pushes — set
  `read_timeout: None` and use application-level liveness for bulk
  transfers. Measurements: `benches/WS_BENCHMARK.md` (see
  [Benchmarks](Benchmarks)).
- **256 KiB messages between two ends of this crate** are slower than
  tungstenite's pairing (cause localised, and the socket-deadline finding
  above is part of it); small and medium messages are at parity or ahead.
  The benchmark document reports both directions of that comparison.

## Where the coverage is

- **27 end-to-end tests** (`tests/ws.rs`) run the real client against the
  real server over a real socket, through **both** drivers: the handshake
  (including the RFC 6455 accept-key vector), masking both ways,
  fragmentation with interleaved control frames, RFC 7692 negotiation and
  interop, UTF-8 failure codes, close-handshake cleanliness, `wss://` over
  the crate's TLS, push from another thread, Origin/subprotocol policy, the
  limits, and the reactor regressions (a closed connection must not park
  the connections that are still open).
- **Examples**: `cargo run --example ws_echo`, `cargo run --example ws_client`.
- **Engine internals, deployment recipes and the full security posture**:
  `src/courierust_ws/README.md`.
- **Benchmarks vs `tungstenite` / `tokio-tungstenite`**:
  `benches/WS_BENCHMARK.md` — code, methodology and the honest rows.
