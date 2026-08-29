# courierust_server

The HTTP server, and the home of the event-driven scheduler. By default, idle / partial / slow connections park on a readiness poller and consume **zero workers**; ready ones are dispatched to event workers in batches. TLS and HTTP/2 connections run on the blocking work-stealing pool. `ServerConfig::event_driven` defaults to `true`.

## The architecture

```
accept thread ──> event loop (poller + classify) ──> event workers (batches)
                      │                                   │
                      └── TLS / h2 ──> blocking pool       └── h1
```

- **Accept thread** only accepts — it never reads, peeks, sleeps, or classifies, so a slow client can never stall the accept path.
- **Event loop** parks plain-HTTP connections on the poller (Winsock `select` / POSIX `poll`), classifies TLS / h2 / h1 from the first bytes, and reaps idle connections.
- **Event workers** run an incremental request parser that resumes where it left off, so a partial request is parked again, not held.
- **TLS and HTTP/2** go to the blocking pool, bounded by `handshake_timeout` / `h2_idle_timeout` / worker count.

The whole thing is held together by a **self-pipe** — a loopback socket pair whose read end is registered in the poller, so a queued control message interrupts a blocking poll *the instant* it's queued. Poll timeout never sits in the request-latency path. The full story, with the 5 ms P99 spike that motivated it, is in `blogs/03-self-pipe-event-scheduler.md`.

## The protection, before workers are involved

- An incomplete request parks on the poller (zero workers).
- Connections idle for `idle_timeout` are reaped.
- `max_connections` caps the parked population outright.
- A herd of keep-alive / SSE / slow-loris connections cannot consume the pool — the concurrency benchmark proves it: 200 idle half-open connections + 2 workers still serve a probe in ~300 µs, while the legacy one-pool-job-per-connection model blocks entirely.

## Scope notes

- The event path serves HTTP/1.1. TLS and h2 run on the blocking pool by design.
- `event_driven: false` restores the legacy model — one pool job per connection — for comparison and debugging. Not recommended for production: idle/slow herds will exhaust the pool.
- A long-blocking synchronous handler occupies a worker (event-driven or not) — any synchronous server's disease. Use channel bodies for streaming.
- Both h2c prior knowledge and `h2c` Upgrade are served.

## H1 per-request stage timing

`COURIERUST_H1_TRACE=1` turns on per-request segment timing, emitted as
`H1SEG|...` lines — a connection-setup line (`event=newconn|accept_us`) and
one line per served request batch with the full nine-stage decomposition
of a 1 KiB keep-alive request:

```
accept_us    accept → registered with the poller            (connection setup)
fresh_wait_us registered → first worker pickup              (first request only)
handoff_us   release → next pickup (keep-alive round trip   = last_write_to_reregistered
             + poll_ready_to_worker_dispatch)
dispatch_us  worker pickup → first byte read
parse_us     first byte read → request complete
handler_us   headers complete → response ready
build_us     response → first write (serialization)
write_us     first write → all written
```

The output is deliberately raw `key=value` pairs so a benchmark or shell
can bucket them. On loopback the dominant terms are `handoff_us` and
`write_us` — the reactor round trip and the socket write — while
`parse_us` / `handler_us` are single-digit microseconds, which is exactly
the answer to "is the time in the parser or in the handoff". Everything
is gated behind the env var; with it unset the hot path pays no
`Instant::now()` at all.

## Usage

```rust
use courierust::courierust_server::{Server, ServerConfig};
use courierust::courierust_http::{Request, Response};

let mut cfg = ServerConfig::default();
cfg.http2 = true; // h2c + h1.1 on the same port
let server = Server::bind_with_config("127.0.0.1:8080", cfg)?;

server.serve(|req: Request<Body>| -> Response<Body> {
    Response::with_status(200.into())
})?;
```

Add `ServerConfig::tls` with an `Identity` + ALPN and the same server speaks HTTPS — see `examples/https.rs`.
