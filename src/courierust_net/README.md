# courierust_net

The transport layer: `Read`/`Write` adapters for real sockets, the readiness poller behind the event-driven server, stats counters, and the UDP reactor for the HTTP/3 path.

## What's here

- **TCP adapters** — `Read`/`Write` impls for `&TcpStream` and `Arc<TcpStream>`, mapping `WouldBlock`/`TimedOut` to the crate's error kinds. `Arc<TcpStream>` lets a connection share one socket between a reader and a writer without self-referencing.
- **`poller`** — the I/O readiness engine: Winsock `select` (batched, first batch full timeout, rest zero) on Windows, POSIX `poll` elsewhere, with an optional wake descriptor (the event server's self-pipe) watched in every batch. The whole slow-connection story lives here — see `blogs/03-self-pipe-event-scheduler.md`.
- **`stats`** — `Arc<AtomicUsize>` counters (connections, h1/h2 syscalls, poll syscalls, wakeups, queue-depth peak, H3 ACK-deferral and credit-stall counts) that the benchmark suite turns into evidence rows. `Counting` wrappers make "how many syscalls did this connection actually make" measurable.
- **`udp`** — the UDP socket reactor the HTTP/3 runtime drives (datagram read/write with non-blocking semantics, timeBeginPeriod 1ms resolution on Windows).

## Why the TCP adapter is fiddly

The `WouldBlock` mapping matters more than it looks: the event server runs sockets in non-blocking mode, so every read can legitimately return "not ready yet". If that's not surfaced as a first-class `ErrorKind::WouldBlock`, the whole event loop's "park the connection and wait for readiness" model falls apart. Getting this mapping right is what makes the codecs transport-agnostic *and* the event loop honest about backpressure.

The mapping has a second half that only shows up once a socket timeout is armed. Windows fails a timed-out read or write with `WSAETIMEDOUT`, POSIX with `EAGAIN` — which is the very code that means "not ready yet". The raw adapter folds both into `WouldBlock`, and the connection records which of the two reasons it handed the socket: a *deadline* (a request or shutdown budget, whose expiry is an answer in itself) or a *poll* (the short timeout the h2/h3 drivers use to regain control). Only a deadline turns `WouldBlock` into `ErrorKind::Timeout`; the poll side keeps `WouldBlock` untouched. Without that split, `Client::request(..).timeout(d)` leaked a POSIX-only error kind to callers, and a close-delimited body treated the expiry as a clean EOF — silently returning a truncated message as a success.

The write half of the same rule is what keeps a saturated send buffer from looking like a dead peer. An upload is paced by the peer's flow-control window, so a `write` that outlives a poll timeout is normal backpressure: the h2 session keeps the frame and resumes it. Without it the failure is platform-shaped — Linux, whose send buffers are large and whose `EAGAIN` already reads as "not ready", uploads a megabyte happily while Windows, whose buffer is small and whose `WSAETIMEDOUT` looked fatal, fails the third request on the same code path.

## Usage

You rarely touch this directly — `courierust_client` / `courierust_server` use it under the hood. But if you're adapting a different transport (a pipe, a TLS stream from elsewhere), this is the pattern to copy: implement `courierust_io::Read`/`Write`, map your blocking states to the crate's error kinds, and the whole stack works.
