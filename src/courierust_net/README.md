# courierust_net

The transport layer: `Read`/`Write` adapters for real sockets, the readiness poller behind the event-driven server, stats counters, and the UDP reactor for the HTTP/3 path.

## What's here

- **TCP adapters** — `Read`/`Write` impls for `&TcpStream` and `Arc<TcpStream>`, mapping `WouldBlock`/`TimedOut` to the crate's error kinds. `Arc<TcpStream>` lets a connection share one socket between a reader and a writer without self-referencing.
- **`poller`** — the I/O readiness engine: Winsock `select` (batched, first batch full timeout, rest zero) on Windows, POSIX `poll` elsewhere, with an optional wake descriptor (the event server's self-pipe) watched in every batch. The whole slow-connection story lives here — see `blogs/03-self-pipe-event-scheduler.md`.
- **`stats`** — `Arc<AtomicUsize>` counters (connections, h1/h2 syscalls, poll syscalls, wakeups, queue-depth peak, H3 ACK-deferral and credit-stall counts) that the benchmark suite turns into evidence rows. `Counting` wrappers make "how many syscalls did this connection actually make" measurable.
- **`udp`** — the UDP socket reactor the HTTP/3 runtime drives (datagram read/write with non-blocking semantics, timeBeginPeriod 1ms resolution on Windows).

## Why the TCP adapter is fiddly

The `WouldBlock` mapping matters more than it looks: the event server runs sockets in non-blocking mode, so every read can legitimately return "not ready yet". If that's not surfaced as a first-class `ErrorKind::WouldBlock`, the whole event loop's "park the connection and wait for readiness" model falls apart. Getting this mapping right is what makes the codecs transport-agnostic *and* the event loop honest about backpressure.

## Usage

You rarely touch this directly — `courierust_client` / `courierust_server` use it under the hood. But if you're adapting a different transport (a pipe, a TLS stream from elsewhere), this is the pattern to copy: implement `courierust_io::Read`/`Write`, map your blocking states to the crate's error kinds, and the whole stack works.
