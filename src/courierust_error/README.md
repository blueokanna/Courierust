# courierust_error

One error type for the whole stack. `ErrorKind` (a cheap `Copy` discriminant) plus an optional human-readable message. `no_std`, zero dependencies.

## Why one type

Every layer — h1, h2, h3, HPACK, TLS, the client, the server, gRPC — fails. If each layer invents its own error type, you get a `From` impl explosion and "which error is this?" guesswork at every boundary. One type means one match, and the discriminant tells you the category even when the message is unhelpful.

## The kinds

They're deliberately coarse — the point is machine-checkability, not precision:

- `Io`, `UnexpectedEof`, `WouldBlock` — transport level.
- `Protocol`, `InvalidHeader`, `Overflow` — "you sent me garbage" (or a limit was hit).
- `Timeout` — deadline exceeded.
- `H2(u32)`, `Grpc(u32)` — wire-level error codes carried through, so the HTTP/2 error code and gRPC status survive the trip up the stack.
- `Canceled` — reset/aborted by either side.
- `Other` — application-level.

Protocol layers refine the coarse kind with a message (`Error::protocol("invalid chunk size")`), so you get both: a category you can branch on and a detail you can log.

## Usage

```rust
use courierust::courierust_error::{Error, ErrorKind, Result};

match err.kind {
    ErrorKind::WouldBlock => /* not ready yet, try again */,
    ErrorKind::Protocol => /* peer violated the RFC */,
    ErrorKind::H2(code) => /* HTTP/2 error code survived intact */,
    _ => /* log err.message */,
}
```
