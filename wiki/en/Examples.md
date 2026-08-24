# Examples

Every example in the repository compiles and runs as-is (`cargo run --example <name>`). They are the fastest way to see the stack in action.

| Example | What it shows | Run |
|---|---|---|
| `hello` | Minimal client + server over h2c in one file | `cargo run --example hello` |
| `greeter` | gRPC server + client: unary (raw + typed), error status | `cargo run --example greeter` |
| `streaming` | Server streams a `Body::Channel`, client consumes chunk by chunk | `cargo run --example streaming` |
| `priority` | RFC 9218: high-urgency stream scheduled ahead of a low-urgency backlog | `cargo run --example priority` |
| `redirects` | 302 chains followed automatically (RFC 9110) | `cargo run --example redirects` |
| `fingerprint` | Print the JA3 / JA4 / Chrome HTTP/2 fingerprint values | `cargo run --example fingerprint` |
| `https` | HTTPS (TLS 1.2 + 1.3) end to end: self-signed Ed25519 identity, validating client, h2 + HTTP/1.1 over ALPN | `cargo run --example https` |
| `protocol_core` | HPACK + h2 codec over an in-memory pipe (no sockets), plus the self-contained hashes | `cargo run --example protocol_core` |
| `diag` | Loopback h2 echo used for diagnostics | `cargo run --example diag` |

## hello

One file: spin up a server on an ephemeral port, then GET and POST to it with an HTTP/2 client. The starting point for everything else.

## greeter

A background gRPC server with two methods plus a client that calls them — raw-bytes `call`, typed `call_unary`, and an error path that surfaces `grpc-status` on the client.

## streaming

The server returns a `Body::Channel`; a producer thread feeds it; the client drains the channel receiver incrementally. Works over HTTP/1.1 (chunked) and HTTP/2.

## priority

Fires 32 `urgency=7` requests, then one `urgency=0` request. The WUCS scheduler must not let the low-urgency backlog starve the high-urgency stream — the example prints how fast the high-urgency request completes.

## redirects

A two-hop `302 -> 302 -> 200` chain; the client follows it transparently and you see the final response.

## fingerprint

Prints the exact ClientHello parameters (`chrome_tls_profile`) plus the JA3 string/hash, JA4, and the Chrome HTTP/2 SETTINGS order — the values you feed to your own TLS layer.

## https

A server with a self-signed Ed25519 identity (the DER files under `tests/certs/`) and a client that trusts that same certificate as its root. The server speaks both h2 (ALPN) and HTTP/1.1 over TLS; the client GETs and POSTs `https://` URLs and prints status + body. Swap in your own certificate chain + key for real deployments.

## protocol_core

The `no_std`-capable core with no sockets: HPACK encode/decode round trip, an h2 `Connection` driven over an in-memory pipe (any type implementing `io::Read`/`io::Write` works), and the dependency-free MD5/SHA-256.

## diag

Loopback h2 echo with status + body printed — handy for confirming the stack works before pointing it at a real endpoint.
