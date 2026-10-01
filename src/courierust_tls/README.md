# courierust_tls

TLS 1.2 + TLS 1.3, **from scratch, zero dependencies**, running over the crate's `Read`/`Write` transport traits. This is the part everyone told me not to write by hand. I did it anyway, because I wanted `https://` to be a first-class capability with nothing between my code and the RFC.

## The cryptographic profile

**TLS 1.3 (RFC 8446):**

- Suites: `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`;
- Key exchange: X25519;
- Certificate verification: RSA-PSS / RSA PKCS#1 v1.5, ECDSA P-256, Ed25519.

**TLS 1.2 (RFC 5246 / RFC 8422):** AEAD ECDHE suites only — the three `ECDHE-ECDSA-*` and three `ECDHE-RSA-*` (AES-128/256-GCM, CHACHA20-POLY1305, secp256r1). No CBC/HMAC, no RC4, no static RSA, ever. RFC 5746 `renegotiation_info` is sent and echoed.

All primitives live in `crypto/` — ChaCha20, Poly1305, ChaCha20-Poly1305, AES, GCM, SHA-256/384, HMAC, HKDF, X25519, Ed25519, ECDSA, RSA, and an OS-seeded ChaCha20 DRBG — implemented from the public specifications. The module is safe Rust apart from two scoped exceptions: the AES-NI intrinsic wrapper and the Windows system entropy call, each behind its own `#[allow(unsafe_code)]`.

## The verification you don't see

- X.509 chain validation: validity windows, name chaining, signature checks, basic-constraints / key-usage, pluggable root store.
- RFC 6125 hostname matching, including IP SANs, single wildcards, and the CVE-2025-61727 subtree-exclusion wildcard rule.
- EKU enforcement — a leaf with an EKU extension must permit `serverAuth`.
- The RFC 8446 §4.1.3 **downgrade sentinel** is written and checked: a pure-TLS-1.3 client refuses a TLS 1.2 ServerHello outright; it never silently downgrades.
- Constant-time `Finished` `verify_data` comparison and per-direction sequence numbers on both versions (tampered records fail `bad_record_mac`).
- A 16 MiB cap on the decrypted handshake buffer, so a peer streaming endless handshake records can't grow memory without bound.
- `handshake_timeout` (10 s default) on both sides — a peer that connects and stalls mid-handshake releases its worker/caller.

## Remote session resumption and key updates

No 0-RTT / early data. TLS 1.3 session resumption is implemented — server-issued session tickets, 1-RTT PSK via `psk_dhe_ke`, a client-side session store keyed by hostname (bounded to 8 sessions) — and the pooled client caches one connector per authority, so a ticket captured on one connection is offered on the next (`tls_session_resumption_across_client_connections` proves it end to end). `KeyUpdate` (RFC 8446 §4.6.3) is implemented in both directions: an inbound update rekeys the read direction and is answered when the peer asked for one, the write direction is rekeyed before it spends its per-key record budget (§5.5), and `request_key_update()` forces one. QUIC key updates still ride the transport's key-phase bit (RFC 9001 §6). `verify: false` exists for testing/untrusted peers and still verifies `CertificateVerify` + `Finished`, so the handshake stays cryptographically sound.

## Mutual TLS (TLS 1.3)

Client authentication is implemented for TLS 1.3 over TCP. A server sets `ServerConfig::client_auth` to a `ClientAuth` (roots + `required`/`optional`) and then sends a `CertificateRequest` between `EncryptedExtensions` and `Certificate`; the client answers with `Certificate` + `CertificateVerify` when `ClientConfig::identity` is set, and with the *empty* certificate list when it is not — the mandated refusal to authenticate (RFC 8446 §4.4.2), never silence. The server validates the offered leaf against the client-auth roots, its validity window, and the `clientAuth` EKU, requires the `CertificateVerify` to prove possession, and records the leaf for the layer above.

The policy is the server's, and the wire says which one it chose: a client that declines when authentication was `required` gets `certificate_required` (116), an unusable or unverifiable chain gets `bad_certificate` (42), a certificate nobody asked for gets `unexpected_message` (10). Alerts are *sent*, in the application-key epoch the peer is reading from, so a refusal is visible instead of merely implied by a closed socket.

Boundaries, stated rather than implied: TLS 1.2 with `client_auth` is refused at handshake time (a TLS 1.2 server would otherwise have to drop to its own, weaker authentication), and the QUIC/HTTP/3 path refuses the combination at startup — mTLS here means TLS 1.3 over TCP. Post-handshake authentication (`CertificateRequest` after `Finished`) is not implemented; a non-empty request context is rejected.

## Usage

```rust
use courierust::courierust_tls::{Identity, RootStore};

let mut roots = RootStore::new();
roots.add_der(root_der);            // no bundled CAs — supply your own
roots.add_pem(ca_bundle_pem)?;      // …or a PEM bundle (text between blocks is ignored)

// `from_pem_file` parses the chain and the key and proves they belong
// together; `Identity::from_pem(cert, key)` and
// `Identity::from_der(chain, key)` are the same check over text/DER you
// already hold. Accepted key containers: PKCS#8 (`PRIVATE KEY`), PKCS#1
// (`RSA PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`) — the DER decides,
// not the label. `ENCRYPTED PRIVATE KEY` is refused by name, and a key
// that does not match the leaf certificate is refused at load time
// instead of failing every handshake.
let identity = Identity::from_pem_file("cert.pem", "key.pem")?;
```

`Identity` is also where a private key stops travelling: its `Debug`
prints the chain's length and the key's *length*, never key bytes, so a
`ServerConfig` that ends up in a log line cannot leak the key.

The client (`TlsSettings` on `ClientConfig`) and server (`TlsSettings` on `ServerConfig`) wire this in; ALPN decides `h2` vs `http/1.1` vs `h3`. `examples/https.rs` and `examples/h3.rs` are working end-to-end demos.
