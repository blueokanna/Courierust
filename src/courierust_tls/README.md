# courierust_tls

TLS 1.2 + TLS 1.3, **from scratch, zero dependencies**, running over the crate's `Read`/`Write` transport traits. This is the part everyone told me not to write by hand. I did it anyway, because I wanted `https://` to be a first-class capability with nothing between my code and the RFC.

## The cryptographic profile

**TLS 1.3 (RFC 8446):**

- Suites: `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`;
- Key exchange: X25519;
- Certificate verification: RSA-PSS / RSA PKCS#1 v1.5, ECDSA P-256, Ed25519.

**TLS 1.2 (RFC 5246 / RFC 8422):** AEAD ECDHE suites only — the three `ECDHE-ECDSA-*` and three `ECDHE-RSA-*` (AES-128/256-GCM, CHACHA20-POLY1305, secp256r1). No CBC/HMAC, no RC4, no static RSA, ever. RFC 5746 `renegotiation_info` is sent and echoed.

All primitives live in `crypto/` — ChaCha20, Poly1305, ChaCha20-Poly1305, AES, GCM, SHA-256/384, HMAC, HKDF, X25519, Ed25519, ECDSA, RSA, and an OS-seeded ChaCha20 DRBG — implemented from the public specifications, **no unsafe code**.

## The verification you don't see

- X.509 chain validation: validity windows, name chaining, signature checks, basic-constraints / key-usage, pluggable root store.
- RFC 6125 hostname matching, including IP SANs, single wildcards, and the CVE-2025-61727 subtree-exclusion wildcard rule.
- EKU enforcement — a leaf with an EKU extension must permit `serverAuth`.
- The RFC 8446 §4.1.3 **downgrade sentinel** is written and checked: a pure-TLS-1.3 client refuses a TLS 1.2 ServerHello outright; it never silently downgrades.
- Constant-time `Finished` `verify_data` comparison and per-direction sequence numbers on both versions (tampered records fail `bad_record_mac`).
- A 16 MiB cap on the decrypted handshake buffer, so a peer streaming endless handshake records can't grow memory without bound.
- `handshake_timeout` (10 s default) on both sides — a peer that connects and stalls mid-handshake releases its worker/caller.

## Honest scope

No 0-RTT / early data. TLS 1.3 session resumption is implemented — server-issued session tickets, 1-RTT PSK via `psk_dhe_ke`, client-side session store keyed by hostname (bounded to 8 sessions) — and unit-tested; the pooled client currently builds a fresh connector per request, so cross-connection resumption is not yet exercised in practice. QUIC key updates are handled at the transport layer via the key-phase bit (RFC 9001 §6); the record-layer TLS 1.3 KeyUpdate message is not sent. No mTLS — the server never requests a client certificate. `verify: false` exists for testing/untrusted peers and still verifies `CertificateVerify` + `Finished`, so the handshake stays cryptographically sound.

## Usage

```rust
use courierust::courierust_tls::{RootStore, Identity};

let mut roots = RootStore::new();
roots.add_der(root_der);            // no bundled CAs — supply your own

let identity = Identity {
    cert_chain: vec![cert_der],     // leaf first
    private_key: key_der,           // PKCS#8 or PKCS#1 (DER)
    is_rsa: false,                  // false for Ed25519/ECDSA
};
```

The client (`TlsSettings` on `ClientConfig`) and server (`TlsSettings` on `ServerConfig`) wire this in; ALPN decides `h2` vs `http/1.1` vs `h3`. `examples/https.rs` and `examples/h3.rs` are working end-to-end demos.
