# courierust_crypto

Two small digests: **MD5** (RFC 1321) for JA3, **SHA-256** (FIPS 180-4) for JA4. `no_std`, zero dependencies, no unsafe code.

## Why only two digests

Because that's all the fingerprint layer needs, and this module exists to serve it. It's not a crypto kitchen sink — the TLS stack has its own full primitive set in `courierust_tls::crypto` (AES-GCM, ChaCha20-Poly1305, X25519, Ed25519, ECDSA, RSA, HKDF, HMAC). This module is deliberately small, boring, and correct.

## The point

JA3's whole trick is MD5 over a canonical ClientHello string; JA4's first half is SHA-256 of the second fingerprint part. You need these two digests in `no_std` with zero deps. That's it. They're implemented from the public specifications, tested against the published test vectors, and contain no unsafe.

## Usage

```rust
use courierust::courierust_crypto::{md5, sha256};

let h = md5::md5(b"data");
let s = sha256::sha256(b"data");
```

Or don't use it at all — the fingerprint functions call these for you.
