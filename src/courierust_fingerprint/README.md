# courierust_fingerprint

Make your client **look like a browser**. JA3 / JA4 TLS fingerprints plus an exact Chrome HTTP/2 fingerprint — all computed from scratch, no dependencies.

TLS itself is deliberately external (this crate has zero deps). What this module produces is the *data* a browser-shaped client presents: the exact cipher suites, extensions, ALPN, and HTTP/2 settings — ready to feed into your own TLS layer.

## What's here

- **JA3** — `ja3_hash()` produces the standard 32-hex-digit fingerprint, matching the published Chrome record (`cd08e31494f9531f560d64c695473da9`). `ja3_string()` / `ja3()` give you the intermediate forms.
- **JA4** — `ja4()` produces the four-part `t13d1516h2_…` fingerprint, matching the spec example. (JA4 needs MD5 + SHA-256; both are implemented in `courierust_crypto`, no deps.)
- **Chrome HTTP/2 fingerprint** — `ChromeH2Fingerprint::chrome()` gives you SETTINGS entries (including `WINDOW_UPDATE` and `MAX_FRAME_SIZE`), the initial frame order, and `order_headers_chrome()` reorders your header fields the way Chrome does.
- **`TlsProfile`** — the structured description of a TLS `ClientHello` (cipher suites, extensions, curves, ALPN, signature algorithms). `chrome_tls_profile()` returns the Chrome-shaped one.

## Why this exists

Server-side fingerprinting (JA3/JA4/HTTP2 fingerprinting) is how CDNs and anti-bot systems tell "real Chrome" from "curl". If you're writing a client that wants to look ordinary, you need your ClientHello and your HTTP/2 setup to match Chrome's *exactly* — not approximately. This module encodes that "exactly", validated against public Chrome records.

## Usage

```rust
use courierust::courierust_fingerprint::{chrome_tls_profile, ja3_hash, ja4, h2::ChromeH2Fingerprint};

let profile = chrome_tls_profile();
assert_eq!(ja3_hash(&profile), "cd08e31494f9531f560d64c695473da9");
assert_eq!(ja4(&profile), "t13d1516h2_8daaf6152771_e5627efa2ab1");

let fp = ChromeH2Fingerprint::chrome();
let settings = fp.settings_entries();
let ordered = fp.order_headers_chrome(&fields);
```

Your TLS layer consumes `TlsProfile` to build the ClientHello; your h2 layer consumes the Chrome settings/order. Courierust's own TLS stack does exactly this.
