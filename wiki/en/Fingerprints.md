# Fingerprints

Servers that care about bot traffic fingerprint the **TLS ClientHello** (JA3 / JA4) and the **HTTP/2 handshake** (SETTINGS values + order, header ordering). Courierust includes a self-contained TLS 1.2 + 1.3 implementation for its built-in client/server, and this module exposes the fingerprint parameters plus self-contained MD5/SHA-256. You can also feed the same parameters to an external TLS library when that is required by your deployment.

## JA3

```rust
use courierust::courierust_fingerprint::{chrome_tls_profile, ja3_hash, ja3_string};

let profile = chrome_tls_profile(); // a TlsProfile, the ClientHello parameters
let s = ja3_string(&profile);       // "771,4865-4866-...,0-...,23,0-29-..."
let hash = ja3_hash(&profile);      // 32 hex chars
```

The Chrome profile is checked against the public record in the test suite:

```rust
assert_eq!(ja3_hash(&profile), "cd08e31494f9531f560d64c695473da9");
```

## JA4

```rust
use courierust::courierust_fingerprint::ja4;

let f = ja4(&profile);
// format: t<version>d<ciphers>h<extensions><alpn>_<SNI hash>_<cipher hash>
assert_eq!(f, "t13d1516h2_8daaf6152771_e5627efa2ab1");
```

GREASE values are filtered automatically (the JA4 spec requires it), so `chrome_tls_profile()` produces a clean JA4.

## The profile object

`TlsProfile` is plain data — you can build your own:

```rust
use courierust::courierust_fingerprint::TlsProfile;

let custom = TlsProfile {
    tls_version: 0x0304, // TLS 1.3
    ciphers: vec![0x1301, 0x1302, 0x1303], // AES-128-GCM, AES-256-GCM, CHACHA
    extensions: vec![0x002b, 0x001d, 0x0000], // supported_versions, ..., SNI
    alpn: vec!["h2".into(), "http/1.1".into()],
    ..Default::default()
};
```

Feed these values into your TLS library's ClientHello builder.

## Chrome HTTP/2 fingerprint

Beyond TLS, Chrome is identified by its HTTP/2 behavior. The `ChromeH2Fingerprint` type carries the long-standing Chromium defaults:

```rust
use courierust::courierust_fingerprint::h2::ChromeH2Fingerprint;

let fp = ChromeH2Fingerprint::chrome();

// SETTINGS entries in the exact order Chrome sends them:
let entries = fp.settings_entries(); // Vec<Setting>

// Apply onto a Settings object, or build a whole h2 Config:
let mut my_settings = courierust::courierust_h2::settings::Settings::default();
fp.apply_to_settings(&mut my_settings);
let h2_cfg = fp.h2_config(); // client-role h2::connection::Config

// Header blocks are ordered pseudo-headers first, then lowercased-sorted:
let ordered = courierust::courierust_fingerprint::h2::order_headers_chrome(&fields);
```

The fingerprint fields are all public and configurable (`header_table_size`, `enable_push`, `max_concurrent_streams`, `initial_window_size`, `max_header_list_size`, `connection_window_update`, `sort_headers`), so you can match a specific Chrome build. Chromium tweaks these occasionally — keep them in sync with the build you're impersonating.

## Wiring it to TLS

For the built-in client, configure `ClientConfig::tls` with a `RootStore` and call an `https://` URL. For a custom transport, the codec is generic over `courierust::courierust_io::Read` / `courierust::courierust_io::Write`, so you can:

1. Build a `TlsProfile` (Chrome's, or yours).
2. Hand the ClientHello parameters to your TLS library (rustls, native-tls, or an FFI to OpenSSL/BoringSSL), or use Courierust's built-in TLS 1.2 + 1.3 connector.
3. Wrap the resulting `TlsStream` in the crate's io traits and drive `h2::Connection` / the client over it.

The HTTP/2 side is covered directly: use `ChromeH2Fingerprint::h2_config()` as the connection config and `order_headers_chrome()` on your outbound header blocks.

## Verification

The test suite pins the public records:

```rust
// JA3 (Chrome)     -> cd08e31494f9531f560d64c695473da9
// JA4 (Chrome)     -> t13d1516h2_8daaf6152771_e5627efa2ab1
```

Run `cargo test --lib` to see the fingerprint tests pass against these.
