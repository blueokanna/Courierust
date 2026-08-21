# no_std

The protocol core compiles for `no_std + alloc` with **zero** dependencies. This is the entire wire-level stack: HTTP message model, HPACK, the HTTP/2 codec/state machine, flow control, the WUCS priority scheduler, fingerprints, and the self-contained MD5/SHA-256. It is suitable for embedded firmware, kernel modules, or any environment without the standard library.

## What compiles without std

| Module | Contents |
|---|---|
| `courierust_http` | request/response/method/status/headers/URI |
| `courierust_hpack` | encoder/decoder, Huffman, static+dynamic tables |
| `courierust_h2` | frames, settings, streams, flow control, WUCS, `PRIORITY_UPDATE` |
| `courierust_fingerprint` | JA3 / JA4 / Chrome HTTP/2 profile |
| `courierust_crypto` | MD5, SHA-256 |
| `courierust_bytes` / `courierust_io` | byte buffers, Read/Write traits |
| `courierust_error` | unified error type |

What requires `std` (behind the default feature): `courierust_pool`, `courierust_net`, `courierust_tls`, `courierust_body`, `courierust_client`, `courierust_server`, `courierust_h1`, `courierust_grpc`.

## Enable it

```toml
[dependencies]
courierust = { version = "0.1", default-features = false }
```

Build check:

```bash
cargo build --no-default-features --lib
```

You need an allocator (global allocator + `alloc`), and the crate's own `io::Read`/`io::Write` traits replace `std::io` — drive them with your platform's byte pipes.

## Using the codec without std

A minimal HTTP/2 client session, driven frame by frame over whatever bytes your platform provides:

```rust
use courierust::courierust_bytes::BytesMut;
use courierust::courierust_h2::connection::{Config, Connection};
use courierust::courierust_h2::priority::Priority;
use courierust::courierust_io::{BufReader, BufWriter};

// Implement crate::courierust_io::Read / crate::courierust_io::Write for your transport.
struct MyTransport; // ... Read + Write impls ...

let reader = BufReader::new(MyTransport, 4096);
let writer = BufWriter::new(MyTransport, 4096);
let mut conn = Connection::new(reader, writer, Config {
    client: true,
    ..Default::default()
});

// Open a request stream, queue headers + body, then poll() to advance.
let sid = conn.open_request(Priority::default())?;
conn.send_headers(sid, &my_header_block, false)?;
conn.send_data(sid, payload, true)?;

loop {
    let progressed = conn.poll()?; // true if anything was flushed/read
    while let Some(ev) = conn.next_event() {
        // Event::Headers / Event::Data / Event::StreamClosed / ...
    }
    if !progressed {
        // no more work right now — yield to your event loop
        break;
    }
}
```

`Connection` is generic over `crate::courierust_io::Read`/`Write`, so the identical code drives TCP, TLS, or a UART-style byte stream.

## Hashes without std

```rust
use courierust::courierust_crypto::md5::md5_hex;
use courierust::courierust_crypto::sha256::sha256_hex;

let h = md5_hex(b"hello");    // "5d41402abc4b2a76b9719d911017c592"
let h = sha256_hex(b"hello"); // "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
```

These power JA3/JA4 and are the only crypto in the crate — both are small, table-driven, and dependency-free.
