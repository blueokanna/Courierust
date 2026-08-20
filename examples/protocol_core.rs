//! Protocol-core demo: HPACK and the HTTP/2 codec driven over an
//! in-memory pipe — no sockets, no `std` networking. This is the same
//! code that runs in `no_std` environments. (For a real transport you
//! would keep an internal leftover buffer on partial reads; the messages
//! here are small enough to fit in the 4 KiB pipe buffer.)
//!
//! Run with `cargo run --example protocol_core`.

use courierust::bytes::BytesMut;
use courierust::h2::connection::{Config as H2Config, Connection};
use courierust::h2::priority::Priority;
use courierust::hpack::{Decoder, Encoder, HeaderField};
use courierust::http::header::{HeaderName, HeaderValue};
use std::sync::mpsc;

/// A read-only in-memory pipe (inbound side of a connection).
struct Pipe {
    rx: mpsc::Receiver<Vec<u8>>,
}

/// A write-only in-memory sink (outbound side of a connection).
struct Sink {
    tx: mpsc::Sender<Vec<u8>>,
}

impl courierust::io::Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> courierust::Result<usize> {
        match self.rx.try_recv() {
            Ok(v) => {
                let n = core::cmp::min(buf.len(), v.len());
                buf[..n].copy_from_slice(&v[..n]);
                Ok(n)
            }
            Err(_) => Ok(0), // nothing buffered right now
        }
    }
}

impl courierust::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> courierust::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map_err(|_| courierust::Error::io("pipe closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> courierust::Result<()> {
        Ok(())
    }
}

fn main() -> courierust::Result<()> {
    // ---- HPACK round trip ----
    let mut enc = Encoder::new();
    let mut dec = Decoder::new(4096, 1 << 20);
    let fields = vec![
        HeaderField::new(
            HeaderName::from_lowercase(":method"),
            HeaderValue::from_static("GET"),
        ),
        HeaderField::new(
            HeaderName::from_lowercase(":path"),
            HeaderValue::from_static("/"),
        ),
        HeaderField::new(
            HeaderName::from_lowercase("user-agent"),
            HeaderValue::from_static("courierust"),
        ),
    ];
    let mut wire = BytesMut::with_capacity(64);
    enc.encode(&fields, &mut wire);
    let decoded = dec.decode(wire.as_slice())?;
    println!(
        "HPACK: encoded {} bytes -> decoded {} fields",
        wire.len(),
        decoded.len()
    );
    assert_eq!(decoded.len(), fields.len());

    // ---- HTTP/2 connection over a memory pipe ----
    // Connection wraps the transport in its own buffers internally, so
    // any type implementing the crate's io traits works — here an
    // in-memory pipe, in production a TCP or TLS stream.
    let (a2b, a2b_rx) = mpsc::channel::<Vec<u8>>();
    let (b2a, b2a_rx) = mpsc::channel::<Vec<u8>>();
    let reader = Pipe { rx: b2a_rx }; // inbound: peer -> us
    let writer = Sink { tx: a2b }; // outbound: us -> peer
    let mut conn = Connection::new(
        reader,
        writer,
        H2Config {
            client: true,
            ..Default::default()
        },
    );

    let sid = conn.open_request(Priority::default())?;
    conn.send_headers(sid, &fields, false)?; // body follows
    conn.send_data(sid, courierust::bytes::Bytes::from_static(b"hello"), true)?;
    conn.flush()?; // writes preface + SETTINGS + HEADERS + DATA into a2b

    // Confirm the bytes actually left the client into the pipe.
    let sent = a2b_rx
        .try_recv()
        .expect("outbound bytes should be in the pipe");
    println!(
        "h2: stream {sid} open, {} outbound bytes written",
        sent.len()
    );
    let _ = b2a; // the peer side (would feed b2a_rx) is not exercised here

    // ---- hashes used by the fingerprint builders ----
    use courierust::crypto::md5::md5_hex;
    use courierust::crypto::sha256::sha256_hex;
    println!("md5(hello)    = {}", md5_hex(b"hello"));
    println!("sha256(hello) = {}", sha256_hex(b"hello"));

    Ok(())
}
