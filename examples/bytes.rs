//! Zero-copy byte buffer demo: `Bytes` shared views and `BytesMut`
//! append buffers.
//!
//! The single innovation demonstrated here is *windowed zero-copy*:
//! slicing, `split_to` / `split_off` and `freeze` only move a (start,
//! len) window over one shared allocation — they never copy the bytes
//! underneath. This is the buffer type every other protocol codec in
//! the crate is built on.
//!
//! Run with `cargo run --example bytes`.

use courierust::courierust_bytes::{Bytes, BytesMut};

fn main() {
    // --- BytesMut: an append-only builder ---------------------------
    let mut buf = BytesMut::with_capacity(4);
    buf.put_u8(0x01);
    buf.put_u16(0x0203);
    buf.put_u8(0x04);
    assert_eq!(buf.as_slice(), &[0x01, 0x02, 0x03, 0x04]);
    println!("BytesMut put_u8/put_u16/put_u8 -> {:02x?}", buf.as_slice());

    // `freeze` hands the allocation to an immutable Bytes (no copy).
    let bytes = buf.freeze();
    assert_eq!(bytes.len(), 4);
    println!("freeze -> len={} (single allocation, no copy)", bytes.len());

    // --- Bytes: windowed slicing shares the same allocation ---------
    let head = bytes.slice(0..2);
    let tail = bytes.slice_from(2);
    assert_eq!(head.as_slice(), &[0x01, 0x02]);
    assert_eq!(tail.as_slice(), &[0x03, 0x04]);
    println!(
        "slice(..2) -> {:02x?}   slice_from(2) -> {:02x?}",
        head.as_slice(),
        tail.as_slice()
    );

    // --- split_to / split_off: mutate the window, never the bytes ---
    let mut packet = Bytes::from_static(b"hello world");
    let hello = packet.split_to(5);
    assert_eq!(hello.as_slice(), b"hello");
    assert_eq!(packet.as_slice(), b" world");
    println!(
        "split_to(5) -> {:?}  |  remaining -> {:?}",
        hello.as_slice(),
        packet.as_slice()
    );

    // --- framing a protocol message out of zero-copy pieces ---------
    // A length-prefixed frame: [4-byte big-endian length][payload],
    // built by appending to one BytesMut and then splitting it.
    let payload = b"GET / HTTP/1.1";
    let mut frame = BytesMut::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    let mut frame = frame.freeze();
    let len_field = frame.split_to(4);
    let len = u32::from_be_bytes(len_field.as_slice().try_into().unwrap()) as usize;
    let body = frame.split_to(len);
    assert_eq!(body.as_slice(), payload);
    println!(
        "length-prefixed frame: len={len} body={:?} (split, zero-copy)",
        body.as_slice()
    );

    println!("all zero-copy window operations verified");
}
