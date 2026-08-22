//! gRPC wire framing demo — the 5-byte length-prefixed message frame
//! every gRPC call is made of (gRPC A6).
//!
//! The single innovation demonstrated here is *framing in isolation*:
//! one flag byte (`0` = identity, `1` = gzip) followed by a 4-byte
//! big-endian payload length, then the payload. `frame_message`
//! produces exactly this, and the demo parses it back by hand so the
//! wire format is visible.
//!
//! Run with `cargo run --example grpc_framing`.

use courierust::courierust_grpc::frame_message;

fn main() -> courierust::Result<()> {
    let payload = b"hello gRPC";

    // --- Uncompressed frame -----------------------------------------
    let framed = frame_message(payload, false);
    assert_eq!(&framed[..5], &[0x00, 0x00, 0x00, 0x00, payload.len() as u8]);
    assert_eq!(&framed[5..], payload);
    println!(
        "identity frame: header={:02x?} payload={:?}",
        &framed[..5],
        String::from_utf8_lossy(&framed[5..])
    );

    // --- Compressed flag --------------------------------------------
    let framed = frame_message(payload, true);
    assert_eq!(framed[0], 0x01, "compression flag must be set");
    println!("compressed flag: header={:02x?}", &framed[..5]);

    // --- Manual parse of the wire format ----------------------------
    let (compressed, len) = parse_frame_header(&framed)?;
    assert!(compressed);
    assert_eq!(len, payload.len());
    assert_eq!(&framed[5..5 + len], payload);
    println!("parsed back: compressed={compressed} len={len}");

    // --- Larger payloads exercise the 4-byte length -----------------
    let big: Vec<u8> = vec![0x42; 1000];
    let framed = frame_message(&big, false);
    let (compressed, len) = parse_frame_header(&framed)?;
    assert!(!compressed);
    assert_eq!(len, big.len());
    assert_eq!(&framed[5..], &big[..]);
    println!(
        "1000-byte payload framed as len={len} (header {:02x?})",
        &framed[..5]
    );

    // --- Empty payload is legal (an empty protobuf message) ---------
    let framed = frame_message(b"", false);
    assert_eq!(framed, [0x00, 0x00, 0x00, 0x00, 0x00]);
    println!("empty message frames as {:02x?}", framed);

    println!("all gRPC framing rules verified");
    Ok(())
}

/// Parse the 5-byte gRPC frame header by hand.
fn parse_frame_header(buf: &[u8]) -> courierust::Result<(bool, usize)> {
    if buf.len() < 5 {
        return Err(courierust::Error::protocol("gRPC frame too short"));
    }
    let compressed = buf[0] != 0;
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    Ok((compressed, len))
}
