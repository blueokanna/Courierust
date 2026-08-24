//! HTTP/3 framing demo (RFC 9114 §7.2) — the frame layer that runs on
//! top of QUIC, in isolation.
//!
//! The single innovation demonstrated here is *varint-addressed
//! framing*: every HTTP/3 frame is `type` + `length` (both QUIC
//! varints) + payload, and unknown extension frame types are preserved
//! losslessly rather than dropped. Unidirectional stream roles
//! (control / QPACK encoder / QPACK decoder) are also exposed.
//!
//! Run with `cargo run --example h3_frames`.

use courierust::courierust_h3::frame::{
    encode_stream_type, Frame, STREAM_TYPE_CONTROL, STREAM_TYPE_QPACK_ENCODER,
};
use courierust::courierust_quic::varint;

fn main() -> courierust::Result<()> {
    let frames = vec![
        Frame::Data(b"payload bytes".to_vec()),
        Frame::Headers(vec![0xc1, 0x00]),
        Frame::Settings(vec![(0x1, 4096), (0x7, 100)]),
        Frame::GoAway(3),
        Frame::MaxPushId(5),
        Frame::Unknown {
            frame_type: 0x21,
            payload: b"ext".to_vec(),
        },
    ];

    let mut wire = Vec::new();
    for frame in &frames {
        frame.encode(&mut wire);
    }
    println!("encoded {} frames -> {} bytes", frames.len(), wire.len());

    let mut pos = 0;
    let mut decoded = Vec::new();
    while let Some(frame) = Frame::decode(&wire, &mut pos)? {
        assert_eq!(frame.frame_type(), frames[decoded.len()].frame_type());
        decoded.push(frame);
    }
    assert_eq!(decoded.len(), frames.len());
    for (original, restored) in frames.iter().zip(&decoded) {
        assert_eq!(original, restored);
    }
    println!("all frames round-tripped exactly (including extension)");

    let frame = Frame::Settings(vec![(0x1, 4096)]);
    let wire = frame.to_bytes();
    assert_eq!(wire, [0x04, 0x04, 0x01, 0xff, 0x81, 0x1e]);
    println!("SETTINGS {{ qpack_cap=4096 }} -> {wire:02x?}");

    let control = encode_stream_type(STREAM_TYPE_CONTROL);
    let qpe = encode_stream_type(STREAM_TYPE_QPACK_ENCODER);
    assert_eq!(varint::read(&control)?, 0);
    assert_eq!(varint::read(&qpe)?, 2);
    println!("control stream type   -> {control:02x?}");
    println!("QPACK encoder stream  -> {qpe:02x?}");

    println!("all HTTP/3 framing rules verified");
    Ok(())
}
