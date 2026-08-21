#![no_main]

use courierust::courierust_h2::frame::{Frame, FrameHeader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 || data.len() - 9 > 16 * 1024 {
        return;
    }
    let payload = &data[9..];
    let header = FrameHeader {
        len: payload.len() as u32,
        kind: data[3],
        flags: data[4],
        stream_id: u32::from_be_bytes([data[5] & 0x7f, data[6], data[7], data[8]]),
    };
    let _ = Frame::parse(header, payload, 16 * 1024);
});
