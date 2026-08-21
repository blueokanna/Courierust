#![no_main]
//! HTTP/2 connection state-machine fuzz target.
//!
//! Feeds an arbitrary byte stream into a live [`Connection`] (both a
//! client and a server endpoint) as a sequence of frames, exactly as a
//! hostile peer would send them. The invariant under test: frame
//! decoding, HPACK, flow control, stream state transitions and error
//! handling must never panic and must never allocate without bound.
//! Every malformed input must surface as a connection or stream error.

use courierust::courierust_h2::connection::{Config, Connection};
use courierust::courierust_io::{SliceReader, VecWriter};
use libfuzzer_sys::fuzz_target;

fn exercise(data: &[u8], client: bool) {
    let reader = SliceReader::new(data);
    let writer = VecWriter(Vec::new());
    let mut conn = Connection::new(
        reader,
        writer,
        Config {
            client,
            max_send_buffer: 1 << 20,
            ..Default::default()
        },
    );
    let _ = conn.poll_available(1024);
    while conn.next_event().is_some() {}
}

fuzz_target!(|data: &[u8]| {
    const CAP: usize = 64 * 1024;
    let data = &data[..data.len().min(CAP)];
    exercise(data, true);
    exercise(data, false);
});
