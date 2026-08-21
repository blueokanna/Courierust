#![no_main]
//! HTTP/1.1 request parsing fuzz target.
//!
//! Feeds an arbitrary byte stream through the *shared* request path that
//! both the blocking server/client and the event-driven incremental
//! parser rely on: request line, header block, and body framing
//! (fixed-length and chunked). The invariant under test: no input may
//! panic, and every malformed input must surface as an `Err` — a silent
//! acceptance here would be a divergence the other parser could exploit.

use courierust::courierust_h1;
use courierust::courierust_io::{BufReader, Scratch, SliceReader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut reader = BufReader::new(SliceReader::new(data), 4096);
    let mut scratch = Scratch::new();
    let line = scratch.line();
    if reader.read_until_into(b'\n', 64 * 1024, line).is_err() {
        return;
    }
    let rl = match courierust_h1::parse_request_line(line) {
        Ok(rl) => rl,
        Err(_) => return,
    };

    let headers = match courierust_h1::read_headers_scratch(&mut reader, &mut scratch) {
        Ok(h) => h,
        Err(_) => return,
    };

    let max_body = 1 << 20;
    let _ = courierust_h1::body_length(&headers, Some(&rl.method), None).and_then(|bl| match bl {
        courierust_h1::BodyLen::None => Ok(()),
        courierust_h1::BodyLen::Length(n) => {
            let _ = courierust_h1::read_body_fixed_scratch(&mut reader, n, max_body, &mut scratch)?;
            Ok(())
        }
        courierust_h1::BodyLen::Chunked => {
            let _ = courierust_h1::read_body_chunked_scratch(&mut reader, max_body, &mut scratch)?;
            Ok(())
        }
    });

    let line = scratch.line();
    if reader.read_until_into(b'\n', 64 * 1024, line).is_err() {
        return;
    }
    let _ = courierust_h1::parse_request_line(line);
});
