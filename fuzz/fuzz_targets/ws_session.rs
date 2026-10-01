#![no_main]
//! WebSocket session state-machine fuzz target.
//!
//! Feeds arbitrary bytes through the *same* `Session` that the blocking
//! server, the reactor driver and the client all drive — in the server
//! role (inbound frames must be masked), the client role (they must not
//! be), and twice more with `permessage-deflate` negotiated so the
//! RFC 7692 inflate path, the decompression-bomb bound and the
//! negotiated-window check are all reachable from here.
//!
//! The invariant that matters for a byte protocol reachable from the
//! network is: no input may panic, hang, or allocate without bound, and
//! every rejection must arrive as an `Err`. A silently accepted malformed
//! frame is a divergence a proxy in front can exploit.

use courierust::courierust_io::{BufReader, SliceReader};
use courierust::courierust_ws::{
    CompressionParams, FrameWriter, MaskSource, Role, Session, SessionConfig, VecSink,
};
use libfuzzer_sys::fuzz_target;

/// Hard cap on the messages one input may drive, so a stream of tiny
/// frames cannot turn a single fuzz case into a benchmark.
const MAX_EVENTS: usize = 256;

/// Bounds every buffer the peer could otherwise choose: the session must
/// reject, not allocate.
const LIMIT: usize = 1 << 16;

fn drive(data: &[u8], role: Role, compression: Option<CompressionParams>) {
    let mask_source = match role {
        Role::Server => MaskSource::None,
        Role::Client => MaskSource::Fixed([0x11, 0x22, 0x33, 0x44]),
    };
    let reader = BufReader::new(SliceReader::new(data), 4096);
    let writer = FrameWriter::new(VecSink::new(), mask_source, compression);
    let mut session = Session::new(
        reader,
        writer,
        SessionConfig {
            role,
            max_frame: LIMIT,
            max_message: LIMIT,
            max_fragments: 64,
            compression,
            auto_pong: true,
        },
    );
    for _ in 0..MAX_EVENTS {
        match session.poll_message() {
            Ok(Some(_)) => continue,
            // `Ok(None)` is "nothing complete yet"; every other outcome is
            // terminal for the session.
            Ok(None) | Err(_) => return,
        }
    }
}

/// A full window: the ordinary negotiated case.
const FULL_WINDOW: CompressionParams = CompressionParams {
    send_window_bits: 15,
    send_no_context_takeover: true,
    recv_window_bits: 15,
    recv_no_context_takeover: true,
};

/// The smallest legal window: every back-reference in the input is
/// checked against a 256-byte history, which is the strictest the format
/// allows and the case a lenient decoder would wave through.
const TINY_WINDOW: CompressionParams = CompressionParams {
    send_window_bits: 8,
    send_no_context_takeover: true,
    recv_window_bits: 8,
    recv_no_context_takeover: true,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    let role = if selector & 1 == 0 {
        Role::Server
    } else {
        Role::Client
    };
    drive(payload, role, None);
    drive(payload, Role::Server, Some(FULL_WINDOW));
    drive(payload, Role::Server, Some(TINY_WINDOW));
});
