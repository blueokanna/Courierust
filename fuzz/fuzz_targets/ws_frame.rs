#![no_main]
//! WebSocket frame-codec fuzz target.
//!
//! Three things are checked, and each of them is a property rather than
//! "does not panic":
//!
//! * **The incremental UTF-8 validator agrees with itself across chunk
//!   boundaries.** A message split at arbitrary byte offsets must reach
//!   the same verdict as the same bytes in one call, and only a complete
//!   message may end cleanly. That equivalence *is* the reason the
//!   streaming validator exists; if it can disagree with `from_utf8`, a
//!   text frame is either rejected wrongly or accepted while illegal.
//! * **A header round-trips byte for byte**, and the length hint that lets
//!   a caller parse straight out of the read buffer agrees with the
//!   parser. A disagreement there is a framing bug two hops can see
//!   differently, which is the shape of a request-smuggling defect.
//! * **Masking is an involution, and the per-byte and lane paths are the
//!   same function.** The 16-byte lane optimisation is only correct if
//!   its phase bookkeeping matches the naive definition for every offset.

use courierust::courierust_ws::{FrameHeader, Mask, Utf8Validator, MAX_HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // ---- incremental UTF-8 validation -----------------------------
    let whole_message = Utf8Validator::validate(data);
    let chunk = 1.max(data.len() / 7);
    let mut split = Utf8Validator::new();
    let mut streamed_ok = true;
    for part in data.chunks(chunk) {
        if split.feed(part).is_err() {
            streamed_ok = false;
            break;
        }
    }
    assert_eq!(
        whole_message,
        streamed_ok && split.is_complete(),
        "chunked validation disagreed with a single call on {} bytes",
        data.len()
    );

    // ---- frame header ---------------------------------------------
    let Ok(Some(header)) = FrameHeader::parse(data) else {
        let _ = FrameHeader::header_len_hint(data);
        return;
    };
    let hint = FrameHeader::header_len_hint(data)
        .expect("a parsed header implies at least two bytes are available");
    assert_eq!(
        hint, header.header_len,
        "header_len_hint disagreed with parse"
    );

    let mut out = [0u8; MAX_HEADER_LEN];
    let written = header.write(&mut out);
    assert_eq!(written, header.header_len, "write disagreed with parse");
    assert_eq!(
        &out[..written],
        &data[..written],
        "the header must re-encode to the bytes that were parsed"
    );

    // Both reserved-bit policies are total.
    let _ = header.check_reserved(true);
    let _ = header.check_reserved(false);

    // ---- masking ---------------------------------------------------
    let payload = data[written..].to_vec();
    let mask = Mask::new(header.mask_key);

    let mut twice = payload.clone();
    mask.apply(0, &mut twice);
    mask.apply(0, &mut twice);
    assert_eq!(twice, payload, "masking must be an involution");

    let mut bulk = payload.clone();
    mask.apply(0, &mut bulk);

    let mut per_byte = payload.clone();
    let mut scratch = [0u8; 1];
    for (offset, byte) in per_byte.iter_mut().enumerate() {
        scratch[0] = *byte;
        mask.apply(offset, &mut scratch);
        *byte = scratch[0];
    }
    assert_eq!(
        bulk, per_byte,
        "the lane masking path disagreed with the byte-at-a-time definition"
    );
});
