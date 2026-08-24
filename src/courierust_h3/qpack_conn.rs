//! QPACK connection state (RFC 9204): the encoder and decoder roles that
//! sit on top of the pure codec in `super::qpack`.
//!
//! Each endpoint holds one encoder table (entries it inserts and
//! references) and one decoder table (entries the peer inserts and it
//! decodes with), plus the two instruction streams:
//!
//! * **Encoder stream** — Set Capacity, Insert With Name/Literal
//!   Reference and Duplicate instructions we emit; the peer applies them
//!   to its decoder table.
//! * **Decoder stream** — Section Acknowledgment, Stream Cancellation and
//!   Insert Count Increment instructions we emit (and the peer's, which
//!   raise the encoder-side Known Received Count).
//!
//! A field section whose Required Insert Count exceeds the entries we
//! have processed is *blocked*: it is buffered (bounded by the advertised
//! `SETTINGS_QPACK_BLOCKED_STREAMS`) and retried once the encoder stream
//! catches up (RFC 9204 §2.2.2.3).

use super::qpack::{self, DecoderInstruction, DynamicTable, EncoderInstruction, FieldLine};
use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_hpack::huffman::HuffmanDecoder;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

/// Headers whose values MUST NOT enter the dynamic table: sensitive
/// credentials (RFC 9204 §4.1.2 never-indexed guidance) and fields that
/// change on every message (inserting them would evict useful entries).
const NEVER_INDEX: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "date",
    "content-length",
    "etag",
    "last-modified",
    "age",
    "expires",
    "if-modified-since",
    "if-none-match",
];

/// Whether a header field is eligible for dynamic-table insertion.
fn indexable(name: &str, value: &[u8], capacity: usize) -> bool {
    // 32-octet overhead per entry (RFC 9204 §3.2.1) must fit.
    if name.len().saturating_add(value.len()).saturating_add(32) > capacity {
        return false;
    }
    !NEVER_INDEX.contains(&name)
}

/// A full QPACK endpoint: encoder + decoder tables, instruction streams,
/// acknowledged-insert accounting and blocked field sections.
pub(crate) struct QpackConnection {
    /// Entries we inserted; we reference them when encoding.
    encoder: DynamicTable,
    /// Entries the peer inserted; we decode field sections with it.
    decoder: DynamicTable,
    /// The capacity we advertise (`SETTINGS_QPACK_MAX_TABLE_CAPACITY`).
    capacity: u64,
    /// Blocked streams we advertise (`SETTINGS_QPACK_BLOCKED_STREAMS`).
    blocked_limit: u64,
    /// The capacity the peer advertised — caps our encoder table and
    /// sizes the RIC modulo range the peer will decode with.
    peer_capacity: u64,
    /// Encoder: how many of OUR inserts the peer has acknowledged via
    /// Insert Count Increment. We must not reference entries with an
    /// absolute index at or above this (RFC 9204 §2.2.2.2), except
    /// entries inserted in the current section (post-base).
    known_received: u64,
    /// Decoder: how many of the peer's inserts we have signaled via
    /// Insert Count Increment.
    signaled: u64,
    /// Pending encoder-stream instruction bytes (sent to the peer).
    encoder_out: Vec<u8>,
    /// Pending decoder-stream instruction bytes (sent to the peer).
    decoder_out: Vec<u8>,
    /// Blocked field sections: (stream id, encoded section).
    blocked: VecDeque<(u64, Vec<u8>)>,
    /// Shared RFC 7541 Huffman decoder (four-level tables built once, not
    /// per string literal — the H3 hot path decodes many literals per
    /// connection).
    huff: HuffmanDecoder,
}

impl QpackConnection {
    /// Create an endpoint with the given advertised settings.
    pub(crate) fn new(capacity: u64, blocked_limit: u64) -> Self {
        Self {
            encoder: DynamicTable::new(0),
            decoder: DynamicTable::new(0),
            capacity,
            blocked_limit,
            peer_capacity: 0,
            known_received: 0,
            signaled: 0,
            encoder_out: Vec::new(),
            decoder_out: Vec::new(),
            blocked: VecDeque::new(),
            huff: HuffmanDecoder::new(),
        }
    }

    /// The capacity we advertise.
    pub(crate) fn capacity(&self) -> u64 {
        self.capacity
    }

    /// The blocked-streams limit we advertise.
    pub(crate) fn blocked_limit(&self) -> u64 {
        self.blocked_limit
    }

    /// The peer's advertised capacity (from its SETTINGS). Enables the
    /// encoder table and emits the mandatory Set Capacity instruction on
    /// the encoder stream (RFC 9204 §4.3.1) once the peer's limit is
    /// known — the encoder must never exceed it.
    pub(crate) fn set_peer_capacity(&mut self, capacity: u64) {
        let effective = capacity.min(self.capacity);
        self.peer_capacity = capacity;
        self.encoder.set_capacity(effective as usize);
        if effective > 0 {
            qpack::encode_encoder_instruction(
                &EncoderInstruction::SetCapacity(effective),
                &mut self.encoder_out,
            );
        }
    }

    /// Whether there are pending encoder-stream bytes to flush.
    pub(crate) fn has_encoder_out(&self) -> bool {
        !self.encoder_out.is_empty()
    }

    /// Take the pending encoder-stream instruction bytes.
    pub(crate) fn take_encoder_out(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.encoder_out)
    }

    /// Re-queue encoder-stream bytes the transport could not send yet
    /// (a full congestion window defers them to the next tick).
    pub(crate) fn restore_encoder_out(&mut self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.encoder_out.splice(0..0, bytes);
        }
    }

    /// Whether there are pending decoder-stream bytes to flush.
    pub(crate) fn has_decoder_out(&self) -> bool {
        !self.decoder_out.is_empty()
    }

    /// Take the pending decoder-stream instruction bytes.
    pub(crate) fn take_decoder_out(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.decoder_out)
    }

    /// Re-queue decoder-stream bytes the transport could not send yet.
    pub(crate) fn restore_decoder_out(&mut self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.decoder_out.splice(0..0, bytes);
        }
    }

    /// Encode a field section with the dynamic table, appending any
    /// insert instructions to the encoder stream. `base` is fixed at the
    /// table's current insert count; entries added during this section
    /// are referenced post-base and contribute to the Required Insert
    /// Count. Pre-base references are limited to entries the peer has
    /// acknowledged (Known Received Count).
    pub(crate) fn encode(
        &mut self,
        fields: &[(String, Vec<u8>)],
        max_header_list: usize,
    ) -> Result<Vec<u8>> {
        let base = self.encoder.insert_count();
        let mut body = Vec::new();
        let mut required: u64 = 0;
        let mut total = 0usize;
        for (name, value) in fields {
            total = total
                .checked_add(name.len())
                .and_then(|t| t.checked_add(value.len()))
                .ok_or_else(|| Error::protocol("QPACK field-section size overflow"))?;
            if total > max_header_list
                || name.is_empty()
                || !name.bytes().all(|b| {
                    b == b':'
                        || b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || b == b'-'
                        || b == b'.'
                        || b == b'_'
                })
            {
                return Err(Error::protocol("invalid HTTP/3 header field"));
            }
            let value_str = core::str::from_utf8(value).unwrap_or("");
            // 1. Exact static match → indexed field line.
            if let Some(index) = qpack::static_index(name, value_str) {
                qpack::encode_integer(index, 6, 0xc0, &mut body);
                continue;
            }
            // 2. Exact dynamic match the peer has acknowledged → indexed
            //    (relative to base, below it).
            if let Some(abs) = self.encoder.find(name, value_str) {
                if abs < self.known_received && abs < base {
                    let relative = base - 1 - abs;
                    qpack::encode_integer(relative, 6, 0x80, &mut body);
                    required = required.max(abs + 1);
                    continue;
                }
            }
            // 3. Dynamic name match the peer has acknowledged → literal
            //    with name reference.
            if let Some(abs) = self.encoder.find_name(name) {
                if abs < self.known_received && abs < base {
                    let relative = base - 1 - abs;
                    qpack::encode_integer(relative, 4, 0x40, &mut body);
                    qpack::encode_string(value, 8, 0x00, &mut body);
                    required = required.max(abs + 1);
                    continue;
                }
            }
            // 4. Insert a new entry (eligible and fits) and reference it
            //    post-base. The encoder-stream instruction precedes the
            //    field section, so the peer processes it before decoding
            //    (blocking if the streams race, RFC 9204 §2.2.2.3).
            let capacity = self.encoder.capacity();
            if indexable(name, value, capacity) {
                if let Some(index) = qpack::static_name_index(name) {
                    qpack::encode_encoder_instruction(
                        &EncoderInstruction::InsertWithNameRef {
                            static_ref: true,
                            index,
                            value,
                        },
                        &mut self.encoder_out,
                    );
                } else if let Some(abs) = self.encoder.find_name(name) {
                    // Name exists in our table (peer may not have acked it);
                    // reference it relative to our current insert count.
                    let relative = self.encoder.insert_count() - 1 - abs;
                    qpack::encode_encoder_instruction(
                        &EncoderInstruction::InsertWithNameRef {
                            static_ref: false,
                            index: relative,
                            value,
                        },
                        &mut self.encoder_out,
                    );
                } else {
                    qpack::encode_encoder_instruction(
                        &EncoderInstruction::InsertWithLiteralName {
                            name: name.as_bytes(),
                            value,
                        },
                        &mut self.encoder_out,
                    );
                }
                if self.encoder.insert(name, value_str) {
                    let abs = self.encoder.insert_count() - 1;
                    let post_base = abs - base;
                    qpack::encode_integer(post_base, 4, 0x10, &mut body);
                    required = required.max(abs + 1);
                    continue;
                }
            }
            // 5. Fall back to a literal (static name reference when
            //    possible, else a full literal name).
            if let Some(index) = qpack::static_name_index(name) {
                qpack::encode_integer(index, 4, 0x50, &mut body);
                qpack::encode_string(value, 8, 0x00, &mut body);
            } else {
                qpack::encode_string(name.as_bytes(), 4, 0x20, &mut body);
                qpack::encode_string(value, 8, 0x00, &mut body);
            }
        }
        let mut out = Vec::with_capacity(4 + body.len());
        // The RIC modulo range is sized by the peer's advertised capacity
        // (RFC 9204 §4.5.1.1) — the range the peer decodes with.
        qpack::encode_field_section_prefix(required, base, self.peer_capacity.max(1), &mut out);
        out.extend_from_slice(&body);
        if out.len() > max_header_list {
            return Err(Error::protocol("encoded QPACK field section exceeds limit"));
        }
        Ok(out)
    }

    /// Apply peer encoder-stream instructions to the decoder table,
    /// emitting Insert Count Increments for the inserts processed.
    /// Returns the bytes consumed (partial on EOF). Enforces the
    /// advertised-capacity bound on Set Capacity (RFC 9204 §4.3.1).
    pub(crate) fn on_encoder_stream(&mut self, bytes: &[u8]) -> Result<usize> {
        let mut pos = 0;
        while pos < bytes.len() {
            let before = pos;
            let insert_count = self.decoder.insert_count();
            match qpack::decode_encoder_instruction(
                bytes,
                &mut pos,
                &mut self.decoder,
                insert_count,
                Some(self.capacity),
                &self.huff,
            ) {
                Ok(()) => {}
                Err(error) if error.kind == ErrorKind::UnexpectedEof => {
                    pos = before;
                    break;
                }
                Err(error) => return Err(error),
            }
            if pos == before {
                break; // no progress (defensive; cannot happen)
            }
        }
        self.flush_icc();
        Ok(pos)
    }

    /// Apply peer decoder-stream instructions: Insert Count Increment
    /// raises the encoder-side Known Received Count; Section
    /// Acknowledgments and Stream Cancellations are recorded. Returns the
    /// bytes consumed (partial on EOF).
    pub(crate) fn on_decoder_stream(&mut self, bytes: &[u8]) -> Result<usize> {
        let mut pos = 0;
        while pos < bytes.len() {
            let before = pos;
            match qpack::decode_decoder_instruction(bytes, &mut pos) {
                Ok(DecoderInstruction::InsertCountIncrement(increment)) => {
                    self.known_received = self
                        .known_received
                        .checked_add(increment)
                        .ok_or_else(|| Error::protocol("QPACK insert count overflow"))?;
                    if self.known_received > self.encoder.insert_count() {
                        // The peer cannot have inserted more than we sent.
                        return Err(Error::protocol(
                            "QPACK Insert Count Increment exceeds encoder inserts",
                        ));
                    }
                }
                Ok(DecoderInstruction::SectionAck(_))
                | Ok(DecoderInstruction::StreamCancellation(_)) => {}
                Err(error) if error.kind == ErrorKind::UnexpectedEof => {
                    pos = before;
                    break;
                }
                Err(error) => return Err(error),
            }
            if pos == before {
                break;
            }
        }
        Ok(pos)
    }

    /// Decode a field section from a request/response stream. `Ok(None)`
    /// means the section is blocked (Required Insert Count not yet met);
    /// it is buffered and retried by [`Self::retry_blocked`]. A fully
    /// decoded section that referenced dynamic entries emits a Section
    /// Acknowledgment (RFC 9204 §4.4.1).
    pub(crate) fn decode(
        &mut self,
        stream_id: u64,
        block: &[u8],
        max_header_list: usize,
    ) -> Result<Option<Vec<FieldLine>>> {
        if block.len() > max_header_list {
            return Err(Error::protocol(
                "QPACK field section exceeds configured limit",
            ));
        }
        match self.try_decode(stream_id, block, max_header_list)? {
            Some(fields) => Ok(Some(fields)),
            None => {
                if self.blocked.len() as u64 >= self.blocked_limit {
                    return Err(Error::protocol(
                        "QPACK blocked streams exceed SETTINGS_QPACK_BLOCKED_STREAMS",
                    ));
                }
                self.blocked.push_back((stream_id, block.to_vec()));
                Ok(None)
            }
        }
    }

    /// Emit a Stream Cancellation if a blocked section belongs to the
    /// given stream (the encoder must not wait for its acknowledgment).
    pub(crate) fn cancel_stream(&mut self, stream_id: u64) {
        let before = self.blocked.len();
        self.blocked.retain(|(id, _)| *id != stream_id);
        if self.blocked.len() != before {
            qpack::encode_decoder_instruction(
                &DecoderInstruction::StreamCancellation(stream_id),
                &mut self.decoder_out,
            );
        }
    }

    /// Retry buffered blocked sections now that the decoder table has
    /// advanced. Returns the streams whose headers can finally be
    /// decoded (with their field lists).
    pub(crate) fn retry_blocked(
        &mut self,
        max_header_list: usize,
    ) -> Result<Vec<(u64, Vec<FieldLine>)>> {
        let mut unblocked = Vec::new();
        let mut still = VecDeque::new();
        while let Some((stream_id, block)) = self.blocked.pop_front() {
            match self.try_decode(stream_id, &block, max_header_list)? {
                Some(fields) => unblocked.push((stream_id, fields)),
                None => still.push_back((stream_id, block)),
            }
        }
        self.blocked = still;
        Ok(unblocked)
    }

    /// Attempt to decode a field section without buffering. `Ok(None)` if
    /// still blocked. Emits a Section Acknowledgment when a section that
    /// referenced dynamic entries is fully decoded.
    fn try_decode(
        &mut self,
        stream_id: u64,
        block: &[u8],
        max_header_list: usize,
    ) -> Result<Option<Vec<FieldLine>>> {
        let mut pos = 0;
        let (required, base) = qpack::decode_field_section_prefix(
            block,
            &mut pos,
            self.decoder.insert_count(),
            self.capacity,
        )?;
        if required > self.decoder.insert_count() {
            return Ok(None);
        }
        let mut fields = Vec::new();
        let mut total = 0usize;
        while pos < block.len() {
            let field = qpack::decode_field_line(block, &mut pos, &self.decoder, base, &self.huff)?;
            total = total
                .checked_add(field.name.len())
                .and_then(|t| t.checked_add(field.value.len()))
                .ok_or_else(|| Error::protocol("QPACK field-section size overflow"))?;
            if total > max_header_list {
                return Err(Error::protocol("QPACK field-section limit exceeded"));
            }
            fields.push(field);
            if fields.len() > 256 {
                return Err(Error::protocol("HTTP/3 header field count exceeds limit"));
            }
        }
        if required > 0 {
            // Acknowledge the inserts first, then the section, so the
            // encoder can reference every entry the section used.
            self.flush_icc();
            qpack::encode_decoder_instruction(
                &DecoderInstruction::SectionAck(stream_id),
                &mut self.decoder_out,
            );
        }
        Ok(Some(fields))
    }

    /// Emit an Insert Count Increment for every peer insert we have
    /// processed but not yet signaled (RFC 9204 §4.4.3).
    fn flush_icc(&mut self) {
        let processed = self.decoder.insert_count();
        if processed > self.signaled {
            let increment = processed - self.signaled;
            self.signaled = processed;
            qpack::encode_decoder_instruction(
                &DecoderInstruction::InsertCountIncrement(increment),
                &mut self.decoder_out,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Drive one full encode → encoder-stream → decode round trip between
    /// two endpoints, including the decoder-stream acknowledgments.
    #[test]
    fn dynamic_table_round_trip_across_endpoints() {
        let mut client = QpackConnection::new(4096, 100); // our encoder
        let mut server = QpackConnection::new(4096, 100); // peer's decoder
        client.set_peer_capacity(4096);
        server.set_peer_capacity(4096);

        let fields = vec![
            (":method".to_string(), b"GET".to_vec()),
            (":path".to_string(), b"/resource".to_vec()),
            ("x-custom-tag".to_string(), b"alpha".to_vec()),
        ];
        let section = client.encode(&fields, 4096).unwrap();
        assert!(
            client.has_encoder_out(),
            "the first encode must emit encoder-stream instructions"
        );
        let encoder_bytes = client.take_encoder_out();

        // Feed the instructions to the peer's decoder.
        let consumed = server.on_encoder_stream(&encoder_bytes).unwrap();
        assert_eq!(consumed, encoder_bytes.len());
        // The decoder acknowledges the inserts it processed.
        assert!(server.has_decoder_out());
        let decoder_bytes = server.take_decoder_out();
        // The encoder applies the Insert Count Increment.
        let consumed = client.on_decoder_stream(&decoder_bytes).unwrap();
        assert_eq!(consumed, decoder_bytes.len());

        // Decode the section; dynamic entries were used (Required > 0).
        let decoded = server
            .decode(0, &section, 4096)
            .unwrap()
            .expect("section must decode after instructions");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].name, ":method");
        assert_eq!(decoded[0].value, b"GET");
        assert_eq!(decoded[2].name, "x-custom-tag");
        assert_eq!(decoded[2].value, b"alpha");
        // Section acknowledgment flowed back.
        assert!(server.has_decoder_out());

        // A second identical section now references the table (fewer
        // bytes than the first, which inserted the entries).
        let section2 = client.encode(&fields, 4096).unwrap();
        let _ = client.take_encoder_out(); // no new inserts expected
        assert!(section2.len() <= section.len());
        let decoded2 = server
            .decode(4, &section2, 4096)
            .unwrap()
            .expect("second section decodes");
        assert_eq!(decoded2.len(), 3);
    }

    /// A field section whose Required Insert Count exceeds the entries
    /// the decoder has processed is blocked and retried once the encoder
    /// stream catches up.
    #[test]
    fn blocked_section_is_buffered_then_unblocked() {
        let mut client = QpackConnection::new(4096, 100);
        let mut server = QpackConnection::new(4096, 100);
        client.set_peer_capacity(4096);

        let fields = vec![
            (":method".to_string(), b"GET".to_vec()),
            ("x-new-header".to_string(), b"value".to_vec()),
        ];
        let section = client.encode(&fields, 4096).unwrap();
        let encoder_bytes = client.take_encoder_out();

        // The decoder has not seen the instructions yet → blocked.
        assert!(server.decode(8, &section, 4096).unwrap().is_none());
        assert!(server.decode(12, &section, 4096).unwrap().is_none());
        assert_eq!(server.blocked.len(), 2);

        // Instructions arrive → both sections unblock.
        let consumed = server.on_encoder_stream(&encoder_bytes).unwrap();
        assert_eq!(consumed, encoder_bytes.len());
        let unblocked = server.retry_blocked(4096).unwrap();
        assert_eq!(unblocked.len(), 2);
        assert_eq!(unblocked[0].0, 8);
        assert_eq!(unblocked[0].1[1].value, b"value");
        assert!(server.blocked.is_empty());
    }

    /// A blocked section for a cancelled stream is removed and a Stream
    /// Cancellation instruction is emitted.
    #[test]
    fn cancel_stream_emits_stream_cancellation() {
        let mut server = QpackConnection::new(4096, 100);
        server.blocked.push_back((42, vec![0x00, 0x00]));
        server.cancel_stream(42);
        assert!(server.blocked.is_empty());
        assert!(server.has_decoder_out());
        let bytes = server.take_decoder_out();
        // `01` prefix + 6-bit integer = Stream Cancellation.
        assert_eq!(bytes[0] & 0xc0, 0x40);
    }

    /// An encoder that exceeds the decoder's advertised capacity is
    /// rejected (RFC 9204 §4.3.1).
    #[test]
    fn set_capacity_above_advertised_is_rejected() {
        let mut server = QpackConnection::new(4096, 100);
        let mut enc = Vec::new();
        qpack::encode_encoder_instruction(&EncoderInstruction::SetCapacity(8192), &mut enc);
        assert!(server.on_encoder_stream(&enc).is_err());
    }
}
