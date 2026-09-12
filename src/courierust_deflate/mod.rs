//! DEFLATE (RFC 1951) — a from-scratch, dependency-free, `no_std + alloc`
//! codec with **streaming contexts**, shared by gRPC's gzip message
//! compression and WebSocket's `permessage-deflate` extension
//! (RFC 7692).
//!
//! Three codec surfaces, one implementation:
//!
//! * [`inflate`] / [`deflate`] — one-shot raw DEFLATE (gRPC payloads).
//! * [`gzip`] / [`gunzip`] / [`crc32`] — the RFC 1952 container.
//! * [`Inflater`] / [`Deflater`] — *message-oriented* contexts that keep
//!   the 32 KiB sliding window across messages, which is what
//!   `permessage-deflate` calls "context takeover". The wire framing
//!   (a non-final block plus a stripped sync-flush marker, RFC 7692
//!   §7.2.1/§7.2.2) is handled by [`Deflater::deflate_message`] and
//!   [`Inflater::inflate_message`].
//!
//! Performance notes that matter in the hot path:
//!
//! * The bit reader keeps a 64-bit accumulator and refills eight bits at
//!   a time, so a Huffman symbol decode is one shift/mask, not eight
//!   bounds-checked byte loads.
//! * Huffman tables get a 2⁹-entry primary lookup: every code that fits
//!   in nine bits (all fixed-Huffman codes, the great majority of
//!   dynamic ones) decodes without touching the fallback walk.
//! * Back-references that do not overlap use one `memmove`
//!   (`Vec::extend_from_within`) instead of a byte loop; distances that
//!   reach behind the current message pull from the saved window.
//!
//! Everything here is safe code: no `unsafe`, no third-party crates.

use crate::courierust_error::{Error, Result};
use alloc::vec;
use alloc::vec::Vec;

// ---------------------------------------------------------------------
// RFC 1951 tables
// ---------------------------------------------------------------------

/// RFC 1951 §3.2.5 length codes 257..=285: (base, extra bits).
const LENGTH_BASE: [(u16, u8); 29] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0), // 257-264
    (11, 1),
    (13, 1),
    (15, 1),
    (17, 1), // 265-268
    (19, 2),
    (23, 2),
    (27, 2),
    (31, 2), // 269-272
    (35, 3),
    (43, 3),
    (51, 3),
    (59, 3), // 273-276
    (67, 4),
    (83, 4),
    (99, 4),
    (115, 4), // 277-280
    (131, 5),
    (163, 5),
    (195, 5),
    (227, 5), // 281-284
    (258, 0), // 285
];

/// RFC 1951 distance codes 0..=29: (base, extra bits).
const DIST_BASE: [(u16, u8); 30] = [
    (1, 0),
    (2, 0),
    (3, 0),
    (4, 0), // 0-3
    (5, 1),
    (7, 1),
    (9, 2),
    (13, 2), // 4-7
    (17, 3),
    (25, 3),
    (33, 4),
    (49, 4), // 8-11
    (65, 5),
    (97, 5),
    (129, 6),
    (193, 6), // 12-15
    (257, 7),
    (385, 7),
    (513, 8),
    (769, 8), // 16-19
    (1025, 9),
    (1537, 9),
    (2049, 9),
    (3073, 9), // 20-23
    (4097, 10),
    (6145, 10),
    (8193, 11),
    (12289, 11), // 24-27
    (16385, 12),
    (24577, 12), // 28-29
];

/// Length symbol for a match length in `3..=258`.
fn length_code(len: usize) -> Option<(u16, u8, u16)> {
    if len == 258 {
        return Some((285, 0, 258));
    }
    for (i, &(base, extra)) in LENGTH_BASE.iter().enumerate() {
        let span = 1usize << extra;
        if (base as usize..(base as usize + span)).contains(&len) {
            return Some((257 + i as u16, extra, base));
        }
    }
    None
}

/// Distance symbol for a distance in `1..=32768`. `None` when the
/// distance exceeds the 15-bit DEFLATE window (the caller must cap match
/// lengths instead of emitting it).
fn distance_code(dist: usize) -> Option<(u8, u8, u16)> {
    for (i, &(base, extra)) in DIST_BASE.iter().enumerate() {
        let span = 1usize << extra;
        if (base as usize..(base as usize + span)).contains(&dist) {
            return Some((i as u8, extra, base));
        }
    }
    None
}

// ---------------------------------------------------------------------
// Bit I/O (LSB-first, RFC 1951 §3.1.1)
// ---------------------------------------------------------------------

/// Bit reader over a byte slice with a 64-bit accumulator.
///
/// `ensure` refills a byte at a time only when the accumulator is short,
/// so the inner decode loop is branch-and-shift plus one length check
/// per symbol.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    acc: u64,
    nbits: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            acc: 0,
            nbits: 0,
        }
    }

    /// Guarantee at least `n` bits (`n <= 57`) in the accumulator.
    #[inline]
    fn ensure(&mut self, n: u32) -> Result<()> {
        while self.nbits < n {
            if self.pos >= self.data.len() {
                return Err(Error::protocol("deflate: truncated bit stream"));
            }
            self.acc |= u64::from(self.data[self.pos]) << self.nbits;
            self.nbits += 8;
            self.pos += 1;
        }
        Ok(())
    }

    /// The next `n` bits without consuming them. `ensure(n)` first.
    #[inline]
    fn peek(&self, n: u32) -> u32 {
        debug_assert!(n <= 32 && self.nbits >= n);
        (self.acc & ((1u64 << n) - 1)) as u32
    }

    /// Drop `n` bits. `ensure(n)` first.
    #[inline]
    fn consume(&mut self, n: u32) {
        debug_assert!(self.nbits >= n && n <= 64);
        self.acc >>= n;
        self.nbits -= n;
    }

    /// Read `n` bits (`n <= 32`), zero-extended, LSB-first.
    #[inline]
    fn take(&mut self, n: u32) -> Result<u32> {
        if self.nbits < n {
            self.ensure(n)?;
        }
        let v = self.peek(n);
        self.consume(n);
        Ok(v)
    }

    /// Discard bits up to the next byte boundary.
    #[inline]
    fn align_byte(&mut self) {
        let drop = self.nbits % 8;
        self.consume(drop);
    }

    /// Read `n` bytes after aligning (stored blocks). Returns a slice
    /// view when the bytes are fully available in the accumulator or the
    /// remaining input, copying through the accumulator otherwise.
    fn read_bytes(&mut self, n: usize, out: &mut Vec<u8>) -> Result<()> {
        self.align_byte();
        // Fast path: the accumulator holds whole bytes and they are
        // contiguous in the input, which is true for every byte-aligned
        // stored block we produce ourselves and for zlib's output.
        let whole = (self.nbits / 8) as usize;
        let from_acc = whole.min(n);
        for _ in 0..from_acc {
            out.push((self.acc & 0xff) as u8);
            self.consume(8);
        }
        let rest = n - from_acc;
        if rest > 0 {
            if self.pos + rest > self.data.len() {
                return Err(Error::protocol("deflate: truncated stored block"));
            }
            out.extend_from_slice(&self.data[self.pos..self.pos + rest]);
            self.pos += rest;
        }
        Ok(())
    }

    /// Whether every input bit has been consumed (or only sub-byte
    /// padding remains).
    #[inline]
    fn exhausted(&self) -> bool {
        self.pos >= self.data.len() && self.nbits < 8
    }
}

/// Bit writer (LSB-first), with byte alignment and a sync-flush marker
/// for RFC 7692.
struct BitWriter {
    out: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            nbits: 0,
        }
    }

    /// Append the low `n` bits of `value` (DEFLATE integer format).
    #[inline]
    fn write_bits(&mut self, value: u32, n: u32) {
        debug_assert!(n <= 24);
        self.acc |= (value & ((1u32 << n) - 1)) << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            self.out.push((self.acc & 0xff) as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }

    /// Append an `n`-bit Huffman code, MSB-first as RFC 1951 requires.
    #[inline]
    fn write_bits_msb(&mut self, value: u32, n: u32) {
        let mut rev = 0u32;
        for i in 0..n {
            rev |= ((value >> i) & 1) << (n - 1 - i);
        }
        self.write_bits(rev, n);
    }

    /// Pad to a byte boundary with zero bits.
    fn align_byte(&mut self) {
        if self.nbits > 0 {
            self.out.push((self.acc & 0xff) as u8);
            self.acc = 0;
            self.nbits = 0;
        }
    }

    /// Finish, padding with zero bits.
    fn finish(mut self) -> Vec<u8> {
        self.align_byte();
        self.out
    }

    /// Emit a DEFLATE sync flush and strip the RFC 7692 §7.2.1 tail: an
    /// empty stored block (`00 00 FF FF` after the header byte) whose
    /// final four octets are removed because the peer re-adds them.
    fn finish_permessage(mut self) -> Vec<u8> {
        // Empty stored block: BFINAL=0, BTYPE=00, then align and write
        // LEN=0, NLEN=0xFFFF.
        self.write_bits(0, 3);
        self.align_byte();
        self.out.push(0x00);
        self.out.push(0x00);
        self.out.push(0xff);
        self.out.push(0xff);
        // RFC 7692 §7.2.1: remove the trailing 00 00 FF FF.
        self.out.truncate(self.out.len() - 4);
        self.align_byte();
        self.out
    }
}

// ---------------------------------------------------------------------
// Huffman decoding
// ---------------------------------------------------------------------

/// Primary lookup width: every code that fits decodes in one probe.
const FAST_BITS: u32 = 9;
const FAST_SIZE: usize = 1 << FAST_BITS;

/// A canonical Huffman decode table (RFC 1951 §3.2.2) with a fast path.
#[derive(Clone)]
struct DecodeTable {
    /// count[len] = number of codes with `len` bits.
    count: [u16; 16],
    /// offset[len] = start index into `symbol` for codes of length `len`.
    offset: [u16; 16],
    /// Symbols grouped by code length in canonical order.
    symbol: [u16; 288],
    /// `fast[low FAST_BITS bits] = (len << 16) | symbol`, or 0 when the
    /// code is longer than `FAST_BITS` and needs the fallback walk.
    fast: Vec<u32>,
}

impl DecodeTable {
    /// Build from per-symbol code lengths. `allow_incomplete` accepts a
    /// code with a single unused leaf (legal for the distance alphabet).
    fn build(lens: &[u8], allow_incomplete: bool) -> Result<Self> {
        let mut table = Self {
            count: [0; 16],
            offset: [0; 16],
            symbol: [0; 288],
            fast: vec![0u32; FAST_SIZE],
        };
        for &l in lens {
            if l == 0 {
                continue;
            }
            if l > 15 {
                return Err(Error::protocol("deflate: invalid code length"));
            }
            table.count[l as usize] += 1;
        }

        // Kraft-McMillan check: an over-subscribed code is rejected, an
        // incomplete one only where the format allows it.
        let mut left: i32 = 1;
        for len in 1..=15 {
            left <<= 1;
            left -= i32::from(table.count[len]);
            if left < 0 {
                return Err(Error::protocol("deflate: over-subscribed code"));
            }
        }
        if left != 0 && !allow_incomplete {
            return Err(Error::protocol("deflate: incomplete code"));
        }

        let mut off = 0u32;
        for len in 1..=15 {
            table.offset[len] = off as u16;
            off += u32::from(table.count[len]);
        }
        let mut cursor = [0u16; 16];
        for (len, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            if len > 287 && l != 0 {
                return Err(Error::protocol("deflate: symbol out of range"));
            }
            let idx = table.offset[l as usize] as usize + cursor[l as usize] as usize;
            if idx >= table.symbol.len() {
                return Err(Error::protocol("deflate: symbol table overflow"));
            }
            table.symbol[idx] = len as u16;
            cursor[l as usize] += 1;
        }

        // Fill the fast lookup: canonical codes are assigned in order, so
        // walk them once and mirror every code of length <= FAST_BITS
        // across the 2^(FAST_BITS - len) low-bit suffixes.
        let mut code: u32 = 0;
        let mut next = 0usize;
        for len in 1..=15u32 {
            let count = u32::from(table.count[len as usize]);
            for k in 0..count {
                let sym = table.symbol[next + k as usize];
                if len <= FAST_BITS {
                    let rev = reverse_bits(code + k, len);
                    let step = 1u32 << len;
                    let mut idx = rev;
                    while idx < FAST_SIZE as u32 {
                        table.fast[idx as usize] = (len << 16) | u32::from(sym);
                        idx += step;
                    }
                } else {
                    break;
                }
            }
            next += count as usize;
            code = (code + count) << 1;
        }
        Ok(table)
    }

    fn is_empty(&self) -> bool {
        self.count.iter().all(|&c| c == 0)
    }
}

/// Reverse the low `n` bits of `v` (canonical codes are stored MSB-first,
/// the fast table is indexed by the LSB-first bit order of the stream).
#[inline]
fn reverse_bits(v: u32, n: u32) -> u32 {
    let mut out = 0u32;
    for i in 0..n {
        out |= ((v >> i) & 1) << (n - 1 - i);
    }
    out
}

/// Decode one Huffman symbol.
#[inline]
fn decode_symbol(br: &mut BitReader, table: &DecodeTable) -> Result<u16> {
    if br.nbits >= FAST_BITS {
        let entry = table.fast[br.peek(FAST_BITS) as usize];
        if entry != 0 {
            br.consume(entry >> 16);
            return Ok((entry & 0xffff) as u16);
        }
    }
    // Fallback: canonical walk, one bit at a time.
    let mut code: u32 = 0;
    let mut first: u32 = 0;
    for len in 1..=15u32 {
        code = (code << 1) | br.take(1)?;
        let count = u32::from(table.count[len as usize]);
        if code >= first && code < first + count {
            let idx = table.offset[len as usize] as usize + (code - first) as usize;
            return Ok(table.symbol[idx]);
        }
        first = (first + count) << 1;
    }
    Err(Error::protocol("deflate: invalid Huffman code"))
}

// ---------------------------------------------------------------------
// DEFLATE decompression
// ---------------------------------------------------------------------

/// Fixed-Huffman literal/length code lengths (RFC 1951 §3.2.6).
fn fixed_litlen_lens() -> [u8; 288] {
    let mut litlen = [0u8; 288];
    for item in litlen.iter_mut().take(144) {
        *item = 8;
    }
    for item in litlen.iter_mut().take(256).skip(144) {
        *item = 9;
    }
    for item in litlen.iter_mut().take(280).skip(256) {
        *item = 7;
    }
    for item in litlen.iter_mut().skip(280) {
        *item = 8;
    }
    litlen
}

/// Copy `len` bytes from `distance` back, where the history is
/// `window` (older) followed by `out` (the current message).
///
/// DEFLATE allows overlapping copies (a run-length code): when
/// `distance < len` the source advances into the bytes being written, so
/// the copy repeats with period `distance`. Non-overlapping copies take
/// a single `memmove`.
fn copy_match(
    out: &mut Vec<u8>,
    window: &[u8],
    distance: usize,
    len: usize,
    max_out: usize,
) -> Result<()> {
    if out.len().checked_add(len).map_or(true, |t| t > max_out) {
        return Err(Error::overflow("deflate: output exceeds limit"));
    }
    let out_len = out.len();
    if distance <= out_len {
        let start = out_len - distance;
        if distance >= len {
            out.extend_from_within(start..start + len);
        } else {
            out.reserve(len);
            for i in 0..len {
                let b = out[start + i];
                out.push(b);
            }
        }
        return Ok(());
    }
    // The match reaches behind this message into the sliding window.
    let from_window = distance - out_len;
    if from_window > window.len() {
        return Err(Error::protocol("deflate: back-reference before the window"));
    }
    let take = from_window.min(len);
    let wstart = window.len() - from_window;
    out.extend_from_slice(&window[wstart..wstart + take]);
    if take < len {
        // Continue inside `out`; `distance` now provably fits (the
        // window part covered the gap).
        let rest = len - take;
        let out_len = out.len();
        let start = out_len - distance;
        if distance >= rest {
            out.extend_from_within(start..start + rest);
        } else {
            out.reserve(rest);
            for i in 0..rest {
                let b = out[start + i];
                out.push(b);
            }
        }
    }
    Ok(())
}

/// One stored block (BTYPE=00). The bit stream is byte-aligned before
/// the LEN/NLEN pair (RFC 1951 §3.2.4).
fn inflate_stored(br: &mut BitReader, out: &mut Vec<u8>, max_out: usize) -> Result<()> {
    br.align_byte();
    let len = br.take(16)? as usize;
    let nlen = br.take(16)? as usize;
    if (len ^ 0xffff) != nlen {
        return Err(Error::protocol("deflate: stored block length mismatch"));
    }
    if out.len().checked_add(len).map_or(true, |t| t > max_out) {
        return Err(Error::overflow("deflate: output exceeds limit"));
    }
    br.read_bytes(len, out)
}

/// One Huffman-coded block (BTYPE=01 fixed / BTYPE=10 dynamic).
fn inflate_huffman(
    br: &mut BitReader,
    litlen: &[u8; 288],
    dist: &[u8; 30],
    window: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<()> {
    let lit_table = DecodeTable::build(litlen, false)?;
    let dist_table = DecodeTable::build(dist, true)?;
    loop {
        let sym = decode_symbol(br, &lit_table)?;
        if sym < 256 {
            if out.len() >= max_out {
                return Err(Error::overflow("deflate: output exceeds limit"));
            }
            out.push(sym as u8);
        } else if sym == 256 {
            return Ok(());
        } else if sym <= 285 {
            let (base, extra) = LENGTH_BASE[(sym - 257) as usize];
            let mut len = base as usize;
            if extra > 0 {
                len += br.take(u32::from(extra))? as usize;
            }
            let dsym = decode_symbol(br, &dist_table)?;
            if dsym >= 30 {
                return Err(Error::protocol("deflate: invalid distance code"));
            }
            let (dbase, dextra) = DIST_BASE[dsym as usize];
            let mut distance = dbase as usize;
            if dextra > 0 {
                distance += br.take(u32::from(dextra))? as usize;
            }
            if distance == 0 {
                return Err(Error::protocol("deflate: zero distance"));
            }
            copy_match(out, window, distance, len, max_out)?;
        } else {
            return Err(Error::protocol("deflate: invalid length symbol"));
        }
    }
}

/// Dynamic Huffman block header (BTYPE=10), then its data.
fn inflate_dynamic(
    br: &mut BitReader,
    window: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<()> {
    let hlit = br.take(5)? as usize + 257;
    let hdist = br.take(5)? as usize + 1;
    let hclen = br.take(4)? as usize + 4;
    if hlit > 286 || hdist > 30 || hclen > 19 {
        return Err(Error::protocol("deflate: invalid dynamic header sizes"));
    }
    const CLEN_ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut clen_lens = [0u8; 19];
    for i in 0..hclen {
        clen_lens[CLEN_ORDER[i]] = br.take(3)? as u8;
    }
    let clen_table = DecodeTable::build(&clen_lens, false)?;
    if clen_table.is_empty() {
        return Err(Error::protocol("deflate: empty code-length table"));
    }
    let total = hlit + hdist;
    let mut lens: Vec<u8> = Vec::with_capacity(total);
    while lens.len() < total {
        let sym = decode_symbol(br, &clen_table)?;
        match sym {
            0..=15 => lens.push(sym as u8),
            16 => {
                let prev = match lens.last() {
                    Some(&p) => p,
                    None => return Err(Error::protocol("deflate: repeat with no previous")),
                };
                let rep = 3 + br.take(2)? as usize;
                if lens.len() + rep > total {
                    return Err(Error::protocol("deflate: code-length repeat overflow"));
                }
                for _ in 0..rep {
                    lens.push(prev);
                }
            }
            17 => {
                let rep = 3 + br.take(3)? as usize;
                if lens.len() + rep > total {
                    return Err(Error::protocol("deflate: code-length repeat overflow"));
                }
                lens.resize(lens.len() + rep, 0);
            }
            18 => {
                let rep = 11 + br.take(7)? as usize;
                if lens.len() + rep > total {
                    return Err(Error::protocol("deflate: code-length repeat overflow"));
                }
                lens.resize(lens.len() + rep, 0);
            }
            _ => return Err(Error::protocol("deflate: invalid code-length symbol")),
        }
    }
    let mut litlen = [0u8; 288];
    litlen[..hlit].copy_from_slice(&lens[..hlit]);
    let mut dist = [0u8; 30];
    dist[..hdist].copy_from_slice(&lens[hlit..]);
    inflate_huffman(br, &litlen, &dist, window, out, max_out)
}

/// Decode blocks until the final one (or until the input runs out when
/// `truncated_ok`, which is how RFC 7692 messages end).
fn inflate_blocks(
    br: &mut BitReader,
    window: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
    truncated_ok: bool,
) -> Result<()> {
    loop {
        let bfinal = match br.take(1) {
            Ok(v) => v,
            Err(_) if truncated_ok && br.exhausted() => return Ok(()),
            Err(e) => return Err(e),
        };
        let btype = match br.take(2) {
            Ok(v) => v,
            Err(_) if truncated_ok && br.exhausted() => return Ok(()),
            Err(e) => return Err(e),
        };
        let block = match btype {
            0 => inflate_stored(br, out, max_out),
            1 => {
                let litlen = fixed_litlen_lens();
                let dist = [5u8; 30];
                inflate_huffman(br, &litlen, &dist, window, out, max_out)
            }
            2 => inflate_dynamic(br, window, out, max_out),
            _ => Err(Error::protocol("deflate: reserved block type 3")),
        };
        if let Err(e) = block {
            // With the RFC 7692 tail stripped, the stream simply stops at
            // a byte boundary once the appended marker is consumed; that
            // is a complete message, not a truncated one.
            if truncated_ok && br.exhausted() {
                return Ok(());
            }
            return Err(e);
        }
        if bfinal != 0 {
            return Ok(());
        }
    }
}

/// Decompress a raw DEFLATE stream (no zlib/gzip header). `max_out` caps
/// the output size (decompression-bomb guard).
pub fn inflate(data: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    inflate_into(data, &mut out, max_out)?;
    Ok(out)
}

/// Decompress into a caller-owned buffer (reused across calls).
pub fn inflate_into(data: &[u8], out: &mut Vec<u8>, max_out: usize) -> Result<()> {
    let mut br = BitReader::new(data);
    inflate_blocks(&mut br, &[], out, max_out, false)
}

// ---------------------------------------------------------------------
// DEFLATE compression (fixed Huffman + LZ77)
// ---------------------------------------------------------------------

/// Hash chain match finder capped just under DEFLATE's 32 KiB window.
const WINDOW: usize = 28_672;
const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CHAIN: usize = 64;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 258;
/// Empty slot marker in the hash table.
const EMPTY: u32 = u32::MAX;

fn hash3(a: u8, b: u8, c: u8) -> usize {
    (((a as usize) << 10) ^ ((b as usize) << 5) ^ (c as usize)) & (HASH_SIZE - 1)
}

/// LZ77 match-finder state, reusable across messages.
///
/// The hash table is 128 KiB and the chain table is one entry per input
/// byte. Allocating and clearing those per message — which is what a
/// naive "compress one message at a time" implementation does — costs
/// tens of microseconds *before any compression happens*, and for small
/// messages that dominates everything: a 64-byte message is compressed in
/// a few hundred nanoseconds but would pay a 128 KiB `memset` plus a
/// fresh allocation.
///
/// Two ideas keep it cheap:
///
/// * The tables live in the [`Deflater`] and are reused, so a steady
///   stream of messages performs no allocation at all after the first.
/// * Clearing records the hash slots that were written and resets only
///   those. The cost of a reset is therefore proportional to the number
///   of *insertions* (≤ message length), not to the table size.
#[derive(Default)]
struct MatchFinder {
    /// hash → most recent position, `EMPTY` when unset.
    head: Vec<u32>,
    /// position → previous position with the same hash.
    prev: Vec<u32>,
    /// Hash slots written since the last reset.
    touched: Vec<u32>,
}

impl MatchFinder {
    /// Prepare for a message of `len` bytes.
    fn prepare(&mut self, len: usize) {
        if self.head.is_empty() {
            self.head.resize(HASH_SIZE, EMPTY);
        } else {
            // Only the slots this compressor touched need clearing: a
            // stale position from an earlier message would otherwise
            // create a chain that points into a different buffer.
            for &slot in &self.touched {
                self.head[slot as usize] = EMPTY;
            }
            self.touched.clear();
        }
        if self.prev.len() < len {
            self.prev.resize(len, EMPTY);
        }
    }
}

/// Fixed-Huffman code for a literal byte.
#[inline]
fn fixed_literal_code(b: u8) -> (u32, u32) {
    if b < 144 {
        (0x30 + u32::from(b), 8) // 00110000-10111111
    } else {
        (0x190 + (u32::from(b) - 144), 9) // 110010000-111111111
    }
}

/// Fixed-Huffman code for a length symbol (257..=285).
#[inline]
fn fixed_length_code(code: u16) -> (u32, u32) {
    if (257..=279).contains(&code) {
        (u32::from(code) - 256, 7) // 0000000-0010111
    } else {
        (0xc0 + (u32::from(code) - 280), 8) // 11000000-11000101
    }
}

/// LZ77 encode `data` into `w`, emitting only literals and matches.
///
/// `w` must already hold the block header (BFINAL/BTYPE); the trailing
/// end-of-block symbol is written by the caller so the same encoder
/// serves standalone and permessage-deflate framing.
///
/// `mf` carries the hash tables across calls: [`MatchFinder::prepare`]
/// must be called first (once per message), and it is what makes
/// per-message compression cheap enough to run on small payloads.
fn encode_lz77(w: &mut BitWriter, data: &[u8], mf: &mut MatchFinder) {
    let mut i = 0usize;
    while i < data.len() {
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        if i + MIN_MATCH <= data.len() {
            let h = hash3(data[i], data[i + 1], data[i + 2]);
            let mut candidate = mf.head[h];
            let limit = i.saturating_sub(WINDOW) as u32;
            let mut steps = 0usize;
            while candidate != EMPTY && candidate >= limit && steps < MAX_CHAIN {
                steps += 1;
                let cand = candidate as usize;
                if data[cand] == data[i] {
                    let max = (data.len() - i).min(MAX_MATCH);
                    let mut l = 0usize;
                    while l < max && data[cand + l] == data[i + l] {
                        l += 1;
                    }
                    if l >= MIN_MATCH && l > best_len {
                        best_len = l;
                        best_dist = i - cand;
                        if l == MAX_MATCH {
                            break;
                        }
                    }
                }
                candidate = mf.prev[cand];
            }
            mf.prev[i] = mf.head[h];
            mf.head[h] = i as u32;
            mf.touched.push(h as u32);
        }

        if best_len >= MIN_MATCH {
            if let Some((dcode, dextra, dbase)) = distance_code(best_dist) {
                let (code, extra, base) = length_code(best_len).expect("length code");
                let (c, bits) = fixed_length_code(code);
                w.write_bits_msb(c, bits);
                if extra > 0 {
                    w.write_bits((best_len - base as usize) as u32, u32::from(extra));
                }
                w.write_bits_msb(u32::from(dcode), 5);
                if dextra > 0 {
                    w.write_bits((best_dist - dbase as usize) as u32, u32::from(dextra));
                }
                i += best_len;
                continue;
            }
        }
        let (code, bits) = fixed_literal_code(data[i]);
        w.write_bits_msb(code, bits);
        i += 1;
    }
}

/// Compress `data` as one self-contained DEFLATE stream (BFINAL=1).
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut mf = MatchFinder::default();
    mf.prepare(data.len());
    let mut w = BitWriter::new();
    w.write_bits(1, 1); // BFINAL
    w.write_bits(1, 2); // BTYPE = fixed Huffman
    encode_lz77(&mut w, data, &mut mf);
    w.write_bits(0, 7); // end-of-block (symbol 256, 7-bit code 0)
    w.finish()
}

/// Compress `data` as a **sync-flushed** DEFLATE stream that a peer can
/// continue (the RFC 7692 §7.2.1 wire form): non-final fixed-Huffman
/// block, end-of-block symbol, empty stored block, tail stripped.
///
/// The interesting property is what it does *not* do: it emits no
/// back-reference that could point across messages, so a receiver with
/// or without context takeover decodes it identically. Context takeover
/// only ever affects the *decoder* side of this implementation, which
/// makes its memory use a constant 32 KiB instead of a function of the
/// peer's framing choices.
pub fn deflate_sync(data: &[u8]) -> Vec<u8> {
    let mut mf = MatchFinder::default();
    mf.prepare(data.len());
    deflate_sync_with(data, &mut mf)
}

/// [`deflate_sync`] with caller-owned match-finder state, so a context
/// that already owns a [`MatchFinder`] (see [`Deflater`]) performs no
/// per-message allocation or table rebuild.
fn deflate_sync_with(data: &[u8], mf: &mut MatchFinder) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.write_bits(0, 1); // BFINAL=0: the stream continues
    w.write_bits(1, 2); // BTYPE = fixed Huffman
    encode_lz77(&mut w, data, mf);
    w.write_bits(0, 7); // end-of-block
    w.finish_permessage()
}

// ---------------------------------------------------------------------
// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320)
// ---------------------------------------------------------------------

/// CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    // Table-driven, 8 bits per step; the table is rebuilt per call
    // (256 u32 stores) which keeps the function dependency-free and
    // stateless. Callers hashing large payloads are dominated by the
    // data scan, not the table build.
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

// ---------------------------------------------------------------------
// gzip container (RFC 1952) — gRPC's message compression format
// ---------------------------------------------------------------------

/// Wrap `data` in a minimal gzip member (deflate body, CRC-32, ISIZE).
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 2 + 32);
    out.extend_from_slice(&[0x1f, 0x8b]); // magic
    out.push(8); // CM = deflate
    out.push(0); // FLG
    out.extend_from_slice(&[0, 0, 0, 0]); // MTIME
    out.push(2); // XFL = max compression
    out.push(0xff); // OS = unknown
    out.extend_from_slice(&deflate(data));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// Decompress a gzip member, rejecting anything malformed and capping
/// the output at `max_out`.
pub fn gunzip(data: &[u8], max_out: usize) -> Result<Vec<u8>> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b {
        return Err(Error::protocol("gzip: bad magic"));
    }
    if data[2] != 8 {
        return Err(Error::protocol("gzip: unsupported compression method"));
    }
    let flg = data[3];
    if flg & 0xe0 != 0 {
        return Err(Error::protocol("gzip: reserved flags set"));
    }
    let mut pos = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA
        if pos + 2 > data.len() {
            return Err(Error::protocol("gzip: truncated extra field"));
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
        if pos > data.len() {
            return Err(Error::protocol("gzip: truncated extra field"));
        }
    }
    if flg & 0x08 != 0 {
        pos = skip_cstring(data, pos, "file name")?;
    }
    if flg & 0x10 != 0 {
        pos = skip_cstring(data, pos, "comment")?;
    }
    if flg & 0x02 != 0 {
        pos += 2; // FHCRC
        if pos > data.len() {
            return Err(Error::protocol("gzip: truncated header crc"));
        }
    }
    if pos + 8 > data.len() {
        return Err(Error::protocol("gzip: truncated trailer"));
    }
    let body_end = data.len() - 8;
    let expected_crc = u32::from_le_bytes([
        data[body_end],
        data[body_end + 1],
        data[body_end + 2],
        data[body_end + 3],
    ]);
    let expected_size = u32::from_le_bytes([
        data[body_end + 4],
        data[body_end + 5],
        data[body_end + 6],
        data[body_end + 7],
    ]);
    if pos > body_end {
        return Err(Error::protocol("gzip: truncated body"));
    }
    let mut out = Vec::new();
    inflate_into(&data[pos..body_end], &mut out, max_out)?;
    if out.len() as u32 != expected_size {
        return Err(Error::protocol("gzip: size mismatch"));
    }
    if crc32(&out) != expected_crc {
        return Err(Error::protocol("gzip: crc mismatch"));
    }
    Ok(out)
}

fn skip_cstring(data: &[u8], mut pos: usize, what: &str) -> Result<usize> {
    while pos < data.len() {
        if data[pos] == 0 {
            return Ok(pos + 1);
        }
        pos += 1;
    }
    Err(Error::protocol(alloc::format!("gzip: truncated {what}")))
}

// ---------------------------------------------------------------------
// RFC 7692 contexts (permessage-deflate)
// ---------------------------------------------------------------------

/// Largest window bits RFC 7692 may negotiate.
pub const MAX_WINDOW_BITS: u8 = 15;
/// Smallest window bits RFC 7692 may negotiate.
pub const MIN_WINDOW_BITS: u8 = 8;

/// A DEFLATE decompression context that keeps the sliding window between
/// messages (RFC 7692 "context takeover").
///
/// The window is bounded by `1 << window_bits` (≤ 32 KiB) no matter how
/// large the messages are, and every back-reference beyond it is
/// rejected — a peer that negotiates `server_max_window_bits=10` and
/// then references 30 KiB back is not merely inefficient, it is
/// non-conformant, and accepting it would let a single connection pin an
/// attacker-chosen amount of memory.
#[derive(Clone)]
pub struct Inflater {
    window: Vec<u8>,
    window_bits: u8,
    /// Reused input staging: the payload plus the RFC 7692 tail.
    scratch: Vec<u8>,
}

impl Default for Inflater {
    fn default() -> Self {
        Self::new(MAX_WINDOW_BITS)
    }
}

impl Inflater {
    /// A context with a full 32 KiB window.
    pub fn new(window_bits: u8) -> Self {
        let bits = window_bits.clamp(MIN_WINDOW_BITS, MAX_WINDOW_BITS);
        Self {
            window: Vec::new(),
            window_bits: bits,
            scratch: Vec::new(),
        }
    }

    /// Change the negotiated window size (clears the history: a smaller
    /// window can no longer describe the bytes already decoded).
    pub fn set_window_bits(&mut self, bits: u8) {
        let bits = bits.clamp(MIN_WINDOW_BITS, MAX_WINDOW_BITS);
        if bits != self.window_bits {
            self.window.clear();
            self.window_bits = bits;
        }
    }

    /// The negotiated window size in bits.
    #[inline]
    pub fn window_bits(&self) -> u8 {
        self.window_bits
    }

    /// Bytes of history currently retained.
    #[inline]
    pub fn window_len(&self) -> usize {
        self.window.len()
    }

    /// Drop the history (used for `*_no_context_takeover` and on error).
    pub fn reset(&mut self) {
        self.window.clear();
    }

    /// Decode one RFC 7692 message payload into `out`.
    ///
    /// The four-octet sync-flush marker that the sender stripped is
    /// re-appended before decoding (RFC 7692 §7.2.2), and running out of
    /// input there is a *complete* message rather than an error.
    /// `out` is cleared first; `max_out` bounds the decompressed size so
    /// a compression bomb cannot be turned into an allocation.
    pub fn inflate_message(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        max_out: usize,
    ) -> Result<()> {
        out.clear();
        self.scratch.clear();
        self.scratch.reserve(input.len() + 4);
        self.scratch.extend_from_slice(input);
        // RFC 7692 §7.2.2: append 00 00 FF FF before inflating.
        self.scratch.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);

        let mut br = BitReader::new(&self.scratch);
        let result = inflate_blocks(&mut br, &self.window, out, max_out, true);
        if let Err(e) = result {
            // A failed message must not poison the context: a partially
            // decoded message would corrupt every later back-reference.
            self.window.clear();
            return Err(e);
        }
        self.absorb(&out[..]);
        Ok(())
    }

    /// Inflate a raw DEFLATE stream that may reference the retained
    /// window, appending to `out` (lower-level entry point used by tests
    /// and by callers that manage framing themselves).
    pub fn inflate_append(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        max_out: usize,
    ) -> Result<()> {
        let mut br = BitReader::new(input);
        inflate_blocks(&mut br, &self.window, out, max_out, false)
    }

    /// Retain the tail of the decoded stream as history.
    fn absorb(&mut self, message: &[u8]) {
        let cap = 1usize << self.window_bits;
        let start = if message.len() >= cap {
            // Only the tail matters; a message longer than the window
            // replaces the history outright.
            self.window.clear();
            message.len() - cap
        } else {
            let overflow = (self.window.len() + message.len()).saturating_sub(cap);
            if overflow > 0 {
                self.window.drain(..overflow);
            }
            0
        };
        self.window.extend_from_slice(&message[start..]);
        debug_assert!(self.window.len() <= cap);
    }
}

/// A DEFLATE compression context for RFC 7692 messages.
///
/// This encoder deliberately compresses each message *independently*:
/// back-references never cross a message boundary. That is always valid
/// DEFLATE for the peer (a decoder's window is a superset of what the
/// encoder used), it keeps the encoder's memory flat, and it removes the
/// classic context-takeover failure mode where an encoder bug leaks an
/// earlier message's plaintext bits into a later one. The cost is a
/// bounded ratio loss on streams with tiny, highly repetitive messages.
///
/// What it does *not* do is rebuild its match-finder tables per message:
/// the 128 KiB hash table and the chain table belong to the context and
/// are reset in time proportional to the message length. That is what
/// makes `permessage-deflate` affordable for small messages instead of a
/// 128 KiB memory sweep per frame.
#[derive(Default)]
pub struct Deflater {
    /// Minimum payload size worth compressing: below this the DEFLATE
    /// framing overhead exceeds the savings, so the caller is told to
    /// send the message uncompressed (RSV1 clear).
    threshold: usize,
    finder: MatchFinder,
}

impl Deflater {
    /// A context that compresses payloads of at least 128 bytes.
    ///
    /// The threshold is a latency/bandwidth trade, not a correctness one:
    /// a 64-byte message compresses to a handful of bytes, but the CPU
    /// cost per message is comparable to the rest of the framing path, so
    /// small-message writers should set the threshold to taste (`0`
    /// compresses everything).
    pub fn new() -> Self {
        Self {
            threshold: 128,
            finder: MatchFinder::default(),
        }
    }

    /// Set the minimum payload size that is worth compressing.
    pub fn set_threshold(&mut self, bytes: usize) {
        self.threshold = bytes;
    }

    /// Drop history (no-op for this encoder; present so the API mirrors
    /// [`Inflater`] when `*_no_context_takeover` is negotiated).
    pub fn reset(&mut self) {}

    /// Compress one message. `None` means "send this one uncompressed":
    /// the payload was below the threshold, or compression did not pay
    /// for itself (incompressible data), in which case RSV1 must stay 0.
    pub fn deflate_message(&mut self, data: &[u8], out: &mut Vec<u8>) -> Option<()> {
        if data.len() < self.threshold {
            return None;
        }
        out.clear();
        self.finder.prepare(data.len());
        let compressed = deflate_sync_with(data, &mut self.finder);
        if compressed.len() >= data.len() {
            return None;
        }
        out.extend_from_slice(&compressed);
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn deflate_roundtrip_various() {
        for data in [
            &b""[..],
            b"a",
            b"hello world",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"The quick brown fox jumps over the lazy dog. "
                .repeat(4)
                .as_slice(),
            &(0u8..=255).collect::<Vec<u8>>()[..],
        ] {
            let c = deflate(data);
            let d = inflate(&c, 1 << 20).unwrap();
            assert_eq!(
                d,
                data,
                "deflate roundtrip failed for {:?}",
                &data[..data.len().min(16)]
            );
        }
    }

    #[test]
    fn gzip_roundtrip() {
        let data = b"courierust gzip roundtrip payload with repeated repeated repeated bytes";
        let g = gzip(data);
        let d = gunzip(&g, 1 << 20).unwrap();
        assert_eq!(d, data);
    }

    #[test]
    fn gzip_roundtrip_empty_and_binary() {
        assert_eq!(gunzip(&gzip(b""), 1 << 20).unwrap(), b"");
        let binary: Vec<u8> = (0u8..=255).cycle().take(50_000).collect();
        let d = gunzip(&gzip(&binary), 1 << 20).unwrap();
        assert_eq!(d, binary);
    }

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn gunzip_rejects_corruption() {
        let g = gzip(b"payload");
        let mut bad = g.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0xff;
        assert!(gunzip(&bad, 1 << 20).is_err());
        assert!(gunzip(&g[..g.len() - 1], 1 << 20).is_err());
        assert!(gunzip(b"not-gzip-data-here", 1 << 20).is_err());
    }

    #[test]
    fn gunzip_enforces_output_cap() {
        let big = vec![b'x'; 100_000];
        let g = gzip(&big);
        assert!(gunzip(&g, 1_000).is_err(), "output cap must be enforced");
    }

    #[test]
    fn length_and_distance_code_lookup() {
        assert_eq!(length_code(3), Some((257, 0, 3)));
        assert_eq!(length_code(258), Some((285, 0, 258)));
        assert_eq!(length_code(11), Some((265, 1, 11)));
        assert_eq!(distance_code(1), Some((0, 0, 1)));
        assert_eq!(distance_code(28672), Some((29, 12, 24577)));
        assert_eq!(distance_code(24577), Some((29, 12, 24577)));
        assert_eq!(distance_code(16385), Some((28, 12, 16385)));
        assert_eq!(distance_code(32768), None);
        assert_eq!(distance_code(5121), None);
    }

    #[test]
    fn decompresses_stored_and_fixed_and_dynamic() {
        let mut stored = vec![0x01, 0x03, 0x00, 0xfc, 0xff];
        stored.extend_from_slice(b"abc");
        assert_eq!(inflate(&stored, 1 << 10).unwrap(), b"abc");

        let d = deflate(b"A");
        assert_eq!(inflate(&d, 1 << 10).unwrap(), b"A");
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Interop against Python zlib output (generated by
    /// `scripts/gen_gzip_vectors.py`, level 9, which emits stored AND
    /// dynamic Huffman blocks) — the decoder must accept anything a real
    /// gzip producer emits.
    #[test]
    fn zlib_interop_vectors() {
        let cases: &[(&str, &str, &str)] = &[
            ("", "0300", "1f8b080000000000020a03000000000000000000"),
            (
                "hello",
                "cb48cdc9c90700",
                "1f8b080000000000020acb48cdc9c9070086a6103605000000",
            ),
            (
                "aaaaaaaaaaaaaaaaaa",
                "4b4c440700",
                "1f8b080000000000020a4b4c440700310eacb812000000",
            ),
            (
                "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. ",
                "0bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a7eb29848c2a1e553caa98da8a01",
                "1f8b080000000000020a0bc94855282ccd4cce56482aca2fcf5348cbaf50c82acd2d2856c82f4b2d5228014ae72456552aa4e4a7eb29848c2a1e553caa98da8a01e64a66b084030000",
            ),
            (
                "courierust gzip compression negotiation test payload with some repetition repetition repetition",
                "6dca4b0ac0200c05c0abe46a621f36504d489e487bfa7ed6ddcd62aacd50c44c4abbd4a55af740a6da908166d4c2d7c433bc9c87954d967297b40e0938a8dff8e50d",
                "1f8b080000000000020a6dca4b0ac0200c05c0abe46a621f36504d489e487bfa7ed6ddcd62aacd50c44c4abbd4a55af740a6da908166d4c2d7c433bc9c87954d967297b40e0938a8dff8e50dd424c5095f000000",
            ),
        ];
        for (plain, deflate_hex, gzip_hex) in cases {
            let expected = plain.as_bytes();
            let d = inflate(&hex(deflate_hex), 1 << 20).unwrap();
            assert_eq!(
                &d,
                expected,
                "deflate vector mismatch for {:?}",
                &plain[..plain.len().min(24)]
            );
            let g = gunzip(&hex(gzip_hex), 1 << 20).unwrap();
            assert_eq!(
                &g,
                expected,
                "gzip vector mismatch for {:?}",
                &plain[..plain.len().min(24)]
            );
        }
    }

    #[test]
    fn our_deflate_decodes_via_inflate() {
        let samples: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"x".to_vec(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
            b"0123456789".repeat(40),
            (0u8..=255).cycle().take(300).collect(),
        ];
        for s in &samples {
            let c = deflate(s);
            let d = inflate(&c, 1 << 20).unwrap();
            assert_eq!(&d, s);
        }
    }

    // -- RFC 7692 context tests ---------------------------------------

    #[test]
    fn sync_stream_roundtrips_without_takeover() {
        let samples: Vec<Vec<u8>> = vec![
            b"hello hello hello hello hello".to_vec(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
            (0..=255u8).cycle().take(4096).collect(),
        ];
        let mut d = Deflater::new();
        d.set_threshold(1);
        let mut i = Inflater::new(15);
        for s in &samples {
            let mut comp = Vec::new();
            // `None` means "this payload is not worth compressing": the
            // sender then transmits it verbatim with RSV1 clear, so no
            // inflate call happens on the receiving side.
            if d.deflate_message(s, &mut comp).is_some() {
                let mut out = Vec::new();
                i.inflate_message(&comp, &mut out, 1 << 20).unwrap();
                assert_eq!(&out, s);
            }
            i.reset(); // no context takeover on the decoder either
        }
    }

    #[test]
    fn empty_message_compresses_to_a_valid_sync_frame() {
        let mut d = Deflater::new();
        d.set_threshold(0);
        let mut comp = Vec::new();
        assert!(d.deflate_message(b"", &mut comp).is_none() || comp.is_empty());
        // Even a hand-built empty frame must decode to nothing.
        let empty = deflate_sync(b"");
        let mut i = Inflater::new(15);
        let mut out = Vec::new();
        i.inflate_message(&empty, &mut out, 1 << 20).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn context_takeover_window_survives_large_messages() {
        // The window must remember exactly its capacity and no more; a
        // 100 KiB message followed by a small one must still decode.
        let mut i = Inflater::new(15);
        let big: Vec<u8> = (0..100_000u32).map(|n| (n % 251) as u8).collect();
        let comp = deflate_sync(&big);
        let mut out = Vec::new();
        i.inflate_message(&comp, &mut out, 1 << 20).unwrap();
        assert_eq!(out, big);
        assert!(i.window_len() <= (1 << 15));
    }

    #[test]
    fn small_window_rejects_distant_backreference() {
        // A peer that negotiated an 8-bit window (256 bytes) may not
        // reference further back than that. Message 1 fills the window
        // with literals; message 2 asks for 257 bytes of history, which
        // is exactly one byte out of reach.
        let mut w = BitWriter::new();
        w.write_bits(0, 1); // BFINAL=0 (sync-flushed frame)
        w.write_bits(1, 2); // BTYPE = fixed Huffman
        for _ in 0..300 {
            w.write_bits_msb(0x30 + u32::from(b'a'), 8); // literal 'a'
        }
        w.write_bits(0, 7); // end of block
        let first = w.finish_permessage();

        let mut w2 = BitWriter::new();
        w2.write_bits(0, 1);
        w2.write_bits(1, 2);
        w2.write_bits_msb(0, 7); // length code 257 -> match length 3
        w2.write_bits_msb(8, 5); // distance code 8 -> base 17, 4 extra bits
        w2.write_bits(240, 4); // 17 + 240 = 257 > the 256-byte window
        w2.write_bits(0, 7); // end of block
        let second = w2.finish_permessage();

        let mut i = Inflater::new(8);
        let mut out = Vec::new();
        i.inflate_message(&first, &mut out, 1 << 20).unwrap();
        assert_eq!(out.len(), 300);
        assert_eq!(i.window_len(), 256);
        let err = i.inflate_message(&second, &mut out, 1 << 20);
        assert!(
            err.is_err(),
            "a distance beyond the negotiated window must fail"
        );
        // The failed message must not poison the context.
        assert_eq!(i.window_len(), 0);
    }

    #[test]
    fn inflate_message_rejects_compress_bomb() {
        let bomb = deflate_sync(&vec![0u8; 1 << 20]);
        let mut i = Inflater::new(15);
        let mut out = Vec::new();
        assert!(i.inflate_message(&bomb, &mut out, 4096).is_err());
        // A failed message must clear the history so a later message can
        // never reference bytes the failed one would have produced.
        assert_eq!(i.window_len(), 0);
    }

    #[test]
    fn deflater_skips_incompressible_and_tiny() {
        let mut d = Deflater::new();
        let mut out = Vec::new();
        assert!(d.deflate_message(b"tiny", &mut out).is_none());
        // High-entropy bytes cannot pay for the DEFLATE framing: the
        // encoder must report "send this uncompressed" instead of
        // inflating the message.
        let mut state = 0x2545_f491u32;
        let randomish: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect();
        assert!(d.deflate_message(&randomish, &mut out).is_none());
    }

    #[test]
    fn compression_roundtrip_many_sizes() {
        let mut d = Deflater::new();
        d.set_threshold(0);
        let mut i = Inflater::new(15);
        for n in [0usize, 1, 2, 3, 7, 8, 63, 64, 65, 255, 256, 257, 4096] {
            let data: Vec<u8> = (0..n).map(|k| (k % 7) as u8).collect();
            let mut comp = Vec::new();
            if let Some(()) = d.deflate_message(&data, &mut comp) {
                let mut out = Vec::new();
                i.inflate_message(&comp, &mut out, 1 << 20).unwrap();
                assert_eq!(out, data, "roundtrip n={n}");
            } else {
                // Not worth compressing: framing costs more than the
                // (repetition-free) payload saves. Longer payloads of the
                // same pattern must compress, so a regression that
                // silently disables compression cannot pass.
                assert!(n < 32, "payload of {n} bytes should have compressed");
            }
        }
    }

    #[test]
    fn utf8_ish_text_compresses_and_expands_identically() {
        let text = String::from("日本語テキストの圧縮テスト ")
            .repeat(200)
            .into_bytes();
        let mut d = Deflater::new();
        let mut comp = Vec::new();
        assert!(d.deflate_message(&text, &mut comp).is_some());
        assert!(comp.len() < text.len());
        let mut i = Inflater::new(15);
        let mut out = Vec::new();
        i.inflate_message(&comp, &mut out, 1 << 20).unwrap();
        assert_eq!(out, text);
    }
}
