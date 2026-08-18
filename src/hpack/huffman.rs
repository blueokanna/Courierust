//! Table-driven RFC 7541 Huffman coding.
//!
//! * Encoding uses a u64 bit accumulator with whole-byte drains — one
//!   table lookup plus a shift per symbol.
//! * Decoding uses lazily-built two-level tables: the first 8 bits index
//!   a 256-entry root table; codes longer than 8 bits descend through
//!   additional 256-entry levels (max code length is 30 bits, so at most
//!   four levels). A symbol is resolved by a single indexed read per 8
//!   consumed bits, with no backtracking.

use crate::hpack::huffman_table::{EOS_SYMBOL, HUFFMAN};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Errors produced while decoding a Huffman string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The bit sequence does not match any code.
    InvalidCode,
    /// The stream contained the EOS symbol.
    Eos,
    /// Trailing padding is not all-ones (RFC 7541 §5.2).
    InvalidPadding,
}

#[derive(Clone, Copy)]
enum Entry {
    /// A complete symbol (`u16`) with its code length.
    Leaf(u16, u8),
    /// Descend into another 256-entry level.
    Next(usize),
    /// No code starts here.
    Empty,
}

/// A table-driven Huffman decoder. The tables (up to four 256-entry
/// levels) are built once per instance and then decode with a single
/// indexed read per 8 consumed bits, no backtracking.
pub struct HuffmanDecoder {
    levels: Vec<Box<[Entry; 256]>>,
}

impl HuffmanDecoder {
    /// Build the decode tables from the RFC 7541 code.
    pub fn new() -> Self {
        Self {
            levels: build_levels(),
        }
    }

    /// Decode `src` into `out`, returning the number of bytes appended.
    pub fn decode(&self, src: &[u8], out: &mut Vec<u8>) -> Result<usize, DecodeError> {
        let start = out.len();
        decode_with(&self.levels, src, out)?;
        Ok(out.len() - start)
    }
}

impl Default for HuffmanDecoder {
    fn default() -> Self {
        Self::new()
    }
}

fn build_levels() -> Vec<Box<[Entry; 256]>> {
    let mut levels: Vec<Box<[Entry; 256]>> = vec![Box::new([Entry::Empty; 256])];
    for (sym, &(code, len)) in HUFFMAN.iter().enumerate() {
        let mut node = 0usize;
        let mut consumed = 0usize;
        // Walk full 8-bit steps while more than 8 bits remain.
        while (len as usize) - consumed > 8 {
            let shift = (len as usize) - consumed - 8;
            let idx = ((code >> shift) & 0xFF) as usize;
            match levels[node][idx] {
                Entry::Next(n) => node = n,
                _ => {
                    let n = levels.len();
                    levels.push(Box::new([Entry::Empty; 256]));
                    levels[node][idx] = Entry::Next(n);
                    node = n;
                }
            }
            consumed += 8;
        }
        // Remaining 1..=8 bits land in this level as a leaf that covers
        // every 8-bit window sharing the same prefix. The remaining bits
        // are the low `rem` bits of the code, aligned to the top of the
        // window.
        let rem = (len as usize) - consumed;
        let shift = 8 - rem;
        let idx_base = ((code & ((1u32 << rem) - 1)) << shift) as usize;
        let span = 1usize << shift;
        for i in 0..span {
            levels[node][idx_base + i] = Entry::Leaf(sym as u16, len);
        }
    }
    levels
}

/// Encode `src` with the static Huffman code, appending EOS-compatible
/// padding, into `out`. Returns the number of bytes appended.
pub fn encode(src: &[u8], out: &mut Vec<u8>) -> usize {
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in src {
        let (code, len) = HUFFMAN[b as usize];
        acc = (acc << len) | code as u64;
        nbits += len as u32;
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if nbits > 0 {
        let pad = 8 - nbits;
        // EOS's most significant bits are all ones, so padding is ones.
        let v = ((acc << pad) | ((1u64 << pad) - 1)) as u8;
        out.push(v);
        nbits = 0;
    }
    let _ = nbits;
    src.len()
}

/// Decode a Huffman string into `out`. Validates padding per RFC 7541
/// §5.2. Returns the number of bytes appended.
///
/// Convenience wrapper that builds a fresh decoder; the hot path should
/// hold a [`HuffmanDecoder`] and call it directly.
pub fn decode(src: &[u8], out: &mut Vec<u8>) -> Result<usize, DecodeError> {
    HuffmanDecoder::new().decode(src, out)
}

fn decode_with(
    levels: &[Box<[Entry; 256]>],
    src: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), DecodeError> {
    let total_bits = src.len() * 8;
    let mut br = BitReader::new(src);
    let mut consumed = 0usize; // bits consumed from the stream
    let mut code_start = 0usize; // stream position where the current code began
    let mut node = 0usize;
    loop {
        let remaining = total_bits - consumed;
        if remaining == 0 {
            // A clean end is only valid at a symbol boundary.
            if node != 0 {
                return Err(DecodeError::InvalidCode);
            }
            break;
        }
        // Read as much of an 8-bit window as is available (fewer bits at
        // the tail, zero-filled below).
        let window_bits = if remaining < 8 { remaining as u32 } else { 8 };
        let v = (br.peek(window_bits) as usize) << (8 - window_bits as usize);
        match levels[node][v] {
            Entry::Leaf(sym, len) => {
                // The code ends at `code_start + len`. The window may
                // contain trailing padding bits (the tail), so validity is
                // decided by whether the code fits inside the stream.
                let code_end = code_start + len as usize;
                if code_end > total_bits {
                    // Truncated code. If fewer than 8 bits remain this is
                    // the tail: it must be all-ones padding (MSBs of EOS).
                    if remaining < 8 {
                        let bits = br.peek(remaining as u32) as u32;
                        if bits == (1u32 << remaining) - 1 {
                            break;
                        }
                    }
                    return Err(DecodeError::InvalidCode);
                }
                if sym as usize == EOS_SYMBOL {
                    return Err(DecodeError::Eos);
                }
                out.push(sym as u8);
                if code_end > consumed {
                    br.skip((code_end - consumed) as u32);
                    consumed = code_end;
                }
                node = 0;
                code_start = code_end;
            }
            Entry::Next(n) => {
                if remaining < 8 {
                    // The code cannot complete in the remaining bits; the
                    // only legal tail is all-ones padding.
                    let bits = br.peek(remaining as u32) as u32;
                    if bits == (1u32 << remaining) - 1 {
                        break;
                    }
                    return Err(DecodeError::InvalidCode);
                }
                br.skip(8);
                consumed += 8;
                node = n;
            }
            Entry::Empty => {
                // No code starts here. At the tail this is legal only if
                // the remaining bits are all-ones padding.
                if remaining < 8 {
                    let bits = br.peek(remaining as u32) as u32;
                    if bits == (1u32 << remaining) - 1 {
                        break;
                    }
                }
                return Err(DecodeError::InvalidCode);
            }
        }
    }
    Ok(())
}

/// MSB-first bit reader over a byte slice. `peek` does not advance;
/// `skip` advances without interpreting.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit: 0,
        }
    }

    /// Read up to 8 bits starting at the current position without
    /// advancing. Assumes `n` bits are available.
    fn peek(&self, n: u32) -> u16 {
        debug_assert!((1..=8).contains(&n));
        let mut v = 0u16;
        let mut have = 0u32;
        let mut p = self.pos;
        let mut b = self.bit;
        while have < n {
            let byte = self.data[p] as u16;
            let take = core::cmp::min(8 - b, n - have);
            let shift = 8 - b - take;
            v = (v << take) | ((byte >> shift) & ((1u16 << take) - 1));
            have += take;
            b += take;
            if b == 8 {
                b = 0;
                p += 1;
            }
        }
        v
    }

    /// Advance `n` bits.
    fn skip(&mut self, n: u32) {
        self.bit += n;
        self.pos += (self.bit / 8) as usize;
        self.bit %= 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8]) {
        let mut enc = Vec::new();
        encode(data, &mut enc);
        let mut dec = Vec::new();
        if let Err(e) = decode(&enc, &mut dec) {
            panic!("data={data:?} enc={enc:02x?} err={e:?}");
        }
        assert_eq!(dec, data);
    }

    #[test]
    fn roundtrip_ascii() {
        roundtrip(b"www.example.com");
        roundtrip(b"GET /index.html HTTP/1.1\r\n");
        roundtrip(b"custom-key: custom-value");
        roundtrip(b"Mon, 21 Oct 2013 20:13:22 GMT");
        roundtrip(b"https://www.example.com");
    }

    #[test]
    fn roundtrip_all_bytes() {
        let all: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        roundtrip(&all);
    }

    #[test]
    fn roundtrip_long_and_binary() {
        let long = vec![b'a'; 4096];
        roundtrip(&long);
        let binary: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        roundtrip(&binary);
    }

    #[test]
    fn rfc_example_authority() {
        // RFC 7541 C.4.1: :authority = www.example.com -> f1e3c2e5f23a6ba0ab90f4ff
        let hex: Vec<u8> = (0..12)
            .map(|i| {
                [
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
                ][i]
            })
            .collect();
        let mut out = Vec::new();
        decode(&hex, &mut out).unwrap();
        assert_eq!(out, b"www.example.com");
    }

    #[test]
    fn roundtrip_crlf() {
        roundtrip(b"\r\n");
        roundtrip(b"a\r\n");
        roundtrip(b"GET /\r\n");
        roundtrip(b"\r\n\r\n");
    }

    #[test]
    fn encode_matches_rfc_example() {
        // Encode "www.example.com" and compare with the RFC C.4.1 hex.
        let mut enc = Vec::new();
        encode(b"www.example.com", &mut enc);
        let expected: Vec<u8> = vec![
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(enc, expected);
    }

    #[test]
    fn rejects_eos_and_padding() {
        // EOS is 30 ones; a string of 0xff 0xff 0xff 0xfc-ish decodes to EOS.
        let eos_encoded = [0xffu8, 0xff, 0xff, 0xff];
        let mut out = Vec::new();
        assert!(decode(&eos_encoded, &mut out).is_err());
        // A single byte 0xff has 8 leading ones: prefix of EOS => InvalidCode
        let mut out2 = Vec::new();
        assert!(decode(&[0xff], &mut out2).is_err());
    }

    #[test]
    fn table_is_prefix_free() {
        use crate::hpack::huffman_table::HUFFMAN;
        // A shorter code must never be a prefix of a longer code.
        for (i, &(c1, l1)) in HUFFMAN.iter().enumerate() {
            for (j, &(c2, l2)) in HUFFMAN.iter().enumerate() {
                if i != j && l1 < l2 {
                    // c2's top l1 bits equal c1?
                    let prefix = c2 >> (l2 - l1);
                    assert_ne!(
                        prefix, c1,
                        "symbol {i} (len {l1}) is a prefix of symbol {j} (len {l2})"
                    );
                }
            }
        }
    }

    #[test]
    fn kraft_sum_is_one() {
        use crate::hpack::huffman_table::HUFFMAN;
        // Sum of 2^-len over all symbols must equal 1 for a complete code.
        let mut acc: f64 = 0.0;
        for &(_, len) in HUFFMAN.iter() {
            acc += 2f64.powi(-(len as i32));
        }
        assert!((acc - 1.0).abs() < 1e-12, "kraft sum = {acc}");
    }
}
