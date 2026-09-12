//! SHA-1 (FIPS 180-4 / RFC 3174), implemented from the public
//! specification with no unsafe code.
//!
//! SHA-1 is *not* collision resistant and MUST NOT be used for new
//! signatures or integrity tags. It is required by exactly one place in
//! this stack: the RFC 6455 §4.2.2 `Sec-WebSocket-Accept` handshake
//! token, whose security comes from the client-supplied random
//! `Sec-WebSocket-Key` (a preimage problem), not from collision
//! resistance. Everything else in the crate uses SHA-256.
//!
//! Both a one-shot [`sha1`] and an incremental [`Sha1`] hasher are
//! provided; the incremental form lets the handshake hash `key || GUID`
//! without materialising a concatenated buffer.

use alloc::string::String;

/// Initial hash values (FIPS 180-4 §5.3.1).
const H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// Round constants (FIPS 180-4 §4.2.1).
const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

/// Incremental SHA-1 state.
///
/// The block loop is the same for the one-shot and streaming forms; both
/// funnel through [`Sha1::update`], so there is a single compression
/// routine to audit.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    /// Partial block (< 64 bytes).
    block: [u8; 64],
    /// Bytes currently held in `block`.
    used: usize,
    /// Total message length in bytes (for the length padding).
    len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// A fresh hasher.
    pub fn new() -> Self {
        Self {
            h: H0,
            block: [0u8; 64],
            used: 0,
            len: 0,
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        let mut rest = data;
        // Top up a partial block first: a resumed stream must not treat
        // the leftover bytes as a fresh block boundary.
        if self.used > 0 {
            let want = 64 - self.used;
            let take = core::cmp::min(want, rest.len());
            self.block[self.used..self.used + take].copy_from_slice(&rest[..take]);
            self.used += take;
            rest = &rest[take..];
            if self.used == 64 {
                let block = self.block;
                self.compress(&block);
                self.used = 0;
            }
        }
        let mut chunks = rest.chunks_exact(64);
        for chunk in &mut chunks {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            self.compress(&block);
        }
        let tail = chunks.remainder();
        if !tail.is_empty() {
            self.block[..tail.len()].copy_from_slice(tail);
            self.used = tail.len();
        }
    }

    /// Finish and return the 20-byte digest.
    pub fn finish(mut self) -> [u8; 20] {
        // Padding: 0x80, zeros, then the 64-bit big-endian bit length.
        let bit_len = self.len.wrapping_mul(8);
        self.block[self.used] = 0x80;
        self.used += 1;
        if self.used > 56 {
            for b in &mut self.block[self.used..] {
                *b = 0;
            }
            let block = self.block;
            self.compress(&block);
            self.used = 0;
        }
        for b in &mut self.block[self.used..56] {
            *b = 0;
        }
        self.block[56..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.block;
        self.compress(&block);

        let mut out = [0u8; 20];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// The compression function over one 64-byte block.
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) =
            (self.h[0], self.h[1], self.h[2], self.h[3], self.h[4]);
        // Four rounds of twenty steps share one unrolled body; `f`/`k`
        // switch per round exactly as the specification defines.
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | ((!b) & d), K[0]),
                1 => (b ^ c ^ d, K[1]),
                2 => ((b & c) | (b & d) | (c & d), K[2]),
                _ => (b ^ c ^ d, K[3]),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

/// One-shot SHA-1 digest.
#[inline]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finish()
}

/// Lowercase hex digest (40 chars).
pub fn sha1_hex(data: &[u8]) -> String {
    let digest = sha1(data);
    let mut out = String::with_capacity(40);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn fips_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn million_a_vector() {
        let mut h = Sha1::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        let digest = h.finish();
        assert_eq!(hex(&digest), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    #[test]
    fn streaming_matches_one_shot_at_every_boundary() {
        // Feeding the same input in two pieces must equal the one-shot
        // digest for every possible split point — this is what catches
        // partial-block resume bugs.
        let data: Vec<u8> = (0u16..300).map(|i| (i % 251) as u8).collect();
        let want = sha1(&data);
        for split in 0..=data.len() {
            let mut h = Sha1::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finish(), want, "split at {split}");
        }
    }

    #[test]
    fn websocket_accept_rfc_vector() {
        // RFC 6455 §1.3: key + GUID hashed, then base64 encoded. The
        // expected digest is checked against the RFC's example key.
        let key = b"dGhlIHNhbXBsZSBub25jZQ==";
        let mut h = Sha1::new();
        h.update(key);
        h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let digest = h.finish();
        assert_eq!(hex(&digest), "b37a4f2cc0624f1690f64606cf385945b2bec4ea");
    }

    fn hex(b: &[u8]) -> String {
        let mut s = String::new();
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }
}
