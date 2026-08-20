//! Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! Implemented with the classic 5×26-bit limb decomposition: every
//! intermediate product fits in `u64` (26+26=52 bits), so there is no
//! platform-dependent overflow and no secret-dependent control flow.
//! The key clamp is applied by masking the full 128-bit `r` value with
//! the RFC 8439 constant before decomposition, which is unambiguous.

/// Poly1305 MAC.
pub struct Poly1305 {
    /// `r` in 5×26-bit limbs (clamped).
    r: [u64; 5],
    /// `s` as four 32-bit words.
    s: [u32; 4],
    /// Accumulator `h` in 5×26-bit limbs.
    h: [u64; 5],
    /// Pending partial block.
    buf: [u8; 16],
    buf_len: usize,
}

const MASK26: u64 = 0x3ff_ffff;
/// RFC 8439 §2.5 clamping constant.
const CLAMP: u128 = 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;

impl Poly1305 {
    /// Initialize with a 32-byte key (`r || s`).
    pub fn new(key: &[u8; 32]) -> Self {
        let r = u128::from_le_bytes(key[0..16].try_into().unwrap()) & CLAMP;
        let r = [
            ((r >> 0) & MASK26 as u128) as u64,
            ((r >> 26) & MASK26 as u128) as u64,
            ((r >> 52) & MASK26 as u128) as u64,
            ((r >> 78) & MASK26 as u128) as u64,
            ((r >> 104) & MASK26 as u128) as u64,
        ];
        let mut s = [0u32; 4];
        for (i, w) in s.iter_mut().enumerate() {
            *w = u32::from_le_bytes(key[16 + i * 4..20 + i * 4].try_into().unwrap());
        }
        Self {
            r,
            s,
            h: [0; 5],
            buf: [0; 16],
            buf_len: 0,
        }
    }

    /// Absorb a full 16-byte block (with the implicit 2^128 bit).
    fn blocks(&mut self, block: &[u8; 16]) {
        let b0 = (u32::from_le_bytes(block[0..4].try_into().unwrap()) as u64) & MASK26;
        let b1 = (u32::from_le_bytes(block[3..7].try_into().unwrap()) as u64 >> 2) & MASK26;
        let b2 = (u32::from_le_bytes(block[6..10].try_into().unwrap()) as u64 >> 4) & MASK26;
        let b3 = (u32::from_le_bytes(block[9..13].try_into().unwrap()) as u64 >> 6) & MASK26;
        let b4 = (u32::from_le_bytes(block[12..16].try_into().unwrap()) as u64 >> 8) & MASK26;

        // h += block + 2^128
        let h0 = self.h[0] + b0;
        let h1 = self.h[1] + b1;
        let h2 = self.h[2] + b2;
        let h3 = self.h[3] + b3;
        let h4 = self.h[4] + b4 + (1 << 24);
        self.h = Self::mul(h0, h1, h2, h3, h4, self.r);
    }

    /// `h * r mod 2^130-5` (RFC 8439 §2.5, the 5×26 limb schoolbook
    /// multiply with the `2^130 ≡ 5` fold).
    #[inline]
    fn mul(h0: u64, h1: u64, h2: u64, h3: u64, h4: u64, r: [u64; 5]) -> [u64; 5] {
        let (r0, r1, r2, r3, r4) = (r[0], r[1], r[2], r[3], r[4]);
        let d0 = h0 * r0 + h1 * 5 * r4 + h2 * 5 * r3 + h3 * 5 * r2 + h4 * 5 * r1;
        let d1 = h0 * r1 + h1 * r0 + h2 * 5 * r4 + h3 * 5 * r3 + h4 * 5 * r2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * 5 * r4 + h4 * 5 * r3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * 5 * r4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // Partial carry (keeps h < 2^130 + small slack between blocks).
        let mut c = d0 >> 26;
        let h0 = d0 & MASK26;
        let d1 = d1 + c;
        c = d1 >> 26;
        let h1 = d1 & MASK26;
        let d2 = d2 + c;
        c = d2 >> 26;
        let h2 = d2 & MASK26;
        let d3 = d3 + c;
        c = d3 >> 26;
        let h3 = d3 & MASK26;
        let d4 = d4 + c;
        c = d4 >> 26;
        let h4 = d4 & MASK26;
        // Fold the 2^130 term as 5.
        let h0 = h0 + c * 5;
        c = h0 >> 26;
        let h0 = h0 & MASK26;
        let h1 = h1 + c;
        [h0, h1, h2, h3, h4]
    }

    /// Absorb `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = core::cmp::min(16 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let block = self.buf;
                self.blocks(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 16 {
            let block: [u8; 16] = data[..16].try_into().unwrap();
            self.blocks(&block);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Finalize and produce the 16-byte tag.
    pub fn finish(mut self) -> [u8; 16] {
        // Process the trailing partial block (append 0x01, no 2^128 bit).
        if self.buf_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block[self.buf_len] = 1;
            let b0 = (u32::from_le_bytes(block[0..4].try_into().unwrap()) as u64) & MASK26;
            let b1 = (u32::from_le_bytes(block[3..7].try_into().unwrap()) as u64 >> 2) & MASK26;
            let b2 = (u32::from_le_bytes(block[6..10].try_into().unwrap()) as u64 >> 4) & MASK26;
            let b3 = (u32::from_le_bytes(block[9..13].try_into().unwrap()) as u64 >> 6) & MASK26;
            let b4 = (u32::from_le_bytes(block[12..16].try_into().unwrap()) as u64 >> 8) & MASK26;
            let h0 = self.h[0] + b0;
            let h1 = self.h[1] + b1;
            let h2 = self.h[2] + b2;
            let h3 = self.h[3] + b3;
            let h4 = self.h[4] + b4;
            self.h = Self::mul(h0, h1, h2, h3, h4, self.r);
        }

        // Full carry.
        let mut h = self.h;
        let mut c = h[0] >> 26;
        h[0] &= MASK26;
        h[1] += c;
        c = h[1] >> 26;
        h[1] &= MASK26;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= MASK26;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= MASK26;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= MASK26;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= MASK26;
        h[1] += c;

        // h - p (p = 2^130 - 5), then select h or h-p by sign of the top.
        let mut g0 = h[0] + 5;
        c = g0 >> 26;
        g0 &= MASK26;
        let mut g1 = h[1] + c;
        c = g1 >> 26;
        g1 &= MASK26;
        let mut g2 = h[2] + c;
        c = g2 >> 26;
        g2 &= MASK26;
        let mut g3 = h[3] + c;
        c = g3 >> 26;
        g3 &= MASK26;
        // Wrapping subtraction emulates the C unsigned arithmetic of the
        // reference implementation; the sign is recovered from bit 63.
        let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 63).wrapping_sub(1); // 0 if g4 < 0, else all-ones
        let inv = !mask;
        let h0 = (h[0] & inv) | (g0 & mask);
        let h1 = (h[1] & inv) | (g1 & mask);
        let h2 = (h[2] & inv) | (g2 & mask);
        let h3 = (h[3] & inv) | (g3 & mask);
        let h4 = (h[4] & inv) | (g4 & mask);

        // Pack the low 128 bits.
        let w0 = (h0 | (h1 << 26)) & 0xffff_ffff;
        let w1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
        let w2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
        let w3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

        // tag = (h + s) mod 2^128.
        let mut f = w0 as u64 + self.s[0] as u64;
        let w0 = (f & 0xffff_ffff) as u32;
        let c = f >> 32;
        f = w1 as u64 + self.s[1] as u64 + c;
        let w1 = (f & 0xffff_ffff) as u32;
        let c = f >> 32;
        f = w2 as u64 + self.s[2] as u64 + c;
        let w2 = (f & 0xffff_ffff) as u32;
        let c = f >> 32;
        f = w3 as u64 + self.s[3] as u64 + c;
        let w3 = (f & 0xffff_ffff) as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&w0.to_le_bytes());
        tag[4..8].copy_from_slice(&w1.to_le_bytes());
        tag[8..12].copy_from_slice(&w2.to_le_bytes());
        tag[12..16].copy_from_slice(&w3.to_le_bytes());
        tag
    }
}

/// One-shot Poly1305 tag.
pub fn poly1305(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut mac = Poly1305::new(key);
    mac.update(data);
    mac.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poly1305_rfc8439_vector() {
        // RFC 8439 §2.5.2 / Appendix A.3.
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305(&key, msg);
        let expected = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(&tag[..], &expected[..]);
    }

    #[test]
    fn poly1305_rfc8439_second_vector() {
        // RFC 8439 A.3 Test Vector #2 (374-byte message, many blocks).
        let key = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96,
            0x22, 0x7a, 0x86, 0x3e,
        ];
        let msg = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
        let tag = poly1305(&key, msg);
        let expected = [
            0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a,
            0x86, 0x3e,
        ];
        assert_eq!(&tag[..], &expected[..]);
    }
}
