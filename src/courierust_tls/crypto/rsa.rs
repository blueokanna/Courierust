//! RSA signature verification (RFC 8017): PKCS#1 v1.5 and PSS.
//!
//! Includes a compact arbitrary-precision integer (`BigInt`) with
//! Montgomery-modular exponentiation. Only the public-key verification
//! path is implemented (the server never signs here); `e = 65537` is
//! assumed in the fast path with a generic fallback.

use super::hash::{BoxDigest, Digest, Sha256, Sha384};
use alloc::vec::Vec;

/// Big-endian unsigned integer with `u64` limbs
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BigInt {
    /// Limbs, least significant first.
    limbs: Vec<u64>,
}

impl BigInt {
    pub(crate) fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub(crate) fn from_u64(v: u64) -> Self {
        if v == 0 {
            Self::zero()
        } else {
            Self { limbs: vec![v] }
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    pub(crate) fn bit_len(&self) -> usize {
        let mut i = self.limbs.len();
        while i > 0 && self.limbs[i - 1] == 0 {
            i -= 1;
        }
        if i == 0 {
            return 0;
        }
        (i - 1) * 64 + (64 - self.limbs[i - 1].leading_zeros() as usize)
    }

    /// From big-endian bytes.
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Self {
        // Chunk from the end so limb boundaries align with the byte
        // stream: the least significant 8 bytes form limb 0, the next
        // 8 form limb 1, etc. The most significant chunk may be short
        // and is left-padded within its limb.
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
        let mut i = bytes.len();
        while i > 0 {
            let start = i.saturating_sub(8);
            let chunk = &bytes[start..i];
            let mut buf = [0u8; 8];
            buf[8 - chunk.len()..].copy_from_slice(chunk);
            limbs.push(u64::from_be_bytes(buf));
            i = start;
        }
        while limbs.len() > 1 && *limbs.last().unwrap() == 0 {
            limbs.pop();
        }
        if limbs.is_empty() {
            limbs.push(0);
        }
        Self { limbs }
    }

    /// From little-endian u64 limbs (the internal representation).
    pub(crate) fn from_le_limbs(limbs: &[u64]) -> Self {
        let mut out = Self {
            limbs: limbs.to_vec(),
        };
        out.trim();
        out
    }

    /// The value as exactly 32 little-endian bytes.
    pub(crate) fn to_le_32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let be = self.to_be_bytes_padded(32);
        for i in 0..32 {
            out[i] = be[31 - i];
        }
        out
    }

    /// To big-endian bytes of exactly `len` bytes (padded).
    pub(crate) fn to_be_bytes_padded(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let mut v = self.clone();
        v.trim();
        let mut idx = len;
        for limb in &v.limbs {
            let bytes = limb.to_be_bytes();
            if idx >= 8 {
                out[idx - 8..idx].copy_from_slice(&bytes);
                idx -= 8;
            } else {
                out[..idx].copy_from_slice(&bytes[8 - idx..]);
                idx = 0;
            }
        }
        out
    }

    fn trim(&mut self) {
        while self.limbs.len() > 1 && *self.limbs.last().unwrap() == 0 {
            self.limbs.pop();
        }
        if self.limbs.is_empty() {
            self.limbs.push(0);
        }
    }

    /// Compare with `other`.
    pub(crate) fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        let a = self.clone();
        let b = other.clone();
        let mut a = a;
        let mut b = b;
        a.trim();
        b.trim();
        if a.limbs.len() != b.limbs.len() {
            return a.limbs.len().cmp(&b.limbs.len());
        }
        for i in (0..a.limbs.len()).rev() {
            if a.limbs[i] != b.limbs[i] {
                return a.limbs[i].cmp(&b.limbs[i]);
            }
        }
        core::cmp::Ordering::Equal
    }

    /// `self + other`.
    pub(crate) fn add(&self, other: &Self) -> Self {
        let n = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u64;
        for i in 0..n {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            let (s1, c1) = a.overflowing_add(b);
            let (s2, c2) = s1.overflowing_add(carry);
            out.push(s2);
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry != 0 {
            out.push(carry);
        }
        Self { limbs: out }
    }

    /// `self - other` (requires self >= other).
    pub(crate) fn sub(&self, other: &Self) -> Self {
        let n = self.limbs.len();
        let mut out = Vec::with_capacity(n);
        let mut borrow = 0u64;
        for i in 0..n {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            let (s1, b1) = a.overflowing_sub(b);
            let (s2, b2) = s1.overflowing_sub(borrow);
            out.push(s2);
            borrow = (b1 as u64) + (b2 as u64);
        }
        let mut r = Self { limbs: out };
        r.trim();
        r
    }

    /// Schoolbook multiplication.
    pub(crate) fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut out = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            // The carry can exceed 2^64 by a few bits, so it is tracked
            // as (lo, hi) where hi is 0..=3. Each 128-bit product is
            // split so no intermediate exceeds u128.
            let mut carry_lo = 0u64;
            let mut carry_hi = 0u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let prod = (a as u128) * (b as u128);
                let pl = prod as u64;
                let ph = (prod >> 64) as u64;
                let s = (out[i + j] as u128) + (pl as u128) + (carry_lo as u128);
                out[i + j] = s as u64;
                let nc = (ph as u128) + (carry_hi as u128) + (s >> 64);
                carry_lo = nc as u64;
                carry_hi = (nc >> 64) as u64;
            }
            let mut k = i + other.limbs.len();
            let mut c_lo = carry_lo;
            let mut c_hi = carry_hi;
            while (c_lo != 0 || c_hi != 0) && k < out.len() {
                let v = (out[k] as u128) + (c_lo as u128) + ((c_hi as u128) << 64);
                out[k] = v as u64;
                c_lo = (v >> 64) as u64;
                c_hi = 0; // v < 2^67: no bits remain above 64
                k += 1;
            }
        }
        let mut r = Self { limbs: out };
        r.trim();
        r
    }

    /// Montgomery reduction of `self` (T with at most 2k limbs) with
    /// modulus `m` (k limbs): returns T * R^-1 mod m.
    ///
    /// `T < m^2 < R^2` implies the intermediate `T + m*N'` is `< 2*m*R`
    /// which may need `2k+1` limbs, so one extra limb is kept for the
    /// carry that would otherwise be dropped for moduli close to `R`.
    pub(crate) fn redc_raw(&self, m: &Self, nprime: u64) -> Self {
        let k = m.limbs.len();
        let mut t = self.limbs.clone();
        t.resize(k * 2 + 1, 0);
        for i in 0..k {
            let ti = t[i];
            let mi = ti.wrapping_mul(nprime);
            // Carry tracked as (lo, hi) with hi small (0..=3) to avoid
            // u128 overflow in the accumulate step.
            let mut carry_lo = 0u64;
            let mut carry_hi = 0u64;
            let mut idx = i;
            for &mj in &m.limbs {
                let prod = (mi as u128) * (mj as u128);
                let pl = prod as u64;
                let ph = (prod >> 64) as u64;
                let s = (t[idx] as u128) + (pl as u128) + (carry_lo as u128);
                t[idx] = s as u64;
                let nc = (ph as u128) + (carry_hi as u128) + (s >> 64);
                carry_lo = nc as u64;
                carry_hi = (nc >> 64) as u64;
                idx += 1;
            }
            // Propagate the remaining carry into position i+k onward.
            let mut c_lo = carry_lo;
            let mut c_hi = carry_hi;
            while (c_lo != 0 || c_hi != 0) && idx < t.len() {
                let v = (t[idx] as u128) + (c_lo as u128) + ((c_hi as u128) << 64);
                t[idx] = v as u64;
                c_lo = (v >> 64) as u64;
                c_hi = 0;
                idx += 1;
            }
        }
        // result = t[k..2k+1] (k+1 limbs), value < 2m.
        let mut r_limbs: Vec<u64> = t[k..k * 2 + 1].to_vec();
        // The result is < 2m: subtract m at most once (borrow tracks
        // whether the subtraction underflowed). If it underflowed the
        // value was already < m and we add m back.
        let mut borrow = 0u64;
        for (i, limb) in r_limbs.iter_mut().enumerate() {
            let a = *limb;
            let b = if i < k { m.limbs[i] } else { 0 };
            let (s1, b1) = a.overflowing_sub(b);
            let (s2, b2) = s1.overflowing_sub(borrow);
            *limb = s2;
            borrow = b1 as u64 + b2 as u64;
        }
        if borrow != 0 {
            let mut carry = 0u64;
            for (i, limb) in r_limbs.iter_mut().enumerate() {
                let a = *limb;
                let b = if i < k { m.limbs[i] } else { 0 };
                let (s1, c1) = a.overflowing_add(b);
                let (s2, c2) = s1.overflowing_add(carry);
                *limb = s2;
                carry = c1 as u64 + c2 as u64;
            }
        }
        let mut r = Self {
            limbs: r_limbs[..k].to_vec(),
        };
        r.trim();
        r
    }

    /// `self` shifted left by `shift` bits.
    pub(crate) fn shl_bits(&self, shift: usize) -> Self {
        let word_shift = shift / 64;
        let bit_shift = (shift % 64) as u32;
        let mut out = vec![0u64; self.limbs.len() + word_shift + 1];
        for (i, &limb) in self.limbs.iter().enumerate() {
            let idx = i + word_shift;
            out[idx] |= limb << bit_shift;
            if bit_shift > 0 {
                out[idx + 1] |= limb >> (64 - bit_shift);
            }
        }
        let mut r = Self { limbs: out };
        r.trim();
        r
    }

    /// `self mod m` via shift-and-subtract (m > 0).
    pub(crate) fn rem(&self, m: &Self) -> Self {
        if m.is_zero() {
            return Self::zero();
        }
        let m_bits = m.bit_len();
        let mut r = self.clone();
        loop {
            let hi = r.bit_len();
            if hi < m_bits {
                break;
            }
            let shift = hi - m_bits;
            let shifted = m.shl_bits(shift);
            if r.cmp(&shifted) != core::cmp::Ordering::Less {
                r = r.sub(&shifted);
            } else if shift > 0 {
                // shifted overshoots; shift down by one (guaranteed ≤ r).
                r = r.sub(&m.shl_bits(shift - 1));
            } else {
                // r < m and no further shift available: done.
                break;
            }
        }
        if r.cmp(m) != core::cmp::Ordering::Less {
            r = r.sub(m);
        }
        r
    }

    /// `self^exp mod m` via Montgomery square-and-multiply.
    ///
    /// Montgomery reduction requires an odd modulus; for an even modulus
    /// (which cannot occur for a real RSA public key but may be fed by a
    /// hostile peer) we fall back to plain square-and-multiply so the
    /// result is always correct rather than silently wrong.
    pub(crate) fn mod_pow(&self, exp: &Self, m: &Self) -> Self {
        if m.is_zero() || (m.limbs.len() == 1 && m.limbs[0] == 1) {
            return Self::zero();
        }
        if m.limbs[0] & 1 == 0 {
            return self.mod_pow_plain(exp, m);
        }
        let nprime = mont_nprime(m);
        let r = mont_r(m);
        let r2 = mont_r2(m, &r);
        // base in Montgomery form.
        let base = self.rem(m);
        let a = {
            let t = base.mul(&r2);
            t.redc_raw(m, nprime)
        };
        let mut result = r; // Montgomery form of 1 is R mod N
        for bit in (0..exp.bit_len()).rev() {
            result = {
                let t = result.mul(&result);
                t.redc_raw(m, nprime)
            };
            if (exp.limbs[bit / 64] >> (bit % 64)) & 1 == 1 {
                let t = result.mul(&a);
                result = t.redc_raw(m, nprime);
            }
        }
        // Convert back: REDC(result).
        let t = result.mul(&Self::from_u64(1));
        t.redc_raw(m, nprime)
    }

    /// `self^exp mod m` via plain square-and-multiply (any modulus).
    pub(crate) fn mod_pow_plain(&self, exp: &Self, m: &Self) -> Self {
        let base = self.rem(m);
        let mut result = Self::from_u64(1);
        for bit in (0..exp.bit_len()).rev() {
            result = result.mul(&result).rem(m);
            if (exp.limbs[bit / 64] >> (bit % 64)) & 1 == 1 {
                result = result.mul(&base).rem(m);
            }
        }
        result
    }
}

/// N' = -N^-1 mod 2^64 (via Newton iteration).
pub(crate) fn mont_nprime(m: &BigInt) -> u64 {
    let n0 = m.limbs[0];
    // Newton: x_{i+1} = x_i * (2 - N * x_i) mod 2^64.
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

/// R = 2^(64k) mod m.
pub(crate) fn mont_r(m: &BigInt) -> BigInt {
    let k = m.limbs.len();
    let mut r = BigInt::from_u64(1);
    for _ in 0..k * 64 {
        r = r.add(&r);
        if r.cmp(m) != core::cmp::Ordering::Less {
            r = r.sub(m);
        }
    }
    r
}

/// R2 = R^2 mod m.
pub(crate) fn mont_r2(m: &BigInt, r: &BigInt) -> BigInt {
    let k = m.limbs.len();
    let mut r2 = r.clone();
    for _ in 0..k * 64 {
        r2 = r2.add(&r2);
        if r2.cmp(m) != core::cmp::Ordering::Less {
            r2 = r2.sub(m);
        }
    }
    r2
}

/// An RSA public key.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// Modulus n.
    pub n: Vec<u8>,
    /// Public exponent e (big-endian).
    pub e: Vec<u8>,
}

impl RsaPublicKey {
    /// RSAVP1: `s^e mod n`.
    fn raw_verify(&self, signature: &[u8]) -> Option<Vec<u8>> {
        let n = BigInt::from_be_bytes(&self.n);
        let s = BigInt::from_be_bytes(signature);
        if s.cmp(&n) != core::cmp::Ordering::Less {
            return None;
        }
        let e = BigInt::from_be_bytes(&self.e);
        let m = s.mod_pow(&e, &n);
        Some(m.to_be_bytes_padded(self.n.len()))
    }

    /// Verify a PKCS#1 v1.5 signature over `digest` with the given
    /// DigestInfo prefix (the ASN.1 `DigestInfo` for the hash).
    pub fn verify_pkcs1v15(&self, digest_info: &[u8], digest: &[u8], signature: &[u8]) -> bool {
        let em = match self.raw_verify(signature) {
            Some(em) => em,
            None => return false,
        };
        let k = self.n.len();
        if em.len() != k || k < 3 + digest_info.len() + digest.len() {
            return false;
        }
        // EM = 0x00 || 0x01 || 0xff..0xff || 0x00 || DigestInfo || digest
        if em[0] != 0x00 || em[1] != 0x01 {
            return false;
        }
        let mut i = 2;
        while i < k && em[i] == 0xff {
            i += 1;
        }
        if i == 2 || i >= k || em[i] != 0x00 {
            return false;
        }
        let body = &em[i + 1..];
        body.len() == digest_info.len() + digest.len()
            && constant_time_eq(body, &[digest_info, digest].concat())
    }

    /// Verify an RSA-PSS signature (RFC 8017 §8.1 / §9.1.2) with
    /// `salt_len` (TLS 1.3 uses salt_len == hash length).
    pub fn verify_pss(
        &self,
        hash: &mut dyn Digest,
        message: &[u8],
        salt_len: usize,
        signature: &[u8],
    ) -> bool {
        let h_len = hash.output_len();
        let em_len = self.n.len();
        // RFC 8017 §9.1.2 step 2: emLen >= hLen + sLen + 2
        if em_len < h_len + salt_len + 2 {
            return false;
        }
        let m_hash = {
            hash.update(message);
            hash.finalize()
        };
        let em = match self.raw_verify(signature) {
            Some(em) => em,
            None => return false,
        };
        verify_pss_em(hash, em, m_hash, salt_len)
    }
}

/// Verify the EMSA-PSS encoding of `em` against `m_hash`.
fn verify_pss_em(hash: &mut dyn Digest, em: Vec<u8>, m_hash: Vec<u8>, salt_len: usize) -> bool {
    let h_len = hash.output_len();
    let em_len = em.len();
    if em_len < h_len + salt_len + 2 {
        return false;
    }
    // EM = maskedDB || H' || 0xbc (RFC 8017 §9.1.1 step 12).
    if *em.last().unwrap() != 0xbc {
        return false;
    }
    let masked_db_len = em_len - h_len - 1;
    let masked_db = &em[..masked_db_len];
    let h_prime = &em[masked_db_len..em_len - 1];

    // RFC 8017 §9.1.2 step 6: the leftmost 8*emLen - emBits bits of
    // maskedDB must be zero. emBits = modBits - 1 = 8*emLen - 1, so the
    // top bit of the first octet of maskedDB (checked BEFORE the XOR)
    // must be clear.
    if masked_db[0] & 0x80 != 0 {
        return false;
    }

    // dbMask = MGF1(H', emLen - hLen - 1)
    let db_mask = mgf1(hash, h_prime, masked_db_len);
    let mut db: Vec<u8> = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // RFC 8017 §9.1.2 step 9: clear the leftmost 8*emLen - emBits bits
    // of DB (top bit of the first octet) before checking PS.
    db[0] &= 0x7f;

    // DB = PS || 0x01 || salt ; PS is zeros of length emLen - hLen - sLen - 2.
    let ps_len = em_len - h_len - salt_len - 2;
    if db[..ps_len].iter().any(|&b| b != 0) {
        return false;
    }
    if db[ps_len] != 0x01 {
        return false;
    }
    let salt = &db[ps_len + 1..ps_len + 1 + salt_len];

    // H = Hash(0x00..0x00 (8) || mHash || salt)
    hash.update(&[0u8; 8]);
    hash.update(&m_hash);
    hash.update(salt);
    let h = hash.finalize();
    constant_time_eq(&h, h_prime)
}

/// MGF1 (RFC 8017 §B.2.1).
fn mgf1(hash: &mut dyn Digest, seed: &[u8], len: usize) -> Vec<u8> {
    let h_len = hash.output_len();
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        hash.update(seed);
        hash.update(&counter.to_be_bytes());
        let block = hash.finalize();
        let take = core::cmp::min(h_len, len - out.len());
        out.extend_from_slice(&block[..take]);
        counter = counter.wrapping_add(1);
    }
    out
}

/// Constant-time byte equality.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 §9.2 note 1).
pub const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// The ASN.1 DigestInfo prefix for SHA-384.
pub const DIGEST_INFO_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];

/// The ASN.1 DigestInfo prefix for SHA-512.
pub const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Verify with the digest selected by `sha384`.
pub fn verify_rsa_pkcs1v15(key: &RsaPublicKey, sha384: bool, digest: &[u8], sig: &[u8]) -> bool {
    if sha384 {
        key.verify_pkcs1v15(DIGEST_INFO_SHA384, digest, sig)
    } else {
        key.verify_pkcs1v15(DIGEST_INFO_SHA256, digest, sig)
    }
}

/// Verify an RSA-PSS signature with SHA-256 or SHA-384.
pub fn verify_rsa_pss(key: &RsaPublicKey, sha384: bool, digest: &[u8], sig: &[u8]) -> bool {
    if sha384 {
        let mut h: BoxDigest = Box::<Sha384>::default();
        key.verify_pss(h.as_mut(), digest, 48, sig)
    } else {
        let mut h: BoxDigest = Box::<Sha256>::default();
        key.verify_pss(h.as_mut(), digest, 32, sig)
    }
}

// ---------------------------------------------------------------------
// Private-key signing (used by the TLS server's CertificateVerify).
// ---------------------------------------------------------------------

/// RSA private-key signing, PKCS#1 v1.5: `s = EMSA-PKCS1-v1_5^d mod n`.
/// `n` and `d` are big-endian byte strings of the same length.
pub(crate) fn sign_pkcs1v15(
    n: &[u8],
    d: &[u8],
    digest_info: &[u8],
    digest: &[u8],
) -> Option<Vec<u8>> {
    let k = n.len();
    let t_len = digest_info.len() + digest.len();
    if k < t_len + 11 {
        return None;
    }
    let mut em = vec![0u8; k];
    em[0] = 0x00;
    em[1] = 0x01;
    for b in em[2..k - t_len - 1].iter_mut() {
        *b = 0xff;
    }
    em[k - t_len - 1] = 0x00;
    em[k - t_len..k - digest.len()].copy_from_slice(digest_info);
    em[k - digest.len()..].copy_from_slice(digest);
    let m = BigInt::from_be_bytes(&em);
    let n_big = BigInt::from_be_bytes(n);
    let d_big = BigInt::from_be_bytes(d);
    if m.cmp(&n_big) != core::cmp::Ordering::Less {
        return None;
    }
    Some(m.mod_pow(&d_big, &n_big).to_be_bytes_padded(k))
}

/// RSA-PSS signing (RFC 8017 §8.1.1) with a random salt of `salt_len`
/// bytes (TLS 1.3 uses salt_len == hash length).
pub(crate) fn sign_pss(
    hash: &mut dyn Digest,
    n: &[u8],
    d: &[u8],
    message: &[u8],
    salt_len: usize,
) -> Option<Vec<u8>> {
    let em_len = n.len();
    let h_len = hash.output_len();
    if em_len < h_len + salt_len + 2 {
        return None;
    }
    let m_hash = {
        hash.update(message);
        hash.finalize()
    };

    let mut salt = vec![0u8; salt_len];
    super::rng::fill_random(&mut salt);

    hash.update(&[0u8; 8]);
    hash.update(&m_hash);
    hash.update(&salt);
    let h = hash.finalize();

    let ps_len = em_len - h_len - salt_len - 2;
    let mut db = vec![0u8; ps_len + 1 + salt_len];
    db[ps_len] = 0x01;
    db[ps_len + 1..].copy_from_slice(&salt);

    let db_mask = mgf1(hash, &h, em_len - h_len - 1);
    let mut masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();
    masked_db[0] &= 0x7f;

    let mut em = vec![0u8; em_len];
    em[..masked_db.len()].copy_from_slice(&masked_db);
    em[masked_db.len()..em_len - 1].copy_from_slice(&h);
    em[em_len - 1] = 0xbc;

    let m = BigInt::from_be_bytes(&em);
    let n_big = BigInt::from_be_bytes(n);
    let d_big = BigInt::from_be_bytes(d);
    if m.cmp(&n_big) != core::cmp::Ordering::Less {
        return None;
    }
    Some(m.mod_pow(&d_big, &n_big).to_be_bytes_padded(em_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_small_key_sign_verify() {
        // n = 3233, e = 17, d = 2753. m = 42: s = 42^2753 mod 3233 = 3065
        // (verified with an independent implementation), and s^17 mod 3233 == 42.
        let n = BigInt::from_be_bytes(&[0x0c, 0xa1]); // 3233
        let e = BigInt::from_be_bytes(&[0x11]); // 17
        let s = BigInt::from_be_bytes(&[0x0b, 0xf9]); // 3065
        let m = s.mod_pow(&e, &n);
        assert_eq!(m.to_be_bytes_padded(2), vec![0x00, 0x2a]); // 42
    }

    #[test]
    fn rsa_mod_pow_properties() {
        // (a*b)^e mod n == ((a^e mod n)*(b^e mod n)) mod n
        // n is a real (odd) 384-bit RSA modulus p*q generated with an
        // independent implementation; e = 65537.
        let n = BigInt::from_be_bytes(&[
            0x93, 0x9e, 0xca, 0x3a, 0x3e, 0x96, 0xde, 0x65, 0x2d, 0x86, 0x18, 0x0c, 0x79, 0x30,
            0x94, 0x6a, 0xfb, 0x59, 0x4b, 0x29, 0x9f, 0x76, 0xdc, 0x9b, 0x7d, 0xd4, 0x71, 0xe5,
            0xc2, 0x7d, 0x58, 0x6f, 0x92, 0x6c, 0x90, 0x29, 0x73, 0xda, 0x8a, 0x54, 0xc3, 0x3c,
            0x72, 0x09, 0x71, 0xcb, 0x22, 0xbf,
        ]);
        let e = BigInt::from_be_bytes(&[0x01, 0x00, 0x01]);
        let a = BigInt::from_be_bytes(&[0x12, 0x34, 0x56]);
        let b = BigInt::from_be_bytes(&[0x65, 0x43, 0x21]);
        let ab = a.mul(&b);
        let lhs = ab.mod_pow(&e, &n);
        let ae = a.mod_pow(&e, &n);
        let be = b.mod_pow(&e, &n);
        let t = ae.mul(&be);
        let reduced = t.rem(&n);
        assert_eq!(lhs, reduced);
        // Also check the even-modulus fallback path against a reference.
        let n_even = BigInt::from_be_bytes(&[
            0x00, 0xa5, 0x23, 0x9b, 0x8f, 0x1c, 0x0d, 0x21, 0x77, 0x54, 0x09, 0xcc, 0x62, 0x01,
            0x9e, 0x99, 0x1c,
        ]);
        let v = BigInt::from_be_bytes(&[0x01, 0x02, 0x03]);
        let r_even = v.mod_pow(&e, &n_even);
        // Reference: computed with Python pow(v, e, n_even) == 0x2da03a573b5158eff3a802d1b74c8a7b
        let expect = BigInt::from_be_bytes(&[
            0x2d, 0xa0, 0x3a, 0x57, 0x3b, 0x51, 0x58, 0xef, 0xf3, 0xa8, 0x02, 0xd1, 0xb7, 0x4c,
            0x8a, 0x7b,
        ]);
        assert_eq!(r_even, expect);
    }

    #[test]
    fn digest_info_lengths() {
        // The digest-info prefixes embed the digest length; validate.
        assert_eq!(DIGEST_INFO_SHA256.len(), 19);
        assert_eq!(DIGEST_INFO_SHA384.len(), 19);
    }
}
