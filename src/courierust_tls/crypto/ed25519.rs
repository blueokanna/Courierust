//! Ed25519 signature verification (RFC 8032).
//!
//! Reuses the GF(2^255-19) arithmetic from [`super::x25519`]. The
//! verification is the **cofactored** equation
//! `[8S]B == [8](R + [h]A)` plus explicit rejection of small-order
//! public keys and R values, which is the defense-in-depth posture used
//! by modern implementations (it prevents the small-order forgery
//! classes). Only the verification path is implemented.

use super::hash::{BoxDigest, Digest};
use super::x25519::{
    fe_add, fe_frombytes, fe_invert, fe_mul, fe_sq, fe_sub, fe_tobytes, Fe, ONE, ZERO,
};
use alloc::vec::Vec;

/// The group order L = 2^252 + 27742317777372353535851937790883648493.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

/// The curve constant d = -121665/121666 mod p.
fn d() -> Fe {
    compute_d_const()
}

fn fe_small(v: u64) -> Fe {
    let mut f = ZERO;
    f[0] = v;
    f
}

/// d = -121665/121666 mod p.
fn compute_d_const() -> Fe {
    let neg_121665 = fe_sub(ZERO, fe_small(121665));
    fe_mul(neg_121665, fe_invert(fe_small(121666)))
}

/// 2d mod p.
fn d2() -> Fe {
    let dd = d();
    fe_add(dd, dd)
}

/// sqrt(-1) mod p = 2^((p-1)/4) = 2^(2^253 - 5) (verified: squares to
/// p-1). The naive `(-1)^((p+3)/8)` is wrong here because (p+3)/8 is
/// even.
fn sqrt_m1() -> Fe {
    let exp = [
        0xffff_ffff_ffff_fffb,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x1fff_ffff_ffff_ffff,
    ];
    fe_pow(fe_small(2), &exp)
}

/// `a^e mod p` where `e` is a 256-bit little-endian exponent
/// (MSB-first square-and-multiply on the result).
fn fe_pow(a: Fe, e: &[u64; 4]) -> Fe {
    let mut result = ONE;
    for word in e.iter().rev() {
        for bit in (0..64).rev() {
            result = fe_sq(result);
            if (*word >> bit) & 1 == 1 {
                result = fe_mul(result, a);
            }
        }
    }
    result
}

/// A point in extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z.
#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    fn identity() -> Self {
        Self {
            x: ZERO,
            y: ONE,
            z: ONE,
            t: ZERO,
        }
    }

    fn is_identity(&self) -> bool {
        self.x == ZERO && fe_mul(self.y, self.z) == self.z
    }
}

/// Point addition (a = -1, extended coordinates, ref10 edwards_add).
fn point_add(p: Point, q: Point) -> Point {
    let a = fe_mul(fe_sub(p.y, p.x), fe_sub(q.y, q.x));
    let b = fe_mul(fe_add(p.y, p.x), fe_add(q.y, q.x));
    let c = fe_mul(fe_mul(p.t, q.t), d2());
    let dd = fe_add(fe_mul(p.z, q.z), fe_mul(p.z, q.z));
    let e = fe_sub(b, a);
    let f = fe_sub(dd, c);
    let g = fe_add(dd, c);
    let h = fe_add(b, a);
    Point {
        x: fe_mul(e, f),
        y: fe_mul(g, h),
        t: fe_mul(e, h),
        z: fe_mul(f, g),
    }
}

/// Point doubling (a = -1, extended coordinates).
fn point_double(p: Point) -> Point {
    let a = fe_sq(p.x);
    let b = fe_sq(p.y);
    let z2 = fe_sq(p.z);
    let c = fe_add(z2, z2); // 2·Z1²
    let d = fe_sub(ZERO, a);
    let e = fe_sub(fe_sub(fe_sq(fe_add(p.x, p.y)), a), b);
    let g = fe_add(d, b);
    let f = fe_sub(g, c);
    let h = fe_sub(d, b);
    Point {
        x: fe_mul(e, f),
        y: fe_mul(g, h),
        t: fe_mul(e, h),
        z: fe_mul(f, g),
    }
}

/// `[8]P`.
fn point_mul8(p: Point) -> Point {
    point_double(point_double(point_double(p)))
}

/// Decompress a point, validating it is on the curve.
fn point_decompress(bytes: &[u8; 32]) -> Option<Point> {
    let sign = bytes[31] >> 7;
    let mut y_bytes = *bytes;
    y_bytes[31] &= 0x7f;
    let y = fe_frombytes(&y_bytes);
    let y2 = fe_sq(y);
    let u = fe_sub(y2, ONE);
    let v = fe_add(fe_mul(d(), y2), ONE);
    let x = sqrt_ratio(u, v)?;
    // Enforce the sign bit.
    let x = if (x[0] & 1) != sign as u64 {
        fe_sub(ZERO, x)
    } else {
        x
    };
    // Reject x == 0 with sign bit 1.
    if fe_tobytes(x) == fe_tobytes(ZERO) && sign == 1 {
        return None;
    }
    Some(Point {
        x,
        y,
        z: ONE,
        t: fe_mul(x, y),
    })
}

/// Compute `sqrt(u/v)` if it exists (ref10 sqrt_ratio).
fn sqrt_ratio(u: Fe, v: Fe) -> Option<Fe> {
    // (p-5)/8 = 2^252 - 3.
    let exp = [u64::MAX - 2, u64::MAX, u64::MAX, 0x0fff_ffff_ffff_ffff];
    let v3 = fe_mul(fe_sq(v), v);
    let v7 = fe_mul(fe_sq(v3), v);
    let uv7 = fe_mul(u, v7);
    let x = fe_mul(fe_mul(u, v3), fe_pow(uv7, &exp));
    // NOTE: `u`/`v` are non-canonical (fe_sub adds a 2^54 bias), so
    // compare through the canonical byte encoding.
    if fe_tobytes(fe_mul(v, fe_sq(x))) == fe_tobytes(u) {
        return Some(x);
    }
    let x_m1 = fe_mul(x, sqrt_m1());
    if fe_tobytes(fe_mul(v, fe_sq(x_m1))) == fe_tobytes(u) {
        return Some(x_m1);
    }
    None
}

/// Compress a point to 32 bytes.
fn point_compress(p: Point) -> [u8; 32] {
    let z_inv = fe_invert(p.z);
    let x = fe_mul(p.x, z_inv);
    let y = fe_mul(p.y, z_inv);
    let mut out = fe_tobytes(y);
    let x_bytes = fe_tobytes(x);
    out[31] |= (x_bytes[0] & 1) << 7;
    out
}

/// Scalar multiplication (variable base), double-and-add from the MSB.
/// Handles any 256-bit scalar (the group order L is < 2^253, but the
/// clamped Ed25519 signing scalar may have bit 254 set).
fn scalar_mult(p: Point, scalar: &[u64; 4]) -> Point {
    let mut result = Point::identity();
    for bit in (0..256).rev() {
        result = point_double(result);
        if (scalar[bit / 64] >> (bit % 64)) & 1 == 1 {
            result = point_add(result, p);
        }
    }
    result
}

// ---- 256-bit helpers for scalar reduction mod L ----

fn cmp8(a: &[u64; 8], b: &[u64; 8]) -> core::cmp::Ordering {
    for i in (0..8).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    core::cmp::Ordering::Equal
}

fn sub8(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut out = [0u64; 8];
    let mut borrow = 0u64;
    for i in 0..8 {
        let (s1, b1) = a[i].overflowing_sub(b[i]);
        let (s2, b2) = s1.overflowing_sub(borrow);
        out[i] = s2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    out
}

fn highest_bit(a: &[u64; 8]) -> Option<usize> {
    for i in (0..8).rev() {
        if a[i] != 0 {
            return Some(i * 64 + 63 - a[i].leading_zeros() as usize);
        }
    }
    None
}

fn shl8(a: &[u64; 8], shift: usize) -> [u64; 8] {
    let mut out = [0u64; 8];
    let word_shift = shift / 64;
    let bit_shift = (shift % 64) as u32;
    for i in (word_shift..8).rev() {
        let v = a[i - word_shift];
        out[i] |= v << bit_shift;
        if bit_shift > 0 && i > word_shift {
            out[i] |= a[i - word_shift - 1] >> (64 - bit_shift);
        }
    }
    out
}

/// Reduce a 512-bit value (8 limbs, little-endian) mod L.
fn mod_l(a: [u64; 8]) -> [u64; 4] {
    let l8: [u64; 8] = [L[0], L[1], L[2], L[3], 0, 0, 0, 0];
    let mut r = a;
    while let Some(hi) = highest_bit(&r) {
        if hi < 253 {
            break;
        }
        let shift = hi - 252;
        let shifted = shl8(&l8, shift);
        r = if cmp8(&r, &shifted) >= core::cmp::Ordering::Equal {
            sub8(&r, &shifted)
        } else {
            sub8(&r, &shl8(&l8, shift - 1))
        };
    }
    let mut out = [r[0], r[1], r[2], r[3]];
    if cmp8(&r, &l8) >= core::cmp::Ordering::Equal {
        let l4 = L;
        let mut borrow = 0u64;
        for i in 0..4 {
            let (s1, b1) = out[i].overflowing_sub(l4[i]);
            let (s2, b2) = s1.overflowing_sub(borrow);
            out[i] = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }
    out
}

/// The Ed25519 base point (y = 4/5 mod p, x even), as its compressed
/// encoding (RFC 8032 §5.1).
const BASE_POINT: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Verify an Ed25519 signature `(r || s)` over `message` with `public_key`.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let a = match point_decompress(public_key) {
        Some(a) => a,
        None => return false,
    };
    // Reject identity / small-order public keys.
    if a.is_identity() || point_mul8(a).is_identity() {
        return false;
    }
    let r = match point_decompress(&signature[..32].try_into().unwrap()) {
        Some(r) => r,
        None => return false,
    };
    // Reject identity / small-order R.
    if r.is_identity() || point_mul8(r).is_identity() {
        return false;
    }

    // S must be < L.
    let s_limbs: [u64; 4] = {
        let mut l = [0u64; 4];
        for (i, chunk) in signature[32..64].chunks(8).enumerate() {
            l[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        l
    };
    if cmp4(&s_limbs, &L) != core::cmp::Ordering::Less {
        return false;
    }

    // h = SHA-512(R || A || M) mod L.
    let mut hasher = Sha512::new();
    hasher.update(&signature[..32]);
    hasher.update(public_key);
    hasher.update(message);
    let h64 = hasher.finalize();
    let mut h_limbs = [0u64; 8];
    for (i, chunk) in h64.chunks(8).enumerate() {
        h_limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let h = mod_l(h_limbs);

    // Cofactored verification: [8S]B == [8](R + [h]A).
    let lhs = point_mul8(scalar_mult(base_point(), &s_limbs));
    let rhs_inner = point_add(r, scalar_mult(a, &h));
    let rhs = point_mul8(rhs_inner);
    point_compress(lhs) == point_compress(rhs)
}

fn base_point() -> Point {
    point_decompress(&BASE_POINT).expect("valid base point")
}

/// Sign `message` with a 32-byte Ed25519 seed (RFC 8032 §5.1.6).
pub(crate) fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use super::rsa::BigInt;

    // Expand: SHA-512(seed) → 64 bytes; first 32 = clamped scalar,
    // last 32 = nonce prefix.
    let mut expand = Sha512::new();
    expand.update(seed);
    let h = expand.finalize();
    let mut a_limbs = [0u64; 4];
    for (i, chunk) in h[..32].chunks(8).enumerate() {
        a_limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    a_limbs[0] &= 0xffff_ffff_ffff_fff8;
    a_limbs[3] &= 0x3fff_ffff_ffff_ffff;
    a_limbs[3] |= 0x4000_0000_0000_0000;

    // A = a·B
    let a_point = scalar_mult(base_point(), &a_limbs);
    let public_key = point_compress(a_point);

    // r = SHA-512(prefix || M) mod L
    let mut r_hash = Sha512::new();
    r_hash.update(&h[32..64]);
    r_hash.update(message);
    let r64 = r_hash.finalize();
    let mut r_full = [0u64; 8];
    for (i, chunk) in r64.chunks(8).enumerate() {
        r_full[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let r = mod_l(r_full);

    // R = r·B
    let r_enc = point_compress(scalar_mult(base_point(), &r));

    // k = SHA-512(R || A || M) mod L
    let mut k_hash = Sha512::new();
    k_hash.update(&r_enc);
    k_hash.update(&public_key);
    k_hash.update(message);
    let k64 = k_hash.finalize();
    let mut k_full = [0u64; 8];
    for (i, chunk) in k64.chunks(8).enumerate() {
        k_full[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    let k = mod_l(k_full);

    // S = (r + k·a) mod L (via the big-integer module).
    let l = BigInt::from_le_limbs(&L);
    let r_big = BigInt::from_le_limbs(&r);
    let k_big = BigInt::from_le_limbs(&k);
    let a_big = BigInt::from_le_limbs(&a_limbs);
    let s = r_big.add(&k_big.mul(&a_big)).rem(&l);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_enc);
    sig[32..].copy_from_slice(&s.to_le_32());
    sig
}

fn cmp4(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    core::cmp::Ordering::Equal
}

/// A SHA-512 incremental hasher (RFC 8032 uses SHA-512 for Ed25519).
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total: u64,
}

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const H512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// New incremental SHA-512 hasher.
    pub fn new() -> Self {
        Self {
            state: H512,
            buf: [0u8; 128],
            buf_len: 0,
            total: 0,
        }
    }

    fn compress(&mut self, block: &[u8]) {
        let mut w = [0u64; 80];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u64::from_be_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            self.state[4],
            self.state[5],
            self.state[6],
            self.state[7],
        );
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Digest for Sha512 {
    fn update(&mut self, data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        let mut data = data;
        if self.buf_len > 0 {
            let take = core::cmp::min(128 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 128 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 128 {
            let block: [u8; 128] = data[..128].try_into().unwrap();
            self.compress(&block);
            data = &data[128..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(&mut self) -> Vec<u8> {
        let bit_len = self.total.wrapping_mul(8);
        let bit_len_hi = 0u64;
        let block_count = if self.buf_len < 112 { 1 } else { 2 };
        for i in 0..block_count {
            let mut b = [0u8; 128];
            if i == 0 {
                b[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
                b[self.buf_len] = 0x80;
            }
            if i == block_count - 1 {
                b[112..120].copy_from_slice(&bit_len_hi.to_be_bytes());
                b[120..128].copy_from_slice(&bit_len.to_be_bytes());
            }
            self.compress(&b);
        }
        let mut out = Vec::with_capacity(64);
        for v in self.state.iter() {
            out.extend_from_slice(&v.to_be_bytes());
        }
        self.state = H512;
        self.buf = [0u8; 128];
        self.buf_len = 0;
        self.total = 0;
        out
    }

    fn output_len(&self) -> usize {
        64
    }

    fn block_len(&self) -> usize {
        128
    }

    fn fork(&self) -> BoxDigest {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s = s.replace(' ', "");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(v: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(v.len() * 2);
        for &b in v {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    #[test]
    fn base_point_sanity() {
        let b = base_point();
        let (x, y) = {
            let z_inv = fe_invert(b.z);
            (fe_mul(b.x, z_inv), fe_mul(b.y, z_inv))
        };
        // y == 4/5 mod p.
        let expected_y = fe_mul(fe_small(4), fe_invert(fe_small(5)));
        assert_eq!(fe_tobytes(y), fe_tobytes(expected_y), "base point y wrong");
        // On-curve: x^2·v == u with u = y^2-1, v = d·y^2+1.
        let y2 = fe_sq(y);
        let u = fe_sub(y2, ONE);
        let v = fe_add(fe_mul(d(), y2), ONE);
        let x2 = fe_mul(fe_sq(x), v);
        assert_eq!(fe_tobytes(x2), fe_tobytes(u), "base point on curve");
        // [L]B == identity (order check).
        let order_check = scalar_mult(b, &L);
        let identity = Point::identity();
        let oc = point_compress(order_check);
        let ic = point_compress(identity);
        assert_eq!(oc, ic, "order check");
    }

    #[test]
    fn ed25519_rfc8032_vector_1() {
        // RFC 8032 §7.1 TEST 1.
        let pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let msg = hex("");
        let sig = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        let mut pk_arr = [0u8; 32];
        let mut sig_arr = [0u8; 64];
        pk_arr.copy_from_slice(&pk);
        sig_arr.copy_from_slice(&sig);
        assert!(verify(&pk_arr, &msg, &sig_arr));
    }

    #[test]
    fn ed25519_rfc8032_vector_3() {
        // RFC 8032 §7.1 TEST 3 (3-byte message).
        let pk = hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        let msg = hex("af82");
        let sig = hex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
        let mut pk_arr = [0u8; 32];
        let mut sig_arr = [0u8; 64];
        pk_arr.copy_from_slice(&pk);
        sig_arr.copy_from_slice(&sig);
        assert!(verify(&pk_arr, &msg, &sig_arr));
    }

    #[test]
    fn ed25519_rejects_forged() {
        let pk = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        let mut pk_arr = [0u8; 32];
        let mut sig_arr = [0u8; 64];
        pk_arr.copy_from_slice(&pk);
        sig_arr.copy_from_slice(&sig);
        // Wrong message.
        assert!(!verify(&pk_arr, b"wrong message", &sig_arr));
        // Tampered signature.
        let mut bad = sig_arr;
        bad[0] ^= 1;
        assert!(!verify(&pk_arr, b"", &bad));
        // All-zero public key (identity) must be rejected.
        let zero_pk = [0u8; 32];
        assert!(!verify(&zero_pk, b"", &sig_arr));
    }

    #[test]
    fn sha512_known() {
        let mut h = Sha512::new();
        h.update(b"abc");
        let digest = h.finalize();
        let hex_digest: String = to_hex(&digest);
        assert_eq!(
            hex_digest,
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                .replace(' ', "")
        );
    }

    /// Regression test: the two- and three-block SHA-512 padding paths
    /// (message lengths whose final 128-byte block holds 112..=127 bytes)
    /// must hash identically to an independent reference. The previous
    /// implementation re-copied the buffered message into the length
    /// block, corrupting every digest in this range — silently rejecting
    /// valid Ed25519 / P-521 signatures over such messages.
    #[test]
    fn sha512_multiblock_boundaries() {
        let mut source = [0u8; 512];
        for (i, b) in source.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        // (length, sha512 digest) from Python hashlib.
        let vectors: &[(usize, &str)] = &[
            (111, "a1a111449b198d9b1f538bad7f3fc1022b3a5b1a5e90a0bc860de8512746cbc31599e6c834de3a3235327af0b51ff57bf7acf1974a73014d9c3953812edc7c8d"),
            (112, "c5fbd731d19d2ae1180f001be72c2c1aaba1d7b094b3748880e24593b8e117a750e11c1bd867cc2f96dace8c8b74abd2d5c4f236be444e77d30d1916174070b9"),
            (113, "61b2e77db697dfe5571fff3ed06bd60c41e1e7b7c08a80de01cb16526d9a9a52d690dfbe792278a60f6e2b4c57a97c729773f26e258d2393890c985d645f6715"),
            (126, "2681bf910ddfa680b7204037294d00d0fcaee84a3747f6e302a16704b3b08efbda0e57dbb8e61e92348c8d5fc5a59eab74c77949a74c7740c30412a9fc65bf34"),
            (127, "eab89674feaa34e27aebeeff3c0a4d70070bb872d5e9f186cf1dbbdee517b6e35724d629ff025a5b07185e911ada7e3c8acf830aa0e4f71777bd2d44f504f7f0"),
            (128, "1dffd5e3adb71d45d2245939665521ae001a317a03720a45732ba1900ca3b8351fc5c9b4ca513eba6f80bc7b1d1fdad4abd13491cb824d61b08d8c0e1561b3f7"),
            (129, "1d9da57fbbdab09afb3506ab2d223d06109d65c1c8ad197f50138f714bc4c3f2fe5787922639c680acad1c651f955990425954ce2cba0c5cc83f2667d878eb0f"),
            (240, "6c48466c9f6c07e4ab762c696b7eeb35cfe236fca73683e5fab873ac3489b4d2eb3d7afcce7e8165dbbf37aded3b5b0c889c0b7e0f1790a8330d8677429d91a5"),
            (241, "4f663484efca758d670147758a5d4d9e5933fe22c0a1dc01f954738ff8310a6515b3ec42094449075ed678c55ee001a4fb91b1081dfae6ab83860b7b4cc7b4ab"),
            (254, "e2da07644daa73b66c1b6fbcdae7ff28e3b9024f0bc5408fe02c18e3744cf9bd6dd54ea7bfa1f6f3a81c8560fb938fdff9a38a29853a3a819b58d10213a290ec"),
            (255, "15025c9d135861ff5a549df0bfd6c398fd126613496d4e97627651e68b7b1f80407f187d7978464f0f78bfeea787600faaebbe991eddb60671cd0ce874f0a744"),
            (256, "1e7b80bc8edc552c8feeb2780e111477e5bc70465fac1a77b29b35980c3f0ce4a036a6c9462036824bd56801e62af7e9feba5c22ed8a5af877bf7de117dcac6d"),
            (377, "28c20d33eb44a2976e5f12b79ce215b8ed25f64d0b7553d29dc53e49dcb94454a7d9d2cadaaa7c07d033b6aefd38ad1408ef72e9ef36a83b9e710384317eabd7"),
            (511, "a496013faccd4c2cc09c214736811521533c2feb200ccbc241728f3af2831b14c1b44b7ff6eabefb62cbed6528a609e9248e9eef9949474c5888d1f8ca6262de"),
            (512, "edb9bed721aa6a5f6fbc6619d3a3c2be3d043043f05a9aebc7b1197a2aa9c49a57d5ddd4674c1785785088d9f1ff42c797a02adc9b817a139a50970da6c99524"),
        ];
        for &(len, expected) in vectors {
            let mut h = Sha512::new();
            h.update(&source[..len]);
            let digest = h.finalize();
            let hex_digest: String = to_hex(&digest);
            assert_eq!(
                hex_digest, expected,
                "SHA-512 mismatch at message length {len}"
            );
        }
    }

    #[test]
    fn mod_l_reduces() {
        // L mod L == 0.
        let l8: [u64; 8] = [L[0], L[1], L[2], L[3], 0, 0, 0, 0];
        assert_eq!(mod_l(l8), [0, 0, 0, 0]);
        // 2^512 - 1 mod L is well-defined; recompute via a second path.
        let max = [u64::MAX; 8];
        let reduced = mod_l(max);
        // reduced < L
        assert_eq!(cmp4(&reduced, &L), core::cmp::Ordering::Less);
    }
}
