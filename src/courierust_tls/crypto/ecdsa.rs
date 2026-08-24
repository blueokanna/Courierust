//! ECDSA signature verification and signing over the NIST curves
//! P-256 / P-384 / P-521 (SEC 1 / FIPS 186-4), plus ECDHE for the
//! TLS 1.2 `secp256r1` suite.
//!
//! All three curves have `a = -3`, so a single Jacobian-coordinate
//! point implementation parameterized by curve constants serves all of
//! them. Field and scalar arithmetic run in the Montgomery domain with
//! constant-time CIOS multiplication (fixed iteration counts, masked
//! carries — no secret-dependent branches or indexing), field
//! exponentiation uses square-and-multiply-always, and scalar
//! multiplication uses a constant-time Montgomery ladder with masked
//! conditional swaps. Consequently the secret scalars (ECDHE private
//! keys, ECDSA nonces and private scalars) never influence execution
//! time or memory access patterns.
//!
//! The curve↔hash mapping follows the strictest mainstream
//! interpretation (identical to rustls/webpki): `ecdsa-with-SHA256`
//! requires P-256, `ecdsa-with-SHA384` requires P-384, and
//! `ecdsa-with-SHA512` requires P-521.
//!
//! Lints: the field/scalar kernels use explicit `for i in 0..K` loops and
//! `from_*` helpers on the Montgomery context on purpose — fixed
//! iteration counts are part of the constant-time contract, and iterator
//! rewrites risk subtly changing codegen. These are the only two lints
//! suppressed for this module.
#![allow(clippy::needless_range_loop, clippy::wrong_self_convention)]

use super::hash::{Sha256, Sha384};
use super::hmac::hmac;
use super::rsa::BigInt;
use alloc::vec::Vec;

/// The NIST curves supported for ECDSA / ECDHE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// secp256r1 / prime256v1 (associated hash: SHA-256).
    P256,
    /// secp384r1 (associated hash: SHA-384).
    P384,
    /// secp521r1 (associated hash: SHA-512).
    P521,
}

impl Curve {
    /// The coordinate size in bytes (also the size of an `r`/`s` scalar).
    pub(crate) fn coord_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }
}

/// The hash associated with a curve (RFC 6979 §2.4 / FIPS 186-4).
#[derive(Debug, Clone, Copy)]
enum CurveHash {
    Sha256,
    Sha384,
    Sha512,
}

impl CurveHash {
    fn output_len(self) -> usize {
        match self {
            CurveHash::Sha256 => 32,
            CurveHash::Sha384 => 48,
            CurveHash::Sha512 => 64,
        }
    }

    fn boxed(self) -> super::hash::BoxDigest {
        match self {
            CurveHash::Sha256 => Box::<Sha256>::default(),
            CurveHash::Sha384 => Box::<Sha384>::default(),
            CurveHash::Sha512 => Box::<super::ed25519::Sha512>::default(),
        }
    }
}

// ---------------------------------------------------------------------
// Curve constants (canonical SEC 2 big-endian hex).
// ---------------------------------------------------------------------

const P256_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const P256_GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const P256_GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
const P256_B: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";

const P384_P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
const P384_N: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
const P384_GX: &str = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
const P384_GY: &str = "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
const P384_B: &str = "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef";

const P521_P: &str = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const P521_N: &str = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
const P521_GX: &str = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
const P521_GY: &str = "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650";
const P521_B: &str = "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00";

/// Decode a big-endian hex string into `K` little-endian limbs.
/// `hex` must contain at most `16 * K` hex digits (verified by tests);
/// shorter strings are right-aligned, i.e. the value's leading zero
/// bytes are implicit (needed for P-521, whose 66-byte parameters fit
/// in 9 limbs).
const fn hex_to_le_limbs<const K: usize>(hex: &str) -> [u64; K] {
    let bytes = hex.as_bytes();
    let n = bytes.len();
    let mut out = [0u64; K];
    // Number of implicit leading (zero) nibbles.
    let nibble_offset = 16 * K - n;
    let mut i = 0;
    while i + 1 < n {
        let hi = hex_val(bytes[i]);
        let lo = hex_val(bytes[i + 1]);
        let byte = (hi << 4) | lo;
        let abs_nibble = nibble_offset + i; // position in the full array
        let limb_from_msb = abs_nibble / 16; // 0 = most significant limb
        let pos = abs_nibble % 16; // hex-nibble position within that limb
        let byte_pos = pos / 2; // byte position within the limb (MSB first)
        let shift = (7 - byte_pos) * 8;
        out[K - 1 - limb_from_msb] |= (byte as u64) << shift;
        i += 2;
    }
    out
}

const fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// A curve parameter set (all values as little-endian limbs).
struct CurveSpec<const K: usize> {
    p: [u64; K],
    n: [u64; K],
    gx: [u64; K],
    gy: [u64; K],
    b: [u64; K],
    coord_len: usize,
    hash: CurveHash,
}

const fn p256_spec() -> CurveSpec<4> {
    CurveSpec {
        p: hex_to_le_limbs(P256_P),
        n: hex_to_le_limbs(P256_N),
        gx: hex_to_le_limbs(P256_GX),
        gy: hex_to_le_limbs(P256_GY),
        b: hex_to_le_limbs(P256_B),
        coord_len: 32,
        hash: CurveHash::Sha256,
    }
}

const fn p384_spec() -> CurveSpec<6> {
    CurveSpec {
        p: hex_to_le_limbs(P384_P),
        n: hex_to_le_limbs(P384_N),
        gx: hex_to_le_limbs(P384_GX),
        gy: hex_to_le_limbs(P384_GY),
        b: hex_to_le_limbs(P384_B),
        coord_len: 48,
        hash: CurveHash::Sha384,
    }
}

const fn p521_spec() -> CurveSpec<9> {
    CurveSpec {
        p: hex_to_le_limbs(P521_P),
        n: hex_to_le_limbs(P521_N),
        gx: hex_to_le_limbs(P521_GX),
        gy: hex_to_le_limbs(P521_GY),
        b: hex_to_le_limbs(P521_B),
        coord_len: 66,
        hash: CurveHash::Sha512,
    }
}

/// Little-endian limbs from big-endian bytes.
///
/// The input is **right-aligned** in the K·8-byte window: for a value
/// whose encoding is shorter than K·8 bytes (P-521 coordinates are
/// 66 bytes in a 72-byte window), the leading zero bytes are implicit.
/// Mis-aligning this shifts the value up (×2^48 for P-521), which both
/// corrupts results and turns `from_be`'s reduction loop into an
/// effectively unbounded number of subtractions.
fn be_to_le_limbs<const K: usize>(bytes: &[u8]) -> [u64; K] {
    let mut out = [0u64; K];
    let window = K * 8;
    let n = bytes.len();
    if n == 0 {
        return out;
    }
    let take = n.min(window);
    let offset = window - take; // leading zero bytes in the window
    let start = n - take;
    for (i, &b) in bytes[start..].iter().enumerate() {
        let idx = offset + i; // window position (0 = most significant byte)
        let from_lsb = window - 1 - idx; // distance from the least significant byte
        let limb = from_lsb / 8;
        let byte_pos = from_lsb % 8;
        out[limb] |= (b as u64) << (8 * byte_pos);
    }
    out
}

/// Big-endian bytes (exactly `len`) from little-endian limbs.
///
/// The output is right-aligned: it carries the value's low `min(K·8, len)`
/// bytes, with leading zero bytes only when `len > K·8`. Reading from the
/// top instead (as a full-width conversion would) drops the low bytes of
/// values narrower than the limb window — for P-521 (66-byte values in a
/// 72-byte window) that silently divided by 2^48.
fn le_limbs_to_be<const K: usize>(v: &[u64; K], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let window = K * 8;
    let take = window.min(len);
    let offset = len - take;
    for i in 0..take {
        // Output byte `offset + i` holds the value's byte `take-1-i`
        // from the least-significant end.
        let from_lsb = take - 1 - i;
        let limb = from_lsb / 8;
        let byte_pos = from_lsb % 8;
        out[offset + i] = (v[limb] >> (8 * byte_pos)) as u8;
    }
    out
}

// ---------------------------------------------------------------------
// Constant-time Montgomery arithmetic (CIOS multiplication).
// ---------------------------------------------------------------------

/// Montgomery context for a K-limb odd modulus `m` (R = 2^(64K)).
struct MontCtx<const K: usize> {
    m: [u64; K],
    /// -m^-1 mod 2^64.
    m0_inv: u64,
    /// R^2 mod m (used to convert into the Montgomery domain).
    r2: [u64; K],
    /// Canonical byte length of a value below `m`.
    out_len: usize,
}

impl<const K: usize> MontCtx<K> {
    fn new(m: [u64; K], out_len: usize) -> Self {
        let m0_inv = mont_nprime(&m);
        let r2 = mont_r2(&m);
        Self {
            m,
            m0_inv,
            r2,
            out_len,
        }
    }

    #[inline]
    fn zero(&self) -> [u64; K] {
        [0; K]
    }

    /// The Montgomery form of 1 (i.e. R mod m).
    fn one(&self) -> [u64; K] {
        let mut o = [0u64; K];
        o[0] = 1;
        self.mul(&o, &self.r2)
    }

    #[inline]
    fn is_zero(&self, a: &[u64; K]) -> bool {
        a.iter().all(|&v| v == 0)
    }

    /// Field-element equality (representations are canonical: every value
    /// is kept reduced below the modulus, so the representation is unique).
    #[inline]
    fn eq(&self, a: &[u64; K], b: &[u64; K]) -> bool {
        a == b
    }

    /// Convert an already-reduced little-endian limb value into the
    /// Montgomery domain (constant time).
    fn to_mont(&self, a: &[u64; K]) -> [u64; K] {
        self.mul(a, &self.r2)
    }

    /// Convert from the Montgomery domain back to canonical LE limbs.
    fn from_mont(&self, a: &[u64; K]) -> [u64; K] {
        let mut o = [0u64; K];
        o[0] = 1;
        self.mul(a, &o)
    }

    /// `a + b mod m` (constant time, inputs < m).
    fn add(&self, a: &[u64; K], b: &[u64; K]) -> [u64; K] {
        let mut r = [0u64; K];
        let mut carry = 0u64;
        for i in 0..K {
            let (s1, c1) = a[i].overflowing_add(b[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            r[i] = s2;
            carry = (c1 as u64).wrapping_add(c2 as u64);
        }
        // r < 2m: subtract m once, masked on (carry || r >= m).
        let ge_mask = mask_from_bool(carry != 0 || cmp_ge(&r, &self.m));
        sub_masked(&mut r, &self.m, ge_mask);
        r
    }

    /// `a - b mod m` (constant time, inputs < m).
    fn sub(&self, a: &[u64; K], b: &[u64; K]) -> [u64; K] {
        // a - b mod m = a + (m - b) mod m
        let mut neg_b = [0u64; K];
        let mut borrow = 0u64;
        for i in 0..K {
            let (s1, b1) = self.m[i].overflowing_sub(b[i]);
            let (s2, b2) = s1.overflowing_sub(borrow);
            neg_b[i] = s2;
            borrow = (b1 as u64).wrapping_add(b2 as u64);
        }
        // If b == 0 then neg_b == m (not < m); force it to 0.
        let b_zero_mask = mask_from_bool(self.is_zero(b));
        for i in 0..K {
            neg_b[i] &= !b_zero_mask;
        }
        self.add(a, &neg_b)
    }

    /// `k·a mod m` for a small public constant `k` (constant time).
    fn mul_small(&self, a: &[u64; K], k: u64) -> [u64; K] {
        let mut r = self.zero();
        let mut i = 0;
        while i < k {
            r = self.add(&r, a);
            i += 1;
        }
        r
    }

    /// Montgomery multiplication `a·b·R^-1 mod m` (CIOS, constant time).
    fn mul(&self, a: &[u64; K], b: &[u64; K]) -> [u64; K] {
        // CIOS workspace: K+2 limbs. Every supported curve has K ≤ 9, so a
        // fixed 11-limb buffer covers all specializations (K+2 ≤ 11).
        let mut t = [0u64; 11];
        for i in 0..K {
            let bi = b[i];
            // Step 1: t = t + a·b[i]
            let mut c: u128 = 0;
            for j in 0..K {
                let cur = t[j] as u128 + (a[j] as u128) * (bi as u128) + c;
                t[j] = cur as u64;
                c = cur >> 64;
            }
            let cur = t[K] as u128 + c;
            t[K] = cur as u64;
            t[K + 1] = (cur >> 64) as u64;

            // Step 2: m_i = t[0]·m0_inv mod 2^64; t = (t + m_i·m) >> 64.
            let mi = t[0].wrapping_mul(self.m0_inv);
            let mut c: u128 = (t[0] as u128 + (mi as u128) * (self.m[0] as u128)) >> 64;
            for j in 1..K {
                let cur = t[j] as u128 + (mi as u128) * (self.m[j] as u128) + c;
                t[j - 1] = cur as u64;
                c = cur >> 64;
            }
            let cur = t[K] as u128 + c;
            t[K - 1] = cur as u64;
            let fin = t[K + 1] as u128 + (cur >> 64);
            t[K] = fin as u64;
        }
        let mut res = [0u64; K];
        // The CIOS result R lives in K+1 limbs (t[0..K], with t[K] ∈
        // {0,1,2}) and satisfies R < 2m. Since m is near 2^(64K), R can
        // exceed 2^(64K), so the top limb must participate in the final
        // reduction: subtract m once when R >= m (constant time). Every
        // supported curve has K ≤ 9, so a fixed 10-limb buffer covers all
        // specializations.
        let mut r = [0u64; 10];
        r[..K].copy_from_slice(&t[..K]);
        r[K] = t[K];
        let ge = t[K] != 0 || cmp_ge(&r[..K].try_into().unwrap(), &self.m);
        let mask = mask_from_bool(ge);
        let mut borrow = 0u64;
        for i in 0..K {
            let mi = self.m[i] & mask;
            let (s1, b1) = r[i].overflowing_sub(mi);
            let (s2, b2) = s1.overflowing_sub(borrow);
            r[i] = s2;
            borrow = (b1 as u64).wrapping_add(b2 as u64);
        }
        r[K] = r[K].wrapping_sub(borrow & mask);
        res.copy_from_slice(&r[..K]);
        res
    }

    /// `a^exp mod m` with a fixed iteration count and masked selection
    /// (square-and-multiply-always; constant time).
    fn pow(&self, a: &[u64; K], exp: &[u64; K]) -> [u64; K] {
        let mut acc = self.one();
        for bit in (0..K * 64).rev() {
            let sq = self.mul(&acc, &acc);
            let with_mul = self.mul(&sq, a);
            let mask = mask_from_bool(exp[bit / 64] >> (bit % 64) & 1 == 1);
            for j in 0..K {
                acc[j] = sq[j] ^ ((sq[j] ^ with_mul[j]) & mask);
            }
        }
        acc
    }

    /// `a^-1 mod m` via Fermat (m prime): a^(m-2) (constant time).
    fn inv(&self, a: &[u64; K]) -> [u64; K] {
        let mut exp = self.m;
        let mut borrow = 0u64;
        for i in 0..K {
            let sub = if i == 0 { 2u64 } else { 0u64 };
            let (s1, b1) = exp[i].overflowing_sub(sub);
            let (s2, b2) = s1.overflowing_sub(borrow);
            exp[i] = s2;
            borrow = (b1 as u64).wrapping_add(b2 as u64);
        }
        self.pow(a, &exp)
    }

    /// Little-endian limbs from big-endian bytes, reduced mod m (public
    /// data; the reduction loop is variable-time).
    fn from_be(&self, bytes: &[u8]) -> [u64; K] {
        let mut v = be_to_le_limbs::<K>(bytes);
        while cmp_ge(&v, &self.m) {
            let _ = sub_inplace(&mut v, &self.m);
        }
        self.to_mont(&v)
    }

    /// Canonical big-endian bytes (out_len) of a field element.
    fn to_be(&self, a: &[u64; K]) -> Vec<u8> {
        let v = self.from_mont(a);
        le_limbs_to_be(&v, self.out_len)
    }
}

/// -m^-1 mod 2^64 via Newton iteration.
fn mont_nprime<const K: usize>(m: &[u64; K]) -> u64 {
    let n0 = m[0];
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(x)));
    }
    x.wrapping_neg()
}

/// R^2 mod m with R = 2^(64K) (computed once per curve at setup).
fn mont_r2<const K: usize>(m: &[u64; K]) -> [u64; K] {
    let m_big = BigInt::from_le_limbs(m);
    let mut r2 = BigInt::from_u64(1);
    for _ in 0..K * 128 {
        r2 = r2.add(&r2);
        if r2.cmp(&m_big) != core::cmp::Ordering::Less {
            r2 = r2.sub(&m_big);
        }
    }
    let bytes = r2.to_be_bytes_padded(K * 8);
    be_to_le_limbs::<K>(&bytes)
}

#[inline]
fn mask_from_bool(b: bool) -> u64 {
    0u64.wrapping_sub(b as u64)
}

/// `a >= b` (constant time).
fn cmp_ge<const K: usize>(a: &[u64; K], b: &[u64; K]) -> bool {
    let mut lt = 0u64;
    let mut gt = 0u64;
    for i in (0..K).rev() {
        let neither = !(lt | gt);
        gt |= neither & mask_from_bool(a[i] > b[i]);
        lt |= neither & mask_from_bool(a[i] < b[i]);
    }
    lt == 0 // a >= b iff not(a < b)
}

/// `a -= b` (returns 1 if a < b, i.e. a borrow out of the top limb).
fn sub_inplace<const K: usize>(a: &mut [u64; K], b: &[u64; K]) -> u64 {
    let mut borrow = 0u64;
    for i in 0..K {
        let (s1, b1) = a[i].overflowing_sub(b[i]);
        let (s2, b2) = s1.overflowing_sub(borrow);
        a[i] = s2;
        borrow = (b1 as u64).wrapping_add(b2 as u64);
    }
    borrow
}

/// `a -= (b & mask)` (constant time).
fn sub_masked<const K: usize>(a: &mut [u64; K], b: &[u64; K], mask: u64) {
    let mut borrow = 0u64;
    for i in 0..K {
        let bi = b[i] & mask;
        let (s1, b1) = a[i].overflowing_sub(bi);
        let (s2, b2) = s1.overflowing_sub(borrow);
        a[i] = s2;
        borrow = (b1 as u64).wrapping_add(b2 as u64);
    }
}

// ---------------------------------------------------------------------
// Jacobian point arithmetic (a = -3) — constant-time on the ladder.
// ---------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Point<const K: usize> {
    x: [u64; K],
    y: [u64; K],
    z: [u64; K],
}

fn infinity_point<const K: usize>(f: &MontCtx<K>) -> Point<K> {
    Point {
        x: f.zero(),
        y: f.zero(),
        z: f.zero(),
    }
}

fn select_point<const K: usize>(a: &Point<K>, b: &Point<K>, mask: u64) -> Point<K> {
    let mut r = Point {
        x: a.x,
        y: a.y,
        z: a.z,
    };
    for i in 0..K {
        r.x[i] ^= (r.x[i] ^ b.x[i]) & mask;
        r.y[i] ^= (r.y[i] ^ b.y[i]) & mask;
        r.z[i] ^= (r.z[i] ^ b.z[i]) & mask;
    }
    r
}

fn cswap_point<const K: usize>(a: &mut Point<K>, b: &mut Point<K>, mask: u64) {
    for i in 0..K {
        let tx = (a.x[i] ^ b.x[i]) & mask;
        a.x[i] ^= tx;
        b.x[i] ^= tx;
        let ty = (a.y[i] ^ b.y[i]) & mask;
        a.y[i] ^= ty;
        b.y[i] ^= ty;
        let tz = (a.z[i] ^ b.z[i]) & mask;
        a.z[i] ^= tz;
        b.z[i] ^= tz;
    }
}

/// Jacobian doubling (a = -3); masked handling of the point at infinity.
fn point_double<const K: usize>(p: &Point<K>, f: &MontCtx<K>) -> Point<K> {
    let a = f.mul(&p.x, &p.x);
    let b = f.mul(&p.y, &p.y);
    let c = f.mul(&b, &b);
    let xb = f.add(&p.x, &b);
    let e = f.sub(&f.sub(&f.mul(&xb, &xb), &a), &c);
    let d = f.add(&e, &e); // 2E
    let z2 = f.mul(&p.z, &p.z);
    let z4 = f.mul(&z2, &z2);
    // E3 = 3A - 3Z^4 (a = -3).
    let e3 = f.sub(&f.mul_small(&a, 3), &f.mul_small(&z4, 3));
    let x3 = f.sub(&f.mul(&e3, &e3), &f.add(&d, &d));
    let y3 = f.sub(&f.mul(&e3, &f.sub(&d, &x3)), &f.mul_small(&c, 8));
    let z3 = f.mul(&f.add(&p.y, &p.y), &p.z);
    let inf_mask = mask_from_bool(f.is_zero(&p.z));
    select_point(
        &Point {
            x: x3,
            y: y3,
            z: z3,
        },
        p,
        inf_mask,
    )
}

/// Jacobian addition (a = -3). Constant-time in the ladder context
/// (masked infinity handling; the p==q / p==-q branches are provably
/// never taken there because R1 - R0 = P ≠ O). For public verification
/// the equality branches are handled correctly.
fn point_add<const K: usize>(p: &Point<K>, q: &Point<K>, f: &MontCtx<K>) -> Point<K> {
    let z1z1 = f.mul(&p.z, &p.z);
    let z2z2 = f.mul(&q.z, &q.z);
    let u1 = f.mul(&p.x, &z2z2);
    let u2 = f.mul(&q.x, &z1z1);
    let s1 = f.mul(&f.mul(&p.y, &z2z2), &q.z);
    let s2 = f.mul(&f.mul(&q.y, &z1z1), &p.z);
    let h = f.sub(&u2, &u1);
    let r = f.sub(&s2, &s1);
    let h2 = f.mul(&h, &h);
    let h3 = f.mul(&h2, &h);
    let u1h2 = f.mul(&u1, &h2);
    let x3 = f.sub(&f.sub(&f.mul(&r, &r), &h3), &f.add(&u1h2, &u1h2));
    let y3 = f.sub(&f.mul(&r, &f.sub(&u1h2, &x3)), &f.mul(&s1, &h3));
    let z3 = f.mul(&f.mul(&h, &p.z), &q.z);
    let general = Point {
        x: x3,
        y: y3,
        z: z3,
    };

    let p_inf = f.is_zero(&p.z);
    let q_inf = f.is_zero(&q.z);
    let same = !p_inf && !q_inf && f.is_zero(&h) && f.is_zero(&r);
    if same {
        // p == q: doubling. Never taken on the ladder (R0 ≠ R1).
        return point_double(p, f);
    }
    if !p_inf && !q_inf && f.is_zero(&h) && !f.is_zero(&r) {
        // p == -q: the result is the point at infinity.
        return infinity_point(f);
    }
    // Masked infinity handling (constant time).
    let p_inf_mask = mask_from_bool(p_inf);
    let q_inf_mask = mask_from_bool(q_inf);
    let mut res = general;
    res = select_point(&res, q, p_inf_mask);
    res = select_point(&res, p, q_inf_mask);
    res
}

/// Constant-time scalar multiplication: Montgomery ladder with masked
/// conditional swaps. `scalar` is `K` little-endian limbs; the iteration
/// count is fixed at K*64 bits regardless of the value.
fn scalar_mult<const K: usize>(p: &Point<K>, scalar: &[u64; K], f: &MontCtx<K>) -> Point<K> {
    let mut r0 = infinity_point(f);
    let mut r1 = Point {
        x: p.x,
        y: p.y,
        z: p.z,
    };
    for bit in (0..K * 64).rev() {
        let mask = mask_from_bool(scalar[bit / 64] >> (bit % 64) & 1 == 1);
        cswap_point(&mut r0, &mut r1, mask);
        r1 = point_add(&r0, &r1, f);
        r0 = point_double(&r0, f);
        cswap_point(&mut r0, &mut r1, mask);
    }
    r0
}

/// Affine x coordinate (None at the point at infinity). The branch on
/// `z == 0` is never taken for the inputs used here (valid on-curve
/// points multiplied by scalars in [1, n-1] on a prime-order curve),
/// so it does not leak secret information.
fn affine_x<const K: usize>(p: &Point<K>, f: &MontCtx<K>) -> Option<[u64; K]> {
    if f.is_zero(&p.z) {
        return None;
    }
    let zi = f.inv(&p.z);
    let zi2 = f.mul(&zi, &zi);
    Some(f.mul(&p.x, &zi2))
}

fn affine_y<const K: usize>(p: &Point<K>, f: &MontCtx<K>) -> Option<[u64; K]> {
    if f.is_zero(&p.z) {
        return None;
    }
    let zi = f.inv(&p.z);
    let zi2 = f.mul(&zi, &zi);
    let zi3 = f.mul(&zi2, &zi);
    Some(f.mul(&p.y, &zi3))
}

/// On-curve check: y² == x³ - 3x + b (affine coordinates).
fn on_curve<const K: usize>(
    spec: &CurveSpec<K>,
    f: &MontCtx<K>,
    x: &[u64; K],
    y: &[u64; K],
) -> bool {
    let b_mont = f.to_mont(&spec.b);
    let lhs = f.mul(y, y);
    let x2 = f.mul(x, x);
    let x3 = f.mul(&x2, x);
    let rhs = f.sub(&f.add(&x3, &b_mont), &f.mul_small(x, 3));
    f.eq(&lhs, &rhs)
}

/// The base point with Z = 1 (in Montgomery form).
fn base_point<const K: usize>(spec: &CurveSpec<K>, f: &MontCtx<K>) -> Point<K> {
    Point {
        x: f.to_mont(&spec.gx),
        y: f.to_mont(&spec.gy),
        z: f.one(),
    }
}

/// Little-endian limbs (K) from a BigInt (padded).
fn bigint_to_limbs<const K: usize>(v: &BigInt) -> [u64; K] {
    let bytes = v.to_be_bytes_padded(K * 8);
    be_to_le_limbs::<K>(&bytes)
}

// ---------------------------------------------------------------------
// ECDSA signature parsing
// ---------------------------------------------------------------------

/// Parse a DER `ECDSA-Sig-Value`: `SEQUENCE { r INTEGER, s INTEGER }`.
/// Integers must be positive, minimally encoded, and no wider than the
/// curve order.
fn parse_der_signature<const K: usize>(der: &[u8], coord_len: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    fn read_tlv(der: &[u8], pos: &mut usize) -> Option<(u8, Vec<u8>)> {
        if *pos >= der.len() {
            return None;
        }
        let tag = der[*pos];
        *pos += 1;
        if *pos >= der.len() {
            return None;
        }
        let len_byte = der[*pos];
        *pos += 1;
        let len = if len_byte & 0x80 == 0 {
            len_byte as usize
        } else {
            let n = (len_byte & 0x7f) as usize;
            if n == 0 || n > 4 || *pos + n > der.len() {
                return None;
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | der[*pos] as usize;
                *pos += 1;
            }
            l
        };
        if *pos + len > der.len() {
            return None;
        }
        let value = der[*pos..*pos + len].to_vec();
        *pos += len;
        Some((tag, value))
    }

    fn int_ok(v: &[u8], coord_len: usize) -> bool {
        if v.is_empty() || v.len() > coord_len + 1 {
            return false;
        }
        // A negative INTEGER (no leading sign byte) is invalid here.
        if v[0] & 0x80 != 0 {
            return false;
        }
        // A leading 0x00 is only legal to clear the sign bit.
        if v.len() > 1 && v[0] == 0x00 && v[1] < 0x80 {
            return false;
        }
        true
    }

    let mut pos = 0usize;
    let (tag, body) = read_tlv(der, &mut pos)?;
    if tag != 0x30 || pos != der.len() {
        return None;
    }
    let mut p = 0usize;
    let (r_tag, r) = read_tlv(&body, &mut p)?;
    if r_tag != 0x02 {
        return None;
    }
    let (s_tag, s) = read_tlv(&body, &mut p)?;
    if s_tag != 0x02 || p != body.len() {
        return None;
    }
    if !int_ok(&r, coord_len) || !int_ok(&s, coord_len) {
        return None;
    }
    let rv = strip_leading_zero(&r);
    let sv = strip_leading_zero(&s);
    if rv.is_empty() || sv.is_empty() || rv.len() > coord_len || sv.len() > coord_len {
        return None;
    }
    let mut r_out = vec![0u8; coord_len];
    let mut s_out = vec![0u8; coord_len];
    r_out[coord_len - rv.len()..].copy_from_slice(rv);
    s_out[coord_len - sv.len()..].copy_from_slice(sv);
    Some((r_out, s_out))
}

fn strip_leading_zero(v: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < v.len() && v[i] == 0 {
        i += 1;
    }
    &v[i..]
}

/// The integer `e` for ECDSA: the leftmost `min(qlen, 8·len(digest))`
/// bits of the digest, reduced mod n.
fn digest_to_e(digest: &[u8], coord_len: usize, n: &BigInt) -> BigInt {
    let e_bytes = if digest.len() >= coord_len {
        &digest[..coord_len]
    } else {
        digest
    };
    BigInt::from_be_bytes(e_bytes).rem(n)
}

// ---------------------------------------------------------------------
// ECDSA verification
// ---------------------------------------------------------------------

/// Verify a DER `ECDSA-Sig-Value` over `digest` with the EC public key
/// `(qx, qy)` (big-endian, `coord_len` bytes each). The digest must be
/// the curve's associated hash output (SHA-256 / SHA-384 / SHA-512).
pub fn verify_der(curve: Curve, qx: &[u8], qy: &[u8], digest: &[u8], der: &[u8]) -> bool {
    match curve {
        Curve::P256 => verify_curve(&p256_spec(), qx, qy, digest, der),
        Curve::P384 => verify_curve(&p384_spec(), qx, qy, digest, der),
        Curve::P521 => verify_curve(&p521_spec(), qx, qy, digest, der),
    }
}

fn verify_curve<const K: usize>(
    spec: &CurveSpec<K>,
    qx: &[u8],
    qy: &[u8],
    digest: &[u8],
    der: &[u8],
) -> bool {
    let (r_bytes, s_bytes) = match parse_der_signature::<K>(der, spec.coord_len) {
        Some(sig) => sig,
        None => return false,
    };
    let n = BigInt::from_le_limbs(&spec.n);
    let one = BigInt::from_u64(1);
    let r = BigInt::from_be_bytes(&r_bytes);
    let s = BigInt::from_be_bytes(&s_bytes);
    // r, s in [1, n-1].
    if r.cmp(&one) == core::cmp::Ordering::Less
        || r.cmp(&n) != core::cmp::Ordering::Less
        || s.cmp(&one) == core::cmp::Ordering::Less
        || s.cmp(&n) != core::cmp::Ordering::Less
    {
        return false;
    }

    // Public key coordinates must be exactly the coordinate size and
    // strictly below the field prime (canonical, rejects invalid-curve
    // and small-subgroup attacks).
    if qx.len() != spec.coord_len || qy.len() != spec.coord_len {
        return false;
    }
    let qx_limbs = be_to_le_limbs::<K>(qx);
    let qy_limbs = be_to_le_limbs::<K>(qy);
    if cmp_ge(&qx_limbs, &spec.p) || cmp_ge(&qy_limbs, &spec.p) {
        return false;
    }
    let f = MontCtx::new(spec.p, spec.coord_len);
    let qx_fe = f.to_mont(&qx_limbs);
    let qy_fe = f.to_mont(&qy_limbs);
    if !on_curve(spec, &f, &qx_fe, &qy_fe) {
        return false;
    }

    // e = leftmost min(qlen, hashlen) bits of the digest.
    let e = digest_to_e(digest, spec.coord_len, &n);
    let n_minus_2 = n.sub(&BigInt::from_u64(2));
    let w = s.mod_pow(&n_minus_2, &n);
    let u1 = e.mul(&w).rem(&n);
    let u2 = r.mul(&w).rem(&n);

    let g = base_point(spec, &f);
    let q = Point {
        x: qx_fe,
        y: qy_fe,
        z: f.one(),
    };
    let x1 = scalar_mult(&g, &bigint_to_limbs::<K>(&u1), &f);
    let x2 = scalar_mult(&q, &bigint_to_limbs::<K>(&u2), &f);
    let xsum = point_add(&x1, &x2, &f);
    let x_coord = match affine_x(&xsum, &f) {
        Some(x) => x,
        None => return false, // u1G + u2Q at infinity: invalid.
    };
    let v = BigInt::from_be_bytes(&f.to_be(&x_coord)).rem(&n);
    v.cmp(&r) == core::cmp::Ordering::Equal
}

// ---------------------------------------------------------------------
// ECDSA signing (RFC 6979 deterministic nonce, constant time)
// ---------------------------------------------------------------------

/// Sign `digest` (the curve's associated hash output) with the private
/// scalar `d` (big-endian, `coord_len` bytes). Returns `(r, s)` as
/// big-endian `coord_len`-byte values.
pub(crate) fn sign(curve: Curve, d: &[u8], digest: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    match curve {
        Curve::P256 => sign_curve(&p256_spec(), d, digest),
        Curve::P384 => sign_curve(&p384_spec(), d, digest),
        Curve::P521 => sign_curve(&p521_spec(), d, digest),
    }
}

fn sign_curve<const K: usize>(
    spec: &CurveSpec<K>,
    d: &[u8],
    digest: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let n = BigInt::from_le_limbs(&spec.n);
    let one = BigInt::from_u64(1);
    let d_int = BigInt::from_be_bytes(d);
    // d in [1, n-1].
    if d_int.cmp(&one) == core::cmp::Ordering::Less || d_int.cmp(&n) != core::cmp::Ordering::Less {
        return None;
    }

    let f = MontCtx::new(spec.p, spec.coord_len);
    let sn = MontCtx::new(spec.n, spec.coord_len);

    // Deterministic nonce k in [1, n-1] (RFC 6979 §3.2).
    let k = rfc6979_nonce(spec, d, digest)?;

    // R = k·G (constant-time ladder; k is secret).
    let g = base_point(spec, &f);
    let kg = scalar_mult(&g, &k, &f);
    let x1 = affine_x(&kg, &f)?;
    let r = BigInt::from_be_bytes(&f.to_be(&x1)).rem(&n);
    if r.is_zero() {
        return None;
    }

    // s = k^-1 · (e + r·d) mod n — all scalar arithmetic in the
    // constant-time Montgomery domain over n.
    let d_mont = sn.to_mont(&be_to_le_limbs::<K>(d));
    let k_mont = sn.to_mont(&k);
    let r_mont = sn.to_mont(&bigint_to_limbs::<K>(&r));
    let e_bytes = if digest.len() >= spec.coord_len {
        &digest[..spec.coord_len]
    } else {
        digest
    };
    let e_mont = sn.from_be(e_bytes);

    let k_inv = sn.inv(&k_mont);
    let rd = sn.mul(&r_mont, &d_mont);
    let s_mont = sn.mul(&sn.add(&e_mont, &rd), &k_inv);
    let s_bytes = sn.to_be(&s_mont);
    let s = BigInt::from_be_bytes(&s_bytes);
    if s.is_zero() {
        return None;
    }

    let r_bytes = r.to_be_bytes_padded(spec.coord_len);
    Some((r_bytes, s_bytes))
}

/// RFC 6979 §3.2 deterministic nonce: HMAC keyed by the private scalar
/// with the message digest; iterates the candidate chain until k in
/// [1, n-1]. Returns `K` little-endian limbs.
fn rfc6979_nonce<const K: usize>(spec: &CurveSpec<K>, d: &[u8], digest: &[u8]) -> Option<[u64; K]> {
    let hlen = spec.hash.output_len();
    let rolen = spec.coord_len;
    let n = BigInt::from_le_limbs(&spec.n);

    // bits2octets(H(m)): H(m) truncated to qlen bits, reduced mod n,
    // padded to rolen bytes. For our curves H(m) never exceeds qlen.
    let e = BigInt::from_be_bytes(digest)
        .rem(&n)
        .to_be_bytes_padded(rolen);

    let mut v = vec![0x01u8; hlen];
    let mut k = vec![0x00u8; hlen];

    // K = HMAC(K, V || 0x00 || int2octets(d) || bits2octets(H(m)))
    let mut m0 = Vec::with_capacity(hlen + 1 + rolen * 2);
    m0.extend_from_slice(&v);
    m0.push(0x00);
    m0.extend_from_slice(d);
    m0.extend_from_slice(&e);
    k = hmac(spec.hash.boxed().as_mut(), &k, &m0);
    v = hmac(spec.hash.boxed().as_mut(), &k, &v);

    // K = HMAC(K, V || 0x01 || int2octets(d) || bits2octets(H(m)))
    let mut m1 = Vec::with_capacity(hlen + 1 + rolen * 2);
    m1.extend_from_slice(&v);
    m1.push(0x01);
    m1.extend_from_slice(d);
    m1.extend_from_slice(&e);
    k = hmac(spec.hash.boxed().as_mut(), &k, &m1);
    v = hmac(spec.hash.boxed().as_mut(), &k, &v);

    let one = BigInt::from_u64(1);
    for _ in 0..1024 {
        v = hmac(spec.hash.boxed().as_mut(), &k, &v);
        let cand = BigInt::from_be_bytes(&v);
        if cand.cmp(&one) != core::cmp::Ordering::Less && cand.cmp(&n) == core::cmp::Ordering::Less
        {
            return Some(be_to_le_limbs::<K>(&cand.to_be_bytes_padded(rolen)));
        }
        // K = HMAC(K, V || 0x00); V = HMAC(K, V)
        let mut m2 = Vec::with_capacity(hlen + 1);
        m2.extend_from_slice(&v);
        m2.push(0x00);
        k = hmac(spec.hash.boxed().as_mut(), &k, &m2);
        v = hmac(spec.hash.boxed().as_mut(), &k, &v);
    }
    None // entropy/edge guard: the RFC 6979 chain always terminates.
}

// ---------------------------------------------------------------------
// ECDHE (TLS 1.2 `secp256r1` key agreement)
// ---------------------------------------------------------------------

/// Generate an ECDHE key pair for TLS 1.2: returns the 32-byte private
/// scalar and the 65-byte uncompressed public point `0x04 || X || Y`.
/// The scalar is rejection-sampled in [1, n-1] and the point is
/// validated to lie on the curve. All secret operations are constant
/// time.
pub(crate) fn ecdhe_generate(fallback: Option<&[u8; 32]>) -> Option<([u8; 32], [u8; 65])> {
    let spec = p256_spec();
    let d = sample_scalar(&spec, fallback)?;
    let f = MontCtx::new(spec.p, spec.coord_len);
    let g = base_point(&spec, &f);
    let d_limbs = be_to_le_limbs::<4>(&d);
    let q = scalar_mult(&g, &d_limbs, &f);
    let x = affine_x(&q, &f)?;
    let y = affine_y(&q, &f)?;
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(&f.to_be(&x));
    point[33..65].copy_from_slice(&f.to_be(&y));
    Some((d, point))
}

/// Compute the ECDH shared secret for TLS 1.2: the 32-byte big-endian
/// x-coordinate of `d · Q`. The peer point is validated to be a
/// canonical on-curve point (invalid-curve defence) and the scalar is
/// checked to be in [1, n-1] before use.
pub(crate) fn ecdhe_shared(d: &[u8; 32], peer_point: &[u8; 65]) -> Option<[u8; 32]> {
    if peer_point[0] != 0x04 {
        return None;
    }
    let spec = p256_spec();
    let n = BigInt::from_le_limbs(&spec.n);
    let one = BigInt::from_u64(1);
    let d_int = BigInt::from_be_bytes(d);
    if d_int.cmp(&one) == core::cmp::Ordering::Less || d_int.cmp(&n) != core::cmp::Ordering::Less {
        return None;
    }
    let qx_limbs = be_to_le_limbs::<4>(&peer_point[1..33]);
    let qy_limbs = be_to_le_limbs::<4>(&peer_point[33..65]);
    if cmp_ge(&qx_limbs, &spec.p) || cmp_ge(&qy_limbs, &spec.p) {
        return None;
    }
    let f = MontCtx::new(spec.p, spec.coord_len);
    let qx_fe = f.to_mont(&qx_limbs);
    let qy_fe = f.to_mont(&qy_limbs);
    if !on_curve(&spec, &f, &qx_fe, &qy_fe) {
        return None;
    }
    let q = Point {
        x: qx_fe,
        y: qy_fe,
        z: f.one(),
    };
    let d_limbs = be_to_le_limbs::<4>(d);
    let p = scalar_mult(&q, &d_limbs, &f);
    let x = affine_x(&p, &f)?;
    let out = f.to_be(&x);
    // RFC 8422 §5.7: the shared secret must not be the point at
    // infinity; for a prime-order curve the x-coordinate is then
    // non-zero.
    if out.iter().all(|&b| b == 0) {
        return None;
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    Some(r)
}

/// Rejection-sample a private scalar in [1, n-1]. Falls back to
/// `fallback` (used in tests to inject a fixed scalar).
fn sample_scalar(spec: &CurveSpec<4>, fallback: Option<&[u8; 32]>) -> Option<[u8; 32]> {
    let n = BigInt::from_le_limbs(&spec.n);
    let one = BigInt::from_u64(1);
    let mut attempt = 0u32;
    loop {
        let mut d = [0u8; 32];
        let ok = match fallback {
            Some(f) => {
                d.copy_from_slice(f);
                true
            }
            None => super::rng::fill_random(&mut d),
        };
        if !ok {
            return None;
        }
        let d_int = BigInt::from_be_bytes(&d);
        if d_int.cmp(&one) != core::cmp::Ordering::Less
            && d_int.cmp(&n) == core::cmp::Ordering::Less
        {
            return Some(d);
        }
        if fallback.is_some() {
            return None; // a fixed invalid scalar is a test error
        }
        attempt += 1;
        if attempt > 64 {
            return None; // OS entropy degenerated; fail closed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_tls::crypto::hash::Digest;

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

    fn sha256(data: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize()
    }

    fn sha384(data: &[u8]) -> Vec<u8> {
        let mut h = Sha384::new();
        h.update(data);
        h.finalize()
    }

    fn sha512(data: &[u8]) -> Vec<u8> {
        let mut h = super::super::ed25519::Sha512::new();
        h.update(data);
        h.finalize()
    }

    #[test]
    fn curve_constant_hex_lengths() {
        assert_eq!(P256_P.len(), 64);
        assert_eq!(P256_N.len(), 64);
        assert_eq!(P256_GX.len(), 64);
        assert_eq!(P256_GY.len(), 64);
        assert_eq!(P256_B.len(), 64);
        assert_eq!(P384_P.len(), 96);
        assert_eq!(P384_N.len(), 96);
        assert_eq!(P384_GX.len(), 96);
        assert_eq!(P384_GY.len(), 96);
        assert_eq!(P384_B.len(), 96);
        assert_eq!(P521_P.len(), 132);
        assert_eq!(P521_N.len(), 132);
        assert_eq!(P521_GX.len(), 132);
        assert_eq!(P521_GY.len(), 132);
        assert_eq!(P521_B.len(), 132);
        // P-521's prime is 2^521 - 1: top limb 0x1FF, low limbs all-ones.
        let p521 = p521_spec();
        assert_eq!(p521.p[8], 0x1ff);
        for i in 0..8 {
            assert_eq!(p521.p[i], u64::MAX);
        }
        // P-521 order has a 0x01 top byte and a known tail.
        let n521 = BigInt::from_le_limbs(&p521.n);
        assert_eq!(n521.to_be_bytes_padded(66)[0], 0x01);
    }

    #[test]
    fn mont_debug() {
        // m = 13, K = 1: verify m0_inv, r2, and mont_mul by hand.
        let m: [u64; 1] = [13];
        let f = MontCtx::<1>::new(m, 1);
        // -13^-1 mod 2^64: 13 * x = 1 + k*2^64; 2^64 ≡ 3 (mod 13), k ≡ 4.
        // x = (1 + 4*2^64)/13
        let expected_inv: u64 = ((1u128 + 4u128 * (1u128 << 64)) / 13) as u64;
        assert_eq!(f.m0_inv, expected_inv.wrapping_neg());
        // r2 = R^2 mod m = 2^128 mod 13. 2^128 = (2^64)^2; 2^64 ≡ 3 mod 13 → 9.
        let r2_big = BigInt::from_le_limbs(&[9]);
        assert_eq!(
            r2_big.cmp(&BigInt::from_le_limbs(&f.r2)),
            core::cmp::Ordering::Equal
        );
        // mont_mul(a, b) = a*b*R^-1 mod 13; to_mont(a) = a*R mod 13 = a*9? No:
        // R mod 13 = 3, so to_mont(a) = a*3*... let's verify to_mont(2) = 2*R mod 13 = 6.
        let two = f.to_mont(&[2]);
        assert_eq!(two[0], 6);
        // from_mont(two) = 2
        assert_eq!(f.from_mont(&two)[0], 2);
        // mont_mul(to_mont(2), to_mont(3)) = to_mont(6) = 6*3 mod 13 = 18 mod 13 = 5
        let three = f.to_mont(&[3]);
        let six = f.mul(&two, &three);
        assert_eq!(f.from_mont(&six)[0], 6);
    }

    #[test]
    fn mont_debug_k2() {
        // K = 2 with a real 2-limb modulus; verify r2 / to_mont / mul
        // against BigInt.
        let m: [u64; 2] = [0xfffffffffffffff5, 0xffffffffffffffff];
        let f = MontCtx::<2>::new(m, 16);
        let m_big = BigInt::from_le_limbs(&m);
        let r2_big = BigInt::from_le_limbs(&f.r2);
        // r2 must equal 2^256 mod m.
        let mut exp = BigInt::from_u64(1);
        for _ in 0..256 {
            exp = exp.add(&exp);
            if exp.cmp(&m_big) != core::cmp::Ordering::Less {
                exp = exp.sub(&m_big);
            }
        }
        assert_eq!(r2_big.cmp(&exp), core::cmp::Ordering::Equal, "r2 wrong");
        // R = 2^128 mod m.
        let mut r = BigInt::from_u64(1);
        for _ in 0..128 {
            r = r.add(&r);
            if r.cmp(&m_big) != core::cmp::Ordering::Less {
                r = r.sub(&m_big);
            }
        }
        let a = [0x123456789abcdef0u64, 0x0fedcba987654321u64];
        let a_big = BigInt::from_le_limbs(&a);
        let expected_tomont = a_big.mul(&r).rem(&m_big);
        let got = f.to_mont(&a);
        assert_eq!(
            BigInt::from_le_limbs(&got).cmp(&expected_tomont),
            core::cmp::Ordering::Equal,
            "to_mont wrong"
        );
        let b = [0xdeadbeefcafebabeu64, 0x1234567890abcdefu64];
        let b_big = BigInt::from_le_limbs(&b);
        let ma = f.to_mont(&a);
        let mb = f.to_mont(&b);
        // mul(ma, mb) must equal to_mont(a*b mod m).
        let ab = a_big.mul(&b_big).rem(&m_big);
        let expected_mont = f.to_mont(&{
            let bytes = ab.to_be_bytes_padded(16);
            let mut limbs = [0u64; 2];
            for (i, chunk) in bytes.chunks(8).enumerate() {
                limbs[1 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
            }
            limbs
        });
        let raw = f.mul(&ma, &mb);
        assert_eq!(
            BigInt::from_le_limbs(&raw).cmp(&BigInt::from_le_limbs(&expected_mont)),
            core::cmp::Ordering::Equal,
            "mul(ma,mb) != to_mont(ab): raw {} expected_mont {}",
            to_hex(&BigInt::from_le_limbs(&raw).to_be_bytes_padded(16)),
            to_hex(&BigInt::from_le_limbs(&expected_mont).to_be_bytes_padded(16))
        );
        let c = f.from_mont(&raw);
        let expected_mul = a_big.mul(&b_big).rem(&m_big);
        assert_eq!(
            BigInt::from_le_limbs(&c).cmp(&expected_mul),
            core::cmp::Ordering::Equal,
            "mont_mul wrong: got {} expected {}",
            to_hex(&BigInt::from_le_limbs(&c).to_be_bytes_padded(16)),
            to_hex(&expected_mul.to_be_bytes_padded(16))
        );
    }

    /// P-521 Montgomery domain sanity: verify R, to_mont, from_mont and
    /// one multiplication directly against BigInt.
    #[test]
    fn mont_debug_p521() {
        let spec = p521_spec();
        let f = MontCtx::new(spec.p, spec.coord_len);
        let p = BigInt::from_le_limbs(&spec.p);
        // R = 2^(64*9) = 2^576.
        let mut r = BigInt::from_u64(1);
        for _ in 0..576 {
            r = r.add(&r);
            if r.cmp(&p) != core::cmp::Ordering::Less {
                r = r.sub(&p);
            }
        }
        // to_mont(2) must be 2*R mod p.
        let two = f.to_mont(&{
            let mut t = [0u64; 9];
            t[0] = 2;
            t
        });
        assert_eq!(
            BigInt::from_le_limbs(&two).cmp(&BigInt::from_u64(2).mul(&r).rem(&p)),
            core::cmp::Ordering::Equal,
            "to_mont(2) wrong"
        );
        // from_mont(to_mont(2)) == 2.
        let back = f.from_mont(&two);
        assert_eq!(
            BigInt::from_le_limbs(&back).cmp(&BigInt::from_u64(2)),
            core::cmp::Ordering::Equal,
            "from_mont roundtrip wrong"
        );
        // mul(to_mont(2), to_mont(3)) == to_mont(6).
        let three = f.to_mont(&{
            let mut t = [0u64; 9];
            t[0] = 3;
            t
        });
        let six = f.mul(&two, &three);
        let six_back = f.from_mont(&six);
        assert_eq!(
            BigInt::from_le_limbs(&six_back).cmp(&BigInt::from_u64(6)),
            core::cmp::Ordering::Equal,
            "2*3 mont mul wrong"
        );
        // from_be of a full 66-byte value must equal to_mont of the value.
        let a_be = {
            let mut v = vec![0u8; 66];
            for (i, b) in v.iter_mut().enumerate() {
                *b = i as u8;
            }
            v
        };
        let v_big = BigInt::from_be_bytes(&a_be);
        let via_be = f.from_be(&a_be);
        let expected_tomont = f.to_mont(&{
            let bytes = v_big.to_be_bytes_padded(72);
            let mut limbs = [0u64; 9];
            for (i, chunk) in bytes.chunks(8).enumerate() {
                limbs[8 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
            }
            limbs
        });
        assert_eq!(
            BigInt::from_le_limbs(&via_be).cmp(&BigInt::from_le_limbs(&expected_tomont)),
            core::cmp::Ordering::Equal,
            "from_be != to_mont: via_be={} expected={}",
            to_hex(&BigInt::from_le_limbs(&via_be).to_be_bytes_padded(66)),
            to_hex(&BigInt::from_le_limbs(&expected_tomont).to_be_bytes_padded(66))
        );
        // Cross-check the full multiply on the crosscheck's seed-0 values:
        // a*b mod p must match, both in mont domain and after from_mont.
        let a2: Vec<u8> = (0u8..66).collect();
        let b2: Vec<u8> = (0u8..66).map(|i| i.wrapping_mul(3)).collect();
        let am = f.from_be(&a2);
        let bm = f.from_be(&b2);
        let ab = BigInt::from_be_bytes(&a2)
            .mul(&BigInt::from_be_bytes(&b2))
            .rem(&p);
        let ab_limbs = {
            let bytes = ab.to_be_bytes_padded(72);
            let mut limbs = [0u64; 9];
            for (i, chunk) in bytes.chunks(8).enumerate() {
                limbs[8 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
            }
            limbs
        };
        let expect_mont = f.to_mont(&ab_limbs);
        let prod_mont = f.mul(&am, &bm);
        assert_eq!(
            BigInt::from_le_limbs(&prod_mont).cmp(&BigInt::from_le_limbs(&expect_mont)),
            core::cmp::Ordering::Equal,
            "mont-domain mul wrong: got={} expected={}",
            to_hex(&BigInt::from_le_limbs(&prod_mont).to_be_bytes_padded(66)),
            to_hex(&BigInt::from_le_limbs(&expect_mont).to_be_bytes_padded(66))
        );
        let prod_plain = f.from_mont(&prod_mont);
        assert_eq!(
            BigInt::from_le_limbs(&prod_plain).cmp(&ab),
            core::cmp::Ordering::Equal,
            "plain mul wrong"
        );
    }

    /// Montgomery multiplication cross-checked against BigInt for every
    /// curve: mont_mul(a,b) == a·b mod m.
    fn check_mont_mul<const K: usize>(spec: &CurveSpec<K>) {
        let f = MontCtx::new(spec.p, spec.coord_len);
        let p = BigInt::from_le_limbs(&spec.p);
        for seed in 0..8u8 {
            let mut a_be = vec![0u8; spec.coord_len];
            let mut b_be = vec![0u8; spec.coord_len];
            for (i, b) in a_be.iter_mut().enumerate() {
                *b = seed.wrapping_mul(31).wrapping_add(i as u8);
            }
            for (i, b) in b_be.iter_mut().enumerate() {
                *b = seed.wrapping_mul(17).wrapping_add(i as u8).wrapping_mul(3);
            }
            let a_mont = f.from_be(&a_be);
            let b_mont = f.from_be(&b_be);
            let c = f.from_mont(&f.mul(&a_mont, &b_mont));
            let c_be = BigInt::from_be_bytes(&le_limbs_to_be(&c, spec.coord_len));
            let expected = BigInt::from_be_bytes(&a_be)
                .mul(&BigInt::from_be_bytes(&b_be))
                .rem(&p);
            if c_be.cmp(&expected) != core::cmp::Ordering::Equal {
                eprintln!(
                    "seed={} a={} b={} got={} expected={}",
                    seed,
                    to_hex(&BigInt::from_be_bytes(&a_be).to_be_bytes_padded(spec.coord_len)),
                    to_hex(&BigInt::from_be_bytes(&b_be).to_be_bytes_padded(spec.coord_len)),
                    to_hex(
                        &BigInt::from_be_bytes(&le_limbs_to_be(&c, spec.coord_len))
                            .to_be_bytes_padded(spec.coord_len)
                    ),
                    to_hex(&expected.to_be_bytes_padded(spec.coord_len)),
                );
            }
            assert_eq!(
                c_be.cmp(&expected),
                core::cmp::Ordering::Equal,
                "mont mul mismatch on {:?}",
                spec.hash
            );
            // add / sub against BigInt.
            let s = f.from_mont(&f.add(&a_mont, &b_mont));
            let s_be = BigInt::from_be_bytes(&le_limbs_to_be(&s, spec.coord_len));
            let exp_add = BigInt::from_be_bytes(&a_be)
                .add(&BigInt::from_be_bytes(&b_be))
                .rem(&p);
            assert_eq!(s_be.cmp(&exp_add), core::cmp::Ordering::Equal);
        }
    }

    #[test]
    fn mont_mul_crosscheck_p256() {
        check_mont_mul(&p256_spec());
    }

    #[test]
    fn mont_mul_crosscheck_p384() {
        check_mont_mul(&p384_spec());
    }

    #[test]
    fn mont_mul_crosscheck_p521() {
        check_mont_mul(&p521_spec());
    }

    /// Generic field/group sanity for every curve: base point on curve,
    /// n·G = O, (n+1)·G = G, field identities, inverse.
    fn check_curve<const K: usize>(spec: &CurveSpec<K>) {
        let f = MontCtx::new(spec.p, spec.coord_len);

        let g = base_point(spec, &f);
        assert!(on_curve(spec, &f, &g.x, &g.y), "base point on curve");

        // n·G == infinity (order check).
        let ng = scalar_mult(&g, &spec.n, &f);
        assert!(f.is_zero(&ng.z), "n*G == infinity");

        // (n+1)·G == G (affine comparison; Jacobian coordinates are
        // only equal up to the common Z scaling).
        let mut np1 = spec.n;
        np1[0] = np1[0].wrapping_add(1);
        let ngp1 = scalar_mult(&g, &np1, &f);
        let ax = affine_x(&ngp1, &f).expect("(n+1)G not at infinity");
        let ay = affine_y(&ngp1, &f).expect("(n+1)G not at infinity");
        assert!(f.eq(&ax, &g.x) && f.eq(&ay, &g.y), "(n+1)*G == G");

        // Field identities (integer 1 in Montgomery form).
        let mut one_raw = [0u64; K];
        one_raw[0] = 1;
        let one_int = f.to_mont(&one_raw);
        let mut a_raw = vec![0u8; spec.coord_len];
        a_raw[0] = 0x12;
        a_raw[1] = 0x34;
        let a = f.from_be(&a_raw);
        let p_minus_1 = f.sub(&f.zero(), &one_int); // 0 - 1 ≡ m - 1
        assert!(f.is_zero(&f.add(&p_minus_1, &one_int)), "p-1+1 == 0");
        assert!(f.is_zero(&f.sub(&p_minus_1, &p_minus_1)), "x-x == 0");
        assert!(
            f.eq(&f.mul(&p_minus_1, &p_minus_1), &one_int),
            "(p-1)^2 == 1"
        );
        let inv = f.inv(&a);
        assert!(f.eq(&f.mul(&a, &inv), &one_int), "a*inv(a) == 1");
    }

    /// BigInt modular math for the P-521 group order, cross-checked
    /// against an independent Python computation (w = s^-1 mod n).
    #[test]
    fn bigint_p521_modmath() {
        let spec = p521_spec();
        let n = BigInt::from_le_limbs(&spec.n);
        let s = BigInt::from_be_bytes(&hex(
            "007646d44dc1fd2148a569564195424c61566777f712d7ce40c45d68a3fbeb91a97ccbba92e66272c41d487bad0296635fc512661ecc18f41ef8fd053f683a0fab67",
        ));
        let n_minus_2 = n.sub(&BigInt::from_u64(2));
        let w = s.mod_pow(&n_minus_2, &n);
        let expected_w = BigInt::from_be_bytes(&hex(
            "fd9157b7ae1b00c51db943e38a0935e798950c3cb0dedc09984351ead520857bfa2e6efe5361d129cf76f9ffed4e41db72206c1dc63c148a110ea304f005bf722b",
        ));
        assert_eq!(
            w.cmp(&expected_w),
            core::cmp::Ordering::Equal,
            "w = s^-1 mod n wrong: got={}",
            to_hex(&w.to_be_bytes_padded(66))
        );
        // w*s mod n == 1.
        assert_eq!(
            w.mul(&s).rem(&n).cmp(&BigInt::from_u64(1)),
            core::cmp::Ordering::Equal,
            "w*s != 1 mod n"
        );
    }

    /// The BE→LE conversion must right-align short encodings (P-521
    /// coordinates are 66 bytes in a 72-byte window).
    #[test]
    fn be_to_le_limbs_right_aligns() {
        // A tiny value in 66 bytes maps to limb 0 only (no top-limb
        // bits), i.e. it is not shifted up.
        let mut v = vec![0u8; 66];
        v[65] = 0x34;
        v[64] = 0x12;
        let limbs = be_to_le_limbs::<9>(&v);
        assert_eq!(limbs[0], 0x1234);
        for i in 1..9 {
            assert_eq!(limbs[i], 0);
        }
        // A full P-521 value (0x01 + 0xFF*65) puts 0x1FF in the top limb.
        let mut p = vec![0xFFu8; 66];
        p[0] = 0x01;
        let lp = be_to_le_limbs::<9>(&p);
        assert_eq!(lp[8], 0x1FF);
        for i in 0..8 {
            assert_eq!(lp[i], u64::MAX);
        }
        // 32-byte full-width value maps to 4 limbs unchanged.
        let mut w = vec![0u8; 32];
        w[0] = 0xAB;
        w[31] = 0x01;
        let l4 = be_to_le_limbs::<4>(&w);
        assert_eq!(l4[3], 0xAB00000000000000);
        assert_eq!(l4[0], 0x01);
    }

    #[test]
    fn p256_group_sanity() {
        check_curve(&p256_spec());
    }

    #[test]
    fn p384_group_sanity() {
        check_curve(&p384_spec());
    }

    #[test]
    fn p521_group_sanity() {
        check_curve(&p521_spec());
    }

    #[test]
    fn ecdsa_p256_rfc6979_vector() {
        // RFC 6979 §A.2.5 "sample" / SHA-256 (P-256).
        let qx = hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
        let qy = hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
        let digest = sha256(b"sample");
        let sig = hex(
            "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716\
             022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        );
        assert!(verify_der(Curve::P256, &qx, &qy, &digest, &sig));
        let mut bad = digest.clone();
        bad[0] ^= 1;
        assert!(!verify_der(Curve::P256, &qx, &qy, &bad, &sig));
    }

    #[test]
    fn ecdsa_roundtrip_all_curves() {
        // Sign then verify with a fresh key on each curve; tampered
        // digests and off-curve keys must fail.
        for curve in [Curve::P256, Curve::P384, Curve::P521] {
            let coord_len = curve.coord_len();
            let msg = format!("courierust roundtrip {:?}", curve);
            let digest = match curve {
                Curve::P256 => sha256(msg.as_bytes()),
                Curve::P384 => sha384(msg.as_bytes()),
                Curve::P521 => sha512(msg.as_bytes()),
            };
            // Deterministic private scalar (fixed for reproducibility).
            let mut d = vec![0u8; coord_len];
            d[coord_len - 1] = 0x01;
            d[coord_len - 2] = 0x02;

            let (r, s) = sign(curve, &d, &digest).expect("sign");
            // Recompute the public key: Q = d·G.
            let q = match curve {
                Curve::P256 => {
                    let spec = p256_spec();
                    let f = MontCtx::new(spec.p, spec.coord_len);
                    let g = base_point(&spec, &f);
                    let q = scalar_mult(&g, &be_to_le_limbs::<4>(&d), &f);
                    (
                        f.to_be(&affine_x(&q, &f).unwrap()),
                        f.to_be(&affine_y(&q, &f).unwrap()),
                    )
                }
                Curve::P384 => {
                    let spec = p384_spec();
                    let f = MontCtx::new(spec.p, spec.coord_len);
                    let g = base_point(&spec, &f);
                    let q = scalar_mult(&g, &be_to_le_limbs::<6>(&d), &f);
                    (
                        f.to_be(&affine_x(&q, &f).unwrap()),
                        f.to_be(&affine_y(&q, &f).unwrap()),
                    )
                }
                Curve::P521 => {
                    let spec = p521_spec();
                    let f = MontCtx::new(spec.p, spec.coord_len);
                    let g = base_point(&spec, &f);
                    let q = scalar_mult(&g, &be_to_le_limbs::<9>(&d), &f);
                    (
                        f.to_be(&affine_x(&q, &f).unwrap()),
                        f.to_be(&affine_y(&q, &f).unwrap()),
                    )
                }
            };
            let der = encode_sig(&r, &s);
            assert!(
                verify_der(curve, &q.0, &q.1, &digest, &der),
                "roundtrip {:?}",
                curve
            );
            let mut bad = digest.clone();
            bad[0] ^= 1;
            assert!(
                !verify_der(curve, &q.0, &q.1, &bad, &der),
                "tampered digest"
            );

            // Off-curve public key must fail.
            let mut qy_bad = q.1.clone();
            qy_bad[0] ^= 1;
            assert!(
                !verify_der(curve, &q.0, &qy_bad, &digest, &der),
                "off-curve key"
            );
        }
    }

    fn encode_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        fn enc_int(v: &[u8]) -> Vec<u8> {
            let mut body = v.to_vec();
            while body.len() > 1 && body[0] == 0 {
                body.remove(0);
            }
            if body[0] & 0x80 != 0 {
                body.insert(0, 0);
            }
            let mut out = Vec::with_capacity(2 + body.len());
            out.push(0x02);
            out.push(body.len() as u8);
            out.extend_from_slice(&body);
            out
        }
        let r_der = enc_int(r);
        let s_der = enc_int(s);
        let body_len = r_der.len() + s_der.len();
        let mut out = Vec::with_capacity(4 + body_len);
        out.push(0x30);
        if body_len < 128 {
            out.push(body_len as u8);
        } else {
            out.push(0x81);
            out.push(body_len as u8);
        }
        out.extend_from_slice(&r_der);
        out.extend_from_slice(&s_der);
        out
    }

    #[test]
    fn ecdhe_roundtrip() {
        let (a, point_a) = ecdhe_generate(None).unwrap();
        let (b, point_b) = ecdhe_generate(None).unwrap();
        let s1 = ecdhe_shared(&a, &point_b).unwrap();
        let s2 = ecdhe_shared(&b, &point_a).unwrap();
        assert_eq!(s1, s2);
        // A point not on the curve must be rejected.
        let mut bad = point_b;
        bad[10] ^= 1;
        assert!(ecdhe_shared(&a, &bad).is_none());
    }
}
