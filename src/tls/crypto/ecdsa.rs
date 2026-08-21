//! ECDSA P-256 signature verification (SEC 1 / FIPS 186-4) and
//! deterministic signing (RFC 6979).
//!
//! The field arithmetic uses the special form of the P-256 prime
//! p = 2^256 - 2^224 + 2^192 + 2^96 - 1 to fold 512-bit products back
//! into 4×64-bit limbs. Point arithmetic is in Jacobian coordinates with
//! a = -3. Signatures are DER-encoded `ECDSA-Sig-Value` (as used by
//! TLS 1.3 CertificateVerify).

use super::hash::Sha256;
use super::rsa::BigInt;
use alloc::vec::Vec;

/// P-256 field modulus (little-endian limbs).
///
/// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
///   = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
const P: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0,
    0xffff_ffff_0000_0001,
];

/// P-256 group order.
const N: [u64; 4] = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];

/// Base point Gx as four big-endian 8-byte chunks (MSB chunk first).
const GX: [u64; 4] = [
    0x6b17_d1f2_e12c_4247,
    0xf8bc_e6e5_63a4_40f2,
    0x7703_7d81_2deb_33a0,
    0xf4a1_3945_d898_c296,
];

/// Base point Gy as four big-endian 8-byte chunks (MSB chunk first).
const GY: [u64; 4] = [
    0x4fe3_42e2_fe1a_7f9b,
    0x8ee7_eb4a_7c0f_9e16,
    0x2bce_3357_6b31_5ece,
    0xcbb6_4068_37bf_51f5,
];

/// Curve coefficient b (big-endian chunks).
const B: [u64; 4] = [
    0x5ac6_35d8_aa3a_93e7,
    0xb3eb_bd55_7698_86bc,
    0x651d_06b0_cc53_b0f6,
    0x3bce_3c3e_27d2_604b,
];

/// A field element mod p (4×64-bit limbs, little-endian, fully reduced).
type Fe = [u64; 4];

const FE_ZERO: Fe = [0; 4];
const FE_ONE: Fe = [1, 0, 0, 0];

#[inline]
fn cmp4(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    core::cmp::Ordering::Equal
}

/// Add two field elements (result reduced mod p).
fn fe_add(a: Fe, b: Fe) -> Fe {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        r[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    // r < 2p; subtract p once if needed.
    if carry != 0 || cmp4(&r, &P) != core::cmp::Ordering::Less {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (s1, b1) = r[i].overflowing_sub(P[i]);
            let (s2, b2) = s1.overflowing_sub(borrow);
            r[i] = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }
    r
}

/// Subtract two field elements (result reduced mod p).
fn fe_sub(a: Fe, b: Fe) -> Fe {
    // a - b mod p = a + (p - b) mod p
    let mut neg = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (s1, b1) = P[i].overflowing_sub(b[i]);
        let (s2, b2) = s1.overflowing_sub(borrow);
        neg[i] = s2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    fe_add(a, neg)
}

/// Multiply two field elements, reducing the 512-bit product mod p using
/// the special form of the P-256 prime.
fn fe_mul(a: Fe, b: Fe) -> Fe {
    // Schoolbook product → 8 limbs.
    let mut t = [0u64; 8];
    for (i, &ai) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &bj) in b.iter().enumerate() {
            let cur = t[i + j] as u128 + (ai as u128) * (bj as u128) + carry;
            t[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 4;
        while carry != 0 {
            let cur = t[k] as u128 + carry;
            t[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }
    reduce8(t)
}

/// Reduce an 8-limb value (≤ 2^512) mod p by folding high limbs with
/// 2^256 ≡ 2^224 - 2^192 - 2^96 + 1 (mod p).
fn reduce8(mut t: [u64; 8]) -> Fe {
    // c = 2^224 - 2^192 - 2^96 + 1 = 2^256 - p, as 4 LE limbs.
    const C: [u64; 4] = [
        1,
        0xffff_ffff_0000_0000,
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_fffe,
    ];
    for _ in 0..16 {
        let hi = [t[4], t[5], t[6], t[7]];
        if hi == [0; 4] {
            break;
        }
        let lo = [t[0], t[1], t[2], t[3]];
        // prod = hi * c (8 limbs).
        let mut prod = [0u64; 8];
        for (i, &hi_i) in hi.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &cj) in C.iter().enumerate() {
                let cur = prod[i + j] as u128 + (hi_i as u128) * (cj as u128) + carry;
                prod[i + j] = cur as u64;
                carry = cur >> 64;
            }
            let mut k = i + 4;
            while carry != 0 {
                let cur = prod[k] as u128 + carry;
                prod[k] = cur as u64;
                carry = cur >> 64;
                k += 1;
            }
        }
        // sum = lo + prod. After the first fold, prod < 2^480 and
        // lo < 2^256, so sum < 2^481: no limb beyond 8 is ever set.
        let mut carry = 0u64;
        for i in 0..8 {
            let a = if i < 4 { lo[i] } else { 0 };
            let (s1, c1) = a.overflowing_add(prod[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            t[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        debug_assert_eq!(carry, 0);
    }
    let mut out = [t[0], t[1], t[2], t[3]];
    // r < 2^256 < 2p: at most one subtraction.
    if cmp4(&out, &P) != core::cmp::Ordering::Less {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (s1, b1) = out[i].overflowing_sub(P[i]);
            let (s2, b2) = s1.overflowing_sub(borrow);
            out[i] = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }
    out
}

/// Square a field element.
fn fe_sq(a: Fe) -> Fe {
    fe_mul(a, a)
}

/// Field exponentiation `a^e mod p` with a 256-bit little-endian exponent.
fn fe_pow(a: Fe, e: &[u64; 4]) -> Fe {
    let mut result = FE_ONE;
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

/// Field inverse via Fermat: a^(p-2) mod p.
fn fe_inv(a: Fe) -> Fe {
    // p - 2 (verified against the P-256 prime).
    let exp: [u64; 4] = [
        0xffff_ffff_ffff_fffd,
        0x0000_0000_ffff_ffff,
        0,
        0xffff_ffff_0000_0001,
    ];
    fe_pow(a, &exp)
}

/// A point in Jacobian coordinates (X:Y:Z); Z = 0 is the point at
/// infinity.
#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Point {
    fn infinity() -> Self {
        Self {
            x: FE_ONE,
            y: FE_ONE,
            z: FE_ZERO,
        }
    }

    fn is_infinity(&self) -> bool {
        self.z == FE_ZERO
    }
}

/// Jacobian doubling for a = -3.
fn point_double(p: Point) -> Point {
    if p.is_infinity() {
        return p;
    }
    let a = fe_sq(p.x);
    let b = fe_sq(p.y);
    let c = fe_sq(b);
    // d = 2·((X+B)² - A - C) = 4·X·Y²
    let e = fe_sub(fe_sub(fe_sq(fe_add(p.x, b)), a), c);
    let d = fe_add(e, e);
    // E = 3·A + a·Z^4 with a = -3: 3·(A - Z^4).
    let z1_2 = fe_sq(p.z);
    let z1_4 = fe_sq(z1_2);
    let three_a = fe_sub(fe_add(fe_add(a, a), a), fe_add(fe_add(z1_4, z1_4), z1_4));
    let f = fe_sq(three_a);
    let x3 = fe_sub(f, fe_add(d, d));
    let mut c8 = fe_add(c, c);
    c8 = fe_add(c8, c8);
    c8 = fe_add(c8, c8); // 8C
    let y3 = fe_sub(fe_mul(three_a, fe_sub(d, x3)), c8);
    let z3 = fe_mul(fe_add(p.y, p.y), p.z);
    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// General Jacobian addition (a = -3).
fn point_add(p: Point, q: Point) -> Point {
    if p.is_infinity() {
        return q;
    }
    if q.is_infinity() {
        return p;
    }
    let z1z1 = fe_sq(p.z);
    let z2z2 = fe_sq(q.z);
    let u1 = fe_mul(p.x, z2z2);
    let u2 = fe_mul(q.x, z1z1);
    let s1 = fe_mul(p.y, fe_mul(z2z2, q.z));
    let s2 = fe_mul(q.y, fe_mul(z1z1, p.z));
    if u1 == u2 {
        if s1 == s2 {
            return point_double(p);
        }
        return Point::infinity();
    }
    let h = fe_sub(u2, u1);
    let r = fe_sub(s2, s1);
    let h2 = fe_sq(h);
    let h3 = fe_mul(h2, h);
    let u1h2 = fe_mul(u1, h2);
    let x3 = fe_sub(fe_sub(fe_sq(r), h3), fe_add(u1h2, u1h2));
    let y3 = fe_sub(fe_mul(r, fe_sub(u1h2, x3)), fe_mul(s1, h3));
    let z3 = fe_mul(fe_mul(h, p.z), q.z);
    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Scalar multiplication (double-and-add, MSB first). `scalar` is a
/// 256-bit little-endian value.
fn scalar_mult(p: Point, scalar: &[u64; 4]) -> Point {
    let mut result = Point::infinity();
    for word in scalar.iter().rev() {
        for bit in (0..64).rev() {
            result = point_double(result);
            if (*word >> bit) & 1 == 1 {
                result = point_add(result, p);
            }
        }
    }
    result
}

/// Convert to affine and return the x coordinate (or None at infinity).
fn affine_x(p: Point) -> Option<Fe> {
    if p.is_infinity() {
        return None;
    }
    let z_inv = fe_inv(p.z);
    let z_inv2 = fe_sq(z_inv);
    Some(fe_mul(p.x, z_inv2))
}

/// Verify an ECDSA P-256 signature over `digest` (32 bytes) with the
/// public key `(qx, qy)` (32 bytes each). The signature is a DER
/// `ECDSA-Sig-Value`.
pub fn verify_der(qx: &[u8; 32], qy: &[u8; 32], digest: &[u8], der: &[u8]) -> bool {
    let (r, s) = match parse_der_signature(der) {
        Some(sig) => sig,
        None => return false,
    };
    verify_raw(qx, qy, digest, &r, &s)
}

/// Verify with raw `(r, s)` as 32-byte big-endian integers.
pub fn verify_raw(qx: &[u8; 32], qy: &[u8; 32], digest: &[u8], r: &[u8; 32], s: &[u8; 32]) -> bool {
    if digest.len() < 32 {
        return false;
    }
    let n = BigInt::from_be_bytes(&be_u64_4(&N));
    let one = BigInt::from_u64(1);
    let r_int = BigInt::from_be_bytes(r);
    let s_int = BigInt::from_be_bytes(s);
    // r, s in [1, n-1].
    if r_int.cmp(&one) == core::cmp::Ordering::Less
        || r_int.cmp(&n) != core::cmp::Ordering::Less
        || s_int.cmp(&one) == core::cmp::Ordering::Less
        || s_int.cmp(&n) != core::cmp::Ordering::Less
    {
        return false;
    }
    // e = leftmost 256 bits of the digest.
    let e = &digest[..32];

    // The public key must be a valid point on the curve.
    let qx_fe = from_be_bytes_fe(qx);
    let qy_fe = from_be_bytes_fe(qy);
    if !on_curve_affine(qx_fe, qy_fe) {
        return false;
    }

    // w = s^-1 mod n; u1 = e·w mod n; u2 = r·w mod n.
    let n_minus_2 = n.sub(&BigInt::from_u64(2));
    let w = s_int.mod_pow(&n_minus_2, &n);
    let e_int = BigInt::from_be_bytes(e);
    let u1 = e_int.mul(&w).rem(&n);
    let u2 = r_int.mul(&w).rem(&n);

    let g = Point {
        x: from_be(GX),
        y: from_be(GY),
        z: FE_ONE,
    };
    let q = Point {
        x: qx_fe,
        y: qy_fe,
        z: FE_ONE,
    };
    let x1 = scalar_mult(g, &limbs_of(&u1));
    let x2 = scalar_mult(q, &limbs_of(&u2));
    let xsum = point_add(x1, x2);
    let x_coord = match affine_x(xsum) {
        Some(x) => x,
        None => return false,
    };
    // v = x(X) mod n
    let v = BigInt::from_be_bytes(&be(x_coord)).rem(&n);
    v == r_int
}

/// ECDSA P-256 signing (RFC 6979 §3.2 style): returns `(r, s)` as
/// 32-byte big-endian values. `d` is the 32-byte private scalar and
/// `digest` the 32-byte message digest.
pub(crate) fn sign(d: &[u8; 32], digest: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
    let n = BigInt::from_le_limbs(&N);
    let one = BigInt::from_u64(1);
    let d_int = BigInt::from_be_bytes(d);
    if d_int.cmp(&one) == core::cmp::Ordering::Less || d_int.cmp(&n) != core::cmp::Ordering::Less {
        return None;
    }
    let e_int = BigInt::from_be_bytes(digest).rem(&n);
    let n_minus_2 = n.sub(&BigInt::from_u64(2));

    // Deterministic k (RFC 6979 §3.2) so signing is reproducible and
    // there is no dependency on an RNG for the nonce.
    let k = rfc6979_nonce(d, digest, &n);
    let k_int = BigInt::from_le_limbs(&k);

    // (x1, y1) = k·G
    let g = Point {
        x: from_be(GX),
        y: from_be(GY),
        z: FE_ONE,
    };
    let kg = scalar_mult(g, &k);
    let x1 = affine_x(kg)?;
    let r = BigInt::from_be_bytes(&be(x1)).rem(&n);
    if r.is_zero() {
        return None;
    }
    // s = k^-1 (e + r·d) mod n
    let k_inv = k_int.mod_pow(&n_minus_2, &n);
    let rd = r.mul(&d_int).rem(&n);
    let s = k_inv.mul(&e_int.add(&rd).rem(&n)).rem(&n);
    if s.is_zero() {
        return None;
    }
    Some((r.to_be_bytes_padded(32), s.to_be_bytes_padded(32)))
}

/// RFC 6979 §3.2 deterministic nonce: HMAC-SHA256 keyed by the private
/// key with the digest; iterates the candidate chain until k in [1, n-1].
fn rfc6979_nonce(d: &[u8; 32], digest: &[u8; 32], n: &BigInt) -> [u64; 4] {
    use super::hmac::hmac;
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];
    // bits2octets(H(m)) — the digest truncated/reduced mod n.
    let h_mod = BigInt::from_be_bytes(digest).rem(n).to_be_bytes_padded(32);

    // K = HMAC(K, V || 0x00 || int2octets(d) || bits2octets(H(m)))
    let mut m0 = Vec::new();
    m0.extend_from_slice(&v);
    m0.push(0x00);
    m0.extend_from_slice(d);
    m0.extend_from_slice(&h_mod);
    let mut sha = Sha256::new();
    k = hmac(&mut sha, &k, &m0).try_into().expect("32 bytes");
    let mut sha = Sha256::new();
    v = hmac(&mut sha, &k, &v).try_into().expect("32 bytes");

    // K = HMAC(K, V || 0x01 || int2octets(d) || bits2octets(H(m)))
    let mut m1 = Vec::new();
    m1.extend_from_slice(&v);
    m1.push(0x01);
    m1.extend_from_slice(d);
    m1.extend_from_slice(&h_mod);
    let mut sha = Sha256::new();
    k = hmac(&mut sha, &k, &m1).try_into().expect("32 bytes");
    let mut sha = Sha256::new();
    v = hmac(&mut sha, &k, &v).try_into().expect("32 bytes");

    loop {
        let mut sha = Sha256::new();
        v = hmac(&mut sha, &k, &v).try_into().expect("32 bytes");
        let cand = BigInt::from_be_bytes(&v);
        if cand.cmp(&BigInt::from_u64(1)) != core::cmp::Ordering::Less
            && cand.cmp(n) == core::cmp::Ordering::Less
        {
            // Convert to LE limbs.
            let bytes = cand.to_be_bytes_padded(32);
            let mut out = [0u64; 4];
            for (i, chunk) in bytes.chunks(8).enumerate() {
                out[3 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
            }
            return out;
        }
        // K = HMAC(K, V || 0x00)
        let mut m2 = Vec::new();
        m2.extend_from_slice(&v);
        m2.push(0x00);
        let mut sha = Sha256::new();
        k = hmac(&mut sha, &k, &m2).try_into().expect("32 bytes");
        let mut sha = Sha256::new();
        v = hmac(&mut sha, &k, &v).try_into().expect("32 bytes");
    }
}

/// On-curve check for an affine point: y² == x³ - 3x + b.
fn on_curve_affine(x: Fe, y: Fe) -> bool {
    let lhs = fe_sq(y);
    let rhs = fe_add(fe_sub(fe_mul(fe_sq(x), x), fe_add(x, fe_add(x, x))), B_FE);
    lhs == rhs
}

const B_FE: Fe = from_be(B);

/// Convert four big-endian 8-byte chunks (MSB first) into LE limbs.
const fn from_be(v: [u64; 4]) -> [u64; 4] {
    [v[3], v[2], v[1], v[0]]
}

/// Big-endian bytes from a field element.
fn be(v: Fe) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    for limb in v.iter().rev() {
        out.extend_from_slice(&limb.to_be_bytes());
    }
    out
}

/// 4 little-endian limbs → big-endian 32-byte string.
fn be_u64_4(v: &[u64; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    for limb in v.iter().rev() {
        out.extend_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Extract the 4×64 limbs (little-endian) from a `BigInt`.
fn limbs_of(v: &BigInt) -> [u64; 4] {
    let bytes = v.to_be_bytes_padded(32);
    let mut out = [0u64; 4];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        out[3 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    out
}

/// 32 big-endian bytes → field element (LE limbs).
fn from_be_bytes_fe(v: &[u8; 32]) -> Fe {
    [
        u64::from_be_bytes(v[24..32].try_into().unwrap()),
        u64::from_be_bytes(v[16..24].try_into().unwrap()),
        u64::from_be_bytes(v[8..16].try_into().unwrap()),
        u64::from_be_bytes(v[0..8].try_into().unwrap()),
    ]
}

/// Parse a DER `ECDSA-Sig-Value`: SEQUENCE { r INTEGER, s INTEGER }.
fn parse_der_signature(der: &[u8]) -> Option<([u8; 32], [u8; 32])> {
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
    // Integers must be positive and at most 32 bytes.
    if r.is_empty() || s.is_empty() || r.len() > 33 || s.len() > 33 {
        return None;
    }
    let mut r32 = [0u8; 32];
    let mut s32 = [0u8; 32];
    let rv = strip_leading_zero(&r);
    let sv = strip_leading_zero(&s);
    if rv.len() > 32 || sv.len() > 32 || rv.is_empty() || sv.is_empty() {
        return None;
    }
    r32[32 - rv.len()..].copy_from_slice(rv);
    s32[32 - sv.len()..].copy_from_slice(sv);
    Some((r32, s32))
}

fn strip_leading_zero(v: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < v.len() && v[i] == 0 {
        i += 1;
    }
    &v[i..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::crypto::hash::Digest;

    fn hex(s: &str) -> Vec<u8> {
        let s = s.replace(' ', "");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn field_reduction_properties() {
        // p - 1 + 1 == 0 mod p.
        let p_minus_1: Fe = [P[0] - 1, P[1], P[2], P[3]];
        let sum = fe_add(p_minus_1, FE_ONE);
        assert_eq!(sum, FE_ZERO);
        // p - 1 - (p - 1) == 0.
        assert_eq!(fe_sub(p_minus_1, p_minus_1), FE_ZERO);
        // (p-1)² mod p == 1.
        assert_eq!(fe_mul(p_minus_1, p_minus_1), FE_ONE);
        // inverse property.
        let a: Fe = [0x1234_5678_9abc_def0, 1, 2, 3];
        let inv = fe_inv(a);
        let prod = fe_mul(a, inv);
        assert_eq!(prod, FE_ONE);
    }

    #[test]
    fn ecdsa_rfc6979_vector() {
        // A well-known ECDSA P-256 test vector (RFC 6979 §A.2.5,
        // SHA-256, k = 0x... first case) — public key and signature.
        let qx = hex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
        let qy = hex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
        let msg = b"sample";
        // Message hash (SHA-256 of "sample").
        let digest = {
            let mut h = crate::tls::crypto::hash::Sha256::new();
            h.update(msg);
            let d = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&d);
            out
        };
        // DER-encoded ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s })
        // for the RFC 6979 §A.2.5 "sample"/SHA-256 vector:
        // r = EFD48B2A...EAF3716, s = F7CB1C94...43ACDA8.
        let sig = hex(
            "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716\
             022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        );
        let mut qx_arr = [0u8; 32];
        let mut qy_arr = [0u8; 32];
        qx_arr.copy_from_slice(&qx);
        qy_arr.copy_from_slice(&qy);
        assert!(verify_der(&qx_arr, &qy_arr, &digest, &sig));

        // Wrong digest must fail.
        let mut bad = digest;
        bad[0] ^= 1;
        assert!(!verify_der(&qx_arr, &qy_arr, &bad, &sig));
    }

    #[test]
    fn base_point_on_curve() {
        let g = Point {
            x: from_be(GX),
            y: from_be(GY),
            z: FE_ONE,
        };
        assert!(on_curve_affine(g.x, g.y));
        // n*G == infinity (order check).
        let ng = scalar_mult(g, &N);
        assert!(ng.is_infinity());
    }
}
