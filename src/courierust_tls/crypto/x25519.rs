//! X25519 Diffie-Hellman (RFC 7748).
//!
//! Field arithmetic follows curve25519-donna (5×51-bit limbs in `u64`,
//! products in `u128`), with the exact add/sub/mul/square structure of
//! that implementation: add/sub are raw limb-wise (subtraction uses a
//! 2^54 bias so limbs never go negative), and multiply/square fully
//! mask every output limb so bounds are preserved across arbitrarily
//! long chains (including the hundreds of squarings inside the
//! inversion). All operations are constant-time.
//!
//! The Montgomery ladder is the standard RFC 7748 §5 algorithm with
//! a24 = 121665.

/// A field element mod 2^255 - 19 (5 limbs of 51 bits).
pub type Fe = [u64; 5];

const MASK51: u64 = (1 << 51) - 1;

/// The additive identity (0).
pub const ZERO: Fe = [0, 0, 0, 0, 0];
/// The multiplicative identity (1).
pub const ONE: Fe = [1, 0, 0, 0, 0];
/// a24 = (A - 2) / 4 for Curve25519 (A = 486662).
const A24: Fe = [121665, 0, 0, 0, 0];

#[inline]
fn load64(b: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&b[..8]);
    u64::from_le_bytes(out)
}

/// Add two field elements (raw limb-wise; carries are absorbed by the
/// next multiply/square, exactly as in curve25519-donna).
pub fn fe_add(f: Fe, g: Fe) -> Fe {
    [
        f[0] + g[0],
        f[1] + g[1],
        f[2] + g[2],
        f[3] + g[3],
        f[4] + g[4],
    ]
}

/// Two-to-the-54-minus-152 bias for limb 0 of subtraction.
const TWO54M152: u64 = (1 << 54) - 152;
/// Two-to-the-54-minus-8 bias for limbs 1..4 of subtraction.
const TWO54M8: u64 = (1 << 54) - 8;

/// Subtract two field elements (raw limb-wise with a 2^54 bias so the
/// result is never negative; carries are absorbed by the next
/// multiply/square, exactly as in curve25519-donna).
pub fn fe_sub(f: Fe, g: Fe) -> Fe {
    [
        f[0].wrapping_add(TWO54M152).wrapping_sub(g[0]),
        f[1].wrapping_add(TWO54M8).wrapping_sub(g[1]),
        f[2].wrapping_add(TWO54M8).wrapping_sub(g[2]),
        f[3].wrapping_add(TWO54M8).wrapping_sub(g[3]),
        f[4].wrapping_add(TWO54M8).wrapping_sub(g[4]),
    ]
}

/// Multiply two field elements.
///
/// Uses the curve25519-donna-c64 formulation: the high limbs of `g`
/// are pre-multiplied by 19 (since 2^255 ≡ 19 mod 2^255-19), the five
/// partial products are accumulated in `u128`, and every output limb is
/// masked to 51 bits. This keeps all limbs bounded across arbitrarily
/// long chains of multiplications/squarings.
pub fn fe_mul(f: Fe, g: Fe) -> Fe {
    let (a0, a1, a2, a3, a4) = (f[0], f[1], f[2], f[3], f[4]);
    let (b0, b1, b2, b3, b4) = (g[0], g[1], g[2], g[3], g[4]);

    let b1_19 = b1 * 19;
    let b2_19 = b2 * 19;
    let b3_19 = b3 * 19;
    let b4_19 = b4 * 19;

    let t0 = a0 as u128 * b0 as u128
        + a1 as u128 * b4_19 as u128
        + a2 as u128 * b3_19 as u128
        + a3 as u128 * b2_19 as u128
        + a4 as u128 * b1_19 as u128;
    let mut t1 = a0 as u128 * b1 as u128
        + a1 as u128 * b0 as u128
        + a2 as u128 * b4_19 as u128
        + a3 as u128 * b3_19 as u128
        + a4 as u128 * b2_19 as u128;
    let mut t2 = a0 as u128 * b2 as u128
        + a1 as u128 * b1 as u128
        + a2 as u128 * b0 as u128
        + a3 as u128 * b4_19 as u128
        + a4 as u128 * b3_19 as u128;
    let mut t3 = a0 as u128 * b3 as u128
        + a1 as u128 * b2 as u128
        + a2 as u128 * b1 as u128
        + a3 as u128 * b0 as u128
        + a4 as u128 * b4_19 as u128;
    let mut t4 = a0 as u128 * b4 as u128
        + a1 as u128 * b3 as u128
        + a2 as u128 * b2 as u128
        + a3 as u128 * b1 as u128
        + a4 as u128 * b0 as u128;

    // The carry is kept in u128 end-to-end: with the 2^54 subtraction
    // bias the input limbs can reach ~2^54, which makes the final
    // `c * 19` fold exceed u64. u128 holds it safely and the outputs
    // stay masked to 51 bits.
    let mut c: u128;
    let r0 = (t0 as u64) & MASK51;
    c = t0 >> 51;
    t1 += c;
    let r1 = (t1 as u64) & MASK51;
    c = t1 >> 51;
    t2 += c;
    let r2 = (t2 as u64) & MASK51;
    c = t2 >> 51;
    t3 += c;
    let r3 = (t3 as u64) & MASK51;
    c = t3 >> 51;
    t4 += c;
    let r4 = (t4 as u64) & MASK51;
    c = t4 >> 51;
    let folded = r0 as u128 + c * 19;
    let r0 = (folded as u64) & MASK51;
    let r1 = r1 + (folded >> 51) as u64;
    [r0, r1, r2, r3, r4]
}

/// Square a field element.
pub fn fe_sq(f: Fe) -> Fe {
    fe_mul(f, f)
}

/// Square `a` `n` times (donna `square_times`), used by the inversion
/// chain. Each squaring keeps all limbs bounded below 2^51 + small, so
/// arbitrarily long chains are safe.
pub fn fe_sq_times(a: Fe, n: u32) -> Fe {
    let (mut r0, mut r1, mut r2, mut r3, mut r4) = (a[0], a[1], a[2], a[3], a[4]);
    for _ in 0..n {
        let d0 = r0 * 2;
        let d1 = r1 * 2;
        let d2 = r2 * 2 * 19;
        let d419 = r4 * 19;
        let d4 = d419 * 2;

        let t0 = r0 as u128 * r0 as u128 + d4 as u128 * r1 as u128 + d2 as u128 * r3 as u128;
        let mut t1 =
            d0 as u128 * r1 as u128 + d4 as u128 * r2 as u128 + (r3 as u128) * (r3 as u128 * 19);
        let mut t2 = d0 as u128 * r2 as u128 + r1 as u128 * r1 as u128 + d4 as u128 * r3 as u128;
        let mut t3 = d0 as u128 * r3 as u128 + d1 as u128 * r2 as u128 + r4 as u128 * d419 as u128;
        let mut t4 = d0 as u128 * r4 as u128 + d1 as u128 * r3 as u128 + r2 as u128 * r2 as u128;

        let mut c: u128;
        r0 = (t0 as u64) & MASK51;
        c = t0 >> 51;
        t1 += c;
        r1 = (t1 as u64) & MASK51;
        c = t1 >> 51;
        t2 += c;
        r2 = (t2 as u64) & MASK51;
        c = t2 >> 51;
        t3 += c;
        r3 = (t3 as u64) & MASK51;
        c = t3 >> 51;
        t4 += c;
        r4 = (t4 as u64) & MASK51;
        c = t4 >> 51;
        let folded = r0 as u128 + c * 19;
        r0 = (folded as u64) & MASK51;
        r1 += (folded >> 51) as u64;
    }
    [r0, r1, r2, r3, r4]
}

/// Constant-time conditional swap of two field elements.
pub fn fe_cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap & 1);
    for i in 0..5 {
        let dummy = mask & (a[i] ^ b[i]);
        a[i] ^= dummy;
        b[i] ^= dummy;
    }
}

/// Invert a field element: `z^(2^255 - 21)` via the standard addition
/// chain (Fermat's little theorem).
pub fn fe_invert(z: Fe) -> Fe {
    let mut t0 = fe_sq(z);
    let mut t1 = fe_sq(t0);
    t1 = fe_sq(t1);
    t1 = fe_mul(z, t1);
    t0 = fe_mul(t0, t1);
    let mut t2 = fe_sq(t0);
    t1 = fe_mul(t1, t2);
    t2 = fe_sq_times(t1, 5);
    t1 = fe_mul(t2, t1);
    t2 = fe_sq_times(t1, 10);
    t2 = fe_mul(t2, t1);
    let mut t3 = fe_sq_times(t2, 20);
    t2 = fe_mul(t3, t2);
    t2 = fe_sq_times(t2, 10);
    t1 = fe_mul(t2, t1);
    t2 = fe_sq_times(t1, 50);
    t2 = fe_mul(t2, t1);
    t3 = fe_sq_times(t2, 100);
    t2 = fe_mul(t3, t2);
    t2 = fe_sq_times(t2, 50);
    t1 = fe_mul(t2, t1);
    t1 = fe_sq_times(t1, 5);
    fe_mul(t1, t0)
}

/// Decode 32 bytes into a field element (masks the high bit).
pub fn fe_frombytes(bytes: &[u8; 32]) -> Fe {
    let mut mask = *bytes;
    mask[31] &= 0x7f;
    let mut h = [
        load64(&mask[0..8]) & MASK51,
        (load64(&mask[6..14]) >> 3) & MASK51,
        (load64(&mask[12..20]) >> 6) & MASK51,
        (load64(&mask[19..27]) >> 1) & MASK51,
        (load64(&mask[24..32]) >> 12) & MASK51,
    ];

    // Carry and reduce mod p.
    let mut c = h[0] >> 51;
    h[0] &= MASK51;
    h[1] += c;
    c = h[1] >> 51;
    h[1] &= MASK51;
    h[2] += c;
    c = h[2] >> 51;
    h[2] &= MASK51;
    h[3] += c;
    c = h[3] >> 51;
    h[3] &= MASK51;
    h[4] += c;
    c = h[4] >> 51;
    h[4] &= MASK51;
    h[0] += c * 19;
    c = h[0] >> 51;
    h[0] &= MASK51;
    h[1] += c;
    h[1] &= MASK51;

    // Canonicalize: h -= p if h >= p.
    let mut g0 = h[0] + 19;
    c = g0 >> 51;
    g0 &= MASK51;
    let mut g1 = h[1] + c;
    c = g1 >> 51;
    g1 &= MASK51;
    let mut g2 = h[2] + c;
    c = g2 >> 51;
    g2 &= MASK51;
    let mut g3 = h[3] + c;
    c = g3 >> 51;
    g3 &= MASK51;
    let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 51);

    let mask = (g4 >> 63).wrapping_sub(1); // 0 if g4 < 0 (h < p), else all-ones
    let inv = !mask;
    [
        (h[0] & inv) | (g0 & mask),
        (h[1] & inv) | (g1 & mask),
        (h[2] & inv) | (g2 & mask),
        (h[3] & inv) | (g3 & mask),
        (h[4] & inv) | (g4 & mask),
    ]
}

/// Encode a field element into 32 bytes (fully carried and
/// canonicalized mod p).
pub fn fe_tobytes(f: Fe) -> [u8; 32] {
    let mut h = f;
    // Full carry with the 2^255 ≡ 19 fold.
    let mut c = h[0] >> 51;
    h[0] &= MASK51;
    h[1] += c;
    c = h[1] >> 51;
    h[1] &= MASK51;
    h[2] += c;
    c = h[2] >> 51;
    h[2] &= MASK51;
    h[3] += c;
    c = h[3] >> 51;
    h[3] &= MASK51;
    h[4] += c;
    c = h[4] >> 51;
    h[4] &= MASK51;
    h[0] += c * 19;
    c = h[0] >> 51;
    h[0] &= MASK51;
    h[1] += c;

    // Canonicalize: h -= p if h >= p (p = 2^255 - 19).
    let mut g0 = h[0] + 19;
    c = g0 >> 51;
    g0 &= MASK51;
    let mut g1 = h[1] + c;
    c = g1 >> 51;
    g1 &= MASK51;
    let mut g2 = h[2] + c;
    c = g2 >> 51;
    g2 &= MASK51;
    let mut g3 = h[3] + c;
    c = g3 >> 51;
    g3 &= MASK51;
    let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 51);

    let mask = (g4 >> 63).wrapping_sub(1); // 0 if g4 < 0 (h < p), else all-ones
    let inv = !mask;
    let h0 = (h[0] & inv) | (g0 & mask);
    let h1 = (h[1] & inv) | (g1 & mask);
    let h2 = (h[2] & inv) | (g2 & mask);
    let h3 = (h[3] & inv) | (g3 & mask);
    let h4 = (h[4] & inv) | (g4 & mask);

    let mut out = [0u8; 32];
    // 5 limbs → 32 bytes little-endian.
    let limbs = [
        h0 | (h1 << 51),
        (h1 >> 13) | (h2 << 38),
        (h2 >> 26) | (h3 << 25),
        (h3 >> 39) | (h4 << 12),
    ];
    for (i, limb) in limbs.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    // h4 < 2^51 after canonicalization, so bit 255 is clear.
    out[31] &= 0x7f;
    out
}

/// X25519 scalar multiplication: `k * u` on the Montgomery curve.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    // Clamp the scalar (RFC 7748 §5).
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = fe_frombytes(u);
    let mut x2 = ONE;
    let mut z2 = ZERO;
    let mut x3 = x1;
    let mut z3 = ONE;
    let mut swap = 0u64;

    for t in (0..255).rev() {
        let k_t = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= k_t;
        fe_cswap(swap, &mut x2, &mut x3);
        fe_cswap(swap, &mut z2, &mut z3);
        swap = k_t;

        let a = fe_add(x2, z2);
        let aa = fe_sq(a);
        let b = fe_sub(x2, z2);
        let bb = fe_sq(b);
        let e = fe_sub(aa, bb);
        let c = fe_add(x3, z3);
        let d = fe_sub(x3, z3);
        let da = fe_mul(d, a);
        let cb = fe_mul(c, b);
        x3 = fe_sq(fe_add(da, cb));
        z3 = fe_mul(x1, fe_sq(fe_sub(da, cb)));
        x2 = fe_mul(aa, bb);
        z2 = fe_mul(e, fe_add(aa, fe_mul(A24, e)));
    }
    fe_cswap(swap, &mut x2, &mut x3);
    fe_cswap(swap, &mut z2, &mut z3);

    let z_inv = fe_invert(z2);
    let result = fe_mul(x2, z_inv);
    fe_tobytes(result)
}

/// Generate a fresh X25519 key pair.
pub fn keypair(rng: &mut impl FnMut(&mut [u8])) -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    rng(&mut secret);
    let public = x25519(
        &secret,
        &[
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
    );
    (secret, public)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn x25519_rfc7748_vector_1() {
        let scalar =
            hex_to_bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex_to_bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected =
            hex_to_bytes("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        let mut s = [0u8; 32];
        let mut uu = [0u8; 32];
        s.copy_from_slice(&scalar);
        uu.copy_from_slice(&u);
        assert_eq!(&x25519(&s, &uu)[..], &expected[..]);
    }

    #[test]
    fn x25519_rfc7748_vector_2() {
        let scalar =
            hex_to_bytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = hex_to_bytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected =
            hex_to_bytes("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        let mut s = [0u8; 32];
        let mut uu = [0u8; 32];
        s.copy_from_slice(&scalar);
        uu.copy_from_slice(&u);
        assert_eq!(&x25519(&s, &uu)[..], &expected[..]);
    }

    #[test]
    fn x25519_rfc7748_iterated() {
        // RFC 7748 §5.2 iterative scalar multiplication (1 iteration).
        let k = hex_to_bytes("0900000000000000000000000000000000000000000000000000000000000000");
        let mut s = [0u8; 32];
        s.copy_from_slice(&k);
        let out = x25519(&s, &s);
        let expected_1 =
            hex_to_bytes("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        assert_eq!(&out[..], &expected_1[..]);
    }

    #[test]
    fn x25519_roundtrip() {
        let mut rng_state = [0x5au8; 32];
        let mut rng = |out: &mut [u8]| {
            for b in out.iter_mut() {
                *b = rng_state[0];
                rng_state.rotate_left(1);
            }
        };
        let (sk_a, pk_a) = keypair(&mut rng);
        let (sk_b, pk_b) = keypair(&mut rng);
        let shared_a = x25519(&sk_a, &pk_b);
        let shared_b = x25519(&sk_b, &pk_a);
        assert_eq!(shared_a, shared_b);
        assert_ne!(shared_a, [0u8; 32]);
    }

    #[test]
    fn fe_arithmetic_basic() {
        let a = fe_frombytes(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let b = fe_frombytes(&[
            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ]);
        // (a + b) - b == a
        let sum = fe_add(a, b);
        let back = fe_sub(sum, b);
        assert_eq!(fe_tobytes(back).as_slice(), fe_tobytes(a).as_slice());
        // a * 1 == a
        let mul1 = fe_mul(a, ONE);
        assert_eq!(fe_tobytes(mul1).as_slice(), fe_tobytes(a).as_slice());
        // a * a^-1 == 1
        let inv = fe_invert(a);
        let product = fe_mul(a, inv);
        assert_eq!(fe_tobytes(product).as_slice(), fe_tobytes(ONE).as_slice());
        // round-trip frombytes/tobytes
        assert_eq!(
            fe_tobytes(a).as_slice(),
            fe_tobytes(fe_frombytes(&fe_tobytes(a))).as_slice()
        );
    }
}
