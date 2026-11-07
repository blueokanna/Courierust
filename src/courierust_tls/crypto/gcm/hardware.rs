//! Carry-less field multiplication; NIST SP 800-38D section 6.3.
//!
//! No secret-indexed lookup tables or data-dependent reduction branches.
//! The portable multiplier remains the reference and runtime fallback.
#![allow(unsafe_code)]

use core::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128, _mm_xor_si128,
};

pub(super) fn available() -> bool {
    std::is_x86_feature_detected!("pclmulqdq")
}

pub(super) fn multiply(a: u128, b: u128) -> u128 {
    if !available() {
        return super::gf_mul(a, b);
    }
    unsafe { product(a, b) }
}

#[target_feature(enable = "pclmulqdq")]
unsafe fn product(a: u128, b: u128) -> u128 {
    let a = a.reverse_bits();
    let b = b.reverse_bits();
    let av = _mm_set_epi64x((a >> 64) as i64, a as i64);
    let bv = _mm_set_epi64x((b >> 64) as i64, b as i64);
    let low = _mm_clmulepi64_si128::<0x00>(av, bv);
    let high = _mm_clmulepi64_si128::<0x11>(av, bv);
    let cross = _mm_xor_si128(
        _mm_clmulepi64_si128::<0x01>(av, bv),
        _mm_clmulepi64_si128::<0x10>(av, bv),
    );
    let mut lo = [0u64; 2];
    let mut hi = [0u64; 2];
    let mut middle = [0u64; 2];
    _mm_storeu_si128(lo.as_mut_ptr().cast::<__m128i>(), low);
    _mm_storeu_si128(hi.as_mut_ptr().cast::<__m128i>(), high);
    _mm_storeu_si128(middle.as_mut_ptr().cast::<__m128i>(), cross);
    let low = u128::from(lo[0]) | (u128::from(lo[1] ^ middle[0]) << 64);
    let high = u128::from(hi[0] ^ middle[1]) | (u128::from(hi[1]) << 64);
    let overflow = (high >> 127) ^ (high >> 126) ^ (high >> 121);
    let reduced = low
        ^ high
        ^ (high << 1)
        ^ (high << 2)
        ^ (high << 7)
        ^ overflow
        ^ (overflow << 1)
        ^ (overflow << 2)
        ^ (overflow << 7);
    reduced.reverse_bits()
}
