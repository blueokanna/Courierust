//! GCM authenticated encryption (NIST SP 800-38D) with 96-bit nonces,
//! as used by the TLS 1.3 AES-GCM suites.
//!
//! The GF(2^128) multiplication follows the NIST convention: the
//! 128-bit block is a polynomial with the *leftmost* bit as x^127, so
//! the multiply is the shift-right algorithm with reduction
//! R = 11100001 || 0^120 (x^128 + x^7 + x^2 + x + 1).

use super::aes::Aes;
use alloc::vec::Vec;

/// Tag length in bytes (16 for TLS).
pub const TAG_LEN: usize = 16;

/// The GCM reduction constant R = x^128 + x^7 + x^2 + x + 1 (as a
/// 128-bit value with bit 120 = x^127 ... per the NIST representation).
const R: u128 = 0xe1 << 120;

/// Multiply two field elements in the GCM representation (NIST SP
/// 800-38D Algorithm 1). `a` is consumed from its leftmost bit (x^127)
/// down to bit 0 (x^0).
fn gf_mul(a: u128, b: u128) -> u128 {
    let mut z = 0u128;
    let mut v = b;
    for i in (0..128).rev() {
        if (a >> i) & 1 == 1 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb == 1 {
            v ^= R;
        }
    }
    z
}

/// GHASH over AAD and ciphertext, plus the 64-bit length block.
fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut y = 0u128;
    let mut block = [0u8; 16];
    let mut process = |y: &mut u128, data: &[u8]| {
        for chunk in data.chunks(16) {
            block.fill(0);
            block[..chunk.len()].copy_from_slice(chunk);
            *y ^= u128::from_be_bytes(block);
            *y = gf_mul(*y, h);
        }
    };
    process(&mut y, aad);
    process(&mut y, ct);
    let la = (aad.len() as u128) * 8;
    let lc = (ct.len() as u128) * 8;
    y ^= (la << 64) | lc;
    gf_mul(y, h)
}

/// Increment the low 32 bits of a counter block (J0 inc32).
#[inline]
fn inc32(v: u128) -> u128 {
    let low = (v & 0xffff_ffff) as u32;
    (v & !0xffff_ffffu128) | ((low.wrapping_add(1)) as u128)
}

fn cipher_block(aes: &Aes, v: u128) -> u128 {
    let mut block = v.to_be_bytes();
    aes.encrypt_block(&mut block);
    u128::from_be_bytes(block)
}

/// GCM seal. `key` is 16 or 32 bytes; `iv` is 12 bytes.
pub fn seal(key: &[u8], iv: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes::new(key)?;
    let h = cipher_block(&aes, 0);
    // J0 = IV || 0^31 || 1
    let mut j0_bytes = [0u8; 16];
    j0_bytes[..12].copy_from_slice(iv);
    j0_bytes[15] = 1;
    let j0 = u128::from_be_bytes(j0_bytes);

    // GCTR keystream from counter = inc32(J0), inc32 twice, ...
    let mut ct = Vec::with_capacity(plaintext.len());
    let mut counter = inc32(j0);
    for chunk in plaintext.chunks(16) {
        let ks = cipher_block(&aes, counter);
        let ks_bytes = ks.to_be_bytes();
        let mut out = [0u8; 16];
        for (i, b) in chunk.iter().enumerate() {
            out[i] = b ^ ks_bytes[i];
        }
        ct.extend_from_slice(&out[..chunk.len()]);
        counter = inc32(counter);
    }

    let y = ghash(h, aad, &ct);
    let s = cipher_block(&aes, j0);
    let tag = (s ^ y).to_be_bytes();

    let mut sealed = ct;
    sealed.extend_from_slice(&tag);
    Some(sealed)
}

/// GCM open: verify the tag and return the plaintext.
pub fn open(key: &[u8], iv: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < TAG_LEN {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let aes = Aes::new(key)?;
    let h = cipher_block(&aes, 0);
    let mut j0_bytes = [0u8; 16];
    j0_bytes[..12].copy_from_slice(iv);
    j0_bytes[15] = 1;
    let j0 = u128::from_be_bytes(j0_bytes);

    let y = ghash(h, aad, ct);
    let s = cipher_block(&aes, j0);
    let expected = (s ^ y).to_be_bytes();
    if !super::constant_time_eq(&expected, tag) {
        return None;
    }

    let mut pt = Vec::with_capacity(ct.len());
    let mut counter = inc32(j0);
    for chunk in ct.chunks(16) {
        let ks = cipher_block(&aes, counter);
        let ks_bytes = ks.to_be_bytes();
        let mut out = [0u8; 16];
        for (i, b) in chunk.iter().enumerate() {
            out[i] = b ^ ks_bytes[i];
        }
        pt.extend_from_slice(&out[..chunk.len()]);
        counter = inc32(counter);
    }
    Some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn gcm_nist_vector_1() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let sealed = seal(&key, &iv, b"", b"").unwrap();
        assert_eq!(sealed, hex("58e2fccefa7e3061367f1d57a4e7455a"));
        assert_eq!(open(&key, &iv, b"", &sealed).unwrap(), b"");
    }

    #[test]
    fn gcm_nist_vector_2() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let pt = [0u8; 16];
        let sealed = seal(&key, &iv, b"", &pt).unwrap();
        assert_eq!(
            sealed,
            hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
        );
        assert_eq!(open(&key, &iv, b"", &sealed).unwrap(), pt);
    }

    #[test]
    fn gcm_nist_vector_3() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let iv = hex("cafebabefacedbaddecaf888");
        let pt = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let mut k = [0u8; 16];
        k.copy_from_slice(&key);
        let mut ivv = [0u8; 12];
        ivv.copy_from_slice(&iv);
        let sealed = seal(&k, &ivv, b"", &pt).unwrap();
        assert_eq!(
            sealed,
            hex(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
                 4d5c2af327cd64a62cf35abd2ba6fab4"
            )
        );
        assert_eq!(open(&k, &ivv, b"", &sealed).unwrap(), pt);
    }

    #[test]
    fn gcm_rejects_tamper() {
        let key = [1u8; 16];
        let iv = [2u8; 12];
        let sealed = seal(&key, &iv, b"aad", b"hello world").unwrap();
        assert!(open(&key, &iv, b"aad", &sealed).is_some());
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(open(&key, &iv, b"aad", &bad).is_none());
        assert!(open(&key, &iv, b"other", &sealed).is_none());
    }
}
