//! ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
//!
//! The Poly1305 key is derived from ChaCha20 block 0; the plaintext is
//! encrypted with the same cipher starting at block 1. The tag covers
//! AAD and ciphertext, each padded to 16 bytes, followed by the two
//! 8-byte little-endian lengths.

use super::chacha20::ChaCha20;
use super::poly1305::Poly1305;
use alloc::vec::Vec;

/// Tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Encrypt `plaintext` with associated data `aad` under `key`/`nonce`,
/// returning ciphertext || tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // Poly1305 key = first 32 bytes of ChaCha20 block 0.
    let mut poly_key = [0u8; 64];
    let chacha = ChaCha20::new(key, nonce);
    chacha.block_at(0, &mut poly_key);
    let mut one_time = [0u8; 32];
    one_time.copy_from_slice(&poly_key[..32]);

    // Encrypt from block 1.
    let mut ct = plaintext.to_vec();
    let mut chacha = chacha;
    chacha.set_counter(1);
    chacha.apply_keystream(&mut ct);

    // MAC over aad || ciphertext, each zero-padded to 16 bytes, then
    // the two 8-byte little-endian lengths.
    let tag = compute_tag(&one_time, aad, &ct);

    let mut out = Vec::with_capacity(ct.len() + TAG_LEN);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

/// Compute the Poly1305 tag over `aad` and `ciphertext` per RFC 8439.
fn compute_tag(one_time_key: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    // Save the original lengths first: the loop below advances the `aad`
    // slice, so reading `aad.len()` afterwards would give the remainder
    // (a real bug for AAD >= 16 bytes).
    let aad_len = aad.len();
    let ct_len = ct.len();
    let mut mac = Poly1305::new(one_time_key);
    let mut block = [0u8; 16];
    let mut aad = aad;
    while aad.len() >= 16 {
        block.copy_from_slice(&aad[..16]);
        mac.update(&block);
        aad = &aad[16..];
    }
    if !aad.is_empty() {
        block.fill(0);
        block[..aad.len()].copy_from_slice(aad);
        mac.update(&block);
    }
    let mut ct_slice = ct;
    while ct_slice.len() >= 16 {
        block.copy_from_slice(&ct_slice[..16]);
        mac.update(&block);
        ct_slice = &ct_slice[16..];
    }
    if !ct_slice.is_empty() {
        block.fill(0);
        block[..ct_slice.len()].copy_from_slice(ct_slice);
        mac.update(&block);
    }
    mac.update(&(aad_len as u64).to_le_bytes());
    mac.update(&(ct_len as u64).to_le_bytes());
    mac.finish()
}

/// Open a sealed buffer (`ciphertext || tag`), verifying `aad`.
/// Returns the plaintext, or `None` on a tag mismatch.
pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < TAG_LEN {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - TAG_LEN);

    let mut poly_key = [0u8; 64];
    let chacha = ChaCha20::new(key, nonce);
    chacha.block_at(0, &mut poly_key);
    let mut one_time = [0u8; 32];
    one_time.copy_from_slice(&poly_key[..32]);

    let expected = compute_tag(&one_time, aad, ct);
    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(tag);
    if !constant_time_eq(&expected, &tag_arr) {
        return None;
    }

    let mut pt = ct.to_vec();
    let mut chacha = chacha;
    chacha.set_counter(1);
    chacha.apply_keystream(&mut pt);
    Some(pt)
}

/// Constant-time equality over fixed-length buffers.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20poly1305_rfc8439_vector() {
        // RFC 8439 §2.8.2 (A.5).
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = seal(&key, &nonce, &aad, plaintext);
        let expected = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca967\
             1282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee3280\
             91b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10\
             b594f09e26a7e902ecbd0600691",
        );
        assert_eq!(sealed, expected);

        // Round-trip.
        let opened = open(&key, &nonce, &aad, &sealed).unwrap();
        assert_eq!(&opened[..], &plaintext[..]);

        // Tampering is rejected.
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(open(&key, &nonce, &aad, &bad).is_none());
        // Wrong AAD is rejected.
        assert!(open(&key, &nonce, b"other", &sealed).is_none());
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
