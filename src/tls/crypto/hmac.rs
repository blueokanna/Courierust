//! HMAC (RFC 2104) over the [`Digest`] trait, and HKDF (RFC 5869) as
//! used by TLS 1.3 (RFC 8446 §7.1) with the HKDF-Expand-Label
//! construction.

use super::hash::Digest;
use alloc::vec::Vec;

/// Compute HMAC over `key` and `data` using digest `d` (its state is
/// reset by this call; pass a freshly created hasher for clarity).
pub fn hmac(d: &mut dyn Digest, key: &[u8], data: &[u8]) -> Vec<u8> {
    let block = d.block_len();
    let mut k = key.to_vec();
    if k.len() > block {
        k = d.finalize();
        d.update(&k);
        k = d.finalize();
    }
    while k.len() < block {
        k.push(0);
    }
    let mut ipad = vec![0x36u8; block];
    let mut opad = vec![0x5cu8; block];
    for i in 0..block {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    d.update(&ipad);
    d.update(data);
    let inner = d.finalize();
    d.update(&opad);
    d.update(&inner);
    d.finalize()
}

/// HKDF-Extract (RFC 5869 §2.2).
pub fn extract(d: &mut dyn Digest, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    // The salt is used as the HMAC key; an empty salt is zero-filled to
    // one block (RFC 5869 §2.2). `hmac` already zero-pads short keys.
    hmac(d, salt, ikm)
}

/// HKDF-Expand (RFC 5869 §2.3).
pub fn expand(d: &mut dyn Digest, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hash_len = d.output_len();
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        // T(i) = HMAC(PRK, T(i-1) || info || i)
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac(d, prk, &msg);
        let take = core::cmp::min(hash_len, len - out.len());
        out.extend_from_slice(&t[..take]);
        counter = counter.wrapping_add(1);
        if counter == 0 {
            // Wrapped: more than 255 blocks requested.
            break;
        }
    }
    out
}

/// The "HKDF-Expand-Label" construction (RFC 8446 §7.1).
pub fn expand_label(
    d: &mut dyn Digest,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    // length(2) || label_len(1) || "tls13 " + label || context_len(1) || context
    let label_with_prefix = b"tls13 ";
    let mut info = Vec::with_capacity(2 + 1 + label_with_prefix.len() + label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((label_with_prefix.len() + label.len()) as u8);
    info.extend_from_slice(label_with_prefix);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    expand(d, secret, &info, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::crypto::hash::Sha256;

    fn hex(d: &[u8]) -> String {
        let mut s = String::new();
        for b in d {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    #[test]
    fn hmac_sha256_rfc4231() {
        // RFC 4231 Test Case 2 (single block key).
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mut d = Sha256::new();
        let mac = hmac(&mut d, key, data);
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hkdf_sha256_rfc5869() {
        // RFC 5869 Test Case 1.
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut d = Sha256::new();
        let prk = extract(&mut d, &salt, &ikm);
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = expand(&mut d, &prk, &info, 42);
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_expand_label_known() {
        // Verify the label assembly against a manually-constructed info
        // passed through the RFC 5869 `expand` (already vector-tested).
        let secret = [0u8; 32];
        let mut d = Sha256::new();
        let out = expand_label(&mut d, &secret, b"key", b"", 32);
        let manual_info = [
            0x00, 0x20, // length 32
            0x09, // label len
            b't', b'l', b's', b'1', b'3', b' ', b'k', b'e', b'y',
            0x00, // context len
        ];
        let expected = expand(&mut d, &secret, &manual_info, 32);
        assert_eq!(out, expected);
    }
}
