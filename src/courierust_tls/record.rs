//! TLS 1.3 record layer (RFC 8446 §5).
//!
//! Handles the protected records: the inner plaintext is
//! `content || padding || padding_len || real_content_type`, the outer
//! type is always `application_data`, and each AEAD invocation uses
//! `nonce = iv XOR sequence_number`. Sequence numbers are 64-bit and
//! must never overflow; record sizes are bounded to the TLS 1.3 limit.

use super::key_schedule::{CipherSuite, TrafficKeys};
use super::TlsError;
use alloc::vec::Vec;

/// Content type: change_cipher_spec.
pub(crate) const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
/// Content type: alert.
pub(crate) const CONTENT_ALERT: u8 = 21;
/// Content type: handshake.
pub(crate) const CONTENT_HANDSHAKE: u8 = 22;
/// Content type: application_data.
pub(crate) const CONTENT_APPLICATION_DATA: u8 = 23;

/// The maximum size of a TLS record payload (2^14 + 256 for TLS 1.3).
pub(crate) const MAX_RECORD_PAYLOAD: usize = 16_384 + 256;

/// Tracks the 64-bit sequence number for one read or write direction.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Sequence {
    value: u64,
}

impl Sequence {
    pub(crate) fn next(&mut self) -> Result<u64, TlsError> {
        let v = self.value;
        // RFC 8446 §5.3: the sequence number MUST NOT wrap.
        if self.value == u64::MAX {
            return Err(TlsError::Protocol(
                "record sequence number exhausted".into(),
            ));
        }
        self.value += 1;
        Ok(v)
    }
}

/// Build the AEAD nonce: `iv XOR (0^4 || seq_be8)` (RFC 8446 §5.3).
fn build_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

/// Encrypt one record. `content_type` is the real inner content type;
/// the outer wire type is always `application_data` for protected
/// records.
pub(crate) fn seal_record(
    suite: CipherSuite,
    keys: &TrafficKeys,
    seq: u64,
    content_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, TlsError> {
    if plaintext.len() + 2 > MAX_RECORD_PAYLOAD {
        return Err(TlsError::Protocol("record too large".into()));
    }
    // TLSInnerPlaintext = content || padding(0) || type
    let mut inner = Vec::with_capacity(plaintext.len() + 2);
    inner.extend_from_slice(plaintext);
    inner.push(0); // zero padding length
    inner.push(content_type);

    let nonce = build_nonce(&keys.iv, seq);
    // AAD = outer type (23) || legacy_record_version (0x0303) || length.
    // Length is the full encrypted_record size (ciphertext + tag).
    let tag_len = 16usize;
    let ct_len = inner.len() + tag_len;
    if ct_len > u16::MAX as usize {
        return Err(TlsError::Protocol("record too large".into()));
    }
    let header = [
        CONTENT_APPLICATION_DATA,
        0x03,
        0x03,
        (ct_len >> 8) as u8,
        ct_len as u8,
    ];
    let encrypted = suite
        .seal(&keys.key[..suite.key_len()], &nonce, &header, &inner)
        .ok_or_else(|| TlsError::Internal("AEAD seal failed".into()))?;
    let mut out = Vec::with_capacity(5 + encrypted.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

/// Decrypt one record. `header` is the 5-byte record header as received
/// (used verbatim as the AAD). Returns the real inner content type and
/// the plaintext (padding already stripped).
pub(crate) fn open_record(
    suite: CipherSuite,
    keys: &TrafficKeys,
    seq: u64,
    header: &[u8; 5],
    encrypted: &[u8],
) -> Result<(u8, Vec<u8>), TlsError> {
    if header[0] != CONTENT_APPLICATION_DATA {
        return Err(TlsError::Protocol("unexpected record type".into()));
    }
    if encrypted.len() < 16 || encrypted.len() > MAX_RECORD_PAYLOAD + 16 {
        return Err(TlsError::Protocol("bad record length".into()));
    }
    let nonce = build_nonce(&keys.iv, seq);
    let inner = suite
        .open(&keys.key[..suite.key_len()], &nonce, header, encrypted)
        .ok_or(TlsError::Alert {
            level: 2,        // fatal
            description: 20, // bad_record_mac
        })?;
    if inner.len() < 2 {
        return Err(TlsError::Protocol("record too short".into()));
    }
    // TLSInnerPlaintext = content || padding(zeros) || padding_len || type
    let n = inner.len();
    let content_type = inner[n - 1];
    if !matches!(
        content_type,
        CONTENT_CHANGE_CIPHER_SPEC | CONTENT_ALERT | CONTENT_HANDSHAKE | CONTENT_APPLICATION_DATA
    ) {
        return Err(TlsError::Alert {
            level: 2,
            description: 10, // unexpected_message
        });
    }
    let pad_len = inner[n - 2] as usize;
    if pad_len > n - 2 {
        return Err(TlsError::Alert {
            level: 2,
            description: 20, // bad_record_mac
        });
    }
    let content_len = n - 2 - pad_len;
    if inner[content_len..n - 2].iter().any(|&b| b != 0) {
        return Err(TlsError::Alert {
            level: 2,
            description: 20, // bad_record_mac
        });
    }
    let plaintext = inner[..content_len].to_vec();
    Ok((content_type, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_tls::key_schedule::CipherSuite;

    #[test]
    fn record_roundtrip_all_suites() {
        for suite in [
            CipherSuite::TlsAes128GcmSha256,
            CipherSuite::TlsAes256GcmSha384,
            CipherSuite::TlsChaCha20Poly1305Sha256,
        ] {
            let keys = TrafficKeys {
                key: [0x42; 32],
                iv: [0x24; 12],
            };
            let plaintext = b"hello TLS 1.3 record layer";
            for seq in 0..3u64 {
                let rec =
                    seal_record(suite, &keys, seq, CONTENT_HANDSHAKE, plaintext).expect("seal");
                let mut header = [0u8; 5];
                header.copy_from_slice(&rec[..5]);
                let encrypted = &rec[5..];
                let (ct, out) = open_record(suite, &keys, seq, &header, encrypted).expect("open");
                assert_eq!(ct, CONTENT_HANDSHAKE);
                assert_eq!(out, plaintext);
            }
        }
    }

    #[test]
    fn record_wrong_sequence_fails() {
        let suite = CipherSuite::TlsChaCha20Poly1305Sha256;
        let keys = TrafficKeys {
            key: [0x42; 32],
            iv: [0x24; 12],
        };
        let rec = seal_record(suite, &keys, 0, CONTENT_APPLICATION_DATA, b"x").unwrap();
        let mut header = [0u8; 5];
        header.copy_from_slice(&rec[..5]);
        // Tampered ciphertext must fail authentication.
        let mut bad = rec[5..].to_vec();
        bad[0] ^= 1;
        assert!(open_record(suite, &keys, 0, &header, &bad).is_err());
        // Wrong sequence number must fail.
        assert!(open_record(suite, &keys, 1, &header, &rec[5..]).is_err());
    }

    #[test]
    fn record_tampered_aad_fails() {
        let suite = CipherSuite::TlsAes128GcmSha256;
        let keys = TrafficKeys {
            key: [0x42; 32],
            iv: [0x24; 12],
        };
        let rec = seal_record(suite, &keys, 0, CONTENT_APPLICATION_DATA, b"payload").unwrap();
        // A different declared length must fail the AEAD check.
        let mut header = [0u8; 5];
        header.copy_from_slice(&rec[..5]);
        header[4] ^= 1;
        assert!(open_record(suite, &keys, 0, &header, &rec[5..]).is_err());
    }

    #[test]
    fn record_bad_inner_type_fails() {
        let suite = CipherSuite::TlsAes256GcmSha384;
        let keys = TrafficKeys {
            key: [0x42; 32],
            iv: [0x24; 12],
        };
        // Craft an inner plaintext with an invalid content type byte.
        let nonce = [0u8; 12];
        let mut iv = keys.iv;
        for i in 0..8 {
            iv[4 + i] ^= 0;
        }
        let _ = nonce;
        let inner: Vec<u8> = vec![0x01, 0x02, 0x03, 0x00, 0x99]; // type 0x99 invalid
        let ct_len = inner.len() + 16;
        let header = [
            CONTENT_APPLICATION_DATA,
            0x03,
            0x03,
            (ct_len >> 8) as u8,
            ct_len as u8,
        ];
        let enc = suite
            .seal(&keys.key[..suite.key_len()], &iv, &header, &inner)
            .unwrap();
        assert!(open_record(suite, &keys, 0, &header, &enc).is_err());
    }
}
