//! QUIC packet protection (RFC 9001 sections 5-6).
//!
//! This module deliberately owns only packet protection.  Packet-number
//! spaces, loss recovery, and stream scheduling belong to the runtime above
//! it; keeping the AEAD/header-protection code independent makes it possible
//! to test the wire primitive against RFC vectors without opening sockets.

use crate::courierust_error::{Error, Result};
use crate::courierust_tls::crypto::hash::{BoxDigest, Sha256, Sha384};
use crate::courierust_tls::crypto::hmac::{expand, extract};
use alloc::vec::Vec;

/// TLS_AES_128_GCM_SHA256.
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS_AES_256_GCM_SHA384.
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
/// TLS_CHACHA20_POLY1305_SHA256.
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// QUIC v1 initial salt (RFC 9001 section 5.2).
pub const INITIAL_SALT_V1: [u8; 20] = [
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
    0xbe, 0xf9, 0x50, 0x2f,
];

const AEAD_TAG_LEN: usize = 16;

// RFC 9001 section 5.8. These values are public by design; the tag also
// covers the original destination connection ID, so a Retry cannot be moved
// to another connection by an off-path sender.
const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

fn digest_for_suite(suite: u16) -> BoxDigest {
    match suite {
        TLS_AES_256_GCM_SHA384 => Box::new(Sha384::new()),
        _ => Box::new(Sha256::new()),
    }
}

fn hash_len(suite: u16) -> usize {
    if suite == TLS_AES_256_GCM_SHA384 {
        48
    } else {
        32
    }
}

fn key_len(suite: u16) -> Option<usize> {
    match suite {
        TLS_AES_128_GCM_SHA256 => Some(16),
        TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256 => Some(32),
        _ => None,
    }
}

fn expand_quic(suite: u16, secret: &[u8], label: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + 5 + label.len() + 1);
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((5 + label.len()) as u8);
    info.extend_from_slice(b"quic ");
    info.extend_from_slice(label);
    info.push(0);
    expand(digest_for_suite(suite).as_mut(), secret, &info, len)
}

fn nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut out = *iv;
    for (slot, byte) in out[4..].iter_mut().zip(packet_number.to_be_bytes()) {
        *slot ^= byte;
    }
    out
}

/// Packet protection keys for one QUIC packet-number space and direction.
#[derive(Clone)]
pub struct PacketKey {
    suite: u16,
    key: [u8; 32],
    iv: [u8; 12],
    hp: [u8; 32],
    key_len: usize,
    secret: [u8; 48],
    secret_len: usize,
}

impl core::fmt::Debug for PacketKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketKey")
            .field("suite", &format_args!("0x{:04x}", self.suite))
            .field("key_len", &self.key_len)
            .finish_non_exhaustive()
    }
}

impl PacketKey {
    /// Derive QUIC packet keys from a TLS traffic secret.
    pub fn from_secret(suite: u16, secret: &[u8]) -> Result<Self> {
        let key_len =
            key_len(suite).ok_or_else(|| Error::protocol("unsupported QUIC cipher suite"))?;
        if secret.len() != hash_len(suite) {
            return Err(Error::protocol("invalid QUIC traffic-secret length"));
        }
        let key = expand_quic(suite, secret, b"key", key_len);
        let iv = expand_quic(suite, secret, b"iv", 12);
        let hp = expand_quic(suite, secret, b"hp", key_len);
        let mut key_arr = [0u8; 32];
        let mut hp_arr = [0u8; 32];
        let mut iv_arr = [0u8; 12];
        let mut secret_arr = [0u8; 48];
        key_arr[..key_len].copy_from_slice(&key);
        hp_arr[..key_len].copy_from_slice(&hp);
        iv_arr.copy_from_slice(&iv);
        secret_arr[..secret.len()].copy_from_slice(secret);
        Ok(Self {
            suite,
            key: key_arr,
            iv: iv_arr,
            hp: hp_arr,
            key_len,
            secret: secret_arr,
            secret_len: secret.len(),
        })
    }

    /// Derive the next 1-RTT key phase (RFC 9001 section 6).
    pub fn next_key_phase(&self) -> Result<Self> {
        let secret = expand_quic(
            self.suite,
            &self.secret[..self.secret_len],
            b"ku",
            self.secret_len,
        );
        Self::from_secret(self.suite, &secret)
    }

    /// Derive the QUIC v1 Initial key for the requested direction.
    pub fn initial(dcid: &[u8], server_direction: bool) -> Result<Self> {
        if dcid.is_empty() || dcid.len() > 20 {
            return Err(Error::protocol("QUIC Initial DCID must contain 1-20 bytes"));
        }
        let mut digest = Sha256::new();
        let initial_secret = extract(&mut digest, &INITIAL_SALT_V1, dcid);
        let label = if server_direction {
            b"server in"
        } else {
            b"client in"
        };
        let secret = expand_quic(TLS_AES_128_GCM_SHA256, &initial_secret, label, 32);
        Self::from_secret(TLS_AES_128_GCM_SHA256, &secret)
    }

    /// The negotiated TLS cipher suite.
    pub fn suite(&self) -> u16 {
        self.suite
    }

    /// Seal a QUIC payload. `header` is the unprotected packet header,
    /// including the truncated packet number, and becomes AEAD AAD.
    pub fn seal(&self, packet_number: u64, header: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let iv = nonce(&self.iv, packet_number);
        let sealed = match self.suite {
            TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 => {
                crate::courierust_tls::crypto::gcm::seal(
                    &self.key[..self.key_len],
                    &iv,
                    header,
                    plaintext,
                )
            }
            TLS_CHACHA20_POLY1305_SHA256 => {
                let key: &[u8; 32] = self.key[..32]
                    .try_into()
                    .map_err(|_| Error::protocol("invalid ChaCha20 key length"))?;
                Some(crate::courierust_tls::crypto::chacha20poly1305::seal(
                    key, &iv, header, plaintext,
                ))
            }
            _ => None,
        }
        .ok_or_else(|| Error::protocol("QUIC AEAD seal failed"))?;
        Ok(sealed)
    }

    /// Open and authenticate a QUIC payload. Authentication is completed
    /// before any plaintext is returned to the caller.
    pub fn open(&self, packet_number: u64, header: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < AEAD_TAG_LEN {
            return Err(Error::protocol("QUIC packet is shorter than its AEAD tag"));
        }
        let iv = nonce(&self.iv, packet_number);
        let plain = match self.suite {
            TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 => {
                crate::courierust_tls::crypto::gcm::open(
                    &self.key[..self.key_len],
                    &iv,
                    header,
                    sealed,
                )
            }
            TLS_CHACHA20_POLY1305_SHA256 => {
                let key: &[u8; 32] = self.key[..32]
                    .try_into()
                    .map_err(|_| Error::protocol("invalid ChaCha20 key length"))?;
                crate::courierust_tls::crypto::chacha20poly1305::open(key, &iv, header, sealed)
            }
            _ => None,
        }
        .ok_or_else(|| Error::protocol("QUIC packet authentication failed"))?;
        Ok(plain)
    }

    fn hp_mask(&self, sample: &[u8; 16]) -> [u8; 5] {
        let mut mask = [0u8; 5];
        match self.suite {
            TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 => {
                let aes = crate::courierust_tls::crypto::aes::Aes::new(&self.hp[..self.key_len])
                    .expect("validated AES header-protection key");
                let mut block = *sample;
                aes.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            TLS_CHACHA20_POLY1305_SHA256 => {
                let key: &[u8; 32] = self.hp[..32].try_into().expect("validated ChaCha key");
                let nonce: &[u8; 12] = sample[4..].try_into().expect("QUIC HP sample size");
                let counter = u32::from_le_bytes(sample[..4].try_into().expect("QUIC HP sample"));
                let chacha = crate::courierust_tls::crypto::chacha20::ChaCha20::new(key, nonce);
                let mut block = [0u8; 64];
                chacha.block_at(counter, &mut block);
                mask.copy_from_slice(&block[..5]);
            }
            _ => unreachable!("PacketKey validates the suite"),
        }
        mask
    }

    /// Apply QUIC header protection in place. `pn_offset` points to the
    /// first packet-number byte and `long_header` selects the mask width.
    pub fn protect_header(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
        long_header: bool,
    ) -> Result<()> {
        let sample_start = pn_offset
            .checked_add(4)
            .ok_or_else(|| Error::overflow("QUIC header-protection sample offset overflow"))?;
        let sample_end = sample_start
            .checked_add(16)
            .ok_or_else(|| Error::overflow("QUIC header-protection sample end overflow"))?;
        let sample = packet
            .get(sample_start..sample_end)
            .ok_or_else(|| Error::protocol("QUIC packet is too short for header protection"))?;
        let sample: &[u8; 16] = sample.try_into().expect("checked QUIC sample length");
        let mask = self.hp_mask(sample);
        // The packet-number length is encoded in the unprotected low bits.
        // Read it before masking the first byte; deriving it afterwards can
        // select a different number of PN bytes and make the sender's AAD
        // differ from the receiver's reconstructed header.
        let pn_len = (packet[0] & 0x03) as usize + 1;
        packet[0] ^= mask[0] & if long_header { 0x0f } else { 0x1f };
        let pn_end = pn_offset
            .checked_add(pn_len)
            .ok_or_else(|| Error::overflow("QUIC packet number end overflow"))?;
        if packet.len() < pn_end {
            return Err(Error::protocol("QUIC packet number is truncated"));
        }
        for (byte, m) in packet[pn_offset..pn_end]
            .iter_mut()
            .zip(mask.iter().skip(1))
        {
            *byte ^= *m;
        }
        Ok(())
    }

    /// Remove header protection in place and return the packet-number
    /// length. The caller must pass the packet-number offset found from
    /// the unprotected portion of the header.
    pub fn unprotect_header(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
        long_header: bool,
    ) -> Result<usize> {
        let sample_start = pn_offset
            .checked_add(4)
            .ok_or_else(|| Error::overflow("QUIC header-protection sample offset overflow"))?;
        let sample_end = sample_start
            .checked_add(16)
            .ok_or_else(|| Error::overflow("QUIC header-protection sample end overflow"))?;
        let sample = packet
            .get(sample_start..sample_end)
            .ok_or_else(|| Error::protocol("QUIC packet is too short for header protection"))?;
        let sample: &[u8; 16] = sample.try_into().expect("checked QUIC sample length");
        let mask = self.hp_mask(sample);
        packet[0] ^= mask[0] & if long_header { 0x0f } else { 0x1f };
        let pn_len = (packet[0] & 0x03) as usize + 1;
        let pn_end = pn_offset
            .checked_add(pn_len)
            .ok_or_else(|| Error::overflow("QUIC packet number end overflow"))?;
        if packet.len() < pn_end {
            return Err(Error::protocol("QUIC packet number is truncated"));
        }
        for (byte, m) in packet[pn_offset..pn_end]
            .iter_mut()
            .zip(mask.iter().skip(1))
        {
            *byte ^= *m;
        }
        if packet[0] & 0x40 == 0 || packet[0] & if long_header { 0x0c } else { 0x18 } != 0 {
            return Err(Error::protocol(
                "QUIC fixed or reserved header bits are invalid",
            ));
        }
        Ok(pn_len)
    }
}

/// Derive both directions of QUIC Initial packet protection.
pub fn initial_pair(dcid: &[u8]) -> Result<(PacketKey, PacketKey)> {
    Ok((
        PacketKey::initial(dcid, false)?,
        PacketKey::initial(dcid, true)?,
    ))
}

/// Compute the QUIC v1 Retry integrity tag (RFC 9001 section 5.8).
///
/// `retry_packet` must exclude its final 16-byte tag. The original
/// destination connection ID is authenticated as part of the pseudo-packet.
pub fn retry_integrity_tag(original_dcid: &[u8], retry_packet: &[u8]) -> Result<[u8; 16]> {
    if original_dcid.len() > 20 {
        return Err(Error::protocol(
            "QUIC original DCID is longer than 20 bytes",
        ));
    }
    let mut aad = Vec::with_capacity(1 + original_dcid.len() + retry_packet.len());
    aad.push(original_dcid.len() as u8);
    aad.extend_from_slice(original_dcid);
    aad.extend_from_slice(retry_packet);
    let tag = crate::courierust_tls::crypto::gcm::seal(
        &RETRY_INTEGRITY_KEY,
        &RETRY_INTEGRITY_NONCE,
        &aad,
        &[],
    )
    .ok_or_else(|| Error::protocol("QUIC Retry integrity calculation failed"))?;
    tag.as_slice()
        .try_into()
        .map_err(|_| Error::protocol("QUIC Retry integrity tag has invalid length"))
}

/// Verify a QUIC v1 Retry integrity tag without accepting a truncated tag.
pub fn verify_retry_integrity(
    original_dcid: &[u8],
    retry_packet_without_tag: &[u8],
    tag: &[u8],
) -> Result<bool> {
    if tag.len() != AEAD_TAG_LEN {
        return Ok(false);
    }
    let expected = retry_integrity_tag(original_dcid, retry_packet_without_tag)?;
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(tag) {
        difference |= left ^ right;
    }
    Ok(difference == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_keys_are_directional() {
        let (client, server) =
            initial_pair(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap();
        let mut header = vec![
            0xc1, 0, 0, 0, 1, 8, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0, 0, 0x40, 0x04,
            0, 1,
        ];
        let plain = b"ping";
        let sealed = client.seal(0, &header, plain).unwrap();
        header.extend_from_slice(&sealed);
        assert_eq!(
            client
                .open(0, &header[..header.len() - sealed.len()], &sealed)
                .unwrap(),
            plain
        );
        assert!(server
            .open(0, &header[..header.len() - sealed.len()], &sealed)
            .is_err());
        assert!(server
            .open(1, &header[..header.len() - sealed.len()], &sealed)
            .is_err());
    }
}
