//! TLS 1.3 key schedule (RFC 8446 §7.1).
//!
//! Derives the handshake and application traffic secrets from the
//! ECDHE shared secret and the running transcript hash, then expands
//! each secret into AEAD keys and IVs. The transcript is fed message by
//! message (including the 4-byte handshake header) as required by
//! RFC 8446 §4.4.1.

use super::crypto::hash::{BoxDigest, Digest};
use super::crypto::hmac::{expand_label, extract as hkdf_extract};
use alloc::vec::Vec;

/// Hash function used by a cipher suite (SHA-256 or SHA-384).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuiteHash {
    /// SHA-256 (used by TLS_AES_128_GCM_SHA256 and
    /// TLS_CHACHA20_POLY1305_SHA256).
    Sha256,
    /// SHA-384 (used by TLS_AES_256_GCM_SHA384).
    Sha384,
}

impl SuiteHash {
    pub(crate) fn hash_len(self) -> usize {
        match self {
            SuiteHash::Sha256 => 32,
            SuiteHash::Sha384 => 48,
        }
    }

    pub(crate) fn new_digest(self) -> BoxDigest {
        match self {
            SuiteHash::Sha256 => Box::new(super::crypto::hash::Sha256::new()),
            SuiteHash::Sha384 => Box::new(super::crypto::hash::Sha384::new()),
        }
    }
}

/// A TLS 1.3 cipher suite (RFC 8446 §Appendix B.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256 (0x1301).
    TlsAes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384 (0x1302).
    TlsAes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303).
    TlsChaCha20Poly1305Sha256,
}

impl CipherSuite {
    /// Wire value.
    pub(crate) fn wire(self) -> u16 {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 0x1301,
            CipherSuite::TlsAes256GcmSha384 => 0x1302,
            CipherSuite::TlsChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    pub(crate) fn from_wire(v: u16) -> Option<Self> {
        match v {
            0x1301 => Some(CipherSuite::TlsAes128GcmSha256),
            0x1302 => Some(CipherSuite::TlsAes256GcmSha384),
            0x1303 => Some(CipherSuite::TlsChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    /// The hash used by the suite.
    pub(crate) fn hash(self) -> SuiteHash {
        match self {
            CipherSuite::TlsAes128GcmSha256 | CipherSuite::TlsChaCha20Poly1305Sha256 => {
                SuiteHash::Sha256
            }
            CipherSuite::TlsAes256GcmSha384 => SuiteHash::Sha384,
        }
    }

    /// The AEAD key length in bytes.
    pub(crate) fn key_len(self) -> usize {
        match self {
            CipherSuite::TlsAes128GcmSha256 => 16,
            CipherSuite::TlsAes256GcmSha384 => 32,
            CipherSuite::TlsChaCha20Poly1305Sha256 => 32,
        }
    }

    /// Encrypt `plaintext` with `key`, `nonce` and `aad`. Returns the
    /// ciphertext plus the 16-byte authentication tag.
    pub(crate) fn seal(
        self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        match self {
            CipherSuite::TlsAes128GcmSha256 | CipherSuite::TlsAes256GcmSha384 => {
                super::crypto::gcm::seal(key, nonce, aad, plaintext)
            }
            CipherSuite::TlsChaCha20Poly1305Sha256 => {
                let k: [u8; 32] = key.try_into().ok()?;
                Some(super::crypto::chacha20poly1305::seal(
                    &k, nonce, aad, plaintext,
                ))
            }
        }
    }

    /// Decrypt and authenticate `sealed` (ciphertext + tag).
    pub(crate) fn open(
        self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        match self {
            CipherSuite::TlsAes128GcmSha256 | CipherSuite::TlsAes256GcmSha384 => {
                super::crypto::gcm::open(key, nonce, aad, sealed)
            }
            CipherSuite::TlsChaCha20Poly1305Sha256 => {
                let k: [u8; 32] = key.try_into().ok()?;
                super::crypto::chacha20poly1305::open(&k, nonce, aad, sealed)
            }
        }
    }
}

/// The running handshake transcript (RFC 8446 §4.4.1).
///
/// Every handshake message is hashed with its 4-byte header
/// (type || length). The transcript is used both to derive traffic
/// secrets at specific points and to verify the Finished messages.
pub(crate) struct Transcript {
    digest: BoxDigest,
}

impl Transcript {
    pub(crate) fn new(h: SuiteHash) -> Self {
        Self {
            digest: h.new_digest(),
        }
    }

    /// Feed a full handshake message (header + body).
    pub(crate) fn update(&mut self, msg: &[u8]) {
        self.digest.update(msg);
    }

    /// The current transcript hash (snapshot; does not disturb state).
    pub(crate) fn current_hash(&self) -> Vec<u8> {
        let mut fork = self.digest.as_ref().fork();
        fork.finalize()
    }
}

/// Derive-Secret (RFC 8446 §7.1):
/// HKDF-Expand-Label(secret, label, transcript_hash, Hash.length).
fn derive_secret(h: SuiteHash, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let mut d = h.new_digest();
    expand_label(d.as_mut(), secret, label, transcript_hash, h.hash_len())
}

/// HKDF-Expand-Label for a traffic key / IV / finished key.
pub(crate) fn expand_secret(
    h: SuiteHash,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut d = h.new_digest();
    expand_label(d.as_mut(), secret, label, context, len)
}

/// A pair of AEAD traffic keys derived from a traffic secret.
#[derive(Debug, Clone)]
pub(crate) struct TrafficKeys {
    /// The 32-byte AEAD key.
    pub(crate) key: [u8; 32],
    /// The 12-byte nonce base (RFC 8446 §5.3: nonce = base XOR seq).
    pub(crate) iv: [u8; 12],
}

impl TrafficKeys {
    fn from_secret(suite: CipherSuite, secret: &[u8]) -> Self {
        let h = suite.hash();
        let key = expand_secret(h, secret, b"key", &[], suite.key_len());
        let iv = expand_secret(h, secret, b"iv", &[], 12);
        let mut k = [0u8; 32];
        k[..key.len()].copy_from_slice(&key);
        let mut i = [0u8; 12];
        i.copy_from_slice(&iv);
        Self { key: k, iv: i }
    }
}

/// The full TLS 1.3 key schedule state for a 1-RTT handshake.
#[derive(Debug, Clone)]
pub(crate) struct KeySchedule {
    suite: CipherSuite,
    handshake_secret: Vec<u8>,
    master_secret: Vec<u8>,
    /// client_handshake_traffic_secret.
    c_hs: Vec<u8>,
    /// server_handshake_traffic_secret.
    s_hs: Vec<u8>,
    /// client_application_traffic_secret_0.
    c_ap: Vec<u8>,
    /// server_application_traffic_secret_0.
    s_ap: Vec<u8>,
}

impl KeySchedule {
    /// Compute the handshake-stage secrets from the ECDHE shared secret
    /// and the ClientHello..ServerHello transcript.
    pub(crate) fn handshake(suite: CipherSuite, ecdhe: &[u8; 32], transcript_hash: &[u8]) -> Self {
        let h = suite.hash();
        // early_secret = HKDF-Extract(0, 0)  (no PSK)
        let zeros = vec![0u8; h.hash_len()];
        let early = hkdf_extract(&mut h.new_digest(), &zeros, &zeros);
        // derived = Derive-Secret(early, "derived", Hash(""))
        let empty_hash = {
            let mut d = h.new_digest();
            d.finalize()
        };
        let derived = derive_secret(h, &early, b"derived", &empty_hash);
        // handshake_secret = HKDF-Extract(derived, ecdhe)
        let handshake_secret = hkdf_extract(&mut h.new_digest(), &derived, ecdhe);
        let c_hs = derive_secret(h, &handshake_secret, b"c hs traffic", transcript_hash);
        let s_hs = derive_secret(h, &handshake_secret, b"s hs traffic", transcript_hash);
        Self {
            suite,
            handshake_secret,
            master_secret: Vec::new(),
            c_hs,
            s_hs,
            c_ap: Vec::new(),
            s_ap: Vec::new(),
        }
    }

    /// Compute the master secret and application traffic secrets after
    /// the server Finished (transcript hash up to and including it).
    pub(crate) fn application(&mut self, transcript_hash: &[u8]) -> Result<(), super::TlsError> {
        let h = self.suite.hash();
        let empty_hash = {
            let mut d = h.new_digest();
            d.finalize()
        };
        let derived = derive_secret(h, &self.handshake_secret, b"derived", &empty_hash);
        let zeros = vec![0u8; h.hash_len()];
        self.master_secret = hkdf_extract(&mut h.new_digest(), &derived, &zeros);
        self.c_ap = derive_secret(h, &self.master_secret, b"c ap traffic", transcript_hash);
        self.s_ap = derive_secret(h, &self.master_secret, b"s ap traffic", transcript_hash);
        Ok(())
    }

    /// client_handshake_traffic_secret.
    pub(crate) fn client_handshake(&self) -> &[u8] {
        &self.c_hs
    }

    /// server_handshake_traffic_secret.
    pub(crate) fn server_handshake(&self) -> &[u8] {
        &self.s_hs
    }

    /// Derive the client handshake AEAD keys.
    pub(crate) fn client_handshake_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(self.suite, &self.c_hs)
    }

    /// Derive the server handshake AEAD keys.
    pub(crate) fn server_handshake_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(self.suite, &self.s_hs)
    }

    /// Derive the client application AEAD keys.
    pub(crate) fn client_application_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(self.suite, &self.c_ap)
    }

    /// Derive the server application AEAD keys.
    pub(crate) fn server_application_keys(&self) -> TrafficKeys {
        TrafficKeys::from_secret(self.suite, &self.s_ap)
    }

    /// The `finished_key` for a traffic secret (RFC 8446 §4.4.4).
    pub(crate) fn finished_key(&self, secret: &[u8]) -> Vec<u8> {
        let h = self.suite.hash();
        expand_secret(h, secret, b"finished", &[], h.hash_len())
    }

    /// The negotiated cipher suite.
    pub(crate) fn suite(&self) -> CipherSuite {
        self.suite
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

    /// RFC 8448 §3 (simple 1-RTT handshake) key schedule values.
    /// ECDHE = 8bd4054f..., transcript hash (CH||SH) = 860c06ed...
    #[test]
    fn rfc8448_key_schedule_sha256() {
        let ecdhe: [u8; 32] =
            hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
                .try_into()
                .unwrap();
        let th: [u8; 32] = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
            .try_into()
            .unwrap();
        let ks = KeySchedule::handshake(CipherSuite::TlsAes128GcmSha256, &ecdhe, &th);
        assert_eq!(
            hex_str(ks.client_handshake()),
            "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
        );
        assert_eq!(
            hex_str(ks.server_handshake()),
            "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
        );
        // The master secret is derived from the handshake secret and the
        // "derived" label (verified independently).
        let empty = {
            let mut d = CipherSuite::TlsAes128GcmSha256.hash().new_digest();
            d.finalize()
        };
        let derived2 = derive_secret(
            CipherSuite::TlsAes128GcmSha256.hash(),
            ks.handshake_secret.clone().as_slice(),
            b"derived",
            &empty,
        );
        let master = hkdf_extract(
            &mut CipherSuite::TlsAes128GcmSha256.hash().new_digest(),
            &derived2,
            &[0u8; 32],
        );
        assert_eq!(
            hex_str(&master),
            "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
        );
    }

    fn hex_str(v: &[u8]) -> String {
        v.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
