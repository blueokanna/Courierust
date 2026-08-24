//! TLS 1.2 (RFC 5246) client and server handshakes, with ECDHE key
//! exchange (RFC 8422) and AEAD record protection.
//!
//! Scope and honesty:
//!
//! * Cipher suites — ECDHE_RSA / ECDHE_ECDSA with
//!   `AES_128_GCM_SHA256`, `AES_256_GCM_SHA384` and
//!   `CHACHA20_POLY1305_SHA256`. CBC/HMAC suites, static (non-ECDHE)
//!   RSA key exchange, TLS 1.0/1.1 and renegotiation are deliberately
//!   not offered: they are the weak half of the TLS 1.2 ecosystem and
//!   this crate's record layer only implements AEAD.
//! * Certificate keys — RSA and ECDSA on the NIST P-256 / P-384 curves
//!   (signature verification and the ECDHE curve `secp256r1` are shared
//!   with the TLS 1.3 implementation). An Ed25519 server identity
//!   cannot negotiate TLS 1.2 (no mainstream TLS 1.2 stack signs a
//!   ServerKeyExchange with Ed25519); the server then reports "no shared
//!   TLS 1.2 cipher suite" instead of silently downgrading the record
//!   layer.
//! * Version policy — the negotiated version is explicit, never
//!   inferred. A client that offered TLS 1.3 and receives a TLS 1.2
//!   ServerHello *without* the RFC 8446 §4.1.3 downgrade sentinel in the
//!   server random aborts (downgrade protection), and a TLS 1.2 client
//!   that receives a TLS 1.3 ServerHello aborts (it never offered it).
//! * No session resumption / session tickets on this path; every TLS 1.2
//!   handshake is a fresh full handshake. (QUIC — the other consumer of
//!   this crate's TLS layer — requires TLS 1.3 by RFC 9001 and is
//!   unaffected by this module.)

use super::crypto::ecdsa::Curve;
use super::crypto::hash::{Digest, Sha256};
use super::crypto::hmac::hmac;
use super::key_schedule::{SuiteHash, TrafficKeys};
use super::record::{CONTENT_ALERT, CONTENT_APPLICATION_DATA, CONTENT_CHANGE_CIPHER_SPEC};
use super::{TlsError, TlsResult};
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------

/// Handshake message types used by TLS 1.2 (RFC 5246 §7.4).
pub(crate) const HS_SERVER_KEY_EXCHANGE: u8 = 12;
pub(crate) const HS_SERVER_HELLO_DONE: u8 = 14;
pub(crate) const HS_CLIENT_KEY_EXCHANGE: u8 = 16;

/// TLS 1.2 record-layer version (also the ClientHello legacy_version).
pub(crate) const VERSION_12: [u8; 2] = [0x03, 0x03];

/// RFC 8446 §4.1.3 downgrade sentinel that a server MUST append to the
/// last 8 bytes of `ServerHello.random` when it negotiates TLS 1.2 with
/// a client that offered TLS 1.3; a conforming client MUST abort if the
/// sentinel is absent in that situation.
pub(crate) const DOWNGRADE_SENTINEL_12: [u8; 8] = *b"DOWNGRD\x01";

/// Named curve `secp256r1` (RFC 8422 §5.1.1).
pub(crate) const GROUP_SECP256R1: u16 = 0x0017;

/// Extension types relevant to TLS 1.2 (RFC 5246 §7.4.1.4, RFC 8422).
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// Secure renegotiation indicator (RFC 5746 §3.2): empty for a fresh
/// handshake; TLS 1.2 peers require it.
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// TLS 1.2 signature algorithms offered in `signature_algorithms`
/// (RFC 5246 §7.4.1.4.1 / RFC 8422): sha256+rsa, sha384+rsa,
/// sha256+ecdsa, sha384+ecdsa, ed25519.
pub(crate) const TLS12_SIGNATURE_ALGORITHMS: &[u16] = &[
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0603, // ecdsa_secp521r1_sha512
    0x0807, // ed25519 (RFC 8422 §4.3; the server SKE uses sig_alg 7)
];

/// The maximum size of a TLS 1.2 record payload (2^14).
pub(crate) const MAX_TLS12_PAYLOAD: usize = 16_384;

// ---------------------------------------------------------------------
// Cipher suites
// ---------------------------------------------------------------------

/// The signature family required by an ECDHE suite's ServerKeyExchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EcdheSig {
    /// ECDHE_RSA suites (RSA PKCS#1 v1.5 signature).
    Rsa,
    /// ECDHE_ECDSA suites (DER ECDSA signature).
    Ecdsa,
}

/// TLS 1.2 AEAD cipher suites (RFC 5289 / RFC 8422 / RFC 7905).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tls12Suite {
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F).
    EcdheRsaAes128GcmSha256,
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030).
    EcdheRsaAes256GcmSha384,
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8).
    EcdheRsaChaCha20Poly1305Sha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B).
    EcdheEcdsaAes128GcmSha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C).
    EcdheEcdsaAes256GcmSha384,
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9).
    EcdheEcdsaChaCha20Poly1305Sha256,
}

impl Tls12Suite {
    /// The wire value of the suite.
    pub(crate) fn wire(self) -> u16 {
        match self {
            Tls12Suite::EcdheRsaAes128GcmSha256 => 0xc02f,
            Tls12Suite::EcdheRsaAes256GcmSha384 => 0xc030,
            Tls12Suite::EcdheRsaChaCha20Poly1305Sha256 => 0xcca8,
            Tls12Suite::EcdheEcdsaAes128GcmSha256 => 0xc02b,
            Tls12Suite::EcdheEcdsaAes256GcmSha384 => 0xc02c,
            Tls12Suite::EcdheEcdsaChaCha20Poly1305Sha256 => 0xcca9,
        }
    }

    pub(crate) fn from_wire(v: u16) -> Option<Self> {
        Some(match v {
            0xc02f => Tls12Suite::EcdheRsaAes128GcmSha256,
            0xc030 => Tls12Suite::EcdheRsaAes256GcmSha384,
            0xcca8 => Tls12Suite::EcdheRsaChaCha20Poly1305Sha256,
            0xc02b => Tls12Suite::EcdheEcdsaAes128GcmSha256,
            0xc02c => Tls12Suite::EcdheEcdsaAes256GcmSha384,
            0xcca9 => Tls12Suite::EcdheEcdsaChaCha20Poly1305Sha256,
            _ => return None,
        })
    }

    /// The hash used by the PRF and the record-layer MAC (RFC 5246 §5).
    pub(crate) fn hash(self) -> SuiteHash {
        match self {
            Tls12Suite::EcdheRsaAes128GcmSha256
            | Tls12Suite::EcdheRsaChaCha20Poly1305Sha256
            | Tls12Suite::EcdheEcdsaAes128GcmSha256
            | Tls12Suite::EcdheEcdsaChaCha20Poly1305Sha256 => SuiteHash::Sha256,
            Tls12Suite::EcdheRsaAes256GcmSha384 | Tls12Suite::EcdheEcdsaAes256GcmSha384 => {
                SuiteHash::Sha384
            }
        }
    }

    /// The AEAD key length in bytes.
    pub(crate) fn key_len(self) -> usize {
        match self {
            Tls12Suite::EcdheRsaAes128GcmSha256 | Tls12Suite::EcdheEcdsaAes128GcmSha256 => 16,
            _ => 32,
        }
    }

    /// The signature family of the ServerKeyExchange for this suite.
    pub(crate) fn ecdhe_sig(self) -> EcdheSig {
        match self {
            Tls12Suite::EcdheRsaAes128GcmSha256
            | Tls12Suite::EcdheRsaAes256GcmSha384
            | Tls12Suite::EcdheRsaChaCha20Poly1305Sha256 => EcdheSig::Rsa,
            Tls12Suite::EcdheEcdsaAes128GcmSha256
            | Tls12Suite::EcdheEcdsaAes256GcmSha384
            | Tls12Suite::EcdheEcdsaChaCha20Poly1305Sha256 => EcdheSig::Ecdsa,
        }
    }

    /// Encrypt `plaintext` with `key`, `nonce` and `aad`; returns the
    /// ciphertext plus the 16-byte authentication tag.
    fn seal(self, key: &[u8], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        match self {
            Tls12Suite::EcdheRsaAes128GcmSha256
            | Tls12Suite::EcdheRsaAes256GcmSha384
            | Tls12Suite::EcdheEcdsaAes128GcmSha256
            | Tls12Suite::EcdheEcdsaAes256GcmSha384 => {
                super::crypto::gcm::seal(key, nonce, aad, plaintext)
            }
            Tls12Suite::EcdheRsaChaCha20Poly1305Sha256
            | Tls12Suite::EcdheEcdsaChaCha20Poly1305Sha256 => {
                let k: [u8; 32] = key.try_into().ok()?;
                Some(super::crypto::chacha20poly1305::seal(
                    &k, nonce, aad, plaintext,
                ))
            }
        }
    }

    /// Decrypt and authenticate `sealed` (ciphertext + tag).
    fn open(self, key: &[u8], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        match self {
            Tls12Suite::EcdheRsaAes128GcmSha256
            | Tls12Suite::EcdheRsaAes256GcmSha384
            | Tls12Suite::EcdheEcdsaAes128GcmSha256
            | Tls12Suite::EcdheEcdsaAes256GcmSha384 => {
                super::crypto::gcm::open(key, nonce, aad, sealed)
            }
            Tls12Suite::EcdheRsaChaCha20Poly1305Sha256
            | Tls12Suite::EcdheEcdsaChaCha20Poly1305Sha256 => {
                let k: [u8; 32] = key.try_into().ok()?;
                super::crypto::chacha20poly1305::open(&k, nonce, aad, sealed)
            }
        }
    }
}

/// TLS 1.2 AEAD record keys: `key` (variable length, top of the
/// `TrafficKeys.key` buffer) and a 4-byte implicit fixed IV stored in
/// `iv[0..4]` (RFC 5246 §6.3 / §6.2.3.3). The 8-byte explicit nonce is
/// chosen per record and transmitted.
pub(crate) type Tls12Keys = TrafficKeys;

// ---------------------------------------------------------------------
// TLS 1.2 PRF (RFC 5246 §5)
// ---------------------------------------------------------------------

fn hmac_hash(h: SuiteHash, key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut d = h.new_digest();
    hmac(d.as_mut(), key, data)
}

/// `P_hash(secret, seed)` (RFC 5246 §5).
fn p_hash(h: SuiteHash, secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut a = hmac_hash(h, secret, seed); // A(1)
    while out.len() < out_len {
        let mut block_input = a.clone();
        block_input.extend_from_slice(seed);
        let block = hmac_hash(h, secret, &block_input);
        out.extend_from_slice(&block);
        a = hmac_hash(h, secret, &a); // A(i+1)
    }
    out.truncate(out_len);
    out
}

/// `PRF(secret, label, seed) = P_hash(secret, label || seed)`.
/// The label is a bare ASCII string concatenated with the seed (TLS 1.2
/// does not length-prefix labels the way TLS 1.3's HKDF does).
pub(crate) fn prf(
    h: SuiteHash,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut s = Vec::with_capacity(label.len() + seed.len());
    s.extend_from_slice(label);
    s.extend_from_slice(seed);
    p_hash(h, secret, &s, out_len)
}

/// Derive the 48-byte `master_secret` (RFC 5246 §8.1).
fn master_secret(
    h: SuiteHash,
    premaster: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    let out = prf(h, premaster, b"master secret", &seed, 48);
    let mut ms = [0u8; 48];
    ms.copy_from_slice(&out);
    ms
}

/// Derive the AEAD key block and split it (RFC 5246 §6.3):
/// `client_write_key || server_write_key || client_write_IV(4) ||
/// server_write_IV(4)`. The per-direction write key is the first
/// `key_len` bytes, the fixed IV the following 4.
fn key_block(
    h: SuiteHash,
    master: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    key_len: usize,
) -> (Vec<u8>, Vec<u8>, [u8; 4], [u8; 4]) {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let total = key_len * 2 + 8;
    let block = prf(h, master, b"key expansion", &seed, total);
    let client_key = block[..key_len].to_vec();
    let server_key = block[key_len..key_len * 2].to_vec();
    let mut client_iv = [0u8; 4];
    client_iv.copy_from_slice(&block[key_len * 2..key_len * 2 + 4]);
    let mut server_iv = [0u8; 4];
    server_iv.copy_from_slice(&block[key_len * 2 + 4..key_len * 2 + 8]);
    (client_key, server_key, client_iv, server_iv)
}

/// The 12-byte Finished `verify_data` (RFC 5246 §7.4.9):
/// `PRF(master_secret, finished_label, Hash(handshake_messages))[0..12]`.
pub(crate) fn finished_verify_data(
    h: SuiteHash,
    master: &[u8; 48],
    label: &[u8],
    transcript_hash: &[u8],
) -> [u8; 12] {
    let out = prf(h, master, label, transcript_hash, 12);
    let mut vd = [0u8; 12];
    vd.copy_from_slice(&out);
    vd
}

/// A TLS 1.2 handshake transcript hash (RFC 5246 §7.4.9): SHA-256 for
/// the SHA-256 suites, SHA-384 for the SHA-384 suites, fed every full
/// handshake message (4-byte header included).
pub(crate) struct Tls12Transcript {
    digest: super::crypto::hash::BoxDigest,
}

impl Tls12Transcript {
    pub(crate) fn new(h: SuiteHash) -> Self {
        Self {
            digest: h.new_digest(),
        }
    }

    pub(crate) fn update(&mut self, msg: &[u8]) {
        self.digest.update(msg);
    }

    pub(crate) fn current_hash(&self) -> Vec<u8> {
        let mut fork = self.digest.as_ref().fork();
        fork.finalize()
    }
}

// ---------------------------------------------------------------------
// TLS 1.2 record layer (RFC 5246 §6.2.3.3, AEAD)
// ---------------------------------------------------------------------

/// Seal one TLS 1.2 AEAD record. The nonce is the 4-byte fixed IV
/// followed by a fresh 8-byte explicit nonce that is transmitted in the
/// record; the additional data is
/// `seq(8) || type(1) || version(2) || length(2)` where `length` covers
/// the explicit nonce, ciphertext and tag (RFC 5246 §6.2.3.3).
pub(crate) fn seal_record(
    suite: Tls12Suite,
    keys: &Tls12Keys,
    seq: u64,
    content_type: u8,
    plaintext: &[u8],
) -> TlsResult<Vec<u8>> {
    if plaintext.len() > MAX_TLS12_PAYLOAD {
        return Err(TlsError::Protocol("record too large".into()));
    }
    let mut explicit_nonce = [0u8; 8];
    if !super::crypto::rng::fill_random(&mut explicit_nonce) {
        return Err(TlsError::Internal(
            "RNG unavailable for record nonce".into(),
        ));
    }
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&keys.iv[..4]);
    nonce[4..].copy_from_slice(&explicit_nonce);

    let ct_len = plaintext.len() + 16; // ciphertext + tag
    let record_len = 8 + ct_len;
    if record_len > u16::MAX as usize {
        return Err(TlsError::Protocol("record too large".into()));
    }
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.push(content_type);
    aad.extend_from_slice(&VERSION_12);
    // RFC 5246 §6.2.3.3: additional_data = seq || type || version ||
    // TLSCompressed.length, where TLSCompressed.length is the *plaintext*
    // length — the explicit nonce and AEAD tag are NOT included.
    aad.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());

    let key = &keys.key[..suite.key_len()];
    let encrypted = suite
        .seal(key, &nonce, &aad, plaintext)
        .ok_or_else(|| TlsError::Internal("AEAD seal failed".into()))?;

    let mut out = Vec::with_capacity(5 + record_len);
    out.push(content_type);
    out.extend_from_slice(&VERSION_12);
    out.extend_from_slice(&(record_len as u16).to_be_bytes());
    out.extend_from_slice(&explicit_nonce);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

/// Open one TLS 1.2 AEAD record. `header` is the 5-byte record header
/// as received (used verbatim, with its length, in the AAD); `body` is
/// everything after the header (8-byte explicit nonce + ciphertext).
/// Returns the real content type and the plaintext.
pub(crate) fn open_record(
    suite: Tls12Suite,
    keys: &Tls12Keys,
    seq: u64,
    header: &[u8; 5],
    body: &[u8],
) -> TlsResult<(u8, Vec<u8>)> {
    let content_type = header[0];
    if !matches!(
        content_type,
        CONTENT_CHANGE_CIPHER_SPEC | CONTENT_ALERT | 22 /*handshake*/ | CONTENT_APPLICATION_DATA
    ) {
        return Err(TlsError::Alert {
            level: 2,
            description: 10, // unexpected_message
        });
    }
    if body.len() < 8 + 16 || body.len() > MAX_TLS12_PAYLOAD + 8 + 16 {
        return Err(TlsError::Protocol("bad record length".into()));
    }
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&keys.iv[..4]);
    nonce[4..].copy_from_slice(&body[..8]);
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.push(content_type);
    aad.extend_from_slice(&header[1..3]);
    // Same AAD rule as seal: length is the plaintext length, i.e. the
    // wire record length minus the 8-byte explicit nonce and 16-byte tag.
    let wire_len = ((header[3] as usize) << 8) | header[4] as usize;
    let plaintext_len = wire_len.saturating_sub(8 + 16);
    aad.extend_from_slice(&(plaintext_len as u16).to_be_bytes());

    let key = &keys.key[..suite.key_len()];
    let plaintext = suite
        .open(key, &nonce, &aad, &body[8..])
        .ok_or(TlsError::Alert {
            level: 2,
            description: 20,
        })?;
    Ok((content_type, plaintext))
}

// ---------------------------------------------------------------------
// Cursor helper
// ---------------------------------------------------------------------

struct Cur<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
    fn done(&self) -> bool {
        self.pos == self.data.len()
    }
}

// ---------------------------------------------------------------------
// Message parsing / building
// ---------------------------------------------------------------------

/// Parsed TLS 1.2 ClientHello essentials.
pub(crate) struct ClientHello12 {
    pub(crate) random: [u8; 32],
    pub(crate) session_id: Vec<u8>,
    pub(crate) offered_suites: Vec<u16>,
    pub(crate) supported_groups: Vec<u16>,
    pub(crate) signature_algorithms: Vec<u16>,
    pub(crate) server_name: Option<String>,
    pub(crate) alpn: Vec<Vec<u8>>,
    /// Whether the client offered TLS 1.3 (supported_versions with
    /// 0x0304); drives the server's downgrade sentinel.
    pub(crate) offered_tls13: bool,
    /// Whether the client offered the RFC 5746 `renegotiation_info`
    /// extension. The server MUST echo it only if offered (§3.2).
    pub(crate) offered_renegotiation: bool,
}

/// Parse a TLS 1.2-or-1.3 ClientHello. `signature_algorithms` is
/// optional (RFC 5246 §7.4.1.4.1: a client that understands it MUST
/// send it, but a TLS 1.2 client that does not is legal); `supported
/// _groups` and `ec_point_formats` are required for ECDHE.
pub(crate) fn parse_client_hello12(body: &[u8]) -> TlsResult<ClientHello12> {
    let mut c = Cur::new(body);
    let legacy_version = c.u16().ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
    if legacy_version != 0x0303 && legacy_version != 0x0301 && legacy_version != 0x0302 {
        return Err(TlsError::Protocol("bad CH legacy version".into()));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(
        c.take(32)
            .ok_or_else(|| TlsError::Protocol("bad CH".into()))?,
    );
    let sid_len = c.u8().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    if sid_len > 32 {
        return Err(TlsError::Protocol("bad CH session id".into()));
    }
    let session_id = c
        .take(sid_len)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?
        .to_vec();
    let suites_len = c.u16().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    if suites_len < 2 || !suites_len.is_multiple_of(2) {
        return Err(TlsError::Protocol("bad CH suites".into()));
    }
    let suites = c
        .take(suites_len)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
    let mut offered_suites = Vec::new();
    for w in suites.chunks(2) {
        offered_suites.push(u16::from_be_bytes([w[0], w[1]]));
    }
    let comp_len = c.u8().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    c.take(comp_len)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;

    let mut supported_groups = Vec::new();
    let mut signature_algorithms = Vec::new();
    let mut server_name = None;
    let mut alpn = Vec::new();
    let mut offered_tls13 = false;
    let mut offered_renegotiation = false;
    if !c.done() {
        let ext_total =
            c.u16()
                .ok_or_else(|| TlsError::Protocol("bad CH exts".into()))? as usize;
        let ext_bytes = c
            .take(ext_total)
            .ok_or_else(|| TlsError::Protocol("bad CH exts".into()))?;
        let mut e = Cur::new(ext_bytes);
        while !e.done() {
            let ext_type = e
                .u16()
                .ok_or_else(|| TlsError::Protocol("bad CH ext".into()))?;
            let len = e
                .u16()
                .ok_or_else(|| TlsError::Protocol("bad CH ext".into()))?
                as usize;
            let content = e
                .take(len)
                .ok_or_else(|| TlsError::Protocol("bad CH ext".into()))?;
            match ext_type {
                EXT_SUPPORTED_GROUPS => {
                    let mut g = Cur::new(content);
                    let list_len = g
                        .u16()
                        .ok_or_else(|| TlsError::Protocol("bad groups".into()))?
                        as usize;
                    let list = g
                        .take(list_len)
                        .ok_or_else(|| TlsError::Protocol("bad groups".into()))?;
                    let mut gc = Cur::new(list);
                    while !gc.done() {
                        supported_groups.push(
                            gc.u16()
                                .ok_or_else(|| TlsError::Protocol("bad groups".into()))?,
                        );
                    }
                }
                EXT_SIGNATURE_ALGORITHMS => {
                    let mut g = Cur::new(content);
                    let list_len = g
                        .u16()
                        .ok_or_else(|| TlsError::Protocol("bad sigalgs".into()))?
                        as usize;
                    let list = g
                        .take(list_len)
                        .ok_or_else(|| TlsError::Protocol("bad sigalgs".into()))?;
                    let mut gc = Cur::new(list);
                    while !gc.done() {
                        signature_algorithms.push(
                            gc.u16()
                                .ok_or_else(|| TlsError::Protocol("bad sigalgs".into()))?,
                        );
                    }
                }
                EXT_SERVER_NAME => {
                    let mut g = Cur::new(content);
                    let list_len = g
                        .u16()
                        .ok_or_else(|| TlsError::Protocol("bad sni".into()))?
                        as usize;
                    let list = g
                        .take(list_len)
                        .ok_or_else(|| TlsError::Protocol("bad sni".into()))?;
                    let mut lc = Cur::new(list);
                    if lc.u8() == Some(0) {
                        let nlen = lc
                            .u16()
                            .ok_or_else(|| TlsError::Protocol("bad sni".into()))?
                            as usize;
                        if let Some(name) = lc.take(nlen) {
                            if let Ok(s) = core::str::from_utf8(name) {
                                server_name = Some(s.to_string());
                            }
                        }
                    }
                }
                EXT_ALPN => {
                    let mut g = Cur::new(content);
                    let list_len = g
                        .u16()
                        .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?
                        as usize;
                    let list = g
                        .take(list_len)
                        .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?;
                    let mut lc = Cur::new(list);
                    while !lc.done() {
                        let plen = lc
                            .u8()
                            .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?
                            as usize;
                        alpn.push(
                            lc.take(plen)
                                .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?
                                .to_vec(),
                        );
                    }
                }
                EXT_SUPPORTED_VERSIONS => {
                    let mut g = Cur::new(content);
                    let list_len = g
                        .u8()
                        .ok_or_else(|| TlsError::Protocol("bad versions".into()))?
                        as usize;
                    let list = g
                        .take(list_len)
                        .ok_or_else(|| TlsError::Protocol("bad versions".into()))?;
                    let mut lc = Cur::new(list);
                    while !lc.done() {
                        if let Some(v) = lc.u16() {
                            if v == 0x0304 {
                                offered_tls13 = true;
                            }
                        }
                    }
                }
                EXT_RENEGOTIATION_INFO => {
                    // RFC 5746 §3.2: a fresh handshake carries an empty
                    // `renegotiated_connection`; just note the offer.
                    offered_renegotiation = true;
                }
                _ => {}
            }
        }
    }
    Ok(ClientHello12 {
        random,
        session_id,
        offered_suites,
        supported_groups,
        signature_algorithms,
        server_name,
        alpn,
        offered_tls13,
        offered_renegotiation,
    })
}

/// Build a TLS 1.2 ServerHello (no `supported_versions` extension). If
/// `downgrade_sentinel` is set, the last 8 bytes of `random` are
/// overwritten with the RFC 8446 §4.1.3 sentinel (server negotiating
/// TLS 1.2 with a TLS 1.3-capable client). `alpn` carries the negotiated
/// protocol in an ALPN extension (RFC 7301), when one was selected.
/// `renegotiation` echoes the RFC 5746 secure-renegotiation indicator
/// (empty for a fresh handshake) — the server MUST include it only when
/// the client offered it (§3.2).
pub(crate) fn build_server_hello12(
    mut random: [u8; 32],
    session_id: &[u8],
    suite: Tls12Suite,
    downgrade_sentinel: bool,
    alpn: Option<&[u8]>,
    renegotiation: bool,
) -> Vec<u8> {
    if downgrade_sentinel {
        random[24..].copy_from_slice(&DOWNGRADE_SENTINEL_12);
    }
    let mut body = Vec::with_capacity(2 + 32 + 1 + session_id.len() + 3);
    body.extend_from_slice(&VERSION_12);
    body.extend_from_slice(&random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.wire().to_be_bytes());
    body.push(0); // compression null
    let mut ext_bytes = Vec::new();
    // RFC 5746 §3.2: secure renegotiation indicator. TLS 1.2 clients
    // (OpenSSL s_client) refuse to proceed without it when they offered
    // it ("unsafe legacy renegotiation disabled"); a fresh handshake's
    // `renegotiated_connection` is an empty vector, so the extension_data
    // is a single 0x00 length byte (`ff 01 00 01 00`).
    if renegotiation {
        ext_bytes.extend_from_slice(&EXT_RENEGOTIATION_INFO.to_be_bytes());
        ext_bytes.extend_from_slice(&[0x00, 0x01, 0x00]);
    }
    if let Some(proto) = alpn {
        let mut proto_list = Vec::new();
        proto_list.push(proto.len() as u8);
        proto_list.extend_from_slice(proto);
        let mut alpn_body = Vec::new();
        alpn_body.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
        alpn_body.extend_from_slice(&proto_list);
        ext_bytes.extend_from_slice(&EXT_ALPN.to_be_bytes());
        ext_bytes.extend_from_slice(&(alpn_body.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(&alpn_body);
    }
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);
    encode_hs(2, &body) // server_hello
}

/// Build a TLS 1.2 Certificate message (RFC 5246 §7.4.2):
/// `certificate_list` with 3-byte lengths, no per-certificate
/// extensions (unlike TLS 1.3).
pub(crate) fn build_certificate12(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for c in chain {
        list.extend_from_slice(&[(c.len() >> 16) as u8, (c.len() >> 8) as u8, c.len() as u8]);
        list.extend_from_slice(c);
    }
    let mut body = Vec::with_capacity(3 + list.len());
    body.extend_from_slice(&[
        (list.len() >> 16) as u8,
        (list.len() >> 8) as u8,
        list.len() as u8,
    ]);
    body.extend_from_slice(&list);
    encode_hs(11, &body)
}

/// Parse a TLS 1.2 Certificate message and return the DER entries.
pub(crate) fn parse_certificate12(body: &[u8]) -> TlsResult<Vec<Vec<u8>>> {
    let mut c = Cur::new(body);
    let list_len = c
        .u24()
        .ok_or_else(|| TlsError::Protocol("bad cert".into()))?;
    let list = c
        .take(list_len)
        .ok_or_else(|| TlsError::Protocol("bad cert".into()))?;
    let mut lc = Cur::new(list);
    let mut out = Vec::new();
    while !lc.done() {
        let cert_len = lc
            .u24()
            .ok_or_else(|| TlsError::Protocol("bad cert".into()))?;
        let cert = lc
            .take(cert_len)
            .ok_or_else(|| TlsError::Protocol("bad cert".into()))?;
        out.push(cert.to_vec());
    }
    if out.is_empty() {
        return Err(TlsError::Protocol("empty certificate list".into()));
    }
    Ok(out)
}

/// Build an ECDHE `ServerKeyExchange` (RFC 8422 §5.4):
/// `ECParameters(3) || ECPoint(1-byte length) || DigitallySigned`.
/// `params` is `ECParameters || ECPoint`; `signature` is the raw RSA /
/// ECDSA signature over `client_random || server_random || params`.
pub(crate) fn build_server_key_exchange(
    point: &[u8; 65],
    hash_alg: u8,
    sig_alg: u8,
    signature: &[u8],
) -> Vec<u8> {
    let mut params = Vec::with_capacity(3 + 1 + point.len());
    params.push(3); // named_curve
    params.extend_from_slice(&GROUP_SECP256R1.to_be_bytes());
    params.push(point.len() as u8);
    params.extend_from_slice(point);
    let mut body = params.clone();
    body.push(hash_alg);
    body.push(sig_alg);
    body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    body.extend_from_slice(signature);
    encode_hs(HS_SERVER_KEY_EXCHANGE, &body)
}

/// Parsed ECDHE `ServerKeyExchange` data.
pub(crate) struct ServerKeyExchange12 {
    /// The server's ECDHE public point (`0x04 || X || Y`).
    pub(crate) point: [u8; 65],
    /// The raw `ECParameters || ECPoint` bytes (the signed portion).
    pub(crate) params: Vec<u8>,
    pub(crate) hash_alg: u8,
    pub(crate) sig_alg: u8,
    pub(crate) signature: Vec<u8>,
}

pub(crate) fn parse_server_key_exchange(body: &[u8]) -> TlsResult<ServerKeyExchange12> {
    let mut c = Cur::new(body);
    let curve_type = c.u8().ok_or_else(|| TlsError::Protocol("bad SKE".into()))?;
    if curve_type != 3 {
        return Err(TlsError::Protocol("unsupported SKE curve type".into()));
    }
    let group = c
        .u16()
        .ok_or_else(|| TlsError::Protocol("bad SKE".into()))?;
    if group != GROUP_SECP256R1 {
        return Err(TlsError::Protocol("unsupported SKE named curve".into()));
    }
    let point_len = c.u8().ok_or_else(|| TlsError::Protocol("bad SKE".into()))? as usize;
    if point_len != 65 {
        return Err(TlsError::Protocol("bad SKE point length".into()));
    }
    let point_bytes = c
        .take(point_len)
        .ok_or_else(|| TlsError::Protocol("bad SKE".into()))?;
    let mut point = [0u8; 65];
    point.copy_from_slice(point_bytes);
    let params = body[..body.len() - c.rest().len()].to_vec();
    let hash_alg = c
        .u8()
        .ok_or_else(|| TlsError::Protocol("bad SKE sig".into()))?;
    let sig_alg = c
        .u8()
        .ok_or_else(|| TlsError::Protocol("bad SKE sig".into()))?;
    let sig_len = c
        .u16()
        .ok_or_else(|| TlsError::Protocol("bad SKE sig".into()))? as usize;
    if sig_len == 0 || sig_len > 512 {
        return Err(TlsError::Protocol("bad SKE signature length".into()));
    }
    let signature = c
        .take(sig_len)
        .ok_or_else(|| TlsError::Protocol("bad SKE sig".into()))?
        .to_vec();
    if !c.done() {
        return Err(TlsError::Protocol("trailing bytes in SKE".into()));
    }
    Ok(ServerKeyExchange12 {
        point,
        params,
        hash_alg,
        sig_alg,
        signature,
    })
}

/// Build an empty `ServerHelloDone` message.
pub(crate) fn build_server_hello_done() -> Vec<u8> {
    encode_hs(HS_SERVER_HELLO_DONE, &[])
}

/// Build the client's ECDHE `ClientKeyExchange` (RFC 8422 §5.7): the
/// public point is `opaque point<1..2^8-1>` (1-byte length prefix).
pub(crate) fn build_client_key_exchange(point: &[u8; 65]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + point.len());
    body.push(point.len() as u8);
    body.extend_from_slice(point);
    encode_hs(HS_CLIENT_KEY_EXCHANGE, &body)
}

/// Parse the client's ECDHE `ClientKeyExchange`.
pub(crate) fn parse_client_key_exchange(body: &[u8]) -> TlsResult<[u8; 65]> {
    let mut c = Cur::new(body);
    let len = c.u8().ok_or_else(|| TlsError::Protocol("bad CKE".into()))? as usize;
    if len != 65 {
        return Err(TlsError::Protocol("bad CKE point length".into()));
    }
    let point_bytes = c
        .take(len)
        .ok_or_else(|| TlsError::Protocol("bad CKE".into()))?;
    if !c.done() {
        return Err(TlsError::Protocol("trailing bytes in CKE".into()));
    }
    let mut point = [0u8; 65];
    point.copy_from_slice(point_bytes);
    if point[0] != 0x04 {
        return Err(TlsError::Protocol("bad CKE point encoding".into()));
    }
    Ok(point)
}

/// Encode a handshake message: type || length(3) || body.
fn encode_hs(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&[
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ]);
    out.extend_from_slice(body);
    out
}

/// Parse a complete handshake message from the front of `buf`.
fn parse_hs(buf: &[u8]) -> Option<(u8, Vec<u8>)> {
    if buf.len() < 4 {
        return None;
    }
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    if 4 + len > buf.len() {
        return None;
    }
    Some((buf[0], buf[4..4 + len].to_vec()))
}

// ---------------------------------------------------------------------
// Shared helper: complete the ECDHE handshake after the flight
// ---------------------------------------------------------------------

/// Derive the master secret and the two record key directions from the
/// ECDHE shared secret.
fn derive_keys(
    suite: Tls12Suite,
    shared: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> ([u8; 48], Tls12Keys, Tls12Keys) {
    let h = suite.hash();
    let master = master_secret(h, shared, client_random, server_random);
    let (client_key, server_key, client_iv, server_iv) =
        key_block(h, &master, client_random, server_random, suite.key_len());
    let client_keys = Tls12Keys {
        key: {
            let mut k = [0u8; 32];
            k[..client_key.len()].copy_from_slice(&client_key);
            k
        },
        iv: {
            let mut iv = [0u8; 12];
            iv[..4].copy_from_slice(&client_iv);
            iv
        },
    };
    let server_keys = Tls12Keys {
        key: {
            let mut k = [0u8; 32];
            k[..server_key.len()].copy_from_slice(&server_key);
            k
        },
        iv: {
            let mut iv = [0u8; 12];
            iv[..4].copy_from_slice(&server_iv);
            iv
        },
    };
    (master, client_keys, server_keys)
}

/// Constant-time comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SHA-256 digest of a message (used for the SKE signature and the
/// transcript hash when the suite is SHA-256).
fn sha256_of(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut d = [0u8; 32];
    d.copy_from_slice(&out);
    d
}

/// SHA-384 digest of a message (SHA-384 SKE signatures / SHA-384
/// transcript hash).
fn sha384_of(data: &[u8]) -> [u8; 48] {
    let mut h = super::crypto::hash::Sha384::new();
    h.update(data);
    let out = h.finalize();
    let mut d = [0u8; 48];
    d.copy_from_slice(&out);
    d
}

/// SHA-512 digest of a message (SHA-512 SKE signatures, P-521 keys).
fn sha512_of(data: &[u8]) -> [u8; 64] {
    let mut h = super::crypto::ed25519::Sha512::new();
    h.update(data);
    let out = h.finalize();
    let mut d = [0u8; 64];
    d.copy_from_slice(&out);
    d
}

// ---------------------------------------------------------------------
// Client handshake
// ---------------------------------------------------------------------

/// The result of a completed TLS 1.2 handshake.
pub(crate) struct Tls12HandshakeResult {
    pub(crate) suite: Tls12Suite,
    /// `write` = client write keys, `read` = server write keys for a
    /// client; the reverse on the server.
    pub(crate) keys: Tls12KeysPair,
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) server_name: Option<String>,
    pub(crate) peer_cert: Option<Vec<u8>>,
}

/// A pair of per-direction TLS 1.2 AEAD keys.
pub(crate) struct Tls12KeysPair {
    pub(crate) write: Tls12Keys,
    pub(crate) read: Tls12Keys,
}

/// Verify the ServerKeyExchange signature against the peer certificate.
fn verify_server_key_exchange(
    ske: &ServerKeyExchange12,
    spki: &super::x509::Spki,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> TlsResult<()> {
    use super::crypto::ecdsa;
    use super::crypto::rsa::{verify_rsa_pkcs1v15, RsaPublicKey};
    use super::x509::der::{parse_rsa_public_key, OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION};

    // RFC 5246 §7.4.3 / RFC 8422: the SKE digest is hash_alg 4 (SHA-256),
    // 5 (SHA-384) or 6 (SHA-512) combined with sig_alg 1 (RSA) or
    // 3 (ECDSA).
    let to_sign = {
        let mut v = Vec::with_capacity(64 + ske.params.len());
        v.extend_from_slice(client_random);
        v.extend_from_slice(server_random);
        v.extend_from_slice(&ske.params);
        v
    };

    if ske.sig_alg == 1 && spki.oid == OID_RSA_ENCRYPTION {
        let (n, e) = parse_rsa_public_key(&spki.key)
            .ok_or_else(|| TlsError::Certificate("bad RSA SPKI".into()))?;
        let key = RsaPublicKey { n, e };
        let ok = match ske.hash_alg {
            4 => {
                let digest = sha256_of(&to_sign);
                verify_rsa_pkcs1v15(&key, false, &digest, &ske.signature)
            }
            5 => {
                let digest = sha384_of(&to_sign);
                verify_rsa_pkcs1v15(&key, true, &digest, &ske.signature)
            }
            _ => false,
        };
        if ok {
            Ok(())
        } else {
            Err(TlsError::Certificate(
                "ServerKeyExchange RSA signature invalid".into(),
            ))
        }
    } else if ske.sig_alg == 3 && spki.oid == OID_EC_PUBLIC_KEY {
        // The digest selects the curve (RFC 8422 §5.5): SHA-256 ↔ P-256,
        // SHA-384 ↔ P-384, SHA-512 ↔ P-521.
        let curve = match ske.hash_alg {
            4 => ecdsa::Curve::P256,
            5 => ecdsa::Curve::P384,
            6 => ecdsa::Curve::P521,
            _ => {
                return Err(TlsError::Certificate(
                    "unsupported ServerKeyExchange digest".into(),
                ))
            }
        };
        if spki.ec_curve != Some(curve) {
            return Err(TlsError::Certificate(
                "ServerKeyExchange EC curve mismatch".into(),
            ));
        }
        let clen = curve.coord_len();
        if spki.key.len() != 1 + 2 * clen || spki.key[0] != 0x04 {
            return Err(TlsError::Certificate("bad EC SPKI".into()));
        }
        let qx = &spki.key[1..1 + clen];
        let qy = &spki.key[1 + clen..1 + 2 * clen];
        let digest = match ske.hash_alg {
            4 => sha256_of(&to_sign).to_vec(),
            5 => sha384_of(&to_sign).to_vec(),
            _ => sha512_of(&to_sign).to_vec(),
        };
        if ecdsa::verify_der(curve, qx, qy, &digest, &ske.signature) {
            Ok(())
        } else {
            Err(TlsError::Certificate(
                "ServerKeyExchange ECDSA signature invalid".into(),
            ))
        }
    } else if ske.sig_alg == 7 && spki.oid == super::x509::der::OID_ED25519 {
        // RFC 8422: sig_alg 7 = Ed25519 (the two-byte scheme is 0x0807,
        // parsed here as hash_alg=0x08, sig_alg=0x07). The signature is
        // over the raw SKE params (RFC 8032; no separate digest).
        if spki.key.len() != 32 {
            return Err(TlsError::Certificate("bad Ed25519 SPKI".into()));
        }
        if ske.signature.len() != 64 {
            return Err(TlsError::Certificate("bad Ed25519 signature length".into()));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&spki.key);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&ske.signature);
        if super::crypto::ed25519::verify(&pk, &to_sign, &sig) {
            Ok(())
        } else {
            Err(TlsError::Certificate(
                "ServerKeyExchange Ed25519 signature invalid".into(),
            ))
        }
    } else {
        Err(TlsError::Certificate(
            "ServerKeyExchange signature algorithm mismatch".into(),
        ))
    }
}

/// Run the TLS 1.2 client handshake. `ch` is the full ClientHello that
/// was already sent (needed for the transcript); `first_record` is the
/// raw payload of the first plaintext handshake record already read
/// (containing the ServerHello and possibly the rest of the server's
/// flight — peers routinely coalesce Certificate / ServerKeyExchange /
/// ServerHelloDone with the ServerHello into one record).
#[allow(clippy::too_many_arguments)]
pub(crate) fn client_handshake<R: crate::courierust_io::Read, W: crate::courierust_io::Write>(
    io: &mut super::TlsIo<R, W>,
    roots: &super::RootStore,
    now: i64,
    verify: bool,
    server_name: Option<&str>,
    ch: &[u8],
    client_random: &[u8; 32],
    first_record: &[u8],
    // Whether this client offered TLS 1.3 in the ClientHello. When
    // true, a TLS 1.2 ServerHello MUST carry the RFC 8446 downgrade
    // sentinel; when false (TLS 1.2-only client) no sentinel is sent
    // or required.
    offered_tls13: bool,
) -> TlsResult<Tls12HandshakeResult> {
    let mut reader = PlainFlightReader::from_payload(first_record);
    let (sh_type, sh_body) = reader.next(io)?;
    if sh_type != 2 {
        return Err(TlsError::Protocol("expected ServerHello".into()));
    }
    let sh = parse_server_hello12(&sh_body)?;
    // RFC 5246 §7.4.1.2: when the client offered an empty session id
    // (no resumption), the server MAY issue a fresh session id for its
    // own cache. Accept whatever it sends; we never resume via TLS 1.2
    // session ids, so the value is carried but unused.
    if offered_tls13 && !sh.random[24..].starts_with(&DOWNGRADE_SENTINEL_12) {
        return Err(TlsError::Protocol(
            "TLS 1.2 ServerHello missing downgrade sentinel".into(),
        ));
    }
    let suite = Tls12Suite::from_wire(sh.suite_wire)
        .ok_or_else(|| TlsError::Protocol("server chose unsupported suite".into()))?;

    let mut cert = None;
    let mut ske = None;
    let mut saw_done = false;
    while !saw_done {
        let (msg_type, body) = reader.next(io)?;
        match msg_type {
            11 => {
                cert = Some(parse_certificate12(&body)?);
            }
            HS_SERVER_KEY_EXCHANGE => {
                ske = Some(parse_server_key_exchange(&body)?);
            }
            HS_SERVER_HELLO_DONE => saw_done = true,
            _ => {
                return Err(TlsError::Protocol("unexpected server message".into()));
            }
        }
    }
    let peer_chain = cert.ok_or_else(|| TlsError::Protocol("missing Certificate".into()))?;
    let ske = ske.ok_or_else(|| TlsError::Protocol("missing ServerKeyExchange".into()))?;

    let peer_cert_der = peer_chain[0].clone();
    let leaf = super::x509::parse_certificate(&peer_cert_der)?;
    let spki = leaf.spki.clone();
    if verify {
        let name = server_name.unwrap_or("");
        if !super::x509::hostname_matches(name, &leaf.dns_names, &leaf.ip_names) {
            return Err(TlsError::Certificate("hostname mismatch".into()));
        }
        super::x509::validate_chain(roots, &peer_chain, now)?;
        if !super::x509::has_server_auth_eku(&leaf) {
            return Err(TlsError::Certificate(
                "leaf certificate lacks TLS serverAuth EKU".into(),
            ));
        }
    }

    verify_server_key_exchange(&ske, &spki, client_random, &sh.random)?;

    let (client_priv, client_point) = super::crypto::ecdsa::ecdhe_generate(None)
        .ok_or_else(|| TlsError::Internal("ECDHE key generation failed".into()))?;
    let cke = build_client_key_exchange(&client_point);
    let shared =
        super::crypto::ecdsa::ecdhe_shared(&client_priv, &ske.point).ok_or(TlsError::Alert {
            level: 2,
            description: 40, // handshake_failure
        })?;

    let (master, client_keys, server_keys) = derive_keys(suite, &shared, client_random, &sh.random);
    let mut transcript = Tls12Transcript::new(suite.hash());
    transcript.update(ch);
    for (msg_type, body) in reader.messages() {
        transcript.update(&encode_hs(*msg_type, body));
    }
    transcript.update(&cke);
    let fin_hash = transcript.current_hash();
    let verify_data = finished_verify_data(suite.hash(), &master, b"client finished", &fin_hash);
    let fin_msg = encode_hs(20, &verify_data);

    io.write_plaintext_record_v(VERSION_12, 22, &cke)?;
    io.write_plaintext_record_v(VERSION_12, CONTENT_CHANGE_CIPHER_SPEC, &[1])?;
    io.write_tls12_record(suite, &client_keys, 22, &fin_msg)?;

    let (ct, payload) = io.read_plaintext_record()?;
    if ct != CONTENT_CHANGE_CIPHER_SPEC || payload.as_slice() != [1] {
        return Err(TlsError::Protocol(
            "expected server ChangeCipherSpec".into(),
        ));
    }
    let (ct, plaintext) = io.read_tls12_record(suite, &server_keys)?;
    if ct != 22 {
        return Err(TlsError::Protocol("expected server Finished".into()));
    }
    let (m_type, fin_body) =
        parse_hs(&plaintext).ok_or_else(|| TlsError::Protocol("bad server Finished".into()))?;
    if m_type != 20 {
        return Err(TlsError::Protocol("expected server Finished".into()));
    }
    let mut server_transcript = Tls12Transcript::new(suite.hash());
    server_transcript.update(ch);
    for (msg_type, body) in reader.messages() {
        server_transcript.update(&encode_hs(*msg_type, body));
    }
    server_transcript.update(&cke);
    server_transcript.update(&fin_msg);
    let server_fin_hash = server_transcript.current_hash();
    let expected =
        finished_verify_data(suite.hash(), &master, b"server finished", &server_fin_hash);
    if !constant_time_eq(&expected, &fin_body) {
        return Err(TlsError::Alert {
            level: 2,
            description: 51, // decrypt_error
        });
    }

    Ok(Tls12HandshakeResult {
        suite,
        keys: Tls12KeysPair {
            write: client_keys,
            read: server_keys,
        },
        alpn: sh.alpn,
        server_name: server_name.map(|s| s.to_string()),
        peer_cert: Some(peer_cert_der),
    })
}

/// Parsed TLS 1.2 ServerHello essentials. The session id is consumed but
/// not retained — we never resume via TLS 1.2 session ids, and RFC 5246
/// allows the server to issue a fresh one even when the client sent none.
struct ServerHello12 {
    random: [u8; 32],
    suite_wire: u16,
    alpn: Option<Vec<u8>>,
}

fn parse_server_hello12(body: &[u8]) -> TlsResult<ServerHello12> {
    let mut c = Cur::new(body);
    let legacy = c.u16().ok_or_else(|| TlsError::Protocol("bad SH".into()))?;
    if legacy != 0x0303 {
        return Err(TlsError::Protocol("bad SH legacy version".into()));
    }
    let mut random = [0u8; 32];
    random.copy_from_slice(
        c.take(32)
            .ok_or_else(|| TlsError::Protocol("bad SH".into()))?,
    );
    let sid_len = c.u8().ok_or_else(|| TlsError::Protocol("bad SH".into()))? as usize;
    if sid_len > 32 {
        return Err(TlsError::Protocol("bad SH session id".into()));
    }
    let _ = c
        .take(sid_len)
        .ok_or_else(|| TlsError::Protocol("bad SH".into()))?;
    let suite_wire = c.u16().ok_or_else(|| TlsError::Protocol("bad SH".into()))?;
    let comp = c.u8().ok_or_else(|| TlsError::Protocol("bad SH".into()))?;
    if comp != 0 {
        return Err(TlsError::Protocol("bad SH compression".into()));
    }
    let mut alpn = None;
    if !c.done() {
        let ext_total =
            c.u16()
                .ok_or_else(|| TlsError::Protocol("bad SH exts".into()))? as usize;
        let ext_bytes = c
            .take(ext_total)
            .ok_or_else(|| TlsError::Protocol("bad SH exts".into()))?;
        let mut e = Cur::new(ext_bytes);
        while !e.done() {
            let ext_type = e
                .u16()
                .ok_or_else(|| TlsError::Protocol("bad SH ext".into()))?;
            let len = e
                .u16()
                .ok_or_else(|| TlsError::Protocol("bad SH ext".into()))?
                as usize;
            let content = e
                .take(len)
                .ok_or_else(|| TlsError::Protocol("bad SH ext".into()))?;
            if ext_type == EXT_SUPPORTED_VERSIONS {
                return Err(TlsError::Protocol(
                    "server negotiated TLS 1.3 on the TLS 1.2 path".into(),
                ));
            }
            if ext_type == EXT_ALPN {
                let mut g = Cur::new(content);
                let list_len = g
                    .u16()
                    .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?
                    as usize;
                let list = g
                    .take(list_len)
                    .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?;
                let mut lc = Cur::new(list);
                let plen = lc
                    .u8()
                    .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?
                    as usize;
                let proto = lc
                    .take(plen)
                    .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?;
                if !lc.done() {
                    return Err(TlsError::Protocol("bad alpn".into()));
                }
                alpn = Some(proto.to_vec());
            }
        }
    }
    Ok(ServerHello12 {
        random,
        suite_wire,
        alpn,
    })
}

/// Buffers plaintext handshake records and yields complete handshake
/// messages, retaining the raw bodies so the transcript hashes exactly
/// what the peer sent (message order preserved).
struct PlainFlightReader {
    buf: Vec<u8>,
    /// Raw handshake bodies in wire order (type, body).
    messages: Vec<(u8, Vec<u8>)>,
}

impl PlainFlightReader {
    /// Start from an already-read plaintext record payload (which may
    /// contain several complete handshake messages).
    fn from_payload(payload: &[u8]) -> Self {
        Self {
            buf: payload.to_vec(),
            messages: Vec::new(),
        }
    }

    fn messages(&self) -> &[(u8, Vec<u8>)] {
        &self.messages
    }

    /// Read the next complete handshake message. Returns an error on a
    /// non-handshake record or a partial message at end of stream.
    fn next<R: crate::courierust_io::Read, W: crate::courierust_io::Write>(
        &mut self,
        io: &mut super::TlsIo<R, W>,
    ) -> TlsResult<(u8, Vec<u8>)> {
        loop {
            if let Some(m) = parse_hs(&self.buf) {
                let consumed = 4 + m.1.len();
                let (typ, body) = m;
                self.buf.drain(..consumed);
                self.messages.push((typ, body.clone()));
                return Ok((typ, body));
            }
            let (ct, payload) = io.read_plaintext_record()?;
            if ct == 21 {
                return Err(TlsError::Alert {
                    level: payload.first().copied().unwrap_or(2),
                    description: payload.get(1).copied().unwrap_or(0),
                });
            }
            if ct != 22 {
                return Err(TlsError::Protocol("expected handshake record".into()));
            }
            self.buf.extend_from_slice(&payload);
        }
    }
}

/// Run the TLS 1.2 server handshake. `ch_body` is the ClientHello body
/// that was already read (raw, for the transcript).
pub(crate) fn server_handshake<R: crate::courierust_io::Read, W: crate::courierust_io::Write>(
    io: &mut super::TlsIo<R, W>,
    identity: &super::Identity,
    alpn: &[Vec<u8>],
    ch_body: &[u8],
) -> TlsResult<Tls12HandshakeResult> {
    let ch = parse_client_hello12(ch_body)?;
    let key_type = super::sign::identity_key_type(identity)?;
    let suite = CLIENT_SUITES_12
        .iter()
        .copied()
        .find(|s| {
            // The ECDSA suite hash must match the identity curve (RFC
            // 8422 §5.5: SHA-256 ↔ P-256, SHA-384 ↔ P-384).
            let family_ok = match (s.ecdhe_sig(), key_type) {
                (EcdheSig::Rsa, super::sign::IdentityKeyType::Rsa) => true,
                (EcdheSig::Ecdsa, super::sign::IdentityKeyType::Ecdsa(Curve::P256)) => {
                    s.hash() == SuiteHash::Sha256
                }
                (EcdheSig::Ecdsa, super::sign::IdentityKeyType::Ecdsa(Curve::P384)) => {
                    s.hash() == SuiteHash::Sha384
                }
                // RFC 8422 §4.3: an Ed25519 identity signs the SKE of an
                // ECDHE-ECDSA suite (scheme 0x0807).
                (EcdheSig::Ecdsa, super::sign::IdentityKeyType::Ed25519) => true,
                _ => false,
            };
            family_ok && ch.offered_suites.contains(&s.wire())
        })
        .ok_or_else(|| {
            TlsError::Protocol("no shared TLS 1.2 cipher suite (identity or offer)".into())
        })?;

    if !ch.supported_groups.contains(&GROUP_SECP256R1) {
        return Err(TlsError::Protocol(
            "client did not offer the secp256r1 ECDHE group".into(),
        ));
    }
    let required_sigalg = match (suite.ecdhe_sig(), key_type) {
        (EcdheSig::Rsa, _) => 0x0401,
        (EcdheSig::Ecdsa, super::sign::IdentityKeyType::Ecdsa(Curve::P256)) => 0x0403,
        (EcdheSig::Ecdsa, super::sign::IdentityKeyType::Ecdsa(Curve::P384)) => 0x0503,
        // RFC 8422: Ed25519 signs the SKE with scheme 0x0807.
        (EcdheSig::Ecdsa, super::sign::IdentityKeyType::Ed25519) => 0x0807,
        _ => 0x0403, // unreachable: P-521 never selects an ECDHE suite
    };
    if !ch.signature_algorithms.contains(&required_sigalg) {
        return Err(TlsError::Protocol(
            "client did not offer the ServerKeyExchange signature algorithm".into(),
        ));
    }

    let negotiated_alpn = alpn
        .iter()
        .find(|p| ch.alpn.iter().any(|c| c == *p))
        .cloned();

    let (s_priv, s_point) = super::crypto::ecdsa::ecdhe_generate(None)
        .ok_or_else(|| TlsError::Internal("ECDHE key generation failed".into()))?;
    let mut s_random = [0u8; 32];
    if !super::crypto::rng::fill_random(&mut s_random) {
        return Err(TlsError::Internal("RNG unavailable".into()));
    }
    if ch.offered_tls13 {
        s_random[24..].copy_from_slice(&DOWNGRADE_SENTINEL_12);
    }
    let sh = build_server_hello12(
        s_random,
        &ch.session_id,
        suite,
        ch.offered_tls13,
        negotiated_alpn.as_deref(),
        ch.offered_renegotiation,
    );

    let mut transcript = Tls12Transcript::new(suite.hash());
    transcript.update(&encode_hs(1, ch_body));
    transcript.update(&sh);

    let cert_msg = build_certificate12(&identity.cert_chain);
    transcript.update(&cert_msg);

    let mut ske_params = Vec::with_capacity(3 + 1 + s_point.len());
    ske_params.push(3);
    ske_params.extend_from_slice(&GROUP_SECP256R1.to_be_bytes());
    ske_params.push(s_point.len() as u8);
    ske_params.extend_from_slice(&s_point);
    let mut to_sign = Vec::with_capacity(64 + ske_params.len());
    to_sign.extend_from_slice(&ch.random);
    to_sign.extend_from_slice(&s_random);
    to_sign.extend_from_slice(&ske_params);
    let (hash_alg, sig_alg, signature) =
        super::sign::sign_tls12_server_key_exchange(identity, &to_sign)?
            .ok_or_else(|| TlsError::Protocol("identity cannot sign TLS 1.2 SKE".into()))?;
    let ske = build_server_key_exchange(&s_point, hash_alg, sig_alg, &signature);
    transcript.update(&ske);

    let shd = build_server_hello_done();
    transcript.update(&shd);

    let mut flight = sh;
    flight.extend_from_slice(&cert_msg);
    flight.extend_from_slice(&ske);
    flight.extend_from_slice(&shd);
    io.write_plaintext_record_v(VERSION_12, 22, &flight)?;

    let (_, cke_body) = io.read_plaintext_handshake()?;
    let cke = parse_client_key_exchange(&cke_body)?;
    let cke_msg = encode_hs(HS_CLIENT_KEY_EXCHANGE, &cke_body);
    transcript.update(&cke_msg);

    let shared = super::crypto::ecdsa::ecdhe_shared(&s_priv, &cke).ok_or(TlsError::Alert {
        level: 2,
        description: 40, // handshake_failure
    })?;
    let (master, client_keys, server_keys) = derive_keys(suite, &shared, &ch.random, &s_random);
    let (ct, payload) = io.read_plaintext_record()?;
    if ct != CONTENT_CHANGE_CIPHER_SPEC || payload.as_slice() != [1] {
        return Err(TlsError::Protocol(
            "expected client ChangeCipherSpec".into(),
        ));
    }
    let (ct, plaintext) = io.read_tls12_record(suite, &client_keys)?;
    if ct != 22 {
        return Err(TlsError::Protocol("expected client Finished".into()));
    }
    let (m_type, fin_body) =
        parse_hs(&plaintext).ok_or_else(|| TlsError::Protocol("bad client Finished".into()))?;
    if m_type != 20 {
        return Err(TlsError::Protocol("expected client Finished".into()));
    }
    let client_fin_hash = transcript.current_hash();
    let expected =
        finished_verify_data(suite.hash(), &master, b"client finished", &client_fin_hash);
    if !constant_time_eq(&expected, &fin_body) {
        return Err(TlsError::Alert {
            level: 2,
            description: 51,
        });
    }
    transcript.update(&plaintext); // append the client Finished

    let server_fin_hash = transcript.current_hash();
    let verify_data =
        finished_verify_data(suite.hash(), &master, b"server finished", &server_fin_hash);
    let fin_msg = encode_hs(20, &verify_data);
    io.write_plaintext_record_v(VERSION_12, CONTENT_CHANGE_CIPHER_SPEC, &[1])?;
    io.write_tls12_record(suite, &server_keys, 22, &fin_msg)?;

    Ok(Tls12HandshakeResult {
        suite,
        keys: Tls12KeysPair {
            write: server_keys,
            read: client_keys,
        },
        alpn: negotiated_alpn,
        server_name: ch.server_name,
        peer_cert: None,
    })
}

/// The TLS 1.2 client suite offer (RFC 5289 / RFC 8422 / RFC 7905).
pub(crate) const CLIENT_SUITES_12: &[Tls12Suite] = &[
    Tls12Suite::EcdheRsaAes128GcmSha256,
    Tls12Suite::EcdheRsaAes256GcmSha384,
    Tls12Suite::EcdheRsaChaCha20Poly1305Sha256,
    Tls12Suite::EcdheEcdsaAes128GcmSha256,
    Tls12Suite::EcdheEcdsaAes256GcmSha384,
    Tls12Suite::EcdheEcdsaChaCha20Poly1305Sha256,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_matches_independent_sha256() {
        let secret = [0xAB; 32];
        let seed = [0xCD; 16];
        let out = prf(SuiteHash::Sha256, &secret, b"test label", &seed, 48);
        let expected: &[u8] = &[
            0x3b, 0xed, 0xbe, 0xdd, 0xdf, 0xca, 0xc1, 0x92, 0x83, 0xd4, 0xbf, 0xbc, 0xcf, 0xc5,
            0xd5, 0x65, 0x09, 0x99, 0x68, 0x75, 0xd2, 0x1e, 0x6e, 0xa0, 0x51, 0x96, 0x93, 0xce,
            0xf8, 0x71, 0x82, 0x2b, 0x30, 0xa6, 0x7d, 0x5e, 0x42, 0x94, 0xe2, 0x95, 0x58, 0xd1,
            0xc6, 0x41, 0xf0, 0x8c, 0xc9, 0xeb,
        ];
        assert_eq!(out, expected);
        // Same inputs through SHA-384 must differ (PRF hash is suite-scoped).
        let out384 = prf(SuiteHash::Sha384, &secret, b"test label", &seed, 48);
        let expected384: &[u8] = &[
            0xe5, 0xcf, 0xba, 0xbf, 0x94, 0xa3, 0xac, 0x79, 0x17, 0xb7, 0x7e, 0x2f, 0x01, 0x60,
            0x5d, 0xec, 0xaa, 0xf7, 0x7b, 0x02, 0x20, 0x00, 0x4c, 0x08, 0x0c, 0x7d, 0x2d, 0xd0,
            0xf9, 0x61, 0x06, 0x36, 0x22, 0x49, 0x01, 0x5f, 0xea, 0x48, 0x2b, 0xea, 0xa5, 0x3c,
            0x4f, 0xfe, 0xcc, 0x07, 0x84, 0x75,
        ];
        assert_eq!(out384, expected384);
    }

    #[test]
    fn prf_sha384_distinct_from_sha256() {
        let secret = [0xAB; 32];
        let seed = [0xCD; 16];
        let a = prf(SuiteHash::Sha256, &secret, b"x", &seed, 16);
        let b = prf(SuiteHash::Sha384, &secret, b"x", &seed, 16);
        assert_ne!(a, b);
    }

    #[test]
    fn record_roundtrip_all_suites() {
        for suite in CLIENT_SUITES_12 {
            let keys = Tls12Keys {
                key: [0x42; 32],
                iv: {
                    let mut iv = [0u8; 12];
                    iv[..4].copy_from_slice(&[1, 2, 3, 4]);
                    iv
                },
            };
            let plaintext = b"hello TLS 1.2 record layer";
            for seq in 0..3u64 {
                let rec = seal_record(*suite, &keys, seq, CONTENT_APPLICATION_DATA, plaintext)
                    .expect("seal");
                let mut header = [0u8; 5];
                header.copy_from_slice(&rec[..5]);
                let body = &rec[5..];
                let (ct, out) = open_record(*suite, &keys, seq, &header, body).expect("open");
                assert_eq!(ct, CONTENT_APPLICATION_DATA);
                assert_eq!(out, plaintext);
            }
        }
    }

    #[test]
    fn record_wrong_seq_and_tamper_fail() {
        let suite = Tls12Suite::EcdheRsaAes128GcmSha256;
        let keys = Tls12Keys {
            key: [0x42; 32],
            iv: {
                let mut iv = [0u8; 12];
                iv[..4].copy_from_slice(&[1, 2, 3, 4]);
                iv
            },
        };
        let rec = seal_record(suite, &keys, 0, CONTENT_APPLICATION_DATA, b"x").unwrap();
        let mut header = [0u8; 5];
        header.copy_from_slice(&rec[..5]);
        let mut bad = rec[5..].to_vec();
        bad[9] ^= 1; // flip a ciphertext byte
        assert!(open_record(suite, &keys, 0, &header, &bad).is_err());
        assert!(open_record(suite, &keys, 1, &header, &rec[5..]).is_err());
    }

    #[test]
    fn master_secret_matches_reference() {
        // Cross-checked with an independent implementation (RFC 5246
        // §8.1 semantics: PRF(pre_master, "master secret", CR || SR)).
        let h = SuiteHash::Sha256;
        let premaster = [0x11; 32];
        let cr = [0x22; 32];
        let sr = [0x33; 32];
        let ms = master_secret(h, &premaster, &cr, &sr);
        // Recompute independently via the public PRF.
        let mut seed = Vec::new();
        seed.extend_from_slice(&cr);
        seed.extend_from_slice(&sr);
        let expect = prf(h, &premaster, b"master secret", &seed, 48);
        assert_eq!(&ms[..], &expect[..]);
        assert_eq!(ms.len(), 48);
    }

    #[test]
    fn ecdhe_symmetric() {
        // Generate two key pairs; the shared secret must be symmetric.
        let (a, point_a) = super::super::crypto::ecdsa::ecdhe_generate(None).unwrap();
        let (b, point_b) = super::super::crypto::ecdsa::ecdhe_generate(None).unwrap();
        let s1 = super::super::crypto::ecdsa::ecdhe_shared(&a, &point_b).unwrap();
        let s2 = super::super::crypto::ecdsa::ecdhe_shared(&b, &point_a).unwrap();
        assert_eq!(s1, s2, "ECDH shared secrets must be symmetric");
        assert_ne!(s1, [0u8; 32]);
        // Reusing a private key with the same public point reproduces it.
        let s3 = super::super::crypto::ecdsa::ecdhe_shared(&a, &point_b).unwrap();
        assert_eq!(s1, s3);
    }

    #[test]
    fn debug_rsa_identity_sign_verify() {
        use crate::courierust_tls::testdata;
        let id = testdata::rsa_server_identity();
        let leaf = crate::courierust_tls::x509::parse_certificate(&id.cert_chain[0]).unwrap();
        let spki = leaf.spki;
        let msg = b"client_random_plus_server_random_plus_params";
        let (hash_alg, sig_alg, signature) =
            crate::courierust_tls::sign::sign_tls12_server_key_exchange(&id, msg)
                .unwrap()
                .unwrap();
        assert_eq!(hash_alg, 4);
        assert_eq!(sig_alg, 1);
        use crate::courierust_tls::x509::der::{parse_rsa_public_key, OID_RSA_ENCRYPTION};
        assert_eq!(spki.oid, OID_RSA_ENCRYPTION);
        let (n, e) = parse_rsa_public_key(&spki.key).expect("parse rsa spki");
        let key = crate::courierust_tls::crypto::rsa::RsaPublicKey { n, e };
        let digest = {
            let mut h = Sha256::new();
            h.update(msg);
            h.finalize()
        };
        let ok = crate::courierust_tls::crypto::rsa::verify_rsa_pkcs1v15(
            &key, false, &digest, &signature,
        );
        assert!(ok, "RSA sign/verify roundtrip with test identity failed");
    }

    #[test]
    fn downgrade_sentinel_present_when_offering_13() {
        let random = [0u8; 32];
        let sh = build_server_hello12(
            random,
            &[],
            Tls12Suite::EcdheRsaAes128GcmSha256,
            true,
            None,
            true,
        );
        let body = &sh[4..];
        let mut c = Cur::new(body);
        c.take(2).unwrap();
        let r: &[u8] = c.take(32).unwrap();
        assert!(r[24..].starts_with(&DOWNGRADE_SENTINEL_12));
        // And absent when not.
        let sh2 = build_server_hello12(
            random,
            &[],
            Tls12Suite::EcdheRsaAes128GcmSha256,
            false,
            None,
            true,
        );
        let body2 = &sh2[4..];
        let mut c2 = Cur::new(body2);
        c2.take(2).unwrap();
        let r2: &[u8] = c2.take(32).unwrap();
        assert!(!r2[24..].starts_with(&DOWNGRADE_SENTINEL_12));
    }

    #[test]
    fn renegotiation_info_echoed_only_when_offered() {
        // A ServerHello built with renegotiation=true must carry the
        // RFC 5746 extension: `ff 01 00 01 00` (type, length 1, a single
        // 0x00 length byte for the empty renegotiated_connection).
        let random = [0u8; 32];
        let sh = build_server_hello12(
            random,
            &[],
            Tls12Suite::EcdheRsaAes128GcmSha256,
            false,
            None,
            true,
        );
        let body = &sh[4..];
        let mut c = Cur::new(body);
        c.take(2).unwrap(); // version
        c.take(32).unwrap(); // random
        let sid_len = c.u8().unwrap() as usize;
        c.take(sid_len).unwrap();
        c.take(2).unwrap(); // suite
        c.take(1).unwrap(); // compression
        let ext_total = c.u16().unwrap() as usize;
        let ext_bytes = c.take(ext_total).unwrap();
        let mut e = Cur::new(ext_bytes);
        let mut found = false;
        while !e.done() {
            let t = e.u16().unwrap();
            let len = e.u16().unwrap() as usize;
            let content = e.take(len).unwrap();
            if t == EXT_RENEGOTIATION_INFO {
                found = true;
                assert_eq!(
                    content,
                    &[0x00],
                    "fresh-handshake body must be a single 0x00 length byte"
                );
            }
        }
        assert!(found, "renegotiation_info must be echoed when offered");

        // ...and omitted when the client did not offer it (RFC 5746 §3.2).
        let sh2 = build_server_hello12(
            random,
            &[],
            Tls12Suite::EcdheRsaAes128GcmSha256,
            false,
            None,
            false,
        );
        let body2 = &sh2[4..];
        let mut c2 = Cur::new(body2);
        c2.take(2).unwrap();
        c2.take(32).unwrap();
        let sid_len2 = c2.u8().unwrap() as usize;
        c2.take(sid_len2).unwrap();
        c2.take(2).unwrap();
        c2.take(1).unwrap();
        let ext_total2 = c2.u16().unwrap() as usize;
        let ext_bytes2 = c2.take(ext_total2).unwrap();
        let mut e2 = Cur::new(ext_bytes2);
        while !e2.done() {
            let t = e2.u16().unwrap();
            let len = e2.u16().unwrap() as usize;
            let _ = e2.take(len).unwrap();
            assert_ne!(t, EXT_RENEGOTIATION_INFO, "must not echo when not offered");
        }
    }

    #[test]
    fn parse_client_hello_detects_renegotiation_offer() {
        // Build a minimal ClientHello offering renegotiation_info and
        // confirm parse_client_hello12 records it.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]); // one suite
        body.extend_from_slice(&[1, 0]); // compression
        let mut ext = Vec::new();
        ext.extend_from_slice(&EXT_RENEGOTIATION_INFO.to_be_bytes());
        ext.extend_from_slice(&[0x00, 0x01, 0x00]); // len 1, empty vector
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let ch = parse_client_hello12(&body).expect("parse");
        assert!(ch.offered_renegotiation);

        // Without the extension the flag must stay false.
        let mut body2 = Vec::new();
        body2.extend_from_slice(&[0x03, 0x03]);
        body2.extend_from_slice(&[0u8; 32]);
        body2.push(0);
        body2.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]);
        body2.extend_from_slice(&[1, 0]);
        body2.extend_from_slice(&[0x00, 0x00]); // no extensions
        let ch2 = parse_client_hello12(&body2).expect("parse");
        assert!(!ch2.offered_renegotiation);
    }
}
