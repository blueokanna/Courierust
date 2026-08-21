//! TLS 1.3 handshake state machines (RFC 8446 §4).
//!
//! Implements the client and server sides of a full 1-RTT handshake:
//! ClientHello / ServerHello / EncryptedExtensions / Certificate /
//! CertificateVerify / Finished. Only X25519 key exchange is offered;
//! the negotiated suite is chosen by the server from the supported set.
//!
//! The Finished verify_data is computed over the transcript hash taken
//! *before* the Finished message is appended (as in rustls/OpenSSL);
//! the Finished message is then added to the transcript for deriving
//! the application traffic secrets.

use super::crypto::hash::Digest;
use super::crypto::hmac::hmac;

use super::crypto::x25519;
use super::key_schedule::{CipherSuite, KeySchedule, TrafficKeys, Transcript};
use super::record::*;
use super::{TlsError, TlsResult};
use alloc::string::String;
use alloc::vec::Vec;

/// Handshake message types (RFC 8446 §4).
pub(crate) const HS_CLIENT_HELLO: u8 = 1;
pub(crate) const HS_SERVER_HELLO: u8 = 2;
pub(crate) const HS_NEW_SESSION_TICKET: u8 = 4;
/// EndOfEarlyData (used in 0-RTT; recognized here for completeness).
#[allow(dead_code)]
pub(crate) const HS_END_OF_EARLY_DATA: u8 = 5;
pub(crate) const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const HS_CERTIFICATE: u8 = 11;
/// CertificateRequest (used for client auth; not yet supported).
#[allow(dead_code)]
pub(crate) const HS_CERTIFICATE_REQUEST: u8 = 13;
pub(crate) const HS_CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const HS_FINISHED: u8 = 20;

/// Extension types.
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

/// Named group for X25519.
const GROUP_X25519: u16 = 0x001d;

/// Signature schemes offered (RFC 8446 §4.2.3): RSA-PSS-PSS, RSA-PSS-RSAE,
/// ECDSA P-256, Ed25519, and RSA PKCS#1.
const SIGNATURE_SCHEMES: &[u16] = &[
    0x0809, // rsa_pss_pss_sha256
    0x080a, // rsa_pss_pss_sha384
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0403, // ecdsa_secp256r1_sha256
    0x0807, // ed25519
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
];

/// Encode a handshake message: type || length(3) || body.
fn encode_hs(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len() as u32;
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    out.extend_from_slice(body);
    out
}

/// A parsed handshake message from a stream of handshake bytes.
pub(crate) struct HsMessage<'a> {
    pub(crate) msg_type: u8,
    pub(crate) body: &'a [u8],
}

/// Parse a single handshake message (4-byte header + body).
fn parse_hs<'a>(buf: &'a [u8]) -> Option<HsMessage<'a>> {
    if buf.len() < 4 {
        return None;
    }
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    if 4 + len > buf.len() {
        return None;
    }
    Some(HsMessage {
        msg_type: buf[0],
        body: &buf[4..4 + len],
    })
}

/// If `buf` starts with a complete handshake message, return it.
pub(crate) fn peek_complete_hs<'a>(buf: &'a [u8]) -> Option<HsMessage<'a>> {
    parse_hs(buf).filter(|m| 4 + m.body.len() <= buf.len())
}

/// Whether `buf` contains a complete `Finished` handshake message.
///
/// In a 1-RTT handshake the Finished is the final message of the peer's
/// first flight, so "a complete Finished is buffered" is the right
/// condition for [`TlsIo::read_encrypted_handshake`] to stop: it must
/// keep consuming records until the whole flight is present (a server
/// may fragment EncryptedExtensions / Certificate / CertificateVerify /
/// Finished across several records). Walks complete messages only, so a
/// partial trailing message simply means "keep reading".
pub(crate) fn has_complete_finished(buf: &[u8]) -> bool {
    let mut off = 0;
    while off + 4 <= buf.len() {
        let len =
            ((buf[off + 1] as usize) << 16) | ((buf[off + 2] as usize) << 8) | buf[off + 3] as usize;
        if off + 4 + len > buf.len() {
            return false; // trailing message is incomplete
        }
        if buf[off] == HS_FINISHED {
            return true;
        }
        off += 4 + len;
    }
    false
}

/// Read a u8/u16/u24 from a cursor.
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

/// A parsed extension: type + content.
struct Ext<'a> {
    ext_type: u16,
    content: &'a [u8],
}

/// Parse the extension list of a handshake message body.
fn parse_extensions(body: &[u8]) -> Option<Vec<Ext<'_>>> {
    let mut c = Cur::new(body);
    let total = c.u16()? as usize;
    let ext_bytes = c.take(total)?;
    let mut out = Vec::new();
    let mut e = Cur::new(ext_bytes);
    while !e.done() {
        let ext_type = e.u16()?;
        let len = e.u16()? as usize;
        let content = e.take(len)?;
        out.push(Ext { ext_type, content });
    }
    Some(out)
}

/// The offered cipher suites the client sends.
const CLIENT_SUITES: &[CipherSuite] = &[
    CipherSuite::TlsChaCha20Poly1305Sha256,
    CipherSuite::TlsAes128GcmSha256,
    CipherSuite::TlsAes256GcmSha384,
];

/// The negotiated handshake result shared by both sides.
pub(crate) struct HandshakeResult {
    pub(crate) suite: CipherSuite,
    pub(crate) keys: AppKeys,
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) server_name: Option<String>,
    pub(crate) peer_cert: Option<Vec<u8>>,
}

/// The application traffic keys (write = client, read = server and
/// vice-versa), fully derived.
#[derive(Debug, Clone)]
pub(crate) struct AppKeys {
    pub(crate) write: TrafficKeys,
    pub(crate) read: TrafficKeys,
}

// ---------------------------------------------------------------------
// ClientHello construction
// ---------------------------------------------------------------------

/// Build a full ClientHello message (header + body) with the given
/// random, session id, key share and ALPN list.
pub(crate) fn build_client_hello(
    random: &[u8; 32],
    key_share: &[u8; 32],
    alpn: &[Vec<u8>],
    server_name: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    // legacy_version = 0x0303
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(random);
    // legacy_session_id (empty for a non-resuming client)
    body.push(0);
    // cipher_suites (big-endian u16 length)
    body.extend_from_slice(&(CLIENT_SUITES.len() as u16 * 2).to_be_bytes());
    for s in CLIENT_SUITES {
        body.extend_from_slice(&s.wire().to_be_bytes());
    }
    // legacy_compression_methods
    body.extend_from_slice(&[1, 0]);

    // extensions
    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();

    // server_name (RFC 6066): NameList { ServerNameList }
    if let Some(name) = server_name {
        let name_bytes = name.as_bytes();
        let mut server_name_ext = Vec::new();
        let mut name_list = Vec::new();
        name_list.push(0); // host_name
        name_list.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        name_list.extend_from_slice(name_bytes);
        server_name_ext.extend_from_slice(&(name_list.len() as u16).to_be_bytes());
        server_name_ext.extend_from_slice(&name_list);
        exts.push((EXT_SERVER_NAME, server_name_ext));
    }

    // supported_groups
    let mut groups = Vec::new();
    groups.extend_from_slice(&[0x00, 0x02, 0x00, 0x1d]); // list len 2, X25519
    exts.push((EXT_SUPPORTED_GROUPS, groups));

    // signature_algorithms
    let mut sigs = Vec::new();
    sigs.extend_from_slice(&(SIGNATURE_SCHEMES.len() as u16 * 2).to_be_bytes());
    for s in SIGNATURE_SCHEMES {
        sigs.extend_from_slice(&s.to_be_bytes());
    }
    exts.push((EXT_SIGNATURE_ALGORITHMS, sigs));

    // supported_versions: 0x0304
    let mut versions = Vec::new();
    versions.extend_from_slice(&[0x02, 0x03, 0x04]);
    exts.push((EXT_SUPPORTED_VERSIONS, versions));

    // key_share: one X25519 entry
    let mut ks = Vec::new();
    ks.extend_from_slice(&[0x00, 0x24]); // 2 bytes list len = 36
    ks.extend_from_slice(&GROUP_X25519.to_be_bytes());
    ks.extend_from_slice(&[0x00, 0x20]); // 32-byte key
    ks.extend_from_slice(key_share);
    exts.push((EXT_KEY_SHARE, ks));

    // ALPN (RFC 7301)
    if !alpn.is_empty() {
        let mut alpn_body = Vec::new();
        let mut proto_list = Vec::new();
        for p in alpn {
            proto_list.push(p.len() as u8);
            proto_list.extend_from_slice(p);
        }
        alpn_body.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
        alpn_body.extend_from_slice(&proto_list);
        exts.push((EXT_ALPN, alpn_body));
    }

    let mut ext_bytes = Vec::new();
    for (t, c) in exts {
        ext_bytes.extend_from_slice(&t.to_be_bytes());
        ext_bytes.extend_from_slice(&(c.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(&c);
    }
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);

    encode_hs(HS_CLIENT_HELLO, &body)
}

// ---------------------------------------------------------------------
// ServerHello parsing
// ---------------------------------------------------------------------

/// Result of parsing a ServerHello.
struct ServerHelloInfo {
    random: [u8; 32],
    suite: CipherSuite,
    key_share: [u8; 32],
    /// The echoed legacy_session_id (must equal the one we sent).
    session_id: Vec<u8>,
}

fn parse_server_hello(body: &[u8]) -> TlsResult<ServerHelloInfo> {
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
    let session_id = c
        .take(sid_len)
        .ok_or_else(|| TlsError::Protocol("bad SH".into()))?
        .to_vec();
    let suite_wire = c.u16().ok_or_else(|| TlsError::Protocol("bad SH".into()))?;
    let suite = CipherSuite::from_wire(suite_wire)
        .ok_or_else(|| TlsError::Protocol("unsupported suite".into()))?;
    let comp = c.u8().ok_or_else(|| TlsError::Protocol("bad SH".into()))?;
    if comp != 0 {
        return Err(TlsError::Protocol("bad SH compression".into()));
    }
    let exts =
        parse_extensions(c.rest()).ok_or_else(|| TlsError::Protocol("bad SH exts".into()))?;
    let mut key_share = None;
    let mut saw_supported_versions = false;
    for e in exts {
        match e.ext_type {
            EXT_SUPPORTED_VERSIONS => {
                let mut v = Cur::new(e.content);
                let ver = v
                    .u16()
                    .ok_or_else(|| TlsError::Protocol("bad SH ver".into()))?;
                if ver != 0x0304 {
                    return Err(TlsError::Protocol("server does not speak TLS 1.3".into()));
                }
                saw_supported_versions = true;
            }
            EXT_KEY_SHARE => {
                let mut v = Cur::new(e.content);
                let group = v
                    .u16()
                    .ok_or_else(|| TlsError::Protocol("bad SH ks".into()))?;
                let klen = v
                    .u16()
                    .ok_or_else(|| TlsError::Protocol("bad SH ks".into()))?
                    as usize;
                if group != GROUP_X25519 || klen != 32 {
                    return Err(TlsError::Protocol("unexpected key share".into()));
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(
                    v.take(32)
                        .ok_or_else(|| TlsError::Protocol("bad SH ks".into()))?,
                );
                key_share = Some(k);
            }
            _ => {}
        }
    }
    if !saw_supported_versions || key_share.is_none() {
        return Err(TlsError::Protocol("SH missing required extensions".into()));
    }
    Ok(ServerHelloInfo {
        random,
        suite,
        key_share: key_share.unwrap(),
        session_id,
    })
}

// ---------------------------------------------------------------------
// EncryptedExtensions parsing
// ---------------------------------------------------------------------

fn parse_encrypted_extensions(body: &[u8]) -> TlsResult<Option<Vec<u8>>> {
    let exts = parse_extensions(body).ok_or_else(|| TlsError::Protocol("bad EE".into()))?;
    let mut alpn = None;
    for e in exts {
        if e.ext_type == EXT_ALPN {
            let mut c = Cur::new(e.content);
            let list_len =
                c.u16()
                    .ok_or_else(|| TlsError::Protocol("bad alpn".into()))? as usize;
            let list = c
                .take(list_len)
                .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?;
            let mut lc = Cur::new(list);
            let plen =
                lc.u8()
                    .ok_or_else(|| TlsError::Protocol("bad alpn".into()))? as usize;
            let proto = lc
                .take(plen)
                .ok_or_else(|| TlsError::Protocol("bad alpn".into()))?;
            if !lc.done() {
                return Err(TlsError::Protocol("bad alpn".into()));
            }
            alpn = Some(proto.to_vec());
        }
    }
    Ok(alpn)
}

// ---------------------------------------------------------------------
// Certificate parsing
// ---------------------------------------------------------------------

/// Parse a TLS 1.3 Certificate message and return all certificate
/// DER entries (leaf first).
fn parse_certificate_list(body: &[u8]) -> TlsResult<Vec<Vec<u8>>> {
    let mut c = Cur::new(body);
    let ctx_len = c
        .u8()
        .ok_or_else(|| TlsError::Protocol("bad cert".into()))? as usize;
    c.take(ctx_len)
        .ok_or_else(|| TlsError::Protocol("bad cert".into()))?;
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
        let ext_len = lc
            .u16()
            .ok_or_else(|| TlsError::Protocol("bad cert".into()))? as usize;
        lc.take(ext_len)
            .ok_or_else(|| TlsError::Protocol("bad cert".into()))?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// CertificateVerify parsing
// ---------------------------------------------------------------------

pub(crate) struct CertVerify {
    pub(crate) scheme: u16,
    pub(crate) signature: Vec<u8>,
}

fn parse_cert_verify(body: &[u8]) -> TlsResult<CertVerify> {
    let mut c = Cur::new(body);
    let scheme = c.u16().ok_or_else(|| TlsError::Protocol("bad CV".into()))?;
    let sig_len = c.u16().ok_or_else(|| TlsError::Protocol("bad CV".into()))? as usize;
    let signature = c
        .take(sig_len)
        .ok_or_else(|| TlsError::Protocol("bad CV".into()))?
        .to_vec();
    if !c.done() {
        return Err(TlsError::Protocol("bad CV".into()));
    }
    Ok(CertVerify { scheme, signature })
}

/// The signature message for CertificateVerify (RFC 8446 §4.4.3).
fn cert_verify_message(handshake_hash: &[u8], client: bool) -> Vec<u8> {
    let context: &[u8] = if client {
        b"TLS 1.3, client CertificateVerify\x00"
    } else {
        b"TLS 1.3, server CertificateVerify\x00"
    };
    let mut out = vec![0x20u8; 64];
    out.extend_from_slice(context);
    out.extend_from_slice(handshake_hash);
    out
}

/// Verify a CertificateVerify signature given the peer's SPKI and the
/// transcript hash. Returns Ok(()) if valid.
pub(crate) fn verify_cert_verify(
    cv: &CertVerify,
    spki: &super::x509::Spki,
    handshake_hash: &[u8],
    client: bool,
) -> TlsResult<()> {
    use super::crypto::rsa::{verify_rsa_pkcs1v15, verify_rsa_pss, RsaPublicKey};
    use super::crypto::{ecdsa, ed25519};
    use super::x509::der::{
        parse_rsa_public_key, OID_EC_PUBLIC_KEY, OID_ED25519, OID_RSA_ENCRYPTION,
    };

    let msg = cert_verify_message(handshake_hash, client);
    let hash = {
        let mut d = super::crypto::hash::Sha256::new();
        d.update(&msg);
        d.finalize()
    };

    if spki.oid == OID_RSA_ENCRYPTION {
        let (n, e) = parse_rsa_public_key(&spki.key)
            .ok_or_else(|| TlsError::Certificate("bad RSA SPKI".into()))?;
        let key = RsaPublicKey { n, e };
        let ok = match cv.scheme {
            0x0804 | 0x0401 => verify_rsa_pkcs1v15(&key, false, &hash, &cv.signature),
            0x0805 | 0x0501 => {
                let h384 = {
                    let mut d = super::crypto::hash::Sha384::new();
                    d.update(&msg);
                    d.finalize()
                };
                verify_rsa_pkcs1v15(&key, true, &h384, &cv.signature)
            }
            0x0809 => verify_rsa_pss(&key, false, &hash, &cv.signature),
            0x080a => {
                let h384 = {
                    let mut d = super::crypto::hash::Sha384::new();
                    d.update(&msg);
                    d.finalize()
                };
                verify_rsa_pss(&key, true, &h384, &cv.signature)
            }
            _ => false,
        };
        if ok {
            Ok(())
        } else {
            Err(TlsError::Certificate(
                "RSA signature verification failed".into(),
            ))
        }
    } else if spki.oid == OID_EC_PUBLIC_KEY {
        if cv.scheme != 0x0403 || spki.key.len() != 65 || spki.key[0] != 0x04 {
            return Err(TlsError::Certificate("unsupported EC signature".into()));
        }
        let mut qx = [0u8; 32];
        let mut qy = [0u8; 32];
        qx.copy_from_slice(&spki.key[1..33]);
        qy.copy_from_slice(&spki.key[33..65]);
        if ecdsa::verify_der(&qx, &qy, &hash, &cv.signature) {
            Ok(())
        } else {
            Err(TlsError::Certificate(
                "ECDSA signature verification failed".into(),
            ))
        }
    } else if spki.oid == OID_ED25519 {
        if cv.scheme != 0x0807 || spki.key.len() != 32 {
            return Err(TlsError::Certificate(
                "unsupported Ed25519 signature".into(),
            ));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&spki.key);
        let mut sig = [0u8; 64];
        if cv.signature.len() != 64 {
            return Err(TlsError::Certificate("bad Ed25519 signature length".into()));
        }
        sig.copy_from_slice(&cv.signature);
        if ed25519::verify(&pk, &msg, &sig) {
            Ok(())
        } else {
            Err(TlsError::Certificate(
                "Ed25519 signature verification failed".into(),
            ))
        }
    } else {
        Err(TlsError::Certificate("unknown key type".into()))
    }
}

// ---------------------------------------------------------------------
// Finished
// ---------------------------------------------------------------------

/// Compute the Finished verify_data.
pub(crate) fn finished_verify_data(
    ks: &KeySchedule,
    secret: &[u8],
    transcript_hash: &[u8],
) -> Vec<u8> {
    let fk = ks.finished_key(secret);
    let mut d = ks.suite().hash().new_digest();
    hmac(d.as_mut(), &fk, transcript_hash)
}

// ---------------------------------------------------------------------
// Client handshake
// ---------------------------------------------------------------------

/// Client-side handshake driver.
/// Fill `buf` from OS entropy, failing the handshake when the source is
/// unavailable. Never proceed with zeroed bytes: an all-zero X25519
/// private key makes the ECDHE shared secret predictable.
fn fill_entropy(buf: &mut [u8]) -> TlsResult<()> {
    if super::crypto::rng::fill_random(buf) {
        Ok(())
    } else {
        Err(TlsError::Internal(
            "cryptographic RNG unavailable; refusing to generate a predictable key".into(),
        ))
    }
}

pub(crate) struct ClientHandshake {
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) server_name: Option<String>,
    pub(crate) verify: bool,
}

impl ClientHandshake {
    /// Run the full client handshake over `io` and return the negotiated
    /// application keys.
    pub(crate) fn run<R: crate::courierust_io::Read, W: crate::courierust_io::Write>(
        &self,
        io: &mut super::TlsIo<R, W>,
        roots: &super::x509::RootStore,
        now: i64,
    ) -> TlsResult<HandshakeResult> {
        // 1. ClientHello. Entropy is mandatory: continuing with a failed
        //    OS entropy source would yield an all-zero X25519 private
        //    key (predictable ECDHE → compromised session keys), so the
        //    handshake fails closed instead.
        let mut random = [0u8; 32];
        fill_entropy(&mut random)?;
        let mut priv_key = [0u8; 32];
        fill_entropy(&mut priv_key)?;
        let pub_key = x25519::x25519(&priv_key, &x25519::BASE_POINT);
        let ch = build_client_hello(&random, &pub_key, &self.alpn, self.server_name.as_deref());
        io.write_plaintext_record(CONTENT_HANDSHAKE, &ch)?;

        // 2. ServerHello. The transcript is created *after* the suite is
        //    known: RFC 8446 §4.4.1 uses the negotiated suite's hash for
        //    every message, including the ClientHello. Creating it with
        //    SHA-256 up front is wrong when the server picks
        //    TLS_AES_256_GCM_SHA384 (OpenSSL's default preference), which
        //    would make both sides derive different handshake keys and
        //    fail with bad_record_mac.
        let (_, sh_body) = io.read_plaintext_handshake()?;
        let sh = parse_server_hello(&sh_body)?;
        // RFC 8446 §4.1.3: the echoed session id must match the one we
        // sent (we send an empty one).
        if !sh.session_id.is_empty() {
            return Err(TlsError::Protocol("ServerHello session id mismatch".into()));
        }

        let mut transcript = Transcript::new(sh.suite.hash());
        transcript.update(&ch);
        let sh_msg = encode_hs(HS_SERVER_HELLO, &sh_body);
        transcript.update(&sh_msg);

        // 3. ECDHE + key schedule
        let shared = x25519::x25519(&priv_key, &sh.key_share);
        let th = transcript.current_hash();
        let mut ks = KeySchedule::handshake(sh.suite, &shared, &th);
        let _ = sh.random;

        // 4. Encrypted flight (EncryptedExtensions, Certificate,
        //    CertificateVerify, Finished) — decrypted with the server
        //    handshake keys.
        let s_hs_keys = ks.server_handshake_keys();
        let plaintext = io.read_encrypted_handshake(sh.suite, &s_hs_keys)?;
        let mut messages = Vec::new();
        let mut rest = &plaintext[..];
        while !rest.is_empty() {
            let m =
                parse_hs(rest).ok_or_else(|| TlsError::Protocol("bad handshake stream".into()))?;
            let total = 4 + m.body.len();
            messages.push((m.msg_type, m.body.to_vec()));
            rest = &rest[total..];
        }

        let mut peer_chain = None;
        let mut cv = None;
        let mut negotiated_alpn = None;
        let mut saw_ee = false;
        for (t, body) in &messages {
            match *t {
                HS_ENCRYPTED_EXTENSIONS => {
                    negotiated_alpn = parse_encrypted_extensions(body)?;
                    saw_ee = true;
                }
                HS_CERTIFICATE => {
                    peer_chain = Some(parse_certificate_list(body)?);
                }
                HS_CERTIFICATE_VERIFY => {
                    cv = Some(parse_cert_verify(body)?);
                }
                HS_FINISHED => {}
                _ => {
                    return Err(TlsError::Protocol("unexpected server message".into()));
                }
            }
        }
        if !saw_ee {
            return Err(TlsError::Protocol("missing EncryptedExtensions".into()));
        }
        let peer_chain =
            peer_chain.ok_or_else(|| TlsError::Protocol("missing Certificate".into()))?;
        if peer_chain.is_empty() {
            return Err(TlsError::Protocol("empty certificate list".into()));
        }
        let peer_cert_der = peer_chain[0].clone();
        let cv = cv.ok_or_else(|| TlsError::Protocol("missing CertificateVerify".into()))?;

        for (t, body) in &messages {
            if *t == HS_ENCRYPTED_EXTENSIONS || *t == HS_CERTIFICATE {
                transcript.update(&encode_hs(*t, body));
            }
        }
        let cv_hash = transcript.current_hash();

        let leaf = super::x509::parse_certificate(&peer_cert_der)?;
        let spki = leaf.spki.clone();
        if self.verify {
            let name = self.server_name.as_deref().unwrap_or("");
            if !super::x509::hostname_matches(name, &leaf.dns_names, &leaf.ip_names) {
                return Err(TlsError::Certificate("hostname mismatch".into()));
            }
            super::x509::validate_chain(roots, &peer_chain, now)?;
            // RFC 5280 §4.2.1.12: a leaf with an EKU extension must
            // permit TLS server authentication.
            if !super::x509::has_server_auth_eku(&leaf) {
                return Err(TlsError::Certificate(
                    "leaf certificate lacks TLS serverAuth EKU".into(),
                ));
            }
        }

        // Verify the CertificateVerify signature.
        verify_cert_verify(&cv, &spki, &cv_hash, false)?;

        // Add CV to transcript.
        transcript.update(&encode_hs(HS_CERTIFICATE_VERIFY, &cv_body(&messages)));

        // Verify server Finished (hash before Finished).
        let finished_body = messages
            .iter()
            .find(|(t, _)| *t == HS_FINISHED)
            .map(|(_, b)| b.clone())
            .ok_or_else(|| TlsError::Protocol("missing Finished".into()))?;
        let server_fin_hash = transcript.current_hash();
        let expected_fin = finished_verify_data(&ks, ks.server_handshake(), &server_fin_hash);
        if !constant_time_eq(&expected_fin, &finished_body) {
            return Err(TlsError::Alert {
                level: 2,
                description: 51, // decrypt_error
            });
        }

        // Add server Finished to transcript; derive app secrets.
        transcript.update(&encode_hs(HS_FINISHED, &finished_body));
        let after_fin_hash = transcript.current_hash();
        ks.application(&after_fin_hash)?;

        // 5. Client Finished (hash before client Finished).
        let client_fin_hash = transcript.current_hash();
        let client_fin = finished_verify_data(&ks, ks.client_handshake(), &client_fin_hash);
        let fin_msg = encode_hs(HS_FINISHED, &client_fin);
        let c_hs_keys = ks.client_handshake_keys();
        io.write_encrypted_record(sh.suite, &c_hs_keys, CONTENT_HANDSHAKE, &fin_msg)?;
        transcript.update(&fin_msg);

        // 6. Application keys.
        let write = ks.client_application_keys();
        let read = ks.server_application_keys();
        Ok(HandshakeResult {
            suite: sh.suite,
            keys: AppKeys { write, read },
            alpn: negotiated_alpn,
            server_name: self.server_name.clone(),
            peer_cert: Some(peer_cert_der),
        })
    }
}

/// Recover the raw body bytes of the CertificateVerify message from the
/// message list (used to continue the transcript).
fn cv_body(messages: &[(u8, Vec<u8>)]) -> Vec<u8> {
    messages
        .iter()
        .find(|(t, _)| *t == HS_CERTIFICATE_VERIFY)
        .map(|(_, b)| b.clone())
        .unwrap_or_default()
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

// ---------------------------------------------------------------------
// Server handshake
// ---------------------------------------------------------------------

/// Server-side handshake driver.
pub(crate) struct ServerHandshake {
    pub(crate) identity: super::Identity,
    pub(crate) alpn: Vec<Vec<u8>>,
}

impl ServerHandshake {
    /// Run the full server handshake over `io`.
    pub(crate) fn run<R: crate::courierust_io::Read, W: crate::courierust_io::Write>(
        &self,
        io: &mut super::TlsIo<R, W>,
    ) -> TlsResult<HandshakeResult> {
        // 1. Read ClientHello.
        let (_, ch_body) = io.read_plaintext_handshake()?;
        let ch = parse_client_hello(&ch_body)?;

        let mut transcript = Transcript::new(ch.suite.hash());
        transcript.update(&encode_hs(HS_CLIENT_HELLO, &ch_body));

        // 2. ECDHE + ServerHello. Same fail-closed entropy requirement as
        //    the client: an all-zero server private key would make the
        //    session keys predictable to a passive attacker.
        let mut s_priv = [0u8; 32];
        fill_entropy(&mut s_priv)?;
        let s_pub = x25519::x25519(&s_priv, &x25519::BASE_POINT);
        let shared = x25519::x25519(&s_priv, &ch.key_share);
        let mut random = [0u8; 32];
        fill_entropy(&mut random)?;
        let sh = build_server_hello(&random, &s_pub, ch.suite, &ch.session_id);
        io.write_plaintext_record(CONTENT_HANDSHAKE, &sh)?;
        let sh_body = sh[4..].to_vec();
        transcript.update(&encode_hs(HS_SERVER_HELLO, &sh_body));

        let th = transcript.current_hash();
        let mut ks = KeySchedule::handshake(ch.suite, &shared, &th);

        // 3. EncryptedExtensions, Certificate, CertificateVerify, Finished.
        let mut ee_body = Vec::new();
        // ALPN (RFC 7301): the server selects exactly ONE protocol from
        // the client's offer, in server-preference order.
        let negotiated_alpn = self
            .alpn
            .iter()
            .find(|p| ch.alpn.iter().any(|c| c == *p))
            .cloned();
        let mut ee_exts: Vec<(u16, Vec<u8>)> = Vec::new();
        if let Some(proto) = &negotiated_alpn {
            let mut proto_list = Vec::new();
            proto_list.push(proto.len() as u8);
            proto_list.extend_from_slice(proto);
            let mut alpn_body = Vec::new();
            alpn_body.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
            alpn_body.extend_from_slice(&proto_list);
            ee_exts.push((EXT_ALPN, alpn_body));
        }
        let mut ee_bytes = Vec::new();
        for (t, c) in ee_exts {
            ee_bytes.extend_from_slice(&t.to_be_bytes());
            ee_bytes.extend_from_slice(&(c.len() as u16).to_be_bytes());
            ee_bytes.extend_from_slice(&c);
        }
        ee_body.extend_from_slice(&(ee_bytes.len() as u16).to_be_bytes());
        ee_body.extend_from_slice(&ee_bytes);
        let ee = encode_hs(HS_ENCRYPTED_EXTENSIONS, &ee_body);

        // Certificate message.
        let mut cert_body = Vec::new();
        cert_body.push(0); // certificate_request_context (empty)
        let mut entry_list = Vec::new();
        for c in &self.identity.cert_chain {
            entry_list.extend_from_slice(&[
                (c.len() >> 16) as u8,
                (c.len() >> 8) as u8,
                c.len() as u8,
            ]);
            entry_list.extend_from_slice(c);
            entry_list.extend_from_slice(&[0x00, 0x00]); // entry extensions
        }
        cert_body.extend_from_slice(&[
            (entry_list.len() >> 16) as u8,
            (entry_list.len() >> 8) as u8,
            entry_list.len() as u8,
        ]);
        cert_body.extend_from_slice(&entry_list);
        let cert = encode_hs(HS_CERTIFICATE, &cert_body);

        // Update transcript with EE + Certificate.
        transcript.update(&ee);
        transcript.update(&cert);

        // CertificateVerify: sign the transcript hash. Per RFC 8446
        // §4.4.3 the signature is computed over the concatenation
        // `64 x 0x20 || "TLS 1.3, server CertificateVerify" || 0x00 ||
        // transcript-hash` (the digest schemes hash that content; Ed25519
        // signs it verbatim).
        let cv_hash = transcript.current_hash();
        let sig_content = cert_verify_message(&cv_hash, false);
        let cv = match super::server_sign(&self.identity, &sig_content)? {
            Some((scheme, signature)) => {
                let mut cv_body = Vec::new();
                cv_body.extend_from_slice(&scheme.to_be_bytes());
                cv_body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
                cv_body.extend_from_slice(&signature);
                encode_hs(HS_CERTIFICATE_VERIFY, &cv_body)
            }
            None => {
                // No signing identity configured — reject (server must
                // authenticate).
                return Err(TlsError::Certificate(
                    "no server identity configured".into(),
                ));
            }
        };
        transcript.update(&cv);

        // Finished: hash before adding Finished.
        let fin_hash = transcript.current_hash();
        let fin = finished_verify_data(&ks, ks.server_handshake(), &fin_hash);
        let fin_msg = encode_hs(HS_FINISHED, &fin);
        transcript.update(&fin_msg);

        // Derive app secrets (transcript includes server Finished).
        let after_fin_hash = transcript.current_hash();
        ks.application(&after_fin_hash)?;

        // Send the encrypted flight.
        let s_hs_keys = ks.server_handshake_keys();
        let mut flight = ee;
        flight.extend_from_slice(&cert);
        flight.extend_from_slice(&cv);
        flight.extend_from_slice(&fin_msg);
        io.write_encrypted_record(ch.suite, &s_hs_keys, CONTENT_HANDSHAKE, &flight)?;

        // 4. Read client Finished.
        let c_hs_keys = ks.client_handshake_keys();
        let plaintext = io.read_encrypted_handshake(ch.suite, &c_hs_keys)?;
        // Parse the (single) Finished message.
        let m =
            parse_hs(&plaintext).ok_or_else(|| TlsError::Protocol("bad client flight".into()))?;
        if m.msg_type != HS_FINISHED {
            return Err(TlsError::Protocol("expected client Finished".into()));
        }
        let client_fin_hash = transcript.current_hash();
        let expected = finished_verify_data(&ks, ks.client_handshake(), &client_fin_hash);
        if !constant_time_eq(&expected, m.body) {
            return Err(TlsError::Alert {
                level: 2,
                description: 51,
            });
        }
        transcript.update(&plaintext);

        let write = ks.server_application_keys();
        let read = ks.client_application_keys();
        Ok(HandshakeResult {
            suite: ch.suite,
            keys: AppKeys { write, read },
            alpn: negotiated_alpn,
            server_name: ch.server_name,
            peer_cert: None,
        })
    }
}

/// Parsed ClientHello essentials.
struct ClientHelloInfo {
    suite: CipherSuite,
    key_share: [u8; 32],
    server_name: Option<String>,
    /// ALPN protocols offered by the client.
    alpn: Vec<Vec<u8>>,
    /// The client's legacy_session_id (RFC 8446 §4.1.3: the server MUST
    /// echo it verbatim in the ServerHello, or a conforming client will
    /// abort with illegal_parameter).
    session_id: Vec<u8>,
}

fn parse_client_hello(body: &[u8]) -> TlsResult<ClientHelloInfo> {
    let mut c = Cur::new(body);
    // legacy_version
    c.u16().ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
    c.take(32)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?; // random
    let sid_len = c.u8().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    if sid_len > 32 {
        return Err(TlsError::Protocol("bad CH sid".into()));
    }
    let session_id = c
        .take(sid_len)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?
        .to_vec();
    // cipher suites
    let suites_len = c.u16().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    if suites_len < 2 || !suites_len.is_multiple_of(2) {
        return Err(TlsError::Protocol("bad CH suites".into()));
    }
    let suites = c
        .take(suites_len)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
    let mut offered: Vec<u16> = Vec::new();
    for w in suites.chunks(2) {
        offered.push(u16::from_be_bytes([w[0], w[1]]));
    }
    // compression
    let comp_len = c.u8().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    c.take(comp_len)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;

    let exts =
        parse_extensions(c.rest()).ok_or_else(|| TlsError::Protocol("bad CH exts".into()))?;
    let mut key_share = None;
    let mut server_name = None;
    let mut client_alpn: Vec<Vec<u8>> = Vec::new();
    let mut saw_versions = false;
    for e in exts {
        match e.ext_type {
            EXT_SUPPORTED_VERSIONS => {
                let mut v = Cur::new(e.content);
                let list_len = v.u8().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
                let list = v
                    .take(list_len)
                    .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
                if list.contains(&0x03) && list.contains(&0x04) {
                    saw_versions = true;
                }
            }
            EXT_KEY_SHARE => {
                let mut v = Cur::new(e.content);
                let list_len = v.u16().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
                let list = v
                    .take(list_len)
                    .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
                let mut lc = Cur::new(list);
                while !lc.done() {
                    let group = lc
                        .u16()
                        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
                    let klen = lc
                        .u16()
                        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?
                        as usize;
                    let k = lc
                        .take(klen)
                        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
                    if group == GROUP_X25519 && klen == 32 {
                        let mut ks = [0u8; 32];
                        ks.copy_from_slice(k);
                        key_share = Some(ks);
                    }
                }
            }
            EXT_ALPN => {
                let mut v = Cur::new(e.content);
                let list_len = v.u16().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
                let list = v
                    .take(list_len)
                    .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
                let mut lc = Cur::new(list);
                while !lc.done() {
                    let plen = lc.u8().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
                    let p = lc
                        .take(plen)
                        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
                    client_alpn.push(p.to_vec());
                }
            }
            EXT_SERVER_NAME => {
                let mut v = Cur::new(e.content);
                let list_len = v.u16().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
                let list = v
                    .take(list_len)
                    .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
                let mut lc = Cur::new(list);
                if let Some(typ) = lc.u8() {
                    if typ == 0 {
                        let nlen = lc
                            .u16()
                            .ok_or_else(|| TlsError::Protocol("bad CH".into()))?
                            as usize;
                        if let Some(name) = lc.take(nlen) {
                            if let Ok(s) = core::str::from_utf8(name) {
                                server_name = Some(s.to_string());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if !saw_versions || key_share.is_none() {
        return Err(TlsError::Protocol("CH missing required extensions".into()));
    }
    // Choose the first offered suite we support.
    let suite = CLIENT_SUITES
        .iter()
        .copied()
        .find(|s| offered.contains(&s.wire()))
        .ok_or_else(|| TlsError::Protocol("no shared cipher suite".into()))?;
    Ok(ClientHelloInfo {
        suite,
        key_share: key_share.unwrap(),
        session_id,
        server_name,
        alpn: client_alpn,
    })
}

/// Build a ServerHello (full message) for the given suite and key share.
/// The client's `session_id` is echoed verbatim (RFC 8446 §4.1.3).
pub(crate) fn build_server_hello(
    random: &[u8; 32],
    key_share: &[u8; 32],
    suite: CipherSuite,
    session_id: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(random);
    // legacy_session_id_echo: must match the client's session id.
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.wire().to_be_bytes());
    body.push(0); // compression null

    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut ks = Vec::new();
    ks.extend_from_slice(&GROUP_X25519.to_be_bytes());
    ks.extend_from_slice(&[0x00, 0x20]);
    ks.extend_from_slice(key_share);
    exts.push((EXT_KEY_SHARE, ks));
    let mut versions = Vec::new();
    versions.extend_from_slice(&[0x03, 0x04]);
    exts.push((EXT_SUPPORTED_VERSIONS, versions));

    let mut ext_bytes = Vec::new();
    for (t, c) in exts {
        ext_bytes.extend_from_slice(&t.to_be_bytes());
        ext_bytes.extend_from_slice(&(c.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(&c);
    }
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);
    encode_hs(HS_SERVER_HELLO, &body)
}
