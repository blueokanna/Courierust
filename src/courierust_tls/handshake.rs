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
/// Synthetic `message_hash` handshake type used after a HelloRetryRequest
/// (RFC 8446 §4.4.1).
pub(crate) const HS_MESSAGE_HASH: u8 = 254;

/// HelloRetryRequest random: SHA-256("HelloRetryRequest") (RFC 8446 §4.1.3).
pub(crate) const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Extension types.
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// cookie extension (RFC 8446 §4.2.2) — sent in the HelloRetryRequest and
/// echoed verbatim by the client in the retried ClientHello.
pub(crate) const EXT_COOKIE: u16 = 0x002c;
const EXT_KEY_SHARE: u16 = 0x0033;
/// QUIC transport parameters (RFC 9001 section 5.2).
pub(crate) const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;

/// Named group for X25519.
pub(crate) const GROUP_X25519: u16 = 0x001d;

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
pub(crate) fn encode_hs(msg_type: u8, body: &[u8]) -> Vec<u8> {
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
pub(crate) fn parse_hs<'a>(buf: &'a [u8]) -> Option<HsMessage<'a>> {
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
        let len = ((buf[off + 1] as usize) << 16)
            | ((buf[off + 2] as usize) << 8)
            | buf[off + 3] as usize;
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
    /// True when the handshake was resumed from a PSK.
    pub(crate) resumed: bool,
    /// Server side: the resumption master secret, used to issue a
    /// NewSessionTicket after the handshake.
    pub(crate) resumption_master: Option<Vec<u8>>,
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

/// Build a ClientHello with an optional QUIC transport-parameters
/// extension. The ordinary TLS path passes `None`. This is the TLS 1.3
/// client hello used by the QUIC path (RFC 9001 requires TLS 1.3); the
/// TCP connector uses [`build_client_hello_negotiated`] instead so it
/// can also speak TLS 1.2.
pub(crate) fn build_client_hello_with_transport_params(
    random: &[u8; 32],
    key_share: &[u8; 32],
    alpn: &[Vec<u8>],
    server_name: Option<&str>,
    transport_params: Option<&[u8]>,
) -> Vec<u8> {
    build_client_hello_negotiated(
        random,
        Some(key_share),
        alpn,
        server_name,
        transport_params,
        true,
        false,
    )
}

/// Build a ClientHello covering a configurable version window.
///
/// * `key_share` — `Some` includes an X25519 share; `None` emits an
///   empty `client_shares` vector (RFC 8446 §4.2.8 allows requesting
///   group selection, which makes the server answer with a
///   HelloRetryRequest).
/// * `offer13` — include `supported_versions` (0x0304) and the TLS 1.3
///   suites.
/// * `offer12` — also include the TLS 1.2 AEAD ECDHE suites and the
///   `ec_point_formats` extension, so a TLS 1.2-only server can
///   negotiate TLS 1.2.
///
/// `supported_groups` always lists X25519 and secp256r1 (the latter is
/// what a TLS 1.2 ECDHE server needs); `signature_algorithms` carries
/// both the TLS 1.3 and the TLS 1.2 scheme sets.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_client_hello_negotiated(
    random: &[u8; 32],
    key_share: Option<&[u8; 32]>,
    alpn: &[Vec<u8>],
    server_name: Option<&str>,
    transport_params: Option<&[u8]>,
    offer13: bool,
    offer12: bool,
) -> Vec<u8> {
    let mut body = Vec::new();
    // legacy_version = 0x0303
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(random);
    // legacy_session_id (empty for a non-resuming client)
    body.push(0);
    // cipher_suites (big-endian u16 length): TLS 1.3 suites when
    // offering TLS 1.3, then TLS 1.2 AEAD ECDHE suites when offering
    // TLS 1.2. RFC 8446 §4.1.2: a client that supports TLS 1.3 MUST put
    // the 1.3 suites in `cipher_suites` (they are identified by the
    // 0x03 prefix) — TLS 1.2 servers simply ignore them.
    let mut suite_wires: Vec<u16> = Vec::new();
    if offer13 {
        suite_wires.extend(CLIENT_SUITES.iter().map(|s| s.wire()));
    }
    if offer12 {
        suite_wires.extend(super::tls12::CLIENT_SUITES_12.iter().map(|s| s.wire()));
    }
    body.extend_from_slice(&(suite_wires.len() as u16 * 2).to_be_bytes());
    for s in &suite_wires {
        body.extend_from_slice(&s.to_be_bytes());
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

    // supported_groups: X25519 + secp256r1.
    let mut groups = Vec::new();
    groups.extend_from_slice(&[0x00, 0x04]); // list len 4
    groups.extend_from_slice(&(0x001d_u16).to_be_bytes()); // X25519
    groups.extend_from_slice(&super::tls12::GROUP_SECP256R1.to_be_bytes()); // secp256r1
    exts.push((EXT_SUPPORTED_GROUPS, groups));

    // signature_algorithms: TLS 1.3 schemes + TLS 1.2 schemes.
    let mut sigs = Vec::new();
    let mut sig_schemes: Vec<u16> = SIGNATURE_SCHEMES.to_vec();
    sig_schemes.extend_from_slice(super::tls12::TLS12_SIGNATURE_ALGORITHMS);
    sigs.extend_from_slice(&(sig_schemes.len() as u16 * 2).to_be_bytes());
    for s in &sig_schemes {
        sigs.extend_from_slice(&s.to_be_bytes());
    }
    exts.push((EXT_SIGNATURE_ALGORITHMS, sigs));

    // ec_point_formats (required by TLS 1.2 ECDHE): uncompressed only.
    if offer12 {
        exts.push((EXT_EC_POINT_FORMATS, vec![1, 0]));
    }

    // supported_versions + key_share only when offering TLS 1.3.
    if offer13 {
        let mut versions = Vec::new();
        versions.extend_from_slice(&[0x02, 0x03, 0x04]);
        exts.push((EXT_SUPPORTED_VERSIONS, versions));

        let mut ks = Vec::new();
        match key_share {
            Some(share) => {
                ks.extend_from_slice(&[0x00, 0x24]); // 2 bytes list len = 36
                ks.extend_from_slice(&GROUP_X25519.to_be_bytes());
                ks.extend_from_slice(&[0x00, 0x20]); // 32-byte key
                ks.extend_from_slice(share);
            }
            // Empty client_shares: ask the server to pick a group.
            None => ks.extend_from_slice(&[0x00, 0x00]),
        }
        exts.push((EXT_KEY_SHARE, ks));
    }

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

    if let Some(params) = transport_params {
        exts.push((EXT_QUIC_TRANSPORT_PARAMETERS, params.to_vec()));
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

/// Whether a ServerHello negotiates TLS 1.3: true when the
/// `supported_versions` extension is present with value 0x0304. A TLS
/// 1.2 ServerHello carries no such extension. Used by the connector to
/// dispatch between the TLS 1.3 and TLS 1.2 paths.
pub(crate) fn server_hello_negotiates_tls13(body: &[u8]) -> bool {
    let mut c = Cur::new(body);
    // legacy_version (must be 0x0303), random (32), session id.
    if c.u16().is_none() || c.take(32).is_none() {
        return false;
    }
    let sid_len = match c.u8() {
        Some(n) => n as usize,
        None => return false,
    };
    if c.take(sid_len).is_none() {
        return false;
    }
    // cipher_suite (2), compression (1), then extensions.
    if c.take(3).is_none() {
        return false;
    }
    let Some(exts) = parse_extensions(c.rest()) else {
        return false;
    };
    for e in exts {
        if e.ext_type == EXT_SUPPORTED_VERSIONS {
            let mut v = Cur::new(e.content);
            if let Some(ver) = v.u16() {
                return ver == 0x0304;
            }
        }
    }
    false
}

/// Whether a ClientHello offers TLS 1.3 (`supported_versions` contains
/// 0x0304). Used by the acceptor to decide between the TLS 1.3 and
/// TLS 1.2 paths before running either state machine.
pub(crate) fn client_hello_offers_tls13(body: &[u8]) -> TlsResult<bool> {
    let mut c = Cur::new(body);
    if c.u16().is_none() || c.take(32).is_none() {
        return Err(TlsError::Protocol("bad CH".into()));
    }
    let sid_len = c.u8().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    if sid_len > 32 {
        return Err(TlsError::Protocol("bad CH sid".into()));
    }
    c.take(sid_len)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
    let suites_len = c.u16().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    if suites_len < 2 || !suites_len.is_multiple_of(2) {
        return Err(TlsError::Protocol("bad CH suites".into()));
    }
    c.take(suites_len)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
    let comp_len = c.u8().ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    c.take(comp_len)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
    let exts =
        parse_extensions(c.rest()).ok_or_else(|| TlsError::Protocol("bad CH exts".into()))?;
    for e in exts {
        if e.ext_type == EXT_SUPPORTED_VERSIONS {
            let mut v = Cur::new(e.content);
            let list_len = v
                .u8()
                .ok_or_else(|| TlsError::Protocol("bad versions".into()))?
                as usize;
            let list = v
                .take(list_len)
                .ok_or_else(|| TlsError::Protocol("bad versions".into()))?;
            let mut lc = Cur::new(list);
            while !lc.done() {
                if let Some(ver) = lc.u16() {
                    if ver == 0x0304 {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------
// ServerHello parsing
// ---------------------------------------------------------------------

/// Result of parsing a ServerHello.
pub(crate) struct ServerHelloInfo {
    pub(crate) random: [u8; 32],
    pub(crate) suite: CipherSuite,
    pub(crate) key_share: [u8; 32],
    /// The echoed legacy_session_id (must equal the one we sent).
    pub(crate) session_id: Vec<u8>,
    /// True when the server accepted our resumption PSK.
    pub(crate) resumed: bool,
}

pub(crate) fn parse_server_hello(body: &[u8]) -> TlsResult<ServerHelloInfo> {
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
    let mut resumed = false;
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
            super::session::EXT_PRE_SHARED_KEY => {
                // selected_identity must be 0 (we offer one identity).
                let mut v = Cur::new(e.content);
                let selected = v
                    .u16()
                    .ok_or_else(|| TlsError::Protocol("bad SH psk".into()))?;
                if selected != 0 {
                    return Err(TlsError::Protocol("server selected unknown PSK".into()));
                }
                if !v.done() {
                    return Err(TlsError::Protocol("bad SH psk".into()));
                }
                resumed = true;
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
        resumed,
    })
}

// ---------------------------------------------------------------------
// EncryptedExtensions parsing
// ---------------------------------------------------------------------

/// The parsed content of an EncryptedExtensions message: the negotiated
/// ALPN protocol (if any) and the QUIC transport parameters (if present).
/// Per RFC 9001 §8.2 the server's `quic_transport_parameters` extension is
/// carried in EncryptedExtensions, never in the ServerHello.
#[allow(clippy::type_complexity)]
pub(crate) fn parse_encrypted_extensions(
    body: &[u8],
) -> TlsResult<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let exts = parse_extensions(body).ok_or_else(|| TlsError::Protocol("bad EE".into()))?;
    let mut alpn = None;
    let mut transport_params = None;
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
        } else if e.ext_type == EXT_QUIC_TRANSPORT_PARAMETERS {
            transport_params = Some(e.content.to_vec());
        }
    }
    Ok((alpn, transport_params))
}

// ---------------------------------------------------------------------
// Certificate parsing
// ---------------------------------------------------------------------

/// Parse a TLS 1.3 Certificate message and return all certificate
/// DER entries (leaf first).
pub(crate) fn parse_certificate_list(body: &[u8]) -> TlsResult<Vec<Vec<u8>>> {
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

pub(crate) fn parse_cert_verify(body: &[u8]) -> TlsResult<CertVerify> {
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
pub(crate) fn cert_verify_message(handshake_hash: &[u8], client: bool) -> Vec<u8> {
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
    suite: CipherSuite,
) -> TlsResult<()> {
    use super::crypto::rsa::{verify_rsa_pkcs1v15, RsaPublicKey};
    use super::crypto::{ecdsa, ed25519};
    use super::x509::der::{
        parse_rsa_public_key, OID_EC_PUBLIC_KEY, OID_ED25519, OID_RSA_ENCRYPTION,
    };

    let msg = cert_verify_message(handshake_hash, client);
    let hash = {
        let mut d: super::crypto::hash::BoxDigest = match suite.hash() {
            super::key_schedule::SuiteHash::Sha256 => Box::<super::crypto::hash::Sha256>::default(),
            super::key_schedule::SuiteHash::Sha384 => Box::<super::crypto::hash::Sha384>::default(),
        };
        d.update(&msg);
        d.finalize()
    };

    if spki.oid == OID_RSA_ENCRYPTION {
        let (n, e) = parse_rsa_public_key(&spki.key)
            .ok_or_else(|| TlsError::Certificate("bad RSA SPKI".into()))?;
        let key = RsaPublicKey { n, e };
        // PSS verifies the *raw* certificate-verify content (RFC 8446
        // §4.4.3 / RFC 8017 §9.1: mHash = Hash(M)); PKCS#1 v1.5 signs
        // the digest of that content. Passing the pre-hashed digest to
        // the PSS path would double-hash and reject every valid
        // signature.
        let ok = match cv.scheme {
            0x0804 if suite.hash() == super::key_schedule::SuiteHash::Sha256 => {
                let mut h = super::crypto::hash::Sha256::default();
                key.verify_pss(&mut h, &msg, 32, &cv.signature)
            }
            0x0805 if suite.hash() == super::key_schedule::SuiteHash::Sha384 => {
                let mut h = super::crypto::hash::Sha384::default();
                key.verify_pss(&mut h, &msg, 48, &cv.signature)
            }
            0x0401 if suite.hash() == super::key_schedule::SuiteHash::Sha256 => {
                verify_rsa_pkcs1v15(&key, false, &hash, &cv.signature)
            }
            0x0501 if suite.hash() == super::key_schedule::SuiteHash::Sha384 => {
                verify_rsa_pkcs1v15(&key, true, &hash, &cv.signature)
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
        // TLS 1.3 fixes the ECDSA CertificateVerify scheme from the
        // negotiated cipher-suite hash: SHA-256 → 0x0403 with a P-256
        // key, SHA-384 → 0x0503 with a P-384 key. P-521 would require
        // a SHA-512 suite, which this profile does not offer, so it can
        // never appear here (identical to rustls).
        let (curve, expected_scheme) = match suite.hash() {
            super::key_schedule::SuiteHash::Sha256 => (ecdsa::Curve::P256, 0x0403),
            super::key_schedule::SuiteHash::Sha384 => (ecdsa::Curve::P384, 0x0503),
        };
        if cv.scheme != expected_scheme || spki.ec_curve != Some(curve) {
            return Err(TlsError::Certificate("unsupported EC signature".into()));
        }
        let clen = curve.coord_len();
        if spki.key.len() != 1 + 2 * clen || spki.key[0] != 0x04 {
            return Err(TlsError::Certificate("bad EC SPKI".into()));
        }
        let qx = &spki.key[1..1 + clen];
        let qy = &spki.key[1 + clen..1 + 2 * clen];
        if ecdsa::verify_der(curve, qx, qy, &hash, &cv.signature) {
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
pub(crate) fn fill_entropy(buf: &mut [u8]) -> TlsResult<()> {
    if super::crypto::rng::fill_random(buf) {
        Ok(())
    } else {
        Err(TlsError::Internal(
            "cryptographic RNG unavailable; refusing to generate a predictable key".into(),
        ))
    }
}

pub(crate) struct ClientHandshake {
    pub(crate) server_name: Option<String>,
    pub(crate) verify: bool,
    /// A resumption PSK to offer (RFC 8446 §4.2.11), with its suite.
    pub(crate) psk: Option<(Vec<u8>, CipherSuite)>,
}

impl ClientHandshake {
    /// Continue a client handshake whose ClientHello has already been
    /// sent and whose ServerHello has already been read (used by the
    /// version-negotiating connector, which must see the ServerHello to
    /// decide between the TLS 1.3 and TLS 1.2 paths).
    #[allow(clippy::too_many_arguments)]
    /// * `hrr` — when the handshake went through a HelloRetryRequest,
    ///   the `(ClientHello1, HelloRetryRequest, ClientHello2)` messages;
    ///   the transcript then starts with `message_hash(Hash(CH1)) ||
    ///   HRR || CH2` (RFC 8446 §4.4.1) instead of a single ClientHello.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_from_server_hello<
        R: crate::courierust_io::Read,
        W: crate::courierust_io::Write,
    >(
        &self,
        io: &mut super::TlsIo<R, W>,
        roots: &super::x509::RootStore,
        now: i64,
        ch: &[u8],
        _random: &[u8; 32],
        priv_key: &[u8; 32],
        sh_body: &[u8],
        hrr: Option<(&[u8], &[u8], &[u8])>,
    ) -> TlsResult<HandshakeResult> {
        let sh = parse_server_hello(sh_body)?;
        // RFC 8446 §4.1.3: the echoed session id must match the one we
        // sent (we send an empty one).
        if !sh.session_id.is_empty() {
            return Err(TlsError::Protocol("ServerHello session id mismatch".into()));
        }

        let mut transcript = Transcript::new(sh.suite.hash());
        match hrr {
            Some((ch1, hrr_msg, ch2)) => {
                transcript.update(&message_hash_message(ch1, sh.suite));
                transcript.update(hrr_msg);
                transcript.update(ch2);
            }
            None => transcript.update(ch),
        }
        let sh_msg = encode_hs(HS_SERVER_HELLO, sh_body);
        transcript.update(&sh_msg);

        // 3. ECDHE + key schedule
        let shared = x25519::x25519(priv_key, &sh.key_share);
        let th = transcript.current_hash();
        let mut ks = if sh.resumed {
            // The server accepted our resumption PSK (RFC 8446 §4.2.11);
            // the negotiated suite must be the PSK's suite.
            let (psk, psk_suite) = self
                .psk
                .clone()
                .ok_or_else(|| TlsError::Protocol("server resumed without a PSK offer".into()))?;
            if psk_suite != sh.suite {
                return Err(TlsError::Protocol(
                    "resumption cipher suite does not match the PSK".into(),
                ));
            }
            KeySchedule::handshake_with_psk(sh.suite, &shared, &psk, &th)
        } else {
            KeySchedule::handshake(sh.suite, &shared, &th)
        };
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
                    let (alpn, _transport_params) = parse_encrypted_extensions(body)?;
                    negotiated_alpn = alpn;
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
        verify_cert_verify(&cv, &spki, &cv_hash, false, sh.suite)?;

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

        // The resumption master secret (transcript = CH..client Finished)
        // lets the client derive the PSK of any NewSessionTicket it reads
        // after the handshake (RFC 8446 §7.1).
        let resumption_master = Some(ks.resumption_master(&transcript.current_hash()));

        // 6. Application keys.
        let write = ks.client_application_keys();
        let read = ks.server_application_keys();
        Ok(HandshakeResult {
            suite: sh.suite,
            keys: AppKeys { write, read },
            alpn: negotiated_alpn,
            server_name: self.server_name.clone(),
            peer_cert: Some(peer_cert_der),
            resumed: sh.resumed,
            resumption_master,
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
    /// Key used to encrypt/decrypt session tickets. `None` disables
    /// session resumption (the QUIC path passes None).
    pub(crate) ticket_key: Option<[u8; 32]>,
    /// Current Unix time (used to validate ticket age).
    pub(crate) now: i64,
}

impl ServerHandshake {
    /// Continue a server handshake whose ClientHello has already been
    /// read (used by the version-negotiating acceptor).
    pub(crate) fn run_from_client_hello<
        R: crate::courierust_io::Read,
        W: crate::courierust_io::Write,
    >(
        &self,
        io: &mut super::TlsIo<R, W>,
        ch_body: &[u8],
    ) -> TlsResult<HandshakeResult> {
        let suite_hash_pref = super::sign::tls13_suite_hash_pref(&self.identity);

        // 1. Read ClientHello. If the client supports X25519 but did not
        //    offer a share, send a HelloRetryRequest (RFC 8446 §4.1.4)
        //    and read the retried ClientHello. The transcript replaces
        //    ClientHello1 with message_hash(Hash(ClientHello1)) and then
        //    appends HelloRetryRequest and ClientHello2 (§4.4.1); a PSK
        //    binder in ClientHello2 is computed over CH1 || HRR ||
        //    Truncate(CH2) (§4.2.11.2).
        let mut ch = parse_client_hello(ch_body, suite_hash_pref)?;
        let mut transcript = Transcript::new(ch.suite.hash());
        // The ClientHello body that carries the resumption offer, plus
        // the (ClientHello1, HelloRetryRequest) pair when a retry
        // happened (the CH2 binder is over CH1 || HRR || Truncate(CH2)).
        let mut resume_body: Vec<u8> = ch_body.to_vec();
        let mut hrr_prefix: Option<(Vec<u8>, Vec<u8>)> = None;
        if ch.key_share.is_none() {
            if !ch.x25519_in_groups {
                return Err(TlsError::Protocol(
                    "no mutually supported key exchange group".into(),
                ));
            }
            let hrr = build_hello_retry_request(ch.suite, &ch.session_id);
            io.write_plaintext_record(CONTENT_HANDSHAKE, &hrr)?;
            let (ct2, ch2) = io.read_plaintext_record()?;
            if ct2 != CONTENT_HANDSHAKE || ch2.len() < 4 || ch2[0] != HS_CLIENT_HELLO {
                return Err(TlsError::Protocol("expected a retried ClientHello".into()));
            }
            let ch2_body = ch2[4..].to_vec();
            let ch2_info = parse_client_hello(&ch2_body, suite_hash_pref)?;
            let ch2_share = ch2_info.key_share.ok_or_else(|| {
                TlsError::Protocol("retried ClientHello lacks an X25519 share".into())
            })?;
            if ch2_info.suite != ch.suite {
                return Err(TlsError::Protocol(
                    "retried ClientHello changed the cipher suite".into(),
                ));
            }
            let ch1_msg = encode_hs(HS_CLIENT_HELLO, ch_body);
            transcript.update(&message_hash_message(&ch1_msg, ch.suite));
            transcript.update(&hrr);
            transcript.update(&encode_hs(HS_CLIENT_HELLO, &ch2_body));
            ch.key_share = Some(ch2_share);
            ch.session_id = ch2_info.session_id;
            ch.server_name = ch2_info.server_name;
            ch.alpn = ch2_info.alpn;
            ch.transport_params = ch2_info.transport_params;
            resume_body = ch2_body;
            hrr_prefix = Some((ch1_msg, hrr));
        } else {
            transcript.update(&encode_hs(HS_CLIENT_HELLO, ch_body));
        }

        // 1b. Resumption: a well-formed pre_shared_key offer whose ticket
        // decrypts, matches the negotiated suite, and carries a valid
        // binder resumes the session (RFC 8446 §4.2.11). Any failure
        // falls back to a full handshake (the client proceeds without the
        // PSK), except a malformed offer, which is a protocol error.
        let mut resumed = false;
        let mut resume_psk: Option<Vec<u8>> = None;
        if let Some(offer) = super::session::parse_pre_shared_key(&resume_body)? {
            if let Some(key) = self.ticket_key {
                if let Ok((ticket_suite, psk)) =
                    super::session::decrypt_ticket(&key, &offer.ticket, self.now)
                {
                    let binder_ok = match &hrr_prefix {
                        Some((ch1, hrr)) => super::session::verify_binder_hrr(
                            ch1,
                            hrr,
                            &resume_body,
                            &offer,
                            ch.suite,
                            &psk,
                        ),
                        None => {
                            super::session::verify_binder(&resume_body, &offer, ch.suite, &psk)
                        }
                    };
                    if ticket_suite == ch.suite && binder_ok {
                        resumed = true;
                        resume_psk = Some(psk);
                    }
                }
            }
        }

        // 2. ECDHE + ServerHello. Same fail-closed entropy requirement as
        //    the client: an all-zero server private key would make the
        //    session keys predictable to a passive attacker.
        let ch_share = ch.key_share.expect("X25519 share resolved above");
        let mut s_priv = [0u8; 32];
        fill_entropy(&mut s_priv)?;
        let s_pub = x25519::x25519(&s_priv, &x25519::BASE_POINT);
        let shared = x25519::x25519(&s_priv, &ch_share);
        let mut random = [0u8; 32];
        fill_entropy(&mut random)?;
        let sh = if resumed {
            super::session::build_server_hello_psk(&random, &s_pub, ch.suite, &ch.session_id)
        } else {
            build_server_hello(&random, &s_pub, ch.suite, &ch.session_id)
        };
        io.write_plaintext_record(CONTENT_HANDSHAKE, &sh)?;
        let sh_body = sh[4..].to_vec();
        transcript.update(&encode_hs(HS_SERVER_HELLO, &sh_body));

        let th = transcript.current_hash();
        let mut ks = if resumed {
            let psk = resume_psk.expect("resume psk set above");
            KeySchedule::handshake_with_psk(ch.suite, &shared, &psk, &th)
        } else {
            KeySchedule::handshake(ch.suite, &shared, &th)
        };

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
        let cv = match super::server_sign(&self.identity, &sig_content, ch.suite)? {
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

        // The application keys start a fresh record sequence space
        // (RFC 8446 §5.2: sequence numbers reset at each key change).
        io.reset_sequences();

        // 5. Issue a NewSessionTicket (session resumption, RFC 8446
        //    §4.6.1). Sent after the handshake, protected by the server
        //    application keys. The PSK is derived from the resumption
        //    master secret with a fresh nonce and encrypted inside the
        //    ticket with the server-held ticket key.
        if let Some(key) = self.ticket_key {
            let mut nonce = [0u8; 8];
            fill_entropy(&mut nonce)?;
            let psk = ks.resumption_psk(&transcript.current_hash(), &nonce);
            let ticket = super::session::encrypt_ticket(&key, ch.suite, &psk, self.now);
            let msg = super::session::build_new_session_ticket(
                super::session::SESSION_LIFETIME_SECS as u32,
                &nonce,
                &ticket,
            );
            io.write_encrypted_record(ch.suite, &write, CONTENT_HANDSHAKE, &msg)?;
        }

        Ok(HandshakeResult {
            suite: ch.suite,
            keys: AppKeys { write, read },
            alpn: negotiated_alpn,
            server_name: ch.server_name,
            peer_cert: None,
            resumed,
            resumption_master: None,
        })
    }
}

/// Parsed ClientHello essentials.
pub(crate) struct ClientHelloInfo {
    pub(crate) suite: CipherSuite,
    /// The client's X25519 key share, when one was offered.
    pub(crate) key_share: Option<[u8; 32]>,
    /// Whether X25519 appears in the client's `supported_groups` (used to
    /// decide between a HelloRetryRequest and a hard failure).
    pub(crate) x25519_in_groups: bool,
    pub(crate) server_name: Option<String>,
    /// ALPN protocols offered by the client.
    pub(crate) alpn: Vec<Vec<u8>>,
    /// The client's legacy_session_id (RFC 8446 §4.1.3: the server MUST
    /// echo it verbatim in the ServerHello, or a conforming client will
    /// abort with illegal_parameter).
    pub(crate) session_id: Vec<u8>,
    /// QUIC transport parameters, when present.
    pub(crate) transport_params: Option<Vec<u8>>,
}

/// Parse a ClientHello. `suite_hash_pref` (from the server identity key)
/// restricts the chosen cipher suite to one whose hash matches the EC
/// identity curve, so the CertificateVerify scheme is always valid.
pub(crate) fn parse_client_hello(
    body: &[u8],
    suite_hash_pref: Option<super::key_schedule::SuiteHash>,
) -> TlsResult<ClientHelloInfo> {
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
    let mut x25519_in_groups = false;
    let mut server_name = None;
    let mut client_alpn: Vec<Vec<u8>> = Vec::new();
    let mut saw_versions = false;
    let mut transport_params = None;
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
            EXT_SUPPORTED_GROUPS => {
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
                    if group == GROUP_X25519 {
                        x25519_in_groups = true;
                    }
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
            EXT_QUIC_TRANSPORT_PARAMETERS => {
                if transport_params.is_some() {
                    return Err(TlsError::Protocol(
                        "duplicate QUIC transport parameters".into(),
                    ));
                }
                transport_params = Some(e.content.to_vec());
            }
            _ => {}
        }
    }
    if !saw_versions {
        return Err(TlsError::Protocol("CH missing supported_versions".into()));
    }
    // Choose the first offered suite we support whose hash matches the
    // identity key (for EC identities the TLS 1.3 ECDSA scheme is fixed
    // by the suite hash).
    let suite = CLIENT_SUITES
        .iter()
        .copied()
        .filter(|s| suite_hash_pref.is_none_or(|h| s.hash() == h))
        .find(|s| offered.contains(&s.wire()))
        .ok_or_else(|| TlsError::Protocol("no shared cipher suite".into()))?;
    Ok(ClientHelloInfo {
        suite,
        key_share,
        x25519_in_groups,
        session_id,
        server_name,
        alpn: client_alpn,
        transport_params,
    })
}

/// Whether a ServerHello is actually a HelloRetryRequest (RFC 8446
/// §4.1.3: the random value equals SHA-256("HelloRetryRequest")).
pub(crate) fn is_hello_retry_request(body: &[u8]) -> bool {
    let mut c = Cur::new(body);
    if c.u16().is_none() {
        return false;
    }
    match c.take(32) {
        Some(r) => r == HRR_RANDOM,
        None => false,
    }
}

/// A parsed HelloRetryRequest (RFC 8446 §4.1.4).
pub(crate) struct HrrInfo {
    /// The group the server wants a share for (key_share extension).
    pub(crate) selected_group: u16,
}

/// Parse a HelloRetryRequest body. The client MUST verify that
/// `supported_versions` is 0x0304 and that `key_share` carries the
/// selected group; the caller then decides whether it can comply.
pub(crate) fn parse_hello_retry_request(body: &[u8]) -> Result<HrrInfo, TlsError> {
    let mut c = Cur::new(body);
    c.u16()
        .ok_or_else(|| TlsError::Protocol("bad HRR".into()))?; // legacy_version
    let random = c
        .take(32)
        .ok_or_else(|| TlsError::Protocol("bad HRR".into()))?;
    if random != HRR_RANDOM {
        return Err(TlsError::Protocol("not a HelloRetryRequest".into()));
    }
    let sid_len = c.u8().ok_or_else(|| TlsError::Protocol("bad HRR".into()))? as usize;
    c.take(sid_len)
        .ok_or_else(|| TlsError::Protocol("bad HRR".into()))?; // session id echo
    c.u16()
        .ok_or_else(|| TlsError::Protocol("bad HRR".into()))?; // cipher_suite
    let comp = c.u8().ok_or_else(|| TlsError::Protocol("bad HRR".into()))?;
    if comp != 0 {
        return Err(TlsError::Protocol("bad HRR compression".into()));
    }
    let exts =
        parse_extensions(c.rest()).ok_or_else(|| TlsError::Protocol("bad HRR exts".into()))?;
    let mut selected_group = None;
    let mut saw_versions = false;
    for e in exts {
        match e.ext_type {
            EXT_SUPPORTED_VERSIONS => {
                let mut v = Cur::new(e.content);
                let ver = v
                    .u16()
                    .ok_or_else(|| TlsError::Protocol("bad HRR ver".into()))?;
                if ver != 0x0304 {
                    return Err(TlsError::Protocol(
                        "HRR selected a version below TLS 1.3".into(),
                    ));
                }
                saw_versions = true;
            }
            EXT_KEY_SHARE => {
                let mut v = Cur::new(e.content);
                selected_group = Some(
                    v.u16()
                        .ok_or_else(|| TlsError::Protocol("bad HRR key_share".into()))?,
                );
            }
            EXT_COOKIE => {
                // Validate the stateless cookie's framing; this client has
                // no re-issue path, so the content is not retained.
                let mut v = Cur::new(e.content);
                let len = v
                    .u16()
                    .ok_or_else(|| TlsError::Protocol("bad HRR cookie".into()))?
                    as usize;
                v.take(len)
                    .ok_or_else(|| TlsError::Protocol("bad HRR cookie".into()))?;
            }
            _ => {}
        }
    }
    if !saw_versions || selected_group.is_none() {
        return Err(TlsError::Protocol("HRR missing required extensions".into()));
    }
    Ok(HrrInfo {
        selected_group: selected_group.unwrap(),
    })
}

/// Build a HelloRetryRequest (full message) requesting an X25519 share,
/// echoing the client's session id (RFC 8446 §4.1.4).
pub(crate) fn build_hello_retry_request(suite: CipherSuite, session_id: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&HRR_RANDOM);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.wire().to_be_bytes());
    body.push(0); // legacy_compression_method
                  // Extensions: supported_versions (selected) + key_share (selected_group).
    let mut exts = Vec::new();
    let mut sv = Vec::new();
    sv.extend_from_slice(&0x0304u16.to_be_bytes());
    exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
    exts.extend_from_slice(&(sv.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sv);
    let mut ks = Vec::new();
    ks.extend_from_slice(&GROUP_X25519.to_be_bytes());
    exts.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
    exts.extend_from_slice(&(ks.len() as u16).to_be_bytes());
    exts.extend_from_slice(&ks);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    encode_hs(HS_SERVER_HELLO, &body)
}

/// RFC 8446 §4.4.1: replace ClientHello1 in the transcript with the
/// synthetic `message_hash` handshake message carrying Hash(ClientHello1).
fn message_hash_message(ch1: &[u8], suite: CipherSuite) -> Vec<u8> {
    let mut d = suite.hash().new_digest();
    d.update(ch1);
    let h = d.finalize();
    encode_hs(HS_MESSAGE_HASH, &h)
}

/// Build a ServerHello (full message) for the given suite and key share.
/// The client's `session_id` is echoed verbatim (RFC 8446 §4.1.3).
pub(crate) fn build_server_hello(
    random: &[u8; 32],
    key_share: &[u8; 32],
    suite: CipherSuite,
    session_id: &[u8],
) -> Vec<u8> {
    build_server_hello_with_transport_params(random, key_share, suite, session_id, None)
}

/// Build a ServerHello with an optional QUIC transport-parameters
/// extension. The ordinary TLS path passes `None`.
pub(crate) fn build_server_hello_with_transport_params(
    random: &[u8; 32],
    key_share: &[u8; 32],
    suite: CipherSuite,
    session_id: &[u8],
    transport_params: Option<&[u8]>,
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
    if let Some(params) = transport_params {
        exts.push((EXT_QUIC_TRANSPORT_PARAMETERS, params.to_vec()));
    }

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
