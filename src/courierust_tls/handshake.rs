//! TLS 1.3 handshake state machines (RFC 8446 §4): client and server
//! sides of the 1-RTT handshake, X25519 only. The Finished verify_data
//! is taken over the transcript hash *before* the Finished message is
//! appended (as in rustls/OpenSSL).

use super::crypto::hash::{Digest, Sha256};
use super::crypto::hmac::hmac;

use super::crypto::x25519;
use super::key_schedule::{CipherSuite, KeySchedule, TrafficKeys, Transcript};
use super::record::*;
use super::{TlsError, TlsResult};
use crate::courierust_fingerprint::profile::TlsProfile;
use alloc::string::String;
use alloc::vec::Vec;

/// Handshake message types (RFC 8446 §4).
pub(crate) const HS_CLIENT_HELLO: u8 = 1;
pub(crate) const HS_SERVER_HELLO: u8 = 2;
pub(crate) const HS_KEY_UPDATE: u8 = 24;
pub(crate) const HS_NEW_SESSION_TICKET: u8 = 4;
pub(crate) const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const HS_CERTIFICATE: u8 = 11;
pub(crate) const HS_CERTIFICATE_REQUEST: u8 = 13;
pub(crate) const HS_CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const HS_FINISHED: u8 = 20;
/// Synthetic `message_hash` type used after a HelloRetryRequest (RFC 8446 §4.4.1).
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
/// cookie extension (RFC 8446 §4.2.2).
pub(crate) const EXT_COOKIE: u16 = 0x002c;
const EXT_KEY_SHARE: u16 = 0x0033;
/// QUIC transport parameters (RFC 9001 section 5.2).
pub(crate) const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 0x0039;
/// Secure renegotiation indicator (RFC 5746 §3.2); TLS 1.2 servers require it.
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// Named group for X25519.
pub(crate) const GROUP_X25519: u16 = 0x001d;

/// Signature schemes offered (RFC 8446 §4.2.3).
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
pub(crate) fn parse_hs(buf: &[u8]) -> Option<HsMessage<'_>> {
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
pub(crate) fn peek_complete_hs(buf: &[u8]) -> Option<HsMessage<'_>> {
    parse_hs(buf).filter(|m| 4 + m.body.len() <= buf.len())
}

/// Whether `buf` holds a complete `Finished` message, i.e. the peer's
/// first flight is fully buffered (it may span several records).
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
    /// Server side: the resumption master secret for a NewSessionTicket.
    pub(crate) resumption_master: Option<Vec<u8>>,
}

/// The application traffic keys (write = client, read = server and
/// vice-versa) plus the secrets behind them: a `KeyUpdate`'s next
/// generation is derived from the secret (RFC 8446 §7.2), not the key.
#[derive(Debug, Clone)]
pub(crate) struct AppKeys {
    pub(crate) write: TrafficKeys,
    pub(crate) read: TrafficKeys,
    pub(crate) write_secret: Vec<u8>,
    pub(crate) read_secret: Vec<u8>,
}

/// Deterministic filler (SHA-256 chain over `tag || random || counter`)
/// for the browser-shaped bytes a real client draws from its CSPRNG;
/// reproducible under test.
fn derived_bytes(seed: &[u8; 32], tag: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;
    while out.len() < len {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Build a ClientHello from a [`TlsProfile`] (§4.1.2): suites, extension
/// order, groups, point formats and signature algorithms go on the wire
/// as given, with GREASE (RFC 8701) where browsers put it.
fn build_profiled_client_hello(
    random: &[u8; 32],
    profile: &TlsProfile,
    key_share: Option<&[u8; 32]>,
    alpn: &[Vec<u8>],
    server_name: Option<&str>,
) -> Vec<u8> {
    fn grease(nibble: u8) -> u16 {
        let n = (nibble & 0x0f) as u16;
        0x0a0a | (n << 12) | (n << 4)
    }
    let mut grease_slot = 0usize;
    let mut next_grease = || {
        let v = grease(random[grease_slot % random.len()]);
        grease_slot += 1;
        v
    };
    let mut group_grease: u16 = 0;
    let mut body = Vec::new();
    body.extend_from_slice(&profile.tls_version.to_be_bytes());
    body.extend_from_slice(random);
    let session_id = derived_bytes(random, b"segmeris-tls13-session-id", 32);
    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);

    let mut suites = Vec::with_capacity(profile.ciphers.len() + 1);
    suites.push(next_grease());
    suites.extend_from_slice(&profile.ciphers);
    body.extend_from_slice(&(suites.len() as u16 * 2).to_be_bytes());
    for suite in &suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // null compression

    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();
    exts.push((next_grease(), Vec::new()));
    for &ext in &profile.extensions {
        if crate::courierust_fingerprint::profile::is_grease(ext) {
            continue;
        }
        let payload: Vec<u8> = match ext {
            EXT_SERVER_NAME => {
                let Some(name) = server_name else {
                    continue;
                };
                let name = name.as_bytes();
                let mut list = Vec::new();
                list.push(0); // host_name
                list.extend_from_slice(&(name.len() as u16).to_be_bytes());
                list.extend_from_slice(name);
                let mut v = Vec::new();
                v.extend_from_slice(&(list.len() as u16).to_be_bytes());
                v.extend_from_slice(&list);
                v
            }
            EXT_SUPPORTED_GROUPS => {
                let grease_group = next_grease();
                group_grease = grease_group;
                let mut groups = Vec::with_capacity(profile.groups.len() + 1);
                groups.push(grease_group);
                groups.extend_from_slice(&profile.groups);
                let mut v = Vec::new();
                v.extend_from_slice(&(groups.len() as u16 * 2).to_be_bytes());
                for group in &groups {
                    v.extend_from_slice(&group.to_be_bytes());
                }
                v
            }
            EXT_EC_POINT_FORMATS => {
                let mut v = vec![profile.point_formats.len() as u8];
                v.extend_from_slice(&profile.point_formats);
                v
            }
            EXT_SIGNATURE_ALGORITHMS => {
                let mut schemes = Vec::with_capacity(profile.signature_algorithms.len() + 1);
                schemes.push(next_grease());
                schemes.extend_from_slice(&profile.signature_algorithms);
                let mut v = Vec::new();
                v.extend_from_slice(&(schemes.len() as u16 * 2).to_be_bytes());
                for scheme in &schemes {
                    v.extend_from_slice(&scheme.to_be_bytes());
                }
                v
            }
            EXT_ALPN => {
                let mut list = Vec::new();
                for protocol in alpn {
                    list.push(protocol.len() as u8);
                    list.extend_from_slice(protocol);
                }
                let mut v = Vec::new();
                v.extend_from_slice(&(list.len() as u16).to_be_bytes());
                v.extend_from_slice(&list);
                v
            }
            EXT_SUPPORTED_VERSIONS => {
                let mut versions = Vec::with_capacity(profile.supported_versions.len() + 1);
                versions.push(next_grease());
                versions.extend_from_slice(&profile.supported_versions);
                let mut v = vec![(versions.len() * 2) as u8];
                for version in &versions {
                    v.extend_from_slice(&version.to_be_bytes());
                }
                v
            }
            EXT_KEY_SHARE => {
                let grease_group = if group_grease != 0 {
                    group_grease
                } else {
                    next_grease()
                };
                let mut entries: Vec<(u16, Vec<u8>)> = vec![(grease_group, vec![0u8])];
                if let Some(share) = key_share {
                    entries.push((GROUP_X25519, share.to_vec()));
                }
                let total: usize = entries.iter().map(|(_, share)| 4 + share.len()).sum();
                let mut v = Vec::new();
                v.extend_from_slice(&(total as u16).to_be_bytes());
                for (group, share) in &entries {
                    v.extend_from_slice(&group.to_be_bytes());
                    v.extend_from_slice(&(share.len() as u16).to_be_bytes());
                    v.extend_from_slice(share);
                }
                v
            }
            0x0005 => vec![1, 0, 0, 0, 0],
            0x002d => vec![1, 1],
            0xff01 => vec![0x00],
            0x001b => vec![0x02, 0x00, 0x02],
            0x44cd => vec![0x00, 0x03, 0x02, b'h', b'2'],
            0x4469 => vec![0x02, b'h', b'2', 0x00, 0x00],
            0xfe0d => {
                let filler = derived_bytes(random, b"segmeris-ech-grease", 32 + 240);
                let mut v = Vec::with_capacity(282);
                v.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x27, 0x00, 0x20]);
                v.extend_from_slice(&filler[..32]);
                v.extend_from_slice(&[0x00, 0xf0]);
                v.extend_from_slice(&filler[32..]);
                v
            }
            _ => Vec::new(),
        };
        exts.push((ext, payload));
    }
    exts.push((next_grease(), Vec::new()));

    let mut ext_block = Vec::new();
    let total: usize = exts.iter().map(|(_, v)| v.len() + 4).sum();
    ext_block.extend_from_slice(&(total as u16).to_be_bytes());
    for (ext, payload) in &exts {
        ext_block.extend_from_slice(&ext.to_be_bytes());
        ext_block.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        ext_block.extend_from_slice(payload);
    }
    body.extend_from_slice(&ext_block);
    encode_hs(HS_CLIENT_HELLO, &body)
}

/// Build a ClientHello with an optional QUIC transport-parameters
/// extension (RFC 9001); the TCP connector uses
/// [`build_client_hello_negotiated`] so it can also speak TLS 1.2.
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
        None,
    )
}

/// Build a ClientHello covering a configurable version window: `offer13`
/// adds `supported_versions` and the TLS 1.3 suites, `offer12` the TLS
/// 1.2 ECDHE suites, and `key_share: None` emits an empty `client_shares`
/// vector so the server answers with a HelloRetryRequest (RFC 8446
/// §4.2.8). `profile` reproduces a fingerprint on the wire instead of the
/// built-in parameter set and overrides the version flags.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_client_hello_negotiated(
    random: &[u8; 32],
    key_share: Option<&[u8; 32]>,
    alpn: &[Vec<u8>],
    server_name: Option<&str>,
    transport_params: Option<&[u8]>,
    offer13: bool,
    offer12: bool,
    profile: Option<&TlsProfile>,
) -> Vec<u8> {
    if let Some(profile) = profile {
        return build_profiled_client_hello(random, profile, key_share, alpn, server_name);
    }
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(random);
    let session_id = derived_bytes(random, b"segmeris-tls13-session-id", 32);
    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);
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
    body.extend_from_slice(&[1, 0]);

    let mut exts: Vec<(u16, Vec<u8>)> = Vec::new();

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

    let mut groups = Vec::new();
    if offer13 {
        groups.extend_from_slice(&[0x00, 0x04]); // 2 curves
        groups.extend_from_slice(&GROUP_X25519.to_be_bytes()); // X25519
        groups.extend_from_slice(&super::tls12::GROUP_SECP256R1.to_be_bytes()); // secp256r1
    } else {
        groups.extend_from_slice(&[0x00, 0x02]); // 1 curve
        groups.extend_from_slice(&super::tls12::GROUP_SECP256R1.to_be_bytes());
    }
    exts.push((EXT_SUPPORTED_GROUPS, groups));

    let mut sigs = Vec::new();
    let mut sig_schemes: Vec<u16> = SIGNATURE_SCHEMES.to_vec();
    sig_schemes.extend_from_slice(super::tls12::TLS12_SIGNATURE_ALGORITHMS);
    sigs.extend_from_slice(&(sig_schemes.len() as u16 * 2).to_be_bytes());
    for s in &sig_schemes {
        sigs.extend_from_slice(&s.to_be_bytes());
    }
    exts.push((EXT_SIGNATURE_ALGORITHMS, sigs));

    if offer12 {
        exts.push((EXT_EC_POINT_FORMATS, vec![1, 0]));
        exts.push((EXT_RENEGOTIATION_INFO, vec![0x00]));
    }

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
            None => ks.extend_from_slice(&[0x00, 0x00]),
        }
        exts.push((EXT_KEY_SHARE, ks));
    }

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

/// Whether a ServerHello carries `supported_versions` = 0x0304, i.e.
/// negotiates TLS 1.3 (a TLS 1.2 ServerHello has no such extension).
pub(crate) fn server_hello_negotiates_tls13(body: &[u8]) -> bool {
    let mut c = Cur::new(body);
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

/// Whether a ClientHello offers TLS 1.3 (`supported_versions` has 0x0304).
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
    if suites_len < 2 || suites_len % 2 != 0 {
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
            if list_len % 2 != 0 {
                return Err(TlsError::Protocol("bad versions".into()));
            }
            let list = v
                .take(list_len)
                .ok_or_else(|| TlsError::Protocol("bad versions".into()))?;
            let mut lc = Cur::new(list);
            while let Some(ver) = lc.u16() {
                if ver == 0x0304 {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

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

/// The `legacy_session_id` of a full ClientHello message (header
/// included), for checking a ServerHello's echo (RFC 8446 §4.1.3).
pub(crate) fn client_hello_session_id(ch: &[u8]) -> TlsResult<Vec<u8>> {
    let body = ch
        .get(4..)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))?;
    // legacy_version (2) || random (32) || session_id<1..32>
    let sid_len = *body
        .get(34)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))? as usize;
    body.get(35..35 + sid_len)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| TlsError::Protocol("bad CH".into()))
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
    let key_share = match (saw_supported_versions, key_share) {
        (true, Some(share)) => share,
        _ => return Err(TlsError::Protocol("SH missing required extensions".into())),
    };
    Ok(ServerHelloInfo {
        random,
        suite,
        key_share,
        session_id,
        resumed,
    })
}

/// The parsed content of an EncryptedExtensions message: the negotiated
/// ALPN protocol and the QUIC transport parameters (RFC 9001 §8.2 places
/// those in EncryptedExtensions, never in the ServerHello).
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

/// Parse a TLS 1.3 Certificate message into its request context and DER
/// entries (leaf first); entry extensions are refused (RFC 8446 §4.4.2).
pub(crate) fn parse_certificate(body: &[u8]) -> TlsResult<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut c = Cur::new(body);
    let bad = || TlsError::Protocol("bad cert".into());
    let ctx_len = c.u8().ok_or_else(bad)? as usize;
    let ctx = c.take(ctx_len).ok_or_else(bad)?.to_vec();
    let list_len = c.u24().ok_or_else(bad)?;
    let list = c.take(list_len).ok_or_else(bad)?;
    let mut lc = Cur::new(list);
    let mut out = Vec::new();
    while !lc.done() {
        let cert_len = lc.u24().ok_or_else(bad)?;
        let cert = lc.take(cert_len).ok_or_else(bad)?;
        out.push(cert.to_vec());
        let ext_len = lc.u16().ok_or_else(bad)? as usize;
        if ext_len != 0 {
            return Err(TlsError::Protocol(
                "Certificate entry extensions are not defined in TLS 1.3".into(),
            ));
        }
    }
    Ok((ctx, out))
}

/// Return just the certificate DER entries (leaf first).
pub(crate) fn parse_certificate_list(body: &[u8]) -> TlsResult<Vec<Vec<u8>>> {
    parse_certificate(body).map(|(_, entries)| entries)
}

/// Build a TLS 1.3 Certificate message (RFC 8446 §4.4.2).
pub(crate) fn build_certificate(context: &[u8], chain: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(context.len() as u8);
    body.extend_from_slice(context);
    let mut entries = Vec::new();
    for der in chain {
        entries.extend_from_slice(&[
            (der.len() >> 16) as u8,
            (der.len() >> 8) as u8,
            der.len() as u8,
        ]);
        entries.extend_from_slice(der);
        entries.extend_from_slice(&[0x00, 0x00]); // entry extensions
    }
    body.extend_from_slice(&[
        (entries.len() >> 16) as u8,
        (entries.len() >> 8) as u8,
        entries.len() as u8,
    ]);
    body.extend_from_slice(&entries);
    encode_hs(HS_CERTIFICATE, &body)
}

/// The signature schemes this stack can *produce* for a CertificateVerify
/// (RSA uses PKCS#1 v1.5; PSS is verification-only here).
pub(crate) const CERT_VERIFY_SCHEMES: [u16; 7] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0603, // ecdsa_secp521r1_sha512
    0x0807, // ed25519
    0x0401, // rsa_pkcs1_sha256
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
];

/// Build a CertificateRequest (RFC 8446 §4.4.2): empty handshake context
/// and the mandatory `signature_algorithms` extension.
pub(crate) fn build_certificate_request(context: &[u8]) -> Vec<u8> {
    let mut alg_list = Vec::new();
    for scheme in CERT_VERIFY_SCHEMES {
        alg_list.extend_from_slice(&scheme.to_be_bytes());
    }
    let mut algs = Vec::new();
    algs.extend_from_slice(&(alg_list.len() as u16).to_be_bytes());
    algs.extend_from_slice(&alg_list);
    let mut exts = Vec::new();
    exts.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
    exts.extend_from_slice(&(algs.len() as u16).to_be_bytes());
    exts.extend_from_slice(&algs);
    let mut body = Vec::new();
    body.push(context.len() as u8);
    body.extend_from_slice(context);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    encode_hs(HS_CERTIFICATE_REQUEST, &body)
}

/// Parse a CertificateRequest: the request context and the offered
/// signature schemes. A non-empty context (post-handshake auth) is refused.
pub(crate) fn parse_certificate_request(body: &[u8]) -> TlsResult<(Vec<u8>, Vec<u16>)> {
    let mut c = Cur::new(body);
    let bad = || TlsError::Protocol("bad CertificateRequest".into());
    let ctx_len = c.u8().ok_or_else(bad)? as usize;
    let ctx = c.take(ctx_len).ok_or_else(bad)?.to_vec();
    if !ctx.is_empty() {
        return Err(TlsError::Protocol(
            "post-handshake CertificateRequest is not supported".into(),
        ));
    }
    let ext_len = c.u16().ok_or_else(bad)? as usize;
    let exts = c.take(ext_len).ok_or_else(bad)?;
    let mut ec = Cur::new(exts);
    let mut schemes = Vec::new();
    while !ec.done() {
        let ext_type = ec.u16().ok_or_else(bad)?;
        let len = ec.u16().ok_or_else(bad)? as usize;
        let ext = ec.take(len).ok_or_else(bad)?;
        if ext_type == EXT_SIGNATURE_ALGORITHMS {
            let mut sc = Cur::new(ext);
            let total = sc.u16().ok_or_else(bad)? as usize;
            let list = sc.take(total).ok_or_else(bad)?;
            if list.len() % 2 != 0 {
                return Err(TlsError::Protocol("bad signature_algorithms".into()));
            }
            for pair in list.chunks(2) {
                schemes.push(u16::from_be_bytes([pair[0], pair[1]]));
            }
        }
    }
    Ok((ctx, schemes))
}

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

/// Verify a CertificateVerify signature with the peer's SPKI. The scheme
/// carries its own hash, independent of the suite's transcript hash
/// (RFC 8446 §4.4.3): a SHA-384 suite routinely pairs with
/// `rsa_pss_rsae_sha256`.
pub(crate) fn verify_cert_verify(
    cv: &CertVerify,
    spki: &super::x509::Spki,
    handshake_hash: &[u8],
    client: bool,
) -> TlsResult<()> {
    use super::crypto::hash::{hash as digest, Sha256, Sha384};
    use super::crypto::rsa::{
        RsaPublicKey, DIGEST_INFO_SHA256, DIGEST_INFO_SHA384, DIGEST_INFO_SHA512,
    };
    use super::crypto::{ecdsa, ed25519};
    use super::x509::der::{
        parse_rsa_public_key, OID_EC_PUBLIC_KEY, OID_ED25519, OID_RSA_ENCRYPTION,
    };

    let msg = cert_verify_message(handshake_hash, client);

    if spki.oid == OID_RSA_ENCRYPTION {
        let (n, e) = parse_rsa_public_key(&spki.key)
            .ok_or_else(|| TlsError::Certificate("bad RSA SPKI".into()))?;
        let key = RsaPublicKey { n, e };
        let ok = match cv.scheme {
            0x0804 => key.verify_pss(&mut Sha256::new(), &msg, 32, &cv.signature),
            0x0805 => key.verify_pss(&mut Sha384::new(), &msg, 48, &cv.signature),
            0x0806 => {
                let mut h = ed25519::Sha512::new();
                key.verify_pss(&mut h, &msg, 64, &cv.signature)
            }
            0x0401 => key.verify_pkcs1v15(
                DIGEST_INFO_SHA256,
                &digest(&mut Sha256::new(), &msg),
                &cv.signature,
            ),
            0x0501 => key.verify_pkcs1v15(
                DIGEST_INFO_SHA384,
                &digest(&mut Sha384::new(), &msg),
                &cv.signature,
            ),
            0x0601 => key.verify_pkcs1v15(
                DIGEST_INFO_SHA512,
                &digest(&mut ed25519::Sha512::new(), &msg),
                &cv.signature,
            ),
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
        let (curve, signed_digest) = match cv.scheme {
            0x0403 => (ecdsa::Curve::P256, digest(&mut Sha256::new(), &msg)),
            0x0503 => (ecdsa::Curve::P384, digest(&mut Sha384::new(), &msg)),
            0x0603 => (
                ecdsa::Curve::P521,
                digest(&mut ed25519::Sha512::new(), &msg),
            ),
            _ => return Err(TlsError::Certificate("unsupported EC signature".into())),
        };
        if spki.ec_curve != Some(curve) {
            return Err(TlsError::Certificate("EC curve mismatch".into()));
        }
        let clen = curve.coord_len();
        if spki.key.len() != 1 + 2 * clen || spki.key[0] != 0x04 {
            return Err(TlsError::Certificate("bad EC SPKI".into()));
        }
        let qx = &spki.key[1..1 + clen];
        let qy = &spki.key[1 + clen..1 + 2 * clen];
        if ecdsa::verify_der(curve, qx, qy, &signed_digest, &cv.signature) {
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

/// Fill `buf` from OS entropy; fail the handshake when the source is
/// unavailable, since an all-zero X25519 key is predictable.
pub(crate) fn fill_entropy(buf: &mut [u8]) -> TlsResult<()> {
    if super::crypto::rng::fill_random(buf) {
        Ok(())
    } else {
        Err(TlsError::Internal(
            "cryptographic RNG unavailable; refusing to generate a predictable key".into(),
        ))
    }
}

/// RFC 7748 §6.1: a low-order peer share yields an all-zero shared
/// secret; reject it (rustls/BoringSSL abort here too).
pub(crate) fn validate_shared_secret(shared: &[u8; 32]) -> TlsResult<()> {
    if shared.iter().all(|&b| b == 0) {
        return Err(TlsError::Protocol(
            "peer X25519 share produced an all-zero shared secret".into(),
        ));
    }
    Ok(())
}

pub(crate) struct ClientHandshake {
    pub(crate) server_name: Option<String>,
    pub(crate) verify: bool,
    /// A resumption PSK to offer (RFC 8446 §4.2.11), with its suite.
    pub(crate) psk: Option<(Vec<u8>, CipherSuite)>,
    /// The client certificate to present when the server asks for one (mTLS)
    pub(crate) identity: Option<super::Identity>,
}

impl ClientHandshake {
    /// Continue a client handshake whose ServerHello was already read
    /// (the connector needs it to choose between TLS 1.3 and 1.2). `hrr`
    /// carries `(ClientHello1, HelloRetryRequest, ClientHello2)` after a
    /// HelloRetryRequest, so the transcript starts with
    /// `message_hash(Hash(CH1)) || HRR || CH2` (RFC 8446 §4.4.1).
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
        if sh.session_id != client_hello_session_id(ch)? {
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

        let shared = x25519::x25519(priv_key, &sh.key_share);
        validate_shared_secret(&shared)?;
        let th = transcript.current_hash();
        let mut ks = if sh.resumed {
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
        let mut client_auth: Option<Vec<u16>> = None;
        let mut saw_certificate = false;
        for (t, body) in &messages {
            match *t {
                HS_ENCRYPTED_EXTENSIONS => {
                    let (alpn, _transport_params) = parse_encrypted_extensions(body)?;
                    negotiated_alpn = alpn;
                    saw_ee = true;
                }
                HS_CERTIFICATE_REQUEST => {
                    if client_auth.is_some() || saw_certificate {
                        return Err(TlsError::Protocol("CertificateRequest out of order".into()));
                    }
                    let (_context, schemes) = parse_certificate_request(body)?;
                    client_auth = Some(schemes);
                }
                HS_CERTIFICATE => {
                    saw_certificate = true;
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
        for (t, body) in &messages {
            if *t == HS_ENCRYPTED_EXTENSIONS || *t == HS_CERTIFICATE_REQUEST || *t == HS_CERTIFICATE
            {
                transcript.update(&encode_hs(*t, body));
            }
        }

        // A resumed handshake authenticates with the PSK: Certificate,
        // CertificateVerify and CertificateRequest are absent
        // (RFC 8446 §4.4.2, §4.3.2).
        let mut peer_cert_der = None;
        if sh.resumed {
            if peer_chain.is_some() || cv.is_some() || client_auth.is_some() {
                return Err(TlsError::Protocol(
                    "authentication messages in a resumed handshake".into(),
                ));
            }
        } else {
            let peer_chain =
                peer_chain.ok_or_else(|| TlsError::Protocol("missing Certificate".into()))?;
            if peer_chain.is_empty() {
                return Err(TlsError::Protocol("empty certificate list".into()));
            }
            let cv = cv.ok_or_else(|| TlsError::Protocol("missing CertificateVerify".into()))?;
            let cv_hash = transcript.current_hash();
            let leaf = super::x509::parse_certificate(&peer_chain[0])?;
            if self.verify {
                let name = self.server_name.as_deref().unwrap_or("");
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
            verify_cert_verify(&cv, &leaf.spki, &cv_hash, false)?;
            transcript.update(&encode_hs(HS_CERTIFICATE_VERIFY, &cv_body(&messages)));
            peer_cert_der = Some(peer_chain[0].clone());
        }

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

        transcript.update(&encode_hs(HS_FINISHED, &finished_body));
        let after_fin_hash = transcript.current_hash();
        ks.application(&after_fin_hash)?;

        let mut client_flight = Vec::new();
        if let Some(schemes) = client_auth {
            client_flight = match &self.identity {
                Some(identity) => {
                    let cert = build_certificate(&[], &identity.cert_chain);
                    transcript.update(&cert);
                    let cv_hash = transcript.current_hash();
                    let content = cert_verify_message(&cv_hash, true);
                    let (scheme, signature) = super::sign::sign_cert_verify(
                        identity, &content, sh.suite,
                    )?
                    .ok_or_else(|| TlsError::Certificate("client identity cannot sign".into()))?;
                    if !schemes.is_empty() && !schemes.contains(&scheme) {
                        return Err(TlsError::Certificate(
                            "the server does not accept the scheme this client certificate \
                             signs with"
                                .into(),
                        ));
                    }
                    let mut cv_body = Vec::new();
                    cv_body.extend_from_slice(&scheme.to_be_bytes());
                    cv_body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
                    cv_body.extend_from_slice(&signature);
                    let cv = encode_hs(HS_CERTIFICATE_VERIFY, &cv_body);
                    transcript.update(&cv);
                    let mut flight = cert;
                    flight.extend_from_slice(&cv);
                    flight
                }
                None => {
                    let cert = build_certificate(&[], &[]);
                    transcript.update(&cert);
                    cert
                }
            };
        }

        let client_fin_hash = transcript.current_hash();
        let client_fin = finished_verify_data(&ks, ks.client_handshake(), &client_fin_hash);
        let client_fin_msg = encode_hs(HS_FINISHED, &client_fin);
        client_flight.extend_from_slice(&client_fin_msg);
        let c_hs_keys = ks.client_handshake_keys();
        io.write_encrypted_record(sh.suite, &c_hs_keys, CONTENT_HANDSHAKE, &client_flight)?;
        transcript.update(&client_fin_msg);

        let resumption_master = Some(ks.resumption_master(&transcript.current_hash()));

        let write = ks.client_application_keys();
        let read = ks.server_application_keys();
        Ok(HandshakeResult {
            suite: sh.suite,
            keys: AppKeys {
                write,
                read,
                write_secret: ks.client_application_secret().to_vec(),
                read_secret: ks.server_application_secret().to_vec(),
            },
            alpn: negotiated_alpn,
            server_name: self.server_name.clone(),
            peer_cert: peer_cert_der,
            resumed: sh.resumed,
            resumption_master,
        })
    }
}

/// The raw body bytes of the CertificateVerify message (to continue the
/// transcript).
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

/// Server-side handshake driver.
pub(crate) struct ServerHandshake {
    pub(crate) identity: super::Identity,
    pub(crate) alpn: Vec<Vec<u8>>,
    /// Session-ticket key; `None` disables resumption (the QUIC path
    /// passes None).
    pub(crate) ticket_key: Option<[u8; 32]>,
    /// Current Unix time (used to validate ticket age).
    pub(crate) now: i64,
    /// Client authentication (mTLS): when set, a CertificateRequest is
    /// sent and the client's chain is validated against its roots.
    pub(crate) client_auth: Option<super::ClientAuth>,
}

impl ServerHandshake {
    /// Continue a server handshake whose ClientHello was already read.
    pub(crate) fn run_from_client_hello<
        R: crate::courierust_io::Read,
        W: crate::courierust_io::Write,
    >(
        &self,
        io: &mut super::TlsIo<R, W>,
        ch_body: &[u8],
    ) -> TlsResult<HandshakeResult> {
        let suite_hash_pref = super::sign::tls13_suite_hash_pref(&self.identity);
        let mut ch = parse_client_hello(ch_body, suite_hash_pref)?;
        let mut transcript = Transcript::new(ch.suite.hash());
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
                        None => super::session::verify_binder(&resume_body, &offer, ch.suite, &psk),
                    };
                    // A required client certificate cannot be asked for in
                    // a resumed handshake (RFC 8446 §4.3.2), so decline the
                    // PSK and fall back to a full handshake.
                    let cert_owed = self
                        .client_auth
                        .as_ref()
                        .is_some_and(|auth| auth.is_required());
                    if ticket_suite == ch.suite && binder_ok && !cert_owed {
                        resumed = true;
                        resume_psk = Some(psk);
                    }
                }
            }
        }

        let ch_share = ch
            .key_share
            .ok_or_else(|| TlsError::Protocol("no X25519 key share was offered".into()))?;
        let mut s_priv = [0u8; 32];
        fill_entropy(&mut s_priv)?;
        let s_pub = x25519::x25519(&s_priv, &x25519::BASE_POINT);
        let shared = x25519::x25519(&s_priv, &ch_share);
        validate_shared_secret(&shared)?;
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
        let mut ks = match (resumed, &resume_psk) {
            (true, Some(psk)) => KeySchedule::handshake_with_psk(ch.suite, &shared, psk, &th),
            (true, None) => return Err(TlsError::Internal("resumed without a PSK".into())),
            (false, _) => KeySchedule::handshake(ch.suite, &shared, &th),
        };

        let mut ee_body = Vec::new();
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
        // A resumed handshake authenticates with the PSK, so no
        // CertificateRequest, Certificate or CertificateVerify
        // (RFC 8446 §4.4.2, §4.3.2).
        let cr = if resumed {
            None
        } else {
            self.client_auth
                .as_ref()
                .map(|_| build_certificate_request(&[]))
        };
        let cert = (!resumed).then(|| build_certificate(&[], &self.identity.cert_chain));
        transcript.update(&ee);
        if let Some(cr) = &cr {
            transcript.update(cr);
        }
        if let Some(cert) = &cert {
            transcript.update(cert);
        }

        let cv = match &cert {
            Some(_) => {
                let cv_hash = transcript.current_hash();
                let sig_content = cert_verify_message(&cv_hash, false);
                match super::server_sign(&self.identity, &sig_content, ch.suite)? {
                    Some((scheme, signature)) => {
                        let mut cv_body = Vec::new();
                        cv_body.extend_from_slice(&scheme.to_be_bytes());
                        cv_body.extend_from_slice(&(signature.len() as u16).to_be_bytes());
                        cv_body.extend_from_slice(&signature);
                        let cv = encode_hs(HS_CERTIFICATE_VERIFY, &cv_body);
                        transcript.update(&cv);
                        Some(cv)
                    }
                    None => {
                        return Err(TlsError::Certificate(
                            "no server identity configured".into(),
                        ));
                    }
                }
            }
            None => None,
        };

        let fin_hash = transcript.current_hash();
        let fin = finished_verify_data(&ks, ks.server_handshake(), &fin_hash);
        let fin_msg = encode_hs(HS_FINISHED, &fin);
        transcript.update(&fin_msg);

        let after_fin_hash = transcript.current_hash();
        ks.application(&after_fin_hash)?;

        let s_hs_keys = ks.server_handshake_keys();
        let mut flight = ee;
        if let Some(cr) = &cr {
            flight.extend_from_slice(cr);
        }
        if let Some(cert) = &cert {
            flight.extend_from_slice(cert);
        }
        if let Some(cv) = &cv {
            flight.extend_from_slice(cv);
        }
        flight.extend_from_slice(&fin_msg);
        io.write_encrypted_record(ch.suite, &s_hs_keys, CONTENT_HANDSHAKE, &flight)?;

        let c_hs_keys = ks.client_handshake_keys();
        let plaintext = io.read_encrypted_handshake(ch.suite, &c_hs_keys)?;
        let mut off = 0usize;
        let mut client_cert: Option<(Vec<u8>, Vec<Vec<u8>>)> = None;
        let mut client_cv: Option<CertVerify> = None;
        let mut finished_body: Option<Vec<u8>> = None;
        while off + 4 <= plaintext.len() {
            let m = parse_hs(&plaintext[off..])
                .ok_or_else(|| TlsError::Protocol("bad client flight".into()))?;
            let total = 4 + m.body.len();
            match m.msg_type {
                HS_CERTIFICATE if client_cert.is_none() && client_cv.is_none() => {
                    let parsed = parse_certificate(m.body)?;
                    if !parsed.0.is_empty() {
                        return Err(TlsError::Protocol(
                            "client certificate request context mismatch".into(),
                        ));
                    }
                    transcript.update(&plaintext[off..off + total]);
                    client_cert = Some(parsed);
                }
                HS_CERTIFICATE_VERIFY if client_cert.is_some() && client_cv.is_none() => {
                    let cv = parse_cert_verify(m.body)?;
                    let Some(entries) = client_cert.as_ref().map(|(_, entries)| entries) else {
                        return Err(TlsError::Protocol(
                            "CertificateVerify without a client certificate".into(),
                        ));
                    };
                    if entries.is_empty() {
                        return Err(TlsError::Protocol(
                            "CertificateVerify without a client certificate".into(),
                        ));
                    }
                    let cv_hash = transcript.current_hash();
                    let leaf = super::x509::parse_certificate(&entries[0])?;
                    if let Err(e) = verify_cert_verify(&cv, &leaf.spki, &cv_hash, true) {
                        send_alert(io, ch.suite, &ks.server_application_keys(), 2, 42)?;
                        return Err(e);
                    }
                    transcript.update(&plaintext[off..off + total]);
                    client_cv = Some(cv);
                }
                HS_FINISHED if finished_body.is_none() => {
                    finished_body = Some(m.body.to_vec());
                }
                _ => return Err(TlsError::Protocol("unexpected client message".into())),
            }
            off += total;
        }
        if off != plaintext.len() {
            return Err(TlsError::Protocol(
                "trailing bytes in the client flight".into(),
            ));
        }

        let client_cert = match client_cert {
            Some((_, entries)) if entries.is_empty() => None,
            other => other,
        };
        match (&self.client_auth, &client_cert) {
            (None, Some(_)) => {
                send_alert(io, ch.suite, &ks.server_application_keys(), 2, 10)?;
                return Err(TlsError::Protocol(
                    "client sent a certificate that was not requested".into(),
                ));
            }
            (Some(auth), Some((_, entries))) => {
                let leaf = super::x509::parse_certificate(&entries[0])?;
                let refused = super::x509::validate_chain(auth.roots(), entries, self.now)
                    .and_then(|()| {
                        if super::x509::has_client_auth_eku(&leaf) {
                            Ok(())
                        } else {
                            Err(TlsError::Certificate(
                                "client certificate does not carry the clientAuth EKU".into(),
                            ))
                        }
                    });
                if let Err(e) = refused {
                    send_alert(io, ch.suite, &ks.server_application_keys(), 2, 42)?;
                    return Err(e);
                }
                if client_cv.is_none() {
                    send_alert(io, ch.suite, &ks.server_application_keys(), 2, 47)?;
                    return Err(TlsError::Protocol(
                        "client certificate without a CertificateVerify".into(),
                    ));
                }
            }
            (Some(auth), None) => {
                if auth.is_required() {
                    send_alert(io, ch.suite, &ks.server_application_keys(), 2, 116)?;
                    return Err(TlsError::Alert {
                        level: 2,
                        description: 116,
                    });
                }
            }
            (None, None) => {}
        }

        let finished_body =
            finished_body.ok_or_else(|| TlsError::Protocol("missing client Finished".into()))?;
        let client_fin_hash = transcript.current_hash();
        let expected = finished_verify_data(&ks, ks.client_handshake(), &client_fin_hash);
        if !constant_time_eq(&expected, &finished_body) {
            return Err(TlsError::Alert {
                level: 2,
                description: 51,
            });
        }
        transcript.update(&encode_hs(HS_FINISHED, &finished_body));

        let write = ks.server_application_keys();
        let read = ks.client_application_keys();

        io.reset_sequences();

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
            keys: AppKeys {
                write,
                read,
                write_secret: ks.server_application_secret().to_vec(),
                read_secret: ks.client_application_secret().to_vec(),
            },
            alpn: negotiated_alpn,
            server_name: ch.server_name,
            peer_cert: client_cert.map(|(_, entries)| entries[0].clone()),
            resumed,
            resumption_master: None,
        })
    }
}

/// Send an alert to the peer (RFC 8446 §6.2), protected with the
/// application keys: once the server's Finished is out, that is the epoch
/// the peer reads from and where its read sequence numbers restart.
fn send_alert<R: crate::courierust_io::Read, W: crate::courierust_io::Write>(
    io: &mut super::TlsIo<R, W>,
    suite: CipherSuite,
    keys: &TrafficKeys,
    level: u8,
    description: u8,
) -> TlsResult<()> {
    io.reset_sequences();
    io.write_encrypted_record(suite, keys, CONTENT_ALERT, &[level, description])
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
    /// The client's legacy_session_id; the ServerHello must echo it
    /// verbatim (RFC 8446 §4.1.3).
    pub(crate) session_id: Vec<u8>,
    /// QUIC transport parameters, when present.
    pub(crate) transport_params: Option<Vec<u8>>,
}

/// Parse a ClientHello. `suite_hash_pref` (derived from the server
/// identity key) restricts the suite to a hash its signature can use.
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
    if suites_len < 2 || suites_len % 2 != 0 {
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
                let mut lc = Cur::new(list);
                while !lc.done() {
                    let ver = lc
                        .u16()
                        .ok_or_else(|| TlsError::Protocol("bad CH versions".into()))?;
                    if ver == 0x0304 {
                        saw_versions = true;
                    }
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

    let suite = CLIENT_SUITES
        .iter()
        .copied()
        .filter(|s| suite_hash_pref.map_or(true, |h| s.hash() == h))
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

/// Whether a ServerHello is a HelloRetryRequest (random ==
/// SHA-256("HelloRetryRequest"), RFC 8446 §4.1.3).
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

/// Parse a HelloRetryRequest body: `supported_versions` must be 0x0304
/// and `key_share` must carry the selected group.
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
    let selected_group = match (saw_versions, selected_group) {
        (true, Some(group)) => group,
        _ => return Err(TlsError::Protocol("HRR missing required extensions".into())),
    };
    Ok(HrrInfo { selected_group })
}

/// Build a HelloRetryRequest requesting an X25519 share and echoing the
/// client's session id (RFC 8446 §4.1.4).
pub(crate) fn build_hello_retry_request(suite: CipherSuite, session_id: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&HRR_RANDOM);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.wire().to_be_bytes());
    body.push(0); // legacy_compression_method
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

/// RFC 8446 §4.4.1: the synthetic `message_hash` message carrying
/// Hash(ClientHello1), which replaces it in the transcript.
fn message_hash_message(ch1: &[u8], suite: CipherSuite) -> Vec<u8> {
    let mut d = suite.hash().new_digest();
    d.update(ch1);
    let h = d.finalize();
    encode_hs(HS_MESSAGE_HASH, &h)
}

/// Build a ServerHello, echoing the client's `session_id` verbatim
/// (RFC 8446 §4.1.3).
pub(crate) fn build_server_hello(
    random: &[u8; 32],
    key_share: &[u8; 32],
    suite: CipherSuite,
    session_id: &[u8],
) -> Vec<u8> {
    build_server_hello_with_transport_params(random, key_share, suite, session_id, None)
}

/// Build a ServerHello with optional QUIC transport parameters.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_fingerprint::profile::{chrome_tls_profile, is_grease};

    /// Every extension of a ClientHello body, in wire order.
    fn extensions(body: &[u8]) -> Vec<(u16, &[u8])> {
        let mut p = 2 + 32;
        let sid = body[p] as usize;
        p += 1 + sid;
        let suites = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2 + suites;
        let comp = body[p] as usize;
        p += 1 + comp;
        let ext_total = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        let end = p + ext_total;
        let mut out = Vec::new();
        while p + 4 <= end {
            let id = u16::from_be_bytes([body[p], body[p + 1]]);
            let len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
            out.push((id, &body[p + 4..p + 4 + len]));
            p += 4 + len;
        }
        out
    }

    /// A `supported_versions` list with a trailing half-version is
    /// malformed; the probe must reject it instead of spinning on a cursor
    /// that cannot advance (an odd-length list used to hang the acceptor).
    #[test]
    fn malformed_supported_versions_is_rejected() {
        let hello = |versions: &[u8]| {
            let mut body = Vec::new();
            body.extend_from_slice(&[0x03, 0x03]);
            body.extend_from_slice(&[0x11u8; 32]);
            body.push(0); // empty legacy_session_id
            body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one TLS 1.3 suite
            body.extend_from_slice(&[1, 0]); // null compression
            let mut exts = Vec::new();
            exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
            exts.extend_from_slice(&(versions.len() as u16).to_be_bytes());
            exts.extend_from_slice(versions);
            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend_from_slice(&exts);
            body
        };
        assert!(matches!(
            client_hello_offers_tls13(&hello(&[0x02, 0x03, 0x04])),
            Ok(true)
        ));
        assert!(client_hello_offers_tls13(&hello(&[0x01, 0x03])).is_err());
        assert!(matches!(
            client_hello_offers_tls13(&hello(&[0x02, 0x03, 0x03])),
            Ok(false)
        ));
    }

    /// Once GREASE is filtered the profiled hello must reproduce the
    /// Chrome parameter set exactly (that is what JA3/JA4 read).
    #[test]
    fn profiled_client_hello_matches_the_chrome_profile() {
        let profile = chrome_tls_profile();
        let random = [0x5au8; 32];
        let share = [0x77u8; 32];
        let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let ch = build_profiled_client_hello(
            &random,
            &profile,
            Some(&share),
            &alpn,
            Some("api.bilibili.com"),
        );
        let message = parse_hs(&ch).expect("well-formed handshake message");
        assert_eq!(message.msg_type, HS_CLIENT_HELLO);

        let parsed = super::super::tls12::parse_client_hello12(message.body).expect("parses");
        let suites: Vec<u16> = parsed
            .offered_suites
            .iter()
            .copied()
            .filter(|s| !is_grease(*s))
            .collect();
        assert_eq!(suites, profile.ciphers);
        let groups: Vec<u16> = parsed
            .supported_groups
            .iter()
            .copied()
            .filter(|g| !is_grease(*g))
            .collect();
        assert_eq!(groups, profile.groups);
        let schemes: Vec<u16> = parsed
            .signature_algorithms
            .iter()
            .copied()
            .filter(|s| !is_grease(*s))
            .collect();
        assert_eq!(schemes, profile.signature_algorithms);

        let exts = extensions(message.body);
        let ids: Vec<u16> = exts
            .iter()
            .map(|(id, _)| *id)
            .filter(|e| !is_grease(*e))
            .collect();
        assert_eq!(ids, profile.extensions);

        // The key_share length must cover whole entries (group || len ||
        // share): a declared length short of that is rejected by servers.
        let (_, share_payload) = exts
            .iter()
            .find(|(id, _)| *id == EXT_KEY_SHARE)
            .expect("key_share present");
        let declared = u16::from_be_bytes([share_payload[0], share_payload[1]]) as usize;
        assert_eq!(declared, share_payload.len() - 2);
    }
}
