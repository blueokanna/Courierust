//! TLS 1.3 session resumption (RFC 8446 §4.6.1): server-issued
//! `NewSessionTicket` with a resumption PSK, client reconnection via
//! `pre_shared_key` (psk_dhe_ke), and the resumption binder.
//!
//! The server encrypts the resumption PSK inside the ticket with a
//! server-held AEAD key (AES-256-GCM), so tickets are stateless and a
//! connection can be resumed by any acceptor holding the same key. The
//! client stores the decrypted PSK and offers it on reconnect.

use crate::courierust_tls::crypto::hash::Digest;
use crate::courierust_tls::crypto::hmac::hmac;
use crate::courierust_tls::key_schedule::{self, CipherSuite};
use crate::courierust_tls::TlsError;
use alloc::string::String;
use alloc::vec::Vec;

/// pre_shared_key extension (0x0029) — MUST be the last ClientHello
/// extension (RFC 8446 §4.2.11).
pub(crate) const EXT_PRE_SHARED_KEY: u16 = 0x0029;
/// psk_key_exchange_modes extension (0x002d).
pub(crate) const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
/// NewSessionTicket handshake message type.
pub(crate) const HS_NEW_SESSION_TICKET: u8 = 4;
/// Session lifetime the server advertises and enforces.
pub(crate) const SESSION_LIFETIME_SECS: i64 = 7 * 24 * 3600;

/// A resumable session cached by the client.
#[derive(Debug, Clone)]
pub(crate) struct ClientSession {
    pub(crate) hostname: String,
    pub(crate) ticket: Vec<u8>,
    pub(crate) psk: Vec<u8>,
    pub(crate) suite: CipherSuite,
    pub(crate) issued_at: i64,
    /// Validity window in seconds (the server's `ticket_lifetime`, capped
    /// at 7 days per RFC 8446 §4.6.1).
    pub(crate) lifetime: i64,
}

impl ClientSession {
    /// Whether the session is still within its validity window.
    pub(crate) fn is_fresh(&self, now: i64) -> bool {
        now >= self.issued_at && now.saturating_sub(self.issued_at) <= self.lifetime
    }
}

/// A parsed `NewSessionTicket` message.
#[derive(Debug, Clone)]
pub(crate) struct NewSessionTicket {
    pub(crate) nonce: Vec<u8>,
    pub(crate) ticket: Vec<u8>,
    pub(crate) lifetime: u32,
}

/// Parse a `NewSessionTicket` handshake body.
pub(crate) fn parse_new_session_ticket(body: &[u8]) -> Result<NewSessionTicket, TlsError> {
    let mut p = 0usize;
    let lifetime = take_u32(body, &mut p, "ticket lifetime")?;
    // ticket_age_add is ignored (this client sends obfuscated age 0).
    take_u32(body, &mut p, "ticket age add")?;
    let nonce_len = take_u8(body, &mut p, "ticket nonce")? as usize;
    let nonce = take(body, &mut p, nonce_len, "ticket nonce")?.to_vec();
    let ticket_len = take_u16(body, &mut p, "ticket")? as usize;
    if ticket_len == 0 {
        return Err(TlsError::Protocol("empty session ticket".into()));
    }
    let ticket = take(body, &mut p, ticket_len, "ticket")?.to_vec();
    // extensions (this client sends none and ignores the server's)
    if p != body.len() {
        let ext_len = take_u16(body, &mut p, "ticket extensions")? as usize;
        take(body, &mut p, ext_len, "ticket extensions")?;
    }
    Ok(NewSessionTicket {
        nonce,
        ticket,
        lifetime,
    })
}

/// Build a `NewSessionTicket` handshake message.
pub(crate) fn build_new_session_ticket(lifetime: u32, nonce: &[u8], ticket: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(16 + nonce.len() + ticket.len());
    body.extend_from_slice(&lifetime.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // ticket_age_add
    body.push(nonce.len() as u8);
    body.extend_from_slice(nonce);
    body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    body.extend_from_slice(ticket);
    body.extend_from_slice(&0u16.to_be_bytes()); // no extensions
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(HS_NEW_SESSION_TICKET);
    msg.extend_from_slice(&[
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ]);
    msg.extend_from_slice(&body);
    msg
}

// ---------------------------------------------------------------------
// Ticket protection (server side): AES-256-GCM with a server-held key.
// ticket = nonce(12) || ciphertext+tag; the NST `ticket_nonce` (sent in
// clear) is a separate protocol value used for PSK derivation.
// ---------------------------------------------------------------------

/// Encrypt a resumption PSK into a ticket value. The issue time is
/// embedded so the server can enforce the session lifetime on resume.
/// The AEAD nonce is 12 fresh random bytes (NIST SP 800-38D: 96-bit
/// random GCM nonces); `ticket = nonce(12) || ciphertext+tag`.
pub(crate) fn encrypt_ticket(key: &[u8; 32], suite: CipherSuite, psk: &[u8], now: i64) -> Vec<u8> {
    let mut aead_nonce = [0u8; 12];
    let _ = crate::courierust_tls::crypto::rng::fill_random(&mut aead_nonce);
    let mut plaintext = Vec::with_capacity(10 + psk.len());
    plaintext.extend_from_slice(&suite.wire().to_be_bytes());
    plaintext.extend_from_slice(&now.to_be_bytes());
    plaintext.extend_from_slice(psk);
    let sealed = CipherSuite::TlsAes256GcmSha384
        .seal(key, &aead_nonce, &[], &plaintext)
        .expect("AES-256-GCM seal cannot fail");
    let mut ticket = Vec::with_capacity(12 + sealed.len());
    ticket.extend_from_slice(&aead_nonce);
    ticket.extend_from_slice(&sealed);
    ticket
}

/// Decrypt and validate a ticket value, returning the suite and the
/// resumption PSK. Expired tickets and tickets issued in the future are
/// rejected.
pub(crate) fn decrypt_ticket(
    key: &[u8; 32],
    ticket: &[u8],
    now: i64,
) -> Result<(CipherSuite, Vec<u8>), TlsError> {
    if ticket.len() < 12 + 16 + 1 {
        return Err(TlsError::Certificate("malformed session ticket".into()));
    }
    let mut aead_nonce = [0u8; 12];
    aead_nonce.copy_from_slice(&ticket[..12]);
    let sealed = &ticket[12..];
    let plaintext = CipherSuite::TlsAes256GcmSha384
        .open(key, &aead_nonce, &[], sealed)
        .ok_or_else(|| TlsError::Certificate("invalid session ticket".into()))?;
    if plaintext.len() < 10 {
        return Err(TlsError::Certificate("malformed session ticket".into()));
    }
    let suite_wire = u16::from_be_bytes([plaintext[0], plaintext[1]]);
    let issued = i64::from_be_bytes([
        plaintext[2],
        plaintext[3],
        plaintext[4],
        plaintext[5],
        plaintext[6],
        plaintext[7],
        plaintext[8],
        plaintext[9],
    ]);
    let suite = CipherSuite::from_wire(suite_wire)
        .ok_or_else(|| TlsError::Certificate("unsupported ticket suite".into()))?;
    if now < issued || now.saturating_sub(issued) > SESSION_LIFETIME_SECS {
        return Err(TlsError::Certificate("expired session ticket".into()));
    }
    Ok((suite, plaintext[10..].to_vec()))
}

// ---------------------------------------------------------------------
// ClientHello with pre_shared_key + binder (RFC 8446 §4.2.11).
// ---------------------------------------------------------------------

/// Build a TLS 1.3 ClientHello offering a resumption PSK. The
/// `pre_shared_key` extension is emitted last; the binder is computed
/// over the truncated ClientHello (binders removed) with the binder key
/// derived from the PSK.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_client_hello_with_psk(
    random: &[u8; 32],
    key_share: &[u8; 32],
    alpn: &[Vec<u8>],
    server_name: Option<&str>,
    suite: CipherSuite,
    psk: &[u8],
    ticket: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(random);
    body.push(0); // empty legacy_session_id

    // Cipher suites: the TLS 1.3 set (resumption is TLS 1.3 only).
    let suites: [CipherSuite; 3] = [
        CipherSuite::TlsChaCha20Poly1305Sha256,
        CipherSuite::TlsAes128GcmSha256,
        CipherSuite::TlsAes256GcmSha384,
    ];
    body.extend_from_slice(&(suites.len() as u16 * 2).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.wire().to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // legacy_compression_methods

    // Extensions (pre_shared_key appended last, after computing the
    // binder over the truncated message).
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
        exts.push((0x0000, server_name_ext));
    }
    let mut groups = Vec::new();
    groups.extend_from_slice(&[0x00, 0x04]);
    groups.extend_from_slice(&0x001du16.to_be_bytes());
    groups.extend_from_slice(&0x0017u16.to_be_bytes());
    exts.push((0x000a, groups));
    let sig_schemes: &[u16] = &[0x0804, 0x0403, 0x0807, 0x0401, 0x0503, 0x0501, 0x0805];
    let mut sigs = Vec::new();
    sigs.extend_from_slice(&(sig_schemes.len() as u16 * 2).to_be_bytes());
    for s in sig_schemes {
        sigs.extend_from_slice(&s.to_be_bytes());
    }
    exts.push((0x000d, sigs));
    exts.push((0x002b, vec![0x02, 0x03, 0x04])); // supported_versions 1.3
    let mut ks = Vec::new();
    ks.extend_from_slice(&[0x00, 0x24]);
    ks.extend_from_slice(&0x001du16.to_be_bytes());
    ks.extend_from_slice(&[0x00, 0x20]);
    ks.extend_from_slice(key_share);
    exts.push((0x0033, ks));
    if !alpn.is_empty() {
        let mut alpn_body = Vec::new();
        let mut proto_list = Vec::new();
        for p in alpn {
            proto_list.push(p.len() as u8);
            proto_list.extend_from_slice(p);
        }
        alpn_body.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
        alpn_body.extend_from_slice(&proto_list);
        exts.push((0x0010, alpn_body));
    }
    // psk_key_exchange_modes: psk_dhe_ke only (0x01) — forward secrecy.
    exts.push((EXT_PSK_KEY_EXCHANGE_MODES, vec![0x02, 0x01]));

    let mut ext_bytes = Vec::new();
    for (t, c) in exts {
        ext_bytes.extend_from_slice(&t.to_be_bytes());
        ext_bytes.extend_from_slice(&(c.len() as u16).to_be_bytes());
        ext_bytes.extend_from_slice(&c);
    }

    // Identities: one PskIdentity { ticket, obfuscated_ticket_age }.
    // The age is sent as 0; the server validates the ticket's own
    // issue time, so obfuscation (which needs the ticket's age_add) is
    // not required for correctness.
    let mut identities = Vec::new();
    identities.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    identities.extend_from_slice(ticket);
    identities.extend_from_slice(&0u32.to_be_bytes());

    // Full pre_shared_key content: identities + binders-length + one
    // placeholder binder (zeroed; spliced after the hash).
    let mut binders = Vec::new();
    binders.push(suite.hash().hash_len() as u8);
    binders.extend_from_slice(&vec![0u8; suite.hash().hash_len()]);
    let mut full_psk = Vec::new();
    full_psk.extend_from_slice(&(identities.len() as u16).to_be_bytes());
    full_psk.extend_from_slice(&identities);
    full_psk.extend_from_slice(&(binders.len() as u16).to_be_bytes());
    full_psk.extend_from_slice(&binders);

    ext_bytes.extend_from_slice(&EXT_PRE_SHARED_KEY.to_be_bytes());
    ext_bytes.extend_from_slice(&(full_psk.len() as u16).to_be_bytes());
    ext_bytes.extend_from_slice(&full_psk);
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);

    // Full ClientHello message (header + body with the placeholder binder).
    let mut full_msg = Vec::with_capacity(4 + body.len());
    full_msg.push(1);
    full_msg.extend_from_slice(&[
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ]);
    full_msg.extend_from_slice(&body);

    // Truncated ClientHello: the full message with the binders and their
    // length prefix removed, all length fields unchanged (RFC 8446
    // §4.2.11.2; rustls encodes the full message then trims the tail).
    let truncated_len = full_msg.len() - (2 + binders.len());
    let truncated = &full_msg[..truncated_len];
    let binder_key = key_schedule::binder_key(suite, psk);
    let mut d = suite.hash().new_digest();
    d.update(truncated);
    let th = d.finalize();
    let binder = hmac(suite.hash().new_digest().as_mut(), &binder_key, &th);
    let expected_binder_len = suite.hash().hash_len();
    if binder.len() != expected_binder_len {
        return Err(TlsError::Internal("binder length mismatch".into()));
    }

    // Splice the real binder over the placeholder (binders-length field
    // and PskBinderEntry length byte precede it).
    let binder_start = full_msg.len() - binders.len() + 1;
    full_msg[binder_start..binder_start + binder.len()].copy_from_slice(&binder);
    Ok(full_msg)
}

// ---------------------------------------------------------------------
// Server side: parse and verify a client's pre_shared_key offer.
// ---------------------------------------------------------------------

/// The client's PSK offer, extracted from a ClientHello.
pub(crate) struct PskOffer {
    /// The first identity's ticket bytes.
    pub(crate) ticket: Vec<u8>,
    /// The corresponding binder value.
    pub(crate) binder: Vec<u8>,
    /// Byte offset of the binders-length field in the ClientHello body
    /// (the truncated message ends right before it).
    binders_len_offset: usize,
    binders_len: usize,
}

/// Extract the pre_shared_key offer. Returns None when the extension is
/// absent (a full handshake). Malformed offers are rejected with an
/// error rather than silently downgraded (a PSK-armed ClientHello must
/// be well-formed).
pub(crate) fn parse_pre_shared_key(ch_body: &[u8]) -> Result<Option<PskOffer>, TlsError> {
    let mut c = Cursor::new(ch_body);
    c.skip(2)?; // legacy_version
    c.skip(32)?; // random
    let sid_len = c.u8()? as usize;
    c.skip(sid_len)?;
    let suites_len = c.u16()? as usize;
    c.skip(suites_len)?;
    let comp_len = c.u8()? as usize;
    c.skip(comp_len)?;
    let ext_total = c.u16()? as usize;
    let ext_bytes_start = c.pos;
    let ext_bytes = c.take(ext_total)?;
    let mut e = Cursor::new(ext_bytes);
    let mut psk_ext: Option<(usize, usize)> = None; // (content_offset, content_len)
    let mut last_end = 0usize;
    while !e.done() {
        let ext_type = e.u16()?;
        let len = e.u16()? as usize;
        let content_off = e.pos;
        e.skip(len)?;
        last_end = e.pos;
        if ext_type == EXT_PRE_SHARED_KEY {
            if psk_ext.is_some() {
                return Err(TlsError::Protocol("duplicate pre_shared_key".into()));
            }
            psk_ext = Some((content_off, len));
        }
    }
    // pre_shared_key MUST be the last extension (RFC 8446 §4.2.11).
    let Some((content_off, content_len)) = psk_ext else {
        return Ok(None);
    };
    if last_end != ext_bytes.len() {
        return Err(TlsError::Protocol(
            "pre_shared_key is not the last ClientHello extension".into(),
        ));
    }
    let content = &ext_bytes[content_off..content_off + content_len];
    let mut p = Cursor::new(content);
    let identities_len = p.u16()? as usize;
    let identities = p.take(identities_len)?;
    let binders_len = p.u16()? as usize;
    let binders = p.take(binders_len)?;
    if !p.done() {
        return Err(TlsError::Protocol(
            "trailing bytes in pre_shared_key".into(),
        ));
    }
    // First identity.
    let mut id = Cursor::new(identities);
    let ticket_len = id.u16()? as usize;
    if ticket_len == 0 {
        return Err(TlsError::Protocol("empty PSK identity".into()));
    }
    let ticket = id.take(ticket_len)?.to_vec();
    id.skip(4)?; // obfuscated_ticket_age (this client sends 0)
    if !id.done() {
        return Err(TlsError::Protocol("trailing bytes in PSK identity".into()));
    }
    // First binder (must match the identity count).
    let mut b = Cursor::new(binders);
    let binder_len = b.u8()? as usize;
    if !(32..=255).contains(&binder_len) {
        return Err(TlsError::Protocol("invalid PSK binder length".into()));
    }
    let binder = b.take(binder_len)?.to_vec();
    if !b.done() {
        return Err(TlsError::Protocol("trailing bytes in PSK binders".into()));
    }
    // Absolute offset of the binders-length field in the CH body.
    let binders_len_offset = ext_bytes_start + content_off + 2 + identities_len;
    Ok(Some(PskOffer {
        ticket,
        binder,
        binders_len_offset,
        binders_len,
    }))
}

/// Verify a first-flight binder over Truncate(ClientHello).
pub(crate) fn verify_binder(
    ch_body: &[u8],
    offer: &PskOffer,
    suite: CipherSuite,
    psk: &[u8],
) -> bool {
    let Some(msg) = truncate_ch(ch_body, offer) else {
        return false;
    };
    check_binder(&msg, suite, psk, &offer.binder)
}

/// Verify a second-flight binder over `ClientHello1 || HelloRetryRequest
/// || Truncate(ClientHello2)` (RFC 8446 §4.2.11.2: the retried binder
/// includes the initial ClientHello and the HelloRetryRequest, with
/// ClientHello1 hashed directly — not as message_hash).
pub(crate) fn verify_binder_hrr(
    ch1: &[u8],
    hrr: &[u8],
    ch2_body: &[u8],
    offer: &PskOffer,
    suite: CipherSuite,
    psk: &[u8],
) -> bool {
    let Some(msg) = truncate_ch(ch2_body, offer) else {
        return false;
    };
    let mut transcript = Vec::with_capacity(ch1.len() + hrr.len() + msg.len());
    transcript.extend_from_slice(ch1);
    transcript.extend_from_slice(hrr);
    transcript.extend_from_slice(&msg);
    check_binder(&transcript, suite, psk, &offer.binder)
}

/// HMAC(binder_key, Transcript-Hash(transcript)) compared in constant time.
fn check_binder(transcript: &[u8], suite: CipherSuite, psk: &[u8], binder: &[u8]) -> bool {
    let binder_key = key_schedule::binder_key(suite, psk);
    let mut d = suite.hash().new_digest();
    d.update(transcript);
    let th = d.finalize();
    let expected = hmac(suite.hash().new_digest().as_mut(), &binder_key, &th);
    constant_time_eq(&expected, binder)
}

/// Truncate a ClientHello: keep the original handshake header (length
/// set as if the binders were present) and drop everything from the
/// binders-length field onward.
fn truncate_ch(ch_body: &[u8], offer: &PskOffer) -> Option<Vec<u8>> {
    let start = offer.binders_len_offset;
    if start + 2 + offer.binders_len > ch_body.len() {
        return None;
    }
    let mut out = Vec::with_capacity(4 + start);
    out.push(1); // ClientHello
    out.extend_from_slice(&[
        (ch_body.len() >> 16) as u8,
        (ch_body.len() >> 8) as u8,
        ch_body.len() as u8,
    ]);
    out.extend_from_slice(&ch_body[..start]);
    Some(out)
}

/// Derive the per-ticket resumption PSK from the resumption master
/// secret and the ticket nonce (RFC 8446 §7.1).
pub(crate) fn derive_psk(suite: CipherSuite, res_master: &[u8], nonce: &[u8]) -> Vec<u8> {
    use crate::courierust_tls::crypto::hmac::expand_label;
    expand_label(
        suite.hash().new_digest().as_mut(),
        res_master,
        b"resumption",
        nonce,
        suite.hash().hash_len(),
    )
}

/// Build a ServerHello that accepts a resumption (echoes selected
/// identity 0 in the pre_shared_key extension).
pub(crate) fn build_server_hello_psk(
    random: &[u8; 32],
    key_share: &[u8; 32],
    suite: CipherSuite,
    session_id: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.wire().to_be_bytes());
    body.push(0);
    let mut ext_bytes = Vec::new();
    let mut ks = Vec::new();
    ks.extend_from_slice(&0x001du16.to_be_bytes());
    ks.extend_from_slice(&[0x00, 0x20]);
    ks.extend_from_slice(key_share);
    ext_bytes.extend_from_slice(&0x0033u16.to_be_bytes());
    ext_bytes.extend_from_slice(&(ks.len() as u16).to_be_bytes());
    ext_bytes.extend_from_slice(&ks);
    ext_bytes.extend_from_slice(&0x002bu16.to_be_bytes());
    ext_bytes.extend_from_slice(&[0x00, 0x02, 0x03, 0x04]);
    // pre_shared_key: selected identity 0.
    ext_bytes.extend_from_slice(&EXT_PRE_SHARED_KEY.to_be_bytes());
    ext_bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);
    body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext_bytes);
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(2); // ServerHello
    msg.extend_from_slice(&[
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ]);
    msg.extend_from_slice(&body);
    msg
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

/// A minimal cursor for parsing untrusted handshake bytes.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn u8(&mut self) -> Result<u8, TlsError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| TlsError::Protocol("short read in ClientHello".into()))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, TlsError> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }

    fn skip(&mut self, n: usize) -> Result<(), TlsError> {
        self.take(n).map(|_| ())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| TlsError::Protocol("offset overflow in ClientHello".into()))?;
        if end > self.buf.len() {
            return Err(TlsError::Protocol("truncated ClientHello".into()));
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
}

fn take_u8(buf: &[u8], p: &mut usize, what: &str) -> Result<u8, TlsError> {
    let b = *buf
        .get(*p)
        .ok_or_else(|| TlsError::Protocol(format!("truncated {what}")))?;
    *p += 1;
    Ok(b)
}

fn take_u16(buf: &[u8], p: &mut usize, what: &str) -> Result<u16, TlsError> {
    let end = p
        .checked_add(2)
        .ok_or_else(|| TlsError::Protocol("offset overflow".into()))?;
    let b = buf
        .get(*p..end)
        .ok_or_else(|| TlsError::Protocol(format!("truncated {what}")))?;
    *p = end;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn take_u32(buf: &[u8], p: &mut usize, what: &str) -> Result<u32, TlsError> {
    let end = p
        .checked_add(4)
        .ok_or_else(|| TlsError::Protocol("offset overflow".into()))?;
    let b = buf
        .get(*p..end)
        .ok_or_else(|| TlsError::Protocol(format!("truncated {what}")))?;
    *p = end;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn take<'a>(buf: &'a [u8], p: &mut usize, n: usize, what: &str) -> Result<&'a [u8], TlsError> {
    let end = p
        .checked_add(n)
        .ok_or_else(|| TlsError::Protocol("offset overflow".into()))?;
    let b = buf
        .get(*p..end)
        .ok_or_else(|| TlsError::Protocol(format!("truncated {what}")))?;
    *p = end;
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_roundtrip() {
        let key = [7u8; 32];
        let suite = CipherSuite::TlsAes128GcmSha256;
        let psk = vec![0xabu8; 32];
        let now = 1_800_000_000i64;
        let ticket = encrypt_ticket(&key, suite, &psk, now);
        let (dec_suite, dec_psk) = decrypt_ticket(&key, &ticket, now).unwrap();
        assert_eq!(dec_suite, suite);
        assert_eq!(dec_psk, psk);
        // Expired ticket is rejected.
        assert!(decrypt_ticket(&key, &ticket, now + SESSION_LIFETIME_SECS + 1).is_err());
        // Tampering is rejected (flip a ciphertext byte past the nonce).
        let mut bad = ticket.clone();
        bad[13] ^= 1;
        assert!(decrypt_ticket(&key, &bad, now).is_err());
        // A different key rejects.
        let key2 = [8u8; 32];
        assert!(decrypt_ticket(&key2, &ticket, now).is_err());
    }

    #[test]
    fn new_session_ticket_roundtrip() {
        let ticket = build_new_session_ticket(3600, &[1, 2, 3], &[0xdd; 40]);
        // 4-byte handshake header + body.
        let parsed = parse_new_session_ticket(&ticket[4..]).unwrap();
        assert_eq!(parsed.lifetime, 3600);
        assert_eq!(parsed.nonce, vec![1, 2, 3]);
        assert_eq!(parsed.ticket, vec![0xdd; 40]);
    }

    #[test]
    fn client_hello_with_psk_parses_and_binder_verifies() {
        let suite = CipherSuite::TlsAes128GcmSha256;
        let psk = vec![0x42u8; 32];
        let ticket = vec![0x99u8; 40];
        let random = [1u8; 32];
        let key_share = [2u8; 32];
        let ch = build_client_hello_with_psk(
            &random,
            &key_share,
            &[b"h2".to_vec()],
            Some("localhost"),
            suite,
            &psk,
            &ticket,
        )
        .unwrap();
        // The message is a ClientHello.
        assert_eq!(ch[0], 1);
        let body = &ch[4..];
        let offer = parse_pre_shared_key(body).unwrap().expect("psk present");
        assert_eq!(offer.ticket, ticket);
        assert!(
            verify_binder(body, &offer, suite, &psk),
            "binder must verify"
        );
        // A different PSK fails the binder.
        assert!(!verify_binder(body, &offer, suite, &[0u8; 32]));
    }
}
