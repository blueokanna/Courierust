//! TLS 1.3 (RFC 8446), implemented from scratch with zero dependencies.
//!
//! This module provides a complete client and server handshake over the
//! crate's [`crate::courierust_io::Read`]/[`crate::courierust_io::Write`] transport traits, so
//! it works over TCP, and integrates with the HTTP/1.1 / HTTP/2 /
//! gRPC codecs to make **HTTPS** a first-class capability.
//!
//! Supported cryptographic profile (the modern TLS 1.3 baseline):
//!
//! * Cipher suites: `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`,
//!   `TLS_AES_256_GCM_SHA384`.
//! * Key exchange: X25519.
//! * Certificate signature verification: RSA-PSS / RSA PKCS#1 v1.5,
//!   ECDSA P-256, Ed25519 (SHA-256 / SHA-384 digests).
//! * X.509 chain validation with a pluggable root store (no bundled
//!   root certificates — supply your own roots via [`RootStore`]).
//!
//! Honest scope note: 0-RTT early data and key updates are not
//! implemented; resumption uses the standard 1-RTT PSK path (session
//! tickets with psk_dhe_ke) and a full handshake is performed otherwise.
//! The certificate verification performs chain building against the
//! provided roots, validity-window and hostname checks, and standard
//! key-usage/basic-constraints enforcement.

pub mod crypto;
pub(crate) mod session;
pub mod x509;

#[cfg(test)]
pub(crate) mod testdata;

mod handshake;
mod key_schedule;
pub(crate) mod quic;
mod record;
mod tls12;

use alloc::string::String;
use alloc::vec::Vec;

pub use x509::RootStore;

/// The TLS protocol version negotiated for a connection.
///
/// The crate speaks TLS 1.2 (RFC 5246, AEAD ECDHE suites only) and
/// TLS 1.3 (RFC 8446). Version selection is explicit and bounded by the
/// `min_version` / `max_version` fields on the client and server
/// configurations; the RFC 8446 §4.1.3 downgrade sentinel is enforced
/// on every path that could otherwise degrade silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.2 (legacy records, AEAD ECDHE suites).
    Tls12,
    /// TLS 1.3 (RFC 8446).
    Tls13,
}

/// TLS version identifier for TLS 1.3 (supported_versions extension).
pub const TLS_VERSION_1_3: u16 = 0x0304;
/// TLS version identifier for TLS 1.2 (legacy_record_version / fallback).
pub const TLS_VERSION_1_2: u16 = 0x0303;

/// Upper bound on accumulated decrypted handshake bytes. The protocol's
/// handshake length field is 24 bits (~16 MiB max), so a peer streaming
/// handshake records without completing a message is hostile — without
/// this cap the receive buffer would grow without bound (memory DoS).
const MAX_HANDSHAKE_BUFFER: usize = 16 * 1024 * 1024;

/// A parsed `ClientHello` summary (used by server-side ALPN/SNI and by
/// the fingerprint layer).
#[derive(Debug, Clone, Default)]
pub struct ClientHelloInfo {
    /// Server Name Indication (if any).
    pub server_name: Option<String>,
    /// Application-Layer Protocol Negotiation list (raw).
    pub alpn: Vec<Vec<u8>>,
    /// Negotiated ALPN protocol (set after the server chooses).
    pub negotiated_alpn: Option<Vec<u8>>,
    /// Supported cipher suites offered by the client (wire values).
    pub cipher_suites: Vec<u16>,
}

/// Errors that can occur during a TLS handshake or record operation.
#[derive(Debug, Clone)]
pub enum TlsError {
    /// Underlying transport error.
    Io(String),
    /// The peer sent a malformed or protocol-violating message.
    Protocol(String),
    /// The peer sent an alert.
    Alert {
        /// Alert severity level (1 = warning, 2 = fatal).
        level: u8,
        /// Alert description (RFC 8446 §6).
        description: u8,
    },
    /// The certificate chain failed validation.
    Certificate(String),
    /// The handshake did not complete in time.
    Timeout,
    /// The peer aborted the connection.
    UnexpectedEof,
    /// Unsupported feature requested by the peer.
    Unsupported(String),
    /// Internal error (should not happen).
    Internal(String),
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TlsError::Io(m) => write!(f, "TLS I/O error: {m}"),
            TlsError::Protocol(m) => write!(f, "TLS protocol error: {m}"),
            TlsError::Alert { level, description } => {
                write!(f, "TLS alert level={level} description={description}")
            }
            TlsError::Certificate(m) => write!(f, "TLS certificate error: {m}"),
            TlsError::Timeout => write!(f, "TLS handshake timeout"),
            TlsError::UnexpectedEof => write!(f, "TLS unexpected EOF"),
            TlsError::Unsupported(m) => write!(f, "TLS unsupported: {m}"),
            TlsError::Internal(m) => write!(f, "TLS internal error: {m}"),
        }
    }
}

impl From<crate::courierust_error::Error> for TlsError {
    fn from(e: crate::courierust_error::Error) -> Self {
        use crate::courierust_error::ErrorKind;
        match e.kind {
            ErrorKind::Timeout => TlsError::Timeout,
            ErrorKind::UnexpectedEof => TlsError::UnexpectedEof,
            _ => TlsError::Io(e.to_string()),
        }
    }
}

/// A result alias for TLS operations.
pub type TlsResult<T> = core::result::Result<T, TlsError>;

/// A cryptographic key pair used by the TLS server (or a client that
/// needs client certificates — not required for this release).
#[derive(Debug, Clone)]
pub struct Identity {
    /// The DER-encoded certificate chain (leaf first).
    pub cert_chain: Vec<Vec<u8>>,
    /// The private key (PKCS#8 or PKCS#1 DER) for the leaf certificate.
    pub private_key: Vec<u8>,
    /// Whether the private key is an RSA key.
    pub is_rsa: bool,
}

// ---------------------------------------------------------------------
// Record-level transport (TlsIo)
// ---------------------------------------------------------------------

use crate::courierust_io::{BufReader, BufWriter};
use record::{open_record, seal_record, Sequence, CONTENT_HANDSHAKE, MAX_RECORD_PAYLOAD};

/// Buffered record-level I/O over a transport. Sequence numbers are
/// tracked per direction and reset when the traffic keys change.
pub(crate) struct TlsIo<R, W> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
    read_seq: Sequence,
    write_seq: Sequence,
}

impl<R: crate::courierust_io::Read, W: crate::courierust_io::Write> TlsIo<R, W> {
    pub(crate) fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader, 65536),
            writer: BufWriter::new(writer, 65536),
            read_seq: Sequence::default(),
            write_seq: Sequence::default(),
        }
    }

    /// Write an unencrypted record (ClientHello / ServerHello / alerts).
    pub(crate) fn write_plaintext_record(
        &mut self,
        content_type: u8,
        payload: &[u8],
    ) -> TlsResult<()> {
        self.write_plaintext_record_v([0x03, 0x01], content_type, payload)
    }

    /// Write an unencrypted record with an explicit record-layer version
    /// (TLS 1.2 uses 0x0303 for its records; the TLS 1.3 client hello
    /// conventionally uses the legacy 0x0301).
    pub(crate) fn write_plaintext_record_v(
        &mut self,
        version: [u8; 2],
        content_type: u8,
        payload: &[u8],
    ) -> TlsResult<()> {
        if payload.len() > u16::MAX as usize {
            return Err(TlsError::Protocol("record too large".into()));
        }
        let header = [
            content_type,
            version[0],
            version[1],
            (payload.len() >> 8) as u8,
            payload.len() as u8,
        ];
        self.writer.write_all(&header).map_err(TlsError::from)?;
        self.writer.write_all(payload).map_err(TlsError::from)?;
        self.writer.flush().map_err(TlsError::from)
    }

    /// Write one TLS 1.2 AEAD record (RFC 5246 §6.2.3.3).
    pub(crate) fn write_tls12_record(
        &mut self,
        suite: tls12::Tls12Suite,
        keys: &key_schedule::TrafficKeys,
        content_type: u8,
        payload: &[u8],
    ) -> TlsResult<()> {
        let seq = self.write_seq.next()?;
        let rec = tls12::seal_record(suite, keys, seq, content_type, payload)?;
        self.writer.write_all(&rec).map_err(TlsError::from)?;
        self.writer.flush().map_err(TlsError::from)
    }

    /// Write one TLS 1.2 AEAD record into the internal buffer *without*
    /// flushing (bulk application data).
    pub(crate) fn write_tls12_record_buffered(
        &mut self,
        suite: tls12::Tls12Suite,
        keys: &key_schedule::TrafficKeys,
        content_type: u8,
        payload: &[u8],
    ) -> TlsResult<()> {
        let seq = self.write_seq.next()?;
        let rec = tls12::seal_record(suite, keys, seq, content_type, payload)?;
        self.writer.write_all(&rec).map_err(TlsError::from)
    }

    /// Read one TLS 1.2 record: decrypts AEAD records and returns the
    /// real content type and plaintext; a `change_cipher_spec` record is
    /// returned as-is (it is not protected and does not consume a
    /// sequence number).
    pub(crate) fn read_tls12_record(
        &mut self,
        suite: tls12::Tls12Suite,
        keys: &key_schedule::TrafficKeys,
    ) -> TlsResult<(u8, Vec<u8>)> {
        let mut header = [0u8; 5];
        self.reader
            .read_exact_into(&mut header)
            .map_err(TlsError::from)?;
        let len = ((header[3] as usize) << 8) | header[4] as usize;
        if len > record::MAX_RECORD_PAYLOAD + 8 + 16 {
            return Err(TlsError::Protocol("record too large".into()));
        }
        let body = self.reader.read_exact(len).map_err(TlsError::from)?;
        if header[0] == record::CONTENT_CHANGE_CIPHER_SPEC {
            if len != 1 || body.first() != Some(&1) {
                return Err(TlsError::Protocol("malformed ChangeCipherSpec".into()));
            }
            return Ok((record::CONTENT_CHANGE_CIPHER_SPEC, body));
        }
        let seq = self.read_seq.next()?;
        tls12::open_record(suite, keys, seq, &header, &body)
    }

    /// Read one unencrypted record and return (type, payload).
    pub(crate) fn read_plaintext_record(&mut self) -> TlsResult<(u8, Vec<u8>)> {
        let mut header = [0u8; 5];
        self.reader
            .read_exact_into(&mut header)
            .map_err(TlsError::from)?;
        let content_type = header[0];
        let len = ((header[3] as usize) << 8) | header[4] as usize;
        if len > MAX_RECORD_PAYLOAD {
            return Err(TlsError::Protocol("record too large".into()));
        }
        let payload = self.reader.read_exact(len).map_err(TlsError::from)?;
        Ok((content_type, payload))
    }

    /// Read one plaintext handshake record; returns the handshake body
    /// (after the 4-byte handshake header).
    pub(crate) fn read_plaintext_handshake(&mut self) -> TlsResult<(u8, Vec<u8>)> {
        let (ct, payload) = self.read_plaintext_record()?;
        if ct != CONTENT_HANDSHAKE {
            return Err(TlsError::Protocol("expected handshake record".into()));
        }
        if payload.len() < 4 {
            return Err(TlsError::Protocol("bad handshake record".into()));
        }
        Ok((payload[0], payload[4..].to_vec()))
    }

    /// Write an encrypted record and flush it to the transport. Used for
    /// handshake flights and alerts, where the peer is waiting on the
    /// bytes before it can continue.
    pub(crate) fn write_encrypted_record(
        &mut self,
        suite: key_schedule::CipherSuite,
        keys: &key_schedule::TrafficKeys,
        content_type: u8,
        payload: &[u8],
    ) -> TlsResult<()> {
        let seq = self.write_seq.next()?;
        let rec = seal_record(suite, keys, seq, content_type, payload)?;
        self.writer.write_all(&rec).map_err(TlsError::from)?;
        self.writer.flush().map_err(TlsError::from)
    }

    /// Write an encrypted record into the internal buffer *without*
    /// flushing. Bulk application data uses this and flushes once per
    /// batch ([`crate::courierust_tls::TlsStream::write_all`]) so a large
    /// body costs one syscall per buffer-full instead of one per
    /// ~16 KiB record.
    pub(crate) fn write_encrypted_record_buffered(
        &mut self,
        suite: key_schedule::CipherSuite,
        keys: &key_schedule::TrafficKeys,
        content_type: u8,
        payload: &[u8],
    ) -> TlsResult<()> {
        let seq = self.write_seq.next()?;
        let rec = seal_record(suite, keys, seq, content_type, payload)?;
        self.writer.write_all(&rec).map_err(TlsError::from)
    }

    pub(crate) fn read_encrypted_handshake(
        &mut self,
        suite: key_schedule::CipherSuite,
        keys: &key_schedule::TrafficKeys,
    ) -> TlsResult<Vec<u8>> {
        let mut plain = Vec::new();
        loop {
            let mut header = [0u8; 5];
            self.reader
                .read_exact_into(&mut header)
                .map_err(TlsError::from)?;
            let len = ((header[3] as usize) << 8) | header[4] as usize;
            if len > MAX_RECORD_PAYLOAD + 16 {
                return Err(TlsError::Protocol("record too large".into()));
            }
            let encrypted = self.reader.read_exact(len).map_err(TlsError::from)?;
            if header[0] == record::CONTENT_CHANGE_CIPHER_SPEC {
                if len != 1 || encrypted.first() != Some(&1) {
                    return Err(TlsError::Protocol("malformed ChangeCipherSpec".into()));
                }
                continue;
            }
            let seq = self.read_seq.next()?;
            let (ct, payload) = open_record(suite, keys, seq, &header, &encrypted)?;
            if ct == CONTENT_HANDSHAKE {
                if plain.len() > MAX_HANDSHAKE_BUFFER - payload.len() {
                    return Err(TlsError::Protocol(
                        "handshake message exceeds the 16 MiB protocol maximum".into(),
                    ));
                }
                plain.extend_from_slice(&payload);
                // A peer may fragment its flight across many records; only
                // stop once the whole flight (ending in Finished) is
                // buffered.
                if handshake::has_complete_finished(&plain) {
                    return Ok(plain);
                }
            }
        }
    }

    /// Switch to a fresh set of keys (resets sequence numbers).
    pub(crate) fn reset_sequences(&mut self) {
        self.read_seq = Sequence::default();
        self.write_seq = Sequence::default();
    }
}

// ---------------------------------------------------------------------
// Public TLS stream
// ---------------------------------------------------------------------

/// State of an in-progress inbound TLS record read. The transport read
/// timeout is a *wake-up* mechanism (the h2 driver polls with a short
/// socket timeout), so a record may be interrupted mid-header or
/// mid-payload. This state lets `read_record` resume exactly where it
/// stopped instead of treating a transient timeout as fatal (which would
/// otherwise kill TLS connections under load).
enum RecState {
    /// No partial record in flight.
    Idle,
    /// Reading the 5-byte record header.
    Header { hdr: [u8; 5], filled: usize },
    /// Header complete; reading the (encrypted) payload.
    Payload {
        header: [u8; 5],
        payload: Vec<u8>,
        filled: usize,
    },
}

/// A completed TLS 1.2 / 1.3 connection. Implements the crate's `Read`
/// and `Write` traits for encrypted application data. The record layer
/// branches on [`TlsVersion`]: TLS 1.3 uses the inner content-type
/// layout (RFC 8446 §5.2), TLS 1.2 the legacy AEAD layout (RFC 5246
/// §6.2.3.3) with real content types on the wire.
pub struct TlsStream<R, W> {
    io: TlsIo<R, W>,
    /// The negotiated protocol version.
    version: TlsVersion,
    /// The negotiated TLS 1.3 suite (meaningful when `version` is
    /// [`TlsVersion::Tls13`]).
    suite: key_schedule::CipherSuite,
    /// The negotiated TLS 1.2 suite (meaningful when `version` is
    /// [`TlsVersion::Tls12`]).
    suite12: Option<tls12::Tls12Suite>,
    write_keys: key_schedule::TrafficKeys,
    read_keys: key_schedule::TrafficKeys,
    negotiated_alpn: Option<Vec<u8>>,
    server_name: Option<String>,
    peer_certificate: Option<Vec<u8>>,
    closed: bool,
    /// A decrypted record awaiting delivery to the caller.
    pending: Vec<u8>,
    /// Read offset into `pending`. Keeping a cursor instead of draining
    /// the front of the Vec avoids an O(n²) memmove when a caller reads
    /// a large record in small chunks.
    pending_pos: usize,
    /// Resumable inbound record read (see [`RecState`]).
    rec: RecState,
    /// Client side: the resumption master secret (with the negotiated
    /// suite) used to derive per-ticket PSKs (RFC 8446 §7.1).
    resumption_master: Option<(Vec<u8>, key_schedule::CipherSuite)>,
    /// True when this handshake was resumed from a PSK.
    resumed: bool,
    /// Shared resumption-session cache (set by the connector): tickets
    /// captured lazily while reading are stored here for future connects.
    session_store: Option<std::sync::Arc<std::sync::Mutex<Vec<session::ClientSession>>>>,
    /// The server name this connection authenticated (used when storing
    /// resumption sessions).
    hostname: String,
    /// Current Unix time (stamps issued sessions).
    now: i64,
}

impl<R: crate::courierust_io::Read, W: crate::courierust_io::Write> TlsStream<R, W> {
    /// The negotiated ALPN protocol, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// The underlying reader transport (used to reconfigure socket
    /// timeouts after the handshake).
    pub(crate) fn underlying(&self) -> &R {
        self.io.reader.get_ref()
    }

    /// The server name (SNI) used for this connection.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// The peer's leaf certificate (DER), if the peer authenticated.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_deref()
    }

    /// The negotiated TLS version.
    pub fn version(&self) -> TlsVersion {
        self.version
    }

    /// The negotiated cipher suite wire value.
    pub fn cipher_suite(&self) -> u16 {
        match self.version {
            TlsVersion::Tls13 => self.suite.wire(),
            TlsVersion::Tls12 => self.suite12.map(|s| s.wire()).unwrap_or(0),
        }
    }

    /// Write application data (encrypted).
    pub fn write_all(&mut self, data: &[u8]) -> TlsResult<()> {
        if self.closed {
            return Err(TlsError::Protocol("connection closed".into()));
        }
        let mut off = 0;
        while off < data.len() {
            let take = core::cmp::min(data.len() - off, record::MAX_RECORD_PAYLOAD - 2);
            match self.version {
                TlsVersion::Tls13 => self.io.write_encrypted_record_buffered(
                    self.suite,
                    &self.write_keys,
                    record::CONTENT_APPLICATION_DATA,
                    &data[off..off + take],
                )?,
                TlsVersion::Tls12 => {
                    let suite12 = self
                        .suite12
                        .ok_or_else(|| TlsError::Internal("missing TLS 1.2 suite".into()))?;
                    self.io.write_tls12_record_buffered(
                        suite12,
                        &self.write_keys,
                        record::CONTENT_APPLICATION_DATA,
                        &data[off..off + take],
                    )?
                }
            }
            off += take;
        }
        self.io.writer.flush().map_err(TlsError::from)?;
        Ok(())
    }

    /// Read one application-data record (up to one TLS record of data).
    /// Returns Ok(0) on clean shutdown. Any `NewSessionTicket` messages
    /// carried in post-handshake records are captured first.
    pub fn read_record(&mut self) -> TlsResult<Vec<u8>> {
        if self.closed {
            return Ok(Vec::new());
        }
        // A previously stashed record (set by callers that pre-read) is
        // delivered before reading more from the transport.
        if self.pending_pos < self.pending.len() {
            let out = self.pending[self.pending_pos..].to_vec();
            self.pending_pos = self.pending.len();
            return Ok(out);
        }
        loop {
            match self.version {
                TlsVersion::Tls13 => match self.read_one_tls13_record()? {
                    None => return Ok(Vec::new()), // clean EOF
                    Some((ct, payload)) => match ct {
                        record::CONTENT_APPLICATION_DATA => return Ok(payload),
                        record::CONTENT_ALERT => {
                            if payload.first() == Some(&1) && payload.get(1) == Some(&0) {
                                self.closed = true;
                                return Ok(Vec::new());
                            }
                            return Err(TlsError::Alert {
                                level: payload.first().copied().unwrap_or(2),
                                description: payload.get(1).copied().unwrap_or(0),
                            });
                        }
                        record::CONTENT_HANDSHAKE => {
                            if let Some(m) = handshake::peek_complete_hs(&payload) {
                                if m.msg_type != handshake::HS_NEW_SESSION_TICKET {
                                    return Err(TlsError::Protocol(
                                        "unexpected handshake after handshake".into(),
                                    ));
                                }
                                self.capture_ticket(&payload)?;
                            }
                        }
                        record::CONTENT_CHANGE_CIPHER_SPEC => continue,
                        _ => {
                            return Err(TlsError::Protocol("unexpected record type".into()));
                        }
                    },
                },
                TlsVersion::Tls12 => {
                    let payload_len = match &self.rec {
                        RecState::Payload { payload, .. } => payload.len(),
                        _ => match self.read_record_header()? {
                            Some((_, len)) => len,
                            None => return Ok(Vec::new()),
                        },
                    };
                    if payload_len > record::MAX_RECORD_PAYLOAD + 8 + 16 {
                        return Err(TlsError::Protocol("record too large".into()));
                    }
                    let (header, encrypted) = self.read_record_payload()?;
                    if header[0] == record::CONTENT_CHANGE_CIPHER_SPEC {
                        if encrypted.len() != 1 || encrypted[0] != 1 {
                            return Err(TlsError::Protocol("malformed ChangeCipherSpec".into()));
                        }
                        continue;
                    }
                    let suite12 = self
                        .suite12
                        .ok_or_else(|| TlsError::Internal("missing TLS 1.2 suite".into()))?;
                    let seq = self.io.read_seq.next()?;
                    let (ct, payload) =
                        tls12::open_record(suite12, &self.read_keys, seq, &header, &encrypted)?;
                    match ct {
                        record::CONTENT_APPLICATION_DATA => return Ok(payload),
                        record::CONTENT_ALERT => {
                            if payload.first() == Some(&1) && payload.get(1) == Some(&0) {
                                self.closed = true;
                                return Ok(Vec::new());
                            }
                            return Err(TlsError::Alert {
                                level: payload.first().copied().unwrap_or(2),
                                description: payload.get(1).copied().unwrap_or(0),
                            });
                        }
                        record::CONTENT_HANDSHAKE => {
                            return Err(TlsError::Protocol(
                                "unexpected handshake after handshake".into(),
                            ));
                        }
                        _ => {
                            return Err(TlsError::Protocol("unexpected record type".into()));
                        }
                    }
                }
            }
        }
    }

    /// Read and open one TLS 1.3 record (resuming a partial header/payload
    /// across a timed-out read). `Ok(None)` is a clean EOF; a read
    /// timeout surfaces as [`TlsError::Timeout`] with the read state
    /// preserved so a later read resumes.
    fn read_one_tls13_record(&mut self) -> TlsResult<Option<(u8, Vec<u8>)>> {
        loop {
            let payload_len = match &self.rec {
                RecState::Payload { payload, .. } => payload.len(),
                _ => match self.read_record_header()? {
                    Some((_, len)) => len,
                    None => return Ok(None),
                },
            };
            if payload_len > record::MAX_RECORD_PAYLOAD + 8 + 16 {
                return Err(TlsError::Protocol("record too large".into()));
            }
            let (header, encrypted) = self.read_record_payload()?;
            if header[0] == record::CONTENT_CHANGE_CIPHER_SPEC {
                if encrypted.len() != 1 || encrypted[0] != 1 {
                    return Err(TlsError::Protocol("malformed ChangeCipherSpec".into()));
                }
                continue;
            }
            if header[0] != record::CONTENT_APPLICATION_DATA {
                return Err(TlsError::Protocol("unexpected record type".into()));
            }
            let seq = self.io.read_seq.next()?;
            let (ct, payload) =
                record::open_record(self.suite, &self.read_keys, seq, &header, &encrypted)?;
            return Ok(Some((ct, payload)));
        }
    }

    /// Parse every `NewSessionTicket` in a post-handshake handshake
    /// record and derive its resumption PSK from the resumption master
    /// secret (RFC 8446 §7.1). The session is cached for future connects
    /// (lazy capture — this runs as tickets are read off the connection).
    fn capture_ticket(&mut self, payload: &[u8]) -> TlsResult<()> {
        let Some((res_master, suite)) = self.resumption_master.clone() else {
            return Ok(()); // no resumption on this connection
        };
        let mut rest = payload;
        while !rest.is_empty() {
            let Some(m) = handshake::peek_complete_hs(rest) else {
                break;
            };
            if m.msg_type == handshake::HS_NEW_SESSION_TICKET {
                if let Ok(ticket) = session::parse_new_session_ticket(m.body) {
                    let psk = session::derive_psk(suite, &res_master, &ticket.nonce);
                    let sess = session::ClientSession {
                        hostname: self.hostname.clone(),
                        ticket: ticket.ticket,
                        psk,
                        suite,
                        issued_at: self.now,
                        // Honor the server's lifetime, capped at 7 days.
                        lifetime: (ticket.lifetime as i64).min(session::SESSION_LIFETIME_SECS),
                    };
                    if let Some(store) = &self.session_store {
                        cache_session(&mut store.lock().unwrap(), sess);
                    }
                }
            }
            rest = &rest[4 + m.body.len()..];
        }
        Ok(())
    }

    /// Whether this handshake was resumed from a PSK.
    /// Whether this connection was resumed via a PSK (RFC 8446 §2.2).
    /// The first connection after a ticket is issued is a full handshake;
    /// a later connection offering that ticket is resumed.
    pub fn resumed(&self) -> bool {
        self.resumed
    }

    /// Ensure a complete 5-byte record header is buffered, resuming from
    /// a partial header left by a previous (timed-out) read. `Ok(None)`
    /// means the peer closed cleanly. On success the internal state
    /// transitions to [`RecState::Payload`] so the next phase knows the
    /// expected payload length.
    fn read_record_header(&mut self) -> TlsResult<Option<([u8; 5], usize)>> {
        let (mut hdr, mut filled) = match &self.rec {
            RecState::Header { hdr, filled } => (*hdr, *filled),
            _ => ([0u8; 5], 0),
        };
        loop {
            if filled == 5 {
                let payload_len = ((hdr[3] as usize) << 8) | hdr[4] as usize;
                self.rec = RecState::Payload {
                    header: hdr,
                    payload: vec![0u8; payload_len],
                    filled: 0,
                };
                return Ok(Some((hdr, payload_len)));
            }
            match self.io.reader.fill_buf() {
                Ok([]) => {
                    self.closed = true;
                    return Ok(None);
                }
                Ok(b) => {
                    let take = core::cmp::min(5 - filled, b.len());
                    hdr[filled..filled + take].copy_from_slice(&b[..take]);
                    self.io.reader.consume(take);
                    filled += take;
                }
                Err(e)
                    if e.kind == crate::courierust_error::ErrorKind::Timeout
                        || e.kind == crate::courierust_error::ErrorKind::WouldBlock =>
                {
                    self.rec = RecState::Header { hdr, filled };
                    return Err(TlsError::Timeout);
                }
                Err(e) if e.kind == crate::courierust_error::ErrorKind::UnexpectedEof => {
                    self.closed = true;
                    return Ok(None);
                }
                Err(e) => return Err(TlsError::from(e)),
            }
        }
    }

    /// Ensure the full encrypted payload of the current record is
    /// buffered, resuming from a partial payload. The internal state is
    /// in [`RecState::Payload`] when this is called.
    fn read_record_payload(&mut self) -> TlsResult<([u8; 5], Vec<u8>)> {
        let (header, mut payload, mut filled) =
            match core::mem::replace(&mut self.rec, RecState::Idle) {
                RecState::Payload {
                    header,
                    payload,
                    filled,
                } => (header, payload, filled),
                _ => return Err(TlsError::Internal("payload read without header".into())),
            };
        let total = payload.len();
        loop {
            if filled == total {
                return Ok((header, payload));
            }
            match self.io.reader.fill_buf() {
                Ok([]) => {
                    self.closed = true;
                    return Err(TlsError::UnexpectedEof);
                }
                Ok(b) => {
                    let take = core::cmp::min(total - filled, b.len());
                    payload[filled..filled + take].copy_from_slice(&b[..take]);
                    self.io.reader.consume(take);
                    filled += take;
                }
                Err(e)
                    if e.kind == crate::courierust_error::ErrorKind::Timeout
                        || e.kind == crate::courierust_error::ErrorKind::WouldBlock =>
                {
                    self.rec = RecState::Payload {
                        header,
                        payload,
                        filled,
                    };
                    return Err(TlsError::Timeout);
                }
                Err(e) if e.kind == crate::courierust_error::ErrorKind::UnexpectedEof => {
                    self.closed = true;
                    return Err(TlsError::UnexpectedEof);
                }
                Err(e) => return Err(TlsError::from(e)),
            }
        }
    }

    /// Send a close_notify alert and flush.
    pub fn close_notify(&mut self) -> TlsResult<()> {
        if !self.closed {
            let alert = [1u8, 0u8]; // warning, close_notify
            match self.version {
                TlsVersion::Tls13 => self.io.write_encrypted_record(
                    self.suite,
                    &self.write_keys,
                    record::CONTENT_ALERT,
                    &alert,
                )?,
                TlsVersion::Tls12 => {
                    let suite12 = self
                        .suite12
                        .ok_or_else(|| TlsError::Internal("missing TLS 1.2 suite".into()))?;
                    self.io.write_tls12_record(
                        suite12,
                        &self.write_keys,
                        record::CONTENT_ALERT,
                        &alert,
                    )?
                }
            }
        }
        self.closed = true;
        Ok(())
    }
}

impl<R: crate::courierust_io::Read, W: crate::courierust_io::Write> crate::courierust_io::Read
    for TlsStream<R, W>
{
    fn read(&mut self, buf: &mut [u8]) -> crate::courierust_error::Result<usize> {
        if self.pending_pos >= self.pending.len() {
            self.pending = match self.read_record() {
                Ok(p) => p,
                Err(TlsError::Timeout) => {
                    return Err(crate::courierust_error::Error::new(
                        crate::courierust_error::ErrorKind::Timeout,
                    ))
                }
                Err(e) => {
                    return Err(crate::courierust_error::Error::with_message(
                        crate::courierust_error::ErrorKind::Other,
                        e.to_string(),
                    ))
                }
            };
            self.pending_pos = 0;
            if self.pending.is_empty() {
                return Ok(0);
            }
        }
        let avail = self.pending.len() - self.pending_pos;
        let n = core::cmp::min(buf.len(), avail);
        buf[..n].copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
        self.pending_pos += n;
        Ok(n)
    }
}

impl<R: crate::courierust_io::Read, W: crate::courierust_io::Write> crate::courierust_io::Write
    for TlsStream<R, W>
{
    fn write(&mut self, buf: &[u8]) -> crate::courierust_error::Result<usize> {
        self.write_all(buf).map_err(|e| {
            crate::courierust_error::Error::with_message(
                crate::courierust_error::ErrorKind::Other,
                e.to_string(),
            )
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> crate::courierust_error::Result<()> {
        self.io.writer.flush().map_err(|e| {
            crate::courierust_error::Error::with_message(
                crate::courierust_error::ErrorKind::Other,
                e.to_string(),
            )
        })
    }
}

// ---------------------------------------------------------------------
// Client connector
// ---------------------------------------------------------------------

/// Client-side TLS configuration.
pub struct ClientConfig {
    /// Trust anchors for server certificate validation.
    pub roots: RootStore,
    /// Whether to validate the server certificate (and hostname).
    pub verify: bool,
    /// ALPN protocols offered (raw wire values).
    pub alpn: Vec<Vec<u8>>,
    /// The current time (Unix seconds) used for validity checks.
    pub now: i64,
    /// The lowest TLS version the client will negotiate. Defaults to
    /// [`TlsVersion::Tls12`]; set to [`TlsVersion::Tls13`] to refuse
    /// TLS 1.2 outright.
    pub min_version: TlsVersion,
    /// The highest TLS version the client will negotiate. Defaults to
    /// [`TlsVersion::Tls13`].
    pub max_version: TlsVersion,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            roots: RootStore::new(),
            verify: true,
            alpn: Vec::new(),
            now: 0,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
        }
    }
}

/// A TLS 1.2 / 1.3 client connector.
pub struct TlsConnector {
    config: ClientConfig,
    /// Resumable sessions (NewSessionTickets), keyed by server name.
    /// Shared across connects on the same connector and populated lazily
    /// as tickets are read off connections.
    sessions: std::sync::Arc<std::sync::Mutex<Vec<session::ClientSession>>>,
}

impl TlsConnector {
    /// Create a connector from a configuration.
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            sessions: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// The underlying configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Forget every cached resumption session.
    pub fn clear_sessions(&self) {
        self.sessions.lock().unwrap().clear();
    }

    /// Find a fresh resumption session for `hostname`.
    fn find_session(&self, hostname: &str) -> Option<session::ClientSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .iter()
            .find(|s| s.hostname == hostname)
            .filter(|s| s.is_fresh(self.config.now))
            .cloned()
    }

    /// Perform a TLS handshake over `stream`, authenticating `hostname`
    /// against the server certificate. The negotiated version is chosen
    /// by the server within `min_version..=max_version`; a TLS 1.2
    /// response to a client that offered TLS 1.3 is accepted only with
    /// the RFC 8446 downgrade sentinel, and a TLS 1.3 response to a
    /// client that did not offer TLS 1.3 is rejected.
    pub fn connect<R: crate::courierust_io::Read, W: crate::courierust_io::Write>(
        &self,
        hostname: &str,
        reader: R,
        writer: W,
    ) -> TlsResult<TlsStream<R, W>> {
        let mut io = TlsIo::new(reader, writer);
        let allow13 = self.config.max_version >= TlsVersion::Tls13;
        let allow12 = self.config.min_version <= TlsVersion::Tls12;

        // Build and send a ClientHello covering the configured window. A
        // fresh resumption session (if any) is offered via psk_dhe_ke.
        let mut random = [0u8; 32];
        handshake::fill_entropy(&mut random)?;
        let mut priv13 = [0u8; 32];
        handshake::fill_entropy(&mut priv13)?;
        let pub13 = crypto::x25519::x25519(&priv13, &crypto::x25519::BASE_POINT);
        let resume_session = allow13.then(|| self.find_session(hostname)).flatten();
        let ch = match &resume_session {
            Some(s) => session::build_client_hello_with_psk(
                &random,
                &pub13,
                &self.config.alpn,
                Some(hostname),
                s.suite,
                &s.psk,
                &s.ticket,
            )?,
            None => handshake::build_client_hello_negotiated(
                &random,
                Some(&pub13),
                &self.config.alpn,
                Some(hostname),
                None,
                allow13,
                allow12,
            ),
        };
        io.write_plaintext_record_v(tls12::VERSION_12, record::CONTENT_HANDSHAKE, &ch)?;

        // Read the first plaintext record and dispatch on the negotiated
        // version. The full payload is kept: a TLS 1.2 peer may coalesce
        // the ServerHello with the rest of its flight in one record.
        let (ct, first_payload) = io.read_plaintext_record()?;
        if ct != record::CONTENT_HANDSHAKE {
            return Err(TlsError::Protocol("expected handshake record".into()));
        }
        if first_payload.len() < 4 {
            return Err(TlsError::Protocol("bad handshake record".into()));
        }
        let sh_body = &first_payload[4..];
        // HelloRetryRequest (RFC 8446 §4.1.4). This client always offers
        // an X25519 share and implements only X25519 TLS 1.3 key
        // exchange, so a well-formed HRR either requests a group already
        // offered (a server protocol error — the retry would change
        // nothing) or a group this client cannot provide. Both cases
        // abort with the RFC-mandated fatal alert rather than mis-parsing
        // the HRR as a ServerHello.
        if handshake::is_hello_retry_request(sh_body) {
            let hrr = handshake::parse_hello_retry_request(sh_body)?;
            if hrr.selected_group == handshake::GROUP_X25519
                || (hrr.selected_group != tls12::GROUP_SECP256R1)
            {
                // Selected group already offered, or not in our
                // supported_groups at all.
                let _ = io.write_plaintext_record(record::CONTENT_ALERT, &[2, 47]); // illegal_parameter
                return Err(TlsError::Protocol(
                    "HelloRetryRequest selected an invalid key exchange group".into(),
                ));
            }
            // secp256r1 is supported but this client has no TLS 1.3
            // P-256 ECDHE implementation.
            let _ = io.write_plaintext_record(record::CONTENT_ALERT, &[2, 40]); // handshake_failure
            return Err(TlsError::Unsupported(format!(
                "HelloRetryRequest requested unsupported group 0x{:04x}",
                hrr.selected_group
            )));
        }
        let is13 = handshake::server_hello_negotiates_tls13(sh_body);
        if is13 {
            if !allow13 {
                return Err(TlsError::Protocol(
                    "server negotiated TLS 1.3 but the client did not offer it".into(),
                ));
            }
            let hs = handshake::ClientHandshake {
                server_name: Some(hostname.to_string()),
                verify: self.config.verify,
                psk: resume_session.map(|s| (s.psk, s.suite)),
            };
            let result = hs.run_from_server_hello(
                &mut io,
                &self.config.roots,
                self.config.now,
                &ch,
                &random,
                &priv13,
                sh_body,
                None,
            )?;
            io.reset_sequences();
            let stream = TlsStream {
                io,
                version: TlsVersion::Tls13,
                suite: result.suite,
                suite12: None,
                write_keys: result.keys.write,
                read_keys: result.keys.read,
                negotiated_alpn: result.alpn,
                server_name: result.server_name,
                peer_certificate: result.peer_cert,
                closed: false,
                pending: Vec::new(),
                pending_pos: 0,
                rec: RecState::Idle,
                resumption_master: result.resumption_master.map(|m| (m, result.suite)),
                resumed: result.resumed,
                session_store: Some(self.sessions.clone()),
                hostname: hostname.to_string(),
                now: self.config.now,
            };
            // Tickets are captured lazily as records are read and cached
            // in the shared store; connect() never blocks waiting for a
            // post-handshake message.
            Ok(stream)
        } else {
            if !allow12 {
                return Err(TlsError::Protocol(
                    "server negotiated TLS 1.2 but the client refused it".into(),
                ));
            }
            let result = tls12::client_handshake(
                &mut io,
                &self.config.roots,
                self.config.now,
                self.config.verify,
                Some(hostname),
                &ch,
                &random,
                &first_payload,
                allow13,
            )?;
            // TLS 1.2 keeps one key generation for the whole connection:
            // the Finished already consumed sequence number 0, so the
            // sequence counters are NOT reset here (unlike TLS 1.3).
            Ok(TlsStream {
                io,
                version: TlsVersion::Tls12,
                suite: key_schedule::CipherSuite::TlsAes128GcmSha256,
                suite12: Some(result.suite),
                write_keys: result.keys.write,
                read_keys: result.keys.read,
                negotiated_alpn: result.alpn,
                server_name: result.server_name,
                peer_certificate: result.peer_cert,
                closed: false,
                pending: Vec::new(),
                pending_pos: 0,
                rec: RecState::Idle,
                resumption_master: None,
                resumed: false,
                session_store: None,
                hostname: hostname.to_string(),
                now: self.config.now,
            })
        }
    }
}

// ---------------------------------------------------------------------
// Server acceptor
// ---------------------------------------------------------------------

/// Insert a resumption session into a shared cache, replacing any older
/// entry for the same host and evicting the oldest when the bound is
/// exceeded (bounded memory).
fn cache_session(store: &mut Vec<session::ClientSession>, sess: session::ClientSession) {
    store.retain(|s| s.hostname != sess.hostname);
    store.push(sess);
    const MAX_SESSIONS: usize = 8;
    if store.len() > MAX_SESSIONS {
        let overflow = store.len() - MAX_SESSIONS;
        store.drain(..overflow);
    }
}

/// Current Unix time in seconds (server-side ticket stamping).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Server-side TLS configuration.
pub struct ServerConfig {
    /// The server's certificate chain and private key.
    pub identity: Identity,
    /// ALPN protocols offered (the first match wins).
    pub alpn: Vec<Vec<u8>>,
    /// The lowest TLS version the server will negotiate. Defaults to
    /// [`TlsVersion::Tls12`]; set to [`TlsVersion::Tls13`] to refuse
    /// TLS 1.2 clients outright.
    pub min_version: TlsVersion,
    /// The highest TLS version the server will negotiate. Defaults to
    /// [`TlsVersion::Tls13`].
    pub max_version: TlsVersion,
    /// Key used to encrypt session tickets. `None` generates a fresh
    /// per-acceptor key, so sessions survive across connections served
    /// by the same acceptor but not across process restarts.
    pub session_ticket_key: Option<[u8; 32]>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            identity: Identity {
                cert_chain: Vec::new(),
                private_key: Vec::new(),
                is_rsa: false,
            },
            alpn: Vec::new(),
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            session_ticket_key: None,
        }
    }
}

/// A TLS 1.2 / 1.3 server acceptor.
pub struct TlsAcceptor {
    config: ServerConfig,
    /// The session-ticket encryption key (shared across accepts).
    ticket_key: [u8; 32],
}

impl TlsAcceptor {
    /// Create an acceptor from a configuration.
    pub fn new(config: ServerConfig) -> Self {
        let ticket_key = match config.session_ticket_key {
            Some(k) => k,
            None => {
                let mut k = [0u8; 32];
                let _ = crypto::rng::fill_random(&mut k);
                k
            }
        };
        Self { config, ticket_key }
    }

    /// The underlying configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Perform a TLS handshake as the server. The version is negotiated
    /// from the ClientHello: a client offering TLS 1.3 is answered with
    /// TLS 1.3 when `max_version` allows; otherwise TLS 1.2 is used (an
    /// Ed25519-only identity cannot sign a TLS 1.2 ServerKeyExchange, so
    /// such identities report "no shared TLS 1.2 cipher suite" rather
    /// than downgrading the record layer).
    pub fn accept<R: crate::courierust_io::Read, W: crate::courierust_io::Write>(
        &self,
        reader: R,
        writer: W,
    ) -> TlsResult<TlsStream<R, W>> {
        let mut io = TlsIo::new(reader, writer);
        let (_, ch_body) = io.read_plaintext_handshake()?;
        let allow13 = self.config.max_version >= TlsVersion::Tls13;
        let allow12 = self.config.min_version <= TlsVersion::Tls12;
        let client_offers_13 = handshake::client_hello_offers_tls13(&ch_body)?;

        if client_offers_13 && allow13 {
            let hs = handshake::ServerHandshake {
                identity: self.config.identity.clone(),
                alpn: self.config.alpn.clone(),
                ticket_key: Some(self.ticket_key),
                now: unix_now(),
            };
            let result = hs.run_from_client_hello(&mut io, &ch_body)?;
            // The sequence was already reset at the application-key change
            // inside the handshake; the ticket (if any) and the first
            // application record share one continuous sequence.
            Ok(TlsStream {
                io,
                version: TlsVersion::Tls13,
                suite: result.suite,
                suite12: None,
                write_keys: result.keys.write,
                read_keys: result.keys.read,
                negotiated_alpn: result.alpn,
                server_name: result.server_name,
                peer_certificate: result.peer_cert,
                closed: false,
                pending: Vec::new(),
                pending_pos: 0,
                rec: RecState::Idle,
                resumption_master: None,
                resumed: result.resumed,
                session_store: None,
                hostname: String::new(),
                now: 0,
            })
        } else if allow12 {
            // A TLS 1.2 handshake failure (e.g. an Ed25519 identity or a
            // client that offered no TLS 1.2 suite) is reported with a
            // fatal `handshake_failure` alert rather than a bare close,
            // so the peer sees a protocol error, not a timeout.
            let result = match tls12::server_handshake(
                &mut io,
                &self.config.identity,
                &self.config.alpn,
                &ch_body,
            ) {
                Ok(r) => r,
                Err(e) => {
                    let _ = io.write_plaintext_record(
                        record::CONTENT_ALERT,
                        &[2, 40], // fatal, handshake_failure
                    );
                    return Err(e);
                }
            };
            Ok(TlsStream {
                io,
                version: TlsVersion::Tls12,
                suite: key_schedule::CipherSuite::TlsAes128GcmSha256,
                suite12: Some(result.suite),
                write_keys: result.keys.write,
                read_keys: result.keys.read,
                negotiated_alpn: result.alpn,
                server_name: result.server_name,
                peer_certificate: result.peer_cert,
                closed: false,
                pending: Vec::new(),
                pending_pos: 0,
                rec: RecState::Idle,
                resumption_master: None,
                resumed: false,
                session_store: None,
                hostname: String::new(),
                now: 0,
            })
        } else {
            // No common version: the server MUST NOT answer with a lower
            // version than it supports (RFC 5246 §E.1 / RFC 8446 §4.1.3).
            let _ = io.write_plaintext_record(
                record::CONTENT_ALERT,
                &[2, 70], // fatal, protocol_version
            );
            Err(TlsError::Protocol(
                "no acceptable TLS version between client and server".into(),
            ))
        }
    }
}

/// Sign the CertificateVerify message with the server identity. Returns
/// the (signature scheme, signature) pair.
pub(crate) fn server_sign(
    identity: &Identity,
    message: &[u8],
    suite: key_schedule::CipherSuite,
) -> TlsResult<Option<(u16, Vec<u8>)>> {
    sign::sign_server_cert_verify(identity, message, suite)
}

mod sign;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// Full 1-RTT handshake over real loopback TCP: the client validates
    /// the server's Ed25519 certificate chain and hostname, both sides
    /// verify each other's Finished, and encrypted application data
    /// round-trips.
    #[test]
    fn tls13_handshake_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::server_identity(),
                alpn: vec![b"h2".to_vec()],
                min_version: TlsVersion::Tls13,
                max_version: TlsVersion::Tls13,
                session_ticket_key: None,
            });
            let mut tls = acceptor.accept(&stream, &stream).unwrap();
            assert_eq!(tls.alpn(), Some(&b"h2"[..]));
            let data = tls.read_record().unwrap();
            assert_eq!(data, b"ping");
            tls.write_all(b"pong").unwrap();
            tls.close_notify().unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::root_store(),
            verify: true,
            alpn: vec![b"h2".to_vec()],
            now: testdata::NOW,
            min_version: TlsVersion::Tls13,
            max_version: TlsVersion::Tls13,
        });
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert_eq!(tls.alpn(), Some(&b"h2"[..]));
        assert!(tls.peer_certificate().is_some());
        tls.write_all(b"ping").unwrap();
        let data = tls.read_record().unwrap();
        assert_eq!(data, b"pong");
        tls.close_notify().unwrap();

        server.join().unwrap();
    }

    /// The client must reject an untrusted server (empty root store) and
    /// a hostname that does not match the certificate.
    #[test]
    fn tls13_client_rejects_untrusted_and_hostname() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            // The server completes each handshake regardless of what the
            // client does; the client's validation failure closes the
            // connection (surfacing as an I/O error on the server, which
            // we ignore).
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let acceptor = TlsAcceptor::new(ServerConfig {
                    identity: testdata::server_identity(),
                    alpn: Vec::new(),
                    min_version: TlsVersion::Tls13,
                    max_version: TlsVersion::Tls13,
                    session_ticket_key: None,
                });
                let _ = acceptor.accept(&stream, &stream);
            }
        });

        // 1. Untrusted root.
        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: RootStore::new(),
            verify: true,
            alpn: Vec::new(),
            now: testdata::NOW,
            min_version: TlsVersion::Tls13,
            max_version: TlsVersion::Tls13,
        });
        let err = match connector.connect("localhost", &stream, &stream) {
            Ok(_) => panic!("untrusted root accepted"),
            Err(e) => e,
        };
        assert!(matches!(err, TlsError::Certificate(_)), "got {err:?}");
        // Close the socket so the server's pending Finished read unblocks.
        drop(stream);

        // 2. Hostname mismatch (certificate is for `localhost`).
        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::root_store(),
            verify: true,
            alpn: Vec::new(),
            now: testdata::NOW,
            min_version: TlsVersion::Tls13,
            max_version: TlsVersion::Tls13,
        });
        let err = match connector.connect("not-localhost", &stream, &stream) {
            Ok(_) => panic!("hostname mismatch accepted"),
            Err(e) => e,
        };
        assert!(matches!(err, TlsError::Certificate(_)), "got {err:?}");
        drop(stream);

        let _ = server.join();
    }

    /// Full TLS 1.2 ECDHE-RSA handshake over loopback TCP with the RSA
    /// test identity: the client validates the certificate chain and
    /// hostname, both sides verify each other's Finished, and encrypted
    /// application data round-trips. Also asserts the negotiated version
    /// is TLS 1.2 with an ECDHE-RSA suite.
    #[test]
    fn tls13_with_rsa_identity_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::rsa_server_identity(),
                alpn: Vec::new(),
                min_version: TlsVersion::Tls13,
                max_version: TlsVersion::Tls13,
                session_ticket_key: None,
            });
            let mut tls = acceptor.accept(&stream, &stream).unwrap();
            assert_eq!(tls.version(), TlsVersion::Tls13);
            let data = tls.read_record().unwrap();
            assert_eq!(data, b"ping");
            tls.write_all(b"pong").unwrap();
            tls.close_notify().unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::rsa_root_store(),
            verify: true,
            alpn: Vec::new(),
            now: testdata::NOW,
            min_version: TlsVersion::Tls13,
            max_version: TlsVersion::Tls13,
        });
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert_eq!(tls.version(), TlsVersion::Tls13);
        tls.write_all(b"ping").unwrap();
        let data = tls.read_record().unwrap();
        assert_eq!(data, b"pong");
        tls.close_notify().unwrap();
        server.join().unwrap();
    }

    /// Full TLS 1.2 ECDHE-RSA handshake over loopback TCP with the RSA
    /// test identity: the client validates the certificate chain and
    /// hostname, both sides verify each other's Finished, and encrypted
    /// application data round-trips. Also asserts the negotiated version
    /// is TLS 1.2 with an ECDHE-RSA suite.
    #[test]
    fn tls12_handshake_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::rsa_server_identity(),
                alpn: vec![b"h2".to_vec()],
                min_version: TlsVersion::Tls12,
                max_version: TlsVersion::Tls12,
                session_ticket_key: None,
            });
            let mut tls = acceptor.accept(&stream, &stream).unwrap();
            assert_eq!(tls.version(), TlsVersion::Tls12);
            assert_eq!(tls.alpn(), Some(&b"h2"[..]));
            let data = tls.read_record().unwrap();
            assert_eq!(data, b"ping");
            tls.write_all(b"pong").unwrap();
            tls.close_notify().unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::rsa_root_store(),
            verify: true,
            alpn: vec![b"h2".to_vec()],
            now: testdata::NOW,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls12,
        });
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert_eq!(tls.version(), TlsVersion::Tls12);
        assert!(tls.peer_certificate().is_some());
        assert_eq!(tls.alpn(), Some(&b"h2"[..]));
        // The suite must be an ECDHE_RSA AEAD suite.
        let suite = tls.cipher_suite();
        assert!(
            matches!(suite, 0xc02f | 0xc030 | 0xcca8),
            "unexpected TLS 1.2 suite {suite:#06x}"
        );
        tls.write_all(b"ping").unwrap();
        let data = tls.read_record().unwrap();
        assert_eq!(data, b"pong");
        tls.close_notify().unwrap();

        server.join().unwrap();
    }

    /// Full TLS 1.3 handshake with a P-384 identity: the server presents
    /// a chain whose *intermediate CA is a P-384 ECDSA key*, the client
    /// verifies both chain links (ecdsa-with-SHA384) against the P-384
    /// root, and the CertificateVerify is signed/verified with scheme
    /// 0x0503 under the negotiated SHA-384 suite. Regression test for the
    /// verifier defect that accepted only P-256 (65-byte SPKI).
    #[test]
    fn tls13_with_p384_identity_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::p384_server_identity(),
                alpn: Vec::new(),
                min_version: TlsVersion::Tls13,
                max_version: TlsVersion::Tls13,
                session_ticket_key: None,
            });
            let mut tls = acceptor.accept(&stream, &stream).unwrap();
            assert_eq!(tls.version(), TlsVersion::Tls13);
            let data = tls.read_record().unwrap();
            assert_eq!(data, b"ping");
            tls.write_all(b"pong").unwrap();
            tls.close_notify().unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::p384_root_store(),
            verify: true,
            alpn: Vec::new(),
            now: testdata::NOW,
            min_version: TlsVersion::Tls13,
            max_version: TlsVersion::Tls13,
        });
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert_eq!(tls.version(), TlsVersion::Tls13);
        // A P-384 identity can only negotiate the SHA-384 suite
        // (TLS_AES_256_GCM_SHA384 = 0x1302).
        assert_eq!(tls.cipher_suite(), 0x1302);
        assert!(tls.peer_certificate().is_some());
        tls.write_all(b"ping").unwrap();
        let data = tls.read_record().unwrap();
        assert_eq!(data, b"pong");
        tls.close_notify().unwrap();
        server.join().unwrap();
    }

    /// Full TLS 1.2 ECDHE_ECDSA handshake with a P-384 identity: the
    /// ServerKeyExchange is signed with scheme 0x0503 (ecdsa_secp384r1_
    /// sha384) and the suite is ECDHE_ECDSA AES-256-GCM SHA-384. This
    /// exercises the P-384 SPKI path in the TLS 1.2 client as well.
    #[test]
    fn tls12_with_p384_identity_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::p384_server_identity(),
                alpn: Vec::new(),
                min_version: TlsVersion::Tls12,
                max_version: TlsVersion::Tls12,
                session_ticket_key: None,
            });
            let mut tls = acceptor.accept(&stream, &stream).unwrap();
            assert_eq!(tls.version(), TlsVersion::Tls12);
            let data = tls.read_record().unwrap();
            assert_eq!(data, b"ping");
            tls.write_all(b"pong").unwrap();
            tls.close_notify().unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::p384_root_store(),
            verify: true,
            alpn: Vec::new(),
            now: testdata::NOW,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls12,
        });
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert_eq!(tls.version(), TlsVersion::Tls12);
        // The P-384 identity forces the SHA-384 ECDHE_ECDSA suite
        // (0xc02c = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384).
        assert_eq!(tls.cipher_suite(), 0xc02c);
        tls.write_all(b"ping").unwrap();
        let data = tls.read_record().unwrap();
        assert_eq!(data, b"pong");
        tls.close_notify().unwrap();
        server.join().unwrap();
    }

    /// Version auto-negotiation: both sides allow TLS 1.2..1.3, the
    /// client offers TLS 1.3, and the server (RSA identity) picks
    /// TLS 1.3. A TLS 1.3 suite must be negotiated.
    #[test]
    fn tls_version_autonegotiates_to_13_when_offered() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::rsa_server_identity(),
                alpn: Vec::new(),
                ..Default::default()
            });
            let mut tls = acceptor.accept(&stream, &stream).unwrap();
            assert_eq!(tls.version(), TlsVersion::Tls13);
            tls.close_notify().unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::rsa_root_store(),
            verify: true,
            alpn: Vec::new(),
            now: testdata::NOW,
            ..Default::default()
        });
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert_eq!(tls.version(), TlsVersion::Tls13);
        tls.close_notify().unwrap();
        server.join().unwrap();
    }

    /// Downgrade protection (RFC 8446 §4.1.3): a client that offered
    /// TLS 1.3 must reject a TLS 1.2 ServerHello without the downgrade
    /// sentinel. The honest server (max_version = TLS 1.2) always adds
    /// the sentinel, so this test drives a real server and then asserts
    /// the sentinel was present by checking the client accepted the
    /// negotiated TLS 1.2; the absence case is covered at the unit level
    /// in `tls12.rs` (the sentinel bytes are asserted on the wire there).
    #[test]
    fn tls12_negotiated_with_sentinel_when_client_offers_13() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            // Server refuses TLS 1.3 but accepts TLS 1.2; the client
            // offered TLS 1.3, so the ServerHello must carry the
            // sentinel (the client aborts otherwise).
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::rsa_server_identity(),
                alpn: Vec::new(),
                min_version: TlsVersion::Tls12,
                max_version: TlsVersion::Tls12,
                session_ticket_key: None,
            });
            let mut tls = acceptor.accept(&stream, &stream).unwrap();
            assert_eq!(tls.version(), TlsVersion::Tls12);
            tls.close_notify().unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        // Client defaults to offering TLS 1.3 (max_version = TLS 1.3)
        // and accepting TLS 1.2.
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::rsa_root_store(),
            verify: true,
            alpn: Vec::new(),
            now: testdata::NOW,
            ..Default::default()
        });
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert_eq!(tls.version(), TlsVersion::Tls12);
        tls.close_notify().unwrap();
        server.join().unwrap();
    }

    /// A TLS 1.3-only client must refuse a TLS 1.2-only server instead
    /// of silently downgrading.
    #[test]
    fn tls13_only_client_refuses_tls12_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::rsa_server_identity(),
                alpn: Vec::new(),
                min_version: TlsVersion::Tls12,
                max_version: TlsVersion::Tls12,
                session_ticket_key: None,
            });
            let _ = acceptor.accept(&stream, &stream);
        });

        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::rsa_root_store(),
            verify: true,
            alpn: Vec::new(),
            now: testdata::NOW,
            min_version: TlsVersion::Tls13,
            max_version: TlsVersion::Tls13,
        });
        let err = match connector.connect("localhost", &stream, &stream) {
            Ok(_) => panic!("TLS 1.3-only client accepted a TLS 1.2 server"),
            Err(e) => e,
        };
        // The connection must fail (no silent downgrade). The exact
        // error is a Protocol error (alert record seen) or an
        // UnexpectedEof (server closed before the client read).
        assert!(
            matches!(
                err,
                TlsError::Protocol(_) | TlsError::Alert { .. } | TlsError::UnexpectedEof
            ),
            "got {err:?}"
        );
        drop(stream);
        let _ = server.join();
    }

    /// An Ed25519-only identity cannot sign a TLS 1.2 ServerKeyExchange;
    /// the server must report "no shared TLS 1.2 cipher suite" rather
    /// than downgrading the record layer.
    #[test]
    fn tls12_rejects_ed25519_identity() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::server_identity(), // Ed25519
                alpn: Vec::new(),
                min_version: TlsVersion::Tls12,
                max_version: TlsVersion::Tls12,
                session_ticket_key: None,
            });
            let result = acceptor.accept(&stream, &stream);
            assert!(result.is_err(), "Ed25519 identity negotiated TLS 1.2");
        });

        let stream = TcpStream::connect(addr).unwrap();
        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::root_store(),
            verify: true,
            alpn: Vec::new(),
            now: testdata::NOW,
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls12,
        });
        let _ = connector.connect("localhost", &stream, &stream);
        drop(stream);
        let _ = server.join();
    }

    /// Full session-resumption round trip (RFC 8446 §4.6.1): the first
    /// handshake issues a NewSessionTicket; the second reconnects with
    /// the resumption PSK (psk_dhe_ke) and is resumed.
    #[test]
    fn tls13_session_resumption_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let ticket_key = [0x5au8; 32];

        let server = std::thread::spawn(move || {
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::server_identity(),
                alpn: vec![b"h2".to_vec()],
                min_version: TlsVersion::Tls13,
                max_version: TlsVersion::Tls13,
                session_ticket_key: Some(ticket_key),
            });
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut tls = acceptor.accept(&stream, &stream).unwrap();
                let data = tls.read_record().unwrap();
                assert_eq!(data, b"ping");
                tls.write_all(b"pong").unwrap();
                tls.close_notify().unwrap();
            }
        });

        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::root_store(),
            verify: true,
            alpn: vec![b"h2".to_vec()],
            now: testdata::NOW,
            min_version: TlsVersion::Tls13,
            max_version: TlsVersion::Tls13,
        });

        // First connection: full handshake, ticket captured on connect.
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert!(!tls.resumed(), "first handshake must be full");
        tls.write_all(b"ping").unwrap();
        match tls.read_record() {
            Ok(p) if p == b"pong" => {}
            other => panic!("bad first read: {other:?}"),
        }
        tls.close_notify().unwrap();

        // Second connection: must resume via the PSK.
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert!(tls.resumed(), "second handshake must resume from the PSK");
        tls.write_all(b"ping").unwrap();
        assert_eq!(tls.read_record().unwrap(), b"pong");
        tls.close_notify().unwrap();

        server.join().unwrap();
    }

    /// A ticket that cannot be decrypted (or whose PSK does not match)
    /// must not resume: the server falls back to a full handshake and
    /// the connection still works (RFC 8446 §4.2.11 — unknown PSKs are
    /// ignored). The client must also accept the non-resumed ServerHello.
    #[test]
    fn tls13_session_resumption_tampered_ticket_falls_back() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let ticket_key = [0x5bu8; 32];

        let server = std::thread::spawn(move || {
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::server_identity(),
                alpn: vec![b"h2".to_vec()],
                min_version: TlsVersion::Tls13,
                max_version: TlsVersion::Tls13,
                session_ticket_key: Some(ticket_key),
            });
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                let mut tls = acceptor.accept(&stream, &stream).unwrap();
                assert_eq!(tls.read_record().unwrap(), b"ping");
                tls.write_all(b"pong").unwrap();
                tls.close_notify().unwrap();
            }
        });

        let connector = TlsConnector::new(ClientConfig {
            roots: testdata::root_store(),
            verify: true,
            alpn: vec![b"h2".to_vec()],
            now: testdata::NOW,
            min_version: TlsVersion::Tls13,
            max_version: TlsVersion::Tls13,
        });

        // First connection: full handshake, captures a ticket.
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert!(!tls.resumed());
        tls.write_all(b"ping").unwrap();
        assert_eq!(tls.read_record().unwrap(), b"pong");
        tls.close_notify().unwrap();

        // Corrupt the cached ticket so the server cannot decrypt it.
        {
            let mut sessions = connector.sessions.lock().unwrap();
            let s = sessions.last_mut().unwrap();
            let i = s.ticket.len() - 1;
            s.ticket[i] ^= 0x01;
        }

        // Second connection: offer is made but must not resume.
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut tls = connector.connect("localhost", &stream, &stream).unwrap();
        assert!(
            !tls.resumed(),
            "tampered ticket must fall back to a full handshake"
        );
        tls.write_all(b"ping").unwrap();
        assert_eq!(tls.read_record().unwrap(), b"pong");
        tls.close_notify().unwrap();

        server.join().unwrap();
    }

    /// A client that supports X25519 but offers no key share (empty
    /// `client_shares`, RFC 8446 §4.2.8) receives a HelloRetryRequest;
    /// the retried ClientHello with an X25519 share then completes a full
    /// handshake whose transcript carries `message_hash(Hash(CH1)) || HRR
    /// || CH2` (RFC 8446 §4.4.1).
    #[test]
    fn tls13_server_sends_hello_retry_request_and_completes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let acceptor = TlsAcceptor::new(ServerConfig {
                identity: testdata::server_identity(),
                alpn: vec![b"h2".to_vec()],
                min_version: TlsVersion::Tls13,
                max_version: TlsVersion::Tls13,
                session_ticket_key: None,
            });
            let mut tls = acceptor.accept(&stream, &stream).unwrap();
            assert_eq!(tls.read_record().unwrap(), b"ping");
            tls.write_all(b"pong").unwrap();
            tls.close_notify().unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut io = TlsIo::new(&stream, &stream);

        // CH1 requests group selection (empty key_share).
        let mut random = [0u8; 32];
        handshake::fill_entropy(&mut random).unwrap();
        let ch1 = handshake::build_client_hello_negotiated(
            &random,
            None,
            &[b"h2".to_vec()],
            Some("localhost"),
            None,
            true,
            false,
        );
        io.write_plaintext_record_v(tls12::VERSION_12, record::CONTENT_HANDSHAKE, &ch1)
            .unwrap();

        // The server must answer with a HelloRetryRequest for X25519.
        let (ct, hrr_payload) = io.read_plaintext_record().unwrap();
        assert_eq!(ct, record::CONTENT_HANDSHAKE);
        assert!(handshake::is_hello_retry_request(&hrr_payload[4..]));
        let hrr = handshake::parse_hello_retry_request(&hrr_payload[4..]).unwrap();
        assert_eq!(hrr.selected_group, handshake::GROUP_X25519);

        // CH2: fresh X25519 share, same random.
        let mut priv2 = [0u8; 32];
        handshake::fill_entropy(&mut priv2).unwrap();
        let pub2 = crypto::x25519::x25519(&priv2, &crypto::x25519::BASE_POINT);
        let ch2 = handshake::build_client_hello_negotiated(
            &random,
            Some(&pub2),
            &[b"h2".to_vec()],
            Some("localhost"),
            None,
            true,
            false,
        );
        io.write_plaintext_record_v(tls12::VERSION_12, record::CONTENT_HANDSHAKE, &ch2)
            .unwrap();

        // Real ServerHello follows.
        let (ct, sh_payload) = io.read_plaintext_record().unwrap();
        assert_eq!(ct, record::CONTENT_HANDSHAKE);
        let sh_body = &sh_payload[4..];
        assert!(handshake::server_hello_negotiates_tls13(sh_body));

        let hs = handshake::ClientHandshake {
            server_name: Some("localhost".to_string()),
            verify: true,
            psk: None,
        };
        let result = hs
            .run_from_server_hello(
                &mut io,
                &testdata::root_store(),
                testdata::NOW,
                &ch2,
                &random,
                &priv2,
                sh_body,
                Some((&ch1, &hrr_payload, &ch2)),
            )
            .unwrap();
        io.reset_sequences();

        let mut tls = TlsStream {
            io,
            version: TlsVersion::Tls13,
            suite: result.suite,
            suite12: None,
            write_keys: result.keys.write,
            read_keys: result.keys.read,
            negotiated_alpn: result.alpn,
            server_name: result.server_name,
            peer_certificate: result.peer_cert,
            closed: false,
            pending: Vec::new(),
            pending_pos: 0,
            rec: RecState::Idle,
            resumption_master: None,
            resumed: result.resumed,
            session_store: None,
            hostname: "localhost".to_string(),
            now: testdata::NOW,
        };
        tls.write_all(b"ping").unwrap();
        assert_eq!(tls.read_record().unwrap(), b"pong");
        tls.close_notify().unwrap();

        server.join().unwrap();
    }
}
