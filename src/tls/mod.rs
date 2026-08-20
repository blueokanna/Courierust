//! TLS 1.3 (RFC 8446), implemented from scratch with zero dependencies.
//!
//! This module provides a complete client and server handshake over the
//! crate's [`crate::io::Read`]/[`crate::io::Write`] transport traits, so
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
//! Honest scope note: PSK/0-RTT resumption, session tickets, and key
//! updates are not implemented in this initial release; a full 1-RTT
//! handshake is performed every time. The certificate verification
//! performs chain building against the provided roots, validity-window
//! and hostname checks, and standard key-usage/basic-constraints
//! enforcement.

pub mod crypto;
pub mod x509;

#[cfg(test)]
mod testdata;

mod handshake;
mod key_schedule;
mod record;

use alloc::string::String;
use alloc::vec::Vec;

pub use x509::RootStore;

/// TLS version identifier for TLS 1.3 (supported_versions extension).
pub const TLS_VERSION_1_3: u16 = 0x0304;
/// TLS version identifier for TLS 1.2 (legacy_record_version / fallback).
pub const TLS_VERSION_1_2: u16 = 0x0303;

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

impl From<crate::error::Error> for TlsError {
    fn from(e: crate::error::Error) -> Self {
        use crate::error::ErrorKind;
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

use crate::io::{BufReader, BufWriter};
use record::{Sequence, seal_record, open_record, CONTENT_HANDSHAKE, MAX_RECORD_PAYLOAD};

/// Buffered record-level I/O over a transport. Sequence numbers are
/// tracked per direction and reset when the traffic keys change.
pub(crate) struct TlsIo<R, W> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
    read_seq: Sequence,
    write_seq: Sequence,
}

impl<R: crate::io::Read, W: crate::io::Write> TlsIo<R, W> {
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
        if payload.len() > u16::MAX as usize {
            return Err(TlsError::Protocol("record too large".into()));
        }
        let header = [
            content_type,
            0x03,
            0x01,
            (payload.len() >> 8) as u8,
            payload.len() as u8,
        ];
        self.writer.write_all(&header).map_err(TlsError::from)?;
        self.writer.write_all(payload).map_err(TlsError::from)?;
        self.writer.flush().map_err(TlsError::from)
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

    /// Write an encrypted record.
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

    /// Read records until at least one full handshake message is
    /// buffered; returns the accumulated decrypted handshake bytes.
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
            let seq = self.read_seq.next()?;
            let (ct, payload) = open_record(suite, keys, seq, &header, &encrypted)?;
            if ct == CONTENT_HANDSHAKE {
                plain.extend_from_slice(&payload);
                // Stop when we have a complete handshake message.
                if let Some(m) = handshake::peek_complete_hs(&plain) {
                    let _ = m;
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

/// A completed TLS 1.3 connection. Implements the crate's `Read` and
/// `Write` traits for encrypted application data.
pub struct TlsStream<R, W> {
    io: TlsIo<R, W>,
    suite: key_schedule::CipherSuite,
    write_keys: key_schedule::TrafficKeys,
    read_keys: key_schedule::TrafficKeys,
    negotiated_alpn: Option<Vec<u8>>,
    server_name: Option<String>,
    peer_certificate: Option<Vec<u8>>,
    closed: bool,
    /// Bytes of the current decrypted record not yet consumed by the
    /// caller (a TLS record can be up to 16 KiB, larger than any single
    /// `read` buffer).
    pending: Vec<u8>,
    /// Resumable inbound record read (see [`RecState`]).
    rec: RecState,
}

impl<R: crate::io::Read, W: crate::io::Write> TlsStream<R, W> {
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

    /// The negotiated TLS 1.3 cipher suite wire value.
    pub fn cipher_suite(&self) -> u16 {
        self.suite.wire()
    }

    /// Write application data (encrypted).
    pub fn write_all(&mut self, data: &[u8]) -> TlsResult<()> {
        if self.closed {
            return Err(TlsError::Protocol("connection closed".into()));
        }
        // Split into record-sized chunks.
        let mut off = 0;
        while off < data.len() {
            let take = core::cmp::min(data.len() - off, record::MAX_RECORD_PAYLOAD - 2);
            self.io.write_encrypted_record(
                self.suite,
                &self.write_keys,
                record::CONTENT_APPLICATION_DATA,
                &data[off..off + take],
            )?;
            off += take;
        }
        Ok(())
    }

    /// Read one application-data record (up to one TLS record of data).
    /// Returns Ok(0) on clean shutdown.
    pub fn read_record(&mut self) -> TlsResult<Vec<u8>> {
        if self.closed {
            return Ok(Vec::new());
        }
        loop {
            // Phase 1: a complete 5-byte record header.
            let payload_len = match &self.rec {
                RecState::Payload { payload, .. } => {
                    // Header already complete from a previous call.
                    payload.len()
                }
                _ => match self.read_record_header()? {
                    Some((_, len)) => len,
                    None => return Ok(Vec::new()), // clean EOF
                },
            };
            if payload_len > record::MAX_RECORD_PAYLOAD + 16 {
                return Err(TlsError::Protocol("record too large".into()));
            }
            // Phase 2: the (encrypted) payload.
            let (header, encrypted) = self.read_record_payload()?;
            // Phase 3: decrypt and dispatch.
            let seq = self.io.read_seq.next()?;
            let (ct, payload) =
                open_record(self.suite, &self.read_keys, seq, &header, &encrypted)?;
            match ct {
                record::CONTENT_APPLICATION_DATA => return Ok(payload),
                record::CONTENT_ALERT => {
                    // close_notify (0) is a clean shutdown; anything
                    // else is a protocol error.
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
                    // KeyUpdate / NewSessionTicket — parse and ignore
                    // NewSessionTicket; reject anything else.
                    if let Some(m) = handshake::peek_complete_hs(&payload) {
                        if m.msg_type != handshake::HS_NEW_SESSION_TICKET {
                            return Err(TlsError::Protocol(
                                "unexpected handshake after handshake".into(),
                            ));
                        }
                    }
                }
                _ => {
                    return Err(TlsError::Protocol("unexpected record type".into()));
                }
            }
        }
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
                Ok(b) if b.is_empty() => {
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
                    if e.kind == crate::error::ErrorKind::Timeout
                        || e.kind == crate::error::ErrorKind::WouldBlock =>
                {
                    self.rec = RecState::Header { hdr, filled };
                    return Err(TlsError::Timeout);
                }
                Err(e) if e.kind == crate::error::ErrorKind::UnexpectedEof => {
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
                _ => {
                    return Err(TlsError::Internal(
                        "payload read without header".into(),
                    ))
                }
            };
        let total = payload.len();
        loop {
            if filled == total {
                return Ok((header, payload));
            }
            match self.io.reader.fill_buf() {
                Ok(b) if b.is_empty() => {
                    // Peer closed mid-record: truncated record.
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
                    if e.kind == crate::error::ErrorKind::Timeout
                        || e.kind == crate::error::ErrorKind::WouldBlock =>
                {
                    self.rec = RecState::Payload {
                        header,
                        payload,
                        filled,
                    };
                    return Err(TlsError::Timeout);
                }
                Err(e) if e.kind == crate::error::ErrorKind::UnexpectedEof => {
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
            self.io.write_encrypted_record(
                self.suite,
                &self.write_keys,
                record::CONTENT_ALERT,
                &alert,
            )?;
        }
        self.closed = true;
        Ok(())
    }
}

impl<R: crate::io::Read, W: crate::io::Write> crate::io::Read for TlsStream<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> crate::error::Result<usize> {
        // Serve buffered excess from the previous record first; a TLS
        // record (up to 16 KiB) can be much larger than the caller's
        // buffer, so never discard the remainder.
        if self.pending.is_empty() {
            self.pending = match self.read_record() {
                Ok(p) => p,
                // A transport read timeout is a transient "no data yet"
                // (the h2 driver polls with a short socket timeout); the
                // partial record state is preserved and the read resumes
                // on the next call. Only non-timeout failures are fatal.
                Err(TlsError::Timeout) => {
                    return Err(crate::error::Error::new(
                        crate::error::ErrorKind::Timeout,
                    ))
                }
                Err(e) => {
                    return Err(crate::error::Error::with_message(
                        crate::error::ErrorKind::Other,
                        e.to_string(),
                    ))
                }
            };
            if self.pending.is_empty() {
                return Ok(0);
            }
        }
        let n = core::cmp::min(buf.len(), self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl<R: crate::io::Read, W: crate::io::Write> crate::io::Write for TlsStream<R, W> {
    fn write(&mut self, buf: &[u8]) -> crate::error::Result<usize> {
        self.write_all(buf).map_err(|e| {
            crate::error::Error::with_message(crate::error::ErrorKind::Other, e.to_string())
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> crate::error::Result<()> {
        Ok(())
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
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            roots: RootStore::new(),
            verify: true,
            alpn: Vec::new(),
            now: 0,
        }
    }
}

/// A TLS 1.3 client connector.
pub struct TlsConnector {
    config: ClientConfig,
}

impl TlsConnector {
    /// Create a connector from a configuration.
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// The underlying configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Perform a TLS 1.3 handshake over `stream`, authenticating
    /// `hostname` against the server certificate.
    pub fn connect<R: crate::io::Read, W: crate::io::Write>(
        &self,
        hostname: &str,
        reader: R,
        writer: W,
    ) -> TlsResult<TlsStream<R, W>> {
        let mut io = TlsIo::new(reader, writer);
        let hs = handshake::ClientHandshake {
            alpn: self.config.alpn.clone(),
            server_name: Some(hostname.to_string()),
        };
        let result = hs.run(
            &mut io,
            &self.config.roots,
            self.config.now,
        )?;
        // Reset sequence numbers for application data.
        io.reset_sequences();
        Ok(TlsStream {
            io,
            suite: result.suite,
            write_keys: result.keys.write,
            read_keys: result.keys.read,
            negotiated_alpn: result.alpn,
            server_name: result.server_name,
            peer_certificate: result.peer_cert,
            closed: false,
            pending: Vec::new(),
            rec: RecState::Idle,
        })
    }
}

// ---------------------------------------------------------------------
// Server acceptor
// ---------------------------------------------------------------------

/// Server-side TLS configuration.
pub struct ServerConfig {
    /// The server's certificate chain and private key.
    pub identity: Identity,
    /// ALPN protocols offered (the first match wins).
    pub alpn: Vec<Vec<u8>>,
}

/// A TLS 1.3 server acceptor.
pub struct TlsAcceptor {
    config: ServerConfig,
}

impl TlsAcceptor {
    /// Create an acceptor from a configuration.
    pub fn new(config: ServerConfig) -> Self {
        Self { config }
    }

    /// The underlying configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Perform a TLS 1.3 handshake as the server.
    pub fn accept<R: crate::io::Read, W: crate::io::Write>(
        &self,
        reader: R,
        writer: W,
    ) -> TlsResult<TlsStream<R, W>> {
        let mut io = TlsIo::new(reader, writer);
        let hs = handshake::ServerHandshake {
            identity: self.config.identity.clone(),
            alpn: self.config.alpn.clone(),
        };
        let result = hs.run(&mut io)?;
        io.reset_sequences();
        Ok(TlsStream {
            io,
            suite: result.suite,
            write_keys: result.keys.write,
            read_keys: result.keys.read,
            negotiated_alpn: result.alpn,
            server_name: result.server_name,
            peer_certificate: result.peer_cert,
            closed: false,
            pending: Vec::new(),
            rec: RecState::Idle,
        })
    }
}

/// Sign the CertificateVerify message with the server identity. Returns
/// the (signature scheme, signature) pair.
pub(crate) fn server_sign(identity: &Identity, message: &[u8]) -> TlsResult<Option<(u16, Vec<u8>)>> {
    sign::sign_server_cert_verify(identity, message)
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
        });
        let err = match connector.connect("not-localhost", &stream, &stream) {
            Ok(_) => panic!("hostname mismatch accepted"),
            Err(e) => e,
        };
        assert!(matches!(err, TlsError::Certificate(_)), "got {err:?}");
        drop(stream);

        let _ = server.join();
    }
}

