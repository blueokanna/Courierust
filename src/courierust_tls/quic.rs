//! TLS 1.3 over QUIC CRYPTO streams (RFC 9001 section 5).
//!
//! QUIC does not carry TLS records.  It carries the TLS handshake messages
//! directly in CRYPTO frames and uses the TLS traffic secrets as QUIC packet
//! protection secrets.  This module is deliberately a small adapter around
//! the existing TLS 1.3 implementation: certificate validation, signature
//! verification, transcript hashing and HKDF all remain in their owning
//! modules.

use super::crypto::x25519;
use super::handshake::{
    cert_verify_message, encode_hs, finished_verify_data, parse_cert_verify,
    parse_certificate_list, parse_client_hello, parse_encrypted_extensions, parse_hs,
    parse_server_hello, verify_cert_verify, ClientHelloInfo, ServerHelloInfo, HS_CERTIFICATE,
    HS_CERTIFICATE_VERIFY, HS_CLIENT_HELLO, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_SERVER_HELLO,
};
use super::key_schedule::{CipherSuite, KeySchedule, Transcript};
use super::{server_sign, Identity, RootStore, TlsError, TlsResult};
use crate::courierust_quic::protection::PacketKey;
use crate::courierust_quic::varint;
use alloc::vec::Vec;

const MAX_CRYPTO_BUFFER: usize = 16 * 1024 * 1024;
const MAX_TRANSPORT_PARAMETERS: usize = 4096;
const MAX_CERT_CHAIN: usize = 8 * 1024 * 1024;

/// QUIC transport parameters used by the runtime.  Unknown parameters are
/// ignored as required by RFC 9000; known parameters are unique and bounded.
#[derive(Debug, Clone)]
pub(crate) struct TransportParameters {
    pub(crate) max_idle_timeout: u64,
    pub(crate) max_udp_payload_size: u64,
    pub(crate) initial_max_data: u64,
    pub(crate) initial_max_stream_data_bidi_local: u64,
    pub(crate) initial_max_stream_data_bidi_remote: u64,
    pub(crate) initial_max_stream_data_uni: u64,
    pub(crate) initial_max_streams_bidi: u64,
    pub(crate) initial_max_streams_uni: u64,
    pub(crate) active_connection_id_limit: u64,
    pub(crate) initial_source_connection_id: Vec<u8>,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            max_idle_timeout: 30_000,
            max_udp_payload_size: 1350,
            initial_max_data: 16 * 1024 * 1024,
            initial_max_stream_data_bidi_local: 16 * 1024 * 1024,
            initial_max_stream_data_bidi_remote: 16 * 1024 * 1024,
            initial_max_stream_data_uni: 1024 * 1024,
            initial_max_streams_bidi: 1024,
            initial_max_streams_uni: 3,
            active_connection_id_limit: 2,
            initial_source_connection_id: Vec::new(),
        }
    }
}

impl TransportParameters {
    pub(crate) fn encode(&self, source_cid: &[u8]) -> TlsResult<Vec<u8>> {
        if source_cid.len() > 20 {
            return Err(TlsError::Protocol(
                "QUIC connection id is longer than 20 bytes".into(),
            ));
        }
        let mut out = Vec::with_capacity(128);
        put_var_param(&mut out, 0x01, self.max_idle_timeout)?;
        put_var_param(&mut out, 0x02, self.max_udp_payload_size)?;
        put_var_param(&mut out, 0x03, self.initial_max_data)?;
        put_var_param(&mut out, 0x04, self.initial_max_stream_data_bidi_local)?;
        put_var_param(&mut out, 0x05, self.initial_max_stream_data_bidi_remote)?;
        put_var_param(&mut out, 0x06, self.initial_max_stream_data_uni)?;
        put_var_param(&mut out, 0x07, self.initial_max_streams_bidi)?;
        put_var_param(&mut out, 0x08, self.initial_max_streams_uni)?;
        put_var_param(&mut out, 0x0e, self.active_connection_id_limit.max(2))?;
        put_bytes_param(&mut out, 0x0f, source_cid)?;
        Ok(out)
    }

    pub(crate) fn parse(buf: &[u8]) -> TlsResult<Self> {
        if buf.len() > MAX_TRANSPORT_PARAMETERS {
            return Err(TlsError::Protocol(
                "QUIC transport parameters are too large".into(),
            ));
        }
        let mut p = 0usize;
        let mut out = Self::default();
        let mut seen = [false; 10];
        while p < buf.len() {
            let (id, id_len) = varint::decode(&buf[p..])
                .map_err(|_| TlsError::Protocol("malformed QUIC transport parameter id".into()))?;
            p = checked_advance(p, id_len, buf.len())?;
            let (len, len_len) = varint::decode(&buf[p..]).map_err(|_| {
                TlsError::Protocol("malformed QUIC transport parameter length".into())
            })?;
            p = checked_advance(p, len_len, buf.len())?;
            let len = usize::try_from(len)
                .map_err(|_| TlsError::Protocol("transport parameter length overflow".into()))?;
            if len > MAX_TRANSPORT_PARAMETERS {
                return Err(TlsError::Protocol(
                    "transport parameter value is too large".into(),
                ));
            }
            let end = p
                .checked_add(len)
                .ok_or_else(|| TlsError::Protocol("transport parameter length overflow".into()))?;
            if end > buf.len() {
                return Err(TlsError::Protocol(
                    "truncated QUIC transport parameter".into(),
                ));
            }
            let value = &buf[p..end];
            p = end;
            let slot = match id {
                0x01 => Some(0),
                0x02 => Some(1),
                0x03 => Some(2),
                0x04 => Some(3),
                0x05 => Some(4),
                0x06 => Some(5),
                0x07 => Some(6),
                0x08 => Some(7),
                0x0e => Some(8),
                0x0f => Some(9),
                // Retry/source CID parameters are handled by the transport
                // layer when present; they are still length-checked here.
                0x00 | 0x09..=0x0d | 0x10..=0x1f => None,
                _ => None,
            };
            if let Some(slot) = slot {
                if seen[slot] {
                    return Err(TlsError::Protocol(
                        "duplicate QUIC transport parameter".into(),
                    ));
                }
                seen[slot] = true;
            }
            match id {
                0x01 => out.max_idle_timeout = read_var_value(value, "max_idle_timeout")?,
                0x02 => {
                    out.max_udp_payload_size = read_var_value(value, "max_udp_payload_size")?;
                    if out.max_udp_payload_size < 1200 || out.max_udp_payload_size > 65_527 {
                        return Err(TlsError::Protocol("invalid max_udp_payload_size".into()));
                    }
                }
                0x03 => out.initial_max_data = read_var_value(value, "initial_max_data")?,
                0x04 => {
                    out.initial_max_stream_data_bidi_local =
                        read_var_value(value, "initial_max_stream_data_bidi_local")?;
                }
                0x05 => {
                    out.initial_max_stream_data_bidi_remote =
                        read_var_value(value, "initial_max_stream_data_bidi_remote")?;
                }
                0x06 => {
                    out.initial_max_stream_data_uni =
                        read_var_value(value, "initial_max_stream_data_uni")?;
                }
                0x07 => {
                    out.initial_max_streams_bidi =
                        read_var_value(value, "initial_max_streams_bidi")?;
                }
                0x08 => {
                    out.initial_max_streams_uni = read_var_value(value, "initial_max_streams_uni")?;
                }
                0x0e => {
                    out.active_connection_id_limit =
                        read_var_value(value, "active_connection_id_limit")?;
                    if out.active_connection_id_limit < 2 {
                        return Err(TlsError::Protocol(
                            "active_connection_id_limit is below 2".into(),
                        ));
                    }
                }
                0x0f => {
                    if value.len() > 20 {
                        return Err(TlsError::Protocol(
                            "initial_source_connection_id is longer than 20 bytes".into(),
                        ));
                    }
                    out.initial_source_connection_id = value.to_vec();
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

fn checked_advance(pos: usize, amount: usize, len: usize) -> TlsResult<usize> {
    let next = pos
        .checked_add(amount)
        .ok_or_else(|| TlsError::Protocol("QUIC transport parameter offset overflow".into()))?;
    if next > len {
        return Err(TlsError::Protocol(
            "truncated QUIC transport parameter".into(),
        ));
    }
    Ok(next)
}

fn read_var_value(value: &[u8], name: &str) -> TlsResult<u64> {
    let (v, used) =
        varint::decode(value).map_err(|_| TlsError::Protocol(format!("invalid QUIC {name}")))?;
    if used != value.len() {
        return Err(TlsError::Protocol(format!("trailing bytes in QUIC {name}")));
    }
    Ok(v)
}

fn put_var_param(out: &mut Vec<u8>, id: u64, value: u64) -> TlsResult<()> {
    if value > varint::MAX {
        return Err(TlsError::Protocol(
            "QUIC transport parameter exceeds varint".into(),
        ));
    }
    out.extend_from_slice(&varint::encode(id));
    let encoded = varint::encode(value);
    out.extend_from_slice(&varint::encode(encoded.len() as u64));
    out.extend_from_slice(&encoded);
    Ok(())
}

fn put_bytes_param(out: &mut Vec<u8>, id: u64, value: &[u8]) -> TlsResult<()> {
    if value.len() > 20 {
        return Err(TlsError::Protocol("QUIC connection id is too long".into()));
    }
    out.extend_from_slice(&varint::encode(id));
    out.extend_from_slice(&varint::encode(value.len() as u64));
    out.extend_from_slice(value);
    Ok(())
}

/// The key material and TLS messages produced by a QUIC handshake step.
#[derive(Debug, Default)]
pub(crate) struct QuicTlsFlight {
    /// TLS ServerHello or ClientHello bytes for the Initial packet space.
    pub(crate) initial: Vec<u8>,
    /// Encrypted handshake messages for the Handshake packet space.
    pub(crate) handshake: Vec<u8>,
    /// Key used to protect packets sent in the Handshake space.
    pub(crate) handshake_write: Option<PacketKey>,
    /// Key used to open packets received in the Handshake space.
    pub(crate) handshake_read: Option<PacketKey>,
    /// Key used to protect 1-RTT packets sent by this endpoint.
    pub(crate) application_write: Option<PacketKey>,
    /// Key used to open 1-RTT packets received by this endpoint.
    pub(crate) application_read: Option<PacketKey>,
    /// Peer transport parameters.
    pub(crate) peer_transport: Option<TransportParameters>,
}

fn packet_keys(suite: CipherSuite, secret: &[u8]) -> TlsResult<PacketKey> {
    PacketKey::from_secret(suite.wire(), secret).map_err(|e| TlsError::Protocol(e.to_string()))
}

/// Client-side QUIC TLS state machine.
pub(crate) struct QuicClient {
    alpn: Vec<Vec<u8>>,
    server_name: String,
    verify: bool,
    roots: RootStore,
    now: i64,
    client_transport: TransportParameters,
    expected_server_cid: Vec<u8>,
    private_key: [u8; 32],
    client_hello: Vec<u8>,
    initial_in: Vec<u8>,
    handshake_in: Vec<u8>,
    transcript: Option<Transcript>,
    key_schedule: Option<KeySchedule>,
    peer_chain: Option<Vec<Vec<u8>>>,
    cert_verify: Option<super::handshake::CertVerify>,
    negotiated_alpn: Option<Vec<u8>>,
    peer_transport: Option<TransportParameters>,
    saw_ee: bool,
    saw_cert: bool,
    saw_cv: bool,
    complete: bool,
}

impl QuicClient {
    pub(crate) fn new(
        server_name: &str,
        alpn: Vec<Vec<u8>>,
        verify: bool,
        roots: RootStore,
        now: i64,
        client_transport: TransportParameters,
        expected_server_cid: Vec<u8>,
    ) -> Self {
        Self {
            alpn,
            server_name: server_name.into(),
            verify,
            roots,
            now,
            client_transport,
            expected_server_cid,
            private_key: [0; 32],
            client_hello: Vec::new(),
            initial_in: Vec::new(),
            handshake_in: Vec::new(),
            transcript: None,
            key_schedule: None,
            peer_chain: None,
            cert_verify: None,
            negotiated_alpn: None,
            peer_transport: None,
            saw_ee: false,
            saw_cert: false,
            saw_cv: false,
            complete: false,
        }
    }

    pub(crate) fn start(&mut self, source_cid: &[u8]) -> TlsResult<Vec<u8>> {
        let mut random = [0u8; 32];
        super::handshake::fill_entropy(&mut random)?;
        super::handshake::fill_entropy(&mut self.private_key)?;
        let public_key = x25519::x25519(&self.private_key, &x25519::BASE_POINT);
        let params = self.client_transport.encode(source_cid)?;
        self.client_hello = super::handshake::build_client_hello_with_transport_params(
            &random,
            &public_key,
            &self.alpn,
            Some(&self.server_name),
            Some(&params),
        );
        Ok(self.client_hello.clone())
    }

    pub(crate) fn on_initial(&mut self, bytes: &[u8]) -> TlsResult<()> {
        append_bounded(&mut self.initial_in, bytes, MAX_CRYPTO_BUFFER)?;
        let message = parse_single_message(&self.initial_in, HS_SERVER_HELLO)?;
        let sh: ServerHelloInfo = parse_server_hello(&message[4..])?;
        if !sh.session_id.is_empty() {
            return Err(TlsError::Protocol(
                "QUIC ServerHello session id mismatch".into(),
            ));
        }
        let params = sh.transport_params.as_deref().ok_or_else(|| {
            TlsError::Protocol("QUIC ServerHello lacks transport parameters".into())
        })?;
        let peer_transport = TransportParameters::parse(params)?;
        self.peer_transport = Some(peer_transport.clone());
        if peer_transport.initial_source_connection_id != self.expected_server_cid {
            return Err(TlsError::Protocol(
                "server initial_source_connection_id does not match connection id".into(),
            ));
        }
        let mut transcript = Transcript::new(sh.suite.hash());
        transcript.update(&self.client_hello);
        transcript.update(&message);
        let shared = x25519::x25519(&self.private_key, &sh.key_share);
        let th = transcript.current_hash();
        self.key_schedule = Some(KeySchedule::handshake(sh.suite, &shared, &th));
        self.transcript = Some(transcript);
        self.initial_in.clear();
        Ok(())
    }

    /// Transport limits advertised by the server in ServerHello.
    pub(crate) fn peer_transport(&self) -> Option<&TransportParameters> {
        self.peer_transport.as_ref()
    }

    /// The server-to-client Handshake packet key becomes available after
    /// ServerHello has been processed.
    pub(crate) fn handshake_read_key(&self) -> Option<PacketKey> {
        let schedule = self.key_schedule.as_ref()?;
        PacketKey::from_secret(schedule.suite().wire(), schedule.server_handshake()).ok()
    }

    /// The client-to-server Handshake packet key becomes available after
    /// ServerHello has been processed.
    pub(crate) fn handshake_write_key(&self) -> Option<PacketKey> {
        let schedule = self.key_schedule.as_ref()?;
        PacketKey::from_secret(schedule.suite().wire(), schedule.client_handshake()).ok()
    }

    /// Bind the transport-layer server connection id learned from the
    /// Server Initial before validating `initial_source_connection_id`.
    pub(crate) fn set_expected_server_cid(&mut self, cid: Vec<u8>) {
        self.expected_server_cid = cid;
    }

    pub(crate) fn on_handshake(&mut self, bytes: &[u8]) -> TlsResult<Option<QuicTlsFlight>> {
        if self.key_schedule.is_none() {
            return Err(TlsError::Protocol(
                "QUIC handshake keys are not ready".into(),
            ));
        }
        append_bounded(&mut self.handshake_in, bytes, MAX_CRYPTO_BUFFER)?;
        loop {
            let message = match next_complete_message(&self.handshake_in)? {
                Some(m) => m,
                None => return Ok(None),
            };
            let msg_type = message[0];
            let body = &message[4..];
            match msg_type {
                HS_ENCRYPTED_EXTENSIONS => {
                    if self.saw_ee {
                        return Err(TlsError::Protocol("duplicate EncryptedExtensions".into()));
                    }
                    self.negotiated_alpn = parse_encrypted_extensions(body)?;
                    if self.negotiated_alpn.as_deref() != Some(b"h3") {
                        return Err(TlsError::Unsupported(
                            "QUIC requires ALPN h3; server did not negotiate it".into(),
                        ));
                    }
                    self.saw_ee = true;
                    self.transcript_mut()?.update(&message);
                }
                HS_CERTIFICATE => {
                    if !self.saw_ee || self.saw_cert {
                        return Err(TlsError::Protocol("unexpected Certificate message".into()));
                    }
                    let chain = parse_certificate_list(body)?;
                    let total: usize = chain.iter().map(Vec::len).sum();
                    if chain.is_empty() || total > MAX_CERT_CHAIN {
                        return Err(TlsError::Certificate(
                            "invalid server certificate chain".into(),
                        ));
                    }
                    self.peer_chain = Some(chain);
                    self.saw_cert = true;
                    self.transcript_mut()?.update(&message);
                }
                HS_CERTIFICATE_VERIFY => {
                    if !self.saw_cert || self.saw_cv {
                        return Err(TlsError::Protocol(
                            "unexpected CertificateVerify message".into(),
                        ));
                    }
                    let cv = parse_cert_verify(body)?;
                    let chain = self.peer_chain.as_ref().ok_or_else(|| {
                        TlsError::Protocol("CertificateVerify without certificate".into())
                    })?;
                    let leaf = super::x509::parse_certificate(&chain[0])?;
                    let hash = self.transcript_ref()?.current_hash();
                    if self.verify {
                        if !super::x509::hostname_matches(
                            &self.server_name,
                            &leaf.dns_names,
                            &leaf.ip_names,
                        ) {
                            return Err(TlsError::Certificate("hostname mismatch".into()));
                        }
                        super::x509::validate_chain(&self.roots, chain, self.now)?;
                        if !super::x509::has_server_auth_eku(&leaf) {
                            return Err(TlsError::Certificate(
                                "leaf certificate lacks TLS serverAuth EKU".into(),
                            ));
                        }
                    }
                    let suite = self.key_schedule_ref()?.suite();
                    verify_cert_verify(&cv, &leaf.spki, &hash, false, suite)?;
                    self.cert_verify = Some(cv);
                    self.saw_cv = true;
                    self.transcript_mut()?.update(&message);
                }
                HS_FINISHED => {
                    if !self.saw_ee || !self.saw_cert || !self.saw_cv || self.complete {
                        return Err(TlsError::Protocol("unexpected server Finished".into()));
                    }
                    let expected = {
                        let ks = self.key_schedule_ref()?;
                        finished_verify_data(
                            ks,
                            ks.server_handshake(),
                            &self.transcript_ref()?.current_hash(),
                        )
                    };
                    if !constant_time_eq(&expected, body) {
                        return Err(TlsError::Alert {
                            level: 2,
                            description: 51,
                        });
                    }
                    self.transcript_mut()?.update(&message);
                    let after_fin_hash = self.transcript_ref()?.current_hash();
                    self.key_schedule_mut()?.application(&after_fin_hash)?;
                    let client_fin = {
                        let ks = self.key_schedule_ref()?;
                        finished_verify_data(ks, ks.client_handshake(), &after_fin_hash)
                    };
                    let fin = encode_hs(HS_FINISHED, &client_fin);
                    let ks = self.key_schedule_ref()?;
                    let flight = QuicTlsFlight {
                        handshake: fin,
                        handshake_write: Some(packet_keys(ks.suite(), ks.client_handshake())?),
                        handshake_read: Some(packet_keys(ks.suite(), ks.server_handshake())?),
                        application_write: Some(packet_keys(
                            ks.suite(),
                            ks.client_application_secret(),
                        )?),
                        application_read: Some(packet_keys(
                            ks.suite(),
                            ks.server_application_secret(),
                        )?),
                        peer_transport: None,
                        ..Default::default()
                    };
                    self.complete = true;
                    self.handshake_in.clear();
                    return Ok(Some(flight));
                }
                _ => {
                    return Err(TlsError::Protocol(
                        "unexpected QUIC TLS handshake message".into(),
                    ))
                }
            }
            self.handshake_in.drain(..message.len());
        }
    }

    fn transcript_ref(&self) -> TlsResult<&Transcript> {
        self.transcript
            .as_ref()
            .ok_or_else(|| TlsError::Internal("missing QUIC TLS transcript".into()))
    }

    fn transcript_mut(&mut self) -> TlsResult<&mut Transcript> {
        self.transcript
            .as_mut()
            .ok_or_else(|| TlsError::Internal("missing QUIC TLS transcript".into()))
    }

    fn key_schedule_ref(&self) -> TlsResult<&KeySchedule> {
        self.key_schedule
            .as_ref()
            .ok_or_else(|| TlsError::Internal("missing QUIC TLS key schedule".into()))
    }

    fn key_schedule_mut(&mut self) -> TlsResult<&mut KeySchedule> {
        self.key_schedule
            .as_mut()
            .ok_or_else(|| TlsError::Internal("missing QUIC TLS key schedule".into()))
    }
}

/// Server-side QUIC TLS state machine.
pub(crate) struct QuicServer {
    identity: Identity,
    alpn: Vec<Vec<u8>>,
    server_transport: TransportParameters,
    server_source_cid: Vec<u8>,
    transcript: Option<Transcript>,
    key_schedule: Option<KeySchedule>,
    complete: bool,
}

impl QuicServer {
    pub(crate) fn new(
        identity: Identity,
        alpn: Vec<Vec<u8>>,
        server_transport: TransportParameters,
        server_source_cid: Vec<u8>,
    ) -> Self {
        Self {
            identity,
            alpn,
            server_transport,
            server_source_cid,
            transcript: None,
            key_schedule: None,
            complete: false,
        }
    }

    pub(crate) fn on_client_hello(&mut self, bytes: &[u8]) -> TlsResult<QuicTlsFlight> {
        let message = parse_single_message(bytes, HS_CLIENT_HELLO)?;
        let ch: ClientHelloInfo = parse_client_hello(&message[4..])?;
        let client_params = ch.transport_params.as_deref().ok_or_else(|| {
            TlsError::Protocol("QUIC ClientHello lacks transport parameters".into())
        })?;
        let client_transport = TransportParameters::parse(client_params)?;
        if !ch.alpn.iter().any(|p| p.as_slice() == b"h3") {
            return Err(TlsError::Unsupported("client did not offer ALPN h3".into()));
        }
        if !self.alpn.iter().any(|p| p.as_slice() == b"h3") {
            return Err(TlsError::Unsupported(
                "server is not configured to negotiate ALPN h3".into(),
            ));
        }
        if self.identity.cert_chain.is_empty() || self.identity.private_key.is_empty() {
            return Err(TlsError::Certificate(
                "QUIC server identity is incomplete".into(),
            ));
        }
        let mut s_priv = [0u8; 32];
        super::handshake::fill_entropy(&mut s_priv)?;
        let s_pub = x25519::x25519(&s_priv, &x25519::BASE_POINT);
        let shared = x25519::x25519(&s_priv, &ch.key_share);
        let mut random = [0u8; 32];
        super::handshake::fill_entropy(&mut random)?;
        let params = self.server_transport.encode(&self.server_source_cid)?;
        let sh = super::handshake::build_server_hello_with_transport_params(
            &random,
            &s_pub,
            ch.suite,
            &ch.session_id,
            Some(&params),
        );
        let mut transcript = Transcript::new(ch.suite.hash());
        transcript.update(&message);
        transcript.update(&sh);
        let th = transcript.current_hash();
        let mut ks = KeySchedule::handshake(ch.suite, &shared, &th);

        let ee = encrypted_extensions_h3();
        let cert = certificate_message(&self.identity.cert_chain)?;
        transcript.update(&ee);
        transcript.update(&cert);
        let cv_hash = transcript.current_hash();
        let sig_content = cert_verify_message(&cv_hash, false);
        let (scheme, signature) = server_sign(&self.identity, &sig_content, ch.suite)?
            .ok_or_else(|| TlsError::Certificate("server identity cannot sign".into()))?;
        let mut cv_body = Vec::with_capacity(4 + signature.len());
        cv_body.extend_from_slice(&scheme.to_be_bytes());
        let sig_len = u16::try_from(signature.len()).map_err(|_| {
            TlsError::Certificate("CertificateVerify signature is too large".into())
        })?;
        cv_body.extend_from_slice(&sig_len.to_be_bytes());
        cv_body.extend_from_slice(&signature);
        let cv = encode_hs(HS_CERTIFICATE_VERIFY, &cv_body);
        transcript.update(&cv);
        let fin_hash = transcript.current_hash();
        let fin_body = finished_verify_data(&ks, ks.server_handshake(), &fin_hash);
        let fin = encode_hs(HS_FINISHED, &fin_body);
        transcript.update(&fin);
        ks.application(&transcript.current_hash())?;

        self.transcript = Some(transcript);
        self.key_schedule = Some(ks);
        let ks = self.key_schedule_ref()?;
        let flight = QuicTlsFlight {
            initial: sh,
            handshake: [ee, cert, cv, fin].concat(),
            handshake_write: Some(packet_keys(ks.suite(), ks.server_handshake())?),
            handshake_read: Some(packet_keys(ks.suite(), ks.client_handshake())?),
            application_write: Some(packet_keys(ks.suite(), ks.server_application_secret())?),
            application_read: Some(packet_keys(ks.suite(), ks.client_application_secret())?),
            peer_transport: Some(client_transport),
        };
        // The server's initial flight is intentionally explicit; this also
        // prevents a caller from accidentally sending handshake bytes in the
        // Initial packet-number space.
        if flight.initial.is_empty() || flight.handshake.is_empty() {
            return Err(TlsError::Internal("empty QUIC server TLS flight".into()));
        }
        Ok(flight)
    }

    pub(crate) fn on_client_finished(&mut self, bytes: &[u8]) -> TlsResult<QuicTlsFlight> {
        let message = parse_single_message(bytes, HS_FINISHED)?;
        if self.complete {
            return Err(TlsError::Protocol("duplicate QUIC client Finished".into()));
        }
        let hash = self.transcript_ref()?.current_hash();
        let ks = self.key_schedule_ref()?;
        let expected = finished_verify_data(ks, ks.client_handshake(), &hash);
        if !constant_time_eq(&expected, &message[4..]) {
            return Err(TlsError::Alert {
                level: 2,
                description: 51,
            });
        }
        self.transcript_mut()?.update(&message);
        self.complete = true;
        let ks = self.key_schedule_ref()?;
        Ok(QuicTlsFlight {
            application_write: Some(packet_keys(ks.suite(), ks.server_application_secret())?),
            application_read: Some(packet_keys(ks.suite(), ks.client_application_secret())?),
            ..Default::default()
        })
    }

    fn transcript_ref(&self) -> TlsResult<&Transcript> {
        self.transcript
            .as_ref()
            .ok_or_else(|| TlsError::Internal("missing QUIC TLS transcript".into()))
    }

    fn transcript_mut(&mut self) -> TlsResult<&mut Transcript> {
        self.transcript
            .as_mut()
            .ok_or_else(|| TlsError::Internal("missing QUIC TLS transcript".into()))
    }

    fn key_schedule_ref(&self) -> TlsResult<&KeySchedule> {
        self.key_schedule
            .as_ref()
            .ok_or_else(|| TlsError::Internal("missing QUIC TLS key schedule".into()))
    }
}

fn encrypted_extensions_h3() -> Vec<u8> {
    let mut alpn = Vec::with_capacity(5);
    alpn.extend_from_slice(&[0x00, 0x03, 0x02]);
    alpn.push(b'h');
    alpn.push(b'3');
    let extension_len = 2usize + 2 + alpn.len();
    let mut body = Vec::with_capacity(2 + extension_len);
    body.extend_from_slice(&(extension_len as u16).to_be_bytes());
    body.extend_from_slice(&0x0010u16.to_be_bytes());
    body.extend_from_slice(&(alpn.len() as u16).to_be_bytes());
    body.extend_from_slice(&alpn);
    encode_hs(HS_ENCRYPTED_EXTENSIONS, &body)
}

fn certificate_message(chain: &[Vec<u8>]) -> TlsResult<Vec<u8>> {
    let mut entries = Vec::new();
    let mut total = 0usize;
    for cert in chain {
        if cert.len() > 0x00ff_ffff {
            return Err(TlsError::Certificate(
                "certificate is larger than TLS u24".into(),
            ));
        }
        total = total
            .checked_add(3 + cert.len() + 2)
            .ok_or_else(|| TlsError::Certificate("certificate chain length overflow".into()))?;
        if total > MAX_CERT_CHAIN {
            return Err(TlsError::Certificate(
                "certificate chain is too large".into(),
            ));
        }
        entries.extend_from_slice(&[
            (cert.len() >> 16) as u8,
            (cert.len() >> 8) as u8,
            cert.len() as u8,
        ]);
        entries.extend_from_slice(cert);
        entries.extend_from_slice(&[0, 0]);
    }
    if entries.len() > 0x00ff_ffff {
        return Err(TlsError::Certificate(
            "certificate chain is larger than TLS u24".into(),
        ));
    }
    let mut body = Vec::with_capacity(4 + entries.len());
    body.push(0);
    body.extend_from_slice(&[
        (entries.len() >> 16) as u8,
        (entries.len() >> 8) as u8,
        entries.len() as u8,
    ]);
    body.extend_from_slice(&entries);
    Ok(encode_hs(HS_CERTIFICATE, &body))
}

fn parse_single_message(bytes: &[u8], expected_type: u8) -> TlsResult<Vec<u8>> {
    let message = parse_hs(bytes)
        .ok_or_else(|| TlsError::Protocol("incomplete TLS handshake message".into()))?;
    let total = 4usize
        .checked_add(message.body.len())
        .ok_or_else(|| TlsError::Protocol("TLS handshake length overflow".into()))?;
    if total != bytes.len() || message.msg_type != expected_type {
        return Err(TlsError::Protocol(
            "unexpected TLS handshake message layout".into(),
        ));
    }
    Ok(bytes.to_vec())
}

fn next_complete_message(buf: &[u8]) -> TlsResult<Option<Vec<u8>>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let length = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    let total = 4usize
        .checked_add(length)
        .ok_or_else(|| TlsError::Protocol("TLS handshake length overflow".into()))?;
    if total > buf.len() {
        return Ok(None);
    }
    Ok(Some(buf[..total].to_vec()))
}

fn append_bounded(dst: &mut Vec<u8>, bytes: &[u8], max: usize) -> TlsResult<()> {
    let end = dst
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| TlsError::Protocol("QUIC CRYPTO buffer length overflow".into()))?;
    if end > max {
        return Err(TlsError::Protocol(
            "QUIC CRYPTO buffer limit exceeded".into(),
        ));
    }
    dst.extend_from_slice(bytes);
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}
