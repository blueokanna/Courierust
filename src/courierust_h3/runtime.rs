//! A dependency-free HTTP/3 runtime over UDP/QUIC.
//!
//! The runtime intentionally keeps the reactor and protocol state separate:
//! one UDP thread owns connection maps and packet-number spaces, while a
//! bounded set of ordinary Rust threads runs completed application handlers.
//! A partial or slow request therefore retains bounded buffers but never
//! reserves an application worker.

use crate::courierust_body::Body;
use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_h3::frame as h3frame;
use crate::courierust_h3::qpack::FieldLine;
use crate::courierust_h3::qpack_conn::QpackConnection;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::request::{Request, RequestHead};
use crate::courierust_http::response::Response;
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::uri::PathAndQuery;
use crate::courierust_http::version::Version;
use crate::courierust_net::poller::{fd_of, udp_fd_of, Poller, WAKE_ID};
use crate::courierust_net::stats::Stats;
use crate::courierust_quic::frame::Frame as QFrame;
use crate::courierust_quic::packet::{self, LongType};
use crate::courierust_quic::protection::{self, PacketKey};
use crate::courierust_quic::stream as stream_id;
use crate::courierust_quic::varint;
use crate::courierust_server::event::{drain_wake, wake_nudge, wakeup_pair};
use crate::courierust_server::{Handler, ServerConfig, TlsSettings};
use crate::courierust_tls::quic::{QuicClient, QuicServer, TransportParameters};
use crate::courierust_tls::RootStore;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_DATAGRAM: usize = 65_527;
const MIN_INITIAL_DATAGRAM: usize = 1200;
const MAX_PACKET_FRAMES: usize = 1024;
// Keep protected packets below the smallest practical UDP path MTU. A TLS
// flight is split into multiple CRYPTO frames; QUIC retransmits each packet
// independently, so one oversized flight must never become one datagram.
const MAX_CRYPTO_CHUNK: usize = 1000;
const MAX_CRYPTO_BUFFER: usize = 16 * 1024 * 1024;
const MAX_STREAM_CHUNKS: usize = 4096;
const MAX_H3_STREAMS: usize = 1024;
// 16 covers the three mandatory HTTP/3 unidirectional streams (control,
// QPACK encoder, QPACK decoder) plus RFC 9114 §6.2.3 reserved (grease)
// streams that independent peers such as quinn may open; this also
// matches `initial_max_streams_uni` so a reserved stream arriving in the
// same datagram as the mandatory ones is never rejected before the next
// tick replenishes MAX_STREAMS.
const MAX_H3_UNI_STREAMS: usize = 16;
/// Bounded history of completed request-stream ids. A stream's receive
/// state is released as soon as its message is fully consumed (so the
/// concurrent stream cap counts *live* streams, not the cumulative
/// request count); this set lets a late retransmission be ignored without
/// re-creating that state. The QUIC retransmission window is a few RTTs —
/// far smaller than this cap — so evicting the oldest entry is safe.
const MAX_COMPLETED_STREAMS: usize = 1024;
const MAX_H3_PENDING_REQUESTS: usize = 256;
const MAX_H3_CONNECTION_BUFFER: usize = 64 * 1024 * 1024;
/// Upper bound on datagrams drained per poll wake. A peer that floods
/// (or a zero-length datagram burst) must not starve the reactor's
/// connection sweep — `on_tick`/response flushing runs between drains.
const MAX_DATAGRAMS_PER_POLL: usize = 256;
const ACK_DELAY: Duration = Duration::from_millis(2);
/// Lower bound of the adaptive ACK batch window: enough to coalesce a
/// same-burst cluster on loopback/DC, small enough not to add a visible
/// round to a single-request flow.
const MIN_ACK_DELAY: Duration = Duration::from_micros(250);

/// `COURIERUST_H3_ACK_DELAY_MS` override for the interactive ACK batch
/// window (production default [`ACK_DELAY`]). Read once: the ACK path
/// runs per batch, so the env probe must not repeat per packet.
fn ack_delay() -> Duration {
    static DELAY: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *DELAY.get_or_init(|| {
        std::env::var("COURIERUST_H3_ACK_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(ACK_DELAY)
    })
}

/// `COURIERUST_H3_MIN_ACK_DELAY_MS` override (production default
/// [`MIN_ACK_DELAY`]).
fn min_ack_delay() -> Duration {
    static DELAY: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *DELAY.get_or_init(|| {
        std::env::var("COURIERUST_H3_MIN_ACK_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or(MIN_ACK_DELAY)
    })
}

/// `COURIERUST_H3_CWND` override for the initial congestion window in
/// bytes (production default 12 000). A larger value admits a large
/// request body in fewer ACK-paced rounds; clamped to a sane range so a
/// typo cannot disable flow control.
fn initial_congestion_window() -> usize {
    static CWND: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *CWND.get_or_init(|| {
        std::env::var("COURIERUST_H3_CWND")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(12_000)
            .clamp(1_200, 1 << 20)
    })
}

/// Cached `COURIERUST_H3_TRACE` presence. The packet-level event trace
/// (send / ACK / credit) runs on the hot path, so the env probe is
/// evaluated once per process instead of once per packet.
fn h3_packet_trace() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("COURIERUST_H3_TRACE").is_some())
}

/// Role tag used by the packet event trace.
fn h3_role(server: bool) -> &'static str {
    if server {
        "server"
    } else {
        "client"
    }
}

/// `COURIERUST_H3_RETRY=0` disables the server's Retry address
/// validation (benchmark knob; default Retry is on). Without Retry the
/// per-connection anti-amplification limit still applies, so the 3x
/// amplification bound is preserved — only the extra address-validation
/// round trip is removed.
fn h3_retry_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("COURIERUST_H3_RETRY").ok().as_deref() != Some("0"))
}
/// RFC 9000 §9.3.3: PATH_CHALLENGE probe timeout — after this long without
/// a matching PATH_RESPONSE the probe is retried once, then the pending
/// path is abandoned (the validated path remains authoritative).
const PATH_VALIDATION_TIMEOUT: Duration = Duration::from_millis(300);
/// Floor for the per-connection loss time threshold once an RTT sample
/// exists. See [`QuicTransport::loss_detection_threshold`] for why a
/// sub-millisecond floor is wrong on loopback / loaded machines.
///
/// 50 ms absorbs the peer's ACK batching (2 ms), both reactors' poll
/// latency (5 ms each) and the scheduling jitter of a loaded CI runner.
/// With the old 25 ms floor a busy peer's ACK could still arrive after
/// the client had already declared the packet lost, which under
/// sustained load turned into a retransmit storm (each "loss" collapsed
/// the congestion window and re-queued a retransmission, adding load and
/// delaying the next ACK further) until the 8-retransmit cap killed a
/// perfectly healthy connection.
const LOSS_TIMEOUT_FLOOR: Duration = Duration::from_millis(50);
/// RFC 9002 §6.1.1 time-threshold loss detection factor (9/8).
const TIME_THRESHOLD_NUM: u32 = 9;
const TIME_THRESHOLD_DEN: u32 = 8;
/// RFC 9002 §6.1.1 packet-threshold loss detection: a packet is declared
/// lost when `largest_acked` is at least this many packet numbers ahead
/// of it (the RFC's default `kPacketThreshold = 3`).
const PACKET_THRESHOLD: u64 = 3;
const MAX_RETRANSMITS: u8 = 8;
/// Automatic key update cadence: packets sent on one application key
/// phase before deriving the next (RFC 9001 §6 — long-lived
/// connections must not reuse a single AEAD key generation forever).
/// Overridable with `COURIERUST_KEY_UPDATE_PACKETS` (tests force a tiny
/// value to exercise the update deterministically).
const KEY_UPDATE_PACKETS: u64 = 4096;

fn key_update_threshold() -> u64 {
    std::env::var("COURIERUST_KEY_UPDATE_PACKETS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(KEY_UPDATE_PACKETS)
}
const RETRY_TOKEN_TTL: u64 = 30;
const RETRY_CLOCK_SKEW: u64 = 5;
const RETRY_TOKEN_VERSION: u8 = 1;
const H3_CONTROL_STREAM: u64 = h3frame::STREAM_TYPE_CONTROL;
const H3_QPACK_ENCODER_STREAM: u64 = h3frame::STREAM_TYPE_QPACK_ENCODER;
const H3_QPACK_DECODER_STREAM: u64 = h3frame::STREAM_TYPE_QPACK_DECODER;

// QPACK dynamic-table settings we advertise (RFC 9204). 4096 is a sane
// default capacity; 100 blocked streams bounds how many field sections we
// will buffer waiting for the peer's encoder stream to catch up.
const QPACK_MAX_TABLE_CAPACITY: u64 = 4096;
const QPACK_BLOCKED_STREAMS: u64 = 100;
// Client-initiated unidirectional stream ids: control 2, encoder 6,
// decoder 10 (RFC 9114 §6.2). Server-initiated: control 3, encoder 7,
// decoder 11.
const CLIENT_QPACK_ENCODER_STREAM: u64 = 6;
const CLIENT_QPACK_DECODER_STREAM: u64 = 10;
const SERVER_QPACK_ENCODER_STREAM: u64 = 7;
const SERVER_QPACK_DECODER_STREAM: u64 = 11;

/// A field section that was blocked on QPACK encoder-stream progress and
/// can now be decoded: (request/response stream id, decoded fields).
type UnblockedSection = (u64, Vec<FieldLine>);

/// Server idle receive window: bounds how long the reactor parks on the
/// poller with no datagram pending. Datagrams and the completed-response
/// self-pipe both wake the poller immediately; this only paces idle
/// periodic work (retransmit, response queue).
const SERVER_IDLE_TIMEOUT_MS: i32 = 5;
/// Override for the server/loopback reactor poll timeout, in ms.
/// `COURIERUST_H3_SERVER_POLL_MS` (default `SERVER_IDLE_TIMEOUT_MS`).
/// Smaller values trade a little CPU for tighter wake latency on
/// platforms where the self-pipe does not always interrupt the poll.
fn server_poll_ms() -> i32 {
    std::env::var("COURIERUST_H3_SERVER_POLL_MS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(SERVER_IDLE_TIMEOUT_MS)
}

/// Client driver poll timeout while the connection is busy (outstanding
/// requests or unacknowledged data), in ms.
/// `COURIERUST_H3_CLIENT_POLL_MS` (default 5). Small values bound how
/// long a lost wake defers command dispatch.
fn client_busy_poll_ms() -> i32 {
    std::env::var("COURIERUST_H3_CLIENT_POLL_MS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(5)
}

/// Client driver poll timeout while the connection is idle (no active
/// work), in ms. `COURIERUST_H3_CLIENT_IDLE_POLL_MS` (default 10).
/// Small enough that a lost wake does not park an incoming command for
/// the old 50 ms; large enough to stay cheap for many idle connections.
fn client_idle_poll_ms() -> i32 {
    std::env::var("COURIERUST_H3_CLIENT_IDLE_POLL_MS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| *v >= 1)
        .unwrap_or(10)
}
/// Poller id for the reactor's UDP socket (see `Poller::register`).
const SOCKET_ID: usize = 1;

type LevelIndex = usize;
const INITIAL: LevelIndex = 0;
const HANDSHAKE: LevelIndex = 1;
const APPLICATION: LevelIndex = 2;

type OpenPacket = (LevelIndex, u64, Vec<QFrame>, usize);

/// Limits and verification inputs for one synchronous HTTP/3 request.
#[derive(Clone)]
pub(crate) struct ClientRequestOptions {
    pub(crate) roots: RootStore,
    pub(crate) verify: bool,
    pub(crate) now: i64,
    pub(crate) max_header_list: usize,
    pub(crate) max_body: usize,
    pub(crate) timeout: Option<Duration>,
    pub(crate) stats: Option<Arc<Stats>>,
}

#[derive(Clone, Copy)]
struct H3Limits {
    max_header_list: usize,
    max_body: usize,
}

fn protocol(message: impl Into<String>) -> Error {
    Error::with_message(ErrorKind::Protocol, message.into())
}

fn io_error(message: impl Into<String>) -> Error {
    Error::with_message(ErrorKind::Io, message.into())
}

fn tls_error(error: crate::courierust_tls::TlsError) -> Error {
    Error::with_message(ErrorKind::Other, error.to_string())
}

fn random_cid() -> Result<Vec<u8>> {
    let mut cid = [0u8; 8];
    if !crate::courierust_tls::crypto::rng::fill_random(&mut cid) {
        return Err(protocol("OS randomness unavailable for QUIC connection id"));
    }
    Ok(cid.to_vec())
}

fn transport_parameters_for_limits(max_header_list: usize, max_body: usize) -> TransportParameters {
    let mut parameters = TransportParameters::default();
    let stream_limit = (max_body.saturating_add(max_header_list) as u64).min(varint::MAX);
    parameters.initial_max_data = (MAX_H3_CONNECTION_BUFFER as u64).max(stream_limit);
    parameters.initial_max_stream_data_bidi_local = stream_limit;
    parameters.initial_max_stream_data_bidi_remote = stream_limit;
    parameters
}

#[derive(Clone)]
struct RetryProtector {
    secret: [u8; 32],
}

struct RetryToken {
    retry_dcid: Vec<u8>,
    original_dcid: Vec<u8>,
}

impl RetryProtector {
    fn new() -> Result<Self> {
        let mut secret = [0u8; 32];
        if !crate::courierust_tls::crypto::rng::fill_random(&mut secret) {
            return Err(protocol("OS randomness unavailable for QUIC Retry secret"));
        }
        Ok(Self { secret })
    }

    fn mint(&self, peer: SocketAddr, original_dcid: &[u8], retry_dcid: &[u8]) -> Result<Vec<u8>> {
        if original_dcid.is_empty()
            || original_dcid.len() > 20
            || retry_dcid.is_empty()
            || retry_dcid.len() > 20
        {
            return Err(protocol("invalid connection ID in QUIC Retry token"));
        }
        let timestamp = unix_seconds();
        let mut token = Vec::with_capacity(1 + 8 + 1 + 18 + 1 + 20 + 1 + 20 + 32);
        token.push(RETRY_TOKEN_VERSION);
        token.extend_from_slice(&timestamp.to_be_bytes());
        encode_peer_address(&mut token, peer);
        token.push(original_dcid.len() as u8);
        token.extend_from_slice(original_dcid);
        token.push(retry_dcid.len() as u8);
        token.extend_from_slice(retry_dcid);
        let mac = retry_mac(&self.secret, &token);
        token.extend_from_slice(&mac);
        Ok(token)
    }

    fn validate(&self, peer: SocketAddr, token: &[u8]) -> Option<RetryToken> {
        // The fixed fields and two bounded connection IDs make this a cheap
        // reject path before any allocation or TLS work is performed.
        if token.len() < 1 + 8 + 1 + 2 + 1 + 1 + 1 + 32 {
            return None;
        }
        let body_len = token.len().checked_sub(32)?;
        let (body, supplied_mac) = token.split_at(body_len);
        let expected_mac = retry_mac(&self.secret, body);
        if !constant_time_equal(&expected_mac, supplied_mac) {
            return None;
        }
        let mut pos = 0usize;
        if body.get(pos).copied()? != RETRY_TOKEN_VERSION {
            return None;
        }
        pos += 1;
        let timestamp = u64::from_be_bytes(body.get(pos..pos + 8)?.try_into().ok()?);
        pos += 8;
        let (encoded_peer, used) = decode_peer_address(&body[pos..])?;
        pos += used;
        if encoded_peer != peer {
            return None;
        }
        let original_len = *body.get(pos)? as usize;
        pos += 1;
        if !(1..=20).contains(&original_len) {
            return None;
        }
        let original_end = pos.checked_add(original_len)?;
        let original_dcid = body.get(pos..original_end)?.to_vec();
        pos = original_end;
        let retry_len = *body.get(pos)? as usize;
        pos += 1;
        if !(1..=20).contains(&retry_len) {
            return None;
        }
        let retry_end = pos.checked_add(retry_len)?;
        let retry_dcid = body.get(pos..retry_end)?.to_vec();
        if retry_end != body.len() {
            return None;
        }
        let now = unix_seconds();
        if timestamp > now.saturating_add(RETRY_CLOCK_SKEW)
            || now.saturating_sub(timestamp) > RETRY_TOKEN_TTL
        {
            return None;
        }
        Some(RetryToken {
            retry_dcid,
            original_dcid,
        })
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn retry_mac(secret: &[u8; 32], body: &[u8]) -> [u8; 32] {
    use crate::courierust_tls::crypto::hash::Sha256;
    use crate::courierust_tls::crypto::hmac::hmac;

    let mut digest = Sha256::new();
    hmac(&mut digest, secret, body)
        .try_into()
        .expect("SHA-256 HMAC has a fixed 32-byte output")
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

fn encode_peer_address(out: &mut Vec<u8>, peer: SocketAddr) {
    match peer {
        SocketAddr::V4(address) => {
            out.push(4);
            out.extend_from_slice(&address.ip().octets());
            out.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            out.push(6);
            out.extend_from_slice(&address.ip().octets());
            out.extend_from_slice(&address.port().to_be_bytes());
        }
    }
}

fn decode_peer_address(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let family = *buf.first()?;
    let address_len = match family {
        4 => 4,
        6 => 16,
        _ => return None,
    };
    let end = 1usize.checked_add(address_len)?.checked_add(2)?;
    let address = buf.get(1..end - 2)?;
    let port = u16::from_be_bytes(buf.get(end - 2..end)?.try_into().ok()?);
    let peer = if family == 4 {
        SocketAddr::from((<[u8; 4]>::try_from(address).ok()?, port))
    } else {
        SocketAddr::from((<[u8; 16]>::try_from(address).ok()?, port))
    };
    Some((peer, end))
}

/// A server handle is intentionally detached: the main TCP server owns the
/// lifetime of this thread, while dropping the handle never blocks shutdown.
pub(crate) struct Http3Handle {
    _join: thread::JoinHandle<()>,
}

/// Start the UDP HTTP/3 reactor on the UDP port corresponding to the TCP
/// listener. TCP and UDP may legally share a numeric port.
pub(crate) fn spawn_server(
    addr: SocketAddr,
    tls: &TlsSettings,
    handler: Arc<dyn Handler>,
    config: ServerConfig,
) -> std::io::Result<Http3Handle> {
    // macOS (BSD) requires `SO_REUSEADDR` on the UDP socket before it
    // may share its numeric port with the TCP listener; other platforms
    // bind directly (see `courierust_net::udp`).
    let socket = crate::courierust_net::udp::bind_udp(addr)?;
    spawn_server_with_socket(socket, tls, handler, config)
}

/// Start the reactor on an already-bound UDP socket.
///
/// Callers that can choose their own port (tests) use this to sidestep
/// two port-selection hazards that a TCP-derived port can hit on
/// Windows: the probe-then-bind race (the socket stays bound, so no
/// other socket can steal the port between choosing and binding), and
/// the independent TCP/UDP excluded-port ranges (Hyper-V/WinNAT reserve
/// ranges where a port a TCP socket just freed can still be unbindable
/// by UDP — WSAEACCES/10013). Probing with UDP makes the port UDP-valid
/// by construction.
pub(crate) fn spawn_server_with_socket(
    socket: std::net::UdpSocket,
    tls: &TlsSettings,
    handler: Arc<dyn Handler>,
    config: ServerConfig,
) -> std::io::Result<Http3Handle> {
    if !tls.alpn.iter().any(|protocol| protocol.as_slice() == b"h3") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTP/3 requires ServerConfig TLS ALPN to include h3",
        ));
    }
    socket.set_nonblocking(true)?;
    let identity = tls.identity.clone();
    let alpn = tls.alpn.clone();
    let join = thread::Builder::new()
        .name("courierust-h3-reactor".into())
        .spawn(move || {
            let _ = run_server(socket, identity, alpn, handler, config);
        })?;
    Ok(Http3Handle { _join: join })
}

/// Execute one synchronous HTTP/3 request. The UDP transport is still
/// event-driven internally; this API only waits for the final response for
/// Create a fresh QUIC/TLS client connection to `addr`. The socket is
/// returned unconfigured so each caller picks its own wait strategy: the
/// pooled driver registers the socket with the poller.
fn build_client_connection(
    addr: SocketAddr,
    hostname: &str,
    authority: &str,
    options: &ClientRequestOptions,
) -> Result<(UdpSocket, ClientConnection)> {
    if options.max_body == 0 {
        return Err(protocol("HTTP/3 max_body must be non-zero"));
    }
    let socket = UdpSocket::bind(match addr {
        SocketAddr::V4(_) => "0.0.0.0:0"
            .parse::<SocketAddr>()
            .expect("valid IPv4 wildcard"),
        SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>().expect("valid IPv6 wildcard"),
    })
    .map_err(|e| io_error(e.to_string()))?;
    // Left unconnected: `recv_from` reports the real source address so a
    // migrated / NAT-rebound peer path can be validated (RFC 9000 §9).
    socket
        .set_nonblocking(true)
        .map_err(|e| io_error(e.to_string()))?;
    let local_cid = random_cid()?;
    let server_cid = random_cid()?;
    let local_tp = transport_parameters_for_limits(options.max_header_list, options.max_body);
    let mut tls = QuicClient::new(
        hostname,
        vec![b"h3".to_vec()],
        options.verify,
        options.roots.clone(),
        options.now,
        local_tp.clone(),
        server_cid.clone(),
    );
    let client_hello = tls.start(&local_cid).map_err(tls_error)?;
    let mut transport = QuicTransport::client(
        local_cid,
        server_cid.clone(),
        server_cid.clone(),
        options.stats.clone(),
    )?;
    transport.peer = Some(addr);
    transport.set_local_transport(&local_tp);
    let conn = ClientConnection::new(
        transport,
        tls,
        client_hello,
        authority.to_string(),
        H3Limits {
            max_header_list: options.max_header_list,
            max_body: options.max_body,
        },
        options.stats.clone(),
    )?;
    Ok((socket, conn))
}

/// A command submitted to a pooled h3 connection driver.
pub(crate) enum H3Cmd {
    Request {
        request: Request<Body>,
        reply: mpsc::Sender<Result<Response<Body>>>,
    },
    Shutdown,
}

/// Handle to a live pooled h3 connection driver (mirrors the h2 pool's
/// `H2Conn`): dispatch sends a command through `tx` and nudges the
/// driver's wake pipe so its poller returns immediately.
#[derive(Clone)]
pub(crate) struct H3Conn {
    tx: mpsc::Sender<H3Cmd>,
    wake: Arc<std::net::TcpStream>,
    pub(crate) accepting: Arc<AtomicBool>,
    reservations: Arc<AtomicUsize>,
}

impl H3Conn {
    pub(crate) fn reserve(&self) {
        self.reservations.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn release(&self) {
        // `fetch_update` (Rust 1.45) retries the CAS, so a release under
        // contention is never dropped; `try_update` (Rust 1.95) is both
        // above our MSRV and can return `Err`, leaking a reservation.
        let _ = self
            .reservations
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_sub(1))
            });
    }

    pub(crate) fn reservations(&self) -> usize {
        self.reservations.load(Ordering::Acquire)
    }

    /// Submit a command and wake the driver's poller. The large `Err` is
    /// std's `mpsc::SendError`, which carries the command back so the
    /// caller can retry it on a fresh connection — boxing it would defeat
    /// the retry.
    #[allow(clippy::result_large_err)]
    pub(crate) fn send(&self, cmd: H3Cmd) -> Result<(), mpsc::SendError<H3Cmd>> {
        self.tx.send(cmd)?;
        wake_nudge(&self.wake);
        Ok(())
    }
}

/// Flipped to `false` when the driver exits, so the pool stops dispatching
/// to a connection whose thread is gone.
struct DriverAcceptingGuard(Arc<AtomicBool>);

impl Drop for DriverAcceptingGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Open a pooled h3 connection to `addr` and spawn its driver thread. The
/// connection performs the QUIC/TLS handshake on first use; requests
/// submitted before the handshake completes are queued and dispatched by
/// the driver once the connection is usable. Subsequent requests reuse the
/// connection (and its TLS session) for the lifetime of the pool entry.
pub(crate) fn start_h3_driver(
    addr: SocketAddr,
    hostname: String,
    authority: String,
    options: ClientRequestOptions,
    idle_timeout: Option<Duration>,
) -> Result<H3Conn> {
    let (socket, conn) = build_client_connection(addr, &hostname, &authority, &options)?;
    let (tx, rx) = mpsc::channel::<H3Cmd>();
    let accepting = Arc::new(AtomicBool::new(true));
    let reservations = Arc::new(AtomicUsize::new(0));
    let (wake_reader, wake_writer) = wakeup_pair().map_err(|e| io_error(e.to_string()))?;
    let wake_writer = Arc::new(wake_writer);
    if let Some(stats) = options.stats.as_deref() {
        stats.h3_connections.fetch_add(1, Ordering::Relaxed);
        stats.h3_connections_active.fetch_add(1, Ordering::Relaxed);
    }
    let stats = options.stats.clone();
    let accepting2 = accepting.clone();
    thread::Builder::new()
        .name("courierust-h3-driver".into())
        .spawn(move || {
            let _ = run_client_driver(
                socket,
                conn,
                rx,
                wake_reader,
                options,
                accepting2,
                idle_timeout,
                stats,
            );
        })?;
    Ok(H3Conn {
        tx,
        wake: wake_writer,
        accepting,
        reservations,
    })
}

/// The pooled client connection's reactor: owns the socket and the
/// multiplexing connection state, waits on the poller (socket + wake
/// pipe), and serves every request dispatched to this connection. Runs
/// until every in-flight request is done and the connection has been idle
/// for `idle_timeout`, or until the connection fails.
#[allow(clippy::too_many_arguments)]
fn run_client_driver(
    socket: UdpSocket,
    mut conn: ClientConnection,
    commands: mpsc::Receiver<H3Cmd>,
    wake_reader: std::net::TcpStream,
    options: ClientRequestOptions,
    accepting: Arc<AtomicBool>,
    idle_timeout: Option<Duration>,
    stats: Option<Arc<Stats>>,
) -> Result<()> {
    let _stats_guard = stats.map(|stats| H3ActiveGuard { stats });
    let _accepting_guard = DriverAcceptingGuard(accepting);
    let _ = socket.set_nonblocking(true);
    let idle = idle_timeout.unwrap_or(Duration::from_secs(300));
    let mut poller = Poller::new();
    poller.register(SOCKET_ID, udp_fd_of(&socket), false);
    let wake_fd = fd_of(&wake_reader);
    let mut datagram = [0u8; MAX_DATAGRAM];
    let mut last_activity = Instant::now();

    loop {
        let mut shutdown = false;
        while let Ok(cmd) = commands.try_recv() {
            match cmd {
                H3Cmd::Request { request, reply } => {
                    if conn.peer_goaway.is_some() {
                        let _ =
                            reply.send(Err(Error::canceled("HTTP/3 connection received GOAWAY")));
                        continue;
                    }
                    let deadline =
                        Instant::now() + options.timeout.unwrap_or(Duration::from_secs(60));
                    conn.queue_request(request, reply, deadline);
                    last_activity = Instant::now();
                }
                H3Cmd::Shutdown => {
                    shutdown = true;
                    break;
                }
            }
        }
        if shutdown {
            break;
        }

        if let Err(error) = conn.on_tick(&socket) {
            return finish(conn, &socket, error);
        }
        let now = Instant::now();
        conn.check_timeouts(now);

        if conn.has_work() {
            last_activity = now;
        } else if now.duration_since(last_activity) >= idle {
            let _ = conn.send_goaway(&socket);
            let _ = conn.transport.send_connection_close(
                &socket,
                0x1,
                None,
                "HTTP/3 client idle timeout",
            );
            return Ok(());
        }
        if conn.peer_goaway.is_some() {
            _accepting_guard.0.store(false, Ordering::Release);
        }

        let mut wait_ms: i64 = if conn.has_work() || conn.transport.has_unacknowledged() {
            client_busy_poll_ms() as i64
        } else {
            client_idle_poll_ms() as i64
        };
        if conn.is_idle() {
            let remaining = idle.saturating_sub(now.duration_since(last_activity));
            wait_ms = wait_ms.min(remaining.as_millis().min(i64::MAX as u128) as i64);
        }
        if let Some(deadline) = conn.earliest_deadline() {
            let remaining = deadline.saturating_duration_since(now);
            wait_ms = wait_ms.min(remaining.as_millis().min(i64::MAX as u128) as i64);
        }
        // Fold QUIC protocol deadlines (pending ACK batch, loss/PTO
        // timers, path validation) into the poll: a deferred ACK or a
        // loss timer must fire at its absolute deadline, not on the next
        // fixed 5 ms tick — that tick is the H3 loopback tail.
        if let Some(deadline) = conn.transport.earliest_deadline() {
            let remaining = deadline.saturating_duration_since(now);
            wait_ms = wait_ms.min(remaining.as_millis().min(i64::MAX as u128) as i64);
        }
        let wait_started = Instant::now();
        if h3_packet_trace() {
            eprintln!(
                "H3TRACE|client|poll-enter wait_ms={wait_ms} active={} waiting={} unacked={}",
                conn.active.len(),
                conn.waiting.len(),
                conn.transport.unacknowledged_bytes()
            );
        }
        let ready = match poller.wait(wait_ms.max(1) as i32, Some(wake_fd)) {
            Ok(ready) => ready,
            Err(error) => return finish(conn, &socket, io_error(error.to_string())),
        };
        // Per-poll timeline (COURIERUST_H3_TRACE): a long wait here means
        // a lost wake deferred command dispatch or response handling — the
        // client side of the H3 tail.
        if h3_packet_trace() {
            let wait_us = wait_started.elapsed().as_micros() as u64;
            eprintln!(
                "H3TRACE|client|poll-return wait_us={wait_us} ready={ready:?} active={} waiting={}",
                conn.active.len(),
                conn.waiting.len()
            );
        }
        if ready.contains(&SOCKET_ID) {
            // Bounded drain: mirror the server so a flood cannot starve
            // `on_tick` / deadline handling between datagram batches.
            for _ in 0..MAX_DATAGRAMS_PER_POLL {
                match socket.recv_from(&mut datagram) {
                    Ok((n, source)) => {
                        if n == 0 || n > MAX_DATAGRAM {
                            return finish(conn, &socket, protocol("invalid QUIC datagram length"));
                        }
                        last_activity = Instant::now();
                        if let Some(stats) = options.stats.as_deref() {
                            stats.h3_udp_recv_syscalls.fetch_add(1, Ordering::Relaxed);
                        }
                        if let Err(error) = conn.on_datagram(&socket, source, &mut datagram[..n]) {
                            if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                                eprintln!("H3CLIENT on_datagram error: {error}");
                            }
                            return finish(conn, &socket, error);
                        }
                        if conn.peer_closed {
                            conn.fail_all(Error::canceled("HTTP/3 connection closed by peer"));
                            return Ok(());
                        }
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut
                            || error.kind() == std::io::ErrorKind::ConnectionReset =>
                    {
                        break;
                    }
                    Err(error) => return finish(conn, &socket, io_error(error.to_string())),
                }
            }
            // Flush the whole receive batch's ACKs in one pass: the
            // interactive fast path (ack_deadline None) coalesces a burst
            // into one ACK, and doing it here — not per datagram — keeps
            // that coalescing while still acknowledging promptly.
            if let Err(error) = conn.flush_acks(&socket) {
                return finish(conn, &socket, error);
            }
        }
        if ready.contains(&WAKE_ID) {
            drain_wake(&wake_reader);
        }
    }
    let _ = conn.send_goaway(&socket);
    let _ = conn
        .transport
        .send_connection_close(&socket, 0x1, None, "client shutdown");
    conn.fail_all(Error::canceled("HTTP/3 connection closed"));
    Ok(())
}

/// Close the connection and report `error` to every outstanding request.
fn finish(mut conn: ClientConnection, socket: &UdpSocket, error: Error) -> Result<()> {
    let _ = conn
        .transport
        .send_connection_close(socket, 0x1, None, &error.to_string());
    conn.fail_all(error);
    Ok(())
}

/// The reactor's shared mutable state: connection maps keyed by QUIC
/// destination CID, the Retry protector, and the static server setup.
/// Grouping them keeps datagram routing and the per-connection sweep on
/// one coherent unit (high cohesion) without threading nine parameters
/// through every call (low coupling).
struct ServerState {
    connections: HashMap<Vec<u8>, ServerConnection>,
    routes: HashMap<Vec<u8>, Vec<u8>>,
    retry_protector: RetryProtector,
    identity: crate::courierust_tls::Identity,
    alpn: Vec<Vec<u8>>,
    config: ServerConfig,
    /// Process-lifetime secret used to derive stateless reset tokens
    /// (RFC 9000 §10.3.2). Deterministic per CID, so a reset can be sent
    /// for a connection whose state is gone.
    reset_key: [u8; 32],
}

/// Derive the stateless reset token for a connection ID (RFC 9000
/// §10.3.2): HMAC-SHA256(server_reset_key, cid)[0..16]. The server keeps
/// one secret key for the process lifetime, so the token for a dead
/// connection's CID can be recomputed on demand — that is what makes the
/// reset *stateless*.
fn stateless_reset_token(reset_key: &[u8; 32], cid: &[u8]) -> [u8; 16] {
    use crate::courierust_tls::crypto::hash::Sha256;
    use crate::courierust_tls::crypto::hmac::hmac;
    let mut digest = Sha256::new();
    let mac = hmac(&mut digest, reset_key, cid);
    let mut token = [0u8; 16];
    token.copy_from_slice(&mac[..16]);
    token
}

/// Build a stateless reset datagram (RFC 9000 §10.3): a short-header
/// packet addressed to `dcid` with a random payload whose final 16 bytes
/// are the connection's stateless reset token. The datagram is padded so
/// the receiver can read the token without risking the packet being
/// confused with a valid short packet.
fn build_stateless_reset(dcid: &[u8], token: &[u8; 16]) -> Result<Vec<u8>> {
    if dcid.is_empty() || dcid.len() > 20 {
        return Err(protocol("invalid connection ID for stateless reset"));
    }
    let mut out = Vec::with_capacity(1 + dcid.len() + 21 + 16);
    // Short header with the destination connection ID length in the low
    // 6 bits (RFC 9000 §17.3).
    out.push(0x40 | ((dcid.len() as u8).saturating_sub(1) & 0x3f));
    out.extend_from_slice(dcid);
    let mut random = [0u8; 21];
    if !crate::courierust_tls::crypto::rng::fill_random(&mut random) {
        return Err(protocol("OS randomness unavailable for stateless reset"));
    }
    out.extend_from_slice(&random);
    out.extend_from_slice(token);
    Ok(out)
}

fn run_server(
    socket: UdpSocket,
    identity: crate::courierust_tls::Identity,
    alpn: Vec<Vec<u8>>,
    handler: Arc<dyn Handler>,
    config: ServerConfig,
) -> Result<()> {
    let (completed_tx, completed_rx) = mpsc::channel::<CompletedResponse>();
    let worker_count = if config.threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get().clamp(1, 8))
            .unwrap_or(4)
    } else {
        config.threads.max(1)
    };
    let pool = crate::courierust_pool::ThreadPool::with_size(worker_count)
        .map_err(|e| io_error(e.to_string()))?;
    let task_limit = worker_count.saturating_mul(2);
    let active_tasks = Arc::new(AtomicUsize::new(0));
    let mut state = ServerState {
        connections: HashMap::new(),
        routes: HashMap::new(),
        retry_protector: RetryProtector::new()?,
        identity,
        alpn,
        config,
        reset_key: [0u8; 32],
    };
    if !crate::courierust_tls::crypto::rng::fill_random(&mut state.reset_key) {
        return Err(protocol(
            "OS randomness unavailable for stateless reset key",
        ));
    }
    let mut datagram = [0u8; MAX_DATAGRAM];
    let (wake_reader, wake_writer) = wakeup_pair().map_err(|e| io_error(e.to_string()))?;
    let wake_writer = Arc::new(wake_writer);
    let wake_fd = fd_of(&wake_reader);
    let mut poller = Poller::new();
    poller.register(SOCKET_ID, udp_fd_of(&socket), false);

    loop {
        let wait_started = Instant::now();
        // While handlers are in flight a completed response must flush
        // promptly. A lost self-pipe wake would otherwise park it for a
        // full poll timeout; poll tightly with work outstanding (the wake
        // still wins the moment it fires).
        let mut poll_ms = if active_tasks.load(Ordering::Acquire) > 0 {
            server_poll_ms().min(1)
        } else {
            server_poll_ms()
        };
        // Fold the earliest QUIC protocol deadline (pending ACK batch,
        // loss/PTO timer, path validation) into the poll timeout: a
        // deferred ACK or loss timer must fire at its absolute deadline,
        // not on the next fixed tick. Without this, a cwnd-limited
        // upload/response round sleeps the full idle poll (5 ms) instead
        // of waking at the ACK deadline — the loopback quantum.
        let deadline_now = Instant::now();
        let mut protocol_deadline: Option<Instant> = None;
        for connection in state.connections.values() {
            if let Some(deadline) = connection.transport.earliest_deadline() {
                protocol_deadline = Some(protocol_deadline.map_or(deadline, |e| e.min(deadline)));
            }
        }
        if let Some(deadline) = protocol_deadline {
            let remaining = deadline.saturating_duration_since(deadline_now);
            poll_ms = poll_ms.min(remaining.as_millis().min(i32::MAX as u128) as i32);
        }
        let ready = poller
            .wait(poll_ms, Some(wake_fd))
            .map_err(|e| io_error(e.to_string()))?;
        // Tail instrumentation: a wake that fails to interrupt the poll
        // shows up here as a multi-ms wait, i.e. a worker→reactor handoff
        // stall that surfaces as client-side wait_headers latency.
        if std::env::var_os("COURIERUST_H3_TRACE").is_some() {
            let wait_us = wait_started.elapsed().as_micros() as u64;
            if wait_us > 1000 {
                eprintln!("H3TRACE|server|poll-wait={wait_us}us ready={ready:?}");
            }
        }
        if ready.contains(&SOCKET_ID) {
            // Bounded drain: a flood (or zero-length datagrams) must not
            // starve the connection sweep that runs after this loop,
            // which is what flushes queued responses. Remaining data is
            // picked up on the next poll (the socket stays ready).
            for _ in 0..MAX_DATAGRAMS_PER_POLL {
                match socket.recv_from(&mut datagram) {
                    Ok((0, _)) => continue,
                    Ok((n, peer)) if n <= MAX_DATAGRAM => {
                        handle_server_datagram(&socket, &mut datagram[..n], peer, &mut state);
                    }
                    _ => break,
                }
            }
        }
        if ready.contains(&WAKE_ID) {
            drain_wake(&wake_reader);
        }
        while let Ok(completed) = completed_rx.try_recv() {
            if let Some(connection) = state.connections.get_mut(&completed.connection_id) {
                connection.trace_response(&completed);
                connection.queue_response(completed.stream_id, completed.response);
            }
            active_tasks.fetch_sub(1, Ordering::Relaxed);
        }

        let now = Instant::now();
        let mut dead = Vec::new();
        for (connection_id, connection) in state.connections.iter_mut() {
            if connection.peer_closed {
                if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                    eprintln!("H3SERVER conn-closed: peer sent CONNECTION_CLOSE");
                }
                dead.push(connection_id.clone());
                continue;
            }
            if (!connection.handshake_complete && now >= connection.handshake_deadline)
                || now.duration_since(connection.last_activity) >= connection.idle_timeout
            {
                if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                    eprintln!(
                        "H3SERVER conn-removed: handshake={} idle={:?}",
                        connection.handshake_complete,
                        now.duration_since(connection.last_activity),
                    );
                }
                if connection.handshake_complete {
                    let _ = connection.send_goaway(&socket);
                }
                let _ = connection.transport.send_connection_close(
                    &socket,
                    0x1,
                    None,
                    if connection.handshake_complete {
                        "HTTP/3 idle timeout"
                    } else {
                        "QUIC handshake timeout"
                    },
                );
                dead.push(connection_id.clone());
                continue;
            }
            if let Err(error) = connection.on_tick(&socket) {
                if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                    eprintln!("H3SERVER on_tick error: {error}");
                }
                let _ = connection.transport.send_connection_close(
                    &socket,
                    0x1,
                    None,
                    &error.to_string(),
                );
                dead.push(connection_id.clone());
                continue;
            }
            while let Some(request) = connection.take_request() {
                if std::env::var_os("COURIERUST_H3_DEBUG").is_some()
                    && request.request.body.len().unwrap_or(0) > 100 * 1024
                {
                    eprintln!(
                        "H3SERVER request-taken: stream={} pending={}",
                        request.stream_id,
                        connection.pending_requests.len()
                    );
                }
                if active_tasks.load(Ordering::Acquire) >= task_limit {
                    connection.push_request_front(request);
                    break;
                }
                active_tasks.fetch_add(1, Ordering::AcqRel);
                let tx = completed_tx.clone();
                let handler = handler.clone();
                let max_body = state.config.max_body;
                let connection_id = connection_id.clone();
                let wake = wake_writer.clone();
                let received_at = request.received_at;
                pool.spawn(move || {
                    // clippy::blocks_in_conditions: bind the catch_unwind
                    // result before matching on it.
                    let caught = panic::catch_unwind(AssertUnwindSafe(|| {
                        let response = handler.handle(request.request);
                        materialize_response(response, max_body)
                    }));
                    let response = match caught {
                        Ok(response) => response,
                        Err(_) => Err(protocol("HTTP/3 request handler panicked")),
                    };
                    let _ = tx.send(CompletedResponse {
                        connection_id,
                        stream_id: request.stream_id,
                        response,
                        received_at,
                        completed_at: Instant::now(),
                    });
                    // Wake the reactor so the completed response is
                    // flushed without waiting for the next poll tick.
                    wake_nudge(&wake);
                });
            }
        }
        for connection_id in dead {
            state.connections.remove(&connection_id);
            state.routes.retain(|_, target| target != &connection_id);
            if let Some(stats) = state.config.stats.as_deref() {
                Stats::decrement(&stats.connections_active, 1);
                Stats::decrement(&stats.h3_connections_active, 1);
            }
        }
    }
}

/// Route one inbound UDP datagram: to an existing connection (by
/// destination CID, address-checked), or through the Retry-based address
/// validation and `ServerConnection::accept` path for a fresh Initial.
fn handle_server_datagram(
    socket: &UdpSocket,
    datagram: &mut [u8],
    peer: SocketAddr,
    state: &mut ServerState,
) {
    let ServerState {
        connections,
        routes,
        retry_protector,
        identity,
        alpn,
        config,
        reset_key,
    } = state;
    let n = datagram.len();
    if let Some(stats) = config.stats.as_deref() {
        stats.h3_udp_recv_syscalls.fetch_add(1, Ordering::Relaxed);
    }
    if n == 0 || n > MAX_DATAGRAM {
        return;
    }
    let route = packet_destination_cid(datagram)
        .and_then(|cid| routes.get::<[u8]>(cid))
        .cloned();
    if let Some(connection_id) = route {
        let Some(connection) = connections.get_mut(&connection_id) else {
            routes.retain(|_, target| target != &connection_id);
            return;
        };
        if connection.transport.peer != Some(peer) {
            // A packet from a new source address may be a NAT rebinding or
            // a client migration. It is passed through; the connection
            // authenticates it and only then starts path validation.
            // Unauthenticated packets from the new address change nothing
            // (RFC 9000 §9.3).
        }
        let failure = connection.on_datagram(socket, peer, datagram).err();
        if let Some(error) = failure {
            if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                eprintln!("H3SERVER conn-killed: {error}");
            }
            let _ =
                connection
                    .transport
                    .send_connection_close(socket, 0x1, None, &error.to_string());
            connections.remove(&connection_id);
            routes.retain(|_, target| target != &connection_id);
            if let Some(stats) = config.stats.as_deref() {
                Stats::decrement(&stats.connections_active, 1);
                Stats::decrement(&stats.h3_connections_active, 1);
            }
        } else if connection.peer_closed {
            // RFC 9000 §10.2: the client closed the connection — normal
            // termination, removed without the conn-killed error path.
            if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                eprintln!("H3SERVER conn-closed: peer sent CONNECTION_CLOSE");
            }
            connections.remove(&connection_id);
            routes.retain(|_, target| target != &connection_id);
            if let Some(stats) = config.stats.as_deref() {
                Stats::decrement(&stats.connections_active, 1);
                Stats::decrement(&stats.h3_connections_active, 1);
            }
        }
        return;
    }
    if let Ok(parsed) = parse_long_header_identity(datagram) {
        if parsed.version != crate::courierust_quic::VERSION_1
            && parsed.packet_type == LongType::Initial
            && n >= MIN_INITIAL_DATAGRAM
        {
            if let Ok(version_packet) = encode_version_negotiation(datagram) {
                if version_packet.len() <= n.saturating_mul(3) {
                    if let Some(stats) = config.stats.as_deref() {
                        stats.h3_udp_send_syscalls.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = socket.send_to(&version_packet, peer);
                }
            }
        }
    }
    if !datagram.is_empty() && datagram[0] & 0x80 == 0 && datagram[0] & 0x40 != 0 {
        if let Some(dcid) = packet_destination_cid(datagram) {
            let token = stateless_reset_token(reset_key, dcid);
            if let Ok(reset) = build_stateless_reset(dcid, &token) {
                if reset.len() <= MAX_DATAGRAM {
                    if let Some(stats) = config.stats.as_deref() {
                        stats.h3_udp_send_syscalls.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = socket.send_to(&reset, peer);
                    return;
                }
            }
        }
    }
    if config.max_connections != 0 && connections.len() >= config.max_connections {
        return;
    }
    if !looks_like_initial(datagram) || n < MIN_INITIAL_DATAGRAM {
        return;
    }
    let Ok(meta) = PacketMeta::parse(datagram, 8) else {
        return;
    };
    let token = retry_protector.validate(peer, &meta.token);
    let original_dcid = token.as_ref().map(|value| value.original_dcid.as_slice());
    if h3_retry_enabled()
        && token
            .as_ref()
            .map_or(true, |value| value.retry_dcid != meta.dcid)
    {
        let Ok(retry_dcid) = random_cid() else {
            return;
        };
        let Ok(token) = retry_protector.mint(peer, &meta.dcid, &retry_dcid) else {
            return;
        };
        let Ok(retry_packet) = encode_retry_packet(datagram, &meta.dcid, &retry_dcid, &token)
        else {
            return;
        };
        // Retry is sent before address validation; keep the 3x bound
        // explicit so a future token format cannot become an amplifier.
        if retry_packet.len() <= n.saturating_mul(3) {
            if let Some(stats) = config.stats.as_deref() {
                stats.h3_udp_send_syscalls.fetch_add(1, Ordering::Relaxed);
            }
            let _ = socket.send_to(&retry_packet, peer);
        }
        return;
    }
    if let Ok((mut connection, mut initial)) = ServerConnection::accept(
        peer,
        datagram,
        original_dcid,
        identity.clone(),
        alpn.to_vec(),
        config,
        &state.reset_key,
    ) {
        if connection
            .on_datagram(socket, peer, &mut initial[..])
            .is_ok()
        {
            let connection_id = connection.transport.local_cid.clone();
            let initial_id = connection.transport.initial_dcid.clone();
            if routes.contains_key(&connection_id) || routes.contains_key(&initial_id) {
                return;
            }
            if let Some(stats) = config.stats.as_deref() {
                stats.connections_accepted.fetch_add(1, Ordering::Relaxed);
                stats.connections_active.fetch_add(1, Ordering::Relaxed);
                stats.h3_connections.fetch_add(1, Ordering::Relaxed);
                stats.h3_connections_active.fetch_add(1, Ordering::Relaxed);
            }
            routes.insert(connection_id.clone(), connection_id.clone());
            routes.insert(initial_id, connection_id.clone());
            connections.insert(connection_id, connection);
        }
    }
}

struct CompletedResponse {
    connection_id: Vec<u8>,
    stream_id: u64,
    response: Result<Response<Body>>,
    /// Tail instrumentation: when the request stream was fully received.
    received_at: Instant,
    /// When the handler finished (worker side).
    completed_at: Instant,
}

struct H3ActiveGuard {
    stats: Arc<Stats>,
}

impl Drop for H3ActiveGuard {
    fn drop(&mut self) {
        Stats::decrement(&self.stats.h3_connections_active, 1);
    }
}

/// Slow-request trace threshold in µs. `None` disables tracing. Enabled by
/// `COURIERUST_H3_TRACE_MS` (default 2), optionally combined with
/// `COURIERUST_H3_TRACE` — the per-request phase trace alone does NOT
/// enable the (expensive) per-packet `H3TRACE` stream, so a phase split
/// can be measured without the eprintln overhead distorting timing.
fn h3_trace_threshold_us() -> Option<u64> {
    if std::env::var_os("COURIERUST_H3_TRACE").is_none()
        && std::env::var_os("COURIERUST_H3_TRACE_MS").is_none()
    {
        return None;
    }
    let ms = std::env::var("COURIERUST_H3_TRACE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2);
    Some(ms.saturating_mul(1000))
}

fn h3_open_stream(stats: Option<&Arc<Stats>>, active: &mut BTreeSet<u64>, id: u64) {
    if !active.insert(id) {
        return;
    }
    if let Some(stats) = stats {
        stats.h3_streams_total.fetch_add(1, Ordering::Relaxed);
        let aggregate = stats.h3_streams_active.fetch_add(1, Ordering::Relaxed) + 1;
        Stats::bump_peak(&stats.h3_streams_active_peak, aggregate);
        Stats::bump_peak(&stats.h3_streams_per_connection_peak, active.len());
    }
}

fn h3_close_stream(stats: Option<&Arc<Stats>>, active: &mut BTreeSet<u64>, id: u64) {
    if !active.remove(&id) {
        return;
    }
    if let Some(stats) = stats {
        Stats::decrement(&stats.h3_streams_active, 1);
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        if let Some(stats) = self.stats.as_deref() {
            Stats::decrement(&stats.h3_streams_active, self.active_streams.len());
        }
    }
}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        if let Some(stats) = self.stats.as_deref() {
            Stats::decrement(&stats.h3_streams_active, self.active_streams.len());
        }
    }
}

struct PendingRequest {
    stream_id: u64,
    request: Request<Body>,
    /// Tail instrumentation: when the request stream was fully received.
    received_at: Instant,
}

/// A request queued on a pooled client connection, waiting for the
/// handshake / peer SETTINGS to complete or for a free stream slot.
struct WaitingRequest {
    request: Request<Body>,
    reply: mpsc::Sender<Result<Response<Body>>>,
    deadline: Instant,
}

/// A request that owns a QUIC stream; `wire`/`offset` track the request
/// bytes already handed to the transport (a full congestion window defers
/// the remainder to a later tick). `response` accumulates the decoded
/// response until the stream is finished.
struct ActiveRequest {
    wire: Vec<u8>,
    offset: usize,
    reply: mpsc::Sender<Result<Response<Body>>>,
    response: Option<Response<Body>>,
    deadline: Instant,
    // Tail instrumentation (COURIERUST_H3_TRACE): phase timestamps so a
    // slow request is attributed to send / wait-headers / receive-body
    // instead of surfacing as an opaque P99 spike.
    created: Instant,
    sent_at: Option<Instant>,
    headers_at: Option<Instant>,
    /// True while the body upload is parked on a WouldBlock (flow-control
    /// or congestion-window backpressure), for the credit-blocked/resumed
    /// timeline events.
    credit_blocked: bool,
}

struct ClientConnection {
    transport: QuicTransport,
    tls: QuicClient,
    client_hello: Vec<u8>,
    tls_initial_sent: bool,
    tls_server_hello: bool,
    handshake_complete: bool,
    control_sent: bool,
    authority: String,
    max_header_list: usize,
    peer_max_header_list: usize,
    max_body: usize,
    /// Requests submitted but not yet placed on a QUIC stream (the
    /// handshake or peer SETTINGS has not completed, or the per-connection
    /// stream cap is momentarily full).
    waiting: VecDeque<WaitingRequest>,
    /// Requests with an allocated client-initiated bidirectional stream,
    /// keyed by stream id.
    active: BTreeMap<u64, ActiveRequest>,
    /// Next client-initiated bidirectional stream index (id = 4 * index).
    next_stream_index: u64,
    streams: BTreeMap<u64, ReceiveStream>,
    control_received: bool,
    peer_goaway: Option<u64>,
    /// True once GOAWAY has been sent on the control stream (RFC 9114 §7.2.8).
    goaway_sent: bool,
    /// True once the peer sent CONNECTION_CLOSE (RFC 9000 §10.2): the
    /// close is then normal termination, not a protocol error.
    peer_closed: bool,
    qpack: QpackConnection,
    initial_crypto: CryptoReassembly,
    handshake_crypto: CryptoReassembly,
    initial_tls: Vec<u8>,
    last_activity: Instant,
    stats: Option<Arc<Stats>>,
    active_streams: BTreeSet<u64>,
}

impl ClientConnection {
    fn new(
        transport: QuicTransport,
        tls: QuicClient,
        client_hello: Vec<u8>,
        authority: String,
        limits: H3Limits,
        stats: Option<Arc<Stats>>,
    ) -> Result<Self> {
        if limits.max_header_list == 0 {
            return Err(protocol("HTTP/3 max_header_list must be non-zero"));
        }
        Ok(Self {
            transport,
            tls,
            client_hello,
            tls_initial_sent: false,
            tls_server_hello: false,
            handshake_complete: false,
            control_sent: false,
            authority,
            max_header_list: limits.max_header_list,
            peer_max_header_list: limits.max_header_list,
            max_body: limits.max_body,
            waiting: VecDeque::new(),
            active: BTreeMap::new(),
            next_stream_index: 0,
            streams: BTreeMap::new(),
            control_received: false,
            peer_goaway: None,
            goaway_sent: false,
            peer_closed: false,
            qpack: QpackConnection::new(QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS),
            initial_crypto: CryptoReassembly::default(),
            handshake_crypto: CryptoReassembly::default(),
            initial_tls: Vec::new(),
            last_activity: Instant::now(),
            stats,
            active_streams: BTreeSet::new(),
        })
    }

    /// Flush every space's due ACK in one pass. Called after a receive
    /// batch so a burst coalesces into a single acknowledgement instead
    /// of one per datagram.
    fn flush_acks(&mut self, socket: &UdpSocket) -> Result<()> {
        self.transport.flush_acks(socket)
    }

    fn on_datagram(
        &mut self,
        socket: &UdpSocket,
        source: SocketAddr,
        datagram: &mut [u8],
    ) -> Result<()> {
        self.last_activity = Instant::now();
        // Handshake-stage messages (version negotiation / Retry) are only
        // processed from the validated peer; a packet from a new source is
        // authenticated in the packet loop below and only then may start
        // path validation (RFC 9000 §9.3).
        if source == self.transport.peer.unwrap_or(source)
            || self.transport.pending_peer == Some(source)
        {
            if let Ok(Some(version_negotiation)) = version_negotiation_versions(datagram) {
                if version_negotiation.dcid == self.transport.local_cid {
                    if version_negotiation.scid != self.transport.original_dcid {
                        return Err(protocol(
                            "QUIC Version Negotiation has an unexpected source connection ID",
                        ));
                    }
                    if version_negotiation
                        .versions
                        .contains(&crate::courierust_quic::VERSION_1)
                    {
                        return Err(protocol(
                            "QUIC server sent Version Negotiation for a supported version",
                        ));
                    }
                    return Err(protocol("QUIC server does not support QUIC version 1"));
                }
                return Ok(());
            }
            if let Ok(Some(retry)) = parse_retry_packet(datagram) {
                if retry.dcid != self.transport.local_cid {
                    return Ok(());
                }
                let retry_wire = &datagram[..datagram.len().saturating_sub(16)];
                if !protection::verify_retry_integrity(
                    &self.transport.original_dcid,
                    retry_wire,
                    &retry.tag,
                )
                .map_err(|error| protocol(error.to_string()))?
                {
                    return Ok(());
                }
                if self.tls_server_hello || self.handshake_complete {
                    return Err(protocol("QUIC Retry arrived after handshake progress"));
                }
                if !self.transport.apply_retry(retry.scid, retry.token)? {
                    return Err(protocol("multiple QUIC Retry packets are not permitted"));
                }
                let retry_scid = self.transport.initial_dcid.clone();
                self.tls.set_retry_source_cid(retry_scid);
                self.tls_initial_sent = false;
                return Ok(());
            }
        }
        let mut consumed = 0usize;
        while consumed < datagram.len() {
            let opened = self.transport.open(&mut datagram[consumed..]);
            let (level, _pn, frames, packet_len) = match opened {
                Ok(Some(value)) => value,
                _ => {
                    if self.transport.is_stateless_reset(&datagram[consumed..]) {
                        return Err(protocol("peer sent a stateless reset"));
                    }
                    break;
                }
            };
            if packet_len == 0 || packet_len > datagram.len() - consumed {
                return Err(protocol("QUIC packet decoder made no progress"));
            }
            consumed += packet_len;
            for frame in &frames {
                match frame {
                    QFrame::PathChallenge(token) => {
                        self.transport.handle_path_challenge(socket, *token, source);
                    }
                    QFrame::PathResponse(token) => {
                        self.transport.handle_path_response(token, source);
                    }
                    _ => {}
                }
            }
            if source != self.transport.peer.unwrap_or(source)
                && self.transport.pending_peer != Some(source)
            {
                self.transport.initiate_path_validation(socket, source)?;
            }
            for frame in frames {
                match frame {
                    QFrame::Crypto { offset, data } if level == INITIAL => {
                        let ready = self.initial_crypto.insert(offset, &data)?;
                        if !ready.is_empty() {
                            if self.tls_server_hello {
                                return Err(protocol("unexpected QUIC server Initial CRYPTO"));
                            }
                            self.initial_tls.extend_from_slice(&ready);
                            let Some(message_len) = complete_tls_message(&self.initial_tls)? else {
                                continue;
                            };
                            if message_len != self.initial_tls.len() {
                                return Err(protocol(
                                    "multiple TLS messages in QUIC Initial packet space",
                                ));
                            }
                            self.tls
                                .set_expected_server_cid(self.transport.remote_cid.clone());
                            self.tls.on_initial(&self.initial_tls).map_err(tls_error)?;
                            if let Some(parameters) = self.tls.peer_transport() {
                                self.transport.set_peer_transport(parameters);
                            }
                            self.initial_tls.clear();
                            self.tls_server_hello = true;
                            self.transport.set_handshake_keys(
                                packet_keys_from_flight(self.tls.handshake_read_key())?,
                                packet_keys_from_flight(self.tls.handshake_write_key())?,
                            );
                        }
                    }
                    QFrame::Crypto { offset, data } if level == HANDSHAKE => {
                        let ready = self.handshake_crypto.insert(offset, &data)?;
                        if !ready.is_empty() {
                            if self.handshake_complete {
                                return Err(protocol("unexpected QUIC server Handshake CRYPTO"));
                            }
                            if let Some(flight) =
                                self.tls.on_handshake(&ready).map_err(tls_error)?
                            {
                                self.transport
                                    .send_crypto(socket, HANDSHAKE, &flight.handshake)?;
                                self.transport.set_application_keys(
                                    packet_keys_from_flight(flight.application_read)?,
                                    packet_keys_from_flight(flight.application_write)?,
                                );
                                if let Some(parameters) = self.tls.peer_transport() {
                                    self.transport.set_peer_transport(parameters);
                                }
                                self.handshake_complete = true;
                                self.flush_requests(socket)?;
                            }
                        }
                    }
                    QFrame::Ack { .. } => {}
                    QFrame::Stream {
                        stream_id,
                        offset,
                        data,
                        length,
                        fin,
                    } if level == APPLICATION => {
                        if let Some(wire_len) = length {
                            if wire_len != data.len() as u64 {
                                return Err(protocol("QUIC STREAM length does not match payload"));
                            }
                        }
                        self.receive_stream(stream_id, offset.unwrap_or(0), &data, fin)?;
                    }
                    QFrame::ConnectionClose { .. } => {
                        self.peer_closed = true;
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
        if self.handshake_complete && self.control_received {
            self.flush_requests(socket)?;
        }
        Ok(())
    }

    fn on_tick(&mut self, socket: &UdpSocket) -> Result<()> {
        self.transport.flush_acks(socket)?;
        self.transport
            .check_path_validation_timeout(socket, Instant::now())?;
        self.transport.replenish_connection_window(socket)?;
        self.transport.replenish_stream_windows(socket)?;
        self.transport.replenish_stream_limits(socket)?;
        self.transport.retransmit(socket)?;
        self.transport.maybe_key_update();
        if !self.tls_initial_sent {
            self.transport
                .send_crypto(socket, INITIAL, &self.client_hello)?;
            if self.transport.crypto_send_offsets[INITIAL] >= self.client_hello.len() as u64 {
                self.tls_initial_sent = true;
            }
        }
        if self.handshake_complete {
            self.ensure_control_sent(socket)?;
            self.flush_qpack(socket)?;
            self.flush_requests(socket)?;
            self.flush_qpack(socket)?;
            let resumable: Vec<u64> = self
                .active
                .iter()
                .filter(|(_, request)| request.offset < request.wire.len())
                .map(|(&stream_id, _)| stream_id)
                .collect();
            for stream_id in resumable {
                if let Some(request) = self.active.get_mut(&stream_id) {
                    send_request_chunks(&mut self.transport, socket, stream_id, request)?;
                }
            }
        }
        Ok(())
    }

    /// Queue a request for dispatch once the connection can carry it. The
    /// deadline covers the whole wait: handshake, peer SETTINGS and the
    /// response.
    fn queue_request(
        &mut self,
        request: Request<Body>,
        reply: mpsc::Sender<Result<Response<Body>>>,
        deadline: Instant,
    ) {
        self.waiting.push_back(WaitingRequest {
            request,
            reply,
            deadline,
        });
    }

    /// Send the three unidirectional control streams once. Idempotent
    /// (`control_sent` guards a re-send); a full congestion window defers
    /// to the next tick rather than failing the connection.
    fn ensure_control_sent(&mut self, socket: &UdpSocket) -> Result<()> {
        if self.control_sent {
            return Ok(());
        }
        let settings = h3frame::Frame::Settings(vec![
            (
                h3frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                self.qpack.capacity(),
            ),
            (
                h3frame::SETTINGS_QPACK_BLOCKED_STREAMS,
                self.qpack.blocked_limit(),
            ),
            (
                h3frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                self.max_header_list as u64,
            ),
        ])
        .to_bytes();
        match self
            .transport
            .send_stream(socket, APPLICATION, 2, &control_stream(settings), false)
        {
            Ok(()) => {}
            Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
        match self.transport.send_stream(
            socket,
            APPLICATION,
            CLIENT_QPACK_ENCODER_STREAM,
            &stream_type(H3_QPACK_ENCODER_STREAM),
            false,
        ) {
            Ok(()) => {}
            Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
        match self.transport.send_stream(
            socket,
            APPLICATION,
            CLIENT_QPACK_DECODER_STREAM,
            &stream_type(H3_QPACK_DECODER_STREAM),
            false,
        ) {
            Ok(()) => {}
            Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
        self.control_sent = true;
        self.flush_qpack(socket)
    }
    fn send_goaway(&mut self, socket: &UdpSocket) -> Result<()> {
        if self.goaway_sent || !self.control_sent {
            return Ok(());
        }
        let last = 4u64.saturating_mul(self.next_stream_index.saturating_sub(1));
        let goaway = h3frame::Frame::GoAway(last).to_bytes();
        match self
            .transport
            .send_stream_append(socket, APPLICATION, 2, &goaway)
        {
            Ok(()) => self.goaway_sent = true,
            Err(error) if error.kind == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Send any pending QPACK encoder/decoder stream instructions.
    fn flush_qpack(&mut self, socket: &UdpSocket) -> Result<()> {
        if self.qpack.has_encoder_out() {
            let bytes = self.qpack.take_encoder_out();
            match self.transport.send_stream_append(
                socket,
                APPLICATION,
                CLIENT_QPACK_ENCODER_STREAM,
                &bytes,
            ) {
                Ok(()) => {}
                Err(error) if error.kind == ErrorKind::WouldBlock => {
                    self.qpack.restore_encoder_out(bytes);
                }
                Err(error) => return Err(error),
            }
        }
        if self.qpack.has_decoder_out() {
            let bytes = self.qpack.take_decoder_out();
            match self.transport.send_stream_append(
                socket,
                APPLICATION,
                CLIENT_QPACK_DECODER_STREAM,
                &bytes,
            ) {
                Ok(()) => {}
                Err(error) if error.kind == ErrorKind::WouldBlock => {
                    self.qpack.restore_decoder_out(bytes);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Start every queued request the connection can currently carry:
    /// the handshake and peer SETTINGS are done and a stream slot is
    /// free. Requests larger than the peer's flow-control budget fail
    /// cleanly instead of half-sending a body the peer can never accept.
    fn flush_requests(&mut self, socket: &UdpSocket) -> Result<()> {
        if !self.handshake_complete || !self.control_received {
            if !self.waiting.is_empty() && std::env::var_os("COURIERUST_H3_TRACE").is_some() {
                eprintln!(
                    "H3TRACE|client|flush-deferred: handshake={} control={} waiting={}",
                    self.handshake_complete,
                    self.control_received,
                    self.waiting.len()
                );
            }
            return Ok(());
        }
        self.ensure_control_sent(socket)?;
        if !self.control_sent {
            if std::env::var_os("COURIERUST_H3_TRACE").is_some() && !self.waiting.is_empty() {
                eprintln!(
                    "H3TRACE|client|flush-deferred: control-not-sent waiting={}",
                    self.waiting.len()
                );
            }
            return Ok(());
        }
        while let Some(request) = self.waiting.pop_front() {
            if self.active.len() >= MAX_H3_STREAMS {
                self.waiting.push_front(request);
                break;
            }
            let peer_limit = self.transport.peer_stream_count_limit();
            if self.next_stream_index >= peer_limit {
                let _ = request
                    .reply
                    .send(Err(protocol("HTTP/3 peer stream-count limit exceeded")));
                continue;
            }
            let stream_id = 4 * self.next_stream_index;
            self.next_stream_index = self
                .next_stream_index
                .checked_add(1)
                .ok_or_else(|| protocol("HTTP/3 stream id exhausted"))?;
            if h3_packet_trace() {
                eprintln!("H3TRACE|client|stream-created stream={stream_id}");
            }
            let outbound_limit = self.max_header_list.min(self.peer_max_header_list);
            let wire = match build_request_wire(
                request.request,
                &self.authority,
                &mut self.qpack,
                outbound_limit,
                self.max_body,
            ) {
                Ok(wire) => wire,
                Err(error) => {
                    let _ = request.reply.send(Err(error));
                    continue;
                }
            };
            if wire.len() as u64 > self.transport.peer_stream_send_limit(stream_id) {
                let _ = request
                    .reply
                    .send(Err(protocol("HTTP/3 request exceeds peer stream limit")));
                continue;
            }
            let mut active = ActiveRequest {
                wire,
                offset: 0,
                reply: request.reply,
                response: None,
                deadline: request.deadline,
                created: Instant::now(),
                sent_at: None,
                headers_at: None,
                credit_blocked: false,
            };
            if let Err(error) =
                send_request_chunks(&mut self.transport, socket, stream_id, &mut active)
            {
                if error.kind != ErrorKind::WouldBlock {
                    let _ = active.reply.send(Err(error));
                    continue;
                }
            }
            h3_open_stream(self.stats.as_ref(), &mut self.active_streams, stream_id);
            self.active.insert(stream_id, active);
        }
        Ok(())
    }

    /// Deliver timeout errors to requests whose deadline has passed and
    /// release their streams.
    fn check_timeouts(&mut self, now: Instant) {
        let mut expired: Vec<usize> = Vec::new();
        for (index, request) in self.waiting.iter().enumerate() {
            if request.deadline <= now {
                expired.push(index);
            }
        }
        for index in expired.into_iter().rev() {
            let request = self.waiting.remove(index).expect("index in bounds");
            let _ = request.reply.send(Err(Error::new(ErrorKind::Timeout)));
        }
        let expired: Vec<u64> = self
            .active
            .iter()
            .filter(|(_, request)| request.deadline <= now)
            .map(|(&stream_id, _)| stream_id)
            .collect();
        for stream_id in expired {
            if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                let offset = self
                    .active
                    .get(&stream_id)
                    .map(|request| {
                        (
                            request.offset,
                            request.wire.len(),
                            request.response.is_some(),
                        )
                    })
                    .unwrap_or((0, 0, false));
                eprintln!(
                    "H3CLIENT timeout: waiting={} active={} handshake={} control={} cwnd={} unacked={} stream_limit={} offset={} wire={} response={}",
                    self.waiting.len(),
                    self.active.len(),
                    self.handshake_complete,
                    self.control_received,
                    self.transport.congestion_window,
                    self.transport.unacknowledged_bytes(),
                    self.transport.peer_stream_send_limit(stream_id),
                    offset.0,
                    offset.1,
                    offset.2,
                );
            }
            self.fail_stream(stream_id, Error::new(ErrorKind::Timeout));
        }
    }

    /// Emit a per-request timeline when it exceeded the trace threshold.
    /// Splits total latency into send / wait-headers / receive-body so a
    /// slow path is attributed to a phase, plus the connection state at
    /// completion (cwnd, unacked, queue depths) to distinguish "sender
    /// blocked on ACK" from "peer handling" from "receiver flow control".
    fn trace_request(&self, stream_id: &u64, request: &ActiveRequest, done: Instant) {
        let Some(threshold) = h3_trace_threshold_us() else {
            return;
        };
        let total = done.duration_since(request.created).as_micros() as u64;
        if total < threshold {
            return;
        }
        let send = request
            .sent_at
            .map(|t| t.duration_since(request.created).as_micros() as u64)
            .unwrap_or(0);
        let wait_headers = match (request.sent_at, request.headers_at) {
            (Some(s), Some(h)) => h.duration_since(s).as_micros() as u64,
            (Some(s), None) => done.duration_since(s).as_micros() as u64,
            _ => 0,
        };
        let recv_body = request
            .headers_at
            .map(|h| done.duration_since(h).as_micros() as u64)
            .unwrap_or(0);
        eprintln!(
            "H3TRACE|client|stream={stream_id}|total_us={total}|send_us={send}|wait_headers_us={wait_headers}|recv_body_us={recv_body}|sent={}/{}\n  cwnd={} unacked={} active={} waiting={} peer_max_data={} sent_data={}",
            request.offset,
            request.wire.len(),
            self.transport.congestion_window,
            self.transport.unacknowledged_bytes(),
            self.active.len(),
            self.waiting.len(),
            self.transport.peer_max_data,
            self.transport.sent_data,
        );
    }

    /// Drop one active stream and report `error` to its caller.
    fn fail_stream(&mut self, stream_id: u64, error: Error) {
        if let Some(request) = self.active.remove(&stream_id) {
            let _ = request.reply.send(Err(error));
            h3_close_stream(self.stats.as_ref(), &mut self.active_streams, stream_id);
            self.streams.remove(&stream_id);
        }
    }

    /// Report `error` to every outstanding request and drop the streams.
    /// Called when the connection becomes unusable.
    fn fail_all(&mut self, error: Error) {
        while let Some(request) = self.waiting.pop_front() {
            let _ = request.reply.send(Err(error.clone()));
        }
        let stream_ids: Vec<u64> = self.active.keys().copied().collect();
        for stream_id in stream_ids {
            self.fail_stream(stream_id, error.clone());
        }
    }

    /// Whether any request is outstanding (waiting or on a stream).
    fn has_work(&self) -> bool {
        !self.waiting.is_empty() || !self.active.is_empty()
    }

    /// Whether no request is outstanding (used for idle reaping).
    fn is_idle(&self) -> bool {
        self.waiting.is_empty() && self.active.is_empty()
    }

    /// The earliest request deadline, if any (bounds the driver's poll so
    /// a timeout is delivered on time).
    fn earliest_deadline(&self) -> Option<Instant> {
        self.active
            .values()
            .map(|request| request.deadline)
            .chain(self.waiting.iter().map(|request| request.deadline))
            .min()
    }

    fn receive_stream(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) -> Result<()> {
        self.transport.accept_stream_data(id, offset, data.len())?;
        if stream_id::is_unidirectional(id) {
            if stream_id::is_client_initiated(id) {
                return Err(protocol(
                    "client received a client-initiated unidirectional stream",
                ));
            }
            if stream_id::stream_index(id) >= MAX_H3_UNI_STREAMS as u64 {
                return Err(protocol("HTTP/3 unidirectional stream limit exceeded"));
            }
        } else if !stream_id::is_client_initiated(id) {
            return Err(protocol("server response stream has invalid initiator"));
        }
        if !self.streams.contains_key(&id)
            && self.streams.len() >= MAX_H3_STREAMS + MAX_H3_UNI_STREAMS
        {
            return Err(protocol("HTTP/3 stream state limit exceeded"));
        }
        if !stream_id::is_unidirectional(id) && !self.streams.contains_key(&id) {
            h3_open_stream(self.stats.as_ref(), &mut self.active_streams, id);
        }
        let stream = self.streams.entry(id).or_insert_with(|| ReceiveStream {
            id,
            ..Default::default()
        });
        let ready = stream.reassembly.insert(
            offset,
            data,
            fin,
            self.max_body
                .checked_add(self.max_header_list)
                .ok_or_else(|| protocol("HTTP/3 stream limit overflows usize"))?,
        )?;
        stream.frame_buf.extend_from_slice(&ready);
        if stream_id::is_unidirectional(id) {
            let unblocked = process_unidirectional_stream(
                stream,
                &mut self.control_received,
                &mut self.peer_goaway,
                &mut self.peer_max_header_list,
                &mut self.qpack,
                H3Limits {
                    max_header_list: self.max_header_list,
                    max_body: self.max_body,
                },
            )?
            .unwrap_or_default();
            self.unblock_streams(unblocked)?;
        } else {
            let finished = {
                let Some(request) = self.active.get_mut(&id) else {
                    // A response stream we already completed may receive a
                    // retransmitted final packet after delivery; ignore it
                    // and drop the stub entry re-created above.
                    if id < 4 * self.next_stream_index {
                        self.streams.remove(&id);
                        return Ok(());
                    }
                    return Err(protocol("HTTP/3 response on an unrequested stream"));
                };
                process_client_stream(
                    stream,
                    &mut self.control_received,
                    &mut self.peer_goaway,
                    &mut self.peer_max_header_list,
                    &mut self.qpack,
                    H3Limits {
                        max_header_list: self.max_header_list,
                        max_body: self.max_body,
                    },
                    &mut request.response,
                )?;
                if request.response.is_some() && request.headers_at.is_none() {
                    request.headers_at = Some(Instant::now());
                }
                request.response.is_some()
            };
            if finished {
                let mut request = self
                    .active
                    .remove(&id)
                    .expect("request present while receiving its response");
                self.trace_request(&id, &request, Instant::now());
                let response = request.response.take().expect("response just completed");
                let _ = request.reply.send(Ok(response));
                h3_close_stream(self.stats.as_ref(), &mut self.active_streams, id);
                // Release the receive-side state now that the response is
                // fully consumed; the guard above keeps late retransmits
                // from re-creating it.
                self.streams.remove(&id);
            }
        }
        self.ensure_buffer_budget()
    }

    /// Apply field sections that the QPACK encoder stream just unblocked:
    /// install the headers on the paused response stream and resume
    /// draining its remaining frames (delivering the response when the
    /// stream is complete).
    fn unblock_streams(&mut self, unblocked: Vec<UnblockedSection>) -> Result<()> {
        for (id, fields) in unblocked {
            let mut stream = match self.streams.remove(&id) {
                Some(stream) => stream,
                None => continue, // response stream already released
            };
            if stream.headers.is_some() {
                if stream.trailers.is_some() {
                    return Err(protocol("multiple HTTP/3 response trailer blocks"));
                }
                stream.trailers = Some(response_trailers_from_fields(fields)?);
            } else {
                stream.headers = Some(fields);
            }
            stream.blocked = false;
            let mut finished = false;
            if let Some(request) = self.active.get_mut(&id) {
                process_client_stream(
                    &mut stream,
                    &mut self.control_received,
                    &mut self.peer_goaway,
                    &mut self.peer_max_header_list,
                    &mut self.qpack,
                    H3Limits {
                        max_header_list: self.max_header_list,
                        max_body: self.max_body,
                    },
                    &mut request.response,
                )?;
                finished = request.response.is_some();
            }
            if finished {
                let mut request = self
                    .active
                    .remove(&id)
                    .expect("request present while resuming its response");
                let response = request.response.take().expect("response just completed");
                let _ = request.reply.send(Ok(response));
                h3_close_stream(self.stats.as_ref(), &mut self.active_streams, id);
            } else if !(stream.reassembly.finished() && stream.completed) {
                self.streams.insert(id, stream);
            }
        }
        Ok(())
    }

    fn ensure_buffer_budget(&self) -> Result<()> {
        if self.buffered_bytes() > MAX_H3_CONNECTION_BUFFER {
            return Err(protocol("HTTP/3 connection buffer limit exceeded"));
        }
        Ok(())
    }

    fn buffered_bytes(&self) -> usize {
        let active = self
            .active
            .values()
            .map(|request| request.wire.len().saturating_sub(request.offset))
            .fold(0usize, usize::saturating_add);
        let waiting = self
            .waiting
            .iter()
            .map(|request| request.request.body.len().unwrap_or(0))
            .fold(0usize, usize::saturating_add);
        active
            .saturating_add(waiting)
            .saturating_add(self.streams.values().map(ReceiveStream::buffered_len).sum())
            .saturating_add(self.transport.queued_bytes())
    }
}

/// Write the next chunk of a request body to its QUIC stream. `active.offset`
/// already tracks every chunk written, so a full congestion window defers
/// the remainder to a later tick instead of truncating the request.
fn send_request_chunks(
    transport: &mut QuicTransport,
    socket: &UdpSocket,
    stream_id: u64,
    active: &mut ActiveRequest,
) -> Result<()> {
    while active.offset < active.wire.len() {
        let take = (active.wire.len() - active.offset).min(1000);
        let end = active.offset + take;
        let fin = end == active.wire.len();
        match transport.send_stream_chunk(
            socket,
            APPLICATION,
            stream_id,
            active.offset as u64,
            &active.wire[active.offset..end],
            fin,
        ) {
            Ok(()) => {
                if active.credit_blocked {
                    active.credit_blocked = false;
                    if h3_packet_trace() {
                        eprintln!(
                            "H3TRACE|client|credit-resumed stream={stream_id} offset={}/{}",
                            active.offset,
                            active.wire.len()
                        );
                    }
                }
                active.offset = end
            }
            Err(error) if error.kind == ErrorKind::WouldBlock => {
                // Flow-control / congestion-window backpressure: the body
                // upload is parked here until ACKs or credit free the
                // window — the exact stall a 64 KiB upload tail points at.
                if !active.credit_blocked {
                    active.credit_blocked = true;
                    if h3_packet_trace() {
                        eprintln!(
                            "H3TRACE|client|credit-blocked stream={stream_id} offset={}/{} cwnd={} unacked={}",
                            active.offset,
                            active.wire.len(),
                            transport.congestion_window,
                            transport.unacknowledged_bytes()
                        );
                    }
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
    if active.offset >= active.wire.len() && active.sent_at.is_none() {
        active.sent_at = Some(Instant::now());
    }
    if active.wire.is_empty() {
        transport.send_stream_chunk(socket, APPLICATION, stream_id, 0, &[], true)?;
    }
    Ok(())
}

struct ServerConnection {
    transport: QuicTransport,
    tls: QuicServer,
    tls_ready: bool,
    handshake_complete: bool,
    control_sent: bool,
    local_settings_received: bool,
    max_header_list: usize,
    peer_max_header_list: usize,
    max_body: usize,
    idle_timeout: Duration,
    handshake_deadline: Instant,
    last_activity: Instant,
    streams: BTreeMap<u64, ReceiveStream>,
    /// Recently completed request-stream ids, so a late retransmission is
    /// dropped instead of re-creating receive state (see
    /// `MAX_COMPLETED_STREAMS`).
    completed_streams: VecDeque<u64>,
    pending_requests: VecDeque<PendingRequest>,
    qpack: QpackConnection,
    peer_transport: Option<TransportParameters>,
    initial_crypto: CryptoReassembly,
    handshake_crypto: CryptoReassembly,
    initial_tls: Vec<u8>,
    handshake_tls: Vec<u8>,
    pending_initial: Vec<u8>,
    pending_handshake: Vec<u8>,
    peer_goaway: Option<u64>,
    /// Highest client-initiated request stream id accepted; the GOAWAY
    /// value we advertise so peers know which requests were processed.
    max_request_stream_id: u64,
    /// True once GOAWAY has been sent on the control stream (RFC 9114 §7.2.8).
    goaway_sent: bool,
    /// True once the peer sent CONNECTION_CLOSE (RFC 9000 §10.2): the
    /// close is then normal termination, not a protocol error.
    peer_closed: bool,
    stats: Option<Arc<Stats>>,
    active_streams: BTreeSet<u64>,
}

impl ServerConnection {
    fn accept(
        peer: SocketAddr,
        initial: &[u8],
        original_dcid: Option<&[u8]>,
        identity: crate::courierust_tls::Identity,
        alpn: Vec<Vec<u8>>,
        config: &ServerConfig,
        reset_key: &[u8; 32],
    ) -> Result<(Self, Vec<u8>)> {
        let meta = PacketMeta::parse(initial, 8)?;
        if meta.long_type != Some(LongType::Initial) || meta.dcid.is_empty() || meta.scid.is_empty()
        {
            return Err(protocol("invalid QUIC client Initial header"));
        }
        let local_cid = random_cid()?;
        let initial_dcid = meta.dcid.clone();
        let client_cid = meta.scid.clone();
        let mut local_tp = transport_parameters_for_limits(config.max_header_list, config.max_body);
        let reset_token = stateless_reset_token(reset_key, &local_cid);
        local_tp.stateless_reset_token = Some(reset_token);
        match original_dcid {
            Some(odcid) => {
                local_tp.original_destination_connection_id = Some(odcid.to_vec());
                local_tp.retry_source_connection_id = Some(meta.dcid.clone());
            }
            None => {
                local_tp.original_destination_connection_id = Some(meta.dcid.clone());
            }
        }
        let tls = QuicServer::new(identity, alpn, local_tp.clone(), local_cid.clone());
        let mut transport =
            QuicTransport::server(local_cid, client_cid, initial_dcid, config.stats.clone())?;
        transport.set_local_transport(&local_tp);
        transport.stateless_reset_token = Some(reset_token);
        transport.peer = Some(peer);
        let connection = Self {
            transport,
            tls,
            tls_ready: false,
            handshake_complete: false,
            control_sent: false,
            local_settings_received: false,
            max_header_list: config.max_header_list,
            peer_max_header_list: config.max_header_list,
            max_body: config.max_body,
            idle_timeout: config.idle_timeout.unwrap_or(Duration::from_secs(300)),
            handshake_deadline: Instant::now()
                .checked_add(config.handshake_timeout.unwrap_or(Duration::from_secs(10)))
                .unwrap_or_else(Instant::now),
            last_activity: Instant::now(),
            streams: BTreeMap::new(),
            completed_streams: VecDeque::new(),
            pending_requests: VecDeque::new(),
            qpack: QpackConnection::new(QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS),
            peer_transport: None,
            initial_crypto: CryptoReassembly::default(),
            handshake_crypto: CryptoReassembly::default(),
            initial_tls: Vec::new(),
            handshake_tls: Vec::new(),
            pending_initial: Vec::new(),
            pending_handshake: Vec::new(),
            peer_goaway: None,
            max_request_stream_id: 0,
            goaway_sent: false,
            peer_closed: false,
            stats: config.stats.clone(),
            active_streams: BTreeSet::new(),
        };
        Ok((connection, initial.to_vec()))
    }

    fn on_datagram(
        &mut self,
        socket: &UdpSocket,
        source: SocketAddr,
        datagram: &mut [u8],
    ) -> Result<()> {
        self.last_activity = Instant::now();
        let mut consumed = 0usize;
        while consumed < datagram.len() {
            let opened = self.transport.open(&mut datagram[consumed..]);
            let Some((level, _pn, frames, packet_len)) = (match opened {
                Ok(value) => value,
                Err(error) => {
                    // RFC 9000 §10.3: a peer stateless reset is detected
                    // by the token in the final 16 bytes of a packet that
                    // fails to decrypt.
                    if self.transport.is_stateless_reset(&datagram[consumed..]) {
                        return Err(protocol("peer sent a stateless reset"));
                    }
                    return Err(error);
                }
            }) else {
                break;
            };
            if packet_len == 0 || packet_len > datagram.len() - consumed {
                return Err(protocol("QUIC packet decoder made no progress"));
            }
            consumed += packet_len;
            for frame in &frames {
                match frame {
                    QFrame::PathChallenge(token) => {
                        self.transport.handle_path_challenge(socket, *token, source);
                    }
                    QFrame::PathResponse(token) => {
                        self.transport.handle_path_response(token, source);
                    }
                    _ => {}
                }
            }
            if source != self.transport.peer.unwrap_or(source)
                && self.transport.pending_peer != Some(source)
            {
                self.transport.initiate_path_validation(socket, source)?;
            }
            for frame in frames {
                match frame {
                    QFrame::Crypto { offset, data } if level == INITIAL => {
                        let ready = self.initial_crypto.insert(offset, &data)?;
                        if !ready.is_empty() {
                            if self.tls_ready {
                                return Err(protocol("unexpected QUIC client Initial CRYPTO"));
                            }
                            self.initial_tls.extend_from_slice(&ready);
                            let Some(message_len) = complete_tls_message(&self.initial_tls)? else {
                                continue;
                            };
                            if message_len != self.initial_tls.len() {
                                return Err(protocol(
                                    "multiple TLS messages in QUIC Initial packet space",
                                ));
                            }
                            let flight = self
                                .tls
                                .on_client_hello(&self.initial_tls)
                                .map_err(tls_error)?;
                            self.initial_tls.clear();
                            self.peer_transport.clone_from(&flight.peer_transport);
                            if let Some(parameters) = self.peer_transport.as_ref() {
                                self.transport.set_peer_transport(parameters);
                            }
                            self.transport.set_handshake_keys(
                                packet_keys_from_flight(flight.handshake_read)?,
                                packet_keys_from_flight(flight.handshake_write)?,
                            );
                            self.transport.set_application_keys(
                                packet_keys_from_flight(flight.application_read)?,
                                packet_keys_from_flight(flight.application_write)?,
                            );
                            // Keep the TLS flight for incremental delivery:
                            // a flight larger than the congestion window is
                            // sent in pieces on successive ticks instead of
                            // failing the handshake (see
                            // `flush_pending_crypto`).
                            self.pending_initial = flight.initial;
                            self.pending_handshake = flight.handshake;
                            self.tls_ready = true;
                            self.flush_pending_crypto(socket)?;
                        }
                    }
                    QFrame::Crypto { offset, data } if level == HANDSHAKE => {
                        let ready = self.handshake_crypto.insert(offset, &data)?;
                        if !ready.is_empty() {
                            if !self.tls_ready || self.handshake_complete {
                                return Err(protocol("unexpected QUIC client Handshake CRYPTO"));
                            }
                            self.handshake_tls.extend_from_slice(&ready);
                            let Some(message_len) = complete_tls_message(&self.handshake_tls)?
                            else {
                                continue;
                            };
                            if message_len != self.handshake_tls.len() {
                                return Err(protocol(
                                    "multiple TLS messages in QUIC Handshake packet space",
                                ));
                            }
                            let flight = self
                                .tls
                                .on_client_finished(&self.handshake_tls)
                                .map_err(tls_error)?;
                            self.handshake_tls.clear();
                            self.transport.set_application_keys(
                                packet_keys_from_flight(flight.application_read)?,
                                packet_keys_from_flight(flight.application_write)?,
                            );
                            self.handshake_complete = true;
                            if h3_packet_trace() {
                                eprintln!("H3TRACE|client|handshake-complete");
                            }
                            self.send_control(socket)?;
                        }
                    }
                    QFrame::Stream {
                        stream_id,
                        offset,
                        data,
                        length,
                        fin,
                    } if level == APPLICATION => {
                        if let Some(wire_len) = length {
                            if wire_len != data.len() as u64 {
                                return Err(protocol("QUIC STREAM length does not match payload"));
                            }
                        }
                        if !self.handshake_complete {
                            return Err(protocol("HTTP/3 stream before TLS handshake completion"));
                        }
                        self.receive_stream(stream_id, offset.unwrap_or(0), &data, fin)?;
                    }
                    QFrame::ConnectionClose { .. } => {
                        self.peer_closed = true;
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn on_tick(&mut self, socket: &UdpSocket) -> Result<()> {
        self.flush_pending_crypto(socket)?;
        if self.handshake_complete && !self.control_sent {
            self.send_control(socket)?;
        }
        self.flush_qpack(socket)?;
        self.transport.flush_acks(socket)?;
        self.transport
            .check_path_validation_timeout(socket, Instant::now())?;
        self.transport.replenish_connection_window(socket)?;
        self.transport.replenish_stream_windows(socket)?;
        // Stream-count limits too (RFC 9000 §4.6): a long-lived connection
        // must not stop at the initial MAX_STREAMS.
        self.transport.replenish_stream_limits(socket)?;
        self.transport.retransmit(socket)?;
        self.transport.maybe_key_update();
        Ok(())
    }

    /// Deliver the TLS flight incrementally. `send_crypto` resumes from
    /// the last CRYPTO offset written, so this is safe to call on every
    /// tick and becomes a no-op once both flights are fully delivered.
    fn flush_pending_crypto(&mut self, socket: &UdpSocket) -> Result<()> {
        if !self.pending_initial.is_empty() {
            self.transport
                .send_crypto(socket, INITIAL, &self.pending_initial)?;
            if self.transport.crypto_send_offsets[INITIAL] < self.pending_initial.len() as u64 {
                return Ok(());
            }
        }
        if !self.pending_handshake.is_empty() {
            self.transport
                .send_crypto(socket, HANDSHAKE, &self.pending_handshake)?;
        }
        Ok(())
    }

    fn send_control(&mut self, socket: &UdpSocket) -> Result<()> {
        if self.control_sent {
            return Ok(());
        }
        let settings = h3frame::Frame::Settings(vec![
            (
                h3frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                self.qpack.capacity(),
            ),
            (
                h3frame::SETTINGS_QPACK_BLOCKED_STREAMS,
                self.qpack.blocked_limit(),
            ),
            (
                h3frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                self.max_header_list as u64,
            ),
        ])
        .to_bytes();
        match self
            .transport
            .send_stream(socket, APPLICATION, 3, &control_stream(settings), false)
        {
            Ok(()) => {}
            Err(error) if error.kind == ErrorKind::WouldBlock => {
                // The peer has not ACKed enough in-flight handshake data
                // to admit the control stream; on_tick retries. Trace it
                // because a connection parked here holds the client's
                // requests hostage until the SETTINGS gets out.
                if std::env::var_os("COURIERUST_H3_TRACE").is_some() {
                    eprintln!(
                        "H3TRACE|server|control-deferred: cwnd={} unacked={}",
                        self.transport.congestion_window,
                        self.transport.unacknowledged_bytes()
                    );
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        match self.transport.send_stream(
            socket,
            APPLICATION,
            SERVER_QPACK_ENCODER_STREAM,
            &stream_type(H3_QPACK_ENCODER_STREAM),
            false,
        ) {
            Ok(()) => {}
            Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
        match self.transport.send_stream(
            socket,
            APPLICATION,
            SERVER_QPACK_DECODER_STREAM,
            &stream_type(H3_QPACK_DECODER_STREAM),
            false,
        ) {
            Ok(()) => {}
            Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
        self.control_sent = true;
        self.flush_qpack(socket)
    }

    /// Send a GOAWAY frame on the control stream before closing so the
    /// peer learns which request streams were processed (RFC 9114 §7.2.8).
    fn send_goaway(&mut self, socket: &UdpSocket) -> Result<()> {
        if self.goaway_sent || !self.control_sent {
            return Ok(());
        }
        let goaway = h3frame::Frame::GoAway(self.max_request_stream_id).to_bytes();
        match self
            .transport
            .send_stream_append(socket, APPLICATION, 3, &goaway)
        {
            Ok(()) => self.goaway_sent = true,
            Err(error) if error.kind == ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Send any pending QPACK encoder/decoder stream instructions.
    fn flush_qpack(&mut self, socket: &UdpSocket) -> Result<()> {
        if self.qpack.has_encoder_out() {
            let bytes = self.qpack.take_encoder_out();
            match self.transport.send_stream_append(
                socket,
                APPLICATION,
                SERVER_QPACK_ENCODER_STREAM,
                &bytes,
            ) {
                Ok(()) => {}
                Err(error) if error.kind == ErrorKind::WouldBlock => {
                    self.qpack.restore_encoder_out(bytes);
                }
                Err(error) => return Err(error),
            }
        }
        if self.qpack.has_decoder_out() {
            let bytes = self.qpack.take_decoder_out();
            match self.transport.send_stream_append(
                socket,
                APPLICATION,
                SERVER_QPACK_DECODER_STREAM,
                &bytes,
            ) {
                Ok(()) => {}
                Err(error) if error.kind == ErrorKind::WouldBlock => {
                    self.qpack.restore_decoder_out(bytes);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn receive_stream(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) -> Result<()> {
        self.transport.accept_stream_data(id, offset, data.len())?;
        if stream_id::is_unidirectional(id) {
            if !stream_id::is_client_initiated(id) {
                return Err(protocol(
                    "server received a server-initiated unidirectional stream",
                ));
            }
            if stream_id::stream_index(id) >= MAX_H3_UNI_STREAMS as u64 {
                return Err(protocol(format!(
                    "HTTP/3 unidirectional stream limit exceeded (id={id}, index={})",
                    stream_id::stream_index(id)
                )));
            }
        } else if !stream_id::is_client_initiated(id) {
            return Err(protocol("request stream has invalid initiator"));
        }
        if !stream_id::is_unidirectional(id)
            && !self.streams.contains_key(&id)
            && self.completed_streams.contains(&id)
        {
            return Ok(());
        }
        if !self.streams.contains_key(&id)
            && self.streams.len() >= MAX_H3_STREAMS + MAX_H3_UNI_STREAMS
        {
            return Err(protocol("HTTP/3 stream state limit exceeded"));
        }
        if !stream_id::is_unidirectional(id) && !self.streams.contains_key(&id) {
            h3_open_stream(self.stats.as_ref(), &mut self.active_streams, id);
        }
        if !stream_id::is_unidirectional(id) {
            self.max_request_stream_id = self.max_request_stream_id.max(id);
        }
        let (unblocked, remove_stream) = {
            let stream = self.streams.entry(id).or_insert_with(|| ReceiveStream {
                id,
                ..Default::default()
            });
            let max = self.max_body.saturating_add(self.max_header_list);
            let ready = stream.reassembly.insert(offset, data, fin, max)?;
            stream.frame_buf.extend_from_slice(&ready);
            let unblocked = process_server_stream(
                stream,
                &mut self.local_settings_received,
                &mut self.peer_goaway,
                &mut self.peer_max_header_list,
                &mut self.qpack,
                H3Limits {
                    max_header_list: self.max_header_list,
                    max_body: self.max_body,
                },
                &mut self.pending_requests,
            )?;
            let remove_stream = stream.reassembly.finished() && stream.completed;
            (unblocked, remove_stream)
        };
        self.unblock_streams(unblocked)?;
        if remove_stream {
            self.streams.remove(&id);
            self.note_completed_stream(id);
        }
        self.ensure_buffer_budget()
    }

    /// Apply field sections that the QPACK encoder stream just unblocked:
    /// install the request headers on the paused stream and resume
    /// draining its remaining frames (enqueueing the request when the
    /// stream is complete).
    fn unblock_streams(&mut self, unblocked: Vec<UnblockedSection>) -> Result<()> {
        for (id, fields) in unblocked {
            let mut stream = match self.streams.remove(&id) {
                Some(stream) => stream,
                None => continue, // request stream already released
            };
            stream.headers = Some(fields);
            stream.blocked = false;
            process_server_stream(
                &mut stream,
                &mut self.local_settings_received,
                &mut self.peer_goaway,
                &mut self.peer_max_header_list,
                &mut self.qpack,
                H3Limits {
                    max_header_list: self.max_header_list,
                    max_body: self.max_body,
                },
                &mut self.pending_requests,
            )?;
            if stream.reassembly.finished() && stream.completed {
                self.note_completed_stream(id);
            } else {
                self.streams.insert(id, stream);
            }
        }
        Ok(())
    }

    /// Remember a completed request stream so a late retransmission is
    /// dropped without re-creating its receive state.
    fn note_completed_stream(&mut self, id: u64) {
        if self.completed_streams.len() >= MAX_COMPLETED_STREAMS {
            self.completed_streams.pop_front();
        }
        self.completed_streams.push_back(id);
    }

    fn take_request(&mut self) -> Option<PendingRequest> {
        self.pending_requests.pop_front()
    }

    fn push_request_front(&mut self, request: PendingRequest) {
        self.pending_requests.push_front(request);
    }

    /// Emit the worker→reactor handoff time when it exceeded the trace
    /// threshold: received → handler done → queued. This isolates the
    /// handoff that otherwise shows up as client-side wait_headers
    /// latency.
    fn trace_response(&self, completed: &CompletedResponse) {
        let Some(threshold) = h3_trace_threshold_us() else {
            return;
        };
        let now = Instant::now();
        let total = now.duration_since(completed.received_at).as_micros() as u64;
        if total < threshold {
            return;
        }
        let handler = completed
            .completed_at
            .duration_since(completed.received_at)
            .as_micros() as u64;
        let queue = now.duration_since(completed.completed_at).as_micros() as u64;
        eprintln!(
            "H3TRACE|server|stream={}|total_us={total}|handler_us={handler}|queue_us={queue}|pending={}|handshake={}",
            completed.stream_id,
            self.pending_requests.len(),
            self.handshake_complete,
        );
    }

    fn queue_response(&mut self, stream_id: u64, result: Result<Response<Body>>) {
        h3_close_stream(self.stats.as_ref(), &mut self.active_streams, stream_id);
        let response = match result {
            Ok(response) => response,
            Err(_) => {
                self.queue_service_unavailable(stream_id);
                return;
            }
        };
        let outbound_limit = self.max_header_list.min(self.peer_max_header_list);
        if let Ok(wire) =
            build_response_wire(response, &mut self.qpack, outbound_limit, self.max_body)
        {
            let _ = self.transport.queue_stream_wire(stream_id, wire);
        } else {
            self.queue_service_unavailable(stream_id);
        }
    }

    fn queue_service_unavailable(&mut self, stream_id: u64) {
        h3_close_stream(self.stats.as_ref(), &mut self.active_streams, stream_id);
        let response = Response::<Body>::with_status(StatusCode::SERVICE_UNAVAILABLE).header(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("0"),
        );
        let outbound_limit = self.max_header_list.min(self.peer_max_header_list);
        if let Ok(wire) =
            build_response_wire(response, &mut self.qpack, outbound_limit, self.max_body)
        {
            let _ = self.transport.queue_stream_wire(stream_id, wire);
        }
    }

    fn ensure_buffer_budget(&self) -> Result<()> {
        if self.buffered_bytes() > MAX_H3_CONNECTION_BUFFER {
            return Err(protocol("HTTP/3 connection buffer limit exceeded"));
        }
        Ok(())
    }

    fn buffered_bytes(&self) -> usize {
        let pending = self
            .pending_requests
            .iter()
            .map(|request| request.request.body.len().unwrap_or(self.max_body))
            .fold(0usize, usize::saturating_add);
        self.streams
            .values()
            .map(ReceiveStream::buffered_len)
            .fold(0usize, usize::saturating_add)
            .saturating_add(pending)
            .saturating_add(self.transport.queued_bytes())
    }
}

fn materialize_response(response: Response<Body>, max_body: usize) -> Result<Response<Body>> {
    let Response {
        status,
        version,
        headers,
        body,
        trailers,
    } = response;
    let bytes = body
        .collect_limited(max_body)
        .map_err(|error| match error.kind {
            ErrorKind::Overflow => protocol("response body exceeds configured HTTP/3 limit"),
            _ => error,
        })?;
    Ok(Response {
        status,
        version,
        headers,
        body: Body::from(bytes),
        trailers,
    })
}

#[derive(Default)]
struct ReceiveStream {
    id: u64,
    reassembly: StreamReassembly,
    frame_buf: Vec<u8>,
    headers: Option<Vec<FieldLine>>,
    trailers: Option<HeaderMap>,
    body: Vec<u8>,
    completed: bool,
    stream_type: Option<u64>,
    control_started: bool,
    /// True while a HEADERS frame waits for the QPACK encoder stream
    /// (Required Insert Count not yet met). The stream's remaining frames
    /// stay buffered and are drained once the section is decoded.
    blocked: bool,
}

#[derive(Default)]
struct StreamReassembly {
    next: u64,
    chunks: BTreeMap<u64, Vec<u8>>,
    final_size: Option<u64>,
    delivered: Vec<u8>,
}

impl StreamReassembly {
    fn insert(&mut self, offset: u64, data: &[u8], fin: bool, max: usize) -> Result<Vec<u8>> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| protocol("QUIC stream offset overflow"))?;
        let max_u64 = u64::try_from(max).map_err(|_| protocol("stream limit does not fit u64"))?;
        if end > max_u64 || offset > max_u64 {
            return Err(protocol("QUIC stream flow-control limit exceeded"));
        }
        if fin {
            if let Some(previous) = self.final_size {
                if previous != end {
                    return Err(protocol("inconsistent QUIC final stream size"));
                }
            }
            self.final_size = Some(end);
        } else if let Some(final_size) = self.final_size {
            if end > final_size {
                return Err(protocol("QUIC data exceeds final stream size"));
            }
        }
        if offset < self.next {
            let overlap = (self.next - offset).min(data.len() as u64);
            let overlap_len = usize::try_from(overlap)
                .map_err(|_| protocol("QUIC stream overlap does not fit usize"))?;
            let history_start = usize::try_from(offset)
                .map_err(|_| protocol("QUIC stream history offset does not fit usize"))?;
            let history_end = history_start
                .checked_add(overlap_len)
                .ok_or_else(|| protocol("QUIC stream history offset overflow"))?;
            if history_end > self.delivered.len()
                || self.delivered[history_start..history_end] != data[..overlap_len]
            {
                return Err(protocol("overlapping QUIC stream data is not identical"));
            }
            if end <= self.next {
                return self.take_ready();
            }
            let skip = overlap_len;
            let data = &data[skip..];
            return self.insert(self.next, data, fin, max);
        }
        if self.chunks.len() >= MAX_STREAM_CHUNKS && !self.chunks.contains_key(&offset) {
            return Err(protocol("too many out-of-order QUIC stream chunks"));
        }
        if let Some(previous) = self.chunks.get(&offset) {
            if previous.as_slice() != data {
                return Err(protocol("conflicting QUIC stream retransmission"));
            }
        } else {
            if let Some((&start, previous)) = self.chunks.range(..=offset).next_back() {
                let previous_end = start.saturating_add(previous.len() as u64);
                if previous_end > offset {
                    return Err(protocol("overlapping QUIC stream ranges"));
                }
            }
            if let Some((&start, _)) = self.chunks.range(offset..).next() {
                if end > start {
                    return Err(protocol("overlapping QUIC stream ranges"));
                }
            }
            self.chunks.insert(offset, data.to_vec());
        }
        self.take_ready()
    }

    fn take_ready(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunks.remove(&self.next) {
            self.next = self
                .next
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| protocol("QUIC stream offset overflow"))?;
            self.delivered.extend_from_slice(&chunk);
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    fn finished(&self) -> bool {
        self.final_size == Some(self.next)
    }

    fn buffered_len(&self) -> usize {
        self.chunks
            .values()
            .map(Vec::len)
            .fold(0usize, usize::saturating_add)
            .saturating_add(self.delivered.len())
    }
}

#[derive(Default)]
struct CryptoReassembly {
    next: u64,
    chunks: BTreeMap<u64, Vec<u8>>,
}

impl CryptoReassembly {
    fn insert(&mut self, offset: u64, data: &[u8]) -> Result<Vec<u8>> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| protocol("QUIC CRYPTO offset overflow"))?;
        if end > MAX_CRYPTO_BUFFER as u64 {
            return Err(protocol("QUIC CRYPTO stream limit exceeded"));
        }
        if end <= self.next {
            return Ok(Vec::new());
        }
        let (offset, data) = if offset < self.next {
            let skip = usize::try_from(self.next - offset)
                .map_err(|_| protocol("QUIC CRYPTO overlap does not fit usize"))?;
            (self.next, &data[skip..])
        } else {
            (offset, data)
        };
        if let Some(previous) = self.chunks.get(&offset) {
            if previous.as_slice() != data {
                return Err(protocol("conflicting QUIC CRYPTO retransmission"));
            }
            return self.take_ready();
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| protocol("QUIC CRYPTO offset overflow"))?;
        if let Some((&start, previous)) = self.chunks.range(..=offset).next_back() {
            let previous_end = start
                .checked_add(previous.len() as u64)
                .ok_or_else(|| protocol("QUIC CRYPTO range overflow"))?;
            if previous_end > offset {
                return Err(protocol("overlapping QUIC CRYPTO ranges"));
            }
        }
        if let Some((&start, _)) = self.chunks.range(offset..).next() {
            if end > start {
                return Err(protocol("overlapping QUIC CRYPTO ranges"));
            }
        }
        if self.chunks.len() >= MAX_STREAM_CHUNKS {
            return Err(protocol("too many out-of-order QUIC CRYPTO chunks"));
        }
        self.chunks.insert(offset, data.to_vec());
        self.take_ready()
    }

    fn take_ready(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunks.remove(&self.next) {
            self.next = self
                .next
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| protocol("QUIC CRYPTO offset overflow"))?;
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

fn complete_tls_message(buf: &[u8]) -> Result<Option<usize>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let body_len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    let total = 4usize
        .checked_add(body_len)
        .ok_or_else(|| protocol("TLS handshake message length overflow"))?;
    if total > MAX_CRYPTO_BUFFER {
        return Err(protocol("TLS handshake message exceeds limit"));
    }
    Ok((buf.len() >= total).then_some(total))
}

impl ReceiveStream {
    fn buffered_len(&self) -> usize {
        let fields = self.headers.as_ref().map_or(0, |fields| {
            fields.iter().fold(0usize, |total, field| {
                total
                    .saturating_add(field.name.len())
                    .saturating_add(field.value.len())
            })
        });
        let trailers = self.trailers.as_ref().map_or(0, |headers| {
            headers.iter().fold(0usize, |total, (name, value)| {
                total
                    .saturating_add(name.as_str().len())
                    .saturating_add(value.as_bytes().len())
            })
        });
        self.reassembly
            .buffered_len()
            .saturating_add(self.frame_buf.len())
            .saturating_add(self.body.len())
            .saturating_add(fields)
            .saturating_add(trailers)
    }
}

/// Process a unidirectional stream (control / QPACK encoder / QPACK
/// decoder). Returns `Ok(None)` when the stream is a bidirectional
/// request/response stream that still needs draining; `Ok(Some(...))`
/// when the stream was consumed, carrying any field sections that were
/// blocked and are now decodable (their request/response streams must be
/// resumed by the caller).
fn process_unidirectional_stream(
    stream: &mut ReceiveStream,
    control_received: &mut bool,
    peer_goaway: &mut Option<u64>,
    peer_max_header_list: &mut usize,
    qpack: &mut QpackConnection,
    limits: H3Limits,
) -> Result<Option<Vec<UnblockedSection>>> {
    if stream.stream_type.is_none() && stream_id::is_unidirectional(stream_id_of(stream)) {
        let (kind, used) = match varint::decode(&stream.frame_buf) {
            Ok(v) => v,
            Err(error) if error.kind == ErrorKind::UnexpectedEof => {
                if stream.reassembly.finished() {
                    return Err(protocol(
                        "HTTP/3 unidirectional stream ended before its type",
                    ));
                }
                return Ok(Some(Vec::new()));
            }
            Err(error) => return Err(error),
        };
        stream.frame_buf.drain(..used);
        stream.stream_type = Some(kind);
        // RFC 9114 §6.2.3: unknown stream types — including the reserved
        // 0x1f * N + 0x21 grease types, which compliant peers (e.g. the
        // h3 crate) MAY open at any time — MUST be ignored, not rejected.
        // We record the type so the `_` match arm below drains the stream.
    }
    let Some(kind) = stream.stream_type else {
        return Ok(None);
    };
    match kind {
        H3_CONTROL_STREAM => {
            let mut pos = 0;
            while let Some(frame) = h3frame::Frame::decode(&stream.frame_buf, &mut pos)? {
                if !stream.control_started {
                    let h3frame::Frame::Settings(settings) = frame else {
                        return Err(protocol("HTTP/3 SETTINGS must be the first control frame"));
                    };
                    if *control_received {
                        return Err(protocol("duplicate HTTP/3 SETTINGS"));
                    }
                    let peer_capacity =
                        validate_settings(&settings, limits.max_header_list, peer_max_header_list)?;
                    // Enable the encoder table (emits the Set Capacity
                    // instruction on the encoder stream) now that the
                    // peer's limit is known.
                    qpack.set_peer_capacity(peer_capacity);
                    stream.control_started = true;
                    *control_received = true;
                } else {
                    match frame {
                        h3frame::Frame::Settings(_) => {
                            return Err(protocol("duplicate HTTP/3 SETTINGS"));
                        }
                        h3frame::Frame::GoAway(id) => {
                            validate_goaway_id(id, *peer_goaway)?;
                            *peer_goaway =
                                Some(peer_goaway.map_or(id, |previous| previous.min(id)));
                        }
                        h3frame::Frame::Unknown { .. } => {}
                        _ => return Err(protocol("invalid frame on HTTP/3 control stream")),
                    }
                }
            }
            if pos != 0 {
                stream.frame_buf.drain(..pos);
            }
            if stream.reassembly.finished() {
                return Err(protocol("HTTP/3 control stream cannot be closed"));
            }
            Ok(Some(Vec::new()))
        }
        H3_QPACK_ENCODER_STREAM => {
            // Apply the peer's encoder-stream instructions (Set Capacity,
            // inserts, duplicates) and retry any field sections that were
            // waiting on the entries they define.
            if stream.frame_buf.len() > limits.max_header_list {
                return Err(protocol("QPACK encoder stream exceeds limit"));
            }
            let consumed = qpack.on_encoder_stream(&stream.frame_buf)?;
            stream.frame_buf.drain(..consumed);
            if stream.reassembly.finished() {
                return Err(protocol("HTTP/3 QPACK encoder stream cannot be closed"));
            }
            let unblocked = qpack.retry_blocked(limits.max_header_list)?;
            Ok(Some(unblocked))
        }
        H3_QPACK_DECODER_STREAM => {
            // Apply the peer's decoder-stream instructions: Insert Count
            // Increment raises our encoder-side Known Received Count.
            let consumed = qpack.on_decoder_stream(&stream.frame_buf)?;
            stream.frame_buf.drain(..consumed);
            if stream.reassembly.finished() {
                return Err(protocol("HTTP/3 QPACK decoder stream cannot be closed"));
            }
            Ok(Some(Vec::new()))
        }
        _ => {
            process_unknown_unidirectional_stream(stream)?;
            Ok(Some(Vec::new()))
        }
    }
}

/// Ignore an unknown HTTP/3 unidirectional stream type.
///
/// RFC 9114 §6.2.3: unknown stream types — including the reserved
/// `0x1f * N + 0x21` grease types that compliant peers (e.g. the `h3`
/// crate) MAY open at any time — MUST be ignored, not rejected. Drain and
/// discard any buffered bytes; the stream may legally stay open and send
/// more padding later, so each arrival simply clears the buffer again.
fn process_unknown_unidirectional_stream(stream: &mut ReceiveStream) -> Result<bool> {
    stream.frame_buf.clear();
    Ok(true)
}

fn process_server_stream(
    stream: &mut ReceiveStream,
    control_received: &mut bool,
    peer_goaway: &mut Option<u64>,
    peer_max_header_list: &mut usize,
    qpack: &mut QpackConnection,
    limits: H3Limits,
    requests: &mut VecDeque<PendingRequest>,
) -> Result<Vec<UnblockedSection>> {
    if let Some(unblocked) = process_unidirectional_stream(
        stream,
        control_received,
        peer_goaway,
        peer_max_header_list,
        qpack,
        limits,
    )? {
        return Ok(unblocked);
    }
    if stream.blocked {
        return Ok(Vec::new());
    }
    drain_request_frames(
        stream,
        control_received,
        peer_goaway,
        qpack,
        limits.max_header_list,
        limits.max_body,
        requests,
    )?;
    Ok(Vec::new())
}

fn process_client_stream(
    stream: &mut ReceiveStream,
    control_received: &mut bool,
    peer_goaway: &mut Option<u64>,
    peer_max_header_list: &mut usize,
    qpack: &mut QpackConnection,
    limits: H3Limits,
    response: &mut Option<Response<Body>>,
) -> Result<Vec<UnblockedSection>> {
    if let Some(unblocked) = process_unidirectional_stream(
        stream,
        control_received,
        peer_goaway,
        peer_max_header_list,
        qpack,
        limits,
    )? {
        return Ok(unblocked);
    }
    if stream.blocked {
        return Ok(Vec::new());
    }
    drain_response_frames(
        stream,
        control_received,
        qpack,
        limits.max_header_list,
        limits.max_body,
        response,
    )?;
    Ok(Vec::new())
}

fn stream_id_of(stream: &ReceiveStream) -> u64 {
    stream.id
}

fn drain_request_frames(
    stream: &mut ReceiveStream,
    control_received: &bool,
    peer_goaway: &Option<u64>,
    qpack: &mut QpackConnection,
    max_header_list: usize,
    max_body: usize,
    requests: &mut VecDeque<PendingRequest>,
) -> Result<()> {
    let mut pos = 0;
    let mut became_blocked = false;
    while let Some(frame) = h3frame::Frame::decode(&stream.frame_buf, &mut pos)? {
        match frame {
            h3frame::Frame::Headers(block) if stream.headers.is_none() => {
                if block.len() > max_header_list {
                    return Err(protocol("HTTP/3 request headers exceed configured limit"));
                }
                match qpack.decode(stream.id, &block, max_header_list)? {
                    Some(fields) => stream.headers = Some(fields),
                    // The section references dynamic entries we have not
                    // processed yet: consume the frame and pause the
                    // stream until the encoder stream catches up.
                    None => {
                        became_blocked = true;
                        break;
                    }
                }
            }
            h3frame::Frame::Data(data) => {
                if stream.headers.is_none() {
                    return Err(protocol("HTTP/3 DATA before request HEADERS"));
                }
                let next = stream
                    .body
                    .len()
                    .checked_add(data.len())
                    .ok_or_else(|| protocol("HTTP/3 request body length overflow"))?;
                if next > max_body {
                    return Err(protocol("HTTP/3 request body exceeds configured limit"));
                }
                stream.body.extend_from_slice(&data);
            }
            h3frame::Frame::Unknown { .. } => {}
            h3frame::Frame::Headers(_) => {
                return Err(protocol("duplicate HTTP/3 request HEADERS"));
            }
            _ => return Err(protocol("invalid frame on HTTP/3 request stream")),
        }
    }
    if became_blocked {
        // The HEADERS frame is now buffered in the QPACK connection; the
        // remaining frames stay in frame_buf and are drained on unblock.
        stream.frame_buf.drain(..pos);
        stream.blocked = true;
        return Ok(());
    }
    if pos != 0 {
        stream.frame_buf.drain(..pos);
    }
    if stream.reassembly.finished() && !stream.completed {
        if stream.blocked {
            // The request ended while its headers were still blocked;
            // cancel the section so the encoder does not wait on it.
            qpack.cancel_stream(stream.id);
            stream.completed = true;
            return Ok(());
        }
        if peer_goaway.is_some_and(|last| stream.id > last) {
            return Err(protocol("HTTP/3 request is beyond peer GOAWAY"));
        }
        if !*control_received {
            return Err(protocol("HTTP/3 request arrived before peer SETTINGS"));
        }
        if requests.len() >= MAX_H3_PENDING_REQUESTS {
            return Err(protocol("HTTP/3 pending request limit exceeded"));
        }
        let fields = stream
            .headers
            .take()
            .ok_or_else(|| protocol("HTTP/3 request ended without HEADERS"))?;
        let request = request_from_fields(fields, core::mem::take(&mut stream.body))?;
        stream.completed = true;
        if std::env::var_os("COURIERUST_H3_DEBUG").is_some()
            && request.body.len().unwrap_or(0) > 100 * 1024
        {
            eprintln!(
                "H3SERVER request-pushed: stream={} body={} finished=true",
                stream.id,
                request.body.len().unwrap_or(0)
            );
        }
        requests.push_back(PendingRequest {
            stream_id: stream.id,
            request,
            received_at: Instant::now(),
        });
    }
    Ok(())
}

fn drain_response_frames(
    stream: &mut ReceiveStream,
    _control_received: &bool,
    qpack: &mut QpackConnection,
    max_header_list: usize,
    max_body: usize,
    response: &mut Option<Response<Body>>,
) -> Result<()> {
    let mut pos = 0;
    let mut became_blocked = false;
    while let Some(frame) = h3frame::Frame::decode(&stream.frame_buf, &mut pos)? {
        match frame {
            h3frame::Frame::Headers(block) => {
                if block.len() > max_header_list {
                    return Err(protocol("HTTP/3 response headers exceed configured limit"));
                }
                match qpack.decode(stream.id, &block, max_header_list)? {
                    Some(fields) => {
                        if stream.headers.is_none() {
                            stream.headers = Some(fields);
                        } else {
                            if stream.trailers.is_some() {
                                return Err(protocol("multiple HTTP/3 response trailer blocks"));
                            }
                            stream.trailers = Some(response_trailers_from_fields(fields)?);
                        }
                    }
                    None => {
                        became_blocked = true;
                        break;
                    }
                }
            }
            h3frame::Frame::Data(data) => {
                if stream.trailers.is_some() {
                    return Err(protocol("HTTP/3 DATA follows response trailers"));
                }
                let next = stream
                    .body
                    .len()
                    .checked_add(data.len())
                    .ok_or_else(|| protocol("HTTP/3 response body length overflow"))?;
                if next > max_body {
                    return Err(protocol("HTTP/3 response body exceeds configured limit"));
                }
                stream.body.extend_from_slice(&data);
            }
            h3frame::Frame::Unknown { .. } => {}
            _ => return Err(protocol("invalid frame on HTTP/3 response stream")),
        }
    }
    if became_blocked {
        stream.frame_buf.drain(..pos);
        stream.blocked = true;
        return Ok(());
    }
    if pos != 0 {
        stream.frame_buf.drain(..pos);
    }
    if stream.reassembly.finished() && !stream.completed {
        if stream.blocked {
            qpack.cancel_stream(stream.id);
            stream.completed = true;
            return Ok(());
        }
        let fields = stream
            .headers
            .take()
            .ok_or_else(|| protocol("HTTP/3 response ended without HEADERS"))?;
        *response = Some(response_from_fields(
            fields,
            core::mem::take(&mut stream.body),
            stream.trailers.take(),
        )?);
        stream.completed = true;
    }
    Ok(())
}

/// Validate the peer's SETTINGS. Returns the peer's advertised QPACK
/// dynamic-table capacity (0 when absent, RFC 9204 §3.2.2).
fn validate_settings(
    settings: &[(u64, u64)],
    _max_header_list: usize,
    peer_max_header_list: &mut usize,
) -> Result<u64> {
    let mut seen = BTreeSet::new();
    let mut peer_qpack_capacity = 0u64;
    for (id, value) in settings {
        if !seen.insert(*id) {
            return Err(protocol("duplicate HTTP/3 SETTINGS identifier"));
        }
        match *id {
            h3frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY => {
                peer_qpack_capacity = *value;
            }
            h3frame::SETTINGS_QPACK_BLOCKED_STREAMS
            | h3frame::SETTINGS_ENABLE_CONNECT_PROTOCOL
            | h3frame::SETTINGS_H3_DATAGRAM
            | h3frame::SETTINGS_WEBTRANSPORT_MAX_SESSIONS => {}
            h3frame::SETTINGS_MAX_FIELD_SECTION_SIZE => {
                *peer_max_header_list = usize::try_from(*value).unwrap_or(usize::MAX);
            }
            0x02..=0x05 => {
                return Err(protocol("reserved HTTP/3 SETTINGS identifier"));
            }
            _ => {}
        }
    }
    Ok(peer_qpack_capacity)
}

fn validate_content_length(headers: &HeaderMap, actual: usize) -> Result<()> {
    let mut declared = None;
    for value in headers.get_all("content-length") {
        let bytes = value.as_bytes();
        let start = bytes
            .iter()
            .position(|byte| !matches!(*byte, b' ' | b'\t'))
            .unwrap_or(bytes.len());
        let end = bytes
            .iter()
            .rposition(|byte| !matches!(*byte, b' ' | b'\t'))
            .map_or(start, |position| position + 1);
        let digits = &bytes[start..end];
        if digits.is_empty() {
            return Err(protocol("HTTP/3 content-length is empty"));
        }
        let mut length = 0usize;
        for &digit in digits {
            if !digit.is_ascii_digit() {
                return Err(protocol("HTTP/3 content-length is not decimal"));
            }
            length = length
                .checked_mul(10)
                .and_then(|value| value.checked_add((digit - b'0') as usize))
                .ok_or_else(|| protocol("HTTP/3 content-length overflows usize"))?;
        }
        if declared.is_some_and(|previous| previous != length) {
            return Err(protocol("conflicting HTTP/3 content-length"));
        }
        declared = Some(length);
    }
    if declared.is_some_and(|length| length != actual) {
        return Err(protocol("HTTP/3 content-length does not match body"));
    }
    Ok(())
}

fn validate_goaway_id(id: u64, previous: Option<u64>) -> Result<()> {
    if id & 0x03 != 0 {
        return Err(protocol("HTTP/3 GOAWAY contains an invalid stream id"));
    }
    if previous.is_some_and(|last| id > last) {
        return Err(protocol("HTTP/3 GOAWAY stream id increased"));
    }
    Ok(())
}

fn request_from_fields(fields: Vec<FieldLine>, body: Vec<u8>) -> Result<Request<Body>> {
    let mut method = None;
    let mut path = None;
    let mut scheme = None;
    let mut authority = None;
    let mut headers = HeaderMap::new();
    let mut regular = false;
    for field in fields {
        if field.name.starts_with(':') {
            if regular {
                return Err(protocol("HTTP/3 pseudo-header follows regular header"));
            }
            match field.name.as_str() {
                ":method" if method.is_none() => method = Some(field.value),
                ":path" if path.is_none() => path = Some(field.value),
                ":scheme" if scheme.is_none() => scheme = Some(field.value),
                ":authority" if authority.is_none() => authority = Some(field.value),
                _ => return Err(protocol("duplicate or unsupported HTTP/3 pseudo-header")),
            }
        } else {
            regular = true;
            let name = HeaderName::from_bytes(field.name.as_bytes())?;
            if matches!(
                name.as_str(),
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
            ) {
                return Err(protocol(
                    "HTTP/3 request contains a connection-specific header",
                ));
            }
            let value = HeaderValue::from_bytes(&field.value)?;
            headers.append(name, value);
        }
    }
    if scheme.as_deref() != Some(b"https") {
        return Err(protocol("HTTP/3 request :scheme must be https"));
    }
    let method = Method::from_bytes(
        method
            .as_deref()
            .ok_or_else(|| protocol("HTTP/3 request lacks :method"))?,
    )?;
    let path = PathAndQuery::from_bytes(
        path.as_deref()
            .ok_or_else(|| protocol("HTTP/3 request lacks :path"))?,
    )?;
    if let Some(authority) = authority {
        headers.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_bytes(&authority)?,
        );
    }
    validate_content_length(&headers, body.len())?;
    let head = RequestHead {
        method,
        uri: path,
        version: Version::HTTP_3,
        headers,
    };
    Ok(head.with_body(Body::from(body)))
}

fn response_from_fields(
    fields: Vec<FieldLine>,
    body: Vec<u8>,
    trailers: Option<HeaderMap>,
) -> Result<Response<Body>> {
    let mut status = None;
    let mut headers = HeaderMap::new();
    let mut regular = false;
    for field in fields {
        if field.name == ":status" {
            if regular
                || status.is_some()
                || field.value.len() != 3
                || !field.value.iter().all(u8::is_ascii_digit)
            {
                return Err(protocol("invalid HTTP/3 :status"));
            }
            let value = (field.value[0] - b'0') as u16 * 100
                + (field.value[1] - b'0') as u16 * 10
                + (field.value[2] - b'0') as u16;
            status = Some(StatusCode::from_u16(value));
        } else if field.name.starts_with(':') {
            return Err(protocol("unsupported HTTP/3 response pseudo-header"));
        } else {
            regular = true;
            let name = HeaderName::from_bytes(field.name.as_bytes())?;
            let value = HeaderValue::from_bytes(&field.value)?;
            headers.append(name, value);
        }
    }
    let status = status.ok_or_else(|| protocol("HTTP/3 response lacks :status"))?;
    if (status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::RESET_CONTENT
        || status == StatusCode::NOT_MODIFIED)
        && !body.is_empty()
    {
        return Err(protocol("HTTP/3 response status forbids a body"));
    }
    validate_content_length(&headers, body.len())?;
    Ok(Response {
        status,
        version: Version::HTTP_3,
        headers,
        body: Body::from(body),
        trailers,
    })
}

fn response_trailers_from_fields(fields: Vec<FieldLine>) -> Result<HeaderMap> {
    let mut trailers = HeaderMap::new();
    for field in fields {
        if field.name.starts_with(':')
            || matches!(
                field.name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "upgrade"
                    | "content-length"
            )
        {
            return Err(protocol("invalid HTTP/3 response trailer field"));
        }
        let name = HeaderName::from_bytes(field.name.as_bytes())?;
        let value = HeaderValue::from_bytes(&field.value)?;
        trailers.append(name, value);
    }
    Ok(trailers)
}

fn build_request_wire(
    request: Request<Body>,
    authority: &str,
    qpack: &mut QpackConnection,
    max_header_list: usize,
    max_body: usize,
) -> Result<Vec<u8>> {
    let Request {
        method,
        uri,
        headers,
        body,
        ..
    } = request;
    let bytes = body
        .collect_limited(max_body)
        .map_err(|error| match error.kind {
            ErrorKind::Overflow => protocol("HTTP/3 request body exceeds configured limit"),
            _ => error,
        })?;
    let mut fields = vec![
        (":method".to_string(), method.as_str().as_bytes().to_vec()),
        (":scheme".to_string(), b"https".to_vec()),
        (":authority".to_string(), authority.as_bytes().to_vec()),
        (":path".to_string(), uri.as_bytes().to_vec()),
    ];
    for (name, value) in headers.iter() {
        if name.is_pseudo()
            || matches!(
                name.as_str(),
                "host"
                    | "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "transfer-encoding"
                    | "upgrade"
            )
        {
            continue;
        }
        fields.push((name.as_str().to_string(), value.as_bytes().to_vec()));
    }
    let header_block = qpack.encode(&fields, max_header_list)?;
    let mut wire = h3frame::Frame::Headers(header_block).to_bytes();
    if !bytes.is_empty() {
        wire.extend_from_slice(&h3frame::Frame::Data(bytes.to_vec()).to_bytes());
    }
    Ok(wire)
}

fn build_response_wire(
    response: Response<Body>,
    qpack: &mut QpackConnection,
    max_header_list: usize,
    max_body: usize,
) -> Result<Vec<u8>> {
    let response = materialize_response(response, max_body)?;
    let body = response.body.as_bytes().unwrap_or(&[]).to_vec();
    let mut fields = vec![(
        ":status".to_string(),
        response.status.as_u16().to_string().into_bytes(),
    )];
    for (name, value) in response.headers.iter() {
        if name.is_pseudo()
            || matches!(
                name.as_str(),
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
            )
        {
            continue;
        }
        fields.push((name.as_str().to_string(), value.as_bytes().to_vec()));
    }
    let header_block = qpack.encode(&fields, max_header_list)?;
    let mut wire = h3frame::Frame::Headers(header_block).to_bytes();
    if !body.is_empty() {
        wire.extend_from_slice(&h3frame::Frame::Data(body).to_bytes());
    }
    if let Some(trailers) = response.trailers {
        let mut tfields = Vec::new();
        for (name, value) in trailers.iter() {
            let n = name.as_str();
            if n.starts_with(':')
                || matches!(
                    n,
                    "connection"
                        | "keep-alive"
                        | "proxy-connection"
                        | "transfer-encoding"
                        | "upgrade"
                        | "content-length"
                )
            {
                return Err(protocol("invalid HTTP/3 response trailer field"));
            }
            tfields.push((n.to_string(), value.as_bytes().to_vec()));
        }
        if !tfields.is_empty() {
            let trailer_block = qpack.encode(&tfields, max_header_list)?;
            wire.extend_from_slice(&h3frame::Frame::Headers(trailer_block).to_bytes());
        }
    }
    Ok(wire)
}

fn control_stream(settings: Vec<u8>) -> Vec<u8> {
    let mut out = stream_type(H3_CONTROL_STREAM);
    out.extend_from_slice(&settings);
    out
}

fn stream_type(kind: u64) -> Vec<u8> {
    varint::encode(kind)
}

fn packet_keys_from_flight(key: Option<PacketKey>) -> Result<PacketKey> {
    key.ok_or_else(|| protocol("QUIC TLS flight did not contain required packet keys"))
}

struct LongHeaderIdentity {
    version: u32,
    packet_type: LongType,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    payload_offset: usize,
}

struct RetryPacket {
    dcid: Vec<u8>,
    scid: Vec<u8>,
    token: Vec<u8>,
    tag: [u8; 16],
}

struct VersionNegotiationPacket {
    dcid: Vec<u8>,
    scid: Vec<u8>,
    versions: Vec<u32>,
}

fn parse_long_header_identity(buf: &[u8]) -> Result<LongHeaderIdentity> {
    if buf.len() < 7 || buf[0] & 0x80 == 0 {
        return Err(protocol("truncated QUIC long header"));
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let packet_type = match (buf[0] >> 4) & 0x03 {
        0 => LongType::Initial,
        1 => LongType::ZeroRtt,
        2 => LongType::Handshake,
        _ => LongType::Retry,
    };
    let dcid_len = buf[5] as usize;
    let dcid_start = 6usize;
    let dcid_end = dcid_start
        .checked_add(dcid_len)
        .ok_or_else(|| protocol("QUIC DCID offset overflow"))?;
    if dcid_len > 20 || dcid_end >= buf.len() {
        return Err(protocol("invalid QUIC DCID length"));
    }
    let scid_len = buf[dcid_end] as usize;
    let scid_start = dcid_end + 1;
    let scid_end = scid_start
        .checked_add(scid_len)
        .ok_or_else(|| protocol("QUIC SCID offset overflow"))?;
    if scid_len > 20 || scid_end > buf.len() {
        return Err(protocol("invalid QUIC SCID length"));
    }
    Ok(LongHeaderIdentity {
        version,
        packet_type,
        dcid: buf[dcid_start..dcid_end].to_vec(),
        scid: buf[scid_start..scid_end].to_vec(),
        payload_offset: scid_end,
    })
}

fn encode_version_negotiation(initial: &[u8]) -> Result<Vec<u8>> {
    let identity = parse_long_header_identity(initial)?;
    if identity.packet_type != LongType::Initial
        || identity.dcid.is_empty()
        || identity.scid.is_empty()
    {
        return Err(protocol("invalid QUIC Initial for Version Negotiation"));
    }
    let mut out = Vec::with_capacity(6 + identity.scid.len() + identity.dcid.len() + 8);
    out.push(0x80);
    out.extend_from_slice(&crate::courierust_quic::VERSION_NEGOTIATION.to_be_bytes());
    out.push(identity.scid.len() as u8);
    out.extend_from_slice(&identity.scid);
    out.push(identity.dcid.len() as u8);
    out.extend_from_slice(&identity.dcid);
    out.extend_from_slice(&crate::courierust_quic::VERSION_1.to_be_bytes());
    Ok(out)
}

fn encode_retry_packet(
    initial: &[u8],
    original_dcid: &[u8],
    retry_dcid: &[u8],
    token: &[u8],
) -> Result<Vec<u8>> {
    let identity = parse_long_header_identity(initial)?;
    if identity.packet_type != LongType::Initial
        || identity.scid.is_empty()
        || retry_dcid.is_empty()
        || retry_dcid.len() > 20
    {
        return Err(protocol("invalid QUIC Initial for Retry"));
    }
    if token.len() as u64 > varint::MAX {
        return Err(protocol("QUIC Retry token is too large"));
    }
    let mut out = Vec::with_capacity(32 + token.len());
    out.push(0xf0);
    out.extend_from_slice(&crate::courierust_quic::VERSION_1.to_be_bytes());
    out.push(identity.scid.len() as u8);
    out.extend_from_slice(&identity.scid);
    out.push(retry_dcid.len() as u8);
    out.extend_from_slice(retry_dcid);
    out.extend_from_slice(token);
    let tag = protection::retry_integrity_tag(original_dcid, &out)
        .map_err(|error| protocol(error.to_string()))?;
    out.extend_from_slice(&tag);
    Ok(out)
}

fn parse_retry_packet(buf: &[u8]) -> Result<Option<RetryPacket>> {
    if buf.first().map_or(true, |first| first & 0x80 == 0) {
        return Ok(None);
    }
    let identity = parse_long_header_identity(buf)?;
    if identity.version != crate::courierust_quic::VERSION_1
        || identity.packet_type != LongType::Retry
    {
        return Ok(None);
    }
    if identity.dcid.is_empty() || identity.scid.is_empty() {
        return Err(protocol("QUIC Retry contains an empty connection ID"));
    }
    if buf.len() < identity.payload_offset + 16 {
        return Err(protocol("QUIC Retry is shorter than its integrity tag"));
    }
    let tag_start = buf.len() - 16;
    if tag_start < identity.payload_offset {
        return Err(protocol("QUIC Retry token is truncated"));
    }
    let tag: [u8; 16] = buf[tag_start..]
        .try_into()
        .map_err(|_| protocol("QUIC Retry integrity tag has invalid length"))?;
    Ok(Some(RetryPacket {
        dcid: identity.dcid,
        scid: identity.scid,
        token: buf[identity.payload_offset..tag_start].to_vec(),
        tag,
    }))
}

fn version_negotiation_versions(buf: &[u8]) -> Result<Option<VersionNegotiationPacket>> {
    if buf.first().map_or(true, |first| first & 0x80 == 0) {
        return Ok(None);
    }
    let identity = parse_long_header_identity(buf)?;
    if identity.version != crate::courierust_quic::VERSION_NEGOTIATION {
        return Ok(None);
    }
    let versions = &buf[identity.payload_offset..];
    if versions.is_empty() || versions.len() % 4 != 0 {
        return Err(protocol("malformed QUIC Version Negotiation packet"));
    }
    let version_blocks = versions.chunks_exact(4);
    debug_assert!(
        version_blocks.remainder().is_empty(),
        "version list length checked as multiple of 4"
    );
    let versions = version_blocks
        .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    Ok(Some(VersionNegotiationPacket {
        dcid: identity.dcid,
        scid: identity.scid,
        versions,
    }))
}

fn looks_like_initial(buf: &[u8]) -> bool {
    parse_long_header_identity(buf).is_ok_and(|identity| {
        identity.version == crate::courierust_quic::VERSION_1
            && identity.packet_type == LongType::Initial
            && !identity.dcid.is_empty()
            && !identity.scid.is_empty()
    })
}

/// The destination connection id of a packet as a slice into the
/// datagram (zero allocation). Long headers carry it at `[6..]`; short
/// headers always use the 8-byte CID this runtime generates.
fn packet_destination_cid(buf: &[u8]) -> Option<&[u8]> {
    if buf.first().is_some_and(|first| first & 0x80 != 0) {
        let dcid_len = *buf.get(5)? as usize;
        let end = 6usize.checked_add(dcid_len)?;
        (dcid_len <= 20 && end < buf.len()).then(|| &buf[6..end])
    } else {
        let end = 1usize.checked_add(8)?;
        (buf.len() >= end).then(|| &buf[1..end])
    }
}

// -------------------------------------------------------------------------
// QUIC packet transport
// -------------------------------------------------------------------------

#[derive(Default)]
struct PacketSpace {
    next_send: u64,
    largest_received: Option<u64>,
    /// Highest acknowledged packet number in this space (for the RFC 9002
    /// §6.1.1 packet-threshold loss detector).
    largest_acked: Option<u64>,
    /// Highest packet number ever sent in this space (RFC 9000 §13.1:
    /// an ACK is only an error when it exceeds this, never for a
    /// duplicate ACK of an already-acknowledged packet).
    largest_sent: Option<u64>,
    received: BTreeSet<u64>,
    sent: BTreeMap<u64, SentPacket>,
    ack_pending: bool,
    ack_deadline: Option<Instant>,
}

struct SentPacket {
    frames: Vec<QFrame>,
    pad_initial: bool,
    sent_at: Instant,
    retransmits: u8,
    ack_eliciting: bool,
    size: usize,
    pending_resend: bool,
}

/// A response body queued for the wire. `queued_at` feeds the tail
/// instrumentation that splits worker→reactor handoff from the actual
/// flush — the two surfaces where a slow response hides from the client.
struct QueuedStream {
    id: u64,
    wire: Vec<u8>,
    offset: usize,
    queued_at: Instant,
}

struct QuicTransport {
    server: bool,
    peer: Option<SocketAddr>,
    /// Candidate peer address undergoing RFC 9000 §9.3 path validation.
    /// While set, all application data keeps flowing to `peer`; only the
    /// PATH_CHALLENGE probe is sent to this address, and no more than the
    /// anti-amplification budget may be sent to it.
    pending_peer: Option<SocketAddr>,
    /// The outstanding PATH_CHALLENGE token for the pending path.
    path_challenge: Option<[u8; 8]>,
    /// When the pending PATH_CHALLENGE was last sent (drives retry/abort).
    path_challenge_sent: Option<Instant>,
    /// Number of PATH_CHALLENGE retries on the pending path (max 1).
    path_validation_retries: u8,
    /// The peer's `disable_active_migration` transport parameter (RFC 9000
    /// §18.2): when set, this endpoint MUST NOT actively migrate, though
    /// passive path validation still runs.
    peer_disable_active_migration: bool,
    /// Maximum UDP datagram this endpoint will send: the peer's
    /// `max_udp_payload_size`, discovered up via DPLPMTUD-style probing
    /// (RFC 8899) and never above the hard UDP ceiling. RFC 9000 §14
    /// requires sending nothing larger.
    max_packet_size: usize,
    local_cid: Vec<u8>,
    remote_cid: Vec<u8>,
    original_dcid: Vec<u8>,
    initial_dcid: Vec<u8>,
    initial_token: Vec<u8>,
    retry_seen: bool,
    initial_send: PacketKey,
    initial_recv: PacketKey,
    handshake_send: Option<PacketKey>,
    handshake_recv: Option<PacketKey>,
    application_send: Option<PacketKey>,
    application_recv: Option<PacketKey>,
    application_send_phase: bool,
    application_recv_phase: bool,
    key_phase_packets: u64,
    send_update_pending: bool,
    spaces: [PacketSpace; 3],
    crypto_send_offsets: [u64; 3],
    queued_streams: VecDeque<QueuedStream>,
    congestion_window: usize,
    slow_start_threshold: usize,
    smoothed_rtt: Option<Duration>,
    rtt_variance: Duration,
    latest_rtt: Option<Duration>,
    peer_max_data: u64,
    peer_max_stream_data_bidi_local: u64,
    peer_max_stream_data_bidi_remote: u64,
    peer_max_stream_data_uni: u64,
    peer_stream_limits: BTreeMap<u64, u64>,
    sent_data: u64,
    sent_stream_data: BTreeMap<u64, u64>,
    local_max_data: u64,
    local_max_stream_data_bidi_local: u64,
    local_max_stream_data_bidi_remote: u64,
    local_max_stream_data_uni: u64,
    local_stream_limits: BTreeMap<u64, u64>,
    received_data: u64,
    received_stream_data: BTreeMap<u64, u64>,
    peer_max_streams_bidi: u64,
    /// The peer's advertised cumulative limit on the uni streams we
    /// initiate, raised by any MAX_STREAMS we received.
    peer_max_streams_uni: u64,
    local_max_streams_bidi: u64,
    local_max_streams_uni: u64,
    received_streams_bidi: u64,
    received_streams_uni: u64,
    peer_stateless_reset_token: Option<[u8; 16]>,
    stateless_reset_token: Option<[u8; 16]>,
    stats: Option<Arc<Stats>>,
}

impl QuicTransport {
    fn client(
        local_cid: Vec<u8>,
        remote_cid: Vec<u8>,
        initial_dcid: Vec<u8>,
        stats: Option<Arc<Stats>>,
    ) -> Result<Self> {
        let (client_key, server_key) = protection::initial_pair(&initial_dcid)?;
        Ok(Self::new(
            local_cid,
            remote_cid,
            initial_dcid,
            false,
            client_key,
            server_key,
            stats,
        ))
    }

    fn server(
        local_cid: Vec<u8>,
        remote_cid: Vec<u8>,
        initial_dcid: Vec<u8>,
        stats: Option<Arc<Stats>>,
    ) -> Result<Self> {
        let (client_key, server_key) = protection::initial_pair(&initial_dcid)?;
        Ok(Self::new(
            local_cid,
            remote_cid,
            initial_dcid,
            true,
            server_key,
            client_key,
            stats,
        ))
    }

    /// Shared constructor for both roles; only the role flag and the
    /// initial-direction key swap differ between client and server.
    fn new(
        local_cid: Vec<u8>,
        remote_cid: Vec<u8>,
        initial_dcid: Vec<u8>,
        server: bool,
        initial_send: PacketKey,
        initial_recv: PacketKey,
        stats: Option<Arc<Stats>>,
    ) -> Self {
        Self {
            server,
            peer: None,
            pending_peer: None,
            path_challenge: None,
            path_challenge_sent: None,
            path_validation_retries: 0,
            peer_disable_active_migration: false,
            max_packet_size: 1200,
            local_cid,
            remote_cid,
            original_dcid: initial_dcid.clone(),
            initial_dcid,
            initial_token: Vec::new(),
            retry_seen: false,
            initial_send,
            initial_recv,
            handshake_send: None,
            handshake_recv: None,
            application_send: None,
            application_recv: None,
            application_send_phase: false,
            application_recv_phase: false,
            key_phase_packets: 0,
            send_update_pending: false,
            spaces: [
                PacketSpace::default(),
                PacketSpace::default(),
                PacketSpace::default(),
            ],
            crypto_send_offsets: [0; 3],
            queued_streams: VecDeque::new(),
            congestion_window: initial_congestion_window(),
            slow_start_threshold: usize::MAX,
            smoothed_rtt: None,
            rtt_variance: Duration::from_millis(0),
            latest_rtt: None,
            peer_max_data: 16 * 1024 * 1024,
            peer_max_stream_data_bidi_local: 16 * 1024 * 1024,
            peer_max_stream_data_bidi_remote: 16 * 1024 * 1024,
            peer_max_stream_data_uni: 1024 * 1024,
            peer_stream_limits: BTreeMap::new(),
            sent_data: 0,
            sent_stream_data: BTreeMap::new(),
            local_max_data: MAX_H3_CONNECTION_BUFFER as u64,
            local_max_stream_data_bidi_local: 16 * 1024 * 1024,
            local_max_stream_data_bidi_remote: 16 * 1024 * 1024,
            local_max_stream_data_uni: 1024 * 1024,
            local_stream_limits: BTreeMap::new(),
            received_data: 0,
            received_stream_data: BTreeMap::new(),
            peer_max_streams_bidi: 1024,
            peer_max_streams_uni: 16,
            local_max_streams_bidi: 1024,
            local_max_streams_uni: 16,
            received_streams_bidi: 0,
            received_streams_uni: 0,
            peer_stateless_reset_token: None,
            stateless_reset_token: None,
            stats,
        }
    }

    fn set_handshake_keys(&mut self, recv: PacketKey, send: PacketKey) {
        self.handshake_recv = Some(recv);
        self.handshake_send = Some(send);
    }

    fn set_application_keys(&mut self, recv: PacketKey, send: PacketKey) {
        self.application_recv = Some(recv);
        self.application_send = Some(send);
        self.application_send_phase = false;
        self.application_recv_phase = false;
        self.send_update_pending = false;
    }

    fn set_peer_transport(&mut self, parameters: &TransportParameters) {
        self.peer_max_data = parameters.initial_max_data;
        self.peer_max_stream_data_bidi_local = parameters.initial_max_stream_data_bidi_local;
        self.peer_max_stream_data_bidi_remote = parameters.initial_max_stream_data_bidi_remote;
        self.peer_max_stream_data_uni = parameters.initial_max_stream_data_uni;
        self.peer_max_streams_bidi = parameters.initial_max_streams_bidi;
        self.peer_max_streams_uni = parameters.initial_max_streams_uni;
        self.peer_stateless_reset_token = parameters.stateless_reset_token;
        self.peer_disable_active_migration = parameters.disable_active_migration;
        let peer_cap = usize::try_from(parameters.max_udp_payload_size).unwrap_or(MAX_DATAGRAM);
        self.max_packet_size = peer_cap.clamp(1200, MAX_DATAGRAM);
    }

    /// Whether `datagram` is a stateless reset (RFC 9000 §10.3): a
    /// short-header packet whose final 16 bytes match the token the peer
    /// advertised in its transport parameters. Constant-time comparison.
    fn is_stateless_reset(&self, datagram: &[u8]) -> bool {
        let Some(token) = &self.peer_stateless_reset_token else {
            return false;
        };
        if datagram.is_empty() || datagram[0] & 0x80 != 0 || datagram[0] & 0x40 == 0 {
            return false;
        }
        if datagram.len() < 17 || datagram.len() > MAX_DATAGRAM {
            return false;
        }
        constant_time_equal(&datagram[datagram.len() - 16..], token)
    }

    fn apply_retry(&mut self, retry_dcid: Vec<u8>, token: Vec<u8>) -> Result<bool> {
        if self.server || self.retry_seen {
            return Ok(false);
        }
        if retry_dcid.is_empty() || retry_dcid.len() > 20 || token.is_empty() {
            return Err(protocol("invalid QUIC Retry connection ID or token"));
        }
        let (client_initial, server_initial) = protection::initial_pair(&retry_dcid)?;
        self.initial_dcid.clone_from(&retry_dcid);
        self.remote_cid = retry_dcid;
        self.initial_send = client_initial;
        self.initial_recv = server_initial;
        self.initial_token = token;
        self.retry_seen = true;
        self.spaces[INITIAL] = PacketSpace::default();
        self.spaces[HANDSHAKE] = PacketSpace::default();
        self.spaces[APPLICATION] = PacketSpace::default();
        self.crypto_send_offsets = [0; 3];
        self.handshake_send = None;
        self.handshake_recv = None;
        self.application_send = None;
        self.application_recv = None;
        self.application_send_phase = false;
        self.application_recv_phase = false;
        self.key_phase_packets = 0;
        self.send_update_pending = false;
        self.sent_data = 0;
        self.sent_stream_data.clear();
        self.peer_stream_limits.clear();
        self.local_stream_limits.clear();
        self.received_data = 0;
        self.received_stream_data.clear();
        self.latest_rtt = None;
        self.smoothed_rtt = None;
        self.rtt_variance = Duration::from_millis(0);
        self.peer_stateless_reset_token = None;
        Ok(true)
    }

    fn set_local_transport(&mut self, parameters: &TransportParameters) {
        self.local_max_data = parameters.initial_max_data;
        self.local_max_stream_data_bidi_local = parameters.initial_max_stream_data_bidi_local;
        self.local_max_stream_data_bidi_remote = parameters.initial_max_stream_data_bidi_remote;
        self.local_max_stream_data_uni = parameters.initial_max_stream_data_uni;
        self.local_max_streams_bidi = parameters.initial_max_streams_bidi;
        self.local_max_streams_uni = parameters.initial_max_streams_uni;
    }

    /// The peer's advertised cumulative limit on the bidi streams we
    /// initiate (RFC 9000 §4.6), raised by any MAX_STREAMS we received.
    fn peer_stream_count_limit(&self) -> u64 {
        self.peer_max_streams_bidi
    }

    /// The peer's advertised send limit for `id` (its transport parameter,
    /// raised by any `MAX_STREAM_DATA` we received).
    fn peer_stream_send_limit(&self, id: u64) -> u64 {
        let default_limit = if stream_id::is_unidirectional(id) {
            self.peer_max_stream_data_uni
        } else if stream_id::is_client_initiated(id) != self.server {
            self.peer_max_stream_data_bidi_remote
        } else {
            self.peer_max_stream_data_bidi_local
        };
        self.peer_stream_limits
            .get(&id)
            .copied()
            .unwrap_or(default_limit)
    }

    fn accept_stream_data(&mut self, id: u64, offset: u64, length: usize) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        if stream_id::is_client_initiated(id) == self.server {
            let (limit, counter) = if stream_id::is_unidirectional(id) {
                (self.local_max_streams_uni, &mut self.received_streams_uni)
            } else {
                (self.local_max_streams_bidi, &mut self.received_streams_bidi)
            };
            let index = stream_id::stream_index(id);
            if index >= limit {
                return Err(protocol("QUIC peer stream limit exceeded"));
            }
            *counter = (*counter).max(index + 1);
        }
        let end = offset
            .checked_add(length as u64)
            .ok_or_else(|| protocol("QUIC stream receive offset overflow"))?;
        let default_limit = if stream_id::is_unidirectional(id) {
            self.local_max_stream_data_uni
        } else if stream_id::is_client_initiated(id) != self.server {
            self.local_max_stream_data_bidi_local
        } else {
            self.local_max_stream_data_bidi_remote
        };
        let advertised = self
            .local_stream_limits
            .get(&id)
            .copied()
            .unwrap_or(default_limit);
        if end > advertised {
            return Err(protocol("QUIC local stream flow-control limit exceeded"));
        }
        let previous = self.received_stream_data.get(&id).copied().unwrap_or(0);
        let newly_received = end.saturating_sub(previous);
        if self.received_data.saturating_add(newly_received) > self.local_max_data {
            return Err(protocol(
                "QUIC local connection flow-control limit exceeded",
            ));
        }
        self.received_data = self.received_data.saturating_add(newly_received);
        self.received_stream_data.insert(id, previous.max(end));
        Ok(())
    }

    fn open(&mut self, datagram: &mut [u8]) -> Result<Option<OpenPacket>> {
        if datagram.len() < 21 || datagram.len() > MAX_DATAGRAM {
            return Ok(None);
        }
        let meta = match PacketMeta::parse(datagram, self.local_cid.len()) {
            Ok(meta) => meta,
            Err(_) => return Ok(None),
        };
        let (level, key) = if meta.long_type == Some(LongType::Initial) {
            (INITIAL, self.initial_recv.clone())
        } else if meta.long_type == Some(LongType::Handshake) {
            let Some(key) = self.handshake_recv.clone() else {
                return Ok(None);
            };
            (HANDSHAKE, key)
        } else if meta.long_type.is_none() {
            let Some(key) = self.application_recv.clone() else {
                return Ok(None);
            };
            (APPLICATION, key)
        } else {
            return Ok(None);
        };
        if meta.long_type != Some(LongType::Initial) && meta.dcid != self.local_cid {
            return Ok(None);
        }
        if meta.long_type == Some(LongType::Initial)
            && self.server
            && meta.dcid != self.initial_dcid
            && meta.dcid != self.local_cid
        {
            return Ok(None);
        }
        let expected = self.spaces[level]
            .largest_received
            .map(|pn| pn.saturating_add(1))
            .unwrap_or(0);
        let current_phase = if level == APPLICATION {
            Some(self.application_recv_phase)
        } else {
            None
        };
        let mut opened = None;
        if let Some((pn, plaintext)) =
            open_packet_with_key(datagram, &meta, &key, expected, current_phase)?
        {
            opened = Some((pn, plaintext));
        }
        let mut candidate = key;
        let mut next_phase = false;
        if opened.is_none() && level == APPLICATION {
            if let Ok(next) = candidate.next_key_phase() {
                if let Some((pn, plaintext)) = open_packet_with_key(
                    datagram,
                    &meta,
                    &next,
                    expected,
                    Some(!self.application_recv_phase),
                )? {
                    opened = Some((pn, plaintext));
                    candidate = next;
                    next_phase = true;
                }
            }
        }
        let Some((pn, plaintext)) = opened else {
            if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                let phase_bit = if meta.long_type.is_none() {
                    Some((datagram[0] >> 2) & 1)
                } else {
                    None
                };
                let recv_phase = if level == APPLICATION {
                    Some(self.application_recv_phase)
                } else {
                    None
                };
                let recv_fp = self.application_recv.as_ref().map(|k| k.fingerprint());
                let next_fp = self
                    .application_recv
                    .as_ref()
                    .and_then(|k| k.next_key_phase().ok())
                    .map(|k| k.fingerprint());
                let initial_fp = if level == INITIAL {
                    Some(self.initial_recv.fingerprint())
                } else {
                    None
                };
                eprintln!(
                    "H3 auth-fail: {} long_type={:?} level={} len={} recv_phase={:?} send_phase={} phase_bit={:?} pn={} recv_fp={:?} next_fp={:?} send_fp={:?} initial_fp={:?} dcid={:?} scid={:?} token_len={}",
                    if self.server { "server" } else { "client" },
                    meta.long_type,
                    level,
                    datagram.len(),
                    recv_phase,
                    self.application_send_phase,
                    phase_bit,
                    expected,
                    recv_fp,
                    next_fp,
                    self.application_send.as_ref().map(|k| k.fingerprint()),
                    initial_fp,
                    meta.dcid,
                    meta.scid,
                    meta.token.len()
                );
            }
            return Ok(None);
        };
        if level == APPLICATION && next_phase {
            self.application_recv = Some(candidate);
            self.application_recv_phase = !self.application_recv_phase;
            if self.application_send_phase != self.application_recv_phase {
                if let Some(next_send) = self
                    .application_send
                    .as_ref()
                    .and_then(|k| k.next_key_phase().ok())
                {
                    self.application_send = Some(next_send);
                    self.application_send_phase = self.application_recv_phase;
                }
            }
            if self.application_send_phase == self.application_recv_phase {
                self.send_update_pending = false;
            }
            self.key_phase_packets = 0;
            if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                eprintln!(
                    "H3 key-update: {} mirrored peer update -> send_phase={} recv_phase={} pending={} counter={}",
                    if self.server { "server" } else { "client" },
                    self.application_send_phase,
                    self.application_recv_phase,
                    self.send_update_pending,
                    self.key_phase_packets
                );
            }
        }
        let adaptive_delay = self.current_ack_delay();
        let space = &mut self.spaces[level];
        if !space.received.insert(pn) {
            space.ack_pending = true;
            space.ack_deadline = Some(Instant::now() + adaptive_delay);
            return Ok(Some((level, pn, Vec::new(), meta.packet_end)));
        }
        if space.received.len() > 8192 {
            if let Some(first) = space.received.iter().next().copied() {
                space.received.remove(&first);
            }
        }
        if space.largest_received.map_or(true, |largest| pn > largest) {
            space.largest_received = Some(pn);
        }
        if !self.server && level == INITIAL && !meta.scid.is_empty() {
            self.remote_cid = meta.scid;
        }
        let frames = decode_quic_frames(&plaintext)?;
        let mut ack_eliciting = false;
        let mut acknowledged_bytes = 0usize;
        let mut rtt_sample = None;
        for frame in &frames {
            if !matches!(
                frame,
                QFrame::Ack { .. } | QFrame::Padding(_) | QFrame::ConnectionClose { .. }
            ) {
                ack_eliciting = true;
            }
            if let QFrame::Ack {
                largest_acked,
                ranges,
                ..
            } = frame
            {
                space.largest_acked = Some(
                    space
                        .largest_acked
                        .map_or(*largest_acked, |l| l.max(*largest_acked)),
                );
                let (bytes, sample) =
                    acknowledge(&mut space.sent, space.largest_sent, *largest_acked, ranges)?;
                acknowledged_bytes = acknowledged_bytes.saturating_add(bytes);
                rtt_sample = rtt_sample.or(sample);
            }
            match frame {
                QFrame::MaxData(max) => {
                    if h3_packet_trace() {
                        eprintln!(
                            "H3TRACE|{}|credit max_data={max} sent_data={} cwnd={}",
                            h3_role(self.server),
                            self.sent_data,
                            self.congestion_window
                        );
                    }
                    self.peer_max_data = self.peer_max_data.max(*max);
                }
                QFrame::MaxStreams {
                    unidirectional,
                    max,
                } => {
                    if *unidirectional {
                        self.peer_max_streams_uni = self.peer_max_streams_uni.max(*max);
                    } else {
                        self.peer_max_streams_bidi = self.peer_max_streams_bidi.max(*max);
                    }
                }
                QFrame::MaxStreamData { stream_id, max } => {
                    if h3_packet_trace() {
                        eprintln!(
                            "H3TRACE|{}|credit stream={stream_id} max={max}",
                            h3_role(self.server)
                        );
                    }
                    let limit = self.peer_stream_limits.entry(*stream_id).or_insert(0);
                    *limit = (*limit).max(*max);
                }
                _ => {}
            }
        }
        if ack_eliciting {
            if !space.ack_pending {
                space.ack_pending = true;
                space.ack_deadline = None;
            } else if let Some(deadline) = space.ack_deadline {
                if deadline > Instant::now() {
                    space.ack_deadline = Some(Instant::now() + adaptive_delay);
                }
            }
        }
        if acknowledged_bytes != 0 {
            self.on_acknowledgement(acknowledged_bytes, rtt_sample, level);
        }
        Ok(Some((level, pn, frames, meta.packet_end)))
    }

    fn on_acknowledgement(&mut self, bytes: usize, sample: Option<Duration>, level: LevelIndex) {
        if let Some(sample) = sample {
            self.latest_rtt = Some(sample);
            if self.smoothed_rtt.is_none() {
                self.smoothed_rtt = Some(sample);
                self.rtt_variance = sample / 2;
            } else if let Some(smoothed) = self.smoothed_rtt {
                let difference = if smoothed >= sample {
                    smoothed - sample
                } else {
                    sample - smoothed
                };
                self.rtt_variance = (self.rtt_variance * 3 + difference) / 4;
                self.smoothed_rtt = Some((smoothed * 7 + sample) / 8);
            }
        }
        if self.congestion_window < self.slow_start_threshold {
            self.congestion_window = self
                .congestion_window
                .saturating_add(bytes)
                .min(16 * 1024 * 1024);
        } else {
            let increment = 1200usize
                .saturating_mul(bytes)
                .checked_div(self.congestion_window.max(1))
                .unwrap_or(1)
                .max(1);
            self.congestion_window = self
                .congestion_window
                .saturating_add(increment)
                .min(16 * 1024 * 1024);
        }
        let _ = self.detect_lost_packets(level, Instant::now());
        if h3_packet_trace() {
            // ACK event: newly-acknowledged bytes and the cwnd after
            // growth — the release valve for a cwnd-paced upload.
            let rtt_us = self.latest_rtt.map_or(0, |d| d.as_micros() as u64);
            eprintln!(
                "H3TRACE|{}|ack acked_bytes={bytes} cwnd={} unacked={} rtt_us={rtt_us}",
                h3_role(self.server),
                self.congestion_window,
                self.unacknowledged_bytes()
            );
        }
    }

    /// RFC 9002 §6.1.1 time threshold: `9/8 * max(latest_rtt,
    /// smoothed_rtt) + max_ack_delay`, floored to absorb Windows timer
    /// granularity and scheduler jitter (a loopback RTT of ~0.3 ms would
    /// otherwise declare a packet lost while its ACK is still in flight,
    /// collapse the congestion window, and degrade a large transfer to a
    /// crawl).
    fn loss_detection_threshold(&self) -> Duration {
        let rtt = self
            .smoothed_rtt
            .or(self.latest_rtt)
            .unwrap_or(Duration::from_millis(100));
        let scaled = rtt
            .checked_mul(TIME_THRESHOLD_NUM)
            .map(|v| v / TIME_THRESHOLD_DEN)
            .unwrap_or(rtt);
        (scaled + ack_delay()).max(LOSS_TIMEOUT_FLOOR)
    }

    /// RFC 9002 §6.2.1: PTO = smoothed_rtt + max(4·rttvar, granularity) +
    /// max_ack_delay. A PTO expiry triggers a single retransmission (a
    /// probe) and does not by itself declare loss or collapse the
    /// congestion window — only time-threshold detection does.
    fn pto_timeout(&self) -> Duration {
        let Some(smoothed) = self.smoothed_rtt else {
            return Duration::from_millis(1000);
        };
        let variance = (self.rtt_variance * 4).max(Duration::from_millis(1));
        (smoothed + variance + ack_delay()).max(LOSS_TIMEOUT_FLOOR)
    }

    /// Declare ack-eliciting packets in `level` lost once they are older
    /// than the time threshold or `kPacketThreshold` packets behind the
    /// highest acknowledged packet (RFC 9002 §6.1.1). Returns the number
    /// of packets declared lost; the caller halves the congestion window
    /// once per invocation.
    fn detect_lost_packets(&mut self, level: LevelIndex, now: Instant) -> usize {
        let threshold = self.loss_detection_threshold();
        let rtt = self
            .smoothed_rtt
            .or(self.latest_rtt)
            .unwrap_or(Duration::from_millis(100));
        let reorder_window = (rtt / 8).max(Duration::from_millis(1));
        let space = &mut self.spaces[level];
        let largest_acked = space.largest_acked;
        let mut lost: Vec<u64> = Vec::new();
        for (&pn, packet) in &space.sent {
            if !packet.ack_eliciting || packet.pending_resend {
                continue;
            }
            let over_time = now.duration_since(packet.sent_at) >= threshold;
            let over_packet = largest_acked
                .is_some_and(|la| la.saturating_sub(pn) >= PACKET_THRESHOLD && pn < la)
                && now.duration_since(packet.sent_at) >= reorder_window;
            if over_time || over_packet {
                lost.push(pn);
            }
        }
        if lost.is_empty() {
            return 0;
        }
        for pn in &lost {
            space.sent.remove(pn);
        }
        self.on_loss();
        lost.len()
    }

    /// RFC 9002 §5.1 congestion window reaction to loss.
    fn on_loss(&mut self) {
        self.congestion_window = (self.congestion_window / 2).max(2400);
        self.slow_start_threshold = self.congestion_window;
    }

    fn send_crypto(&mut self, socket: &UdpSocket, level: LevelIndex, bytes: &[u8]) -> Result<()> {
        if level > HANDSHAKE {
            return Err(protocol(
                "CRYPTO is only valid in Initial or Handshake space",
            ));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let sent = usize::try_from(self.crypto_send_offsets[level])
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        for chunk in bytes[sent..].chunks(MAX_CRYPTO_CHUNK) {
            let offset = self.crypto_send_offsets[level];
            let frame = QFrame::Crypto {
                offset,
                data: chunk.to_vec(),
            };
            match self.send_frames(socket, level, &[frame], level == INITIAL) {
                Ok(()) => {}
                Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
            self.crypto_send_offsets[level] = offset
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| protocol("QUIC CRYPTO send offset overflow"))?;
        }
        Ok(())
    }

    fn send_stream(
        &mut self,
        socket: &UdpSocket,
        level: LevelIndex,
        id: u64,
        bytes: &[u8],
        fin: bool,
    ) -> Result<()> {
        self.send_stream_chunk(socket, level, id, 0, bytes, fin)
    }

    /// Append bytes to a stream at the next unwritten offset (unlike
    /// [`Self::send_stream`], which always starts at offset 0). Used by
    /// the QPACK encoder/decoder streams, which are written incrementally
    /// as instructions are produced; `sent_stream_data` tracks the
    /// per-stream send position.
    fn send_stream_append(
        &mut self,
        socket: &UdpSocket,
        level: LevelIndex,
        id: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let offset = self.sent_stream_data.get(&id).copied().unwrap_or(0);
        self.send_stream_chunk(socket, level, id, offset, bytes, false)
    }

    fn send_stream_chunk(
        &mut self,
        socket: &UdpSocket,
        level: LevelIndex,
        id: u64,
        offset: u64,
        bytes: &[u8],
        fin: bool,
    ) -> Result<()> {
        if level == APPLICATION && !bytes.is_empty() {
            let end = offset
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| protocol("QUIC stream send offset overflow"))?;
            if end > self.peer_stream_send_limit(id) {
                return Err(protocol("QUIC peer stream flow-control limit exceeded"));
            }
            let previous = self.sent_stream_data.get(&id).copied().unwrap_or(0);
            let newly_sent = end.saturating_sub(previous);
            if self.sent_data.saturating_add(newly_sent) > self.peer_max_data {
                return Err(protocol("QUIC peer connection flow-control limit exceeded"));
            }
            self.sent_data = self.sent_data.saturating_add(newly_sent);
            self.sent_stream_data.insert(id, previous.max(end));
        }
        let frame = QFrame::Stream {
            stream_id: id,
            offset: (offset != 0).then_some(offset),
            data: bytes.to_vec(),
            length: Some(bytes.len() as u64),
            fin,
        };
        self.send_frames(socket, level, &[frame], false)
    }

    fn queue_stream_wire(&mut self, id: u64, wire: Vec<u8>) -> Result<()> {
        if wire.len() > 32 * 1024 * 1024 {
            return Err(protocol("HTTP/3 response stream exceeds queue limit"));
        }
        let queued = self
            .queued_streams
            .iter()
            .map(|s| s.wire.len().saturating_sub(s.offset))
            .fold(0usize, usize::saturating_add);
        if queued.saturating_add(wire.len()) > MAX_H3_CONNECTION_BUFFER {
            return Err(protocol("HTTP/3 response queue limit exceeded"));
        }
        self.queued_streams.push_back(QueuedStream {
            id,
            wire,
            offset: 0,
            queued_at: Instant::now(),
        });
        if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
            eprintln!(
                "H3SERVER wire-queued: stream={} len={}",
                id,
                self.queued_streams.back().map_or(0, |s| s.wire.len())
            );
        }
        if let Some(stats) = self.stats.as_deref() {
            Stats::bump_peak(&stats.h3_queue_depth_peak, self.queued_streams.len());
        }
        Ok(())
    }

    fn queued_bytes(&self) -> usize {
        self.queued_streams
            .iter()
            .map(|s| s.wire.len().saturating_sub(s.offset))
            .fold(0usize, usize::saturating_add)
    }

    fn flush_queued_streams(&mut self, socket: &UdpSocket) -> Result<()> {
        while let Some(queued) = self.queued_streams.pop_front() {
            if let Some(threshold) = h3_trace_threshold_us() {
                let wait = Instant::now().duration_since(queued.queued_at).as_micros() as u64;
                if wait > threshold {
                    eprintln!(
                        "H3TRACE|server|response-queue-wait|stream={}|wait_us={wait}|offset={}/{}|cwnd={}|unacked={}",
                        queued.id,
                        queued.offset,
                        queued.wire.len(),
                        self.congestion_window,
                        self.unacknowledged_bytes(),
                    );
                }
            }
            let id = queued.id;
            let wire = queued.wire;
            let offset = queued.offset;
            if wire.is_empty() {
                if let Err(error) = self.send_stream_chunk(socket, APPLICATION, id, 0, &[], true) {
                    if error.kind == ErrorKind::WouldBlock {
                        self.queued_streams.push_front(QueuedStream {
                            id,
                            wire,
                            offset,
                            queued_at: queued.queued_at,
                        });
                        return Ok(());
                    }
                    return Err(error);
                }
                continue;
            }
            let mut offset = offset;
            while offset < wire.len() {
                let take = (wire.len() - offset).min(1000);
                let end = offset + take;
                let result = self.send_stream_chunk(
                    socket,
                    APPLICATION,
                    id,
                    offset as u64,
                    &wire[offset..end],
                    end == wire.len(),
                );
                if let Err(error) = result {
                    if error.kind == ErrorKind::WouldBlock {
                        if std::env::var_os("COURIERUST_H3_DEBUG").is_some()
                            && wire.len() > 100 * 1024
                        {
                            eprintln!(
                                "H3SERVER wire-deferred: stream={} offset={}/{} cwnd={} unacked={}",
                                id,
                                offset,
                                wire.len(),
                                self.congestion_window,
                                self.unacknowledged_bytes()
                            );
                        }
                        self.queued_streams.push_front(QueuedStream {
                            id,
                            wire,
                            offset,
                            queued_at: queued.queued_at,
                        });
                        return Ok(());
                    }
                    return Err(error);
                }
                offset = end;
            }
        }
        Ok(())
    }

    /// Adaptive ACK batch window: `2 × smoothed_rtt` clamped to
    /// [MIN_ACK_DELAY, ACK_DELAY], so loopback/DC flows are not paced by a
    /// constant 2 ms while WAN flows keep a bounded batch for bursts.
    fn current_ack_delay(&self) -> Duration {
        let Some(smoothed) = self.smoothed_rtt else {
            return ack_delay();
        };
        let window = smoothed.saturating_mul(2);
        window.clamp(min_ack_delay(), ack_delay())
    }

    fn flush_ack(&mut self, socket: &UdpSocket, level: LevelIndex) -> Result<()> {
        if !self.spaces[level].ack_pending {
            return Ok(());
        }
        if self.spaces[level]
            .ack_deadline
            .is_some_and(|deadline| deadline > Instant::now())
        {
            if let Some(stats) = self.stats.as_deref() {
                stats.h3_ack_deferred.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(());
        }
        let Some(largest) = self.spaces[level].largest_received else {
            return Ok(());
        };
        let ranges = ack_ranges(&self.spaces[level].received, largest);
        let frame = QFrame::Ack {
            largest_acked: largest,
            ack_delay: 0,
            ranges,
            ecn: None,
        };
        match self.send_frames(socket, level, &[frame], false) {
            Ok(()) => {
                self.spaces[level].ack_pending = false;
                self.spaces[level].ack_deadline = None;
                Ok(())
            }
            Err(error) if error.kind == ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Retry any ACK deferred by a full send buffer. Called every tick so
    /// a deferred ACK is not left waiting for the peer's retransmission.
    fn flush_acks(&mut self, socket: &UdpSocket) -> Result<()> {
        for level in [INITIAL, HANDSHAKE, APPLICATION] {
            self.flush_ack(socket, level)?;
        }
        Ok(())
    }

    /// Replenish the connection-level receive window as the application
    /// consumes received data. Once the peer has used more than half of
    /// the currently advertised credit, advertise a fresh full window via
    /// `MAX_DATA`, so a long-lived connection is never capped at
    /// `initial_max_data` (previously the connection was torn down as soon
    /// as the cumulative transfer exceeded it).
    fn replenish_connection_window(&mut self, socket: &UdpSocket) -> Result<()> {
        let headroom = self.local_max_data.saturating_sub(self.received_data);
        if headroom > self.local_max_data / 2 {
            return Ok(());
        }
        let new_limit = self
            .received_data
            .saturating_add(self.local_max_data)
            .min(crate::courierust_quic::varint::MAX);
        if new_limit <= self.local_max_data {
            return Ok(());
        }
        self.local_max_data = new_limit;
        match self.send_frames(socket, APPLICATION, &[QFrame::MaxData(new_limit)], false) {
            Ok(()) => Ok(()),
            // A full send buffer defers the update; retry on the next tick.
            Err(error) if error.kind == ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Replenish per-stream receive windows as the application consumes
    /// data (RFC 9000 §4.1). Once a stream's peer has used more than
    /// half of the currently advertised limit, advertise a fresh window
    /// via `MAX_STREAM_DATA` so a long-lived stream is never capped at
    /// `initial_max_stream_data_*`.
    fn replenish_stream_windows(&mut self, socket: &UdpSocket) -> Result<()> {
        let mut updates: Vec<(u64, u64)> = Vec::new();
        for (&id, &received) in &self.received_stream_data {
            let default_limit = if stream_id::is_unidirectional(id) {
                self.local_max_stream_data_uni
            } else if stream_id::is_client_initiated(id) != self.server {
                self.local_max_stream_data_bidi_local
            } else {
                self.local_max_stream_data_bidi_remote
            };
            let headroom = default_limit.saturating_sub(received);
            if headroom <= default_limit / 2 {
                let new_limit = received
                    .saturating_add(default_limit)
                    .min(crate::courierust_quic::varint::MAX);
                updates.push((id, new_limit));
            }
        }
        for (id, new_limit) in updates {
            let advertised = self.local_stream_limits.entry(id).or_insert(0);
            if new_limit <= *advertised {
                continue;
            }
            *advertised = new_limit;
            match self.send_frames(
                socket,
                APPLICATION,
                &[QFrame::MaxStreamData {
                    stream_id: id,
                    max: new_limit,
                }],
                false,
            ) {
                Ok(()) => {}
                // A full send buffer defers the update; retry next tick.
                Err(error) if error.kind == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Replenish the advertised stream-count limits as the peer opens
    /// streams (RFC 9000 §4.6). Once the peer has used more than half of a
    /// limit, advertise a fresh limit via MAX_STREAMS so a long-lived
    /// connection can keep opening streams — otherwise a peer such as
    /// quinn stops at the initial limit (1024 bidi streams) and the next
    /// request times out.
    fn replenish_stream_limits(&mut self, socket: &UdpSocket) -> Result<()> {
        let mut updates = Vec::new();
        let bidi_headroom = self
            .local_max_streams_bidi
            .saturating_sub(self.received_streams_bidi);
        if bidi_headroom <= self.local_max_streams_bidi / 2 {
            let new_limit = self
                .received_streams_bidi
                .saturating_add(self.local_max_streams_bidi)
                .min(crate::courierust_quic::varint::MAX);
            if new_limit > self.local_max_streams_bidi {
                updates.push((false, new_limit));
            }
        }
        let uni_headroom = self
            .local_max_streams_uni
            .saturating_sub(self.received_streams_uni);
        if uni_headroom <= self.local_max_streams_uni / 2 {
            let new_limit = self
                .received_streams_uni
                .saturating_add(self.local_max_streams_uni)
                .min(crate::courierust_quic::varint::MAX);
            if new_limit > self.local_max_streams_uni {
                updates.push((true, new_limit));
            }
        }
        for (unidirectional, new_limit) in updates {
            let slot = if unidirectional {
                &mut self.local_max_streams_uni
            } else {
                &mut self.local_max_streams_bidi
            };
            if new_limit <= *slot {
                continue;
            }
            *slot = new_limit;
            if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                eprintln!(
                    "H3 maxstreams: {} uni={} new_limit={} received_bidi={} received_uni={}",
                    if self.server { "server" } else { "client" },
                    unidirectional,
                    new_limit,
                    self.received_streams_bidi,
                    self.received_streams_uni,
                );
            }
            match self.send_frames(
                socket,
                APPLICATION,
                &[QFrame::MaxStreams {
                    unidirectional,
                    max: new_limit,
                }],
                false,
            ) {
                Ok(()) => {}
                // A full send buffer defers the update; retry next tick.
                Err(error) if error.kind == ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Automatic bidirectional key update (RFC 9001 §6): after a
    /// configurable number of packets on the current application key
    /// phase, the endpoint derives the next packet-protection keys and
    /// toggles the key phase, so long-lived connections refresh their
    /// AEAD keys in both directions instead of reusing one generation
    /// indefinitely.
    ///
    /// The packet number space is deliberately NOT reset on a key update:
    /// RFC 9001 §6.1 only requires the new phase to not reuse a packet
    /// number, and continuing the sequence keeps the peer's packet-number
    /// recovery (`expected = largest_received + 1`) valid across phases.
    fn maybe_key_update(&mut self) {
        let threshold = key_update_threshold();
        if self.send_update_pending
            || self.application_send.is_none()
            || self.key_phase_packets < threshold
        {
            return;
        }
        if let Some(next) = self
            .application_send
            .as_ref()
            .and_then(|k| k.next_key_phase().ok())
        {
            self.application_send = Some(next);
            self.application_send_phase = !self.application_send_phase;
            self.key_phase_packets = 0;
            self.send_update_pending = true;
            if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                eprintln!(
                    "H3 key-update: {} initiated -> send_phase={} recv_phase={} pending=true counter={} fp={:?}",
                    if self.server { "server" } else { "client" },
                    self.application_send_phase,
                    self.application_recv_phase,
                    self.key_phase_packets,
                    self.application_send.as_ref().map(|k| k.fingerprint()),
                );
            }
        }
    }

    fn retransmit(&mut self, socket: &UdpSocket) -> Result<()> {
        let now = Instant::now();
        let lost_threshold = self.loss_detection_threshold();
        let pto = self.pto_timeout();
        let mut resend: Vec<(u64, LevelIndex, Vec<QFrame>, bool, u8)> = Vec::new();
        let mut lost = false;
        let mut probe_armed = false;

        for level in [INITIAL, HANDSHAKE, APPLICATION] {
            let mut expired: Vec<(u64, Vec<QFrame>, bool, u8)> = Vec::new();
            let mut earliest_ack_eliciting: Option<(u64, Instant)> = None;
            {
                let space = &mut self.spaces[level];
                for (&pn, packet) in &mut space.sent {
                    if !packet.ack_eliciting {
                        continue;
                    }
                    let pending = packet.pending_resend;
                    let aged_out = now.duration_since(packet.sent_at) >= lost_threshold;
                    if pending || aged_out {
                        if !pending {
                            if packet.retransmits >= MAX_RETRANSMITS {
                                if std::env::var_os("COURIERUST_H3_DEBUG").is_some() {
                                    eprintln!(
                                        "H3CLIENT retransmit-limit: level={level} pn={pn} retransmits={} sent_bytes={} cwnd={} largest_sent={:?} largest_acked={:?} sent_at_ms={}",
                                        packet.retransmits,
                                        self.sent_data,
                                        self.congestion_window,
                                        space.largest_sent,
                                        space.largest_acked,
                                        now.duration_since(packet.sent_at).as_millis(),
                                    );
                                }
                                return Err(protocol(
                                    "QUIC packet loss exceeded retransmission limit",
                                ));
                            }
                            packet.retransmits += 1;
                            lost = true;
                        }
                        expired.push((
                            pn,
                            packet.frames.clone(),
                            packet.pad_initial,
                            packet.retransmits,
                        ));
                    }
                    if earliest_ack_eliciting.is_none()
                        || packet.sent_at < earliest_ack_eliciting.unwrap().1
                    {
                        earliest_ack_eliciting = Some((pn, packet.sent_at));
                    }
                }
                for (pn, _, _, _) in &expired {
                    space.sent.remove(pn);
                }
            }
            if expired.is_empty() && !probe_armed {
                if let Some((pn, sent_at)) = earliest_ack_eliciting {
                    if now.duration_since(sent_at) >= pto {
                        if let Some(packet) = self.spaces[level].sent.get(&pn) {
                            if packet.retransmits < MAX_RETRANSMITS {
                                probe_armed = true;
                                expired.push((
                                    pn,
                                    packet.frames.clone(),
                                    packet.pad_initial,
                                    packet.retransmits,
                                ));
                                self.spaces[level].sent.remove(&pn);
                            }
                        }
                    }
                }
            }
            for (pn, frames, pad_initial, retransmits) in expired {
                resend.push((pn, level, frames, pad_initial, retransmits));
            }
        }
        if lost {
            self.on_loss();
        }
        if h3_packet_trace() && (lost || probe_armed) {
            eprintln!(
                "H3TRACE|client|retransmit lost={lost} probe={probe_armed} cwnd={} unacked={}",
                self.congestion_window,
                self.unacknowledged_bytes()
            );
        }
        for (pn, level, frames, pad_initial, retransmits) in resend {
            match self.send_frames_with_retransmits(
                socket,
                level,
                &frames,
                pad_initial,
                retransmits,
            ) {
                Ok(()) => {}
                Err(error) if error.kind == ErrorKind::WouldBlock => {
                    let previous = self.spaces[level].sent.insert(
                        pn,
                        SentPacket {
                            frames,
                            pad_initial,
                            sent_at: now,
                            retransmits,
                            ack_eliciting: true,
                            size: 0,
                            pending_resend: true,
                        },
                    );
                    debug_assert!(previous.is_none());
                }
                Err(error) => return Err(error),
            }
        }
        self.flush_queued_streams(socket)
    }

    fn send_frames(
        &mut self,
        socket: &UdpSocket,
        level: LevelIndex,
        frames: &[QFrame],
        pad_initial: bool,
    ) -> Result<()> {
        self.send_frames_with_retransmits(socket, level, frames, pad_initial, 0)
    }

    /// Send frames to an explicit destination (used for the PATH_CHALLENGE
    /// probe to an unvalidated address during RFC 9000 §9.3 validation).
    fn send_frames_to(
        &mut self,
        socket: &UdpSocket,
        level: LevelIndex,
        frames: &[QFrame],
        pad_initial: bool,
        dest: SocketAddr,
    ) -> Result<()> {
        self.send_frames_inner(socket, level, frames, pad_initial, 0, Some(dest))
    }

    fn send_frames_with_retransmits(
        &mut self,
        socket: &UdpSocket,
        level: LevelIndex,
        frames: &[QFrame],
        pad_initial: bool,
        retransmits: u8,
    ) -> Result<()> {
        self.send_frames_inner(socket, level, frames, pad_initial, retransmits, None)
    }

    fn send_frames_inner(
        &mut self,
        socket: &UdpSocket,
        level: LevelIndex,
        frames: &[QFrame],
        pad_initial: bool,
        retransmits: u8,
        dest: Option<SocketAddr>,
    ) -> Result<()> {
        let due_ack = !frames
            .iter()
            .any(|frame| matches!(frame, QFrame::Ack { .. }))
            && self.spaces[level].ack_pending
            && self.spaces[level]
                .ack_deadline
                .map_or(true, |deadline| deadline <= Instant::now());
        let mut piggyback = Vec::new();
        let frames = if due_ack {
            if let Some(largest) = self.spaces[level].largest_received {
                let ranges = ack_ranges(&self.spaces[level].received, largest);
                piggyback.push(QFrame::Ack {
                    largest_acked: largest,
                    ack_delay: 0,
                    ranges,
                    ecn: None,
                });
                self.spaces[level].ack_pending = false;
                self.spaces[level].ack_deadline = None;
                piggyback.extend_from_slice(frames);
                piggyback.as_slice()
            } else {
                frames
            }
        } else {
            frames
        };
        let key = match level {
            INITIAL => self.initial_send.clone(),
            HANDSHAKE => self
                .handshake_send
                .clone()
                .ok_or_else(|| protocol("QUIC handshake send key is unavailable"))?,
            APPLICATION => self
                .application_send
                .clone()
                .ok_or_else(|| protocol("QUIC application send key is unavailable"))?,
            _ => return Err(protocol("invalid QUIC packet-number space")),
        };
        let pn = self.spaces[level].next_send;
        self.spaces[level].next_send = self.spaces[level]
            .next_send
            .checked_add(1)
            .ok_or_else(|| protocol("QUIC packet number exhausted"))?;
        self.spaces[level].largest_sent =
            Some(self.spaces[level].largest_sent.map_or(pn, |l| l.max(pn)));
        let mut plaintext = Vec::new();
        for frame in frames {
            frame.encode(&mut plaintext);
        }
        if plaintext.len() < 4 {
            plaintext.resize(4, 0);
        }
        let long_type = match level {
            INITIAL => Some(LongType::Initial),
            HANDSHAKE => Some(LongType::Handshake),
            _ => None,
        };
        let pn_len = 4usize;
        let mut header;
        let mut sealed;
        let mut wire;
        loop {
            if let Some(packet_type) = long_type {
                header = packet::encode_long(
                    packet_type,
                    &self.remote_cid,
                    &self.local_cid,
                    pn,
                    pn_len,
                    if !self.server && level == INITIAL {
                        &self.initial_token
                    } else {
                        &[]
                    },
                    (pn_len + plaintext.len() + 16) as u64,
                )?;
            } else {
                header = packet::encode_short(
                    &self.remote_cid,
                    pn,
                    pn_len,
                    self.application_send_phase,
                )?;
            }
            sealed = key.seal(pn, &header, &plaintext)?;
            wire = header.clone();
            wire.extend_from_slice(&sealed);
            if pad_initial && wire.len() < MIN_INITIAL_DATAGRAM {
                plaintext.resize(plaintext.len() + (MIN_INITIAL_DATAGRAM - wire.len()), 0);
                continue;
            }
            break;
        }
        let pn_offset = header.len() - pn_len;
        key.protect_header(&mut wire, pn_offset, long_type.is_some())?;
        if wire.len() > self.max_packet_size {
            return Err(protocol(
                "QUIC packet exceeds the peer's max_udp_payload_size",
            ));
        }
        let ack_eliciting = frames.iter().any(|frame| {
            !matches!(
                frame,
                QFrame::Ack { .. } | QFrame::Padding(_) | QFrame::ConnectionClose { .. }
            )
        });
        if ack_eliciting
            && self.unacknowledged_bytes().saturating_add(wire.len()) > self.congestion_window
        {
            if let Some(stats) = self.stats.as_deref() {
                stats.h3_credit_stalls.fetch_add(1, Ordering::Relaxed);
            }
            return Err(Error::new(ErrorKind::WouldBlock));
        }
        if h3_packet_trace() {
            let mut stream_bytes = 0usize;
            let mut first_stream = None;
            for frame in frames {
                if let QFrame::Stream {
                    stream_id, data, ..
                } = frame
                {
                    stream_bytes = stream_bytes.saturating_add(data.len());
                    first_stream = Some(*stream_id);
                }
            }
            eprintln!(
                "H3TRACE|{}|send pn={pn} level={level} wire={} ack_eliciting={ack_eliciting} stream={first_stream:?} stream_bytes={stream_bytes} cwnd={} unacked={}",
                h3_role(self.server),
                wire.len(),
                self.congestion_window,
                self.unacknowledged_bytes()
            );
        }
        self.send_wire(socket, &wire, dest)?;
        if level == APPLICATION {
            self.key_phase_packets = self.key_phase_packets.saturating_add(1);
        }
        if ack_eliciting {
            self.spaces[level].sent.insert(
                pn,
                SentPacket {
                    frames: frames.to_vec(),
                    pad_initial,
                    sent_at: Instant::now(),
                    retransmits,
                    ack_eliciting,
                    size: wire.len(),
                    pending_resend: false,
                },
            );
        }
        Ok(())
    }

    fn unacknowledged_bytes(&self) -> usize {
        self.spaces
            .iter()
            .flat_map(|space| space.sent.values())
            .map(|packet| packet.size)
            .fold(0usize, usize::saturating_add)
    }

    /// The earliest instant at which a protocol timer fires: a pending
    /// ACK batch deadline, the path-validation timeout, or the
    /// loss/PTO timer of the oldest ack-eliciting packet in flight. The
    /// reactor folds this into its poll timeout so every protocol event
    /// is handled on time even when no datagram wakes it — without it, a
    /// deferred ACK or loss timer waits for the next fixed poll tick,
    /// which is the multi-millisecond H3 loopback tail.
    fn earliest_deadline(&self) -> Option<Instant> {
        let now = Instant::now();
        let mut earliest: Option<Instant> = None;
        let loss = self.loss_detection_threshold();
        let pto = self.pto_timeout();
        for space in &self.spaces {
            if let Some(deadline) = space.ack_deadline {
                earliest = Some(earliest.map_or(deadline, |e| e.min(deadline)));
            }
            // Loss detection / PTO: the oldest ack-eliciting packet in
            // flight sets the timer, and the earlier of the two applies.
            // `pending_resend` packets have no timer (they are retried on
            // datagram wakes / the fixed poll), so they are excluded.
            let oldest = space
                .sent
                .values()
                .filter(|packet| packet.ack_eliciting && !packet.pending_resend)
                .map(|packet| packet.sent_at)
                .min();
            if let Some(oldest) = oldest {
                let deadline = oldest + loss.min(pto);
                earliest = Some(earliest.map_or(deadline, |e| e.min(deadline)));
            }
        }
        if let Some(sent) = self.path_challenge_sent {
            let deadline = sent + PATH_VALIDATION_TIMEOUT;
            earliest = Some(earliest.map_or(deadline, |e| e.min(deadline)));
        }
        // A deadline already in the past is "due now"; the caller treats
        // that as an immediate poll return.
        earliest.filter(|deadline| *deadline > now)
    }

    /// Whether any packet is in flight awaiting an ACK (drives the
    /// driver's periodic retransmit pacing).
    fn has_unacknowledged(&self) -> bool {
        self.spaces.iter().any(|space| !space.sent.is_empty())
    }

    fn send_wire(&self, socket: &UdpSocket, wire: &[u8], dest: Option<SocketAddr>) -> Result<()> {
        if let Some(stats) = self.stats.as_deref() {
            stats.h3_udp_send_syscalls.fetch_add(1, Ordering::Relaxed);
        }
        send_datagram(socket, dest.or(self.peer), wire)
    }

    // -----------------------------------------------------------------
    // Path validation (RFC 9000 §9.3) — connection migration / NAT
    // rebinding.
    // -----------------------------------------------------------------

    /// Validate a new peer address before switching traffic to it. Only a
    /// small PATH_CHALLENGE probe is sent to the candidate; all other
    /// traffic continues on the validated path until PATH_RESPONSE commits
    /// the migration (anti-amplification / anti-hijacking).
    fn initiate_path_validation(
        &mut self,
        socket: &UdpSocket,
        candidate: SocketAddr,
    ) -> Result<()> {
        // RFC 9000 §9.6: an endpoint that set disable_active_migration
        // must not be actively migrated to.
        if self.peer_disable_active_migration && !self.server {
            return Ok(());
        }
        let mut token = [0u8; 8];
        if !crate::courierust_tls::crypto::rng::fill_random(&mut token) {
            return Err(protocol("OS randomness unavailable for PATH_CHALLENGE"));
        }
        self.pending_peer = Some(candidate);
        self.path_challenge = Some(token);
        self.path_challenge_sent = Some(Instant::now());
        self.send_frames_to(
            socket,
            APPLICATION,
            &[QFrame::PathChallenge(token)],
            false,
            candidate,
        )
    }

    /// Respond to a PATH_CHALLENGE on the path the challenge arrived on
    /// (RFC 9000 §9.3.2): echo the 8-byte token back to the sender.
    fn handle_path_challenge(&mut self, socket: &UdpSocket, token: [u8; 8], source: SocketAddr) {
        let _ = self.send_frames_to(
            socket,
            APPLICATION,
            &[QFrame::PathResponse(token)],
            false,
            source,
        );
    }

    /// Commit a validated migration: the PATH_RESPONSE echoes our token
    /// and arrives from the candidate address.
    fn handle_path_response(&mut self, token: &[u8; 8], source: SocketAddr) {
        if self.pending_peer != Some(source) || self.path_challenge.as_ref() != Some(token) {
            return;
        }
        self.peer = Some(source);
        self.pending_peer = None;
        self.path_challenge = None;
        self.path_challenge_sent = None;
    }

    /// Re-send or abandon an unanswered PATH_CHALLENGE. A challenge older
    /// than the probe timeout is retried once, then abandoned (the old
    /// path stays authoritative).
    fn check_path_validation_timeout(&mut self, socket: &UdpSocket, now: Instant) -> Result<()> {
        let Some(sent) = self.path_challenge_sent else {
            return Ok(());
        };
        if now.duration_since(sent) < PATH_VALIDATION_TIMEOUT {
            return Ok(());
        }
        let Some(candidate) = self.pending_peer else {
            self.path_challenge_sent = None;
            return Ok(());
        };
        let Some(token) = self.path_challenge else {
            return Ok(());
        };
        // Retry once, then abandon the pending path.
        if self.path_validation_retries < 1 {
            self.path_validation_retries += 1;
            self.path_challenge_sent = Some(now);
            self.send_frames_to(
                socket,
                APPLICATION,
                &[QFrame::PathChallenge(token)],
                false,
                candidate,
            )?;
        } else {
            self.pending_peer = None;
            self.path_challenge = None;
            self.path_challenge_sent = None;
            self.path_validation_retries = 0;
        }
        Ok(())
    }

    fn send_connection_close(
        &mut self,
        socket: &UdpSocket,
        error_code: u64,
        frame_type: Option<u64>,
        reason: &str,
    ) -> Result<()> {
        let level = if self.application_send.is_some() {
            APPLICATION
        } else if self.handshake_send.is_some() {
            HANDSHAKE
        } else {
            INITIAL
        };
        let mut reason_bytes = reason.as_bytes().to_vec();
        reason_bytes.truncate(256);
        self.send_frames(
            socket,
            level,
            &[QFrame::ConnectionClose {
                error_code,
                frame_type,
                reason: reason_bytes,
            }],
            level == INITIAL,
        )
    }
}

fn send_datagram(socket: &UdpSocket, peer: Option<SocketAddr>, wire: &[u8]) -> Result<()> {
    let result = match peer {
        Some(peer) => socket.send_to(wire, peer),
        None => socket.send(wire),
    };
    match result {
        Ok(_) => Ok(()),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Err(Error::new(ErrorKind::WouldBlock))
        }
        Err(e) => Err(io_error(e.to_string())),
    }
}

fn ack_ranges(received: &BTreeSet<u64>, largest: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut iter = received.range(..=largest).rev();
    let Some(mut high) = iter.next().copied() else {
        return vec![(0, 0)];
    };
    let mut low = high;
    let mut pending_gap: Option<u64> = None;
    for packet_number in iter {
        if *packet_number + 1 == low {
            low = *packet_number;
            continue;
        }
        let gap = low.saturating_sub(*packet_number).saturating_sub(2);
        ranges.push((pending_gap.unwrap_or(0), high.saturating_sub(low)));
        pending_gap = Some(gap);
        high = *packet_number;
        low = *packet_number;
    }
    ranges.push((pending_gap.unwrap_or(0), high.saturating_sub(low)));
    ranges
}

fn acknowledge(
    sent: &mut BTreeMap<u64, SentPacket>,
    largest_sent_ever: Option<u64>,
    largest: u64,
    ranges: &[(u64, u64)],
) -> Result<(usize, Option<Duration>)> {
    if largest_sent_ever.map_or(true, |max| largest > max) {
        return Err(protocol("ACK acknowledges an unsent packet number"));
    }
    let now = Instant::now();
    let mut acknowledged_bytes = 0usize;
    let mut rtt_sample = None;
    let mut high = largest;
    for (index, (gap, length)) in ranges.iter().enumerate() {
        let low = match high.checked_sub(*length) {
            Some(v) => v,
            None => break,
        };
        let acknowledged: Vec<u64> = sent.range(low..=high).map(|(&pn, _)| pn).collect();
        for pn in acknowledged {
            if let Some(packet) = sent.remove(&pn) {
                acknowledged_bytes = acknowledged_bytes.saturating_add(packet.size);
                rtt_sample = rtt_sample.or_else(|| now.checked_duration_since(packet.sent_at));
            }
        }
        if index + 1 < ranges.len() {
            let gap_plus_two = match gap.checked_add(2) {
                Some(value) => value,
                None => break,
            };
            high = match low.checked_sub(gap_plus_two) {
                Some(v) => v,
                None => break,
            };
        }
    }
    Ok((acknowledged_bytes, rtt_sample))
}

fn decode_quic_frames(buf: &[u8]) -> Result<Vec<QFrame>> {
    let mut pos = 0usize;
    let mut frames = Vec::new();
    while pos < buf.len() {
        if frames.len() >= MAX_PACKET_FRAMES {
            return Err(protocol("too many QUIC frames in one packet"));
        }
        let (frame, used) = QFrame::decode(&buf[pos..])?;
        if used == 0 || used > buf.len() - pos {
            return Err(protocol("QUIC frame decoder made no progress"));
        }
        pos += used;
        frames.push(frame);
    }
    Ok(frames)
}

/// Try to open one packet with a specific key: header protection is
/// removed in place on a single copy, then the AEAD tag is verified.
/// Returns `Ok(None)` when the header cannot be unprotected or the tag
/// does not verify (wrong key, key phase, or corrupted packet).
fn open_packet_with_key(
    datagram: &mut [u8],
    meta: &PacketMeta,
    key: &PacketKey,
    expected_pn: u64,
    expected_phase: Option<bool>,
) -> Result<Option<(u64, Vec<u8>)>> {
    let header_room = meta.pn_offset.saturating_add(4).min(datagram.len());
    // Header protection is removed in place. A failed attempt (phase
    // mismatch OR an invalid recovered header) must restore the original
    // bytes before returning, because the caller retries with the next
    // key phase on the same buffer: unprotecting once with the wrong
    // phase's HP key corrupts the first byte and packet number, and any
    // subsequent attempt then computes a wrong AAD and can never succeed.
    let saved = expected_phase
        .is_some()
        .then(|| datagram[..header_room].to_vec());
    let pn_len = match key.unprotect_header(datagram, meta.pn_offset, meta.long_type.is_some()) {
        Ok(pn_len) => pn_len,
        Err(_) => {
            if let Some(saved) = &saved {
                datagram[..header_room].copy_from_slice(saved);
            }
            return Ok(None);
        }
    };
    if let Some(expected_phase) = expected_phase {
        // Key phase is bit 2 (0x04) of the short header (RFC 9000
        // §17.3.1); bits 4-3 (0x18) are reserved.
        let phase = datagram[0] & 0x04 != 0;
        if phase != expected_phase {
            if let Some(saved) = &saved {
                datagram[..header_room].copy_from_slice(saved);
            }
            return Ok(None);
        }
    }
    let payload_start = meta.pn_offset.saturating_add(pn_len);
    if payload_start > meta.packet_end {
        if let Some(saved) = &saved {
            datagram[..header_room].copy_from_slice(saved);
        }
        // Malformed packet (packet number runs past the end): drop it
        // rather than terminate the connection (RFC 9000 §5.2 — the
        // header is not authenticated at this point).
        return Ok(None);
    }
    let pn = packet::decode_pn(
        &datagram[meta.pn_offset..payload_start],
        expected_pn,
        pn_len,
    );
    match key.open(
        pn,
        &datagram[..payload_start],
        &datagram[payload_start..meta.packet_end],
    ) {
        Ok(plaintext) => Ok(Some((pn, plaintext))),
        Err(_) => {
            if let Some(saved) = &saved {
                datagram[..header_room].copy_from_slice(saved);
            }
            Ok(None)
        }
    }
}

struct PacketMeta {
    long_type: Option<LongType>,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    pn_offset: usize,
    packet_end: usize,
    token: Vec<u8>,
}

impl PacketMeta {
    fn parse(buf: &[u8], local_cid_len: usize) -> Result<Self> {
        let first = *buf.first().ok_or_else(|| protocol("empty QUIC datagram"))?;
        if first & 0x40 == 0 {
            return Err(protocol("QUIC fixed bit is not set"));
        }
        if first & 0x80 == 0 {
            let pn_offset = 1usize
                .checked_add(local_cid_len)
                .ok_or_else(|| protocol("QUIC short-header offset overflow"))?;
            if buf.len() < pn_offset + 1 {
                return Err(protocol("truncated QUIC short header"));
            }
            return Ok(Self {
                long_type: None,
                dcid: buf[1..pn_offset].to_vec(),
                scid: Vec::new(),
                pn_offset,
                packet_end: buf.len(),
                token: Vec::new(),
            });
        }
        if buf.len() < 7 {
            return Err(protocol("truncated QUIC long header"));
        }
        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if version != crate::courierust_quic::VERSION_1 {
            return Err(protocol("unsupported QUIC version"));
        }
        let packet_type = match (first >> 4) & 0x03 {
            0 => LongType::Initial,
            1 => LongType::ZeroRtt,
            2 => LongType::Handshake,
            _ => LongType::Retry,
        };
        if packet_type == LongType::Retry {
            return Err(protocol(
                "QUIC Retry packets are not supported by this endpoint",
            ));
        }
        let dcid_len = buf[5] as usize;
        let mut pos = 6usize;
        let dcid_end = pos
            .checked_add(dcid_len)
            .ok_or_else(|| protocol("QUIC DCID overflow"))?;
        if dcid_len > 20 || dcid_end >= buf.len() {
            return Err(protocol("invalid QUIC DCID length"));
        }
        let dcid = buf[pos..dcid_end].to_vec();
        pos = dcid_end;
        let scid_len = buf[pos] as usize;
        pos += 1;
        let scid_end = pos
            .checked_add(scid_len)
            .ok_or_else(|| protocol("QUIC SCID overflow"))?;
        if scid_len > 20 || scid_end > buf.len() {
            return Err(protocol("invalid QUIC SCID length"));
        }
        let scid = buf[pos..scid_end].to_vec();
        pos = scid_end;
        let token = if packet_type == LongType::Initial {
            let (len, used) =
                varint::decode(&buf[pos..]).map_err(|_| protocol("invalid QUIC token length"))?;
            pos = pos
                .checked_add(used)
                .ok_or_else(|| protocol("QUIC token offset overflow"))?;
            let len = usize::try_from(len).map_err(|_| protocol("QUIC token length overflow"))?;
            let end = pos
                .checked_add(len)
                .ok_or_else(|| protocol("QUIC token length overflow"))?;
            if end > buf.len() {
                return Err(protocol("truncated QUIC token"));
            }
            let token = buf[pos..end].to_vec();
            pos = end;
            token
        } else {
            Vec::new()
        };
        let (payload_len, used) =
            varint::decode(&buf[pos..]).map_err(|_| protocol("invalid QUIC payload length"))?;
        pos = pos
            .checked_add(used)
            .ok_or_else(|| protocol("QUIC payload offset overflow"))?;
        let payload_len =
            usize::try_from(payload_len).map_err(|_| protocol("QUIC payload length overflow"))?;
        let packet_end = pos
            .checked_add(payload_len)
            .ok_or_else(|| protocol("QUIC packet length overflow"))?;
        if payload_len < 4usize.saturating_add(16) || packet_end > buf.len() {
            return Err(protocol("invalid QUIC protected payload length"));
        }
        Ok(Self {
            long_type: Some(packet_type),
            dcid,
            scid,
            pn_offset: pos,
            packet_end,
            token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9000 §10.3.3: a packet that fails to authenticate MUST NOT
    /// close the connection — it is dropped. Regression test for the
    /// single-forged-datagram connection kill: an attacker who knows the
    /// (plaintext) destination CID can send garbage on the short header;
    /// `open` must return `Ok(None)` (drop) rather than `Err`.
    #[test]
    fn forged_packet_is_dropped_not_connection_fatal() {
        let local_cid = vec![0x11; 8];
        let transport =
            QuicTransport::client(local_cid.clone(), vec![0x22; 8], vec![0x33; 8], None).unwrap();
        let mut transport = transport;
        // Short header with the client's DCID + a bogus packet number and
        // random payload that cannot decrypt.
        let mut forged = vec![0x40u8];
        forged.extend_from_slice(&local_cid);
        forged.push(0x00); // packet number 0 (1-byte length)
        forged.extend_from_slice(&[0xde; 32]); // garbage payload
        let opened = transport.open(&mut forged);
        assert!(
            matches!(opened, Ok(None)),
            "an undecryptable packet must be dropped, got {opened:?}"
        );
    }

    /// RFC 9002 §6.1.1: the packet-number loss threshold applies only to
    /// packets older than the reordering window (max(1/8·RTT, 1 ms)). A
    /// burst whose ACKs coalesce on loopback must not be declared lost
    /// the moment a later packet is acknowledged — that false loss halves
    /// cwnd and spawns the retransmit storm behind the H3 64 KiB tail.
    #[test]
    fn packet_threshold_loss_requires_reorder_window() {
        let mut conn =
            QuicTransport::client(vec![0x11; 8], vec![0x22; 8], vec![0x33; 8], None).unwrap();
        conn.smoothed_rtt = Some(Duration::from_millis(10));
        conn.latest_rtt = Some(Duration::from_millis(10));
        // Reorder window = max(10ms/8, 1ms) = 1.25 ms.
        let reorder_window = Duration::from_micros(1250);
        conn.spaces[APPLICATION].largest_acked = Some(100);
        let now = Instant::now();
        let insert = |conn: &mut QuicTransport, pn: u64, age: Duration| {
            conn.spaces[APPLICATION].sent.insert(
                pn,
                SentPacket {
                    frames: Vec::new(),
                    pad_initial: false,
                    sent_at: now - age,
                    retransmits: 0,
                    ack_eliciting: true,
                    size: 1200,
                    pending_resend: false,
                },
            );
        };
        // 4 numbers behind the largest ACK but younger than the reorder
        // window: NOT lost (this is the loopback ACK-coalescing case).
        insert(&mut conn, 96, reorder_window - Duration::from_micros(100));
        assert_eq!(conn.detect_lost_packets(APPLICATION, now), 0);
        // 4 numbers behind and past the reorder window: lost.
        insert(&mut conn, 96, reorder_window + Duration::from_micros(100));
        assert_eq!(conn.detect_lost_packets(APPLICATION, now), 1);
    }

    /// The same guarantee at the `on_datagram` level (client role): the
    /// error must not propagate as a connection error.
    #[test]
    fn forged_packet_on_datagram_is_dropped() {
        let local_cid = vec![0x44; 8];
        let transport =
            QuicTransport::client(local_cid.clone(), vec![0x55; 8], vec![0x66; 8], None).unwrap();
        let mut conn = ClientConnection::new(
            transport,
            // TLS is never touched for an undecryptable packet; dummy
            // values are sufficient.
            crate::courierust_tls::quic::QuicClient::new(
                "localhost",
                vec![b"h3".to_vec()],
                false,
                crate::courierust_tls::RootStore::new(),
                0,
                TransportParameters::default(),
                vec![0x66; 8],
            ),
            Vec::new(),
            "localhost".into(),
            H3Limits {
                max_header_list: 16 * 1024,
                max_body: 16 * 1024 * 1024,
            },
            None,
        )
        .unwrap();
        let mut forged = vec![0x40u8];
        forged.extend_from_slice(&local_cid);
        forged.push(0x00);
        forged.extend_from_slice(&[0xde; 32]);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = socket.local_addr().unwrap();
        let result = conn.on_datagram(&socket, source, &mut forged);
        assert!(
            matches!(result, Ok(())),
            "a forged datagram must not kill the connection, got {result:?}"
        );
    }

    /// RFC 9000 §5.2: an unauthenticated long-header packet (Version
    /// Negotiation / Retry candidate) that fails to parse — here an
    /// illegal DCID length — MUST be discarded during the handshake, not
    /// treated as a fatal connection error.
    #[test]
    fn malformed_version_negotiation_packet_is_dropped() {
        let local_cid = vec![0x44; 8];
        let transport =
            QuicTransport::client(local_cid.clone(), vec![0x55; 8], vec![0x66; 8], None).unwrap();
        let mut conn = ClientConnection::new(
            transport,
            crate::courierust_tls::quic::QuicClient::new(
                "localhost",
                vec![b"h3".to_vec()],
                false,
                crate::courierust_tls::RootStore::new(),
                0,
                TransportParameters::default(),
                vec![0x66; 8],
            ),
            Vec::new(),
            "localhost".into(),
            H3Limits {
                max_header_list: 16 * 1024,
                max_body: 16 * 1024 * 1024,
            },
            None,
        )
        .unwrap();
        // Long header, version 1, DCID length 0xff (> 20, invalid).
        let mut malformed = vec![0x80, 0x00, 0x00, 0x00, 0x01, 0xff, 0x11, 0x22, 0x33, 0x44];
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = socket.local_addr().unwrap();
        let result = conn.on_datagram(&socket, source, &mut malformed);
        assert!(
            matches!(result, Ok(())),
            "a malformed VN/Retry packet must be dropped, got {result:?}"
        );
    }

    /// RFC 9000 §13.1: an ACK that acknowledges a packet number never
    /// sent is a protocol error, not a silent no-op. A duplicate ACK of an
    /// already-acknowledged packet is legal and must be accepted.
    #[test]
    fn ack_of_unsent_packet_is_protocol_error() {
        use std::collections::BTreeMap;
        let mut sent: BTreeMap<u64, SentPacket> = BTreeMap::new();
        sent.insert(
            5,
            SentPacket {
                frames: Vec::new(),
                pad_initial: false,
                sent_at: Instant::now(),
                retransmits: 0,
                ack_eliciting: true,
                size: 64,
                pending_resend: false,
            },
        );
        // largest_acked = 99, but the highest packet ever sent is 5.
        let err = acknowledge(&mut sent, Some(5), 99, &[(0, 0)])
            .expect_err("unsent ACK must be an error");
        assert!(matches!(err.kind, ErrorKind::Protocol), "got {err:?}");
        // A legitimate ACK (within the sent range) still succeeds.
        assert!(acknowledge(&mut sent, Some(5), 5, &[(0, 0)]).is_ok());
        // A duplicate ACK of an already-acknowledged packet (removed from
        // `sent`) must NOT be treated as a protocol error.
        sent.remove(&5);
        assert!(acknowledge(&mut sent, Some(5), 5, &[(0, 0)]).is_ok());
    }

    /// RFC 9114 §7.2.8: a graceful shutdown sends GOAWAY on the control
    /// stream before CONNECTION_CLOSE, advertising the last request
    /// stream id the peer's requests will be processed up to. The send
    /// must (a) be a no-op before the control stream exists, (b) append
    /// after SETTINGS instead of overwriting offset 0, and (c) be
    /// idempotent.
    #[test]
    fn client_sends_goaway_before_close() {
        let local_cid = vec![0x77; 8];
        let transport =
            QuicTransport::client(local_cid.clone(), vec![0x88; 8], vec![0x99; 8], None).unwrap();
        let mut conn = ClientConnection::new(
            transport,
            crate::courierust_tls::quic::QuicClient::new(
                "localhost",
                vec![b"h3".to_vec()],
                false,
                crate::courierust_tls::RootStore::new(),
                0,
                TransportParameters::default(),
                vec![0x66; 8],
            ),
            Vec::new(),
            "localhost".into(),
            H3Limits {
                max_header_list: 16 * 1024,
                max_body: 16 * 1024 * 1024,
            },
            None,
        )
        .unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // No control stream yet: GOAWAY must be deferred, not sent.
        assert!(!conn.control_sent);
        conn.send_goaway(&socket).unwrap();
        assert!(!conn.goaway_sent, "GOAWAY before control stream is a no-op");
        // Control stream established; streams 0, 4, 8 have been issued.
        // Install application keys so the control-stream write succeeds.
        let send_key =
            crate::courierust_quic::protection::PacketKey::from_secret(0x1301, &[0x42; 32])
                .unwrap();
        let recv_key =
            crate::courierust_quic::protection::PacketKey::from_secret(0x1301, &[0x43; 32])
                .unwrap();
        conn.transport.set_application_keys(recv_key, send_key);
        conn.control_sent = true;
        conn.transport.peer = Some(socket.local_addr().unwrap());
        conn.next_stream_index = 3;
        conn.send_goaway(&socket).unwrap();
        assert!(conn.goaway_sent);
        let advanced = conn
            .transport
            .sent_stream_data
            .get(&2)
            .copied()
            .unwrap_or(0);
        assert!(
            advanced >= 2,
            "GOAWAY advanced the control stream send offset, got {advanced}"
        );
        // A second GOAWAY is idempotent (RFC 9114: at most one).
        conn.send_goaway(&socket).unwrap();
        assert_eq!(
            conn.transport
                .sent_stream_data
                .get(&2)
                .copied()
                .unwrap_or(0),
            advanced
        );
    }

    #[test]
    fn qpack_request_round_trip_is_bounded() {
        let req = Request::<Body>::new(Method::POST, "/upload")
            .header("content-type", "application/octet-stream");
        let mut qpack = QpackConnection::new(QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS);
        qpack.set_peer_capacity(QPACK_MAX_TABLE_CAPACITY);
        let wire =
            build_request_wire(req, "example.test:443", &mut qpack, 16 * 1024, 1024).unwrap();
        assert!(wire.len() < 1024);
    }

    /// RFC 9114 §6.2.3: reserved (grease) stream types — and any unknown
    /// unidirectional stream type — MUST be ignored, never rejected. The
    /// `h3` crate opens a grease stream (type 0x21) on every connection.
    #[test]
    fn unknown_unidirectional_stream_type_is_ignored() {
        let mut stream = ReceiveStream {
            id: 14,                                  // 4th client-initiated unidirectional stream (grease)
            frame_buf: vec![0x21, 0x01, 0x02, 0x03], // grease type + padding
            ..Default::default()
        };
        let mut control_received = false;
        let mut peer_goaway = None;
        let mut peer_max_header_list = 0usize;
        let mut qpack = QpackConnection::new(QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS);
        let limits = H3Limits {
            max_header_list: 16 * 1024,
            max_body: 16 * 1024 * 1024,
        };
        let consumed = process_unidirectional_stream(
            &mut stream,
            &mut control_received,
            &mut peer_goaway,
            &mut peer_max_header_list,
            &mut qpack,
            limits,
        )
        .unwrap();
        assert!(
            consumed.is_some(),
            "unknown uni stream must be consumed, not rejected"
        );
        assert!(
            stream.frame_buf.is_empty(),
            "ignored stream data must be drained"
        );
        assert!(!control_received, "grease stream must not act as control");
        assert_eq!(stream.stream_type, Some(0x21));
    }

    /// RFC 9114 §6.2.3 requires ignoring unknown stream types even when
    /// the stream ends without further data.
    #[test]
    fn unknown_unidirectional_stream_type_tolerates_eof() {
        let mut stream = ReceiveStream {
            id: 14,
            frame_buf: vec![0x21],
            completed: true,
            ..Default::default()
        };
        stream.reassembly.final_size = Some(1);
        let mut control_received = false;
        let mut peer_goaway = None;
        let mut peer_max_header_list = 0usize;
        let mut qpack = QpackConnection::new(QPACK_MAX_TABLE_CAPACITY, QPACK_BLOCKED_STREAMS);
        let limits = H3Limits {
            max_header_list: 16 * 1024,
            max_body: 16 * 1024 * 1024,
        };
        assert!(process_unidirectional_stream(
            &mut stream,
            &mut control_received,
            &mut peer_goaway,
            &mut peer_max_header_list,
            &mut qpack,
            limits,
        )
        .is_ok());
    }

    #[test]
    fn stream_reassembly_rejects_conflicting_ranges() {
        let mut stream = StreamReassembly::default();
        assert!(stream.insert(2, b"cd", false, 16).unwrap().is_empty());
        assert!(stream.insert(2, b"cd", false, 16).unwrap().is_empty());
        assert!(stream.insert(2, b"xx", false, 16).is_err());
        assert_eq!(stream.insert(0, b"ab", false, 16).unwrap(), b"abcd");
        assert!(stream.insert(1, b"b", false, 16).unwrap().is_empty());
        assert!(stream.insert(1, b"x", false, 16).is_err());
    }

    #[test]
    fn content_length_must_match_http3_body() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static(" 2 "),
        );
        headers.append(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("2"),
        );
        validate_content_length(&headers, 2).unwrap();
        assert!(validate_content_length(&headers, 1).is_err());

        headers.append(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("3"),
        );
        assert!(validate_content_length(&headers, 2).is_err());

        headers.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("not-a-number"),
        );
        assert!(validate_content_length(&headers, 2).is_err());
    }

    #[test]
    fn response_statuses_forbid_http3_body() {
        let fields = vec![FieldLine {
            name: ":status".into(),
            value: b"204".to_vec(),
            never_indexed: false,
        }];
        assert!(response_from_fields(fields, b"body".to_vec(), None).is_err());
    }

    /// A pooled HTTP/3 client for loopback tests. Requests go through the
    /// public `Client`, so the pool (driver thread + connection reuse) is
    /// exercised exactly as in production.
    fn h3_client(max_body: usize, timeout: Duration) -> crate::courierust_client::Client {
        use crate::courierust_client::{Client, ClientConfig, TlsSettings as ClientTls};
        Client::with_config(ClientConfig {
            http3: true,
            tls: Some(ClientTls {
                roots: crate::courierust_tls::testdata::root_store(),
                verify: true,
                alpn: vec![b"h3".to_vec()],
                now: crate::courierust_tls::testdata::NOW,
                ..Default::default()
            }),
            max_header_list: 16 * 1024,
            max_body,
            read_timeout: Some(timeout),
            ..Default::default()
        })
    }

    /// Bind the HTTP/3 test reactor on an OS-assigned UDP port and return
    /// its address. The port is probed with a UDP socket (not a TCP one)
    /// and that same socket is handed to the reactor, which guarantees
    /// two things on every platform: the port is valid for UDP (on
    /// Windows the TCP and UDP excluded-port ranges are independent —
    /// Hyper-V/WinNAT reserve ranges where a TCP-released port can still
    /// be unbindable by UDP, surfacing as WSAEACCES/10013), and no other
    /// test can steal the port between probing and binding (the socket
    /// is held open the whole time).
    fn spawn_h3_server(
        tls: &TlsSettings,
        handler: Arc<dyn Handler>,
        config: ServerConfig,
    ) -> (SocketAddr, Http3Handle) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let handle =
            crate::courierust_h3::runtime::spawn_server_with_socket(socket, tls, handler, config)
                .unwrap();
        (addr, handle)
    }

    #[test]
    fn loopback_quic_tls_http3_round_trip() {
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity: identity.clone(),
            alpn: vec![b"h3".to_vec()],
            ..Default::default()
        };
        let handler: Arc<dyn Handler> = Arc::new(|_request: Request<Body>| {
            Response::<Body>::with_status(StatusCode::OK).with_body(Body::from("quic-ok"))
        });
        let config = ServerConfig {
            http3: true,
            tls: Some(tls.clone()),
            max_body: 1024 * 1024,
            ..ServerConfig::default()
        };
        let (addr, _server) = spawn_h3_server(&tls, handler, config);

        let client = h3_client(1024 * 1024, Duration::from_secs(5));
        let response = client
            .get(&format!("https://localhost:{}/health", addr.port()))
            .unwrap();
        assert_eq!(response.version, Version::HTTP_3);
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_bytes(), Some(&b"quic-ok"[..]));
    }

    #[test]
    fn loopback_http3_connection_is_reused_across_requests() {
        // The pool must multiplex sequential requests over one QUIC
        // connection: after the handshake, response bodies arrive on
        // fresh streams without a second handshake round.
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
            ..Default::default()
        };
        let handler: Arc<dyn Handler> = Arc::new(|request: Request<Body>| {
            let path = request.uri.as_str().to_string();
            Response::<Body>::with_status(StatusCode::OK).with_body(Body::from(path))
        });
        let config = ServerConfig {
            http3: true,
            tls: Some(tls.clone()),
            max_body: 1024 * 1024,
            ..ServerConfig::default()
        };
        let (addr, _server) = spawn_h3_server(&tls, handler, config);

        let client = h3_client(1024 * 1024, Duration::from_secs(5));
        for i in 0..50 {
            let path = format!("/req-{i}");
            let response = client
                .get(&format!("https://localhost:{}{path}", addr.port()))
                .unwrap();
            assert_eq!(response.status, StatusCode::OK);
            assert_eq!(response.body.as_bytes(), Some(path.as_bytes()));
        }
    }

    /// Drive a raw `ClientConnection` until the queued request's reply
    /// arrives. `send_socket` is where outbound datagrams go; `sockets`
    /// are polled for inbound datagrams (the old path is kept drained so
    /// packets sent before a migration commits are not misread as loss).
    fn drive_raw_client(
        send_socket: &std::net::UdpSocket,
        sockets: &[&std::net::UdpSocket],
        conn: &mut ClientConnection,
        reply: &std::sync::mpsc::Receiver<Result<Response<Body>>>,
    ) -> Result<Response<Body>> {
        let mut datagram = [0u8; MAX_DATAGRAM];
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let _ = conn.on_tick(send_socket);
            if let Ok(res) = reply.try_recv() {
                return res;
            }
            if Instant::now() > deadline {
                return Err(protocol("test driver deadline exceeded"));
            }
            let mut received = false;
            for socket in sockets {
                loop {
                    match socket.recv_from(&mut datagram) {
                        Ok((n, source)) => {
                            if n > 0 {
                                received = true;
                                conn.on_datagram(socket, source, &mut datagram[..n])?;
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::ConnectionReset
                            ) =>
                        {
                            break;
                        }
                        Err(error) => return Err(io_error(error.to_string())),
                    }
                }
            }
            if !received {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    /// RFC 9000 §9: a NAT rebinding changes the client's source address
    /// while the connection state (CIDs, TLS, stream state) stays put. The
    /// server must validate the new path and keep serving the connection
    /// instead of dropping the packets from the new address.
    #[test]
    fn loopback_http3_survives_client_nat_rebinding() {
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
            ..Default::default()
        };
        let handler: Arc<dyn Handler> = Arc::new(|request: Request<Body>| {
            let path = request.uri.as_str().to_string();
            Response::<Body>::with_status(StatusCode::OK).with_body(Body::from(path))
        });
        let config = ServerConfig {
            http3: true,
            tls: Some(tls.clone()),
            max_body: 1024 * 1024,
            ..ServerConfig::default()
        };
        let (addr, _server) = spawn_h3_server(&tls, handler, config);

        let options = ClientRequestOptions {
            roots: crate::courierust_tls::testdata::root_store(),
            verify: true,
            now: crate::courierust_tls::testdata::NOW,
            max_header_list: 16 * 1024,
            max_body: 1024 * 1024,
            timeout: Some(Duration::from_secs(8)),
            stats: None,
        };
        let (socket1, mut conn) = build_client_connection(
            addr,
            "localhost",
            &format!("localhost:{}", addr.port()),
            &options,
        )
        .unwrap();
        socket1.set_nonblocking(true).unwrap();

        // First request from the original source address.
        let (tx, rx) = std::sync::mpsc::channel();
        conn.queue_request(
            Request::<Body>::new(Method::GET, "/one"),
            tx,
            Instant::now() + Duration::from_secs(8),
        );
        let response = drive_raw_client(&socket1, &[&socket1], &mut conn, &rx).unwrap();
        assert_eq!(response.body.as_bytes(), Some(&b"/one"[..]));

        // NAT rebinding: the same connection now sends from a new source
        // port. The server validates the path; the request must still
        // complete.
        let socket2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket2.set_nonblocking(true).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        conn.queue_request(
            Request::<Body>::new(Method::GET, "/two"),
            tx,
            Instant::now() + Duration::from_secs(8),
        );
        let response = drive_raw_client(&socket2, &[&socket1, &socket2], &mut conn, &rx).unwrap();
        assert_eq!(response.body.as_bytes(), Some(&b"/two"[..]));

        // The migration must have committed: a request driven only on the
        // new socket is served directly (no old-path fallback). If the
        // server had kept `peer` on the old address, this response would
        // be lost and the test would time out.
        let (tx, rx) = std::sync::mpsc::channel();
        conn.queue_request(
            Request::<Body>::new(Method::GET, "/three"),
            tx,
            Instant::now() + Duration::from_secs(8),
        );
        let response = drive_raw_client(&socket2, &[&socket2], &mut conn, &rx).unwrap();
        assert_eq!(response.body.as_bytes(), Some(&b"/three"[..]));
    }

    #[test]
    fn loopback_http3_large_response_drains_congestion_queue() {
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
            ..Default::default()
        };
        let body = vec![b'x'; 64 * 1024];
        let expected = body.clone();
        let handler: Arc<dyn Handler> = Arc::new(move |_request: Request<Body>| {
            Response::<Body>::with_status(StatusCode::OK).with_body(Body::from(body.clone()))
        });
        let config = ServerConfig {
            http3: true,
            tls: Some(tls.clone()),
            max_body: 128 * 1024,
            ..ServerConfig::default()
        };
        let (addr, _server) = spawn_h3_server(&tls, handler, config);
        let client = h3_client(128 * 1024, Duration::from_secs(10));
        let response = client
            .get(&format!("https://localhost:{}/large", addr.port()))
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_bytes(), Some(expected.as_slice()));
    }

    #[test]
    fn loopback_http3_large_request_body_is_fully_delivered() {
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
            ..Default::default()
        };
        // The request body is far larger than the initial congestion
        // window (12 KB), so it must be delivered in ACK-paced chunks.
        // This guards against regressions where a full window used to
        // abort the request instead of deferring the remaining chunks.
        let expected_len = 64 * 1024;
        let handler: Arc<dyn Handler> = Arc::new(|request: Request<Body>| {
            let received = request.body.collect().unwrap_or_default();
            let reply = format!("len={}", received.len()).into_bytes();
            Response::<Body>::with_status(StatusCode::OK).with_body(Body::from(reply))
        });
        let config = ServerConfig {
            http3: true,
            tls: Some(tls.clone()),
            max_body: 128 * 1024,
            ..ServerConfig::default()
        };
        let (addr, _server) = spawn_h3_server(&tls, handler, config);
        let client = h3_client(128 * 1024, Duration::from_secs(15));
        let body = vec![b'p'; expected_len];
        let request = Request::<Body>::new(Method::POST, "/upload").with_body(Body::from(body));
        let response = client
            .execute(
                &format!("https://localhost:{}/upload", addr.port()),
                request,
            )
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        let reply = response
            .body
            .as_bytes()
            .and_then(|bytes| std::str::from_utf8(bytes).ok());
        assert_eq!(reply, Some(format!("len={expected_len}").as_str()));
    }

    #[test]
    fn loopback_http3_round_trip_latency() {
        // A timing harness (not a correctness gate): reports the real
        // per-request cost of the pooled HTTP/3 client once the QUIC/TLS
        // handshake is amortized over the reused connection. Run with
        // `-- --nocapture`.
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
            ..Default::default()
        };
        let handler: Arc<dyn Handler> = Arc::new(|_request: Request<Body>| {
            Response::<Body>::with_status(StatusCode::OK).with_body(Body::from("ok"))
        });
        let config = ServerConfig {
            http3: true,
            tls: Some(tls.clone()),
            max_body: 1024 * 1024,
            ..ServerConfig::default()
        };
        let (addr, _server) = spawn_h3_server(&tls, handler, config);

        let client = h3_client(1024 * 1024, Duration::from_secs(5));
        let url = format!("https://localhost:{}/bench", addr.port());
        // Warm-up: the first requests pay the QUIC handshake and open the
        // pooled connection.
        for _ in 0..2 {
            let _ = client.get(&url).unwrap();
        }
        let runs = 20;
        let mut samples = Vec::with_capacity(runs);
        let started = Instant::now();
        for _ in 0..runs {
            let t = Instant::now();
            let response = client.get(&url).unwrap();
            assert_eq!(response.body.as_bytes(), Some(&b"ok"[..]));
            samples.push(t.elapsed());
        }
        let total = started.elapsed();
        samples.sort_unstable();
        let median = samples[runs / 2].as_micros();
        let p99 = samples[(runs as f64 * 0.99) as usize - 1].as_micros();
        println!(
            "H3 pooled round trip: n={runs} total={:?} avg={}us median={median}us p99={p99}us",
            total,
            total.as_micros() / runs as u128
        );
    }

    /// RFC 9114 §4.1: response trailers are a HEADERS frame after DATA.
    /// Regression test for the server silently dropping `response.trailers`
    /// (the client already decoded them; the server never sent them).
    #[test]
    fn loopback_http3_response_trailers_round_trip() {
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
            ..Default::default()
        };
        let handler: Arc<dyn Handler> = Arc::new(|_request: Request<Body>| {
            let mut trailers = HeaderMap::new();
            trailers.append(
                HeaderName::from_static("checksum"),
                HeaderValue::from_static("sha256:abc123"),
            );
            let mut response =
                Response::<Body>::with_status(StatusCode::OK).with_body(Body::from("trailered"));
            response.trailers = Some(trailers);
            response
        });
        let config = ServerConfig {
            http3: true,
            tls: Some(tls.clone()),
            max_body: 1024 * 1024,
            ..ServerConfig::default()
        };
        let (addr, _server) = spawn_h3_server(&tls, handler, config);

        let client = h3_client(1024 * 1024, Duration::from_secs(5));
        let response = client
            .get(&format!("https://localhost:{}/trailers", addr.port()))
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_bytes(), Some(&b"trailered"[..]));
        let trailers = response
            .trailers
            .expect("response trailers must be delivered");
        assert_eq!(
            trailers.get("checksum").map(|v| v.as_bytes()),
            Some(&b"sha256:abc123"[..])
        );
    }
}
