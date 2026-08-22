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
use crate::courierust_h3::qpack::{self, DynamicTable, FieldLine};
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
const MAX_H3_UNI_STREAMS: usize = 3;
const MAX_H3_PENDING_REQUESTS: usize = 256;
const MAX_H3_CONNECTION_BUFFER: usize = 64 * 1024 * 1024;
const ACK_DELAY: Duration = Duration::from_millis(2);
const LOSS_DELAY: Duration = Duration::from_millis(250);
/// Floor for the per-connection loss timeout once an RTT sample exists.
/// See [`QuicTransport::loss_timeout`] for why a sub-millisecond floor
/// is wrong on loopback / loaded machines.
const LOSS_TIMEOUT_FLOOR: Duration = Duration::from_millis(25);
const MAX_RETRANSMITS: u8 = 8;
const RETRY_TOKEN_TTL: u64 = 30;
const RETRY_CLOCK_SKEW: u64 = 5;
const RETRY_TOKEN_VERSION: u8 = 1;
const H3_CONTROL_STREAM: u64 = h3frame::STREAM_TYPE_CONTROL;
const H3_QPACK_ENCODER_STREAM: u64 = h3frame::STREAM_TYPE_QPACK_ENCODER;
const H3_QPACK_DECODER_STREAM: u64 = h3frame::STREAM_TYPE_QPACK_DECODER;

/// Server idle receive window: bounds how long the reactor parks on the
/// poller with no datagram pending. Datagrams and the completed-response
/// self-pipe both wake the poller immediately; this only paces idle
/// periodic work (retransmit, response queue).
const SERVER_IDLE_TIMEOUT_MS: i32 = 5;
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
        body.get(pos..original_end)?;
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
        Some(RetryToken { retry_dcid })
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
    if !tls.alpn.iter().any(|protocol| protocol.as_slice() == b"h3") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "HTTP/3 requires ServerConfig TLS ALPN to include h3",
        ));
    }
    let socket = UdpSocket::bind(addr)?;
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
    socket.connect(addr).map_err(|e| io_error(e.to_string()))?;
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
        let _ = self
            .reservations
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
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
            5
        } else {
            50
        };
        if conn.is_idle() {
            let remaining = idle.saturating_sub(now.duration_since(last_activity));
            wait_ms = wait_ms.min(remaining.as_millis().min(i64::MAX as u128) as i64);
        }
        if let Some(deadline) = conn.earliest_deadline() {
            let remaining = deadline.saturating_duration_since(now);
            wait_ms = wait_ms.min(remaining.as_millis().min(i64::MAX as u128) as i64);
        }
        let ready = match poller.wait(wait_ms.max(1) as i32, Some(wake_fd)) {
            Ok(ready) => ready,
            Err(error) => return finish(conn, &socket, io_error(error.to_string())),
        };
        if ready.contains(&SOCKET_ID) {
            loop {
                match socket.recv(&mut datagram) {
                    Ok(n) => {
                        if n == 0 || n > MAX_DATAGRAM {
                            return finish(conn, &socket, protocol("invalid QUIC datagram length"));
                        }
                        last_activity = Instant::now();
                        if let Some(stats) = options.stats.as_deref() {
                            stats.h3_udp_recv_syscalls.fetch_add(1, Ordering::Relaxed);
                        }
                        if let Err(error) = conn.on_datagram(&socket, &mut datagram[..n]) {
                            return finish(conn, &socket, error);
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
        }
        if ready.contains(&WAKE_ID) {
            drain_wake(&wake_reader);
        }
    }
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
    };
    let mut datagram = [0u8; MAX_DATAGRAM];
    let (wake_reader, wake_writer) = wakeup_pair().map_err(|e| io_error(e.to_string()))?;
    let wake_writer = Arc::new(wake_writer);
    let wake_fd = fd_of(&wake_reader);
    let mut poller = Poller::new();
    poller.register(SOCKET_ID, udp_fd_of(&socket), false);

    loop {
        let ready = poller
            .wait(SERVER_IDLE_TIMEOUT_MS, Some(wake_fd))
            .map_err(|e| io_error(e.to_string()))?;
        if ready.contains(&SOCKET_ID) {
            while let Ok((n, peer)) = socket.recv_from(&mut datagram) {
                handle_server_datagram(&socket, &mut datagram[..n], peer, &mut state);
            }
        }
        if ready.contains(&WAKE_ID) {
            drain_wake(&wake_reader);
        }
        while let Ok(completed) = completed_rx.try_recv() {
            if let Some(connection) = state.connections.get_mut(&completed.connection_id) {
                connection.queue_response(completed.stream_id, completed.response);
            }
            active_tasks.fetch_sub(1, Ordering::Relaxed);
        }

        let now = Instant::now();
        let mut dead = Vec::new();
        for (connection_id, connection) in state.connections.iter_mut() {
            if (!connection.handshake_complete && now >= connection.handshake_deadline)
                || now.duration_since(connection.last_activity) >= connection.idle_timeout
            {
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
                if active_tasks.load(Ordering::Acquire) >= task_limit {
                    connection.queue_service_unavailable(request.stream_id);
                    continue;
                }
                active_tasks.fetch_add(1, Ordering::AcqRel);
                let tx = completed_tx.clone();
                let handler = handler.clone();
                let max_body = state.config.max_body;
                let connection_id = connection_id.clone();
                let wake = wake_writer.clone();
                pool.spawn(move || {
                    let response = match panic::catch_unwind(AssertUnwindSafe(|| {
                        let response = handler.handle(request.request);
                        materialize_response(response, max_body)
                    })) {
                        Ok(response) => response,
                        Err(_) => Err(protocol("HTTP/3 request handler panicked")),
                    };
                    let _ = tx.send(CompletedResponse {
                        connection_id,
                        stream_id: request.stream_id,
                        response,
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
            return;
        }
        let failure = connection.on_datagram(socket, datagram).err();
        if let Some(error) = failure {
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
    if token
        .as_ref()
        .is_none_or(|value| value.retry_dcid != meta.dcid)
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
    if let Ok((mut connection, mut initial)) =
        ServerConnection::accept(peer, datagram, identity.clone(), alpn.to_vec(), config)
    {
        if connection.on_datagram(socket, &mut initial[..]).is_ok() {
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
}

struct H3ActiveGuard {
    stats: Arc<Stats>,
}

impl Drop for H3ActiveGuard {
    fn drop(&mut self) {
        Stats::decrement(&self.stats.h3_connections_active, 1);
    }
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
    qpack_decoder: DynamicTable,
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
            qpack_decoder: DynamicTable::new(0),
            initial_crypto: CryptoReassembly::default(),
            handshake_crypto: CryptoReassembly::default(),
            initial_tls: Vec::new(),
            last_activity: Instant::now(),
            stats,
            active_streams: BTreeSet::new(),
        })
    }

    fn on_datagram(&mut self, socket: &UdpSocket, datagram: &mut [u8]) -> Result<()> {
        self.last_activity = Instant::now();
        if let Some(version_negotiation) = version_negotiation_versions(datagram)? {
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
        if let Some(retry) = parse_retry_packet(datagram)? {
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
            self.tls_initial_sent = false;
            return Ok(());
        }
        let mut consumed = 0usize;
        while consumed < datagram.len() {
            let Some((level, _pn, frames, packet_len)) =
                self.transport.open(&mut datagram[consumed..])?
            else {
                break;
            };
            if packet_len == 0 || packet_len > datagram.len() - consumed {
                return Err(protocol("QUIC packet decoder made no progress"));
            }
            consumed += packet_len;
            let mut ack = false;
            for frame in frames {
                match frame {
                    QFrame::Crypto { offset, data } if level == INITIAL => {
                        ack = true;
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
                        ack = true;
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
                        ack = true;
                    }
                    QFrame::ConnectionClose { .. } => {
                        return Err(protocol("peer closed HTTP/3"));
                    }
                    _ => {}
                }
            }
            if ack {
                self.transport.ack(level);
            }
            self.transport.flush_ack(socket, level)?;
        }
        if self.handshake_complete && self.control_received {
            self.flush_requests(socket)?;
        }
        Ok(())
    }

    fn on_tick(&mut self, socket: &UdpSocket) -> Result<()> {
        self.transport.retransmit(socket)?;
        if !self.tls_initial_sent {
            self.transport
                .send_crypto(socket, INITIAL, &self.client_hello)?;
            if self.transport.crypto_send_offsets[INITIAL] >= self.client_hello.len() as u64 {
                self.tls_initial_sent = true;
            }
        }
        if self.handshake_complete {
            self.ensure_control_sent(socket)?;
            self.flush_requests(socket)?;
            // Resume request bodies deferred by the congestion window;
            // remaining chunks go out once ACKs free credit.
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
            (h3frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (h3frame::SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (
                h3frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                self.max_header_list as u64,
            ),
        ])
        .to_bytes();
        // Control streams are tiny and idempotent; if the congestion
        // window is momentarily full, defer and retry on the next tick
        // (the peer deduplicates a re-send).
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
            6,
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
            10,
            &stream_type(H3_QPACK_DECODER_STREAM),
            false,
        ) {
            Ok(()) => {}
            Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
        self.control_sent = true;
        Ok(())
    }

    /// Start every queued request the connection can currently carry:
    /// the handshake and peer SETTINGS are done and a stream slot is
    /// free. Requests larger than the peer's flow-control budget fail
    /// cleanly instead of half-sending a body the peer can never accept.
    fn flush_requests(&mut self, socket: &UdpSocket) -> Result<()> {
        if !self.handshake_complete || !self.control_received {
            return Ok(());
        }
        self.ensure_control_sent(socket)?;
        if !self.control_sent {
            return Ok(());
        }
        while let Some(request) = self.waiting.pop_front() {
            if self.active.len() >= MAX_H3_STREAMS {
                self.waiting.push_front(request);
                break;
            }
            let stream_id = 4 * self.next_stream_index;
            self.next_stream_index = self
                .next_stream_index
                .checked_add(1)
                .ok_or_else(|| protocol("HTTP/3 stream id exhausted"))?;
            let outbound_limit = self.max_header_list.min(self.peer_max_header_list);
            let wire = match build_request_wire(
                request.request,
                &self.authority,
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
            self.fail_stream(stream_id, Error::new(ErrorKind::Timeout));
        }
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
            process_unidirectional_stream(
                stream,
                &mut self.control_received,
                &mut self.peer_goaway,
                &mut self.peer_max_header_list,
                H3Limits {
                    max_header_list: self.max_header_list,
                    max_body: self.max_body,
                },
            )?;
        } else {
            let finished = {
                let Some(request) = self.active.get_mut(&id) else {
                    // A response stream we already completed may receive a
                    // retransmitted final packet after delivery; ignore it.
                    if id < 4 * self.next_stream_index {
                        return Ok(());
                    }
                    return Err(protocol("HTTP/3 response on an unrequested stream"));
                };
                process_client_stream(
                    stream,
                    &mut self.control_received,
                    &mut self.peer_goaway,
                    &mut self.peer_max_header_list,
                    &mut self.qpack_decoder,
                    H3Limits {
                        max_header_list: self.max_header_list,
                        max_body: self.max_body,
                    },
                    &mut request.response,
                )?;
                request.response.is_some()
            };
            if finished {
                let mut request = self
                    .active
                    .remove(&id)
                    .expect("request present while receiving its response");
                let response = request.response.take().expect("response just completed");
                let _ = request.reply.send(Ok(response));
                h3_close_stream(self.stats.as_ref(), &mut self.active_streams, id);
            }
        }
        self.ensure_buffer_budget()
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
            Ok(()) => active.offset = end,
            Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
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
    pending_requests: VecDeque<PendingRequest>,
    qpack_decoder: DynamicTable,
    peer_transport: Option<TransportParameters>,
    initial_crypto: CryptoReassembly,
    handshake_crypto: CryptoReassembly,
    initial_tls: Vec<u8>,
    handshake_tls: Vec<u8>,
    pending_initial: Vec<u8>,
    pending_handshake: Vec<u8>,
    peer_goaway: Option<u64>,
    stats: Option<Arc<Stats>>,
    active_streams: BTreeSet<u64>,
}

impl ServerConnection {
    fn accept(
        peer: SocketAddr,
        initial: &[u8],
        identity: crate::courierust_tls::Identity,
        alpn: Vec<Vec<u8>>,
        config: &ServerConfig,
    ) -> Result<(Self, Vec<u8>)> {
        let meta = PacketMeta::parse(initial, 8)?;
        if meta.long_type != Some(LongType::Initial) || meta.dcid.is_empty() || meta.scid.is_empty()
        {
            return Err(protocol("invalid QUIC client Initial header"));
        }
        let local_cid = random_cid()?;
        let initial_dcid = meta.dcid.clone();
        let client_cid = meta.scid.clone();
        let local_tp = transport_parameters_for_limits(config.max_header_list, config.max_body);
        let tls = QuicServer::new(identity, alpn, local_tp.clone(), local_cid.clone());
        let mut transport =
            QuicTransport::server(local_cid, client_cid, initial_dcid, config.stats.clone())?;
        transport.set_local_transport(&local_tp);
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
            pending_requests: VecDeque::new(),
            qpack_decoder: DynamicTable::new(0),
            peer_transport: None,
            initial_crypto: CryptoReassembly::default(),
            handshake_crypto: CryptoReassembly::default(),
            initial_tls: Vec::new(),
            handshake_tls: Vec::new(),
            pending_initial: Vec::new(),
            pending_handshake: Vec::new(),
            peer_goaway: None,
            stats: config.stats.clone(),
            active_streams: BTreeSet::new(),
        };
        Ok((connection, initial.to_vec()))
    }

    fn on_datagram(&mut self, socket: &UdpSocket, datagram: &mut [u8]) -> Result<()> {
        self.last_activity = Instant::now();
        let mut consumed = 0usize;
        while consumed < datagram.len() {
            let Some((level, _pn, frames, packet_len)) =
                self.transport.open(&mut datagram[consumed..])?
            else {
                break;
            };
            if packet_len == 0 || packet_len > datagram.len() - consumed {
                return Err(protocol("QUIC packet decoder made no progress"));
            }
            consumed += packet_len;
            let mut ack = false;
            for frame in frames {
                match frame {
                    QFrame::Crypto { offset, data } if level == INITIAL => {
                        ack = true;
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
                            self.peer_transport = flight.peer_transport.clone();
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
                        ack = true;
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
                        ack = true;
                    }
                    QFrame::ConnectionClose { .. } => {
                        return Err(protocol("peer closed HTTP/3"));
                    }
                    _ => {}
                }
            }
            if ack {
                self.transport.ack(level);
            }
            self.transport.flush_ack(socket, level)?;
        }
        Ok(())
    }

    fn on_tick(&mut self, socket: &UdpSocket) -> Result<()> {
        // Deliver the TLS flight and control streams incrementally; both
        // are deferred (never fatal) when the congestion window is full,
        // so a large certificate or a busy path cannot tear the
        // connection down.
        self.flush_pending_crypto(socket)?;
        if self.handshake_complete && !self.control_sent {
            self.send_control(socket)?;
        }
        self.transport.retransmit(socket)
    }

    /// Deliver the TLS flight incrementally. `send_crypto` resumes from
    /// the last CRYPTO offset written, so this is safe to call on every
    /// tick and becomes a no-op once both flights are fully delivered.
    fn flush_pending_crypto(&mut self, socket: &UdpSocket) -> Result<()> {
        if !self.pending_initial.is_empty() {
            self.transport
                .send_crypto(socket, INITIAL, &self.pending_initial)?;
            if self.transport.crypto_send_offsets[INITIAL] < self.pending_initial.len() as u64 {
                // The client cannot decrypt Handshake data before it has
                // the full Initial flight; hold Handshake until then.
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
            (h3frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
            (h3frame::SETTINGS_QPACK_BLOCKED_STREAMS, 0),
            (
                h3frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                self.max_header_list as u64,
            ),
        ])
        .to_bytes();
        // Control streams are tiny; the only way they can fail is a full
        // congestion window. They are idempotent (the peer's reassembly
        // deduplicates a retry), so defer and retry on a later tick.
        match self
            .transport
            .send_stream(socket, APPLICATION, 3, &control_stream(settings), false)
        {
            Ok(()) => {}
            Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
        match self.transport.send_stream(
            socket,
            APPLICATION,
            7,
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
            11,
            &stream_type(H3_QPACK_DECODER_STREAM),
            false,
        ) {
            Ok(()) => {}
            Err(error) if error.kind == ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
        self.control_sent = true;
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
                return Err(protocol("HTTP/3 unidirectional stream limit exceeded"));
            }
        } else if !stream_id::is_client_initiated(id) {
            return Err(protocol("request stream has invalid initiator"));
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
        let max = self.max_body.saturating_add(self.max_header_list);
        let ready = stream.reassembly.insert(offset, data, fin, max)?;
        stream.frame_buf.extend_from_slice(&ready);
        process_server_stream(
            stream,
            &mut self.local_settings_received,
            &mut self.peer_goaway,
            &mut self.peer_max_header_list,
            &mut self.qpack_decoder,
            H3Limits {
                max_header_list: self.max_header_list,
                max_body: self.max_body,
            },
            &mut self.pending_requests,
        )?;
        self.ensure_buffer_budget()
    }

    fn take_request(&mut self) -> Option<PendingRequest> {
        self.pending_requests.pop_front()
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
        if let Ok(wire) = build_response_wire(response, outbound_limit, self.max_body) {
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
        if let Ok(wire) = build_response_wire(response, outbound_limit, self.max_body) {
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
/// decoder). Returns `true` when the stream was consumed, `false` when it
/// is a bidirectional request/response stream that still needs draining.
fn process_unidirectional_stream(
    stream: &mut ReceiveStream,
    control_received: &mut bool,
    peer_goaway: &mut Option<u64>,
    peer_max_header_list: &mut usize,
    limits: H3Limits,
) -> Result<bool> {
    if stream.stream_type.is_none() && stream_id::is_unidirectional(stream_id_of(stream)) {
        let (kind, used) = match varint::decode(&stream.frame_buf) {
            Ok(v) => v,
            Err(error) if error.kind == ErrorKind::UnexpectedEof => {
                if stream.reassembly.finished() {
                    return Err(protocol(
                        "HTTP/3 unidirectional stream ended before its type",
                    ));
                }
                return Ok(true);
            }
            Err(error) => return Err(error),
        };
        stream.frame_buf.drain(..used);
        stream.stream_type = Some(kind);
        if kind != H3_CONTROL_STREAM
            && kind != H3_QPACK_ENCODER_STREAM
            && kind != H3_QPACK_DECODER_STREAM
        {
            return Err(protocol("unsupported HTTP/3 unidirectional stream type"));
        }
    }
    let Some(kind) = stream.stream_type else {
        return Ok(stream_id::is_unidirectional(stream_id_of(stream)));
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
                    validate_settings(&settings, limits.max_header_list, peer_max_header_list)?;
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
            Ok(true)
        }
        H3_QPACK_ENCODER_STREAM => {
            // Both endpoints advertise a zero dynamic-table capacity, so
            // any instruction bytes are a peer violation (and bounded).
            if stream.frame_buf.len() > limits.max_header_list {
                return Err(protocol("QPACK encoder stream exceeds limit"));
            }
            if !stream.frame_buf.is_empty() {
                return Err(protocol("QPACK dynamic table instructions are disabled"));
            }
            if stream.reassembly.finished() {
                return Err(protocol("HTTP/3 QPACK encoder stream cannot be closed"));
            }
            Ok(true)
        }
        _ => {
            // QPACK decoder stream: instructions are parsed and dropped
            // (the dynamic table is disabled, so nothing is applied).
            let mut pos = 0;
            while pos < stream.frame_buf.len() {
                let before = pos;
                match qpack::decode_decoder_instruction(&stream.frame_buf, &mut pos) {
                    Ok(_) => {}
                    Err(error) if error.kind == ErrorKind::UnexpectedEof => {
                        pos = before;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            if pos != 0 {
                stream.frame_buf.drain(..pos);
            }
            if stream.reassembly.finished() {
                return Err(protocol("HTTP/3 QPACK decoder stream cannot be closed"));
            }
            Ok(true)
        }
    }
}

fn process_server_stream(
    stream: &mut ReceiveStream,
    control_received: &mut bool,
    peer_goaway: &mut Option<u64>,
    peer_max_header_list: &mut usize,
    qpack_decoder: &mut DynamicTable,
    limits: H3Limits,
    requests: &mut VecDeque<PendingRequest>,
) -> Result<()> {
    if process_unidirectional_stream(
        stream,
        control_received,
        peer_goaway,
        peer_max_header_list,
        limits,
    )? {
        return Ok(());
    }
    drain_request_frames(
        stream,
        control_received,
        peer_goaway,
        qpack_decoder,
        limits.max_header_list,
        limits.max_body,
        requests,
    )
}

fn process_client_stream(
    stream: &mut ReceiveStream,
    control_received: &mut bool,
    peer_goaway: &mut Option<u64>,
    peer_max_header_list: &mut usize,
    qpack_decoder: &mut DynamicTable,
    limits: H3Limits,
    response: &mut Option<Response<Body>>,
) -> Result<()> {
    if process_unidirectional_stream(
        stream,
        control_received,
        peer_goaway,
        peer_max_header_list,
        limits,
    )? {
        return Ok(());
    }
    drain_response_frames(
        stream,
        control_received,
        qpack_decoder,
        limits.max_header_list,
        limits.max_body,
        response,
    )
}

fn stream_id_of(stream: &ReceiveStream) -> u64 {
    stream.id
}

fn drain_request_frames(
    stream: &mut ReceiveStream,
    control_received: &bool,
    peer_goaway: &Option<u64>,
    qpack_decoder: &mut DynamicTable,
    max_header_list: usize,
    max_body: usize,
    requests: &mut VecDeque<PendingRequest>,
) -> Result<()> {
    let mut pos = 0;
    while let Some(frame) = h3frame::Frame::decode(&stream.frame_buf, &mut pos)? {
        match frame {
            h3frame::Frame::Headers(block) if stream.headers.is_none() => {
                if block.len() > max_header_list {
                    return Err(protocol("HTTP/3 request headers exceed configured limit"));
                }
                stream.headers = Some(decode_field_section(
                    &block,
                    qpack_decoder,
                    max_header_list,
                )?);
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
    if pos != 0 {
        stream.frame_buf.drain(..pos);
    }
    if stream.reassembly.finished() && !stream.completed {
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
        requests.push_back(PendingRequest {
            stream_id: stream.id,
            request,
        });
    }
    Ok(())
}

fn drain_response_frames(
    stream: &mut ReceiveStream,
    _control_received: &bool,
    qpack_decoder: &mut DynamicTable,
    max_header_list: usize,
    max_body: usize,
    response: &mut Option<Response<Body>>,
) -> Result<()> {
    let mut pos = 0;
    while let Some(frame) = h3frame::Frame::decode(&stream.frame_buf, &mut pos)? {
        match frame {
            h3frame::Frame::Headers(block) => {
                if block.len() > max_header_list {
                    return Err(protocol("HTTP/3 response headers exceed configured limit"));
                }
                let fields = decode_field_section(&block, qpack_decoder, max_header_list)?;
                if stream.headers.is_none() {
                    stream.headers = Some(fields);
                } else {
                    if stream.trailers.is_some() {
                        return Err(protocol("multiple HTTP/3 response trailer blocks"));
                    }
                    stream.trailers = Some(response_trailers_from_fields(fields)?);
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
    if pos != 0 {
        stream.frame_buf.drain(..pos);
    }
    if stream.reassembly.finished() && !stream.completed {
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

fn validate_settings(
    settings: &[(u64, u64)],
    _max_header_list: usize,
    peer_max_header_list: &mut usize,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for (id, value) in settings {
        if !seen.insert(*id) {
            return Err(protocol("duplicate HTTP/3 SETTINGS identifier"));
        }
        match *id {
            h3frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY
            | h3frame::SETTINGS_QPACK_BLOCKED_STREAMS
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
    Ok(())
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

fn decode_field_section(
    block: &[u8],
    table: &DynamicTable,
    max_header_list: usize,
) -> Result<Vec<FieldLine>> {
    if block.len() > max_header_list {
        return Err(protocol("QPACK field section exceeds configured limit"));
    }
    let mut pos = 0;
    let (required, base) = qpack::decode_field_section_prefix(
        block,
        &mut pos,
        table.insert_count(),
        table.capacity() as u64,
    )?;
    if required != 0 {
        return Err(protocol("blocked QPACK field sections are not accepted"));
    }
    let mut fields = Vec::new();
    let mut total = 0usize;
    while pos < block.len() {
        let field = qpack::decode_field_line(block, &mut pos, table, base)?;
        total = total
            .checked_add(field.name.len())
            .and_then(|value| value.checked_add(field.value.len()))
            .ok_or_else(|| protocol("QPACK field-section size overflow"))?;
        if total > max_header_list {
            return Err(protocol("QPACK field-section limit exceeded"));
        }
        fields.push(field);
        if fields.len() > 256 {
            return Err(protocol("HTTP/3 header field count exceeds limit"));
        }
    }
    Ok(fields)
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
    let header_block = encode_field_section(&fields, max_header_list)?;
    let mut wire = h3frame::Frame::Headers(header_block).to_bytes();
    if !bytes.is_empty() {
        wire.extend_from_slice(&h3frame::Frame::Data(bytes.to_vec()).to_bytes());
    }
    Ok(wire)
}

fn build_response_wire(
    response: Response<Body>,
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
    let header_block = encode_field_section(&fields, max_header_list)?;
    let mut wire = h3frame::Frame::Headers(header_block).to_bytes();
    if !body.is_empty() {
        wire.extend_from_slice(&h3frame::Frame::Data(body).to_bytes());
    }
    Ok(wire)
}

fn encode_field_section(fields: &[(String, Vec<u8>)], max_header_list: usize) -> Result<Vec<u8>> {
    let mut total = 0usize;
    let mut out = Vec::new();
    qpack::encode_field_section_prefix(0, 0, 0, &mut out);
    let table = DynamicTable::new(0);
    for (name, value) in fields {
        total = total
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(|| protocol("QPACK field-section size overflow"))?;
        if total > max_header_list
            || name.is_empty()
            || !name.bytes().all(|b| {
                b == b':'
                    || b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'.'
                    || b == b'_'
            })
        {
            return Err(protocol("invalid HTTP/3 header field"));
        }
        qpack::encode_field_line(name, value, &table, 0, &mut out);
    }
    if out.len() > max_header_list {
        return Err(protocol("encoded QPACK field section exceeds limit"));
    }
    Ok(out)
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
    if buf.first().is_none_or(|first| first & 0x80 == 0) {
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
    if buf.first().is_none_or(|first| first & 0x80 == 0) {
        return Ok(None);
    }
    let identity = parse_long_header_identity(buf)?;
    if identity.version != crate::courierust_quic::VERSION_NEGOTIATION {
        return Ok(None);
    }
    let versions = &buf[identity.payload_offset..];
    if versions.is_empty() || !versions.len().is_multiple_of(4) {
        return Err(protocol("malformed QUIC Version Negotiation packet"));
    }
    let (version_chunks, remainder) = versions.as_chunks::<4>();
    debug_assert!(
        remainder.is_empty(),
        "version list length checked as multiple of 4"
    );
    let versions = version_chunks
        .iter()
        .map(|chunk| u32::from_be_bytes(*chunk))
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
}

struct QuicTransport {
    server: bool,
    peer: Option<SocketAddr>,
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
    spaces: [PacketSpace; 3],
    crypto_send_offsets: [u64; 3],
    queued_streams: VecDeque<(u64, Vec<u8>, usize)>,
    congestion_window: usize,
    slow_start_threshold: usize,
    smoothed_rtt: Option<Duration>,
    rtt_variance: Duration,
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
    received_data: u64,
    received_stream_data: BTreeMap<u64, u64>,
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
            spaces: [
                PacketSpace::default(),
                PacketSpace::default(),
                PacketSpace::default(),
            ],
            crypto_send_offsets: [0; 3],
            queued_streams: VecDeque::new(),
            congestion_window: 12_000,
            slow_start_threshold: usize::MAX,
            smoothed_rtt: None,
            rtt_variance: Duration::from_millis(0),
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
            received_data: 0,
            received_stream_data: BTreeMap::new(),
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
    }

    fn set_peer_transport(&mut self, parameters: &TransportParameters) {
        self.peer_max_data = parameters.initial_max_data;
        self.peer_max_stream_data_bidi_local = parameters.initial_max_stream_data_bidi_local;
        self.peer_max_stream_data_bidi_remote = parameters.initial_max_stream_data_bidi_remote;
        self.peer_max_stream_data_uni = parameters.initial_max_stream_data_uni;
    }

    fn apply_retry(&mut self, retry_dcid: Vec<u8>, token: Vec<u8>) -> Result<bool> {
        if self.server || self.retry_seen {
            return Ok(false);
        }
        if retry_dcid.is_empty() || retry_dcid.len() > 20 || token.is_empty() {
            return Err(protocol("invalid QUIC Retry connection ID or token"));
        }
        let (client_initial, server_initial) = protection::initial_pair(&retry_dcid)?;
        self.initial_dcid = retry_dcid.clone();
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
        self.sent_data = 0;
        self.sent_stream_data.clear();
        self.peer_stream_limits.clear();
        self.received_data = 0;
        self.received_stream_data.clear();
        Ok(true)
    }

    fn set_local_transport(&mut self, parameters: &TransportParameters) {
        self.local_max_data = parameters.initial_max_data;
        self.local_max_stream_data_bidi_local = parameters.initial_max_stream_data_bidi_local;
        self.local_max_stream_data_bidi_remote = parameters.initial_max_stream_data_bidi_remote;
        self.local_max_stream_data_uni = parameters.initial_max_stream_data_uni;
    }

    /// The peer's advertised send limit for `id` (its transport parameter,
    /// raised by any `MAX_STREAM_DATA` we received).
    fn peer_stream_send_limit(&self, id: u64) -> u64 {
        let default_limit = if stream_id::is_unidirectional(id) {
            self.peer_max_stream_data_uni
        } else if stream_id::is_client_initiated(id) == !self.server {
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
        let end = offset
            .checked_add(length as u64)
            .ok_or_else(|| protocol("QUIC stream receive offset overflow"))?;
        let default_limit = if stream_id::is_unidirectional(id) {
            self.local_max_stream_data_uni
        } else if stream_id::is_client_initiated(id) == !self.server {
            self.local_max_stream_data_bidi_local
        } else {
            self.local_max_stream_data_bidi_remote
        };
        if end > default_limit {
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
            return Err(protocol("invalid QUIC datagram size"));
        }
        let meta = PacketMeta::parse(datagram, self.local_cid.len())?;
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
        // Common case: current key with a single copy. The key-update path
        // is only exercised when the current key fails.
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
            return Err(protocol("QUIC packet authentication failed"));
        };
        if level == APPLICATION && next_phase {
            self.application_recv = Some(candidate);
            self.application_recv_phase = !self.application_recv_phase;
        }
        let space = &mut self.spaces[level];
        if !space.received.insert(pn) {
            space.ack_pending = true;
            return Ok(Some((level, pn, Vec::new(), meta.packet_end)));
        }
        if space.received.len() > 8192 {
            if let Some(first) = space.received.iter().next().copied() {
                space.received.remove(&first);
            }
        }
        if space.largest_received.is_none_or(|largest| pn > largest) {
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
                let (bytes, sample) = acknowledge(&mut space.sent, *largest_acked, ranges);
                acknowledged_bytes = acknowledged_bytes.saturating_add(bytes);
                rtt_sample = rtt_sample.or(sample);
            }
            match frame {
                QFrame::MaxData(max) => {
                    self.peer_max_data = self.peer_max_data.max(*max);
                }
                QFrame::MaxStreamData { stream_id, max } => {
                    let limit = self.peer_stream_limits.entry(*stream_id).or_insert(0);
                    *limit = (*limit).max(*max);
                }
                _ => {}
            }
        }
        if ack_eliciting {
            space.ack_pending = true;
            space.ack_deadline = Some(Instant::now() + ACK_DELAY);
        }
        if acknowledged_bytes != 0 {
            self.on_acknowledgement(acknowledged_bytes, rtt_sample);
        }
        Ok(Some((level, pn, frames, meta.packet_end)))
    }

    fn on_acknowledgement(&mut self, bytes: usize, sample: Option<Duration>) {
        if let Some(sample) = sample {
            if self.smoothed_rtt.is_none() {
                self.smoothed_rtt = Some(sample);
                self.rtt_variance = sample / 2;
            } else if let Some(smoothed) = self.smoothed_rtt {
                let difference = smoothed.abs_diff(sample);
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
    }

    fn loss_timeout(&self) -> Duration {
        let Some(smoothed) = self.smoothed_rtt else {
            return LOSS_DELAY;
        };
        let variance = (self.rtt_variance * 4).max(Duration::from_millis(1));
        // RFC 9002: PTO = smoothed_rtt + max(4*rttvar, granularity) +
        // max_ack_delay. The floor absorbs scheduling jitter (Windows
        // timer granularity, CPU contention from parallel connections):
        // without it a loopback RTT of ~0.3 ms yields a ~3 ms loss
        // timeout, so a single delayed ACK is misclassified as loss, the
        // congestion window collapses to its 2400-byte floor, and a large
        // body degrades to a crawl (one window per loss timeout).
        (smoothed + variance + ACK_DELAY).max(LOSS_TIMEOUT_FLOOR)
    }

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
            .map(|(_, bytes, offset)| bytes.len().saturating_sub(*offset))
            .fold(0usize, usize::saturating_add);
        if queued.saturating_add(wire.len()) > MAX_H3_CONNECTION_BUFFER {
            return Err(protocol("HTTP/3 response queue limit exceeded"));
        }
        self.queued_streams.push_back((id, wire, 0));
        if let Some(stats) = self.stats.as_deref() {
            Stats::bump_peak(&stats.h3_queue_depth_peak, self.queued_streams.len());
        }
        Ok(())
    }

    fn queued_bytes(&self) -> usize {
        self.queued_streams
            .iter()
            .map(|(_, bytes, offset)| bytes.len().saturating_sub(*offset))
            .fold(0usize, usize::saturating_add)
    }

    fn flush_queued_streams(&mut self, socket: &UdpSocket) -> Result<()> {
        while let Some((id, wire, mut offset)) = self.queued_streams.pop_front() {
            if wire.is_empty() {
                if let Err(error) = self.send_stream_chunk(socket, APPLICATION, id, 0, &[], true) {
                    if error.kind == ErrorKind::WouldBlock {
                        self.queued_streams.push_front((id, wire, offset));
                        return Ok(());
                    }
                    return Err(error);
                }
                continue;
            }
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
                        self.queued_streams.push_front((id, wire, offset));
                        return Ok(());
                    }
                    return Err(error);
                }
                offset = end;
            }
        }
        Ok(())
    }

    fn ack(&mut self, level: LevelIndex) {
        self.spaces[level].ack_pending = true;
        self.spaces[level].ack_deadline = Some(Instant::now());
    }

    fn flush_ack(&mut self, socket: &UdpSocket, level: LevelIndex) -> Result<()> {
        if !self.spaces[level].ack_pending {
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
        self.send_frames(socket, level, &[frame], false)?;
        self.spaces[level].ack_pending = false;
        self.spaces[level].ack_deadline = None;
        Ok(())
    }

    fn retransmit(&mut self, socket: &UdpSocket) -> Result<()> {
        let now = Instant::now();
        let loss_timeout = self.loss_timeout();
        let mut resend = Vec::new();
        let mut lost = false;
        for (level, space) in self.spaces.iter_mut().enumerate() {
            let mut expired = Vec::new();
            for (&pn, packet) in &mut space.sent {
                if packet.ack_eliciting && now.duration_since(packet.sent_at) >= loss_timeout {
                    if packet.retransmits >= MAX_RETRANSMITS {
                        return Err(protocol("QUIC packet loss exceeded retransmission limit"));
                    }
                    packet.retransmits += 1;
                    expired.push((
                        pn,
                        level,
                        packet.frames.clone(),
                        packet.pad_initial,
                        packet.retransmits,
                    ));
                    lost = true;
                }
                if expired.len() >= 8 {
                    break;
                }
            }
            for (pn, _, _, _, _) in &expired {
                space.sent.remove(pn);
            }
            resend.extend(expired);
        }
        if lost {
            self.on_loss();
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
                // The congestion window is full. Put the packet back in
                // `sent` so a later tick retries it with a fresh packet
                // number once ACKs free credit — never tear the
                // connection down over transient congestion.
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

    fn send_frames_with_retransmits(
        &mut self,
        socket: &UdpSocket,
        level: LevelIndex,
        frames: &[QFrame],
        pad_initial: bool,
        retransmits: u8,
    ) -> Result<()> {
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
        if wire.len() > MAX_DATAGRAM {
            return Err(protocol("QUIC packet exceeds UDP datagram limit"));
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
            return Err(Error::new(ErrorKind::WouldBlock));
        }
        self.send_wire(socket, &wire)?;
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

    /// Whether any packet is in flight awaiting an ACK (drives the
    /// driver's periodic retransmit pacing).
    fn has_unacknowledged(&self) -> bool {
        self.spaces.iter().any(|space| !space.sent.is_empty())
    }

    fn send_wire(&self, socket: &UdpSocket, wire: &[u8]) -> Result<()> {
        if let Some(stats) = self.stats.as_deref() {
            stats.h3_udp_send_syscalls.fetch_add(1, Ordering::Relaxed);
        }
        send_datagram(socket, self.peer, wire)
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
    match peer {
        Some(peer) => socket
            .send_to(wire, peer)
            .map(|_| ())
            .map_err(|e| io_error(e.to_string())),
        None => socket
            .send(wire)
            .map(|_| ())
            .map_err(|e| io_error(e.to_string())),
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
    largest: u64,
    ranges: &[(u64, u64)],
) -> (usize, Option<Duration>) {
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
    (acknowledged_bytes, rtt_sample)
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
    let saved = expected_phase
        .is_some()
        .then(|| datagram[..header_room].to_vec());
    let Ok(pn_len) = key.unprotect_header(datagram, meta.pn_offset, meta.long_type.is_some())
    else {
        return Ok(None);
    };
    if let Some(expected_phase) = expected_phase {
        let phase = datagram[0] & 0x04 != 0;
        if phase != expected_phase {
            if let Some(saved) = &saved {
                datagram[..header_room].copy_from_slice(saved);
            }
            return Ok(None);
        }
    }
    let payload_start = meta
        .pn_offset
        .checked_add(pn_len)
        .ok_or_else(|| protocol("QUIC packet-number offset overflow"))?;
    if payload_start > meta.packet_end {
        return Err(protocol("QUIC packet number exceeds packet length"));
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

    #[test]
    fn qpack_request_round_trip_is_bounded() {
        let req = Request::<Body>::new(Method::POST, "/upload")
            .header("content-type", "application/octet-stream");
        let wire = build_request_wire(req, "example.test:443", 16 * 1024, 1024).unwrap();
        assert!(wire.len() < 1024);
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
            }),
            max_header_list: 16 * 1024,
            max_body,
            read_timeout: Some(timeout),
            ..Default::default()
        })
    }

    #[test]
    fn loopback_quic_tls_http3_round_trip() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        drop(tcp);

        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity: identity.clone(),
            alpn: vec![b"h3".to_vec()],
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
        let _server = spawn_server(addr, &tls, handler, config).unwrap();

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
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        drop(tcp);
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
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
        let _server = spawn_server(addr, &tls, handler, config).unwrap();

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

    #[test]
    fn loopback_http3_large_response_drains_congestion_queue() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        drop(tcp);
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
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
        let _server = spawn_server(addr, &tls, handler, config).unwrap();
        let client = h3_client(128 * 1024, Duration::from_secs(10));
        let response = client
            .get(&format!("https://localhost:{}/large", addr.port()))
            .unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_bytes(), Some(expected.as_slice()));
    }

    #[test]
    fn loopback_http3_large_request_body_is_fully_delivered() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        drop(tcp);
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
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
        let _server = spawn_server(addr, &tls, handler, config).unwrap();
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
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        drop(tcp);
        let identity = crate::courierust_tls::testdata::server_identity();
        let tls = TlsSettings {
            identity,
            alpn: vec![b"h3".to_vec()],
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
        let _server = spawn_server(addr, &tls, handler, config).unwrap();

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
}
