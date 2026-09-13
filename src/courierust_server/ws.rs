//! Server-side WebSocket: policy, handshake completion and drivers.
//!
//! # One application API, two drivers
//!
//! An application implements [`WsService`] and returns it from
//! [`crate::courierust_server::Handler::websocket`]. The transport then
//! decides how the service is driven:
//!
//! * **Blocking driver** (`serve_blocking`, private to this module) — one
//!   worker thread per WebSocket. Used for TLS connections and for
//!   `ServerConfig::event_driven = false`. It applies keepalive pings, a
//!   read timeout for liveness, and completes the closing handshake with
//!   a bounded wait.
//! * **Reactor driver** (used by the default event-driven server): the
//!   connection stays in the readiness poller, frames are read only when
//!   the socket is readable, application sends are queued in a bounded
//!   [`OutQueue`] and flushed when it is writable. Ten thousand idle
//!   connections cost ten thousand buffers, not ten thousand threads.
//!
//! Both hand the application the same [`WsConn`] 鈥?including
//! [`WsConn::sender`], a `Send + Sync` push handle for other threads. The
//! *frame* boundary lives inside the sink's lock, so two writers can
//! never interleave a frame's bytes on the wire.
//!
//! # Policy before payload
//!
//! [`plan`] validates the entire opening handshake before a single byte
//! is buffered for the application: method, `Upgrade`/`Connection`
//! tokens, `Sec-WebSocket-Key` shape, `Sec-WebSocket-Version` presence,
//! uniqueness and value (answered with `426` +
//! `Sec-WebSocket-Version: 13` when wrong), the [`OriginPolicy`]
//! (trusted-proxy aware, so an Nginx or Traefik deployment behind TLS
//! still gets a meaningful same-origin check), and the extension offer.
//! A refusal is data ([`WsRefusal`]), so the caller can log the cause and
//! answer with the right status while the connection falls through to
//! the normal HTTP handler.

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::version::Version;
use crate::courierust_io::BufReader;
use crate::courierust_net::ConnStream;
use crate::courierust_server::Handler;
use crate::courierust_ws::frame::{FrameSink, Mask, SharedSink};
use crate::courierust_ws::handshake::{
    self, accept_key, CompressionParams, IpNet, OriginPolicy, PerMessageDeflate, PmDeflatePolicy,
    WsOffer,
};
use crate::courierust_ws::session::{MaskSource, Role, Session, SessionConfig, Stats};
use crate::courierust_ws::writer::{CloseFlag, FrameWriter};
use crate::courierust_ws::Event;
use core::any::Any;
use core::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Server-wide WebSocket policy.
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// Master switch. When off, upgrade requests are answered as normal
    /// HTTP requests.
    pub enabled: bool,
    /// Which `Origin` values are accepted.
    /// the only default a random web page cannot exploit.
    pub origin: OriginPolicy,
    /// Addresses whose `X-Forwarded-*` headers are believed.
    pub trusted_proxies: Vec<IpNet>,
    /// Subprotocols this server supports, in server preference order.
    pub subprotocols: Vec<String>,
    /// `permessage-deflate` policy.
    pub compression: PmDeflatePolicy,
    /// Largest accepted single-frame payload.
    pub max_frame: usize,
    /// Largest accepted message (measured after inflating, for
    /// compressed messages).
    pub max_message: usize,
    /// Largest fragment count per message (0 = unlimited).
    pub max_fragments: u32,
    /// Largest number of bytes queued for a slow consumer before the
    /// connection fails. Bounds memory when the application pushes faster
    /// than the peer reads.
    pub max_send_queue: usize,
    /// Read buffer size per WebSocket connection. Larger buffers mean
    /// fewer read syscalls for large messages, at a per-connection memory
    /// cost; 64 KiB is a good default for media-ish traffic, 16 KiB for
    /// large fleets of mostly-idle connections.
    pub read_buffer: usize,
    /// Send an unsolicited Ping after this much inbound silence, and give
    /// up on the connection at twice that. `None` disables keepalive.
    pub ping_interval: Option<Duration>,
    /// How long to wait for the peer's close echo after we initiate the
    /// closing handshake.
    pub close_timeout: Option<Duration>,
}

impl Default for WsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            origin: OriginPolicy::default(),
            trusted_proxies: Vec::new(),
            subprotocols: Vec::new(),
            compression: PmDeflatePolicy::default(),
            max_frame: 16 * 1024 * 1024,
            max_message: 16 * 1024 * 1024,
            max_fragments: 0,
            max_send_queue: 4 * 1024 * 1024,
            read_buffer: 64 * 1024,
            ping_interval: Some(Duration::from_secs(30)),
            close_timeout: Some(Duration::from_secs(5)),
        }
    }
}

/// What a handler answers when asked about an upgrade request.
pub enum WsUpgradeReply {
    /// Serve the connection with this service.
    Accept(Arc<dyn WsService>),
    /// Refuse the upgrade and answer with this response instead.
    Refuse(Response<Body>),
    /// Not a WebSocket route: fall through to the normal HTTP handler.
    Pass,
}

/// A message delivered to a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsData {
    /// UTF-8 text.
    Text(String),
    /// Binary payload.
    Binary(Bytes),
}

/// The application callbacks for one connection.
///
/// Every method has a default, so a service implements only what it
/// needs. Callbacks must not block for long: on the reactor path they run
/// on an event worker, and a slow callback delays every other connection
/// that worker owns.
pub trait WsService: Send + Sync + 'static {
    /// The handshake completed and the connection is open.
    fn on_open(&self, _c: &mut WsConn) {}

    /// A complete text or binary message arrived.
    fn on_message(&self, _c: &mut WsConn, _msg: WsData) {}

    /// A Pong arrived (usually the answer to our keepalive Ping).
    fn on_pong(&self, _c: &mut WsConn, _payload: &[u8]) {}

    /// The connection ended. `code` is the peer's close code when it sent
    /// one; `clean` is false when the transport failed without a closing
    /// handshake.
    fn on_close(&self, _c: &mut WsConn, _code: Option<u16>, _clean: bool) {}

    /// Called after `ping_interval` of inbound silence. Override to send
    /// application-level keepalive traffic; the default does nothing and
    /// the driver's own Ping already went out.
    fn on_idle(&self, _c: &mut WsConn) {}
}

/// A service that only cares about messages (the common echo case).
impl<F> WsService for F
where
    F: Fn(&mut WsConn, WsData) + Send + Sync + 'static,
{
    fn on_message(&self, c: &mut WsConn, msg: WsData) {
        self(c, msg)
    }
}

/// Everything the application can learn about an accepted connection.
#[derive(Debug, Clone)]
pub struct WsInfo {
    /// Request target the client asked for (`/chat?room=1`).
    pub path: String,
    /// Remote address of the transport peer.
    pub peer: IpAddr,
    /// Client address after trusted-proxy resolution.
    pub client_ip: IpAddr,
    /// Whether the client's connection was encrypted (directly, or at a
    /// trusted proxy that reported `https`).
    pub secure: bool,
    /// The client's `Origin`, when it sent one.
    pub origin: Option<String>,
    /// The negotiated subprotocol, if any.
    pub protocol: Option<String>,
    /// The negotiated `permessage-deflate` parameters, if any.
    pub compression: Option<PerMessageDeflate>,
}

// ---------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------

/// A destination for frames that the event reactor flushes later.
///
/// Sends append here and nudge the reactor; the reactor writes when the
/// socket reports writability. The queue is bounded, so a peer that stops
/// reading while the application keeps pushing fails the connection
/// instead of growing the process.
pub struct OutQueue {
    buf: Vec<u8>,
    pos: usize,
    limit: usize,
    closed: bool,
}

impl OutQueue {
    /// A queue holding at most `limit` bytes.
    pub fn new(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            limit,
            closed: false,
        }
    }

    /// Bytes waiting to be written.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether the queue is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the queue has been failed (overflow or connection close).
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Mark the queue unusable (the connection is going away).
    pub fn close(&mut self) {
        self.closed = true;
        self.buf.clear();
        self.pos = 0;
    }

    /// Append bytes, compacting the consumed prefix first so the buffer
    /// does not grow without bound under steady traffic.
    pub fn append(&mut self, bytes: &[u8]) -> Result<()> {
        if self.closed {
            return Err(Error::canceled("websocket: connection is closed"));
        }
        self.reserve(bytes.len())?;
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Append a masked copy of `payload` (copy and XOR fused into one
    /// pass over the bytes).
    pub fn append_masked(&mut self, payload: &[u8], mask: Mask) -> Result<()> {
        if self.closed {
            return Err(Error::canceled("websocket: connection is closed"));
        }
        self.reserve(payload.len())?;
        let start = self.buf.len();
        self.buf.extend_from_slice(payload);
        mask.apply(0, &mut self.buf[start..]);
        Ok(())
    }

    fn reserve(&mut self, incoming: usize) -> Result<()> {
        if self.pos > 0 && (self.pos == self.buf.len() || self.pos + incoming > self.limit) {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        if self.buf.len() + incoming > self.limit {
            self.closed = true;
            self.buf.clear();
            self.pos = 0;
            return Err(Error::overflow("websocket: send queue overflow"));
        }
        Ok(())
    }

    /// Write as much as the transport accepts. Returns `true` when the
    /// queue drained, `false` when the transport would block.
    pub fn drain(&mut self, writer: &mut impl crate::courierust_io::Write) -> Result<bool> {
        while self.pos < self.buf.len() {
            match crate::courierust_io::Write::write(writer, &self.buf[self.pos..]) {
                Ok(0) => return Err(Error::io("websocket: write made no progress")),
                Ok(n) => self.pos += n,
                Err(e) if e.kind == ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        self.buf.clear();
        self.pos = 0;
        Ok(true)
    }
}

/// A [`FrameSink`] that queues frames for a reactor and nudges it.
#[derive(Clone)]
pub struct QueueSink {
    queue: Arc<Mutex<OutQueue>>,
    wake: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl QueueSink {
    /// Wrap a shared queue; `wake` runs after a frame is queued.
    pub fn new(queue: Arc<Mutex<OutQueue>>, wake: Option<Arc<dyn Fn() + Send + Sync>>) -> Self {
        Self { queue, wake }
    }

    /// The shared queue.
    pub fn queue(&self) -> &Arc<Mutex<OutQueue>> {
        &self.queue
    }
}

impl FrameSink for QueueSink {
    fn write_frame(&mut self, header: &[u8], payload: &[u8], mask: Option<Mask>) -> Result<()> {
        {
            let mut q = lock(&self.queue);
            // Reserve the whole frame before writing a byte of it, so an
            // overflow can never leave half a frame queued.
            if q.len() + header.len() + payload.len() > q.limit {
                q.close();
                return Err(Error::overflow("websocket: send queue overflow"));
            }
            q.append(header)?;
            match mask {
                None => q.append(payload)?,
                Some(m) => q.append_masked(payload, m)?,
            }
        }
        if let Some(wake) = &self.wake {
            wake();
        }
        Ok(())
    }
}

/// A blocking [`FrameSink`] shared between the read loop and any thread
/// that pushes messages: one lock per frame makes frames atomic on the
/// wire.
pub(crate) type SharedStreamSink = SharedSink<Arc<ConnStream>>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Type-erased sink used by [`WsConn`], so the service API is independent
/// of which driver owns the connection.
pub type BoxSink = Box<dyn FrameSink + Send>;

// ---------------------------------------------------------------------
// Connection handed to the application
// ---------------------------------------------------------------------

struct WsConnInner {
    info: WsInfo,
    /// Outbound frames; shared with [`WsConn::sender`] handles.
    writer: Mutex<FrameWriter<BoxSink>>,
    /// One application state slot, so a service can attach per-connection
    /// data instead of instantiating a service per connection.
    state: Mutex<Option<Box<dyn Any + Send>>>,
    /// Set once a close frame has been queued.
    closing: AtomicBool,
}

/// The connection handed to a [`WsService`].
#[derive(Clone)]
pub struct WsConn {
    inner: Arc<WsConnInner>,
}

impl WsConn {
    fn new(info: WsInfo, writer: FrameWriter<BoxSink>) -> Self {
        Self {
            inner: Arc::new(WsConnInner {
                info,
                writer: Mutex::new(writer),
                state: Mutex::new(None),
                closing: AtomicBool::new(false),
            }),
        }
    }

    /// Handshake and connection facts.
    pub fn info(&self) -> &WsInfo {
        &self.inner.info
    }

    /// The requested target (`/chat?room=1`).
    pub fn path(&self) -> &str {
        &self.inner.info.path
    }

    /// The client's address (after trusted-proxy resolution).
    pub fn client_ip(&self) -> IpAddr {
        self.inner.info.client_ip
    }

    /// The transport peer's address.
    pub fn peer(&self) -> IpAddr {
        self.inner.info.peer
    }

    /// Whether the client's connection is encrypted.
    pub fn is_secure(&self) -> bool {
        self.inner.info.secure
    }

    /// The negotiated subprotocol.
    pub fn protocol(&self) -> Option<&str> {
        self.inner.info.protocol.as_deref()
    }

    /// The negotiated compression parameters.
    pub fn compression(&self) -> Option<PerMessageDeflate> {
        self.inner.info.compression
    }

    /// Whether a close frame has already been queued.
    pub fn is_closing(&self) -> bool {
        self.inner.closing.load(Ordering::Acquire)
    }

    /// Attach per-connection application state.
    pub fn set_state<T: Any + Send>(&self, value: T) {
        let mut slot = lock(&self.inner.state);
        *slot = Some(Box::new(value));
    }

    /// Run `f` with the per-connection state, if it holds a `T`.
    pub fn with_state<T: Any + Send, R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut slot = lock(&self.inner.state);
        slot.as_mut()?.downcast_mut::<T>().map(f)
    }

    /// Drop the per-connection state.
    pub fn clear_state(&self) {
        *lock(&self.inner.state) = None;
    }

    /// Send a text message.
    pub fn send_text(&self, text: &str) -> Result<()> {
        lock(&self.inner.writer).send_text(text)
    }

    /// Send a binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        lock(&self.inner.writer).send_binary(data)
    }

    /// Send a Ping.
    pub fn send_ping(&self, payload: &[u8]) -> Result<()> {
        lock(&self.inner.writer).send_ping(payload)
    }

    /// Send a Pong.
    pub fn send_pong(&self, payload: &[u8]) -> Result<()> {
        lock(&self.inner.writer).send_pong(payload)
    }

    /// Start the closing handshake (idempotent).
    pub fn close(&self, code: u16, reason: &str) -> Result<()> {
        if self.inner.closing.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        lock(&self.inner.writer).send_close(code, reason)
    }

    /// A `Send + Sync` handle for pushing messages from other threads.
    pub fn sender(&self) -> WsSender {
        WsSender {
            inner: self.inner.clone(),
        }
    }

    /// The write-side counters for this connection.
    pub fn stats(&self) -> Stats {
        *lock(&self.inner.writer).stats()
    }
}

/// A clone-able push handle for a connection ([`WsConn::sender`]).
#[derive(Clone)]
pub struct WsSender {
    inner: Arc<WsConnInner>,
}

impl WsSender {
    /// Send a text message.
    pub fn send_text(&self, text: &str) -> Result<()> {
        lock(&self.inner.writer).send_text(text)
    }

    /// Send a binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        lock(&self.inner.writer).send_binary(data)
    }

    /// Send a Ping.
    pub fn send_ping(&self, payload: &[u8]) -> Result<()> {
        lock(&self.inner.writer).send_ping(payload)
    }

    /// Start the closing handshake.
    pub fn close(&self, code: u16, reason: &str) -> Result<()> {
        if self.inner.closing.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        lock(&self.inner.writer).send_close(code, reason)
    }

    /// Whether a close has already been queued.
    pub fn is_closing(&self) -> bool {
        self.inner.closing.load(Ordering::Acquire)
    }
}

// ---------------------------------------------------------------------
// Handshake planning
// ---------------------------------------------------------------------

/// Why an upgrade was refused, with the response the caller should send.
#[derive(Debug, Clone)]
pub struct WsRefusal {
    /// HTTP status to answer with.
    pub status: StatusCode,
    /// Short reason, for logs.
    pub reason: &'static str,
    /// Whether to advertise `Sec-WebSocket-Version: 13` (RFC 6455 搂4.4
    /// requires it on the `426` answer).
    pub advertise_version: bool,
}

impl WsRefusal {
    fn new(status: u16, reason: &'static str) -> Self {
        Self {
            status: StatusCode::from_u16(status),
            reason,
            advertise_version: status == 426,
        }
    }

    /// Build the response to send instead of `101`.
    pub fn response(&self) -> Response<Body> {
        let mut resp: Response<Body> = Response::with_status(self.status);
        if self.advertise_version {
            resp.headers.insert(
                HeaderName::from_lowercase("sec-websocket-version"),
                HeaderValue::from_static("13"),
            );
        }
        resp.headers.insert(
            HeaderName::from_lowercase("content-type"),
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        resp.headers.insert(
            HeaderName::from_lowercase("connection"),
            HeaderValue::from_static("close"),
        );
        resp.body = Body::Bytes(Bytes::from(alloc::format!("{}\n", self.reason)));
        resp
    }
}

/// A validated upgrade, ready to be answered with `101`.
#[derive(Debug, Clone)]
pub struct WsPlan {
    /// The parsed client offer.
    pub offer: WsOffer,
    /// Selected subprotocol.
    pub protocol: Option<String>,
    /// Selected extension parameters.
    pub compression: Option<PerMessageDeflate>,
}

impl WsPlan {
    /// Compression parameters for the server endpoint.
    pub fn server_compression(&self) -> Option<CompressionParams> {
        self.compression.map(|p| p.server_view())
    }

    /// The `101 Switching Protocols` head, fully populated.
    pub fn accept_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::with_capacity(4);
        headers.insert(
            HeaderName::from_lowercase("upgrade"),
            HeaderValue::from_static("websocket"),
        );
        headers.insert(
            HeaderName::from_lowercase("connection"),
            HeaderValue::from_static("Upgrade"),
        );
        headers.insert(
            HeaderName::from_lowercase("sec-websocket-accept"),
            HeaderValue::from_bytes(accept_key(&self.offer.key)?.as_bytes())?,
        );
        if let Some(protocol) = &self.protocol {
            headers.insert(
                HeaderName::from_lowercase("sec-websocket-protocol"),
                HeaderValue::from_bytes(protocol.as_bytes())?,
            );
        }
        if let Some(pm) = &self.compression {
            headers.insert(
                HeaderName::from_lowercase("sec-websocket-extensions"),
                HeaderValue::from_bytes(pm.response_header().as_bytes())?,
            );
        }
        Ok(headers)
    }
}

/// Validate an upgrade request against the server policy.
///
/// Pure: it inspects the request and returns either a plan or the refusal
/// to answer with. Nothing is written and no buffer is consumed, so a
/// refusal can fall through to the normal HTTP handler with the
/// connection intact.
pub fn plan(
    req: &Request<Body>,
    peer: IpAddr,
    tls_active: bool,
    ws: &WsConfig,
) -> core::result::Result<WsPlan, WsRefusal> {
    if !ws.enabled {
        return Err(WsRefusal::new(400, "websocket: disabled"));
    }
    // A missing or duplicated upgrade header set is not an upgrade at all
    // (the caller decides whether that is a 400 or a normal request).
    if !handshake::is_websocket_upgrade(&req.headers) {
        return Err(WsRefusal::new(400, "websocket: not an upgrade request"));
    }
    if req.method != Method::GET {
        return Err(WsRefusal::new(405, "websocket: upgrade requires GET"));
    }
    // RFC 6455 §4.1/§4.2.1: the opening handshake is an HTTP/1.1 (or
    // later) GET. Accepting an HTTP/1.0 upgrade would answer 101 to a
    // peer that has no defined meaning for what follows, and a proxy on
    // the path may disagree about whether frames or a body come next.
    if req.version != Version::HTTP_11 {
        return Err(WsRefusal::new(400, "websocket: upgrade requires HTTP/1.1"));
    }
    let versions: Vec<&HeaderValue> = req.headers.get_all("sec-websocket-version").collect();
    if versions.len() != 1 {
        // Not an upgrade, or an ambiguous set of versions.
        return Err(WsRefusal::new(
            426,
            "websocket: missing or duplicate Sec-WebSocket-Version",
        ));
    }
    let version_text = versions[0].to_str().unwrap_or("").trim();
    if version_text != "13" {
        return Err(WsRefusal::new(
            426,
            "websocket: only version 13 is supported",
        ));
    }
    let offer = match WsOffer::parse(req, peer, tls_active, &ws.trusted_proxies) {
        Ok(o) => o,
        Err(_) => return Err(WsRefusal::new(400, "websocket: malformed upgrade request")),
    };
    if !ws
        .origin
        .check(offer.origin.as_deref(), offer.request_origin().as_deref())
    {
        return Err(WsRefusal::new(403, "websocket: origin rejected"));
    }
    // Subprotocol selection. With no server list, none is selected (and
    // none may be advertised: RFC 6455 搂4.2.2 only allows echoing a
    // protocol the server actually supports).
    let protocol = if ws.subprotocols.is_empty() {
        None
    } else {
        offer.select_protocol(&ws.subprotocols)
    };
    let compression = offer
        .extension("permessage-deflate")
        .and_then(|e| PerMessageDeflate::negotiate(e, &ws.compression));
    Ok(WsPlan {
        offer,
        protocol,
        compression,
    })
}

/// The session configuration implied by a plan and the server policy.
pub fn session_config(ws: &WsConfig, params: Option<CompressionParams>) -> SessionConfig {
    SessionConfig {
        role: Role::Server,
        max_frame: ws.max_frame,
        max_message: ws.max_message,
        max_fragments: ws.max_fragments,
        compression: params,
        auto_pong: true,
    }
}

/// Map a protocol error to the close code RFC 6455 §7.4 prescribes.
///
/// Only meaningful for [`reports_violation`] errors; a transport failure
/// has no code to report.
pub fn protocol_close(e: &Error) -> (u16, &'static str) {
    match e.kind {
        ErrorKind::Overflow => (1009, "message too big"),
        ErrorKind::Protocol => {
            if e.message
                .as_deref()
                .map(|m| m.contains("UTF-8"))
                .unwrap_or(false)
            {
                (1007, "invalid payload data")
            } else {
                (1002, "protocol error")
            }
        }
        _ => (1002, "protocol error"),
    }
}

/// Whether an error is the peer's fault and therefore worth a Close frame.
///
/// A protocol violation or an oversized message is reported with the code
/// §7.4 prescribes. A transport failure is not the peer's protocol
/// misbehaviour, there is usually no transport left to report it on, and
/// claiming `1002 protocol error` for a broken socket is a lie the
/// application can see through `clean == false`.
pub fn reports_violation(e: &Error) -> bool {
    matches!(e.kind, ErrorKind::Protocol | ErrorKind::Overflow)
}

/// Ask a handler whether it wants a WebSocket connection.
pub fn ask_handler(handler: &dyn Handler, req: &Request<Body>) -> WsUpgradeReply {
    handler.websocket(req)
}

// ---------------------------------------------------------------------
// The reactor driver
// ---------------------------------------------------------------------

/// What a reactor step wants to happen next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WsStep {
    /// Park the connection on the poller for readability.
    Idle,
    /// Park it for writability (the queue could not drain).
    NeedWrite,
    /// The connection is finished; the reactor drops it.
    Close,
}

/// A late-bound wake callback.
///
/// The reactor is the only component that knows how to wake itself (its
/// control channel plus its self-pipe), and the connection is built
/// before the reactor installs it. A slot bridges the two without
/// threading the reactor's handles through the handshake code.
#[derive(Default)]
pub(crate) struct WakeSlot {
    inner: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl WakeSlot {
    /// A shared, empty slot.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Install the callback (done by the reactor when the connection
    /// joins its registry).
    pub(crate) fn set(&self, wake: Arc<dyn Fn() + Send + Sync>) {
        *lock(&self.inner) = Some(wake);
    }

    /// Ask the reactor to wake this connection's file descriptor.
    pub(crate) fn fire(&self) {
        let wake = lock(&self.inner).clone();
        if let Some(wake) = wake {
            wake();
        }
    }
}

/// The reactor driver for one WebSocket connection.
///
/// The connection never leaves the event loop: frames are read only when
/// the socket is readable, and queued application sends are flushed only
/// when it is writable. An idle WebSocket therefore costs a buffer and a
/// poller slot — not a thread.
pub(crate) struct WsEventConn {
    socket: Arc<std::net::TcpStream>,
    session: Session<Arc<std::net::TcpStream>, BoxSink>,
    conn: WsConn,
    queue: Arc<Mutex<OutQueue>>,
    service: Arc<dyn WsService>,
    ping_interval: Option<Duration>,
    close_timeout: Option<Duration>,
    last_recv: Instant,
    /// When the last keepalive Ping went out. Separate from `last_recv`
    /// so the Ping cadence does not have to lie about when the peer was
    /// last heard from (which is what makes the “two intervals of
    /// silence” cutoff below reachable).
    last_ping: Instant,
    /// When the closing handshake started (our side sent or queued a
    /// close frame).
    closing_at: Option<Instant>,
    /// Set once `on_close` has been delivered, so a service sees exactly
    /// one end-of-connection callback regardless of which path noticed.
    reported: bool,
    /// Late-bound reactor wakeup.
    wake: Arc<WakeSlot>,
}

impl WsEventConn {
    /// Build a reactor connection. `leftover` is whatever the HTTP/1.1
    /// parser had already buffered past the handshake — a client is
    /// allowed to pipeline frames behind its request, and dropping them
    /// would be a silent data loss.
    pub(crate) fn new(
        socket: Arc<std::net::TcpStream>,
        leftover: &[u8],
        plan: WsPlan,
        service: Arc<dyn WsService>,
        ws: &WsConfig,
        wake: Arc<WakeSlot>,
    ) -> Self {
        let info = WsInfo {
            path: plan.offer.path.clone(),
            peer: plan.offer.peer,
            client_ip: plan.offer.client_ip,
            secure: plan.offer.secure,
            origin: plan.offer.origin.clone(),
            protocol: plan.protocol.clone(),
            compression: plan.compression,
        };
        let params = plan.server_compression();
        let queue = Arc::new(Mutex::new(OutQueue::new(ws.max_send_queue)));
        let slot = wake.clone();
        let sink = QueueSink::new(
            queue.clone(),
            Some(Arc::new(move || slot.fire()) as Arc<dyn Fn() + Send + Sync>),
        );
        let writer = FrameWriter::new(Box::new(sink.clone()) as BoxSink, MaskSource::None, params);
        // The read buffer must hold everything the HTTP parser left over,
        // plus a normal working window.
        let cap = ws.read_buffer.max(16 * 1024) + leftover.len();
        let mut reader = BufReader::new(socket.clone(), cap);
        if !leftover.is_empty() {
            reader.seed(leftover);
        }
        let session = Session::new(reader, writer, session_config(ws, params));
        let conn_writer = FrameWriter::with_close_flag(
            Box::new(sink) as BoxSink,
            MaskSource::None,
            params,
            session.writer().close_flag(),
        );
        let mut conn = WsConn::new(info, conn_writer);
        service.on_open(&mut conn);
        Self {
            socket,
            session,
            conn,
            queue,
            service,
            ping_interval: ws.ping_interval,
            close_timeout: ws.close_timeout,
            last_recv: Instant::now(),
            last_ping: Instant::now(),
            closing_at: None,
            reported: false,
            wake,
        }
    }

    /// Install the reactor's wakeup (called when the connection joins the
    /// WebSocket registry).
    pub(crate) fn set_wake(&mut self, wake: Arc<dyn Fn() + Send + Sync>) {
        self.wake.set(wake);
    }

    /// The transport (so the reactor can compute the file descriptor).
    pub(crate) fn socket(&self) -> &Arc<std::net::TcpStream> {
        &self.socket
    }

    /// Whether anything is queued for writing.
    pub(crate) fn has_queued_output(&self) -> bool {
        !lock(&self.queue).is_empty()
    }

    /// The next instant at which [`WsEventConn::step`] must run even
    /// though the socket stays silent.
    ///
    /// Keepalive and the closing handshake are time-driven, and a peer
    /// that goes quiet produces no readiness event to hang them off: a
    /// half-open connection would otherwise keep its poller slot and
    /// buffers until the process exits. The reactor folds this into its
    /// wait timeout and dispatches the connection when it elapses.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        if let Some(started) = self.closing_at {
            return Some(started + self.close_timeout.unwrap_or(Duration::from_secs(5)));
        }
        let interval = self.ping_interval?;
        let close_due = self.last_recv + interval.saturating_mul(2);
        // One Ping per interval, measured from the last Ping as well as
        // from the last inbound frame, so a connection that is already
        // overdue is not dispatched on every reactor tick.
        let ping_due = core::cmp::max(self.last_recv + interval, self.last_ping + interval);
        Some(core::cmp::min(ping_due, close_due))
    }

    /// Push queued frames to the socket.
    /// `Ok(true)` drained, `Ok(false)` would block, `Err(())` fatal.
    fn try_flush(&mut self) -> core::result::Result<bool, ()> {
        if !self.has_queued_output() {
            return Ok(true);
        }
        let stream = self.socket.clone();
        let mut writer: &std::net::TcpStream = &stream;
        let drained = {
            let mut q = lock(&self.queue);
            q.drain(&mut writer)
        };
        match drained {
            Ok(drained) => Ok(drained),
            Err(_) => Err(()),
        }
    }

    /// Deliver the end-of-connection callback exactly once.
    fn report_close(&mut self, code: Option<u16>, clean: bool) {
        if !self.reported {
            self.reported = true;
            self.service.on_close(&mut self.conn, code, clean);
        }
    }

    /// Begin the closing handshake on our side.
    fn request_close(&mut self, code: u16, reason: &str) {
        let _ = self.conn.close(code, reason);
        if self.closing_at.is_none() {
            self.closing_at = Some(Instant::now());
            self.session.note_close_sent();
        }
    }

    /// One non-blocking step: flush what is queued, read what is
    /// available, apply keepalive and close bookkeeping.
    pub(crate) fn step(&mut self) -> WsStep {
        // ---- 1. Flush queued frames -------------------------------
        match self.try_flush() {
            Ok(true) => {}
            Ok(false) => {
                // The peer is not reading. The queue is bounded, so an
                // application that keeps pushing hits the cap and the
                // connection is failed instead of growing the process.
                if lock(&self.queue).is_closed() {
                    self.request_close(1009, "send queue overflow");
                    return WsStep::Close;
                }
                return WsStep::NeedWrite;
            }
            Err(()) => {
                self.report_close(None, false);
                return WsStep::Close;
            }
        }

        // ---- 2. Read available frames -----------------------------
        loop {
            match self.session.poll_message() {
                Ok(Some(event)) => {
                    self.last_recv = Instant::now();
                    match event {
                        Event::Text(t) => self.service.on_message(&mut self.conn, WsData::Text(t)),
                        Event::Binary(b) => {
                            self.service.on_message(&mut self.conn, WsData::Binary(b))
                        }
                        Event::Ping(_) => {
                            // The session queued an identical Pong.
                        }
                        Event::Pong(p) => self.service.on_pong(&mut self.conn, &p),
                        Event::Close(frame) => {
                            let code = frame.as_ref().map(|f| f.code);
                            // Our reply is already queued by the session;
                            // now the handshake just has to drain.
                            self.closing_at = Some(Instant::now());
                            self.report_close(code, true);
                            break;
                        }
                    }
                    if self.conn.is_closing() && self.closing_at.is_none() {
                        // The application asked to close.
                        self.closing_at = Some(Instant::now());
                        self.session.note_close_sent();
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    // A peer protocol violation is answered with the code
                    // §7.4 prescribes; a transport failure is reported to
                    // the application and nothing is claimed to the peer.
                    if reports_violation(&e) {
                        let (code, reason) = protocol_close(&e);
                        self.request_close(code, reason);
                        self.report_close(Some(code), false);
                        // Fall through: the queued close frame (if any)
                        // still has to reach the peer, so the return
                        // below flushes first.
                        break;
                    }
                    // EOF or a reset: there is no peer left to flush a
                    // close frame to, and staying registered would spin
                    // the reactor on a socket that reports readable
                    // forever (a half-closed peer is permanently
                    // “ready”).
                    self.report_close(None, false);
                    return WsStep::Close;
                }
            }
        }

        // ---- 3. Close bookkeeping ---------------------------------
        if let Some(started) = self.closing_at {
            match self.try_flush() {
                Ok(false) => return WsStep::NeedWrite,
                Err(()) => return WsStep::Close,
                Ok(true) => {}
            }
            let timeout = self.close_timeout.unwrap_or(Duration::from_secs(5));
            if self.session.close_received() || started.elapsed() >= timeout {
                self.report_close(None, self.session.close_received());
                return WsStep::Close;
            }
            return WsStep::Idle;
        }

        // ---- 4. Keepalive -----------------------------------------
        if let Some(interval) = self.ping_interval {
            let idle = self.last_recv.elapsed();
            if idle >= interval.saturating_mul(2) {
                self.request_close(1001, "keepalive timeout");
                self.report_close(Some(1001), false);
                return WsStep::NeedWrite;
            }
            if idle >= interval {
                let _ = self.conn.send_ping(b"");
                // One Ping per interval rather than one per reactor wake:
                // the deadline is measured against `last_ping`, not by
                // pretending the peer just spoke.
                self.last_ping = Instant::now();
                self.service.on_idle(&mut self.conn);
            }
        }

        if self.has_queued_output() {
            // A callback (or another thread) queued frames: ask the
            // reactor to wake us up for writability.
            return WsStep::NeedWrite;
        }
        WsStep::Idle
    }
}

// ---------------------------------------------------------------------
// The blocking driver
// ---------------------------------------------------------------------

/// Serve an accepted upgrade on a blocking transport until it ends.
///
/// The caller must already have written the `101` head (the accept
/// headers come from [`WsPlan::accept_headers`]) and must hand over the
/// connection's buffered reader, so bytes the client pipelined behind the
/// handshake are not lost.
pub(crate) fn serve_blocking(
    stream: Arc<ConnStream>,
    reader: BufReader<Arc<ConnStream>>,
    plan: WsPlan,
    service: Arc<dyn WsService>,
    ws: &WsConfig,
) -> Result<()> {
    let info = WsInfo {
        path: plan.offer.path.clone(),
        peer: plan.offer.peer,
        client_ip: plan.offer.client_ip,
        secure: plan.offer.secure,
        origin: plan.offer.origin.clone(),
        protocol: plan.protocol.clone(),
        compression: plan.compression,
    };
    let params = plan.server_compression();
    // Two writers over one shared sink: the session's (Pongs, Close) and
    // the application's (messages). The sink's lock is what makes frames
    // atomic; they share one close flag so that whichever side sends the
    // Close frame, the other one stops (RFC 6455 §5.5.1).
    let sink = SharedStreamSink::new(stream.clone());
    let close_flag = CloseFlag::new();
    let writer = FrameWriter::with_close_flag(
        Box::new(sink.clone()) as BoxSink,
        MaskSource::None,
        params,
        close_flag.clone(),
    );
    let mut session = Session::new(reader, writer, session_config(ws, params));
    let conn_writer = FrameWriter::with_close_flag(
        Box::new(sink) as BoxSink,
        MaskSource::None,
        params,
        close_flag,
    );
    let mut conn = WsConn::new(info, conn_writer);

    service.on_open(&mut conn);

    // Keepalive reads: a deadline on the *idle* wait lets the driver
    // notice a silent peer and Ping it. The deadline is armed only while
    // waiting for the next frame and cleared while a message is being
    // handled, because a socket deadline is not free on every platform:
    // Windows charges for it on every blocking operation of the socket,
    // including writes, and a 256 KiB push loop runs roughly twice as
    // fast with it cleared (and about ten times as fast when the peer
    // also sets one). Idle detection is what it is for; bulk transfer is
    // not idle.
    let mut last_recv = Instant::now();
    let mut close_code: Option<u16> = None;
    let mut clean = false;

    loop {
        if let Some(interval) = ws.ping_interval {
            let _ = stream.configure(Some(interval));
        }
        let polled = session.poll_message();
        if ws.ping_interval.is_some() {
            let _ = stream.configure(None);
        }
        match polled {
            Ok(Some(event)) => {
                last_recv = Instant::now();
                match event {
                    Event::Text(t) => service.on_message(&mut conn, WsData::Text(t)),
                    Event::Binary(b) => service.on_message(&mut conn, WsData::Binary(b)),
                    Event::Ping(_) => {
                        // The session already answered with the identical
                        // payload (RFC 6455 搂5.5.3).
                    }
                    Event::Pong(p) => service.on_pong(&mut conn, &p),
                    Event::Close(frame) => {
                        close_code = frame.as_ref().map(|f| f.code);
                        clean = true;
                        break;
                    }
                }
                if conn.is_closing() {
                    // The application asked to close: finish the handshake.
                    if let Some((code, is_clean)) = drain_close(&mut session, &stream, ws) {
                        close_code = code;
                        clean = is_clean;
                    }
                    break;
                }
            }
            Ok(None) => {
                // A blocking transport should never report "no data": if
                // it does, the connection is gone rather than idle.
                break;
            }
            Err(e) => match e.kind {
                ErrorKind::Timeout => {
                    let Some(interval) = ws.ping_interval else {
                        let _ = conn.close(1001, "idle timeout");
                        drain_close(&mut session, &stream, ws);
                        break;
                    };
                    if last_recv.elapsed() >= interval.saturating_mul(2) {
                        let _ = conn.close(1001, "keepalive timeout");
                        break;
                    }
                    if last_recv.elapsed() >= interval {
                        let _ = conn.send_ping(b"");
                        service.on_idle(&mut conn);
                    }
                }
                ErrorKind::UnexpectedEof => break,
                _ => {
                    // Only a peer protocol violation earns a Close frame;
                    // a transport failure is reported to the application
                    // (code `None`, `clean == false`) and nothing else.
                    if reports_violation(&e) {
                        let (code, reason) = protocol_close(&e);
                        if !session.close_sent() {
                            let _ = session.close(code, reason);
                        }
                        close_code = Some(code);
                    }
                    break;
                }
            },
        }
    }

    let _ = session.flush();
    service.on_close(&mut conn, close_code, clean);
    Ok(())
}

/// Wait for the peer's close echo, bounded by
/// [`WsConfig::close_timeout`]. Returns the peer's code and whether the
/// close was clean.
fn drain_close(
    session: &mut Session<Arc<ConnStream>, BoxSink>,
    stream: &Arc<ConnStream>,
    ws: &WsConfig,
) -> Option<(Option<u16>, bool)> {
    session.note_close_sent();
    let timeout = ws.close_timeout?;
    let _ = stream.configure(Some(timeout));
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Some((None, false));
        }
        match session.poll_message() {
            Ok(Some(Event::Close(frame))) => return Some((frame.as_ref().map(|f| f.code), true)),
            Ok(Some(_)) => continue,
            Ok(None) => return Some((None, false)),
            Err(e) => match e.kind {
                ErrorKind::Timeout => return Some((None, false)),
                _ => return Some((None, false)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_http::header::HeaderName;
    use crate::courierust_http::uri::PathAndQuery;
    use crate::courierust_http::version::Version;

    fn upgrade_request() -> Request<Body> {
        let mut req = Request::new(Method::GET, PathAndQuery::from_static("/chat"));
        req.version = Version::HTTP_11;
        req.headers.append(
            HeaderName::from_static("host"),
            HeaderValue::from_static("ws.example.com"),
        );
        req.headers.append(
            HeaderName::from_static("upgrade"),
            HeaderValue::from_static("websocket"),
        );
        req.headers.append(
            HeaderName::from_static("connection"),
            HeaderValue::from_static("Upgrade"),
        );
        req.headers.append(
            HeaderName::from_static("sec-websocket-key"),
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        req.headers.append(
            HeaderName::from_static("sec-websocket-version"),
            HeaderValue::from_static("13"),
        );
        req
    }

    #[test]
    fn plan_accepts_a_well_formed_upgrade() {
        let req = upgrade_request();
        let p = plan(
            &req,
            "127.0.0.1".parse().unwrap(),
            false,
            &WsConfig::default(),
        )
        .unwrap();
        assert_eq!(p.offer.path, "/chat");
        let headers = p.accept_headers().unwrap();
        assert_eq!(
            headers
                .get("sec-websocket-accept")
                .unwrap()
                .to_str()
                .unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(
            headers.get("upgrade").unwrap().to_str().unwrap(),
            "websocket"
        );
        assert_eq!(
            headers.get("connection").unwrap().to_str().unwrap(),
            "Upgrade"
        );
    }

    #[test]
    fn plan_refuses_wrong_version_with_426() {
        let mut req = upgrade_request();
        req.headers.remove("sec-websocket-version");
        req.headers.append(
            HeaderName::from_static("sec-websocket-version"),
            HeaderValue::from_static("8"),
        );
        let refusal = plan(
            &req,
            "127.0.0.1".parse().unwrap(),
            false,
            &WsConfig::default(),
        )
        .unwrap_err();
        assert_eq!(refusal.status, StatusCode::from_u16(426));
        assert!(refusal.advertise_version);
        let resp = refusal.response();
        assert_eq!(
            resp.headers
                .get("sec-websocket-version")
                .unwrap()
                .to_str()
                .unwrap(),
            "13"
        );
    }

    #[test]
    fn plan_refuses_cross_origin_by_default() {
        let mut req = upgrade_request();
        req.headers.append(
            HeaderName::from_static("origin"),
            HeaderValue::from_static("https://evil.test"),
        );
        let refusal = plan(
            &req,
            "127.0.0.1".parse().unwrap(),
            false,
            &WsConfig::default(),
        )
        .unwrap_err();
        assert_eq!(refusal.status, StatusCode::from_u16(403));

        // ...while a same-origin browser request passes.
        let mut req = upgrade_request();
        req.headers.append(
            HeaderName::from_static("origin"),
            HeaderValue::from_static("http://ws.example.com"),
        );
        assert!(plan(
            &req,
            "127.0.0.1".parse().unwrap(),
            false,
            &WsConfig::default()
        )
        .is_ok());
    }

    #[test]
    fn plan_refuses_a_duplicated_version_header() {
        let mut req = upgrade_request();
        req.headers.append(
            HeaderName::from_static("sec-websocket-version"),
            HeaderValue::from_static("13"),
        );
        assert!(plan(
            &req,
            "127.0.0.1".parse().unwrap(),
            false,
            &WsConfig::default()
        )
        .is_err());
    }

    #[test]
    fn plan_is_inert_when_websockets_are_disabled() {
        let req = upgrade_request();
        let ws = WsConfig {
            enabled: false,
            ..Default::default()
        };
        let refusal = plan(&req, "127.0.0.1".parse().unwrap(), false, &ws).unwrap_err();
        assert_eq!(refusal.status, StatusCode::from_u16(400));
    }

    /// The application handle and the session are two writers on one
    /// connection: a close through either of them must stop the other.
    #[test]
    fn the_application_writer_stops_after_a_close_on_the_session() {
        let info = WsInfo {
            path: String::from("/x"),
            peer: "127.0.0.1".parse().unwrap(),
            client_ip: "127.0.0.1".parse().unwrap(),
            secure: false,
            origin: None,
            protocol: None,
            compression: None,
        };
        let flag = CloseFlag::new();
        let queue = Arc::new(Mutex::new(OutQueue::new(4096)));
        let sink = QueueSink::new(queue.clone(), None);
        let app_writer = FrameWriter::with_close_flag(
            Box::new(sink.clone()) as BoxSink,
            MaskSource::None,
            None,
            flag.clone(),
        );
        let conn = WsConn::new(info, app_writer);

        conn.send_text("hello").unwrap();
        // The session's writer closes the connection.
        let mut session_writer =
            FrameWriter::with_close_flag(Box::new(sink) as BoxSink, MaskSource::None, None, flag);
        session_writer
            .send_close(crate::courierust_ws::close::NORMAL, "bye")
            .unwrap();

        assert!(
            !conn.is_closing(),
            "the close was the writer's, not the application handle's"
        );
        let err = conn.send_text("too late").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Canceled, "{err}");
        assert!(conn.sender().send_binary(b"too late").is_err());
        // Exactly two frames reached the queue: the message and the close.
        let queued = lock(&queue).buf.clone();
        let mut frames = 0usize;
        let mut pos = 0usize;
        while pos < queued.len() {
            let header = crate::courierust_ws::FrameHeader::parse(&queued[pos..])
                .unwrap()
                .unwrap();
            pos += header.header_len + header.payload_len as usize;
            frames += 1;
        }
        assert_eq!(frames, 2);
    }

    #[test]
    fn subprotocol_selection_follows_server_preference() {
        let mut req = upgrade_request();
        req.headers.append(
            HeaderName::from_static("sec-websocket-protocol"),
            HeaderValue::from_static("chat.v1, chat.v2"),
        );
        let ws = WsConfig {
            subprotocols: alloc::vec!["chat.v2".to_string(), "chat.v1".to_string()],
            ..Default::default()
        };
        let p = plan(&req, "127.0.0.1".parse().unwrap(), false, &ws).unwrap();
        assert_eq!(p.protocol.as_deref(), Some("chat.v2"));
        let headers = p.accept_headers().unwrap();
        assert_eq!(
            headers
                .get("sec-websocket-protocol")
                .unwrap()
                .to_str()
                .unwrap(),
            "chat.v2"
        );
    }

    #[test]
    fn extension_negotiation_is_reflected_in_the_accept_headers() {
        let mut req = upgrade_request();
        req.headers.append(
            HeaderName::from_static("sec-websocket-extensions"),
            HeaderValue::from_static("permessage-deflate; client_max_window_bits=10"),
        );
        let p = plan(
            &req,
            "127.0.0.1".parse().unwrap(),
            false,
            &WsConfig::default(),
        )
        .unwrap();
        let pm = p.compression.expect("permessage-deflate selected");
        assert_eq!(pm.client_max_window_bits, 10);
        let headers = p.accept_headers().unwrap();
        assert!(headers
            .get("sec-websocket-extensions")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("permessage-deflate"));
        // The server view maps windows to the right directions.
        let params = p.server_compression().unwrap();
        assert_eq!(params.recv_window_bits, 10);
        assert_eq!(params.send_window_bits, 15);
    }

    #[test]
    fn queue_overflow_fails_the_frame_atomically() {
        let q = Arc::new(Mutex::new(OutQueue::new(16)));
        let mut sink = QueueSink::new(q.clone(), None);
        assert!(sink.write_frame(&[0u8; 4], &[0u8; 8], None).is_ok());
        // The next frame does not fit: it must be refused wholesale.
        assert!(sink.write_frame(&[0u8; 4], &[0u8; 8], None).is_err());
        let guard = lock(&q);
        assert!(guard.is_closed());
        assert!(guard.is_empty());
    }

    #[test]
    fn queue_drains_into_a_writer_and_compacts() {
        let q = Arc::new(Mutex::new(OutQueue::new(64)));
        let mut sink = QueueSink::new(q.clone(), None);
        for _ in 0..4 {
            sink.write_frame(&[0xa1, 0x01], &[0xff], None).unwrap();
        }
        let mut out = crate::courierust_io::VecWriter(Vec::new());
        assert!(lock(&q).drain(&mut out).unwrap());
        assert_eq!(out.0.len(), 12);
        // After draining, the buffer is reusable.
        sink.write_frame(&[0xa1, 0x01], &[0xff], None).unwrap();
        assert_eq!(lock(&q).len(), 3);
    }

    #[test]
    fn protocol_errors_map_to_the_right_close_codes() {
        assert_eq!(protocol_close(&Error::overflow("x")).0, 1009);
        assert_eq!(
            protocol_close(&Error::protocol(
                "websocket: invalid UTF-8 in a text message"
            ))
            .0,
            1007
        );
        assert_eq!(protocol_close(&Error::protocol("anything else")).0, 1002);
    }

    #[test]
    fn only_a_peer_violation_is_reported_to_the_peer() {
        assert!(reports_violation(&Error::protocol("websocket: bad frame")));
        assert!(reports_violation(&Error::overflow("websocket: too big")));
        assert!(reports_violation(&Error::protocol(
            "websocket: invalid UTF-8"
        )));
        // Transport-level failures are not the peer's protocol error.
        assert!(!reports_violation(&Error::io("connection reset")));
        assert!(!reports_violation(&Error::eof()));
        assert!(!reports_violation(&Error::canceled("gone")));
        assert!(!reports_violation(&Error::with_message(
            ErrorKind::Timeout,
            "no data"
        )));
    }
}
