//! Event-driven HTTP/1.1 server (every platform).
//!
//! The classic one-pool-job-per-connection model burns a worker per idle
//! keep-alive / SSE / slow-loris connection. Here an event loop parks
//! idle plain-HTTP connections on a readiness poller (Winsock `select` /
//! POSIX `poll`) so they consume **zero** workers, and hands ready ones
//! to event workers in batches. Key mechanics:
//!
//! * A dedicated accept thread only accepts; classification (TLS / h2 /
//!   h1) is a non-blocking peek in the event loop, so a slow client
//!   never stalls the accept path.
//! * A **self-pipe** (loopback socket pair) lets workers/accept thread
//!   interrupt the event loop's blocking poll the instant a control
//!   message is queued — messages never wait for a poll tick, keeping
//!   per-request latency out of the poll-timeout path.
//! * Workers run an **incremental request parser** that resumes where it
//!   left off, so a partial request is parked again, not held.
//! * Connections idle for [`ServerConfig::idle_timeout`] are reaped.
//!
//! Scope: TLS and HTTP/2 connections still use the blocking pool; a
//! long-blocking synchronous handler still occupies a worker.

use crate::courierust_body::{Body, ChannelStream};
use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, Result};
use crate::courierust_h1;
use crate::courierust_http::header::HeaderMap;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::version::Version;
use crate::courierust_net::poller::{fd_of, Fd, Poller, WAKE_ID};
use crate::courierust_net::stats::Stats;
use crate::courierust_server::{Handler, ServerConfig};
use std::collections::{HashMap, HashSet};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Per-line / per-header-block limits (mirror the blocking server).
const MAX_LINE: usize = 64 * 1024;
const MAX_HEADERS: usize = 1024;
const MAX_HEADER_BLOCK: usize = 1024 * 1024;

/// How many ready connection ids travel in one dispatch message to the
/// event workers. Batching amortizes the shared channel + mutex so a
/// burst of ready connections cannot serialize one send/recv per id.
const DISPATCH_BATCH: usize = 16;

/// Poll cadence for a parked streaming response body (ms).
///
/// A producer without a wake — a raw [`Body::Channel`] built from a plain
/// `std::sync::mpsc` pair — can only be noticed by polling, so its first
/// polls are fast and double up to [`BODY_POLL_MAX_MS`] while the stream
/// stays silent: a slow chunk still goes out promptly, and a quiet stream
/// costs a bounded number of dispatches per second instead of a worker
/// thread.
const BODY_POLL_MIN_MS: u64 = 1;
const BODY_POLL_MAX_MS: u64 = 16;
/// Poll cadence for a body that *did* install a wake (ms). The deadline
/// then only enforces `read_timeout` and covers a wake lost to a dispatch
/// race, so it can be coarse.
const BODY_POLL_WAKE_MS: u64 = 25;

/// Cached `COURIERUST_H1_TRACE` presence. The per-request segment timing
/// reads it at connection construction and per segment, so it is cached
/// once per process instead of per request.
fn h1_trace() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("COURIERUST_H1_TRACE").is_some())
}

/// Start a timed segment when tracing is enabled; `None` otherwise.
#[inline]
fn seg_start(enabled: bool) -> Option<Instant> {
    if enabled {
        Some(Instant::now())
    } else {
        None
    }
}

/// Fold an elapsed segment into `acc` (µs). No-op when tracing is off.
#[inline]
fn seg_end(acc: &mut u64, start: Option<Instant>) {
    if let Some(start) = start {
        *acc = acc.saturating_add(start.elapsed().as_micros() as u64);
    }
}

/// Control messages sent to the event loop.
enum EventMsg {
    NewConn {
        id: usize,
        stream: TcpStream,
        /// Accept → registration timing (`COURIERUST_H1_TRACE`); `None`
        /// when tracing is off, so the message carries no timestamp
        /// overhead in the steady state.
        accepted_at: Option<Instant>,
    },
    Register {
        id: usize,
        fd: Fd,
        want_write: bool,
    },
    /// A streaming response body produced another chunk: dispatch the
    /// connection so its worker can write it.
    ///
    /// The message carries no descriptor on purpose: an application
    /// thread is the sender, and it may fire after the connection it
    /// belonged to is gone. The reactor resolves the id against its own
    /// tables, so a stale wake is a no-op rather than a registration of a
    /// recycled file descriptor.
    BodyChunk {
        id: usize,
    },
    Closed {
        id: usize,
        /// A handle the reactor keeps alive until it has stopped
        /// watching the descriptor.
        ///
        /// The alternative — letting the worker drop the last handle —
        /// closes the descriptor while the reactor may be blocked in a
        /// wait that still names it, and a wait set naming a closed
        /// descriptor fails as a whole on Winsock. Holding one handle
        /// across the handover makes "stop watching" strictly happen
        /// before "close", so the failure cannot be reached at all.
        socket: Option<Arc<TcpStream>>,
    },
    /// A worker handed this connection to a tunnel thread: stop watching
    /// the descriptor. The connection slot stays counted until the tunnel
    /// reports `Closed`, so a herd of tunnels is still bounded by
    /// `max_connections`.
    Detach {
        id: usize,
        socket: Option<Arc<TcpStream>>,
    },
}

/// The connection tables the reactor and its workers share.
///
/// A plain HTTP/1.1 connection (and a WebSocket whose upgrade has not
/// completed) lives in `h1`; a connection whose upgrade has completed
/// lives in `ws`. A connection never moves between the two: what changes
/// at the upgrade is the policy that drives it, not its identity.
#[derive(Clone)]
struct Registries {
    h1: Arc<std::sync::Mutex<HashMap<usize, EventConn>>>,
    ws: Arc<std::sync::Mutex<HashMap<usize, crate::courierust_server::ws::WsEventConn>>>,
}

impl Registries {
    fn new() -> Self {
        Self {
            h1: Arc::new(std::sync::Mutex::new(HashMap::new())),
            ws: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }
}

/// How a worker wants the connection handled next.
enum StepOutcome {
    /// Back to the poller (waiting for the next request / readability).
    Idle,
    /// The socket send buffer is full; wait for writability.
    NeedWrite,
    /// Close the connection.
    Close,
    /// The connection became a WebSocket: the worker moves it to the
    /// WebSocket registry, where it stays in the reactor for its whole
    /// life instead of occupying a thread.
    Upgrade(Box<crate::courierust_server::ws::WsEventConn>),
    /// The connection became a tunnel: its handshake response is on the
    /// wire, and a dedicated thread runs the service on it.
    Tunnel(Box<TunnelJob>),
}

/// A connection leaving the reactor for a [`TunnelService`].
///
/// [`TunnelService`]: crate::courierust_server::TunnelService
struct TunnelJob {
    plan: crate::courierust_server::TunnelPlan,
    /// The same socket handle the reactor held: handing it over is what
    /// keeps the descriptor open after the reactor stops watching it, and
    /// no second descriptor is created for one connection.
    socket: Arc<TcpStream>,
    /// Bytes the peer sent behind the request head (a TLS `ClientHello`
    /// right after `CONNECT`, typically). They must reach the service
    /// before anything it reads from the socket.
    leftover: Vec<u8>,
    /// Whether the connection arrived over TLS.
    secure: bool,
}

/// The protocol class of a fresh connection, decided from its first
/// bytes without consuming them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A TLS handshake record (content type 0x16) — blocking TLS path.
    Tls,
    /// The exact 24-byte HTTP/2 client preface — blocking h2 path.
    H2,
    /// Anything else — event-driven HTTP/1.1.
    H1,
    /// The bytes so far are a prefix of the h2 preface; park for more.
    NeedMore,
    /// The peer closed before sending anything.
    Closed,
}

/// The HTTP/2 client connection preface (RFC 9113 §3.5).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Classify a connection from its first `buf` bytes (peeked, not
/// consumed). TLS is identified by its first record's content type
/// (0x16 = handshake); h2 by the exact client preface; everything else
/// is HTTP/1.1. A prefix of the preface is parked (`NeedMore`) so a
/// slow h2 preface is not mistaken for h1.
fn classify(buf: &[u8]) -> Class {
    if buf.is_empty() {
        return Class::Closed;
    }
    if buf[0] == 0x16 {
        return Class::Tls;
    }
    let n = buf.len().min(H2_PREFACE.len());
    if buf[..n] != H2_PREFACE[..n] {
        return Class::H1;
    }
    if buf.len() < H2_PREFACE.len() {
        return Class::NeedMore;
    }
    Class::H2
}

// ---------------------------------------------------------------------
// Incremental HTTP/1.1 request parser
// ---------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Phase {
    RequestLine,
    Headers,
    BodyFixed { remaining: usize },
    BodyChunked(Chunked),
    Done,
}

#[derive(Clone, Copy)]
enum ChunkState {
    Size,
    Data,
    Crlf,
    Trailers,
}

#[derive(Clone, Copy)]
struct Chunked {
    state: ChunkState,
    remaining: usize,
    /// Total trailer-section bytes (mirrors the blocking decoder's
    /// `MAX_HEADER_BLOCK` cap so a slowloris trailer stream is bounded).
    trailer_bytes: usize,
}

/// Incremental HTTP/1.1 request parser over a non-blocking socket.
///
/// All parsing state lives here, so a partial request can be parked and
/// resumed on a later wake with identical state.
struct IncrRequest {
    /// Raw bytes read from the socket but not yet consumed.
    buf: Vec<u8>,
    /// Consume cursor into `buf` (the prefix is drained once it grows).
    pos: usize,
    /// Current partial line (request line / header line / chunk size).
    line: Vec<u8>,
    /// Raw request line for the in-flight request.
    req_line: Vec<u8>,
    /// The request line parsed exactly once when the header block ended
    /// (re-parsed by neither `body_length` nor `finish_request`).
    parsed_req_line: Option<crate::courierust_h1::RequestLine>,
    /// Accumulated headers.
    headers: HeaderMap,
    /// Accumulated body bytes.
    body: Vec<u8>,
    /// Total header bytes (enforces the header-block cap).
    header_bytes: usize,
    phase: Phase,
    body_limit: usize,
    /// `COURIERUST_H1_TRACE` gate; when off, `first_read_at` stays `None`
    /// and the hot path pays no `Instant::now()`.
    trace: bool,
    /// When the first byte of this request batch was read from the
    /// socket, splitting the worker dispatch (pickup → first read) from
    /// the parse (first read → request complete).
    first_read_at: Option<Instant>,
}

impl IncrRequest {
    fn new(body_limit: usize, trace: bool) -> Self {
        Self {
            buf: Vec::with_capacity(8192),
            pos: 0,
            line: Vec::with_capacity(128),
            req_line: Vec::new(),
            parsed_req_line: None,
            headers: HeaderMap::new(),
            body: Vec::new(),
            header_bytes: 0,
            phase: Phase::RequestLine,
            body_limit,
            trace,
            first_read_at: None,
        }
    }

    /// Read whatever is currently available from `socket` (non-blocking)
    /// into the buffer. Returns `Ok(true)` if any bytes were appended
    /// (the caller should keep parsing), `Ok(false)` if the socket would
    /// block with nothing new to parse.
    fn fill(&mut self, socket: &TcpStream, reads: Option<&AtomicUsize>) -> Result<bool> {
        let mut tmp = [0u8; 8192];
        let mut got = false;
        loop {
            if let Some(reads) = reads {
                reads.fetch_add(1, Ordering::Relaxed);
            }
            let mut r: &TcpStream = socket;
            match std::io::Read::read(&mut r, &mut tmp) {
                Ok(0) => return Err(Error::eof()),
                Ok(n) => {
                    got = true;
                    self.buf.extend_from_slice(&tmp[..n]);
                    if self.trace && self.first_read_at.is_none() {
                        self.first_read_at = Some(Instant::now());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(got),
                Err(e) => return Err(Error::io(e.to_string())),
            }
            if self.buf.len() - self.pos >= 8192 {
                break;
            }
        }
        Ok(got)
    }

    /// Try to read one complete line (up to and including `delim`). The
    /// partial line stays in `self.line` until it is complete. Returns
    /// `None` when more data is needed.
    fn read_line(&mut self, delim: u8, max: usize) -> Option<()> {
        let window = &self.buf[self.pos..];
        match window.iter().position(|&b| b == delim) {
            Some(i) => {
                self.line.extend_from_slice(&window[..i + 1]);
                self.pos += i + 1;
                if self.line.len() > max {
                    self.line.truncate(max);
                }
                Some(())
            }
            None => {
                self.line.extend_from_slice(window);
                self.pos = self.buf.len();
                if self.line.len() > max {
                    self.line.truncate(max);
                }
                None
            }
        }
    }

    /// Drop the consumed prefix once it grows large.
    fn compact(&mut self) {
        if self.pos >= 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    /// Take the bytes that arrived behind the request the server just
    /// finished parsing.
    ///
    /// A tunnel's first payload usually travels with its handshake (a TLS
    /// `ClientHello` behind `CONNECT`, a preamble behind any other
    /// upgrade), and those bytes were read into this buffer by the parser.
    /// They are handed to the tunnel as a seed, so the connection's first
    /// read returns them before a socket read is attempted.
    pub(crate) fn take_remaining(&mut self) -> Vec<u8> {
        let tail = self.buf[self.pos..].to_vec();
        self.buf.clear();
        self.pos = 0;
        self.line.clear();
        self.phase = Phase::RequestLine;
        tail
    }

    /// Try to produce the next request. Reads from `socket` as needed
    /// (non-blocking); returns `Ok(None)` when more data is required.
    pub(crate) fn next_request(
        &mut self,
        socket: &TcpStream,
        reads: Option<&AtomicUsize>,
    ) -> Result<Option<Request<Body>>> {
        loop {
            if let Phase::Done = self.phase {
                return Ok(Some(self.finish_request()?));
            }
            if self.parse_step()? {
                continue;
            }
            self.compact();
            if !self.fill(socket, reads)? {
                return Ok(None);
            }
        }
    }

    /// Advance one parse step. Returns true if progress was made (call
    /// again), false if more input is needed.
    fn parse_step(&mut self) -> Result<bool> {
        match self.phase {
            Phase::RequestLine => match self.read_line(b'\n', MAX_LINE) {
                Some(()) => {
                    if self.line.len() >= MAX_LINE {
                        return Err(Error::overflow("request line too long"));
                    }
                    self.req_line = core::mem::take(&mut self.line);
                    self.phase = Phase::Headers;
                    Ok(true)
                }
                None => Ok(false),
            },
            Phase::Headers => match self.read_line(b'\n', MAX_LINE) {
                Some(()) => {
                    if self.line.len() >= MAX_LINE {
                        return Err(Error::overflow("header line too long"));
                    }
                    self.header_bytes += self.line.len();
                    if self.header_bytes > MAX_HEADER_BLOCK {
                        return Err(Error::overflow("header block too large"));
                    }
                    let trimmed = courierust_h1::trim_crlf(&self.line);
                    if trimmed.is_empty() {
                        let rl = courierust_h1::parse_request_line(&self.req_line)?;
                        let bl = courierust_h1::body_length(&self.headers, Some(&rl.method), None)?;
                        self.parsed_req_line = Some(rl);
                        self.phase = match bl {
                            courierust_h1::BodyLen::None => Phase::Done,
                            courierust_h1::BodyLen::Length(0) => Phase::Done,
                            courierust_h1::BodyLen::Length(n) => {
                                if n > self.body_limit {
                                    return Err(Error::overflow("request body too large"));
                                }
                                Phase::BodyFixed { remaining: n }
                            }
                            courierust_h1::BodyLen::Chunked => Phase::BodyChunked(Chunked {
                                state: ChunkState::Size,
                                remaining: 0,
                                trailer_bytes: 0,
                            }),
                        };
                    } else {
                        if self.headers.len() >= MAX_HEADERS {
                            return Err(Error::overflow("too many header fields"));
                        }
                        let (name, value) = courierust_h1::split_header(trimmed)?;
                        self.headers.append(name, value);
                    }
                    self.line.clear();
                    Ok(true)
                }
                None => Ok(false),
            },
            Phase::BodyFixed { remaining } => {
                let avail = self.buf.len() - self.pos;
                if avail == 0 {
                    return Ok(false);
                }
                let take = core::cmp::min(remaining, avail);
                if self.body.len() + take > self.body_limit {
                    return Err(Error::overflow("request body too large"));
                }
                self.body
                    .extend_from_slice(&self.buf[self.pos..self.pos + take]);
                self.pos += take;
                let left = remaining - take;
                self.phase = if left == 0 {
                    Phase::Done
                } else {
                    Phase::BodyFixed { remaining: left }
                };
                Ok(true)
            }
            Phase::BodyChunked(mut ch) => {
                let progressed = self.parse_chunked(&mut ch)?;
                self.phase = Phase::BodyChunked(ch);
                Ok(progressed)
            }
            Phase::Done => Ok(true),
        }
    }

    /// One chunked-encoding parse step. Returns true on progress.
    ///
    /// The framing rules here must match the blocking decoder in
    /// `courierust_h1` exactly (shared chunk-size parser, strict CRLF
    /// terminators, bounded trailer section) so the event-driven and
    /// blocking server paths can never disagree on a request's meaning.
    fn parse_chunked(&mut self, ch: &mut Chunked) -> Result<bool> {
        match ch.state {
            ChunkState::Size => match self.read_line(b'\n', 1024) {
                Some(()) => {
                    if self.line.len() >= 1024 {
                        return Err(Error::protocol("chunk size line too long"));
                    }
                    let line = core::mem::take(&mut self.line);
                    let sz = courierust_h1::parse_chunk_size(courierust_h1::trim_crlf(&line))
                        .ok_or_else(|| Error::protocol("invalid chunk size"))?;
                    if sz == 0 {
                        ch.state = ChunkState::Trailers;
                    } else {
                        ch.remaining = sz;
                        ch.state = ChunkState::Data;
                    }
                    Ok(true)
                }
                None => Ok(false),
            },
            ChunkState::Data => {
                let avail = self.buf.len() - self.pos;
                if avail == 0 {
                    return Ok(false);
                }
                let take = core::cmp::min(ch.remaining, avail);
                if self.body.len() + take > self.body_limit {
                    return Err(Error::overflow("request body too large"));
                }
                self.body
                    .extend_from_slice(&self.buf[self.pos..self.pos + take]);
                self.pos += take;
                ch.remaining -= take;
                if ch.remaining == 0 {
                    ch.state = ChunkState::Crlf;
                }
                Ok(true)
            }
            ChunkState::Crlf => {
                let avail = self.buf.len() - self.pos;
                if avail >= 2 {
                    if &self.buf[self.pos..self.pos + 2] == b"\r\n" {
                        self.pos += 2;
                        ch.state = ChunkState::Size;
                        Ok(true)
                    } else {
                        Err(Error::protocol("chunk terminator missing"))
                    }
                } else {
                    Ok(false)
                }
            }
            ChunkState::Trailers => match self.read_line(b'\n', MAX_LINE) {
                Some(()) => {
                    if self.line.len() >= MAX_LINE {
                        return Err(Error::overflow("trailer line too long"));
                    }
                    ch.trailer_bytes += self.line.len();
                    if ch.trailer_bytes > MAX_HEADER_BLOCK {
                        return Err(Error::overflow("trailer section too large"));
                    }
                    let line = core::mem::take(&mut self.line);
                    if courierust_h1::trim_crlf(&line).is_empty() {
                        self.phase = Phase::Done;
                    }
                    Ok(true)
                }
                None => Ok(false),
            },
        }
    }

    /// Build the parsed request and reset per-request state (buffered
    /// pipelined bytes are kept for the next call).
    fn finish_request(&mut self) -> Result<Request<Body>> {
        let rl = self
            .parsed_req_line
            .take()
            .ok_or_else(|| Error::protocol("request line not parsed"))?;
        self.req_line.clear();
        let headers = core::mem::take(&mut self.headers);
        self.header_bytes = 0;
        let body = core::mem::take(&mut self.body);
        self.phase = Phase::RequestLine;
        Ok(Request {
            method: rl.method,
            uri: rl.target,
            version: rl.version,
            headers,
            body: if body.is_empty() {
                Body::Empty
            } else {
                Body::Bytes(Bytes::from(body))
            },
        })
    }
}

// ---------------------------------------------------------------------
// Event connection
// ---------------------------------------------------------------------

/// An active event-loop HTTP/1.1 connection.
/// The receive side of a streaming response body, plus the park state the
/// reactor needs while the producer is between chunks.
///
/// One type covers both body variants: a raw [`Body::Channel`] wraps a
/// plain channel ([`ChannelStream::raw`]) and a [`Body::Stream`] carries
/// the producer wake handle that makes delivery immediate.
struct BodyRx {
    stream: ChannelStream,
    /// When the current wait for the next chunk began. The per-chunk
    /// `read_timeout` is measured from here, exactly like the blocking
    /// driver's `recv_timeout`.
    wait_started: Option<Instant>,
    /// Consecutive dispatches that found the queue empty: the poll
    /// backoff for a producer that cannot wake us.
    empty_polls: u32,
    /// When the reactor must re-dispatch this connection to look at the
    /// body again. `None` while the connection is being processed.
    poll_at: Option<Instant>,
}

impl BodyRx {
    fn new(stream: ChannelStream) -> Self {
        Self {
            stream,
            wait_started: None,
            empty_polls: 0,
            poll_at: None,
        }
    }
}

/// How long to wait before polling a parked body again.
///
/// A body with a wake is polled coarsely (the deadline only enforces the
/// read timeout and covers a lost wake). Without one, the poll *is* the
/// progress path, so it starts at 1 ms and backs off to 16 ms; a chunk
/// resets it, so a bursty stream is never charged the backoff.
fn body_poll_delay(body: &BodyRx) -> Duration {
    if body.stream.has_wake() {
        return Duration::from_millis(BODY_POLL_WAKE_MS);
    }
    let shift = body.empty_polls.min(4);
    Duration::from_millis((BODY_POLL_MIN_MS << shift).min(BODY_POLL_MAX_MS))
}

struct EventConn {
    socket: Arc<TcpStream>,
    /// Set once a `101` head has been queued: the next moment the head is
    /// fully written, this connection becomes a WebSocket.
    pending_upgrade: Option<(
        crate::courierust_server::ws::WsPlan,
        Arc<dyn crate::courierust_server::ws::WsService>,
    )>,
    /// Set once a tunnel head has been queued: the next moment the head is
    /// fully written, this connection leaves the reactor for a tunnel
    /// thread.
    pending_tunnel: Option<crate::courierust_server::TunnelPlan>,
    /// Late-bound reactor wakeup, installed by the worker.
    wake_slot: Arc<crate::courierust_server::ws::WakeSlot>,
    reader: IncrRequest,
    /// Full response bytes pending write.
    out: Vec<u8>,
    /// Write cursor into `out`.
    out_pos: usize,
    /// Body of a streaming response that is still being produced. The
    /// head has already been written; each chunk is written as it
    /// arrives, so `out` never holds more than one chunk, and the worker
    /// parks between chunks instead of blocking on the channel.
    stream_rx: Option<BodyRx>,
    /// True once the reactor's wake has been installed into `wake_slot`.
    /// Armed on the first dispatch: a wake must be in place before any
    /// body exists, and every later response reuses it.
    wake_armed: bool,
    keep_alive: bool,
    /// Transport read-call counter (h1 syscall evidence), when attached.
    reads: Option<Arc<AtomicUsize>>,
    /// Transport write-call counter (h1 syscall evidence), when attached.
    writes: Option<Arc<AtomicUsize>>,
    // Per-request segment timing (`COURIERUST_H1_TRACE`); all zero and
    // unused when tracing is off, so the steady-state hot path pays no
    // `Instant::now()` calls.
    trace: bool,
    parse_us: u64,
    handler_us: u64,
    build_us: u64,
    write_us: u64,
    /// Worker pickup → first byte read (the worker side of the dispatch
    /// handoff, separate from parse so a slow first read is not blamed
    /// on the parser).
    dispatch_us: u64,
    trace_requests: u64,
    /// When this connection was last parked on the reactor, for the
    /// worker → reactor → worker handoff measurement.
    parked_at: Option<Instant>,
    /// When this connection was created (classified as h1), for the
    /// first-request dispatch-wait measurement.
    registered_at: Option<Instant>,
    /// When the worker picked this connection up, for the
    /// pickup → first-read split.
    pickup_at: Option<Instant>,
}

impl EventConn {
    fn new(
        socket: TcpStream,
        body_limit: usize,
        stats: Option<&Stats>,
        wake_slot: Arc<crate::courierust_server::ws::WakeSlot>,
    ) -> Self {
        let (reads, writes) = match stats {
            Some(s) => (
                Some(s.h1_read_syscalls.clone()),
                Some(s.h1_write_syscalls.clone()),
            ),
            None => (None, None),
        };
        let trace = h1_trace();
        Self {
            socket: Arc::new(socket),
            pending_upgrade: None,
            pending_tunnel: None,
            wake_slot,
            reader: IncrRequest::new(body_limit, trace),
            out: Vec::new(),
            out_pos: 0,
            stream_rx: None,
            wake_armed: false,
            keep_alive: true,
            reads,
            writes,
            trace,
            parse_us: 0,
            handler_us: 0,
            build_us: 0,
            write_us: 0,
            dispatch_us: 0,
            trace_requests: 0,
            parked_at: None,
            registered_at: trace.then(Instant::now),
            pickup_at: None,
        }
    }

    /// Whether a response (or a `101` head) still has bytes to write.
    ///
    /// Used by the reactor when it rebuilds its wait set after a failed
    /// wait: the parked-direction of a connection is not stored in the
    /// registries, it is derived from this fact.
    fn has_pending_output(&self) -> bool {
        self.out_pos < self.out.len()
    }

    /// Install the reactor's wake callback into this connection, once.
    ///
    /// Called by the worker, which is the only component that holds the
    /// reactor's dispatch handle. A streaming body fires this slot from
    /// the producer's thread, so a chunk goes out the moment it exists
    /// instead of when a poll tick notices it. `make` is only invoked the
    /// first time: every later response reuses the wake already armed.
    fn arm_wake(&mut self, make: impl FnOnce() -> Arc<dyn Fn() + Send + Sync>) {
        if self.wake_armed {
            return;
        }
        self.wake_slot.set(make());
        self.wake_armed = true;
    }

    /// Point a freshly installed streaming body at this connection's wake
    /// slot. The body's producer fires the slot on every chunk.
    fn attach_body_wake(&self, stream: &ChannelStream) {
        let slot = self.wake_slot.clone();
        stream.install_wake(move || slot.fire());
    }

    /// Adopt a freshly built response body.
    ///
    /// The wake is installed before the body is stored: the producer may
    /// already have queued a chunk, and a body that missed its wake would
    /// otherwise wait for the poll deadline.
    fn set_stream(&mut self, stream: Option<ChannelStream>) {
        if let Some(stream) = &stream {
            self.attach_body_wake(stream);
        }
        self.stream_rx = stream.map(BodyRx::new);
    }

    /// Whether this connection is parked on a body chunk whose poll
    /// deadline has already elapsed.
    fn body_poll_due(&self, now: Instant) -> bool {
        self.body_poll_at().is_some_and(|at| at <= now)
    }

    /// When the parked streaming body must be polled again.
    fn body_poll_at(&self) -> Option<Instant> {
        self.stream_rx.as_ref().and_then(|body| body.poll_at)
    }

    /// Process the connection one step (non-blocking). Serves as many
    /// pipelined requests as are fully buffered, then returns how to
    /// continue.
    fn step(&mut self, handler: &dyn Handler, config: &ServerConfig) -> Result<StepOutcome> {
        let trace = self.trace;
        loop {
            if self.out_pos < self.out.len() {
                let outcome = self.write_more()?;
                if !matches!(outcome, StepOutcome::Idle) {
                    return Ok(outcome);
                }
            }
            if self.stream_rx.is_some() {
                let outcome = self.pump_body(config)?;
                if !matches!(outcome, StepOutcome::Idle) {
                    return Ok(outcome);
                }
            }
            if let Some((plan, service)) = self.pending_upgrade.take() {
                let leftover = self.reader.buf[self.reader.pos..].to_vec();
                let conn = crate::courierust_server::ws::WsEventConn::new(
                    self.socket.clone(),
                    &leftover,
                    plan,
                    service,
                    &config.websocket,
                    self.wake_slot.clone(),
                );
                return Ok(StepOutcome::Upgrade(Box::new(conn)));
            }
            if let Some(plan) = self.pending_tunnel.take() {
                return Ok(StepOutcome::Tunnel(Box::new(TunnelJob {
                    plan,
                    socket: self.socket.clone(),
                    leftover: self.reader.take_remaining(),
                    secure: config.tls.is_some(),
                })));
            }
            let parse = seg_start(trace);
            match self
                .reader
                .next_request(&self.socket, self.reads.as_deref())?
            {
                Some(req) => {
                    if trace {
                        if let Some(first_read) = self.reader.first_read_at.take() {
                            let done = Instant::now();
                            if let Some(pickup) = self.pickup_at.take() {
                                if first_read >= pickup {
                                    self.dispatch_us = self.dispatch_us.saturating_add(
                                        first_read.duration_since(pickup).as_micros() as u64,
                                    );
                                }
                            }
                            self.parse_us = self
                                .parse_us
                                .saturating_add(done.duration_since(first_read).as_micros() as u64);
                        } else {
                            seg_end(&mut self.parse_us, parse);
                        }
                    } else {
                        seg_end(&mut self.parse_us, parse);
                    }
                    let request_close = courierust_h1::wants_close(&req.headers);
                    let is_head = req.method == crate::courierust_http::method::Method::HEAD;

                    if let Some(reason) =
                        courierust_h1::host_header_error(req.version, &req.headers)
                    {
                        self.out.clear();
                        let (keep_alive, stream) = build_response(
                            crate::courierust_server::h1::error_response(400, reason),
                            request_close,
                            is_head,
                            &mut self.out,
                        )?;
                        self.out_pos = 0;
                        self.set_stream(stream);
                        self.keep_alive = keep_alive;
                        let outcome = self.write_more()?;
                        match outcome {
                            StepOutcome::Idle => continue,
                            other => return Ok(other),
                        }
                    }

                    // ---- WebSocket upgrade ------------------------------
                    match self.websocket_decision(handler, &req, config)? {
                        WsDecision::Pass => {}
                        WsDecision::Respond(resp) => {
                            let handle = seg_start(trace);
                            seg_end(&mut self.handler_us, handle);
                            self.out.clear();
                            let (keep_alive, stream) =
                                build_response(resp, request_close, is_head, &mut self.out)?;
                            self.out_pos = 0;
                            self.set_stream(stream);
                            self.keep_alive = keep_alive;
                            let outcome = self.write_more()?;
                            match outcome {
                                StepOutcome::Idle => continue,
                                StepOutcome::Close if self.stream_rx.is_some() => continue,
                                other => return Ok(other),
                            }
                        }
                        WsDecision::Upgrade(upgrade) => {
                            let head = upgrade.plan.accept_headers()?;
                            self.out.clear();
                            courierust_h1::write_response_head(
                                &mut self.out,
                                crate::courierust_http::status::StatusCode::SWITCHING_PROTOCOLS,
                                Version::HTTP_11,
                                &head,
                            )?;
                            self.out_pos = 0;
                            self.keep_alive = true;
                            self.pending_upgrade = Some((upgrade.plan, upgrade.service));
                            continue;
                        }
                    }

                    // ---- raw tunnel (CONNECT / custom upgrade) ---------
                    match handler.tunnel(&req) {
                        crate::courierust_server::TunnelReply::Pass => {}
                        crate::courierust_server::TunnelReply::Refuse(resp) => {
                            let handle = seg_start(trace);
                            seg_end(&mut self.handler_us, handle);
                            self.out.clear();
                            let (keep_alive, stream) =
                                build_response(resp, request_close, is_head, &mut self.out)?;
                            self.out_pos = 0;
                            self.set_stream(stream);
                            self.keep_alive = keep_alive;
                            let outcome = self.write_more()?;
                            match outcome {
                                StepOutcome::Idle => continue,
                                StepOutcome::Close if self.stream_rx.is_some() => continue,
                                other => return Ok(other),
                            }
                        }
                        crate::courierust_server::TunnelReply::Accept(plan) => {
                            let handle = seg_start(trace);
                            seg_end(&mut self.handler_us, handle);
                            self.out.clear();
                            courierust_h1::write_response_head(
                                &mut self.out,
                                plan.status,
                                Version::HTTP_11,
                                &plan.headers,
                            )?;
                            self.out_pos = 0;
                            self.keep_alive = false;
                            self.pending_tunnel = Some(plan);
                            continue;
                        }
                    }

                    let handle = seg_start(trace);
                    let resp = handler.handle(req);
                    seg_end(&mut self.handler_us, handle);
                    self.out.clear();
                    let build = seg_start(trace);
                    let (keep_alive, stream) =
                        build_response(resp, request_close, is_head, &mut self.out)?;
                    seg_end(&mut self.build_us, build);
                    self.out_pos = 0;
                    self.set_stream(stream);
                    self.keep_alive = keep_alive;
                    let write = seg_start(trace);
                    let outcome = self.write_more()?;
                    seg_end(&mut self.write_us, write);
                    if trace {
                        self.trace_requests = self.trace_requests.saturating_add(1);
                    }
                    match outcome {
                        StepOutcome::Idle => {
                            continue;
                        }
                        StepOutcome::Close if self.stream_rx.is_some() => continue,
                        other => return Ok(other),
                    }
                }
                None => {
                    seg_end(&mut self.parse_us, parse);
                    if trace {
                        self.reader.first_read_at = None;
                    }
                    return Ok(StepOutcome::Idle);
                }
            }
        }
    }

    /// Pump a channel response body as chunked encoding.
    ///
    /// Each chunk is written as far as the socket allows before the next
    /// one is pulled, so a long — even endless — stream costs one chunk
    /// of memory rather than the whole body, and the client sees the
    /// head immediately instead of after the stream ends. A producer
    /// that stalls past the read timeout fails the connection *without*
    /// the terminating chunk, so a truncated body is detectable; that
    /// matches the blocking driver.
    ///
    /// The worker never blocks here. When the queue is empty the
    /// connection is parked (zero workers held for a stream) and the
    /// reactor re-dispatches it when the producer fires the wake, or when
    /// the poll deadline armed below elapses — the latter is the only
    /// progress path for a producer that installed no wake.
    fn pump_body(&mut self, config: &ServerConfig) -> Result<StepOutcome> {
        let Some(mut body) = self.stream_rx.take() else {
            return Ok(StepOutcome::Idle);
        };
        loop {
            match body.stream.try_recv() {
                Ok(Ok(chunk)) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    body.wait_started = None;
                    body.empty_polls = 0;
                    self.out.clear();
                    self.out_pos = 0;
                    courierust_h1::encode_chunk(&chunk, &mut self.out);
                    if matches!(self.write_more()?, StepOutcome::NeedWrite) {
                        self.stream_rx = Some(body);
                        return Ok(StepOutcome::NeedWrite);
                    }
                }
                Ok(Err(error)) => return Err(error),
                Err(TryRecvError::Empty) => {
                    if let Some(timeout) = config.read_timeout {
                        let started = *body.wait_started.get_or_insert_with(Instant::now);
                        if started.elapsed() >= timeout {
                            return Err(Error::timeout("body stream timed out"));
                        }
                    }
                    body.empty_polls = body.empty_polls.saturating_add(1);
                    body.poll_at = Some(Instant::now() + body_poll_delay(&body));
                    self.stream_rx = Some(body);
                    return Ok(StepOutcome::Idle);
                }
                Err(TryRecvError::Disconnected) => {
                    body.stream.clear_wake();
                    self.out.clear();
                    self.out_pos = 0;
                    self.out.extend_from_slice(courierust_h1::CHUNKED_END);
                    return self.write_more();
                }
            }
        }
    }

    /// Write pending output; returns the continuation.
    fn write_more(&mut self) -> Result<StepOutcome> {
        while self.out_pos < self.out.len() {
            if let Some(writes) = &self.writes {
                writes.fetch_add(1, Ordering::Relaxed);
            }
            let mut w: &TcpStream = &self.socket;
            match std::io::Write::write(&mut w, &self.out[self.out_pos..]) {
                Ok(0) => return Err(Error::eof()),
                Ok(n) => self.out_pos += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(StepOutcome::NeedWrite);
                }
                Err(e) => return Err(Error::io(e.to_string())),
            }
        }
        self.out.clear();
        self.out_pos = 0;
        if self.keep_alive {
            Ok(StepOutcome::Idle)
        } else {
            Ok(StepOutcome::Close)
        }
    }
}

/// The outcome of inspecting a request for a WebSocket upgrade.
///
/// `WsDecision` is produced for **every** request, so its common variants
/// stay small and the (rare) upgrade payload is boxed: otherwise each
/// request would carry a 232-byte `WsPlan` around by value before the
/// enum is matched away.
enum WsDecision {
    /// Handle it as ordinary HTTP.
    Pass,
    /// Answer with this response instead of `101`.
    Respond(Response<Body>),
    /// Switch the connection to the WebSocket reactor.
    Upgrade(Box<WsUpgrade>),
}

/// The handshake state of an accepted upgrade.
struct WsUpgrade {
    plan: crate::courierust_server::ws::WsPlan,
    service: Arc<dyn crate::courierust_server::ws::WsService>,
}

impl EventConn {
    /// Ask the handler about an upgrade and validate it against policy.
    fn websocket_decision(
        &self,
        handler: &dyn Handler,
        req: &Request<Body>,
        config: &ServerConfig,
    ) -> Result<WsDecision> {
        if !config.websocket.enabled || !crate::courierust_ws::is_websocket_upgrade(&req.headers) {
            return Ok(WsDecision::Pass);
        }
        match handler.websocket(req) {
            crate::courierust_server::ws::WsUpgradeReply::Pass => Ok(WsDecision::Pass),
            crate::courierust_server::ws::WsUpgradeReply::Refuse(resp) => {
                Ok(WsDecision::Respond(resp))
            }
            crate::courierust_server::ws::WsUpgradeReply::Accept(service) => {
                let peer = self
                    .socket
                    .peer_addr()
                    .map(|a| a.ip())
                    .unwrap_or(core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED));
                match crate::courierust_server::ws::plan(req, peer, false, &config.websocket) {
                    Ok(plan) => Ok(WsDecision::Upgrade(Box::new(WsUpgrade { plan, service }))),
                    Err(refusal) => Ok(WsDecision::Respond(refusal.response())),
                }
            }
        }
    }
}

/// Serialize the response head (and any in-memory body) into `out`,
/// returning the keep-alive decision and, for a channel body, the stream
/// the caller must pump.
///
/// The caller owns the buffer (`out` is the connection's write buffer),
/// so steady-state responses perform no per-request allocation.
/// `request_close` reflects a request `Connection: close` token, which
/// forces the connection closed (RFC 7230 §6.3).
///
/// A channel body is deliberately *not* buffered here: collecting it
/// would hold a whole (possibly endless) stream in memory before the
/// first byte reaches the client, and a producer that stalls would end
/// up closing the connection as if the response were complete.
fn build_response(
    resp: Response<Body>,
    request_close: bool,
    is_head: bool,
    out: &mut Vec<u8>,
) -> Result<(bool, Option<ChannelStream>)> {
    let keep_alive = crate::courierust_server::h1::response_wire_head(&resp, request_close, out)?;
    match resp.body {
        _ if is_head => Ok((keep_alive, None)),
        Body::Empty => Ok((keep_alive, None)),
        Body::Bytes(b) => {
            out.extend_from_slice(&b);
            Ok((keep_alive, None))
        }
        Body::Channel(rx) => Ok((keep_alive, Some(ChannelStream::raw(rx)))),
        Body::Stream(stream) => Ok((keep_alive, Some(stream))),
    }
}

// ---------------------------------------------------------------------
// Event loop + workers + acceptor
// ---------------------------------------------------------------------

/// Run the event-driven HTTP/1.1 accept loop for `listener`.
///
/// Plain HTTP/1.1 connections are handled by the event loop; TLS and
/// HTTP/2 connections are handed to the blocking pool.
pub(crate) fn serve_event(
    listener: std::net::TcpListener,
    handler: Arc<dyn Handler>,
    config: ServerConfig,
    pool: Arc<crate::courierust_pool::ThreadPool>,
    stop: crate::courierust_server::ServerStop,
) -> std::io::Result<()> {
    let (msg_tx, msg_rx) = channel::<EventMsg>();
    let (ready_tx, ready_rx): (Sender<Vec<usize>>, Receiver<Vec<usize>>) = channel();
    let ready_rx = Arc::new(std::sync::Mutex::new(ready_rx));
    let registries = Registries::new();
    let (wake_reader, wake_writer) = wakeup_pair()?;
    let wake_writer = Arc::new(wake_writer);

    stop.install_reactor_wake(wake_writer.try_clone()?);
    stop.install_listener(listener.try_clone()?);

    let loop_handler = handler.clone();
    let loop_config = config.clone();
    let loop_pool = pool.clone();
    let loop_registries = registries.clone();
    let loop_stop = stop.clone();
    let event_thread = thread::Builder::new()
        .name("courierust-event".into())
        .spawn(move || {
            event_loop(
                msg_rx,
                wake_reader,
                LoopContext {
                    ready_tx,
                    handler: loop_handler,
                    config: loop_config,
                    pool: loop_pool,
                    registries: loop_registries,
                    stop: loop_stop,
                },
            );
        })?;

    // Event worker threads.
    let workers = if config.event_workers == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get().clamp(1, 8))
            .unwrap_or(4)
    } else {
        config.event_workers
    };
    let mut worker_handles = Vec::new();
    for _ in 0..workers {
        let w_registries = registries.clone();
        let w_handler = handler.clone();
        let w_config = config.clone();
        let w_ready_rx = ready_rx.clone();
        let w_msg_tx = msg_tx.clone();
        let w_wake = wake_writer.clone();
        worker_handles.push(
            thread::Builder::new()
                .name("courierust-event-worker".into())
                .spawn(move || {
                    event_worker(
                        w_ready_rx,
                        w_registries,
                        &*w_handler,
                        &w_config,
                        &w_msg_tx,
                        &w_wake,
                    );
                })?,
        );
    }

    let a_msg_tx = msg_tx.clone();
    let a_wake = wake_writer.clone();
    let a_stats = config.stats.clone();
    let a_stop = stop.clone();
    let accept_thread = thread::Builder::new()
        .name("courierust-accept".into())
        .spawn(move || {
            accept_loop(listener, a_msg_tx, &a_wake, a_stats.as_deref(), &a_stop);
        })?;

    let _ = accept_thread.join();
    let _ = event_thread.join();
    for h in worker_handles {
        let _ = h.join();
    }
    Ok(())
}

/// Create a loopback socket pair used as a self-pipe to wake a poller
/// out of a blocking wait. Pure std, cross-platform (Windows has no
/// native `socketpair`; a loopback pair is the portable equivalent).
pub(crate) fn wakeup_pair() -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let writer = TcpStream::connect(listener.local_addr()?)?;
    let (reader, _) = listener.accept()?;
    reader.set_nonblocking(true)?;
    writer.set_nonblocking(true)?;
    let _ = reader.set_nodelay(true);
    let _ = writer.set_nodelay(true);
    Ok((reader, writer))
}

/// Write one byte to the wake pipe (best-effort; a full or failed write
/// only loses an optimization, never correctness).
pub(crate) fn wake_nudge(w: &TcpStream) {
    let mut s: &TcpStream = w;
    let _ = std::io::Write::write(&mut s, &[1]);
}

/// Drain all pending wake bytes so the pipe cannot fire spuriously.
pub(crate) fn drain_wake(r: &TcpStream) {
    let mut buf = [0u8; 64];
    loop {
        let mut s: &TcpStream = r;
        match std::io::Read::read(&mut s, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// The WebSocket connections whose keepalive or close-handshake deadline
/// has elapsed.
///
/// Nothing a silent peer does makes a descriptor ready, so these
/// connections are dispatched on the clock rather than on readiness.
fn ws_due_ids(registries: &Registries, now: Instant) -> Vec<usize> {
    let ws = registries.ws.lock().unwrap();
    ws.iter()
        .filter(|(_, conn)| conn.next_deadline().is_some_and(|d| d <= now))
        .map(|(&id, _)| id)
        .collect()
}

/// Parked streaming responses whose poll deadline has elapsed.
///
/// A producer that installed no wake can only be noticed by polling, and
/// the same deadline is what turns a stalled producer into the read
/// timeout — neither of which socket readiness can deliver.
fn h1_body_due_ids(registries: &Registries, now: Instant) -> Vec<usize> {
    registries
        .h1
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, conn)| conn.body_poll_due(now))
        .map(|(&id, _)| id)
        .collect()
}

/// The earliest streaming-body poll deadline, so the reactor's wait can
/// end when the first one comes due.
fn h1_body_next_deadline(registries: &Registries) -> Option<Instant> {
    registries
        .h1
        .lock()
        .unwrap()
        .values()
        .filter_map(|conn| conn.body_poll_at())
        .min()
}

/// Re-dispatch a parked connection for a producer-side event.
///
/// Nothing is looked up first: the worker that receives the id resolves
/// it, so a wake that arrives after its connection closed costs one
/// lookup instead of risking a registration of a recycled descriptor.
fn wake_connection(id: usize, poller: &mut Poller, ready_tx: &Sender<Vec<usize>>) {
    if id == WAKE_ID {
        return;
    }
    poller.unregister(id);
    let _ = ready_tx.send(vec![id]);
}

/// The earliest keepalive/close deadline across the live WebSocket
/// connections, so the reactor's wait can end when the first one is due.
fn ws_next_deadline(registries: &Registries) -> Option<Instant> {
    registries
        .ws
        .lock()
        .unwrap()
        .values()
        .filter_map(|conn| conn.next_deadline())
        .min()
}

/// Rebuild the reactor's wait set from the live connections.
///
/// The registries are the source of truth: sockets still being
/// classified (`pending`, readable), parked HTTP/1.1 connections
/// (readable again unless a response is still in flight) and parked
/// WebSocket connections (writable exactly while frames are queued). An
/// id no registry knows is left out of the rebuilt set — which is what
/// removes the entry that made the wait fail in the first place.
///
/// This runs only after a wait failed, so it may walk every connection:
/// the cost of rebuilding is paid once, in exchange for a reactor that
/// keeps its guarantees instead of spinning on a broken descriptor set.
fn rebuild_wait_set(
    poller: &mut Poller,
    pending: &HashMap<usize, TcpStream>,
    registries: &Registries,
) {
    poller.clear();
    for (id, stream) in pending.iter() {
        poller.register(*id, fd_of(stream), false);
    }
    for (id, conn) in registries.h1.lock().unwrap().iter() {
        poller.register(*id, fd_of(&conn.socket), conn.has_pending_output());
    }
    for (id, conn) in registries.ws.lock().unwrap().iter() {
        poller.register(*id, fd_of(conn.socket()), conn.has_queued_output());
    }
}

/// The reactor's mutable state, borrowed for one control message.
///
/// The three tables belong together — a message that registers a socket
/// also refreshes its activity clock — so they travel as one value
/// instead of being threaded through every call separately.
struct Reactor<'a> {
    poller: &'a mut Poller,
    pending: &'a mut HashMap<usize, TcpStream>,
    activity: &'a mut HashMap<usize, Instant>,
}

/// Apply one control message to the poller / pending / activity state.
/// Used by both the message-drain path and the block-on-channel path, so
/// a message consumed from the channel is never dropped.
fn handle_msg(
    msg: EventMsg,
    reactor: Reactor<'_>,
    registries: &Registries,
    ready_tx: &Sender<Vec<usize>>,
    max_connections: usize,
    stats: Option<&Stats>,
) {
    let Reactor {
        poller,
        pending,
        activity,
    } = reactor;
    match msg {
        EventMsg::BodyChunk { id } => wake_connection(id, poller, ready_tx),
        EventMsg::NewConn {
            id,
            stream,
            accepted_at,
        } => {
            if max_connections > 0 && activity.len() >= max_connections {
                drop(stream);
                return;
            }
            if stream.set_nonblocking(true).is_err() {
                return;
            }
            let _ = stream.set_nodelay(true);
            if let Some(s) = stats {
                s.connections_active.fetch_add(1, Ordering::Relaxed);
            }
            let fd = fd_of(&stream);
            pending.insert(id, stream);
            activity.insert(id, Instant::now());
            poller.register(id, fd, false);
            if let Some(accepted_at) = accepted_at {
                eprintln!(
                    "H1SEG|id={id}|event=newconn|accept_us={}",
                    accepted_at.elapsed().as_micros()
                );
            }
        }
        EventMsg::Register { id, fd, want_write } => {
            let want_write = registries
                .ws
                .lock()
                .unwrap()
                .get(&id)
                .map(|c| c.has_queued_output())
                .unwrap_or(want_write);
            activity.insert(id, Instant::now());
            poller.register(id, fd, want_write);
        }
        EventMsg::Closed { id, socket } => {
            poller.unregister(id);
            pending.remove(&id);
            if activity.remove(&id).is_some() {
                if let Some(s) = stats {
                    Stats::decrement(&s.connections_active, 1);
                }
            }
            drop(socket);
        }
        EventMsg::Detach { id, socket } => {
            poller.unregister(id);
            pending.remove(&id);
            drop(socket);
        }
    }
}

/// The reactor's shared state: everything the event loop needs that does
/// not change while it runs. Bundled so the loop takes a channel, the
/// wake pipe and *one* context — a signature that grows a parameter per
/// feature is how a loop stops being readable.
struct LoopContext {
    ready_tx: Sender<Vec<usize>>,
    handler: Arc<dyn Handler>,
    config: ServerConfig,
    pool: Arc<crate::courierust_pool::ThreadPool>,
    registries: Registries,
    stop: crate::courierust_server::ServerStop,
}

/// The event loop: polls sockets, classifies new connections, and
/// dispatches ready HTTP/1.1 and WebSocket connections to workers.
fn event_loop(msg_rx: Receiver<EventMsg>, wake_reader: TcpStream, context: LoopContext) {
    let LoopContext {
        ready_tx,
        handler,
        config,
        pool,
        registries,
        stop,
    } = context;
    let mut poller = Poller::new();
    let mut pending: HashMap<usize, TcpStream> = HashMap::new();
    let mut activity: HashMap<usize, Instant> = HashMap::new();
    let stats = config.stats.clone();
    let stats = stats.as_deref();
    let mut wait_errors = 0usize;

    let wake_fd = fd_of(&wake_reader);
    let poll_timeout = config.event_poll_timeout_ms.clamp(1, 1000) as i32;
    let idle_timeout = config.idle_timeout;

    loop {
        if stop.is_requested() {
            return;
        }
        let mut drained = 0usize;
        loop {
            match msg_rx.try_recv() {
                Ok(msg) => {
                    drained += 1;
                    handle_msg(
                        msg,
                        Reactor {
                            poller: &mut poller,
                            pending: &mut pending,
                            activity: &mut activity,
                        },
                        &registries,
                        &ready_tx,
                        config.max_connections,
                        stats,
                    );
                }
                Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => break,
            }
        }
        if drained > 0 {
            if let Some(s) = stats {
                Stats::bump_peak(&s.event_queue_depth_peak, drained);
            }
        }

        if poller.is_empty() {
            match msg_rx.recv_timeout(Duration::from_millis(poll_timeout as u64)) {
                Ok(msg) => handle_msg(
                    msg,
                    Reactor {
                        poller: &mut poller,
                        pending: &mut pending,
                        activity: &mut activity,
                    },
                    &registries,
                    &ready_tx,
                    config.max_connections,
                    stats,
                ),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            }
            continue;
        }

        let now = Instant::now();
        let next_idle = idle_timeout.map(|t| {
            activity
                .values()
                .map(|at| {
                    t.checked_sub(now.duration_since(*at))
                        .unwrap_or(Duration::ZERO)
                })
                .min()
                .unwrap_or(Duration::from_secs(3600))
        });
        let wait_ms = match next_idle {
            Some(next) => next.as_millis().min(poll_timeout as u128).max(1) as i32,
            None => poll_timeout,
        };
        let timed = [
            ws_next_deadline(&registries),
            h1_body_next_deadline(&registries),
        ]
        .into_iter()
        .flatten()
        .min();
        let wait_ms = match timed {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(now).as_millis();
                wait_ms.min(remaining.min(poll_timeout as u128).max(1) as i32)
            }
            None => wait_ms,
        };
        let ready = match poller.wait(wait_ms, Some(wake_fd)) {
            Ok(r) => {
                wait_errors = 0;
                r
            }
            Err(_) => {
                wait_errors += 1;
                if let Some(s) = stats {
                    s.event_wait_errors.fetch_add(1, Ordering::Relaxed);
                }
                rebuild_wait_set(&mut poller, &pending, &registries);
                if wait_errors >= 64 {
                    std::thread::sleep(Duration::from_millis(1));
                }
                continue;
            }
        };
        if let Some(s) = stats {
            s.event_poll_syscalls.fetch_add(1, Ordering::Relaxed);
        }

        if ready.contains(&WAKE_ID) {
            if let Some(s) = stats {
                s.event_wakeups.fetch_add(1, Ordering::Relaxed);
            }
            drain_wake(&wake_reader);
            let mut drained = 0usize;
            loop {
                match msg_rx.try_recv() {
                    Ok(msg) => {
                        drained += 1;
                        handle_msg(
                            msg,
                            Reactor {
                                poller: &mut poller,
                                pending: &mut pending,
                                activity: &mut activity,
                            },
                            &registries,
                            &ready_tx,
                            config.max_connections,
                            stats,
                        );
                    }
                    Err(TryRecvError::Disconnected) => return,
                    Err(TryRecvError::Empty) => break,
                }
            }
            if drained > 0 {
                if let Some(s) = stats {
                    Stats::bump_peak(&s.event_queue_depth_peak, drained);
                }
            }
        }

        let mut to_dispatch: Vec<usize> = Vec::new();
        for id in ready {
            if id == WAKE_ID {
                continue;
            }
            poller.unregister(id);
            activity.insert(id, Instant::now());
            if let Some(stream) = pending.remove(&id) {
                let mut prefix = [0u8; 24];
                let n = match stream.peek(&mut prefix) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        let fd = fd_of(&stream);
                        pending.insert(id, stream);
                        poller.register(id, fd, false);
                        continue;
                    }
                    Err(_) => {
                        activity.remove(&id);
                        if let Some(s) = stats {
                            Stats::decrement(&s.connections_active, 1);
                        }
                        continue;
                    }
                };
                if n == 0 {
                    activity.remove(&id);
                    if let Some(s) = stats {
                        Stats::decrement(&s.connections_active, 1);
                    }
                    continue;
                }
                match classify(&prefix[..n]) {
                    Class::Tls => {
                        let _ = stream.set_nonblocking(false);
                        let h = handler.clone();
                        let c = config.clone();
                        let p = pool.clone();
                        p.spawn(move || {
                            let _ = crate::courierust_server::serve_connection(stream, &*h, &c);
                        });
                        activity.remove(&id);
                        if let Some(s) = stats {
                            Stats::decrement(&s.connections_active, 1);
                        }
                    }
                    Class::H2 => {
                        let _ = stream.set_nonblocking(false);
                        let h = handler.clone();
                        let c = config.clone();
                        let p = pool.clone();
                        p.spawn(move || {
                            let _ = crate::courierust_server::dispatch(
                                crate::courierust_net::ConnStream::plain(stream),
                                &*h,
                                &c,
                            );
                        });
                        activity.remove(&id);
                        if let Some(s) = stats {
                            Stats::decrement(&s.connections_active, 1);
                        }
                    }
                    Class::H1 => {
                        let conn = EventConn::new(
                            stream,
                            config.max_body,
                            stats,
                            crate::courierust_server::ws::WakeSlot::new(),
                        );
                        if let Some(s) = stats {
                            s.h1_connections.fetch_add(1, Ordering::Relaxed);
                        }
                        registries.h1.lock().unwrap().insert(id, conn);
                        to_dispatch.push(id);
                    }
                    Class::NeedMore => {
                        let fd = fd_of(&stream);
                        pending.insert(id, stream);
                        poller.register(id, fd, false);
                    }
                    Class::Closed => {
                        activity.remove(&id);
                        if let Some(s) = stats {
                            Stats::decrement(&s.connections_active, 1);
                        }
                    }
                }
            } else {
                to_dispatch.push(id);
            }
        }
        let now = Instant::now();
        for id in ws_due_ids(&registries, now) {
            poller.unregister(id);
            activity.insert(id, now);
            to_dispatch.push(id);
        }
        for id in h1_body_due_ids(&registries, now) {
            poller.unregister(id);
            activity.insert(id, now);
            to_dispatch.push(id);
        }
        if !to_dispatch.is_empty() {
            for chunk in to_dispatch.chunks(DISPATCH_BATCH) {
                let _ = ready_tx.send(chunk.to_vec());
            }
        }
        if let Some(t) = idle_timeout {
            let near_idle = next_idle
                .map(|next| next <= Duration::from_millis(poll_timeout as u64))
                .unwrap_or(false);
            if near_idle {
                let now = Instant::now();
                let mut expired = Vec::new();
                let registered: HashSet<usize> = registries
                    .h1
                    .lock()
                    .unwrap()
                    .keys()
                    .chain(registries.ws.lock().unwrap().keys())
                    .copied()
                    .collect();
                for (&id, &at) in &activity {
                    if now.duration_since(at) < t {
                        continue;
                    }
                    if pending.contains_key(&id) || registered.contains(&id) {
                        expired.push(id);
                    }
                }
                for id in expired {
                    poller.unregister(id);
                    pending.remove(&id);
                    registries.h1.lock().unwrap().remove(&id);
                    registries.ws.lock().unwrap().remove(&id);
                    if activity.remove(&id).is_some() {
                        if let Some(s) = stats {
                            Stats::decrement(&s.connections_active, 1);
                        }
                    }
                }
            }
        }
    }
}

/// Answer a request that could not be parsed, then linger briefly before
/// the connection is dropped.
///
/// The blocking driver answers through the same status mapping (see
/// `h1::refusal_status`); keeping the two identical matters because which
/// one runs depends on `ServerConfig::event_driven`, and a client must not
/// be able to tell the difference between them by the *absence* of a
/// `400`.
fn refuse_malformed(conn: &EventConn, e: &Error) {
    let Some(status) = crate::courierust_server::h1::refusal_status(e) else {
        return;
    };
    let resp = crate::courierust_server::h1::error_response(status, "bad request");
    let body: &[u8] = match &resp.body {
        Body::Bytes(b) => b.as_ref(),
        _ => b"",
    };
    let mut out = Vec::with_capacity(128 + body.len());
    if courierust_h1::write_response_head(&mut out, resp.status, Version::HTTP_11, &resp.headers)
        .is_err()
    {
        return;
    }
    out.extend_from_slice(body);
    write_and_linger(&conn.socket, &out);
}

/// Write `bytes` to a raw accepted socket and linger briefly before the
/// close, so the answer is not destroyed by the RST the kernel sends when
/// a socket with unread data is closed.
///
/// Both phases poll against a deadline because the socket is
/// non-blocking — that is how the reactor owns it. A plain `write_all`
/// can lose the entire response to a single would-block, and
/// `set_read_timeout` has no effect on a non-blocking descriptor (the
/// linger loop used to exit on its first iteration for that reason).
fn write_and_linger(socket: &std::net::TcpStream, bytes: &[u8]) {
    use std::io::{Read, Write};
    let deadline = Instant::now() + crate::courierust_server::h1::LINGER_DEADLINE;
    let mut sent = 0usize;
    while sent < bytes.len() && Instant::now() < deadline {
        let mut writer: &std::net::TcpStream = socket;
        match writer.write(&bytes[sent..]) {
            Ok(0) => return,
            Ok(n) => sent += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(_) => return,
        }
    }
    let mut sink = [0u8; 8 * 1024];
    let mut left = crate::courierust_server::h1::LINGER_BUDGET;
    while left > 0 && Instant::now() < deadline {
        let mut reader: &std::net::TcpStream = socket;
        let want = core::cmp::min(left, sink.len());
        match reader.read(&mut sink[..want]) {
            Ok(0) => break,
            Ok(n) => left = left.saturating_sub(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(_) => break,
        }
    }
}

/// Emit and reset the per-request trace accumulators of one connection.
/// Called on every dispatch pickup (reporting the previous batch) and on
/// close (reporting the final batch, which would otherwise never be
/// printed — a single-request connection would lose its only row).
fn emit_trace(conn: &mut EventConn, id: usize, handoff_us: u64, fresh_wait_us: u64) {
    if conn.trace && conn.trace_requests > 0 {
        eprintln!(
            "H1SEG|id={id}|reqs={}|fresh_wait_us={fresh_wait_us}|handoff_us={handoff_us}|dispatch_us={}|parse_us={}|handler_us={}|build_us={}|write_us={}",
            conn.trace_requests,
            conn.dispatch_us,
            conn.parse_us,
            conn.handler_us,
            conn.build_us,
            conn.write_us,
        );
    }
    if conn.trace {
        conn.trace_requests = 0;
        conn.dispatch_us = 0;
        conn.parse_us = 0;
        conn.handler_us = 0;
        conn.build_us = 0;
        conn.write_us = 0;
    }
}

/// One event worker: processes a *batch* of ready connections and
/// re-registers the survivors. Each processed connection is followed by a
/// wake byte, so the event loop re-registers it without waiting for a
/// poll tick.
fn event_worker(
    ready_rx: Arc<std::sync::Mutex<Receiver<Vec<usize>>>>,
    registries: Registries,
    handler: &dyn Handler,
    config: &ServerConfig,
    msg_tx: &Sender<EventMsg>,
    wake_writer: &Arc<TcpStream>,
) {
    loop {
        let ids = match ready_rx.lock().unwrap().recv() {
            Ok(ids) => ids,
            Err(_) => return,
        };
        for id in ids {
            let ws_conn = registries.ws.lock().unwrap().remove(&id);
            if let Some(mut ws_conn) = ws_conn {
                let step =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ws_conn.step()));
                let outcome = match step {
                    Ok(o) => o,
                    Err(_) => crate::courierust_server::ws::WsStep::Close,
                };
                match outcome {
                    crate::courierust_server::ws::WsStep::Idle
                    | crate::courierust_server::ws::WsStep::NeedWrite => {
                        let fd = fd_of(ws_conn.socket());
                        let want_write =
                            matches!(outcome, crate::courierust_server::ws::WsStep::NeedWrite);
                        registries.ws.lock().unwrap().insert(id, ws_conn);
                        let _ = msg_tx.send(EventMsg::Register { id, fd, want_write });
                        wake_nudge(wake_writer);
                    }
                    crate::courierust_server::ws::WsStep::Close => {
                        let socket = ws_conn.socket().clone();
                        let _ = msg_tx.send(EventMsg::Closed {
                            id,
                            socket: Some(socket),
                        });
                        wake_nudge(wake_writer);
                    }
                }
                continue;
            }
            let mut conn = match registries.h1.lock().unwrap().remove(&id) {
                Some(c) => c,
                None => continue,
            };

            conn.arm_wake(|| {
                let tx = msg_tx.clone();
                let pipe = wake_writer.clone();
                Arc::new(move || {
                    let _ = tx.send(EventMsg::BodyChunk { id });
                    wake_nudge(&pipe);
                })
            });

            let (handoff_us, fresh_wait_us) = if conn.trace {
                let pickup_at = Instant::now();
                let handoff = conn
                    .parked_at
                    .take()
                    .map(|at| at.elapsed().as_micros() as u64)
                    .unwrap_or(0);
                let fresh = conn
                    .registered_at
                    .take()
                    .map(|at| pickup_at.duration_since(at).as_micros() as u64)
                    .unwrap_or(0);
                conn.pickup_at = Some(pickup_at);
                (handoff, fresh)
            } else {
                (0, 0)
            };
            emit_trace(&mut conn, id, handoff_us, fresh_wait_us);
            let step = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                conn.step(handler, config)
            }));
            let outcome = match step {
                Ok(Ok(o)) => o,
                Ok(Err(e)) => {
                    refuse_malformed(&conn, &e);
                    StepOutcome::Close
                }
                Err(_) => StepOutcome::Close,
            };
            match outcome {
                StepOutcome::Idle | StepOutcome::NeedWrite => {
                    let fd = fd_of(&conn.socket);
                    let want_write = matches!(outcome, StepOutcome::NeedWrite);
                    if conn.trace {
                        conn.parked_at = Some(Instant::now());
                    }
                    registries.h1.lock().unwrap().insert(id, conn);
                    let _ = msg_tx.send(EventMsg::Register { id, fd, want_write });
                    wake_nudge(wake_writer);
                }
                StepOutcome::Close => {
                    emit_trace(&mut conn, id, 0, 0);
                    let socket = conn.socket.clone();
                    let _ = msg_tx.send(EventMsg::Closed {
                        id,
                        socket: Some(socket),
                    });
                    wake_nudge(wake_writer);
                }
                StepOutcome::Tunnel(job) => {
                    emit_trace(&mut conn, id, 0, 0);
                    let TunnelJob {
                        plan,
                        socket,
                        leftover,
                        secure,
                    } = *job;
                    let _ = msg_tx.send(EventMsg::Detach {
                        id,
                        socket: Some(conn.socket.clone()),
                    });
                    wake_nudge(wake_writer);
                    let tx = msg_tx.clone();
                    let wake = wake_writer.clone();
                    let spawned = std::thread::Builder::new()
                        .name("courierust-tunnel".into())
                        .spawn(move || {
                            run_tunnel(socket, leftover, secure, plan);
                            let _ = tx.send(EventMsg::Closed { id, socket: None });
                            wake_nudge(&wake);
                        });
                    if spawned.is_err() {
                        let _ = msg_tx.send(EventMsg::Closed { id, socket: None });
                        wake_nudge(wake_writer);
                    }
                }
                StepOutcome::Upgrade(upgraded) => {
                    let mut ws_conn = *upgraded;
                    let fd = fd_of(ws_conn.socket());
                    let tx = msg_tx.clone();
                    let wake = wake_writer.clone();
                    ws_conn.set_wake(Arc::new(move || {
                        let _ = tx.send(EventMsg::Register {
                            id,
                            fd,
                            want_write: true,
                        });
                        wake_nudge(&wake);
                    }));
                    let step =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ws_conn.step()));
                    let outcome = match step {
                        Ok(o) => o,
                        Err(_) => crate::courierust_server::ws::WsStep::Close,
                    };
                    match outcome {
                        crate::courierust_server::ws::WsStep::Idle
                        | crate::courierust_server::ws::WsStep::NeedWrite => {
                            let want_write =
                                matches!(outcome, crate::courierust_server::ws::WsStep::NeedWrite);
                            registries.ws.lock().unwrap().insert(id, ws_conn);
                            let _ = msg_tx.send(EventMsg::Register { id, fd, want_write });
                            wake_nudge(wake_writer);
                        }
                        crate::courierust_server::ws::WsStep::Close => {
                            let socket = ws_conn.socket().clone();
                            let _ = msg_tx.send(EventMsg::Closed {
                                id,
                                socket: Some(socket),
                            });
                            wake_nudge(wake_writer);
                        }
                    }
                }
            }
        }
    }
}

/// Run one tunnel on the thread that owns it, then close the connection.
///
/// The socket was accepted non-blocking (the reactor never blocks on a
/// read), so it is switched back before the service sees it: a tunnel is a
/// blocking contract by definition, and `read`/`write` on a non-blocking
/// socket would report `WouldBlock` instead of waiting.
fn run_tunnel(
    socket: Arc<TcpStream>,
    leftover: Vec<u8>,
    secure: bool,
    plan: crate::courierust_server::tunnel::TunnelPlan,
) {
    let _ = socket.set_nonblocking(false);
    let stream = Arc::new(crate::courierust_net::ConnStream::plain_shared(socket));
    let mut reader =
        crate::courierust_io::BufReader::new(stream.clone(), leftover.len().max(16 * 1024));
    if !leftover.is_empty() {
        reader.seed(&leftover);
    }
    let conn = crate::courierust_server::TunnelConn::new(stream, reader, secure);
    plan.service.run(conn);
}

/// Accept loop: accept sockets and hand them to the event loop in
/// non-blocking mode. It never reads, peeks, sleeps or classifies, so a
/// slow client can never stall the accept path (which would starve every
/// later connection to this listener). Each accept is followed by a wake
/// byte so the event loop registers the new socket immediately.
fn accept_loop(
    listener: std::net::TcpListener,
    msg_tx: Sender<EventMsg>,
    wake_writer: &Arc<TcpStream>,
    stats: Option<&Stats>,
    stop: &crate::courierust_server::ServerStop,
) {
    let mut next_id = 1usize;
    for stream in listener.incoming() {
        if stop.is_requested() {
            return;
        }
        let Ok(stream) = stream else { continue };
        if let Some(s) = stats {
            s.connections_accepted.fetch_add(1, Ordering::Relaxed);
        }
        let id = next_id;
        next_id += 1;
        let accepted_at = if h1_trace() {
            Some(Instant::now())
        } else {
            None
        };
        let _ = msg_tx.send(EventMsg::NewConn {
            id,
            stream,
            accepted_at,
        });
        wake_nudge(wake_writer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_error::ErrorKind;
    use std::sync::atomic::AtomicUsize;

    /// An `EventConn` on a connected loopback pair, plus the peer end so a
    /// test can read what the connection wrote.
    fn conn_pair() -> (EventConn, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = TcpStream::connect(addr).unwrap();
        let (socket, _) = listener.accept().unwrap();
        socket.set_nonblocking(true).unwrap();
        let conn = EventConn::new(
            socket,
            1024 * 1024,
            None,
            crate::courierust_server::ws::WakeSlot::new(),
        );
        (conn, peer)
    }

    fn test_config() -> ServerConfig {
        ServerConfig {
            read_timeout: Some(Duration::from_millis(50)),
            ..ServerConfig::default()
        }
    }

    /// A chunk produced by the handler fires the wake the worker armed
    /// into the connection, which is what lets the reactor re-dispatch the
    /// connection immediately instead of on its poll deadline.
    #[test]
    fn streaming_body_fires_the_connection_wake() {
        let (mut conn, _peer) = conn_pair();
        let hits = Arc::new(AtomicUsize::new(0));
        let armed = hits.clone();
        conn.arm_wake(move || {
            let armed = armed.clone();
            Arc::new(move || {
                armed.fetch_add(1, Ordering::Relaxed);
            })
        });
        let (tx, body) = crate::courierust_body::channel();
        conn.set_stream(body.into_stream());
        assert!(conn.stream_rx.is_some());

        tx.send(Bytes::from_static(b"chunk")).unwrap();
        assert_eq!(
            hits.load(Ordering::Relaxed),
            1,
            "a produced chunk must wake the connection"
        );
        tx.send_bytes(b"more").unwrap();
        assert_eq!(hits.load(Ordering::Relaxed), 2);

        let (_raw_tx, raw) = std::sync::mpsc::channel();
        conn.set_stream(Some(ChannelStream::raw(raw)));
        assert!(
            !conn.stream_rx.as_ref().unwrap().stream.has_wake(),
            "a raw channel must not claim a wake"
        );
        assert_eq!(
            body_poll_delay(conn.stream_rx.as_ref().unwrap()),
            Duration::from_millis(BODY_POLL_MIN_MS),
            "a raw channel is polled, not waited on"
        );
    }

    /// Waiting for the next chunk parks the connection instead of holding
    /// the worker: the pump returns, the receiver survives, and the
    /// reactor is left a deadline to come back on.
    #[test]
    fn a_parked_stream_does_not_block_the_worker() {
        let (mut conn, mut peer) = conn_pair();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let config = test_config();
        let (tx, body) = crate::courierust_body::channel();
        conn.set_stream(body.into_stream());

        assert!(matches!(
            conn.pump_body(&config).unwrap(),
            StepOutcome::Idle
        ));
        assert!(conn.stream_rx.is_some(), "the receiver must survive a park");
        let due = conn.body_poll_at().expect("a parked body owes a deadline");
        assert!(due > Instant::now() && due <= Instant::now() + Duration::from_secs(1));

        // The chunk is written when the reactor comes back…
        tx.send(Bytes::from_static(b"hello")).unwrap();
        assert!(matches!(
            conn.pump_body(&config).unwrap(),
            StepOutcome::Idle
        ));
        // …and the terminating chunk once the producer is done.
        drop(tx);
        assert!(matches!(
            conn.pump_body(&config).unwrap(),
            StepOutcome::Idle
        ));
        assert!(conn.stream_rx.is_none(), "a finished body is released");
        drop(conn);
        let mut written = Vec::new();
        std::io::Read::read_to_end(&mut peer, &mut written).unwrap();
        assert_eq!(written, b"5\r\nhello\r\n0\r\n\r\n");
    }

    /// A producer that stalls past `read_timeout` fails the connection
    /// *without* the terminating chunk, so a truncated body stays
    /// detectable — the blocking driver's contract.
    #[test]
    fn a_stalled_stream_times_out_on_its_poll_deadline() {
        let (mut conn, _peer) = conn_pair();
        let config = ServerConfig {
            read_timeout: Some(Duration::from_millis(20)),
            ..ServerConfig::default()
        };
        let (tx, body) = crate::courierust_body::channel();
        conn.set_stream(body.into_stream());
        assert!(matches!(
            conn.pump_body(&config).unwrap(),
            StepOutcome::Idle
        ));

        std::thread::sleep(Duration::from_millis(30));
        let error = match conn.pump_body(&config) {
            Err(error) => error,
            Ok(_) => panic!("a stalled producer must time out"),
        };
        assert_eq!(error.kind, ErrorKind::Timeout);
        drop(tx);
    }

    /// A producer without a wake is polled: the deadline backs off to the
    /// cap while the stream stays silent and resets as soon as a chunk
    /// arrives, so a bursty stream is never charged the backoff.
    #[test]
    fn poll_backoff_only_applies_to_a_body_without_a_wake() {
        let (_tx, raw) = std::sync::mpsc::channel();
        let mut body = BodyRx::new(ChannelStream::raw(raw));
        assert_eq!(
            body_poll_delay(&body),
            Duration::from_millis(BODY_POLL_MIN_MS)
        );
        body.empty_polls = 4;
        assert_eq!(
            body_poll_delay(&body),
            Duration::from_millis(BODY_POLL_MAX_MS)
        );
        body.empty_polls = 100;
        assert_eq!(
            body_poll_delay(&body),
            Duration::from_millis(BODY_POLL_MAX_MS),
            "the backoff is capped"
        );

        // A wake-capable body is polled coarsely — but only once a
        // transport has actually installed the wake. The capability alone
        // changes nothing, so a body nobody adopted polls on the same
        // backoff as a raw channel.
        let (_tx, body) = crate::courierust_body::channel();
        let stream = body.into_stream().unwrap();
        let mut body = BodyRx::new(stream);
        body.empty_polls = 100;
        assert_eq!(
            body_poll_delay(&body),
            Duration::from_millis(BODY_POLL_MAX_MS),
            "an unadopted stream polls on the same backoff as a raw channel"
        );
        let (tx, body) = crate::courierust_body::channel();
        let stream = body.into_stream().unwrap();
        stream.install_wake(|| {});
        let mut stream = BodyRx::new(stream);
        stream.empty_polls = 100;
        assert_eq!(
            body_poll_delay(&stream),
            Duration::from_millis(BODY_POLL_WAKE_MS),
            "a wake-capable body needs no fast poll"
        );
        drop(tx);
    }
}
