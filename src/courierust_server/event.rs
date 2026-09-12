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

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, Result};
use crate::courierust_h1;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::version::Version;
use crate::courierust_net::poller::{fd_of, Fd, Poller, WAKE_ID};
use crate::courierust_net::stats::Stats;
use crate::courierust_server::{Handler, ServerConfig};
use std::collections::{HashMap, HashSet};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
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
struct EventConn {
    socket: Arc<TcpStream>,
    /// Set once a `101` head has been queued: the next moment the head is
    /// fully written, this connection becomes a WebSocket.
    pending_upgrade: Option<(
        crate::courierust_server::ws::WsPlan,
        Arc<dyn crate::courierust_server::ws::WsService>,
    )>,
    /// Late-bound reactor wakeup, installed by the worker.
    wake_slot: Arc<crate::courierust_server::ws::WakeSlot>,
    reader: IncrRequest,
    /// Full response bytes pending write.
    out: Vec<u8>,
    /// Write cursor into `out`.
    out_pos: usize,
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
            wake_slot,
            reader: IncrRequest::new(body_limit, trace),
            out: Vec::new(),
            out_pos: 0,
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
                            // Defensive: no read observed (should not
                            // happen for a completed request); fall back
                            // to charging the whole span to parse.
                            seg_end(&mut self.parse_us, parse);
                        }
                    } else {
                        seg_end(&mut self.parse_us, parse);
                    }
                    let request_close = courierust_h1::wants_close(&req.headers);

                    // RFC 9112 §3.2: an HTTP/1.1 request must carry
                    // exactly one non-empty `Host`. Refused before the
                    // WebSocket decision and before the handler, so an
                    // ambiguous request cannot be routed at all.
                    if let Some(reason) =
                        courierust_h1::host_header_error(req.version, &req.headers)
                    {
                        self.out.clear();
                        let keep_alive = build_response(
                            crate::courierust_server::h1::error_response(400, reason),
                            config,
                            request_close,
                            &mut self.out,
                        )?;
                        self.out_pos = 0;
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
                            let keep_alive =
                                build_response(resp, config, request_close, &mut self.out)?;
                            self.out_pos = 0;
                            self.keep_alive = keep_alive;
                            let outcome = self.write_more()?;
                            match outcome {
                                StepOutcome::Idle => continue,
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

                    let handle = seg_start(trace);
                    let resp = handler.handle(req);
                    seg_end(&mut self.handler_us, handle);
                    self.out.clear();
                    let build = seg_start(trace);
                    let keep_alive = build_response(resp, config, request_close, &mut self.out)?;
                    seg_end(&mut self.build_us, build);
                    self.out_pos = 0;
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

/// Serialize a response (head + body, chunked for channel bodies) into
/// `out` and decide keep-alive. The caller owns the buffer (`out` is the
/// connection's write buffer), so steady-state responses perform no
/// per-request allocation. `request_close` reflects a request
/// `Connection: close` token, which forces the connection closed (RFC
/// 7230 §6.3).
fn build_response(
    resp: Response<Body>,
    config: &ServerConfig,
    request_close: bool,
    out: &mut Vec<u8>,
) -> Result<bool> {
    let keep_alive = !request_close
        && courierust_h1::keep_alive_requested(resp.version, &resp.headers)
        && resp.version != Version::HTTP_10;

    let mut out_headers = HeaderMap::with_capacity(resp.headers.len() + 3);
    for (n, v) in resp.headers.iter() {
        if courierust_h1::is_hop_by_hop(n.as_str()) {
            continue;
        }
        out_headers.append(n.clone(), v.clone());
    }
    let chunked = matches!(resp.body, Body::Channel(_));
    let body_len = match &resp.body {
        Body::Bytes(b) => Some(b.len()),
        _ => None,
    };
    if chunked {
        out_headers.insert(
            HeaderName::from_lowercase("transfer-encoding"),
            HeaderValue::from_static("chunked"),
        );
    } else if let Some(n) = body_len {
        let cl = courierust_h1::IToA::new(n);
        out_headers.insert(
            HeaderName::from_lowercase("content-length"),
            HeaderValue::from_bytes(cl.as_slice())?,
        );
    } else if !(resp.status.is_informational()
        || resp.status == crate::courierust_http::status::StatusCode::NO_CONTENT
        || resp.status == crate::courierust_http::status::StatusCode::NOT_MODIFIED)
    {
        out_headers.insert(
            HeaderName::from_lowercase("content-length"),
            HeaderValue::from_static("0"),
        );
    }
    out_headers.insert(
        HeaderName::from_lowercase("connection"),
        HeaderValue::from_static(if keep_alive { "keep-alive" } else { "close" }),
    );

    courierust_h1::write_response_head(out, resp.status, Version::HTTP_11, &out_headers)?;
    match resp.body {
        Body::Empty => {}
        Body::Bytes(b) => out.extend_from_slice(&b),
        Body::Channel(rx) => {
            let timeout = config.read_timeout;
            loop {
                let chunk = match timeout {
                    Some(t) => rx.recv_timeout(t).map_err(|_| ()),
                    None => rx.recv().map_err(|_| ()),
                };
                match chunk {
                    Ok(c) => {
                        let b = c?;
                        if b.is_empty() {
                            continue;
                        }
                        let sz = courierust_h1::IToA::new(b.len());
                        out.extend_from_slice(sz.as_slice());
                        out.extend_from_slice(b"\r\n");
                        out.extend_from_slice(&b);
                        out.extend_from_slice(b"\r\n");
                    }
                    Err(()) => break,
                }
            }
            out.extend_from_slice(b"0\r\n\r\n");
        }
    }
    Ok(keep_alive)
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
) -> std::io::Result<()> {
    let (msg_tx, msg_rx) = channel::<EventMsg>();
    let (ready_tx, ready_rx): (Sender<Vec<usize>>, Receiver<Vec<usize>>) = channel();
    let ready_rx = Arc::new(std::sync::Mutex::new(ready_rx));
    let registries = Registries::new();
    let (wake_reader, wake_writer) = wakeup_pair()?;
    let wake_writer = Arc::new(wake_writer);

    // Event loop thread (owns the poller + pending/activity state).
    let loop_handler = handler.clone();
    let loop_config = config.clone();
    let loop_pool = pool.clone();
    let loop_registries = registries.clone();
    let event_thread = thread::Builder::new()
        .name("courierust-event".into())
        .spawn(move || {
            event_loop(
                msg_rx,
                ready_tx,
                loop_handler,
                loop_config,
                loop_pool,
                loop_registries,
                wake_reader,
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
    let accept_thread = thread::Builder::new()
        .name("courierust-accept".into())
        .spawn(move || {
            accept_loop(listener, a_msg_tx, &a_wake, a_stats.as_deref());
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

/// Apply one control message to the poller / pending / activity state.
/// Used by both the message-drain path and the block-on-channel path, so
/// a message consumed from the channel is never dropped.
fn handle_msg(
    msg: EventMsg,
    poller: &mut Poller,
    pending: &mut HashMap<usize, TcpStream>,
    activity: &mut HashMap<usize, Instant>,
    max_connections: usize,
    stats: Option<&Stats>,
) {
    match msg {
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
    }
}

/// The event loop: polls sockets, classifies new connections, and
/// dispatches ready HTTP/1.1 and WebSocket connections to workers.
fn event_loop(
    msg_rx: Receiver<EventMsg>,
    ready_tx: Sender<Vec<usize>>,
    handler: Arc<dyn Handler>,
    config: ServerConfig,
    pool: Arc<crate::courierust_pool::ThreadPool>,
    registries: Registries,
    wake_reader: TcpStream,
) {
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
        let mut drained = 0usize;
        loop {
            match msg_rx.try_recv() {
                Ok(msg) => {
                    drained += 1;
                    handle_msg(
                        msg,
                        &mut poller,
                        &mut pending,
                        &mut activity,
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
            match msg_rx.recv() {
                Ok(msg) => handle_msg(
                    msg,
                    &mut poller,
                    &mut pending,
                    &mut activity,
                    config.max_connections,
                    stats,
                ),
                Err(_) => return,
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
                            &mut poller,
                            &mut pending,
                            &mut activity,
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
                            let _ = crate::courierust_server::serve_accepted(stream, &*h, &c);
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
                            let _ = crate::courierust_server::serve_connection(
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
                let registered: HashSet<usize> =
                    registries.h1.lock().unwrap().keys().copied().collect();
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
/// The blocking driver does the same thing (see `h1::serve`); keeping the
/// two identical matters because which one runs depends on
/// `ServerConfig::event_driven`, and a client must not be able to tell
/// the difference between them by the *absence* of a `400`.
///
/// The status is the honest one: a protocol error is a `400`, a header
/// block or request line over the limit is a `431`, and a body over the
/// limit is a `413`.
fn refuse_malformed(conn: &EventConn, e: &Error) {
    use crate::courierust_error::ErrorKind;
    let status = match e.kind {
        ErrorKind::Protocol => 400,
        ErrorKind::Overflow => {
            let header = e
                .message
                .as_deref()
                .map(|m| m.contains("header") || m.contains("line"))
                .unwrap_or(false);
            if header {
                431
            } else {
                413
            }
        }
        _ => return,
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
/// close, so the answer is not destroyed by the RST Linux sends when a
/// socket with unread data is closed.
fn write_and_linger(socket: &std::net::TcpStream, bytes: &[u8]) {
    use std::io::{Read, Write};
    {
        let mut writer: &std::net::TcpStream = socket;
        if writer.write_all(bytes).is_err() || writer.flush().is_err() {
            return;
        }
    }
    let _ = socket.set_read_timeout(Some(crate::courierust_server::h1::LINGER_DEADLINE));
    let mut sink = [0u8; 8 * 1024];
    let mut left = crate::courierust_server::h1::LINGER_BUDGET;
    let mut reader: &std::net::TcpStream = socket;
    while left > 0 {
        let want = core::cmp::min(left, sink.len());
        match reader.read(&mut sink[..want]) {
            Ok(0) => break,
            Ok(n) => left = left.saturating_sub(n),
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
) {
    let mut next_id = 1usize;
    for stream in listener.incoming() {
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
