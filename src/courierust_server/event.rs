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

/// Control messages sent to the event loop.
enum EventMsg {
    NewConn { id: usize, stream: TcpStream },
    Register { id: usize, fd: Fd, want_write: bool },
    Closed { id: usize },
}

/// How a worker wants the connection handled next.
#[derive(Debug)]
enum StepOutcome {
    /// Back to the poller (waiting for the next request / readability).
    Idle,
    /// The socket send buffer is full; wait for writability.
    NeedWrite,
    /// Close the connection.
    Close,
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
}

impl IncrRequest {
    fn new(body_limit: usize) -> Self {
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
                                // Reject an over-limit Content-Length up
                                // front, exactly like the blocking path —
                                // otherwise a huge advertised length would
                                // park this connection waiting for a body
                                // that is never allowed to arrive.
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
                    // Strict CRLF (mirrors the blocking decoder). A bare
                    // LF or any other terminator is rejected — the two
                    // paths must agree on where a chunk ends.
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
        // The request line was parsed once when the header block ended;
        // re-parsing here would duplicate that work on every request.
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
}

impl EventConn {
    fn new(socket: TcpStream, body_limit: usize, stats: Option<&Stats>) -> Self {
        let (reads, writes) = match stats {
            Some(s) => (
                Some(s.h1_read_syscalls.clone()),
                Some(s.h1_write_syscalls.clone()),
            ),
            None => (None, None),
        };
        Self {
            socket: Arc::new(socket),
            reader: IncrRequest::new(body_limit),
            out: Vec::new(),
            out_pos: 0,
            keep_alive: true,
            reads,
            writes,
        }
    }

    /// Process the connection one step (non-blocking). Serves as many
    /// pipelined requests as are fully buffered, then returns how to
    /// continue.
    fn step(&mut self, handler: &dyn Handler, config: &ServerConfig) -> Result<StepOutcome> {
        loop {
            if self.out_pos < self.out.len() {
                return self.write_more();
            }
            match self
                .reader
                .next_request(&self.socket, self.reads.as_deref())?
            {
                Some(req) => {
                    let request_close = courierust_h1::wants_close(&req.headers);
                    let resp = handler.handle(req);
                    self.out.clear();
                    let keep_alive = build_response(resp, config, request_close, &mut self.out)?;
                    self.out_pos = 0;
                    self.keep_alive = keep_alive;
                    match self.write_more()? {
                        StepOutcome::Idle => {
                            // Response fully written. Loop to serve any
                            // pipelined request already buffered; when
                            // nothing is complete the next call to
                            // `next_request` parks the connection.
                            continue;
                        }
                        other => return Ok(other),
                    }
                }
                None => return Ok(StepOutcome::Idle),
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
    // `keep_alive_requested` already applies the exact-token `Connection`
    // semantics (a `closex` token does not close); no separate substring
    // check here, or the two paths would disagree.
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

    let mut out = out;
    courierust_h1::write_response_head(&mut out, resp.status, Version::HTTP_11, &out_headers)?;
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
    let registry: Arc<std::sync::Mutex<HashMap<usize, EventConn>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));
    // Self-pipe: the accept thread and the workers write one byte here
    // whenever they queue a control message, so the event loop's blocking
    // poll returns immediately instead of waiting for the next poll tick.
    let (wake_reader, wake_writer) = wakeup_pair()?;
    let wake_writer = Arc::new(wake_writer);

    // Event loop thread (owns the poller + pending/activity state).
    let loop_handler = handler.clone();
    let loop_config = config.clone();
    let loop_pool = pool.clone();
    let loop_registry = registry.clone();
    let event_thread = thread::Builder::new()
        .name("courierust-event".into())
        .spawn(move || {
            event_loop(
                msg_rx,
                ready_tx,
                loop_handler,
                loop_config,
                loop_pool,
                loop_registry,
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
        let w_registry = registry.clone();
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
                        w_registry,
                        &*w_handler,
                        &w_config,
                        &w_msg_tx,
                        &w_wake,
                    );
                })?,
        );
    }

    // Acceptor thread: accept and hand the raw socket to the event loop.
    // It never reads, peeks, sleeps or classifies, so a slow client can
    // never stall the accept path.
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
    // No Nagle: a wake is one byte and must reach the reader's receive
    // buffer immediately — a delayed-ACK/Nagle pause here would hold a
    // worker→reactor handoff open for a full poll timeout.
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
        EventMsg::NewConn { id, stream } => {
            // Connection cap: beyond it, the new socket is closed
            // immediately (its fd is never registered, so the idle
            // timeout does not even have to reap it). The accept thread
            // has already accepted, so this is an accept-then-close —
            // the standard way to bound resources at the accept queue.
            if max_connections > 0 && activity.len() >= max_connections {
                drop(stream);
                return;
            }
            // The accept thread hands us a blocking socket; the event
            // loop requires non-blocking mode. `set_nodelay` disables
            // Nagle so a small response write is not held back by an
            // un-ACKed segment — without it, keep-alive requests on
            // loopback stall tens of milliseconds per request (the
            // exact issue the benchmark had to fix on the hyper side).
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
        }
        EventMsg::Register { id, fd, want_write } => {
            activity.insert(id, Instant::now());
            poller.register(id, fd, want_write);
        }
        EventMsg::Closed { id } => {
            if activity.remove(&id).is_some() {
                if let Some(s) = stats {
                    Stats::decrement(&s.connections_active, 1);
                }
            }
        }
    }
}

/// The event loop: polls sockets, classifies new connections, and
/// dispatches ready HTTP/1.1 connections to workers.
fn event_loop(
    msg_rx: Receiver<EventMsg>,
    ready_tx: Sender<Vec<usize>>,
    handler: Arc<dyn Handler>,
    config: ServerConfig,
    pool: Arc<crate::courierust_pool::ThreadPool>,
    registry: Arc<std::sync::Mutex<HashMap<usize, EventConn>>>,
    wake_reader: TcpStream,
) {
    let mut poller = Poller::new();
    let mut pending: HashMap<usize, TcpStream> = HashMap::new();
    let mut activity: HashMap<usize, Instant> = HashMap::new();
    let stats = config.stats.clone();
    let stats = stats.as_deref();

    let wake_fd = fd_of(&wake_reader);
    let poll_timeout = config.event_poll_timeout_ms.clamp(1, 1000) as i32;
    let idle_timeout = config.idle_timeout;

    loop {
        // 1. Drain control messages (new connections / re-registrations /
        //    closures). The depth of this drain is the control-queue
        //    depth: how many control messages arrived while the loop was
        //    busy (a herd of accepts/registers at once).
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

        // 2. With nothing registered, block for a message instead of
        //    busy-spinning the poller (which would otherwise return an
        //    empty ready set immediately). The received message must be
        //    handled here — it has already been consumed from the
        //    channel and would otherwise be lost.
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

        // 3. Poll. `wait` also watches the self-pipe, so a queued control
        //    message interrupts the timeout immediately; socket
        //    readiness (a client sending data) interrupts it the moment
        //    it happens. The timeout therefore only bounds the wait when
        //    nothing at all is happening — it never sits in the request
        //    latency path.
        let wait_ms = match idle_timeout {
            Some(t) => {
                let now = Instant::now();
                let next = activity
                    .values()
                    .map(|at| {
                        t.checked_sub(now.duration_since(*at))
                            .unwrap_or(Duration::ZERO)
                    })
                    .min()
                    .unwrap_or(Duration::from_secs(3600));
                next.as_millis().min(poll_timeout as u128).max(1) as i32
            }
            None => poll_timeout,
        };
        let ready = match poller.wait(wait_ms, Some(wake_fd)) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Some(s) = stats {
            s.event_poll_syscalls.fetch_add(1, Ordering::Relaxed);
        }

        // 4. A wake byte means a control message is queued. Drain the
        //    pipe (so it cannot fire spuriously) and the channel (so the
        //    message is applied before the next poll).
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

        // 5. Classify and dispatch the ready connections. Ready ids are
        //    collected and sent to the workers in batches.
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
                        // Spurious wake: park again.
                        let fd = fd_of(&stream);
                        pending.insert(id, stream);
                        poller.register(id, fd, false);
                        continue;
                    }
                    Err(_) => {
                        // Peer error: the connection leaves the reactor.
                        activity.remove(&id);
                        if let Some(s) = stats {
                            Stats::decrement(&s.connections_active, 1);
                        }
                        continue;
                    }
                };
                if n == 0 {
                    // Peer closed before sending anything.
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
                        let conn = EventConn::new(stream, config.max_body, stats);
                        if let Some(s) = stats {
                            s.h1_connections.fetch_add(1, Ordering::Relaxed);
                        }
                        registry.lock().unwrap().insert(id, conn);
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
                // An HTTP/1.1 connection (or a stale id — the worker
                // drops it defensively).
                to_dispatch.push(id);
            }
        }
        if !to_dispatch.is_empty() {
            for chunk in to_dispatch.chunks(DISPATCH_BATCH) {
                let _ = ready_tx.send(chunk.to_vec());
            }
        }

        // 6. Reap connections that have made no progress for the idle
        //    timeout (slow-loris / idle keep-alive bound). The registry
        //    is locked once per scan, not once per candidate.
        if let Some(t) = idle_timeout {
            let now = Instant::now();
            let mut expired = Vec::new();
            let registered: HashSet<usize> = registry.lock().unwrap().keys().copied().collect();
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
                registry.lock().unwrap().remove(&id);
                if activity.remove(&id).is_some() {
                    if let Some(s) = stats {
                        Stats::decrement(&s.connections_active, 1);
                    }
                }
            }
        }
    }
}

/// One event worker: processes a *batch* of ready connections and
/// re-registers the survivors. Each processed connection is followed by a
/// wake byte, so the event loop re-registers it without waiting for a
/// poll tick.
fn event_worker(
    ready_rx: Arc<std::sync::Mutex<Receiver<Vec<usize>>>>,
    registry: Arc<std::sync::Mutex<HashMap<usize, EventConn>>>,
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
            let mut conn = match registry.lock().unwrap().remove(&id) {
                Some(c) => c,
                None => continue,
            };
            let step = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                conn.step(handler, config)
            }));
            let outcome = match step {
                Ok(Ok(o)) => o,
                _ => StepOutcome::Close,
            };
            match outcome {
                StepOutcome::Idle | StepOutcome::NeedWrite => {
                    let fd = fd_of(&conn.socket);
                    let want_write = matches!(outcome, StepOutcome::NeedWrite);
                    registry.lock().unwrap().insert(id, conn);
                    let _ = msg_tx.send(EventMsg::Register { id, fd, want_write });
                    wake_nudge(wake_writer);
                }
                StepOutcome::Close => {
                    let _ = msg_tx.send(EventMsg::Closed { id });
                    wake_nudge(wake_writer);
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
        let _ = msg_tx.send(EventMsg::NewConn { id, stream });
        wake_nudge(wake_writer);
    }
}
