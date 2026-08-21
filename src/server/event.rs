//! Event-driven HTTP/1.1 server (Windows).
//!
//! The classic "one pool job per connection" model burns a worker thread
//! for every idle keep-alive / SSE / long-poll connection, so a handful
//! of slow clients can exhaust a fixed pool. This module replaces that
//! with an I/O event loop:
//!
//! * A dedicated **event-loop thread** owns a [`crate::net::poller::Poller`]
//!   (`WSAPoll`) and parks *idle* connections — a connection with no data
//!   to read or write consumes **zero** worker threads.
//! * When a connection becomes readable, the event loop hands it to one
//!   of a small set of **event workers**. Each worker runs an
//!   **incremental request parser** that resumes exactly where it left
//!   off, so a slow sender (partial request) is parked again instead of
//!   holding a worker.
//! * After the response is written the connection returns to the poller
//!   for the next request (keep-alive), again consuming no worker.
//!
//! Honest scope: TLS and HTTP/2 connections still use the blocking pool
//! model; the event loop handles plain HTTP/1.1. A synchronous handler
//! that blocks for a long time still occupies a worker — exactly as with
//! any synchronous server (async handler support is future work).

#![cfg(windows)]

use crate::body::Body;
use crate::bytes::Bytes;
use crate::error::{Error, Result};
use crate::h1;
use crate::http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::http::request::Request;
use crate::http::response::Response;
use crate::http::version::Version;
use crate::net::poller::Poller;
use crate::server::{Handler, ServerConfig};
use std::collections::HashMap;
use std::net::TcpStream;
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread;

/// Per-line / per-header-block limits (mirror the blocking server).
const MAX_LINE: usize = 64 * 1024;
const MAX_HEADERS: usize = 1024;
const MAX_HEADER_BLOCK: usize = 1024 * 1024;

/// Control messages sent to the event loop.
enum EventMsg {
    /// (Re-)register a connection's socket with the poller.
    Register {
        id: usize,
        fd: RawSocket,
        want_write: bool,
    },
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
    fn fill(&mut self, socket: &TcpStream) -> Result<bool> {
        let mut tmp = [0u8; 8192];
        let mut got = false;
        loop {
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
    pub(crate) fn next_request(&mut self, socket: &TcpStream) -> Result<Option<Request<Body>>> {
        loop {
            if let Phase::Done = self.phase {
                return Ok(Some(self.finish_request()?));
            }
            if self.parse_step()? {
                continue;
            }
            // Need more data from the socket.
            self.compact();
            if !self.fill(socket)? {
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
                    let trimmed = h1::trim_crlf(&self.line);
                    if trimmed.is_empty() {
                        // End of headers: determine body framing.
                        let rl = h1::parse_request_line(&self.req_line)?;
                        let bl = h1::body_length(&self.headers, Some(&rl.method), None)?;
                        self.phase = match bl {
                            h1::BodyLen::None => Phase::Done,
                            h1::BodyLen::Length(n) => Phase::BodyFixed { remaining: n },
                            h1::BodyLen::Chunked => Phase::BodyChunked(Chunked {
                                state: ChunkState::Size,
                                remaining: 0,
                            }),
                        };
                    } else {
                        if self.headers.len() >= MAX_HEADERS {
                            return Err(Error::overflow("too many header fields"));
                        }
                        let (name, value) = h1::split_header(trimmed)?;
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
    fn parse_chunked(&mut self, ch: &mut Chunked) -> Result<bool> {
        match ch.state {
            ChunkState::Size => match self.read_line(b'\n', 1024) {
                Some(()) => {
                    if self.line.len() >= 1024 {
                        return Err(Error::protocol("chunk size line too long"));
                    }
                    let line = core::mem::take(&mut self.line);
                    let sz = parse_chunk_size(h1::trim_crlf(&line))
                        .ok_or_else(|| Error::protocol("bad chunk size"))?;
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
                // Consume the CRLF (or lone LF) after chunk data only when
                // it is fully present.
                let avail = self.buf.len() - self.pos;
                if avail >= 2 {
                    if &self.buf[self.pos..self.pos + 2] == b"\r\n" {
                        self.pos += 2;
                        ch.state = ChunkState::Size;
                        Ok(true)
                    } else if self.buf[self.pos] == b'\n' {
                        self.pos += 1;
                        ch.state = ChunkState::Size;
                        Ok(true)
                    } else {
                        Err(Error::protocol("bad chunk terminator"))
                    }
                } else if avail == 1 && self.buf[self.pos] == b'\n' {
                    self.pos += 1;
                    ch.state = ChunkState::Size;
                    Ok(true)
                } else {
                    // A lone '\r' waiting for its '\n', or no data yet.
                    Ok(false)
                }
            }
            ChunkState::Trailers => match self.read_line(b'\n', MAX_LINE) {
                Some(()) => {
                    if self.line.len() >= MAX_LINE {
                        return Err(Error::overflow("trailer line too long"));
                    }
                    let line = core::mem::take(&mut self.line);
                    if h1::trim_crlf(&line).is_empty() {
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
        let rl = h1::parse_request_line(&self.req_line)?;
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

/// Parse a chunk-size line (`1A ; optional-comment`).
fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let hex = line
        .iter()
        .take_while(|&&b| b != b';' && b != b' ')
        .copied()
        .collect::<Vec<u8>>();
    if hex.is_empty() {
        return None;
    }
    let mut n: usize = 0;
    for &b in &hex {
        let d = (b as char).to_digit(16)? as usize;
        n = n.checked_mul(16)?.checked_add(d)?;
    }
    Some(n)
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
}

impl EventConn {
    fn new(socket: TcpStream, body_limit: usize) -> Self {
        Self {
            socket: Arc::new(socket),
            reader: IncrRequest::new(body_limit),
            out: Vec::new(),
            out_pos: 0,
            keep_alive: true,
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
            match self.reader.next_request(&self.socket)? {
                Some(req) => {
                    let resp = handler.handle(req);
                    let (wire, keep_alive) = build_response(resp, config)?;
                    self.out = wire;
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
        self.out = Vec::new();
        self.out_pos = 0;
        if self.keep_alive {
            Ok(StepOutcome::Idle)
        } else {
            Ok(StepOutcome::Close)
        }
    }
}

/// Serialize a response (head + body, chunked for channel bodies) into
/// wire bytes and decide keep-alive.
fn build_response(resp: Response<Body>, config: &ServerConfig) -> Result<(Vec<u8>, bool)> {
    let keep_alive = h1::keep_alive_requested(resp.version, &resp.headers)
        && !resp
            .headers
            .get("connection")
            .map(|v| {
                v.to_str()
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .contains("close")
            })
            .unwrap_or(false)
        && resp.version != Version::HTTP_10;

    let mut out_headers = HeaderMap::with_capacity(resp.headers.len() + 3);
    for (n, v) in resp.headers.iter() {
        if h1::is_hop_by_hop(n.as_str()) {
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
        let cl = h1::IToA::new(n);
        out_headers.insert(
            HeaderName::from_lowercase("content-length"),
            HeaderValue::from_bytes(cl.as_slice())?,
        );
    } else if !(resp.status.is_informational()
        || resp.status == crate::http::status::StatusCode::NO_CONTENT
        || resp.status == crate::http::status::StatusCode::NOT_MODIFIED)
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

    let mut wire = Vec::with_capacity(1024);
    h1::write_response_head(&mut wire, resp.status, Version::HTTP_11, &out_headers)?;
    match resp.body {
        Body::Empty => {}
        Body::Bytes(b) => wire.extend_from_slice(&b),
        Body::Channel(rx) => {
            // Drain the channel synchronously (chunked framing). A long
            // idle stream therefore holds a worker — documented.
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
                        let sz = h1::IToA::new(b.len());
                        wire.extend_from_slice(sz.as_slice());
                        wire.extend_from_slice(b"\r\n");
                        wire.extend_from_slice(&b);
                        wire.extend_from_slice(b"\r\n");
                    }
                    Err(()) => break,
                }
            }
            wire.extend_from_slice(b"0\r\n\r\n");
        }
    }
    Ok((wire, keep_alive))
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
    pool: Arc<crate::pool::ThreadPool>,
) -> std::io::Result<()> {
    let (msg_tx, msg_rx) = channel::<EventMsg>();
    let (ready_tx, ready_rx): (Sender<usize>, Receiver<usize>) = channel();
    // mpsc is single-consumer; workers share the receiver under a mutex
    // (only one worker is ever inside `recv` at a time).
    let ready_rx = Arc::new(std::sync::Mutex::new(ready_rx));
    let registry: Arc<std::sync::Mutex<HashMap<usize, EventConn>>> =
        Arc::new(std::sync::Mutex::new(HashMap::new()));

    // Event loop thread.
    let loop_ready_tx = ready_tx.clone();
    let event_thread = thread::Builder::new()
        .name("courierust-event".into())
        .spawn(move || {
            event_loop(msg_rx, loop_ready_tx);
        })?;

    // Event worker threads.
    let workers = if config.event_workers == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
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
        worker_handles.push(
            thread::Builder::new()
                .name("courierust-event-worker".into())
                .spawn(move || {
                    event_worker(w_ready_rx, w_registry, &*w_handler, &w_config, &w_msg_tx);
                })?,
        );
    }

    // Acceptor thread.
    let a_registry = registry.clone();
    let a_msg_tx = msg_tx.clone();
    let a_handler = handler.clone();
    let a_config = config.clone();
    let a_pool = pool.clone();
    let accept_thread = thread::Builder::new()
        .name("courierust-accept".into())
        .spawn(move || {
            accept_loop(listener, a_registry, a_msg_tx, a_handler, &a_config, a_pool);
        })?;

    // Park: the listener's incoming() loop never returns; block on the
    // accept thread (which ends only if the listener errors).
    let _ = accept_thread.join();
    let _ = event_thread.join();
    for h in worker_handles {
        let _ = h.join();
    }
    Ok(())
}

/// The event loop: polls sockets and dispatches ready connections.
fn event_loop(msg_rx: Receiver<EventMsg>, ready_tx: Sender<usize>) {
    let mut poller = Poller::new();
    loop {
        // Drain control messages (new connections / re-registrations).
        loop {
            match msg_rx.try_recv() {
                Ok(EventMsg::Register { id, fd, want_write }) => {
                    poller.register(id, fd, want_write);
                }
                Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => break,
            }
        }
        let ready = match poller.wait(25) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for id in ready {
            poller.unregister(id);
            let _ = ready_tx.send(id);
        }
    }
}

/// One event worker: processes ready connections and re-registers them.
fn event_worker(
    ready_rx: Arc<std::sync::Mutex<Receiver<usize>>>,
    registry: Arc<std::sync::Mutex<HashMap<usize, EventConn>>>,
    handler: &dyn Handler,
    config: &ServerConfig,
    msg_tx: &Sender<EventMsg>,
) {
    loop {
        let id = match ready_rx.lock().unwrap().recv() {
            Ok(id) => id,
            Err(_) => return,
        };
        let mut conn = match registry.lock().unwrap().remove(&id) {
            Some(c) => c,
            None => continue,
        };
        let outcome = match conn.step(handler, config) {
            Ok(o) => o,
            Err(_) => StepOutcome::Close,
        };
        match outcome {
            StepOutcome::Idle | StepOutcome::NeedWrite => {
                let fd = conn.socket.as_raw_socket();
                let want_write = matches!(outcome, StepOutcome::NeedWrite);
                registry.lock().unwrap().insert(id, conn);
                let _ = msg_tx.send(EventMsg::Register { id, fd, want_write });
            }
            StepOutcome::Close => {
                // Dropped; the poller no longer references it.
            }
        }
    }
}

/// Accept loop: classify each connection and dispatch.
fn accept_loop(
    listener: std::net::TcpListener,
    registry: Arc<std::sync::Mutex<HashMap<usize, EventConn>>>,
    msg_tx: Sender<EventMsg>,
    handler: Arc<dyn Handler>,
    config: &ServerConfig,
    pool: Arc<crate::pool::ThreadPool>,
) {
    let mut next_id = 1usize;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // Classify by peeking the first bytes. We deliberately avoid
        // std's socket read-timeout (SO_RCVTIMEO) here: on Windows it
        // is unreliable under load and can block far beyond the requested
        // timeout, wedging the single accept thread and starving every
        // later connection to this listener. Instead we use an explicit
        // non-blocking peek with bounded sleeps, which can never block
        // indefinitely.
        let _ = stream.set_nonblocking(true);
        let mut prefix = [0u8; 24];
        let mut n = stream.peek(&mut prefix).unwrap_or(0);
        if n == 0 {
            // Servers that can speak h2/TLS must wait long enough for the
            // peer's writer thread to be scheduled under load; plain
            // h1-only servers use a short wait so a batch of idle
            // connections (which send nothing) does not stall the accept
            // loop for seconds.
            let retries = if config.http2 || config.tls.is_some() {
                80 // up to 2 s total
            } else {
                2 // up to 50 ms total
            };
            for _ in 0..retries {
                std::thread::sleep(std::time::Duration::from_millis(25));
                n = stream.peek(&mut prefix).unwrap_or(0);
                if n > 0 {
                    break;
                }
            }
        }
        let _ = stream.set_nonblocking(false);
        let is_tls = n >= 1 && prefix[0] == 0x16;
        let is_h2 = n >= 24 && crate::h2::connection::is_preface(&prefix);
        if is_tls || is_h2 {
            // Hand off to the blocking pool model.
            let h = handler.clone();
            let c = config.clone();
            let p = pool.clone();
            p.spawn(move || {
                if is_tls {
                    let _ = crate::server::serve_accepted(stream, &*h, &c);
                } else {
                    let _ = crate::server::serve_connection(
                        crate::net::ConnStream::plain(stream),
                        &*h,
                        &c,
                    );
                }
            });
            continue;
        }
        // Plain HTTP/1.1: register with the event loop.
        if let Err(e) = stream.set_nonblocking(true) {
            let _ = e;
            continue;
        }
        let id = next_id;
        next_id += 1;
        let conn = EventConn::new(stream, config.max_body);
        let fd = conn.socket.as_raw_socket();
        registry.lock().unwrap().insert(id, conn);
        let _ = msg_tx.send(EventMsg::Register {
            id,
            fd,
            want_write: false,
        });
    }
}
