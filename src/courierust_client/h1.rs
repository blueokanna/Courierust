//! HTTP/1.1 client connection: request serialization, response parsing
//! and keep-alive handling.
//!
//! Each connection owns its read/write buffers and a [`Scratch`] once,
//! so steady-state keep-alive requests perform no per-request buffer
//! allocation and no per-request socket reconfiguration.

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_client::ClientConfig;
use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_h1;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::{Response, ResponseHead};
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::version::Version;
use crate::courierust_io::{BufReader, BufWriter, Scratch};
use crate::courierust_net::poller::Poller;
use crate::courierust_net::{self, ConnStream};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// One HTTP/1 connection with persistent buffers.
pub struct H1Connection {
    stream: Arc<ConnStream>,
    reader: BufReader<Arc<ConnStream>>,
    writer: BufWriter<Arc<ConnStream>>,
    scratch: Scratch,
    version: Version,
    reusable: bool,
    /// Whether the peer produced any part of the *current* response.
    ///
    /// A failure after this point is a real answer (a truncated
    /// response), never a stale connection: the request was processed,
    /// so replaying it would be a second execution, not a retry.
    read_started: bool,
}

impl H1Connection {
    /// Connect to `addr` and configure the socket once. When `tls` is
    /// set, wrap the socket in a TLS 1.3 client connection validated
    /// against `hostname`.
    pub fn connect(
        addr: SocketAddr,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
        cfg: &ClientConfig,
    ) -> Result<Self> {
        let stream = courierust_net::connect(&addr, cfg.connect_timeout)?;
        let conn = match tls {
            Some(c) => {
                courierust_net::configure(&stream, cfg.handshake_timeout)?;
                let conn = ConnStream::tls_client(stream, c, hostname)?;
                if let Some(alpn) = conn.alpn() {
                    if alpn.as_slice() == b"h2" {
                        return Err(Error::protocol(
                            "server negotiated h2 via ALPN, but the client is configured for HTTP/1.1",
                        ));
                    }
                }
                conn
            }
            None => {
                courierust_net::configure(&stream, cfg.read_timeout)?;
                ConnStream::plain(stream)
            }
        };
        let _ = conn.configure(cfg.read_timeout);
        let conn = Arc::new(conn);
        Ok(Self {
            reader: BufReader::new(conn.clone(), 16 * 1024),
            writer: BufWriter::new(conn.clone(), 16 * 1024),
            stream: conn,
            scratch: Scratch::new(),
            version: Version::HTTP_11,
            reusable: true,
            read_started: false,
        })
    }

    /// Wrap an already-open transport (e.g. a socket left over from an
    /// RFC 7540 §3.2 `h2c` Upgrade handshake that the server declined),
    /// seeding the reader with bytes already read past the response head
    /// (the start of the body).
    pub(crate) fn from_stream_seeded(
        stream: ConnStream,
        cfg: &ClientConfig,
        seed: &[u8],
    ) -> Result<Self> {
        let _ = stream.configure(cfg.read_timeout);
        let conn = Arc::new(stream);
        let mut reader = BufReader::new(conn.clone(), 16 * 1024);
        if !seed.is_empty() {
            reader.seed(seed);
        }
        Ok(Self {
            reader,
            writer: BufWriter::new(conn.clone(), 16 * 1024),
            stream: conn,
            scratch: Scratch::new(),
            version: Version::HTTP_11,
            reusable: true,
            read_started: false,
        })
    }

    /// Whether the connection can be returned to the pool.
    pub fn is_reusable(&self) -> bool {
        self.reusable
    }

    /// Re-arm the socket deadline for the request in flight.
    ///
    /// The pool configures each connection once, at connect time; this is
    /// the only reason a request would touch it again. The caller that
    /// overrides the deadline owns restoring it: the connection returns to
    /// the pool afterwards, where the configured value must be in force
    /// again — a pooled connection may not carry one caller's deadline
    /// into another's request.
    pub fn set_read_deadline(&self, timeout: Option<Duration>) -> Result<()> {
        self.stream.configure(timeout)
    }

    /// Whether the peer has closed this connection while it sat idle.
    ///
    /// A pooled keep-alive connection can die without anyone watching:
    /// the server's own keep-alive timeout, an intermediary, a restart.
    /// One zero-timeout poll answers that without consuming anything, and
    /// nothing else is needed: on an idle HTTP/1.1 connection the peer
    /// may legally send *nothing*, so a socket that reports readable is
    /// spent either way — EOF, a reset, an unsolicited record (a TLS
    /// `close_notify` arrives exactly like that).
    ///
    /// Checking *before* a request is what keeps a dead pool entry from
    /// costing anything: nothing has been written yet, so there is no
    /// replay question at all — not even for a `POST`.
    pub fn is_alive(&self) -> bool {
        thread_local! {
            /// Reused across probes: the steady state must not allocate.
            static PROBE: std::cell::RefCell<Poller> =
                std::cell::RefCell::new(Poller::new());
        }
        PROBE.with(|probe| {
            let mut probe = probe.borrow_mut();
            probe.clear();
            probe.register(1, self.stream.raw_fd(), false);
            probe.wait(0, None).unwrap_or_default().is_empty()
        })
    }

    /// Whether the current response has started, i.e. whether the peer
    /// answered at least in part.
    pub fn response_started(&self) -> bool {
        self.read_started
    }

    /// Whether `error` is the signature of a keep-alive connection that
    /// was already gone when the request was written: the peer hung up
    /// without answering anything.
    ///
    /// Only meaningful together with [`Self::response_started`] being
    /// false — a truncated response also ends in an unexpected EOF, but
    /// there the request *was* processed.
    pub fn is_stale_failure(&self, error: &Error) -> bool {
        !self.read_started && matches!(error.kind, ErrorKind::UnexpectedEof | ErrorKind::Canceled)
    }

    /// The remote address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.stream.peer_addr()
    }

    /// Send a request and read the full response.
    pub fn send(
        &mut self,
        req: &Request<Body>,
        cfg: &ClientConfig,
        host_header: &str,
    ) -> Result<Response<Body>> {
        let mut headers = HeaderMap::with_capacity(req.headers.len() + 4);
        for (n, v) in req.headers.iter() {
            if courierust_h1::is_hop_by_hop(n.as_str()) {
                continue;
            }
            headers.append(n.clone(), v.clone());
        }
        headers.insert(
            HeaderName::from_lowercase("host"),
            HeaderValue::from_bytes(host_header.as_bytes())?,
        );
        if !headers.contains_key("user-agent") {
            if let Some(ua) = &cfg.user_agent {
                headers.insert(
                    HeaderName::from_lowercase("user-agent"),
                    HeaderValue::from_bytes(ua.as_bytes())?,
                );
            }
        }
        let body = match &req.body {
            Body::Empty => None,
            Body::Bytes(b) => Some(b),
            Body::Channel(_) | Body::Stream(_) => {
                return Err(Error::protocol("streaming request bodies require h2"));
            }
        };
        if let Some(b) = body {
            let cl = courierust_h1::IToA::new(b.len());
            headers.insert(
                HeaderName::from_lowercase("content-length"),
                HeaderValue::from_bytes(cl.as_slice())?,
            );
        }

        let head = self.scratch.body();
        courierust_h1::write_request_head(head, &req.method, &req.uri, Version::HTTP_11, &headers)?;
        self.read_started = false;
        self.writer.write_all(head)?;
        if let Some(b) = body {
            self.writer.write_all(b)?;
        }
        self.writer.flush()?;

        self.read_response(cfg, req.method.clone())
    }

    fn read_response(&mut self, cfg: &ClientConfig, method: Method) -> Result<Response<Body>> {
        let (reader, scratch) = (&mut self.reader, &mut self.scratch);
        let status_line = scratch.line();
        reader.read_until_into(b'\n', 16 * 1024, status_line)?;
        let (status, version) = courierust_h1::parse_status_line(status_line)?;
        // The peer answered: from here on a failure is a truncated
        // response, not a stale connection.
        self.read_started = true;
        self.version = version;
        let mut status = status;
        let mut headers = courierust_h1::read_headers_scratch(reader, scratch)?;
        while status.is_informational() {
            let line = scratch.line();
            reader.read_until_into(b'\n', 16 * 1024, line)?;
            let (s, _) = courierust_h1::parse_status_line(line)?;
            status = s;
            headers = courierust_h1::read_headers_scratch(reader, scratch)?;
        }
        let head = ResponseHead {
            status,
            version,
            headers,
        };
        self.finish_response(cfg, &method, head)
    }

    /// Read a response body given an already-parsed response head (used
    /// by the `h2c` Upgrade fallback, where the head was consumed by the
    /// handshake). `method` is the request method, which decides whether
    /// a response to a HEAD request may carry a body (RFC 9112 §6.3).
    pub fn finish_response(
        &mut self,
        cfg: &ClientConfig,
        method: &Method,
        head: ResponseHead,
    ) -> Result<Response<Body>> {
        // The caller already consumed the head, so the peer has answered.
        self.read_started = true;
        let status = head.status;
        let version = head.version;
        let (reader, scratch) = (&mut self.reader, &mut self.scratch);
        let mut close_delimited = false;
        let body = match courierust_h1::body_length(&head.headers, Some(method), Some(status))? {
            courierust_h1::BodyLen::None => {
                // RFC 9112 §6.3 lists exactly HEAD, 1xx, 204 and 304 as
                // bodyless. Treating *any* 3xx as empty used to leave a
                // close-delimited redirect body unread and mark the
                // connection reusable, so those bytes were parsed as the
                // next response's status line.
                if *method == Method::HEAD
                    || status == StatusCode::NO_CONTENT
                    || status == StatusCode::NOT_MODIFIED
                    || status.is_informational()
                {
                    Body::Empty
                } else {
                    close_delimited = true;
                    Body::Bytes(read_until_eof_scratch(reader, cfg.max_body, scratch)?)
                }
            }
            courierust_h1::BodyLen::Length(0) => Body::Empty,
            courierust_h1::BodyLen::Length(n) => Body::Bytes(
                courierust_h1::read_body_fixed_scratch(reader, n, cfg.max_body, scratch)?,
            ),
            courierust_h1::BodyLen::Chunked => Body::Bytes(
                courierust_h1::read_body_chunked_scratch(reader, cfg.max_body, scratch)?,
            ),
        };
        self.reusable = !close_delimited
            && !courierust_h1::wants_close(&head.headers)
            && version == Version::HTTP_11;
        Ok(head.with_body(body))
    }
}

/// Read a body delimited by connection close into the scratch body
/// buffer.
///
/// Only a clean EOF (or a WouldBlock on a non-blocking transport) ends
/// the body. Timeouts and transport resets mid-body are propagated as
/// errors — previously every read error was treated as EOF, silently
/// returning a truncated body as a successful response when a server
/// reset/aborted mid-stream.
fn read_until_eof_scratch(
    reader: &mut BufReader<Arc<ConnStream>>,
    max: usize,
    scratch: &mut Scratch,
) -> Result<Bytes> {
    let out = scratch.body();
    loop {
        let b = match reader.fill_buf() {
            Ok([]) => break,
            Ok(b) => b,
            Err(e) => match e.kind {
                ErrorKind::UnexpectedEof => break, // clean close ends the body
                ErrorKind::WouldBlock => break,    // never on a blocking socket
                _ => return Err(e),
            },
        };
        let n = b.len();
        if out.len() + n > max {
            return Err(Error::overflow("body exceeds limit"));
        }
        out.extend_from_slice(b);
        reader.consume(n);
    }
    Ok(Bytes::from(core::mem::take(out)))
}
