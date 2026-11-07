//! HTTP/1.1 client connection: request serialization, response parsing
//! and keep-alive handling.
//!
//! Each connection owns its read/write buffers and a [`Scratch`] once,
//! so steady-state keep-alive requests perform no per-request buffer
//! allocation and no per-request socket reconfiguration.
//! Author: Blueokanna

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

#[cfg(test)]
mod tests;

/// Bound the work a peer can demand before sending a final response.
const MAX_INFORMATIONAL_RESPONSES: usize = 32;

/// One HTTP/1 connection with persistent buffers.
pub struct H1Connection {
    stream: Arc<ConnStream>,
    reader: BufReader<Arc<ConnStream>>,
    writer: BufWriter<Arc<ConnStream>>,
    scratch: Scratch,
    reusable: bool,
    read_started: bool,
}

impl H1Connection {
    /// Connect to `addr` and configure the socket once. When `tls` is
    /// set, wrap the socket in a TLS 1.3 client connection validated
    /// against `hostname`.
    ///
    /// This is the direct path; a client with a proxy dials the proxy and
    /// hands the tunnel to [`Self::from_socket`].
    pub fn connect(
        addr: SocketAddr,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
        cfg: &ClientConfig,
    ) -> Result<Self> {
        let stream = courierust_net::connect(&addr, cfg.connect_timeout)?;
        Self::from_socket(stream, tls, hostname, cfg)
    }

    /// Wrap an already-connected socket (a direct connection, or a
    /// `CONNECT` tunnel to `hostname`), configuring it for the phase it
    /// is about to run.
    pub fn from_socket(
        stream: std::net::TcpStream,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
        cfg: &ClientConfig,
    ) -> Result<Self> {
        let conn = match tls {
            Some(connector) => {
                courierust_net::configure(&stream, cfg.handshake_timeout.or(cfg.read_timeout))?;
                ConnStream::tls_client(stream, connector, hostname)?
            }
            None => ConnStream::plain(stream),
        };
        Self::from_stream_seeded(conn, cfg, &[])
    }

    /// Wrap a socket whose peer is an HTTP proxy, so the request — written
    /// in the absolute form by the caller — is addressed *to the proxy*.
    ///
    /// This is an alias of [`Self::from_socket`]. Forward-proxy request
    /// serialization is selected by the `to_proxy` argument to [`Self::send`].
    pub fn from_proxy_socket(
        stream: std::net::TcpStream,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
        cfg: &ClientConfig,
    ) -> Result<Self> {
        Self::from_socket(stream, tls, hostname, cfg)
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
        if let Some(alpn) = stream.alpn() {
            if alpn != b"http/1.1" {
                return Err(Error::protocol(format!(
                    "server negotiated {:?} via ALPN, expected HTTP/1.1",
                    String::from_utf8_lossy(&alpn)
                )));
            }
        }
        stream.set_deadline(cfg.read_timeout)?;
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
            reusable: true,
            read_started: false,
        })
    }

    /// Whether the connection can be returned to the pool.
    pub fn is_reusable(&self) -> bool {
        self.reusable && self.reader.buffered() == 0 && !self.stream.has_pending_read()
    }

    /// Re-arm the socket deadline for the request in flight.
    ///
    /// The pool configures each connection once, at connect time; this is
    /// the only reason a request would touch it again. The caller that
    /// overrides the deadline owns restoring it: the connection returns to
    /// the pool afterwards, where the configured value must be in force
    /// again — a pooled connection may not carry one caller's deadline
    /// into another's request.
    ///
    /// The deadline is armed with deadline semantics, so its expiry
    /// surfaces as [`ErrorKind::Timeout`] on every platform rather than
    /// as the POSIX-only `WouldBlock` a raw `EAGAIN` would produce.
    pub fn set_read_deadline(&self, timeout: Option<Duration>) -> Result<()> {
        self.stream.set_deadline(timeout)
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
        if !self.is_reusable() {
            return false;
        }
        thread_local! {
            static PROBE: std::cell::RefCell<Poller> =
                std::cell::RefCell::new(Poller::new());
        }
        PROBE.with(|probe| {
            let mut probe = probe.borrow_mut();
            probe.clear();
            probe.register(1, self.stream.raw_fd(), false);
            matches!(probe.wait(0, None), Ok(ready) if ready.is_empty())
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
        to_proxy: bool,
    ) -> Result<Response<Body>> {
        if !self.reusable
            || self.reader.buffered() != 0
            || (self.read_started && self.stream.has_pending_read())
        {
            return Err(Error::protocol("HTTP/1 connection is not reusable"));
        }
        let mut headers = HeaderMap::with_capacity(req.headers.len() + 4);
        headers.insert(
            HeaderName::from_lowercase("host"),
            HeaderValue::from_bytes(host_header.as_bytes())?,
        );
        for (n, v) in req.headers.iter() {
            if n.as_str() == "host" {
                continue;
            }
            if n.as_str() == "proxy-authorization" {
                if !to_proxy {
                    continue;
                }
            } else if courierust_h1::is_hop_by_hop(n.as_str()) {
                continue;
            }
            headers.append(n.clone(), v.clone());
        }
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
        if headers.contains_key("content-length") {
            let actual = body.map_or(0, |bytes| bytes.len());
            if courierust_h1::body_length(&headers, None, None)?
                != courierust_h1::BodyLen::Length(actual)
            {
                return Err(Error::protocol(
                    "content-length does not match request body",
                ));
            }
        }
        if let Some(b) = body {
            let cl = courierust_h1::IToA::new(b.len());
            headers.insert(
                HeaderName::from_lowercase("content-length"),
                HeaderValue::from_bytes(cl.as_slice())?,
            );
        }

        let head = self.scratch.body();
        courierust_h1::write_request_head(head, &req.method, &req.uri, Version::HTTP_11, &headers)?;
        self.reusable = false;
        self.read_started = false;
        self.writer.write_all(head)?;
        if let Some(b) = body {
            self.writer.write_all(b)?;
        }
        self.writer.flush()?;

        self.read_response(cfg, req.method.clone())
    }

    fn read_response(&mut self, cfg: &ClientConfig, method: Method) -> Result<Response<Body>> {
        self.reusable = false;
        for _ in 0..=MAX_INFORMATIONAL_RESPONSES {
            let line = self.scratch.line();
            let read = self.reader.read_until_into(b'\n', 16 * 1024, line);
            self.read_started |= !line.is_empty();
            read?;
            let (status, version) = courierust_h1::parse_status_line(line)?;
            if !matches!(version, Version::HTTP_10 | Version::HTTP_11) {
                return Err(Error::protocol("invalid HTTP/1 response version"));
            }
            if status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(Error::protocol("unsolicited protocol upgrade"));
            }
            let headers = courierust_h1::read_headers_scratch_with_limit(
                &mut self.reader,
                &mut self.scratch,
                cfg.max_header_list,
                || Ok(()),
            )?;
            if !status.is_informational() {
                return self.finish_response(
                    cfg,
                    &method,
                    ResponseHead {
                        status,
                        version,
                        headers,
                    },
                );
            }
        }
        Err(Error::overflow("too many informational responses"))
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
        self.reusable = false;
        let status = head.status;
        let version = head.version;
        let (reader, scratch) = (&mut self.reader, &mut self.scratch);
        let mut close_delimited = false;
        let body = match courierust_h1::body_length(&head.headers, Some(method), Some(status))? {
            courierust_h1::BodyLen::None => {
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
/// Only a clean EOF ends the body. Timeouts and transport resets are propagated as
/// errors — previously every read error was treated as EOF, silently
/// returning a truncated body as a successful response when a server
/// reset/aborted mid-stream. A request deadline that expires mid-body is
/// such an error: it must not be mistaken for the end of the message.
fn read_until_eof_scratch(
    reader: &mut BufReader<Arc<ConnStream>>,
    max: usize,
    scratch: &mut Scratch,
) -> Result<Bytes> {
    let out = scratch.body();
    loop {
        let b = match reader.fill_buf()? {
            [] => break,
            b => b,
        };
        let n = b.len();
        if n > max.saturating_sub(out.len()) {
            return Err(Error::overflow("body exceeds limit"));
        }
        out.extend_from_slice(b);
        reader.consume(n);
    }
    Ok(Bytes::from(core::mem::take(out)))
}
