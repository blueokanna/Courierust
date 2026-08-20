//! HTTP/1.1 client connection: request serialization, response parsing
//! and keep-alive handling.
//!
//! Each connection owns its read/write buffers and a [`Scratch`] once,
//! so steady-state keep-alive requests perform no per-request buffer
//! allocation and no per-request socket reconfiguration.

use crate::body::Body;
use crate::bytes::Bytes;
use crate::client::ClientConfig;
use crate::error::{Error, Result};
use crate::h1;
use crate::http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::http::request::Request;
use crate::http::response::{Response, ResponseHead};
use crate::http::status::StatusCode;
use crate::http::version::Version;
use crate::io::{BufReader, BufWriter, Scratch};
use crate::net;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::Arc;

/// One HTTP/1 connection with persistent buffers.
pub struct H1Connection {
    stream: Arc<TcpStream>,
    reader: BufReader<Arc<TcpStream>>,
    writer: BufWriter<Arc<TcpStream>>,
    scratch: Scratch,
    /// Negotiated version.
    version: Version,
    /// Whether the connection can be reused.
    reusable: bool,
}

impl H1Connection {
    /// Connect to `addr` and configure the socket once.
    pub fn connect(addr: SocketAddr, cfg: &ClientConfig) -> Result<Self> {
        let stream = net::connect(&addr, cfg.connect_timeout)?;
        net::configure(&stream, cfg.read_timeout)?;
        let stream = Arc::new(stream);
        Ok(Self {
            reader: BufReader::new(stream.clone(), 16 * 1024),
            writer: BufWriter::new(stream.clone(), 16 * 1024),
            stream,
            scratch: Scratch::new(),
            version: Version::HTTP_11,
            reusable: true,
        })
    }

    /// Whether the connection can be returned to the pool.
    pub fn is_reusable(&self) -> bool {
        self.reusable
    }

    /// The remote address.
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.stream
            .peer_addr()
            .map_err(|e| Error::io(e.to_string()))
    }

    /// Send a request and read the full response.
    pub fn send(
        &mut self,
        req: &Request<Body>,
        cfg: &ClientConfig,
        host_header: &str,
    ) -> Result<Response<Body>> {
        // Build the wire header set.
        let mut headers = HeaderMap::with_capacity(req.headers.len() + 4);
        for (n, v) in req.headers.iter() {
            if h1::is_hop_by_hop(n.as_str()) {
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
            Body::Channel(_) => {
                return Err(Error::protocol("streaming request bodies require h2"));
            }
        };
        if let Some(b) = body {
            let cl = h1::IToA::new(b.len());
            headers.insert(
                HeaderName::from_lowercase("content-length"),
                HeaderValue::from_bytes(cl.as_slice())?,
            );
        }

        // Serialize the head into the connection scratch, then write the
        // whole request in one buffered pass.
        let head = self.scratch.body();
        h1::write_request_head(head, &req.method, &req.uri, Version::HTTP_11, &headers)?;
        self.writer.write_all(head)?;
        if let Some(b) = body {
            self.writer.write_all(b)?;
        }
        self.writer.flush()?;

        self.read_response(cfg)
    }

    fn read_response(&mut self, cfg: &ClientConfig) -> Result<Response<Body>> {
        let (reader, scratch) = (&mut self.reader, &mut self.scratch);
        // Status line.
        let status_line = scratch.line();
        reader.read_until_into(b'\n', 16 * 1024, status_line)?;
        let (status, version) = h1::parse_status_line(status_line)?;
        self.version = version;
        // 100-continue / informational responses: skip until a final one.
        let mut status = status;
        let mut headers = h1::read_headers_scratch(reader, scratch)?;
        while status.is_informational() {
            let line = scratch.line();
            reader.read_until_into(b'\n', 16 * 1024, line)?;
            let (s, _) = h1::parse_status_line(line)?;
            status = s;
            headers = h1::read_headers_scratch(reader, scratch)?;
        }
        let mut close_delimited = false;
        let body = match h1::body_length(&headers, None, Some(status))? {
            h1::BodyLen::None => {
                // 204/304/1xx carry no body; 3xx without framing are
                // treated as empty in practice; anything else without
                // framing is delimited by connection close.
                if status == StatusCode::NO_CONTENT
                    || status == StatusCode::NOT_MODIFIED
                    || status.is_informational()
                    || status.is_redirection()
                {
                    Body::Empty
                } else {
                    close_delimited = true;
                    Body::Bytes(read_until_eof_scratch(reader, cfg.max_body, scratch)?)
                }
            }
            h1::BodyLen::Length(0) => Body::Empty,
            h1::BodyLen::Length(n) => Body::Bytes(h1::read_body_fixed_scratch(
                reader,
                n,
                cfg.max_body,
                scratch,
            )?),
            h1::BodyLen::Chunked => Body::Bytes(h1::read_body_chunked_scratch(
                reader,
                cfg.max_body,
                scratch,
            )?),
        };
        self.reusable =
            !close_delimited && !h1::wants_close(&headers) && version == Version::HTTP_11;
        let head = ResponseHead {
            status,
            version,
            headers,
        };
        Ok(head.with_body(body))
    }
}

/// Read a body delimited by connection close into the scratch body
/// buffer.
fn read_until_eof_scratch(
    reader: &mut BufReader<Arc<TcpStream>>,
    max: usize,
    scratch: &mut Scratch,
) -> Result<Bytes> {
    let out = scratch.body();
    loop {
        let b = match reader.fill_buf() {
            Ok([]) => break,
            Ok(b) => b,
            Err(_) => break,
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
