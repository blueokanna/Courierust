//! HTTP/1.1 client connection: request serialization, response parsing
//! and keep-alive handling.

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
use crate::io::{BufReader, BufWriter};
use crate::net;
use std::net::SocketAddr;
use std::net::TcpStream;

/// One HTTP/1 connection.
pub struct H1Connection {
    stream: TcpStream,
    /// Negotiated version.
    version: Version,
    /// Whether the connection can be reused.
    reusable: bool,
}

impl H1Connection {
    /// Connect to `addr`.
    pub fn connect(addr: SocketAddr, cfg: &ClientConfig) -> Result<Self> {
        let stream = net::connect(&addr, cfg.connect_timeout)?;
        Ok(Self {
            stream,
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
            headers.insert(
                HeaderName::from_lowercase("content-length"),
                HeaderValue::from_bytes(b.len().to_string().as_bytes())?,
            );
        }

        let mut writer = BufWriter::new(&self.stream, 16 * 1024);
        let mut head = Vec::with_capacity(256);
        h1::write_request_head(&mut head, &req.method, &req.uri, Version::HTTP_11, &headers)?;
        writer.write_all(&head)?;
        if let Some(b) = body {
            writer.write_all(b)?;
        }
        writer.flush()?;
        drop(writer);

        self.read_response(cfg)
    }

    fn read_response(&mut self, cfg: &ClientConfig) -> Result<Response<Body>> {
        net::configure(&self.stream, cfg.read_timeout)?;
        let mut reader = BufReader::new(&self.stream, 16 * 1024);
        // Status line.
        let status_line = reader.read_until(b'\n', 16 * 1024)?;
        let (status, version) = h1::parse_status_line(&status_line)?;
        self.version = version;
        // 100-continue / informational responses: skip until a final one.
        let mut status = status;
        let mut headers = h1::read_headers(&mut reader)?;
        while status.is_informational() {
            let line = reader.read_until(b'\n', 16 * 1024)?;
            let (s, _) = h1::parse_status_line(&line)?;
            status = s;
            headers = h1::read_headers(&mut reader)?;
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
                    Body::Bytes(read_until_eof(&mut reader, cfg.max_body)?)
                }
            }
            h1::BodyLen::Length(0) => Body::Empty,
            h1::BodyLen::Length(n) => {
                Body::Bytes(h1::read_body_fixed(&mut reader, n, cfg.max_body)?)
            }
            h1::BodyLen::Chunked => Body::Bytes(h1::read_body_chunked(&mut reader, cfg.max_body)?),
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

/// Read a body delimited by connection close.
fn read_until_eof(reader: &mut BufReader<&TcpStream>, max: usize) -> Result<Bytes> {
    let mut out = Vec::new();
    loop {
        let b = match reader.fill_buf() {
            Ok([]) => break,
            Ok(b) => b.to_vec(),
            Err(_) => break,
        };
        reader.consume(b.len());
        if out.len() + b.len() > max {
            return Err(Error::overflow("body exceeds limit"));
        }
        out.extend_from_slice(&b);
    }
    Ok(Bytes::from(out))
}
