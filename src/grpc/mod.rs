//! gRPC over the HTTP/2 stack.
//!
//! gRPC is HTTP/2 + length-prefixed binary messages + trailers carrying
//! `grpc-status`. This module implements the framing and status handling
//! on top of [`crate::client::Client`] (h2) and [`crate::server::Server`].
//! Protobuf itself is deliberately out of scope: implement
//! [`crate::grpc::codec::EncodeMessage`] / [`crate::grpc::codec::DecodeMessage`]
//! for your message types (or use the raw-bytes API) and plug in your own
//! protobuf codec.

pub mod codec;
pub mod status;

use crate::body::Body;
use crate::bytes::Bytes;
use crate::client::Client;
use crate::error::{Error, Result};
use crate::h2::priority::Priority;
use crate::http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::http::method::Method;
use crate::http::request::Request;
use crate::http::response::Response;
use crate::http::uri::PathAndQuery;
use crate::server::{Handler, Server, ServerConfig};
use std::sync::{Arc, Mutex};

/// Content type marker for gRPC requests/responses
pub const CONTENT_TYPE: &str = "application/grpc";
/// The `te` header value gRPC requires
pub const TE_VALUE: &str = "trailers";
/// Maximum message size accepted by the framing layer
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// gRPC client.
#[derive(Clone)]
pub struct GrpcClient {
    /// The underlying HTTP/2 client
    pub client: Client,
    /// Base URL (scheme://host:port)
    pub base: String,
}

impl GrpcClient {
    /// Connect to a gRPC endpoint (h2c prior knowledge).
    pub fn new(base: &str) -> Result<Self> {
        let cfg = crate::client::ClientConfig {
            http2: true,
            user_agent: None,
            ..Default::default()
        };
        let client = Client::with_config(cfg);
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_string(),
        })
    }

    /// Perform a unary call with raw bytes. `method` is
    /// `package.Service/Method`.
    pub fn call(&self, method: &str, req: Bytes) -> Result<Bytes> {
        let mut stream = self.call_stream(method, req)?;
        match stream.next_message()? {
            Some(msg) => Ok(msg),
            None => Err(Error::grpc(
                status::INTERNAL,
                "empty response from unary call",
            )),
        }
    }

    /// Perform a unary call with a typed codec.
    pub fn call_unary<Req: codec::EncodeMessage, Resp: codec::DecodeMessage>(
        &self,
        method: &str,
        req: &Req,
    ) -> Result<Resp> {
        let body = req.encode_message()?;
        let resp = self.call(method, Bytes::from(body))?;
        Resp::decode_message(&resp)
    }

    /// Start a server-streaming call and return the message stream.
    pub fn call_stream(&self, method: &str, req: Bytes) -> Result<MessageStream> {
        let msg = frame_message(&req, false);
        let uri = PathAndQuery::from_bytes(method.as_bytes())?;
        let mut request = Request::new(Method::POST, uri);
        request.headers.insert(
            HeaderName::from_lowercase("content-type"),
            HeaderValue::from_static(CONTENT_TYPE),
        );
        request.headers.insert(
            HeaderName::from_lowercase("te"),
            HeaderValue::from_static(TE_VALUE),
        );
        request.headers.insert(
            HeaderName::from_lowercase("grpc-accept-encoding"),
            HeaderValue::from_static("identity"),
        );
        request.body = Body::Bytes(Bytes::from(msg));
        let url = crate::http::uri::Url::parse(&format!("{}{}", self.base, method))?;
        let resp = self
            .client
            .execute_h2_raw(&url, request, Priority::default())?;
        MessageStream::new(resp)
    }
}

/// A stream of decoded gRPC messages (raw payloads, compressed flag
/// stripped).
pub struct MessageStream {
    /// Remaining body bytes.
    buf: Vec<u8>,
    /// grpc-status extracted from trailers (fallback: headers).
    trailers: Arc<Mutex<Option<HeaderMap>>>,
    /// The response head headers (fallback for grpc-status).
    head_headers: HeaderMap,
}

impl MessageStream {
    fn new(resp: crate::client::h2::H2Response) -> Result<Self> {
        // Verify the content type.
        let ct = resp
            .head
            .headers
            .get("content-type")
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");
        if !ct.starts_with(CONTENT_TYPE) {
            return Err(Error::grpc(
                status::INTERNAL,
                format!("unexpected content-type: {ct}"),
            ));
        }
        let buf = resp.body.collect()?;
        Ok(Self {
            buf: buf.to_vec(),
            trailers: resp.trailers,
            head_headers: resp.head.headers,
        })
    }

    /// Pull the next raw message payload.
    pub fn next_message(&mut self) -> Result<Option<Bytes>> {
        if self.buf.is_empty() {
            // No more bytes: verify grpc-status.
            self.finish()?;
            return Ok(None);
        }
        let (compressed, len) = read_frame_header(&self.buf)?;
        let header_len = 5;
        if self.buf.len() < header_len + len {
            return Err(Error::protocol("truncated gRPC message"));
        }
        let payload = &self.buf[header_len..header_len + len];
        let out = if compressed {
            return Err(Error::grpc(
                status::UNIMPLEMENTED,
                "compressed gRPC messages not supported (identity only)",
            ));
        } else {
            Bytes::from(payload)
        };
        self.buf.drain(..header_len + len);
        Ok(Some(out))
    }

    fn finish(&self) -> Result<()> {
        let code = self
            .trailers
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|t| t.get("grpc-status"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u32>().ok())
            .or_else(|| {
                self.head_headers
                    .get("grpc-status")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u32>().ok())
            })
            .unwrap_or(status::OK);
        if code != status::OK {
            let msg = self
                .trailers
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|t| t.get("grpc-message"))
                .or_else(|| self.head_headers.get("grpc-message"))
                .map(|v| percent_decode(v.to_str().unwrap_or("")))
                .unwrap_or_default();
            return Err(Error::grpc(code, msg));
        }
        Ok(())
    }
}

/// Read the 5-byte gRPC frame header.
fn read_frame_header(buf: &[u8]) -> Result<(bool, usize)> {
    if buf.len() < 5 {
        return Err(Error::protocol("truncated gRPC frame header"));
    }
    let compressed = buf[0] != 0;
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(Error::overflow("gRPC message too large"));
    }
    Ok((compressed, len))
}

/// Wrap a payload in a gRPC frame (uncompressed).
pub fn frame_message(payload: &[u8], compressed: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(if compressed { 1 } else { 0 });
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Simple percent-decoding for grpc-message (gRPC encodes non-ASCII as
/// percent-escaped UTF-8).
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 1 && i + 2 < b.len() {
            let hex = &b[i + 1..i + 3];
            if let Ok(Ok(v)) = std::str::from_utf8(hex).map(|h| u8::from_str_radix(h, 16)) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A gRPC service handler: maps `(method, raw request)` to a raw
/// response or a status error.
pub trait Service: Send + Sync + 'static {
    /// Serve one unary call. `method` is `package.Service/Method`.
    fn call(&self, method: &str, req: Bytes) -> Result<Bytes>;
}

impl<F> Service for F
where
    F: Fn(&str, Bytes) -> Result<Bytes> + Send + Sync + 'static,
{
    fn call(&self, method: &str, req: Bytes) -> Result<Bytes> {
        self(method, req)
    }
}

/// A gRPC server built on the HTTP server.
pub struct GrpcServer {
    server: Server,
    service: Arc<dyn Service>,
}

impl GrpcServer {
    /// Bind a gRPC server on `addr`.
    pub fn bind(
        addr: impl std::net::ToSocketAddrs,
        service: impl Service,
    ) -> std::io::Result<Self> {
        let cfg = ServerConfig {
            http2: true,
            ..Default::default()
        };
        let server = Server::bind_with_config(addr, cfg)?;
        Ok(Self {
            server,
            service: Arc::new(service),
        })
    }

    /// The bound address.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.server.local_addr()
    }

    /// Serve forever (blocking).
    pub fn serve(self) -> std::io::Result<()> {
        let service = self.service;
        let server = self.server;
        server.serve_with_config(GrpcHandler { service })
    }

    /// Serve in the background.
    pub fn serve_background(self) -> std::io::Result<crate::server::ServerHandle> {
        let service = self.service;
        let server = self.server;
        server.serve_background(GrpcHandler { service })
    }
}

struct GrpcHandler {
    service: Arc<dyn Service>,
}

impl Handler for GrpcHandler {
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        // The request path is the method (we POST to /pkg.Svc/Method).
        let method = req.uri.as_str().to_string();
        let is_grpc = req
            .headers
            .get("content-type")
            .map(|v| v.to_str().unwrap_or("").starts_with(CONTENT_TYPE))
            .unwrap_or(false);
        if !is_grpc {
            let mut resp = Response::<Body>::with_status(415.into());
            resp.headers.insert(
                HeaderName::from_lowercase("content-type"),
                HeaderValue::from_static("text/plain"),
            );
            resp.body = Body::Bytes(Bytes::from_static(b"content-type must be application/grpc"));
            return resp;
        }
        // Decode the request message.
        let raw = match req.body.collect() {
            Ok(b) => b.to_vec(),
            Err(e) => return grpc_error_response(status::INTERNAL, &e.to_string()),
        };
        let payload = match read_single_message(&raw) {
            Ok(p) => p,
            Err(e) => return grpc_error_response(status::INTERNAL, &e.to_string()),
        };
        match self.service.call(&method, payload) {
            Ok(resp_bytes) => {
                let framed = frame_message(&resp_bytes, false);
                let mut resp = Response::<Body>::with_status(200.into());
                resp.headers.insert(
                    HeaderName::from_lowercase("content-type"),
                    HeaderValue::from_static(CONTENT_TYPE),
                );
                resp.headers.insert(
                    HeaderName::from_lowercase("grpc-encoding"),
                    HeaderValue::from_static("identity"),
                );
                // grpc-status/grpc-message are emitted in the header block
                // (interoperable with both trailer-aware and simple
                // clients).
                resp.headers.insert(
                    HeaderName::from_lowercase("grpc-status"),
                    HeaderValue::from_static("0"),
                );
                resp.body = Body::Bytes(Bytes::from(framed));
                resp
            }
            Err(e) => {
                let code = e.grpc_code().unwrap_or(status::INTERNAL);
                grpc_error_response(code, &e.to_string())
            }
        }
    }
}

/// Extract the single request message payload.
fn read_single_message(raw: &[u8]) -> Result<Bytes> {
    let (compressed, len) = read_frame_header(raw)?;
    if compressed {
        return Err(Error::grpc(
            status::UNIMPLEMENTED,
            "compressed requests not supported",
        ));
    }
    if raw.len() < 5 + len {
        return Err(Error::protocol("truncated gRPC request message"));
    }
    Ok(Bytes::from(&raw[5..5 + len]))
}

/// Build a gRPC error response.
pub fn grpc_error_response(code: u32, message: &str) -> Response<Body> {
    let mut resp = Response::<Body>::with_status(200.into());
    resp.headers.insert(
        HeaderName::from_lowercase("content-type"),
        HeaderValue::from_static(CONTENT_TYPE),
    );
    resp.headers.insert(
        HeaderName::from_lowercase("grpc-status"),
        HeaderValue::from_bytes(code.to_string().as_bytes())
            .unwrap_or_else(|_| HeaderValue::from_static("13")),
    );
    resp.headers.insert(
        HeaderName::from_lowercase("grpc-message"),
        HeaderValue::from_bytes(message.as_bytes())
            .unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp.body = Body::Empty;
    resp
}
