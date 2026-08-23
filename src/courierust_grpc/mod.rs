//! gRPC over the HTTP/2 stack.
//!
//! gRPC is HTTP/2 + length-prefixed binary messages + `grpc-status`
//! metadata. This module implements the framing and status handling on
//! top of [`crate::courierust_client::Client`] (h2) and [`crate::courierust_server::Server`],
//! with unary, server-streaming, client-streaming and bidi calls on both
//! the client and the server side.
//!
//! The crate ships a batteries-included, zero-dependency protobuf +
//! gRPC code-generation chain:
//!
//! * [`proto`] — a from-scratch protobuf wire-format codec (varints,
//!   fixed widths, length-delimited, packed repeated fields, ZigZag,
//!   bounded nesting) with no third-party crates.
//! * [`generated`] — build-time codegen: `build.rs` compiles every
//!   `proto/*.proto` file into type-safe, IDE-friendly Rust structs and
//!   wire codecs (implementing [`codec::EncodeMessage`] /
//!   [`codec::DecodeMessage`]) plus typed gRPC client stubs. The
//!   canonical `proto/helloworld.proto` is shipped and exposed as
//!   `generated::helloworld`. Add your own `.proto` files and they are
//!   generated automatically.
//!
//! Existing users can of course implement the codec traits themselves or
//! wrap an external codec (e.g. prost) — the traits are the seam.
//!
//! Capabilities:
//!
//! * **Call shapes** — unary, server-streaming, client-streaming, bidi.
//! * **Deadlines** — `grpc-timeout` is sent by the client and enforced
//!   server-side (a malformed value is `INVALID_ARGUMENT`, an expired
//!   deadline is `DEADLINE_EXCEEDED`).
//! * **Metadata & interceptors** — arbitrary metadata plus a
//!   [`Interceptor`] hook on the client.
//! * **Load balancing** — `dns:///` targets round-robin over resolved
//!   addresses.
//! * **Health** — `grpc.health.v1.Health` with `Check` (unary) and
//!   `Watch` (server-streaming); no reflection.
//! * **Message size** — the maximum accepted gRPC message size is
//!   configurable and enforced on both ends:
//!   [`DEFAULT_MAX_MESSAGE_SIZE`] (4 MiB, the gRPC default) via
//!   [`GrpcClientConfig::max_message_size`] and
//!   [`GrpcServer::max_message_size`]. Messages larger than the limit
//!   are rejected with an overflow error rather than buffered.
//! * **Compression** — `gzip` and `identity` message compression with
//!   full negotiation (gRPC A6): the client can compress requests via
//!   [`GrpcClientConfig::compress`]; the server compresses responses
//!   when the client's `grpc-accept-encoding` includes `gzip`. The gzip
//!   codec is implemented from scratch (`compress` module) — decompression
//!   handles any standard producer's DEFLATE (stored/fixed/dynamic),
//!   and the decompressed size is bounded by `max_message_size` on both
//!   ends, so a compressed bomb cannot bypass the size limit.
//!
//! Honest scope: the 4 MiB default is a hard per-message ceiling — set
//! it explicitly (see above) for larger payloads.

pub mod codec;
pub mod compress;
pub mod generated;
pub mod health;
pub mod proto;
pub mod status;

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_client::Client;
use crate::courierust_error::{Error, Result};
use crate::courierust_h2::priority::Priority;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::uri::PathAndQuery;
use crate::courierust_server::{Handler, Server, ServerConfig};
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Content type marker for gRPC requests/responses.
pub const CONTENT_TYPE: &str = "application/grpc";
/// The `te` header value gRPC requires.
pub const TE_VALUE: &str = "trailers";
/// Default maximum gRPC message size (4 MiB, the gRPC default).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------
// Deadline / interceptor helpers
// ---------------------------------------------------------------------

/// Format a duration as a `grpc-timeout` value (gRPC A6: `1H`, `1M`,
/// `1S`, `100m`, `100u`, `100n`). The coarsest unit with an integer
/// count is used.
pub fn grpc_timeout(d: Duration) -> String {
    if d.is_zero() {
        return "1n".to_string();
    }
    let nanos = d.as_nanos();
    let hours = d.as_secs() / 3600;
    if hours > 0 {
        return format!("{hours}H");
    }
    let mins = d.as_secs() / 60;
    if mins > 0 {
        return format!("{mins}M");
    }
    let secs = d.as_secs();
    if secs > 0 {
        return format!("{secs}S");
    }
    let millis = nanos / 1_000_000;
    if millis > 0 {
        return format!("{millis}m");
    }
    let micros = nanos / 1_000;
    if micros > 0 {
        return format!("{micros}u");
    }
    format!("{nanos}n")
}

/// A request interceptor: a hook that can inspect / mutate outgoing
/// metadata before a call is issued (auth tokens, tracing headers, ...).
pub trait Interceptor: Send + Sync + 'static {
    /// Called before issuing a call. `method` is `package.Service/Method`;
    /// `headers` may be mutated freely.
    fn intercept(&self, method: &str, headers: &mut HeaderMap);
}

impl<F> Interceptor for F
where
    F: Fn(&str, &mut HeaderMap) + Send + Sync + 'static,
{
    fn intercept(&self, method: &str, headers: &mut HeaderMap) {
        self(method, headers)
    }
}

// ---------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------

/// gRPC client configuration.
pub struct GrpcClientConfig {
    /// Base URL: `http://host:port`, `https://host:port`, or
    /// `dns:///host:port` (round-robin across all resolved addresses).
    pub base: String,
    /// Maximum accepted gRPC message size (framing rejects larger).
    pub max_message_size: usize,
    /// Optional request interceptor applied to every call.
    pub interceptor: Option<Arc<dyn Interceptor>>,
    /// Optional default `grpc-timeout` applied to every call.
    pub timeout: Option<Duration>,
    /// When true, request messages are gzip-compressed and
    /// `grpc-encoding: gzip` is negotiated (server-side decompression is
    /// always accepted via `grpc-accept-encoding: gzip, identity`).
    pub compress: bool,
    /// The HTTP/2 client to drive the transport (set this to provide TLS
    /// settings for `https://` targets).
    pub http_client: Client,
}

/// gRPC client.
#[derive(Clone)]
pub struct GrpcClient {
    /// The underlying HTTP/2 client.
    pub client: Client,
    /// Base URL (scheme://host:port) used when not round-robining.
    base: String,
    /// Resolved round-robin endpoints (for `dns:///` targets).
    addrs: Arc<Vec<String>>,
    /// Round-robin cursor.
    cursor: Arc<AtomicUsize>,
    /// Maximum accepted gRPC message size.
    max_message_size: usize,
    /// Whether request messages are gzip-compressed.
    compress: bool,
    /// Optional request interceptor.
    interceptor: Option<Arc<dyn Interceptor>>,
    /// Optional default grpc-timeout.
    timeout: Option<Duration>,
}

impl GrpcClient {
    /// Connect to a gRPC endpoint (h2c prior knowledge).
    pub fn new(base: &str) -> Result<Self> {
        Self::with_config(GrpcClientConfig {
            base: base.to_string(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            interceptor: None,
            timeout: None,
            compress: false,
            http_client: Client::with_config(crate::courierust_client::ClientConfig {
                http2: true,
                user_agent: None,
                ..Default::default()
            }),
        })
    }

    /// Connect with a custom HTTP/2 client (e.g. one with TLS settings
    /// for `https://` targets).
    pub fn new_with_client(base: &str, client: Client) -> Result<Self> {
        Self::with_config(GrpcClientConfig {
            base: base.to_string(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            interceptor: None,
            timeout: None,
            compress: false,
            http_client: client,
        })
    }

    /// Build a client from a full configuration.
    pub fn with_config(config: GrpcClientConfig) -> Result<Self> {
        let base = config.base.trim_end_matches('/').to_string();
        let (base, addrs) = if let Some(a) = resolve_dns(&base)? {
            (String::new(), Arc::new(a))
        } else {
            (base, Arc::new(Vec::new()))
        };
        Ok(Self {
            client: config.http_client,
            base,
            addrs,
            cursor: Arc::new(AtomicUsize::new(0)),
            max_message_size: config.max_message_size,
            compress: config.compress,
            interceptor: config.interceptor,
            timeout: config.timeout,
        })
    }

    /// The configured maximum message size.
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// The effective base URL for the next call (round-robins over
    /// resolved addresses for `dns:///` targets).
    fn effective_base(&self) -> String {
        if self.addrs.is_empty() {
            self.base.clone()
        } else {
            let i = self.cursor.fetch_add(1, Ordering::Relaxed) % self.addrs.len();
            format!("http://{}", self.addrs[i])
        }
    }

    /// Perform a unary call with raw bytes. `method` is
    /// `package.Service/Method`.
    pub fn call(&self, method: &str, req: Bytes) -> Result<Bytes> {
        let mut stream = self.call_with_metadata(method, req, &HeaderMap::new())?;
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

    /// Perform a unary call with custom metadata.
    pub fn call_with_metadata(
        &self,
        method: &str,
        req: Bytes,
        metadata: &HeaderMap,
    ) -> Result<MessageStream> {
        let msg = frame_outbound(req, self.compress, self.max_message_size)?;
        let request = self.build_request(method, metadata, Body::Bytes(Bytes::from(msg)))?;
        let url = crate::courierust_http::uri::Url::parse(&format!(
            "{}{}",
            self.effective_base(),
            method
        ))?;
        let resp = self
            .client
            .execute_h2_raw(&url, request, Priority::default())?;
        MessageStream::new(resp, self.max_message_size)
    }

    /// Start a server-streaming call (one request, many responses).
    pub fn call_stream(&self, method: &str, req: Bytes) -> Result<MessageStream> {
        self.call_with_metadata(method, req, &HeaderMap::new())
    }

    /// Client-streaming call: send many request messages, receive one
    /// response. `reqs` yields the raw request messages; the call ends
    /// when the channel closes.
    pub fn client_stream(
        &self,
        method: &str,
        reqs: std::sync::mpsc::Receiver<Result<Bytes>>,
    ) -> Result<Bytes> {
        let mut stream = self.bidi_stream(method, reqs)?;
        match stream.next_message()? {
            Some(msg) => Ok(msg),
            None => Err(Error::grpc(
                status::INTERNAL,
                "empty response from client-streaming call",
            )),
        }
    }

    /// Bidi streaming call: send many request messages, receive a stream
    /// of responses.
    pub fn bidi_stream(
        &self,
        method: &str,
        reqs: std::sync::mpsc::Receiver<Result<Bytes>>,
    ) -> Result<MessageStream> {
        // Frame each raw message and stream the frames as the request
        // body (h2 DATA frames, so the peer receives them incrementally).
        let body = frame_stream(reqs, self.max_message_size, self.compress)?;
        let request = self.build_request(method, &HeaderMap::new(), body)?;
        let url = crate::courierust_http::uri::Url::parse(&format!(
            "{}{}",
            self.effective_base(),
            method
        ))?;
        let resp = self
            .client
            .execute_h2_stream(&url, request, Priority::default())?;
        MessageStream::new(resp, self.max_message_size)
    }

    /// Build a gRPC request with standard headers + metadata + timeout,
    /// applying the interceptor.
    fn build_request(
        &self,
        method: &str,
        metadata: &HeaderMap,
        body: Body,
    ) -> Result<Request<Body>> {
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
            HeaderName::from_lowercase("grpc-encoding"),
            if self.compress {
                HeaderValue::from_static("gzip")
            } else {
                HeaderValue::from_static("identity")
            },
        );
        request.headers.insert(
            HeaderName::from_lowercase("grpc-accept-encoding"),
            HeaderValue::from_static("gzip, identity"),
        );
        if let Some(t) = self.timeout {
            let v = grpc_timeout(t);
            request.headers.insert(
                HeaderName::from_lowercase("grpc-timeout"),
                HeaderValue::from_bytes(v.as_bytes())?,
            );
        }
        for (n, v) in metadata.iter() {
            request.headers.append(n.clone(), v.clone());
        }
        if let Some(interceptor) = &self.interceptor {
            interceptor.intercept(method, &mut request.headers);
        }
        request.body = body;
        Ok(request)
    }
}

/// Resolve a `dns:///host:port` target into concrete addresses.
/// Returns `Ok(None)` for non-dns schemes.
fn resolve_dns(base: &str) -> Result<Option<Vec<String>>> {
    let rest = base
        .strip_prefix("dns:///")
        .or_else(|| base.strip_prefix("dns://"))
        .map(|s| s.trim_start_matches('/'));
    let Some(rest) = rest else {
        return Ok(None);
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| Error::grpc(status::INVALID_ARGUMENT, "invalid dns:/// port"))?,
        ),
        None => (rest.to_string(), 80u16),
    };
    let mut seen = std::collections::HashSet::new();
    let mut addrs = Vec::new();
    for a in (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| Error::grpc(status::UNAVAILABLE, format!("dns resolve: {e}")))?
    {
        if seen.insert(a) {
            addrs.push(a.to_string());
        }
    }
    if addrs.is_empty() {
        return Err(Error::grpc(
            status::UNAVAILABLE,
            format!("no addresses for {rest}"),
        ));
    }
    Ok(Some(addrs))
}

// ---------------------------------------------------------------------
// Response stream
// ---------------------------------------------------------------------

/// A stream of decoded gRPC messages (raw payloads, compressed flag
/// stripped).
pub struct MessageStream {
    /// The (possibly still streaming) response body.
    body: Body,
    /// Bytes received but not yet consumed as a complete message.
    buf: Vec<u8>,
    /// Whether the body has been fully drained (channel closed / no more
    /// bytes). Remaining buffered bytes are then either complete frames
    /// or a truncated final frame.
    done: bool,
    /// grpc-status extracted from trailers (fallback: headers).
    trailers: Arc<Mutex<Option<HeaderMap>>>,
    /// The response head headers (fallback for grpc-status).
    head_headers: HeaderMap,
    /// Maximum accepted message size.
    max_message_size: usize,
}

impl MessageStream {
    fn new(
        resp: crate::courierust_client::h2::H2Response,
        max_message_size: usize,
    ) -> Result<Self> {
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
        Ok(Self {
            body: resp.body,
            buf: Vec::new(),
            done: false,
            trailers: resp.trailers,
            head_headers: resp.head.headers,
            max_message_size,
        })
    }

    /// Response headers (initial metadata) sent by the peer.
    pub fn response_headers(&self) -> &HeaderMap {
        &self.head_headers
    }

    /// Response trailers (populated once the body ends).
    pub fn trailers(&self) -> Option<HeaderMap> {
        self.trailers.lock().unwrap().clone()
    }

    /// Pull the next raw message payload, blocking until it is available
    /// (or the stream ends). Returns `None` when the stream is exhausted
    /// and `grpc-status` is verified.
    pub fn next_message(&mut self) -> Result<Option<Bytes>> {
        loop {
            // A complete frame already buffered?
            if self.buf.len() >= 5 {
                let (compressed, len) = read_frame_header(&self.buf, self.max_message_size)?;
                if self.buf.len() >= 5 + len {
                    let payload = self.buf[5..5 + len].to_vec();
                    self.buf.drain(..5 + len);
                    return self.decode_payload(compressed, payload);
                }
            }
            if self.done {
                // Body fully consumed: leftover bytes are a truncated
                // final frame.
                if !self.buf.is_empty() {
                    return Err(Error::protocol("truncated gRPC message"));
                }
                self.finish()?;
                return Ok(None);
            }
            // Refill from the body (blocking).
            match &self.body {
                Body::Channel(rx) => match rx.recv() {
                    Ok(Ok(chunk)) => self.buf.extend_from_slice(&chunk),
                    Ok(Err(e)) => return Err(e),
                    Err(_) => self.done = true,
                },
                Body::Empty => self.done = true,
                Body::Bytes(b) => {
                    self.buf.extend_from_slice(b);
                    self.body = Body::Empty;
                    self.done = true;
                }
            }
        }
    }

    /// Decode one message payload, honoring the compressed flag (gzip,
    /// per-message streams). The decompressed size is bounded by
    /// `max_message_size` (a compression bomb is rejected).
    fn decode_payload(&self, compressed: bool, payload: Vec<u8>) -> Result<Option<Bytes>> {
        if compressed {
            let raw = compress::gunzip(&payload, self.max_message_size)?;
            return Ok(Some(Bytes::from(raw)));
        }
        Ok(Some(Bytes::from(payload)))
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
fn read_frame_header(buf: &[u8], max: usize) -> Result<(bool, usize)> {
    if buf.len() < 5 {
        return Err(Error::protocol("truncated gRPC frame header"));
    }
    let compressed = buf[0] != 0;
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > max {
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

/// Frame a raw outbound message, gzip-compressing it first when
/// requested. Enforces the message-size cap on the *uncompressed* size
/// (compression must not be used to smuggle oversized messages).
fn frame_outbound(msg: Bytes, compress: bool, max_message_size: usize) -> Result<Vec<u8>> {
    if msg.len() > max_message_size {
        return Err(Error::overflow("gRPC message too large"));
    }
    if compress {
        let gz = compress::gzip(&msg);
        Ok(frame_message(&gz, true))
    } else {
        Ok(frame_message(&msg, false))
    }
}

/// Wrap a stream of raw messages into a stream of gRPC frames.
fn frame_stream(
    raw: std::sync::mpsc::Receiver<Result<Bytes>>,
    max_message_size: usize,
    compress: bool,
) -> Result<Body> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("courierust-grpc-frame".into())
        .spawn(move || {
            while let Ok(msg) = raw.recv() {
                let frame = match msg {
                    Ok(m) => frame_outbound(m, compress, max_message_size),
                    Err(e) => Err(e),
                };
                if tx.send(frame.map(Bytes::from)).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| Error::io(e.to_string()))?;
    Ok(Body::Channel(rx))
}

/// Simple percent-decoding for grpc-message (gRPC encodes non-ASCII as
/// percent-escaped UTF-8).
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
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

// ---------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------

/// A unary gRPC service handler.
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

/// A streaming gRPC service handler (server-streaming, client-streaming
/// and bidi calls).
pub trait StreamingService: Send + Sync + 'static {
    /// Serve one call. `method` is `package.Service/Method`; `reqs`
    /// yields the decoded request messages (one for unary /
    /// server-streaming calls); send zero or more response messages to
    /// `tx`. Return `Ok(())` for `grpc-status OK`, or an error with a
    /// gRPC code for a non-OK status.
    fn serve(
        &self,
        method: &str,
        reqs: &mut dyn Iterator<Item = Result<Bytes>>,
        tx: &crate::courierust_body::BodySender,
    ) -> Result<()>;
}

impl<F> StreamingService for F
where
    F: Fn(
            &str,
            &mut dyn Iterator<Item = Result<Bytes>>,
            &crate::courierust_body::BodySender,
        ) -> Result<()>
        + Send
        + Sync
        + 'static,
{
    fn serve(
        &self,
        method: &str,
        reqs: &mut dyn Iterator<Item = Result<Bytes>>,
        tx: &crate::courierust_body::BodySender,
    ) -> Result<()> {
        self(method, reqs, tx)
    }
}

/// A gRPC server built on the HTTP server.
pub struct GrpcServer {
    server: Server,
    service: Arc<dyn StreamingService>,
    max_message_size: usize,
}

impl GrpcServer {
    /// Bind a gRPC server with a unary service.
    pub fn bind(
        addr: impl std::net::ToSocketAddrs,
        service: impl Service,
    ) -> std::io::Result<Self> {
        Self::bind_streaming(addr, UnaryAdapter(Arc::new(service)))
    }

    /// Bind a gRPC server with a streaming service.
    pub fn bind_streaming(
        addr: impl std::net::ToSocketAddrs,
        service: impl StreamingService,
    ) -> std::io::Result<Self> {
        Self::bind_streaming_with_config(addr, service, ServerConfig::default())
    }

    /// Bind a gRPC server with a streaming service over a custom HTTP
    /// server configuration (worker-pool size, timeouts, TLS, ...).
    pub fn bind_streaming_with_config(
        addr: impl std::net::ToSocketAddrs,
        service: impl StreamingService,
        http_cfg: ServerConfig,
    ) -> std::io::Result<Self> {
        let cfg = ServerConfig {
            http2: true,
            ..http_cfg
        };
        let server = Server::bind_with_config(addr, cfg)?;
        Ok(Self {
            server,
            service: Arc::new(service),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        })
    }

    /// The bound address.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.server.local_addr()
    }

    /// Set the maximum accepted gRPC message size.
    pub fn max_message_size(mut self, n: usize) -> Self {
        self.max_message_size = n.max(1);
        self
    }

    /// Serve forever (blocking).
    pub fn serve(self) -> std::io::Result<()> {
        let service = self.service;
        let server = self.server;
        let max = self.max_message_size;
        server.serve_with_config(GrpcHandler {
            service,
            max_message_size: max,
        })
    }

    /// Serve in the background.
    pub fn serve_background(self) -> std::io::Result<crate::courierust_server::ServerHandle> {
        let service = self.service;
        let server = self.server;
        let max = self.max_message_size;
        server.serve_background(GrpcHandler {
            service,
            max_message_size: max,
        })
    }
}

/// Adapt a unary service to the streaming dispatch (used by
/// [`GrpcServer::bind`]).
pub fn unary(service: impl Service) -> impl StreamingService {
    UnaryAdapter(Arc::new(service))
}

/// Adapt a unary service to the streaming dispatch.
struct UnaryAdapter(Arc<dyn Service>);

impl StreamingService for UnaryAdapter {
    fn serve(
        &self,
        method: &str,
        reqs: &mut dyn Iterator<Item = Result<Bytes>>,
        tx: &crate::courierust_body::BodySender,
    ) -> Result<()> {
        let req = reqs.next().transpose()?.unwrap_or_default();
        let resp = self.0.call(method, req)?;
        // Raw message; the handler's framing thread adds the gRPC frame.
        tx.send(resp)?;
        Ok(())
    }
}

/// Decode a buffer of gRPC frames into request messages.
fn decode_messages(raw: &[u8], max: usize) -> Result<Vec<Result<Bytes>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        let (compressed, len) = read_frame_header(&raw[pos..], max)?;
        let start = pos + 5;
        if raw.len() < start + len {
            return Err(Error::protocol("truncated gRPC request message"));
        }
        let payload = &raw[start..start + len];
        if compressed {
            let plain = compress::gunzip(payload, max)?;
            out.push(Ok(Bytes::from(plain)));
        } else {
            out.push(Ok(Bytes::from(payload)));
        }
        pos = start + len;
    }
    Ok(out)
}

struct GrpcHandler {
    service: Arc<dyn StreamingService>,
    max_message_size: usize,
}

/// A parsed gRPC call deadline (`grpc-timeout`, gRPC A6). `None` means no
/// deadline was set by the client.
struct Deadline(Option<std::time::Instant>);

impl Deadline {
    /// Parse the `grpc-timeout` header. A malformed value is
    /// `INVALID_ARGUMENT`; a value of `0` units is treated as an
    /// already-expired deadline.
    fn parse(headers: &HeaderMap) -> Result<Self> {
        let Some(v) = headers.get("grpc-timeout") else {
            return Ok(Self(None));
        };
        let s = v
            .to_str()
            .map_err(|_| Error::grpc(status::INVALID_ARGUMENT, "malformed grpc-timeout value"))?;
        if s.len() < 2 {
            return Err(Error::grpc(
                status::INVALID_ARGUMENT,
                "grpc-timeout must be a value plus a unit",
            ));
        }
        let (num, unit) = s.split_at(s.len() - 1);
        let n: u64 = num
            .parse()
            .map_err(|_| Error::grpc(status::INVALID_ARGUMENT, "bad grpc-timeout value"))?;
        if n > 99_999_999 {
            return Err(Error::grpc(
                status::INVALID_ARGUMENT,
                "grpc-timeout value too large",
            ));
        }
        let dur = match unit {
            "H" => Duration::from_secs(n),
            "M" => Duration::from_secs(n.saturating_mul(60)),
            "S" => Duration::from_secs(n),
            "m" => Duration::from_millis(n),
            "u" => Duration::from_micros(n),
            "n" => Duration::from_nanos(n),
            _ => {
                return Err(Error::grpc(
                    status::INVALID_ARGUMENT,
                    "bad grpc-timeout unit",
                ));
            }
        };
        Ok(Self(Some(std::time::Instant::now() + dur)))
    }

    /// Whether the deadline has already passed.
    fn expired(&self) -> bool {
        match self.0 {
            Some(d) => std::time::Instant::now() >= d,
            None => false,
        }
    }
}

/// A request-message iterator that yields `DEADLINE_EXCEEDED` once the
/// call deadline has passed (enforced between message polls, so
/// client-streaming / bidi loops observe it naturally).
struct DeadlineIter<'a, I> {
    inner: I,
    deadline: &'a Deadline,
}

impl<'a, I: Iterator<Item = Result<Bytes>>> Iterator for DeadlineIter<'a, I> {
    type Item = Result<Bytes>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.deadline.expired() {
            return Some(Err(Error::grpc(
                status::DEADLINE_EXCEEDED,
                "deadline exceeded",
            )));
        }
        self.inner.next()
    }
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

        // Deadline enforcement (gRPC A6): parse grpc-timeout. A malformed
        // value is INVALID_ARGUMENT; an already-expired deadline is
        // DEADLINE_EXCEEDED before any work is dispatched.
        let deadline = match Deadline::parse(&req.headers) {
            Ok(d) => d,
            Err(e) => {
                return grpc_error_response(
                    e.grpc_code().unwrap_or(status::INTERNAL),
                    &e.to_string(),
                );
            }
        };
        if deadline.expired() {
            return grpc_error_response(status::DEADLINE_EXCEEDED, "deadline exceeded");
        }

        // Compression negotiation (gRPC A6): compress responses with gzip
        // only when the client declared it can accept it.
        let accept_gzip = req
            .headers
            .get("grpc-accept-encoding")
            .map(|v| v.to_str().unwrap_or(""))
            .map(|v| {
                v.to_ascii_lowercase()
                    .split(',')
                    .any(|c| c.trim() == "gzip")
            })
            .unwrap_or(false);

        // Decode all request messages from the buffered body.
        let raw = match req.body.collect() {
            Ok(b) => b.to_vec(),
            Err(e) => return grpc_error_response(status::INTERNAL, &e.to_string()),
        };
        let messages = match decode_messages(&raw, self.max_message_size) {
            Ok(m) => m,
            Err(e) => {
                return grpc_error_response(
                    e.grpc_code().unwrap_or(status::INTERNAL),
                    &e.to_string(),
                )
            }
        };

        // The service runs on its own thread so that a server-streaming
        // call (which may never return, e.g. health `Watch`) does not
        // block the connection's worker. The service sends *raw* messages
        // to `msg_tx`; a framing thread wraps each in a gRPC frame and
        // forwards it to the response body channel, so messages stream to
        // the peer incrementally.
        //
        // `handle()` returns as soon as the call either (a) produced its
        // first response message (a streaming call: the response head is
        // decided then and `grpc-status` rides in the trailing block) or
        // (b) finished without producing a message (a finite call: its
        // final status is known and reported exactly, including error
        // codes). Fast-fail conditions above are still reported before
        // any of this.
        let (msg_tx, msg_rx) = std::sync::mpsc::channel();
        let msg_sender = crate::courierust_body::BodySender::from_sender(msg_tx);
        let (body_tx, body) = crate::courierust_body::channel();
        let max = self.max_message_size;
        // Signals `Started` on the first forwarded message. Both threads
        // drop their clones on exit, so `recv()` disconnecting means the
        // call completed without streaming.
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        // Carries the service's final outcome for finite calls.
        let (result_tx, result_rx) =
            std::sync::mpsc::channel::<std::result::Result<(), (u32, String)>>();

        let started_tx2 = started_tx.clone();
        let _ = std::thread::Builder::new()
            .name("courierust-grpc-frame".into())
            .spawn(move || {
                let mut first = true;
                while let Ok(m) = msg_rx.recv() {
                    if first {
                        let _ = started_tx2.send(());
                        first = false;
                    }
                    let frame = match m {
                        Ok(raw) => frame_outbound(raw, accept_gzip, max),
                        Err(e) => Err(e),
                    };
                    if body_tx.send_result(frame.map(Bytes::from)).is_err() {
                        break;
                    }
                }
            });

        let service = self.service.clone();
        let method2 = method.clone();
        // The original `started_tx` is moved into the serve thread: it is
        // dropped only when that thread ends, so `started_rx` disconnects
        // exactly when the call finishes (used to distinguish a finite
        // call with no messages from a streaming one).
        let started_tx3 = started_tx;
        // `deadline` is moved into the serve closure; snapshot the
        // instant first so `handle()` can still wait with a timeout.
        let deadline_instant = deadline.0;
        let _ = std::thread::Builder::new()
            .name("courierust-grpc-serve".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut iter = DeadlineIter {
                        inner: messages.into_iter(),
                        deadline: &deadline,
                    };
                    let r = service.serve(&method2, &mut iter, &msg_sender);
                    r.map_err(|e| (e.grpc_code().unwrap_or(status::INTERNAL), e.to_string()))
                }));
                let mapped = match outcome {
                    Ok(r) => r,
                    Err(_) => Err((status::INTERNAL, "service handler panicked".to_string())),
                };
                let _ = result_tx.send(mapped);
                // Dropping `started_tx3` (and, on the way out, the
                // framing thread's clone once the message channel closes)
                // lets `handle()` see the call finished.
                drop(started_tx3);
            });

        let wait = match deadline_instant {
            Some(d) => {
                let now = std::time::Instant::now();
                if d <= now {
                    return grpc_error_response(status::DEADLINE_EXCEEDED, "deadline exceeded");
                }
                match started_rx.recv_timeout(d - now) {
                    Ok(()) => WaitOutcome::Started,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        WaitOutcome::DeadlineExceeded
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => WaitOutcome::Finished,
                }
            }
            None => {
                if started_rx.recv().is_ok() {
                    WaitOutcome::Started
                } else {
                    WaitOutcome::Finished
                }
            }
        };

        // A response carrying `grpc-status: 0` in the trailing block.
        let streaming_response = |body: Body| {
            let mut resp = Response::<Body>::with_status(200.into());
            resp.headers.insert(
                HeaderName::from_lowercase("content-type"),
                HeaderValue::from_static(CONTENT_TYPE),
            );
            resp.headers.insert(
                HeaderName::from_lowercase("grpc-encoding"),
                if accept_gzip {
                    HeaderValue::from_static("gzip")
                } else {
                    HeaderValue::from_static("identity")
                },
            );
            let mut tr = HeaderMap::new();
            tr.insert(
                HeaderName::from_lowercase("grpc-status"),
                HeaderValue::from_static("0"),
            );
            resp.trailers = Some(tr);
            resp.body = body;
            resp
        };

        match wait {
            // First message produced: the call is streaming.
            WaitOutcome::Started => streaming_response(body),
            // All senders gone: the call finished without streaming, so
            // its exact outcome is known.
            WaitOutcome::Finished => match result_rx.recv() {
                Ok(Ok(())) => streaming_response(body),
                Ok(Err((code, msg))) => grpc_error_response(code, &msg),
                Err(_) => grpc_error_response(status::INTERNAL, "service thread exited"),
            },
            WaitOutcome::DeadlineExceeded => {
                grpc_error_response(status::DEADLINE_EXCEEDED, "deadline exceeded")
            }
        }
    }
}

/// The outcome of waiting for a gRPC call to either stream its first
/// message or complete.
#[derive(Debug)]
enum WaitOutcome {
    /// The call produced its first response message: it is streaming.
    Started,
    /// The call completed without producing a message; its final status
    /// is available on the result channel.
    Finished,
    /// The call deadline elapsed before the first message.
    DeadlineExceeded,
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
