//! WebSocket client (`ws://` and `wss://`).
//!
//! The client owns the same [`Session`] state machine the server uses,
//! configured for the client role: every frame it sends is masked with a
//! fresh, unpredictable key (RFC 6455 §5.3), and every frame it receives
//! must be unmasked.
//!
//! The opening handshake is validated *completely* before a single
//! application byte moves — this is the part of a WebSocket client that
//! mature-looking implementations get wrong, and getting it wrong is
//! enough to talk to the wrong endpoint:
//!
//! * `Sec-WebSocket-Accept` must equal `base64(SHA-1(key || GUID))` for
//!   the key *this* client sent, exactly once.
//! * `Upgrade`/`Connection` must carry the right tokens (token-level
//!   parsing, not substring matching).
//! * A `101` must not carry `Content-Length`/`Transfer-Encoding`: a body
//!   on a protocol switch is a framing ambiguity, and a client that
//!   tolerates it is a desynchronised proxy's best friend.
//! * The `Sec-WebSocket-Protocol` the server selects must be one this
//!   client offered; `Sec-WebSocket-Extensions` parameters must be ones
//!   it offered, with window sizes no larger than requested
//!   ([`PerMessageDeflate::from_response`]).
//!
//! ```no_run
//! # #[cfg(feature = "std")]
//! # fn main() -> courierust::Result<()> {
//! use courierust::courierust_client::ws::WebSocket;
//! use courierust::courierust_client::ClientConfig;
//! use courierust::courierust_ws::Event;
//!
//! let mut ws = WebSocket::connect("ws://127.0.0.1:9001/echo", &ClientConfig::default())?;
//! ws.send_text("hello")?;
//! match ws.read_message()? {
//!     Event::Text(text) => println!("echo: {text}"),
//!     other => panic!("unexpected {other:?}"),
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "std"))]
//! # fn main() {}
//! ```

use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_h1;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::uri::Url;
use crate::courierust_http::version::Version;
use crate::courierust_io::{BufReader, BufWriter, Scratch};
use crate::courierust_net as net;
use crate::courierust_net::ConnStream;
use crate::courierust_ws::frame::SharedSink;
use crate::courierust_ws::handshake::{
    accept_key, generate_key, header_has_token, parse_extensions, PerMessageDeflate,
    PmDeflatePolicy,
};
use crate::courierust_ws::session::{MaskSource, Role, Session, SessionConfig, Stats};
use crate::courierust_ws::writer::FrameWriter;
use crate::courierust_ws::Event;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// The one extension this client offers, in the exact wire form that is
/// sent **and** used to validate the response.
///
/// One constant for both directions is deliberate: a hand-written second
/// copy of "what we offered" is how a client ends up accepting a
/// parameter it never offered (or rejecting one it did).
const PM_DEFLATE_OFFER: &str = "permessage-deflate; client_max_window_bits";

/// Client-side WebSocket options.
#[derive(Debug, Clone)]
pub struct WsClientOptions {
    /// Subprotocols to offer, in preference order.
    pub protocols: Vec<String>,
    /// Offer `permessage-deflate`.
    pub compression: bool,
    /// Fail the handshake when the server does not select one of the
    /// offered subprotocols.
    pub require_subprotocol: bool,
    /// Send an `Origin` header (browsers do this automatically; a native
    /// client usually does not need to).
    pub origin: Option<String>,
    /// Extra request headers (authorization, cookies, tracing ids).
    pub headers: Vec<(String, String)>,
    /// Largest accepted frame payload.
    pub max_frame: usize,
    /// Largest accepted message (after inflating).
    pub max_message: usize,
    /// Read buffer size. Larger values mean fewer read syscalls for large
    /// messages.
    pub read_buffer: usize,
    /// How long to wait for the peer's close echo in [`WebSocket::close`].
    pub close_timeout: Duration,
}

impl Default for WsClientOptions {
    fn default() -> Self {
        Self {
            protocols: Vec::new(),
            compression: true,
            require_subprotocol: false,
            origin: None,
            headers: Vec::new(),
            max_frame: 16 * 1024 * 1024,
            max_message: 16 * 1024 * 1024,
            read_buffer: 64 * 1024,
            close_timeout: Duration::from_secs(5),
        }
    }
}

/// Facts about an established client connection.
#[derive(Debug, Clone)]
pub struct WsClientInfo {
    /// The requested URL.
    pub url: String,
    /// Host as written in the URL (lowercased).
    pub host: String,
    /// TCP port actually connected to.
    pub port: u16,
    /// Remote address of the connection.
    pub peer: SocketAddr,
    /// Whether the connection is TLS.
    pub secure: bool,
    /// The subprotocol the server selected.
    pub protocol: Option<String>,
    /// The negotiated `permessage-deflate` parameters.
    pub compression: Option<PerMessageDeflate>,
}

/// A `Send + Sync` push handle for an established client connection,
/// so another thread can write while the owner thread reads.
#[derive(Clone)]
pub struct WsClientWriter {
    inner: Arc<std::sync::Mutex<FrameWriter<SharedSink<Arc<ConnStream>>>>>,
}

impl WsClientWriter {
    /// Send a text message.
    pub fn send_text(&self, text: &str) -> Result<()> {
        let mut w = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        w.send_text(text)
    }

    /// Send a binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        let mut w = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        w.send_binary(data)
    }

    /// Send a Ping.
    pub fn send_ping(&self, payload: &[u8]) -> Result<()> {
        let mut w = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        w.send_ping(payload)
    }
}

/// A connected WebSocket.
pub struct WebSocket {
    session: Session<Arc<ConnStream>, SharedSink<Arc<ConnStream>>>,
    sink: SharedSink<Arc<ConnStream>>,
    stream: Arc<ConnStream>,
    info: WsClientInfo,
    close_timeout: Duration,
    /// Liveness deadline for the **wait for a frame**.
    ///
    /// `ClientConfig::read_timeout` is deliberately not left armed on the
    /// socket for the life of the connection: on Windows `SO_RCVTIMEO` is
    /// charged on every blocking operation, so a 256 KiB message received
    /// with it armed runs about twice as slow, and every write on the
    /// socket pays it too. It is armed around the wait for a frame header
    /// and cleared while the body streams — the shape the server's
    /// blocking driver already uses. A `Cell` keeps
    /// [`WebSocket::set_read_timeout`] taking `&self`, as it always has.
    read_timeout: std::cell::Cell<Option<Duration>>,
}

impl WebSocket {
    /// Connect with default options.
    pub fn connect(url: &str, cfg: &crate::courierust_client::ClientConfig) -> Result<Self> {
        Self::connect_with(url, cfg, &WsClientOptions::default())
    }

    /// Connect with explicit options.
    pub fn connect_with(
        url: &str,
        cfg: &crate::courierust_client::ClientConfig,
        opts: &WsClientOptions,
    ) -> Result<Self> {
        let (secure, http_url) = normalise_url(url)?;
        let parsed = Url::parse(&http_url)?;
        let host = parsed.host.clone();
        let port = parsed.port;
        let (addr, stream) = connect_to(&host, port, cfg)?;

        let conn = if secure {
            let tls = cfg.tls.as_ref().ok_or_else(|| {
                Error::protocol("ws: a wss:// URL requires ClientConfig::tls to be configured")
            })?;
            net::configure(&stream, cfg.handshake_timeout)?;
            let mut settings = tls.clone();
            settings.alpn = vec![b"http/1.1".to_vec()];
            let connector = crate::courierust_tls::TlsConnector::new(
                crate::courierust_client::connector_config(&settings),
            );
            let conn = ConnStream::tls_client(stream, &connector, &host)?;
            if let Some(alpn) = conn.alpn() {
                if alpn.as_slice() == b"h2" {
                    return Err(Error::protocol(
                        "ws: the server negotiated HTTP/2 via ALPN; WebSocket over HTTP/2 (RFC 8441) is not supported",
                    ));
                }
            }
            conn
        } else {
            net::configure(&stream, cfg.read_timeout)?;
            ConnStream::plain(stream)
        };
        // The handshake read is a deadline: a peer that stops answering
        // must surface as `Timeout`, not as the `WouldBlock` a POSIX poll
        // timeout produces.
        let _ = conn.set_deadline(cfg.read_timeout);
        let stream = Arc::new(conn);

        // ---- handshake ------------------------------------------------
        let key = generate_key()?;
        let mut reader = BufReader::new(stream.clone(), opts.read_buffer.max(16 * 1024));
        let mut writer = BufWriter::new(stream.clone(), 16 * 1024);
        let mut scratch = Scratch::new();

        let mut headers = HeaderMap::with_capacity(8 + opts.protocols.len());
        let host_header = {
            // An IPv6 literal must keep its brackets in `Host` (RFC 3986
            // §3.2.2, RFC 9112 §3.2): `Host: ::1:9001` is not a valid
            // authority, and the peer cannot tell where the port starts.
            let authority = if host.contains(':') {
                alloc::format!("[{host}]")
            } else {
                host.clone()
            };
            if (secure && port == 443) || (!secure && port == 80) {
                authority
            } else {
                alloc::format!("{authority}:{port}")
            }
        };
        push(&mut headers, "host", &host_header)?;
        push(&mut headers, "upgrade", "websocket")?;
        push(&mut headers, "connection", "Upgrade")?;
        push(&mut headers, "sec-websocket-key", &key)?;
        push(&mut headers, "sec-websocket-version", "13")?;
        if !opts.protocols.is_empty() {
            push(
                &mut headers,
                "sec-websocket-protocol",
                &opts.protocols.join(", "),
            )?;
        }
        if opts.compression {
            push(&mut headers, "sec-websocket-extensions", PM_DEFLATE_OFFER)?;
        }
        if let Some(origin) = &opts.origin {
            push(&mut headers, "origin", origin)?;
        }
        for (name, value) in &opts.headers {
            push(&mut headers, name, value)?;
        }
        if !headers.contains_key("user-agent") {
            if let Some(ua) = &cfg.user_agent {
                push(&mut headers, "user-agent", ua)?;
            }
        }
        // A WebSocket handshake is a request from the same client, so the
        // configured defaults travel with it — but never at the expense of
        // a field the handshake itself defines (host, upgrade, connection,
        // sec-websocket-*).
        for (name, value) in cfg.default_headers.iter() {
            if !headers.contains_key(name.as_str()) {
                headers.insert(name.clone(), value.clone());
            }
        }

        let request_head = scratch.body();
        courierust_h1::write_request_head(
            request_head,
            &Method::GET,
            &parsed.path_and_query,
            Version::HTTP_11,
            &headers,
        )?;
        writer.write_all(request_head)?;
        writer.flush()?;

        // ---- response -------------------------------------------------
        let (status, _version, response_headers) = read_response_head(&mut reader, &mut scratch)?;
        validate_response(status, &response_headers, &key)?;

        let protocol = response_headers
            .get("sec-websocket-protocol")
            .map(|v| v.to_str().map(String::from))
            .transpose()?;
        if let Some(p) = &protocol {
            if !opts.protocols.iter().any(|o| o == p) {
                return Err(Error::protocol(
                    "ws: the server selected a subprotocol that was not offered",
                ));
            }
        }
        if opts.require_subprotocol && protocol.is_none() {
            return Err(Error::protocol("ws: the server selected no subprotocol"));
        }

        let mut compression = None;
        if response_headers.get("sec-websocket-extensions").is_some() {
            // Validate against the offer this client actually sent: with
            // compression disabled nothing was offered, so any extension
            // in the response fails the connection (RFC 6455 §4.1).
            let mut offered = if opts.compression {
                crate::courierust_ws::handshake::parse_extension_value(PM_DEFLATE_OFFER)?
            } else {
                Vec::new()
            };
            let offers = parse_extensions(&response_headers)?;
            if offers.len() > 1 {
                return Err(Error::protocol(
                    "ws: the server selected more than one extension",
                ));
            }
            for ext in &offers {
                let offer = offered
                    .iter_mut()
                    .find(|o| o.name == ext.name)
                    .ok_or_else(|| {
                        Error::protocol("ws: the server selected an extension that was not offered")
                    })?;
                compression = Some(PerMessageDeflate::from_response(
                    offer,
                    ext,
                    &PmDeflatePolicy::default(),
                )?);
            }
        }

        let params = compression.map(|p| p.client_view());
        let sink = SharedSink::new(stream.clone());
        let frame_writer = FrameWriter::new(sink.clone(), MaskSource::Random, params);
        let session = Session::new(
            reader,
            frame_writer,
            SessionConfig {
                role: Role::Client,
                max_frame: opts.max_frame,
                max_message: opts.max_message,
                max_fragments: 0,
                compression: params,
                auto_pong: true,
            },
        );
        let _ = writer.flush();
        let _ = stream.configure(None);

        Ok(Self {
            session,
            sink,
            stream,
            info: WsClientInfo {
                url: String::from(url),
                host,
                port,
                peer: addr,
                secure,
                protocol,
                compression,
            },
            close_timeout: opts.close_timeout,
            read_timeout: std::cell::Cell::new(cfg.read_timeout),
        })
    }

    /// Facts about the connection.
    pub fn info(&self) -> &WsClientInfo {
        &self.info
    }

    /// The selected subprotocol.
    pub fn protocol(&self) -> Option<&str> {
        self.info.protocol.as_deref()
    }

    /// The negotiated compression parameters.
    pub fn compression(&self) -> Option<PerMessageDeflate> {
        self.info.compression
    }

    /// Send a text message.
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.session.send_text(text)
    }

    /// Send a binary message.
    pub fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.session.send_binary(data)
    }

    /// Send a Ping.
    pub fn send_ping(&mut self, payload: &[u8]) -> Result<()> {
        self.session.send_ping(payload)
    }

    /// Send a Pong.
    pub fn send_pong(&mut self, payload: &[u8]) -> Result<()> {
        self.session.send_pong(payload)
    }

    /// Block until the next message arrives.
    ///
    /// [`ClientConfig::read_timeout`](super::ClientConfig::read_timeout)
    /// bounds the **wait for a frame** and surfaces as
    /// [`ErrorKind::Timeout`]. It is not left armed while a
    /// message body transfers: `SO_RCVTIMEO` is charged on every blocking
    /// operation on Windows, which roughly doubles the cost of a 256 KiB
    /// receive and taxes every write on the socket. A peer that announces
    /// a frame and then goes silent is still caught, because the wait for
    /// the header is bounded; a peer that stalls *inside* a body is left
    /// to TCP, which is the same posture the crate's blocking server
    /// takes (a body in flight is not an idle connection).
    ///
    /// The deadline is cleared again before returning, so a caller that
    /// echoes (read then write) never pays it on the write half either.
    pub fn read_message(&mut self) -> Result<Event> {
        if !self.session.is_mid_frame() {
            self.arm_read_timeout()?;
        }
        let header = self.session.poll_header();
        let _ = self.stream.configure(None);
        if !header? {
            return Err(Error::new(ErrorKind::WouldBlock));
        }
        self.session.read_message()
    }

    /// Arm the transport for the wait for the next frame header.
    ///
    /// A *deadline* when one is configured, so its expiry is `Timeout` on
    /// every platform: POSIX reports a poll timeout as `WouldBlock`, the
    /// code for "nothing yet", and this wait is not a lull — it is the
    /// bound the caller asked for. With no deadline configured there is
    /// nothing to classify, and the arm is cleared outright.
    fn arm_read_timeout(&self) -> Result<()> {
        match self.read_timeout.get() {
            Some(timeout) => self.stream.set_deadline(Some(timeout)),
            None => self.stream.configure(None),
        }
    }

    /// A non-blocking poll: `Ok(None)` means “nothing complete yet”.
    pub fn poll_message(&mut self) -> Result<Option<Event>> {
        self.session.poll_message()
    }

    /// A push handle usable from another thread while this one reads.
    pub fn writer(&self) -> WsClientWriter {
        WsClientWriter {
            inner: Arc::new(std::sync::Mutex::new(FrameWriter::new(
                self.sink.clone(),
                MaskSource::Random,
                self.session.compression(),
            ))),
        }
    }

    /// Counters for this connection.
    pub fn stats(&self) -> Stats {
        self.session.stats()
    }

    /// Whether the closing handshake has completed.
    pub fn is_closed(&self) -> bool {
        self.session.is_finished()
    }

    /// Start the closing handshake and wait (bounded by
    /// [`WsClientOptions::close_timeout`]) for the peer's echo.
    pub fn close(&mut self, code: u16, reason: &str) -> Result<()> {
        if self.session.close_sent() {
            return Ok(());
        }
        self.session.close(code, reason)?;
        self.session.flush()?;
        let deadline = std::time::Instant::now() + self.close_timeout;
        let _ = self.stream.configure(Some(self.close_timeout));
        loop {
            if std::time::Instant::now() >= deadline {
                return Ok(());
            }
            match self.session.poll_message() {
                Ok(Some(Event::Close(_))) => return Ok(()),
                Ok(Some(_)) => continue,
                Ok(None) => return Ok(()),
                Err(e) => match e.kind {
                    ErrorKind::Timeout | ErrorKind::UnexpectedEof => return Ok(()),
                    _ => return Err(e),
                },
            }
        }
    }

    /// Send a closing frame without waiting for the echo.
    pub fn close_now(&mut self, code: u16, reason: &str) -> Result<()> {
        self.session.close(code, reason)?;
        self.session.flush()
    }

    /// The remote address of the connection.
    pub fn peer_addr(&self) -> SocketAddr {
        self.info.peer
    }

    /// Set the liveness deadline for the wait for a frame.
    ///
    /// [`WebSocket::read_message`] re-scopes it per frame: it arms the
    /// deadline for the wait for a header and clears it while a body
    /// streams, so this bounds how long a wait for *new* data may take,
    /// not the transfer of a body that has already started. Setting it
    /// also applies it to the socket immediately, which is the historical
    /// behaviour and matters to a caller that arms it before its own read.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.read_timeout.set(timeout);
        self.arm_read_timeout()
    }
}

/// Split a `ws://`/`wss://` URL into “is TLS” plus the equivalent
/// `http://`/`https://` URL the shared parser understands.
fn normalise_url(url: &str) -> Result<(bool, String)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::protocol("ws: URL is missing a scheme"))?;
    let scheme = scheme.to_ascii_lowercase();
    match scheme.as_str() {
        "ws" => Ok((false, alloc::format!("http://{rest}"))),
        "wss" => Ok((true, alloc::format!("https://{rest}"))),
        _ => Err(Error::protocol(
            "ws: only ws:// and wss:// URLs are supported",
        )),
    }
}

/// Connect to the first address that accepts.
///
/// A host name that resolves to several addresses (the usual `localhost`
/// case: `::1` and `127.0.0.1`) must not fail just because the first one
/// in the list is not the one the server bound. Each attempt keeps its
/// own connect timeout, and the last failure is reported.
fn connect_to(
    host: &str,
    port: u16,
    cfg: &crate::courierust_client::ClientConfig,
) -> Result<(SocketAddr, std::net::TcpStream)> {
    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| Error::io(alloc::format!("ws: cannot resolve {host}:{port}: {e}")))?
        .collect();
    if addresses.is_empty() {
        return Err(Error::io(alloc::format!(
            "ws: {host}:{port} resolved to no address"
        )));
    }
    let mut last: Option<Error> = None;
    for addr in addresses {
        match net::connect(&addr, cfg.connect_timeout) {
            Ok(stream) => return Ok((addr, stream)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| Error::io("ws: connect failed")))
}

fn push(headers: &mut HeaderMap, name: &str, value: &str) -> Result<()> {
    let name = HeaderName::from_bytes(name.as_bytes())?;
    let value = HeaderValue::from_bytes(value.as_bytes())?;
    headers.append(name, value);
    Ok(())
}

/// The most `1xx` responses a handshake will skip before giving up: a peer
/// that only ever sends informational responses must not be able to stall
/// the client for ever.
const MAX_INFORMATIONAL: usize = 4;

/// Read the response head, skipping up to [`MAX_INFORMATIONAL`] `1xx`
/// responses.
fn read_response_head(
    reader: &mut BufReader<Arc<ConnStream>>,
    scratch: &mut Scratch,
) -> Result<(
    crate::courierust_http::status::StatusCode,
    Version,
    HeaderMap,
)> {
    for _ in 0..=MAX_INFORMATIONAL {
        // The status line borrows the scratch line buffer; it is parsed
        // and released before the header block reuses that buffer.
        let (status, version) = {
            let line = scratch.line();
            reader.read_until_into(b'\n', 16 * 1024, line)?;
            courierust_h1::parse_status_line(line)?
        };
        let headers = courierust_h1::read_headers_scratch(reader, scratch)?;
        if status.is_informational()
            && status != crate::courierust_http::status::StatusCode::SWITCHING_PROTOCOLS
        {
            continue;
        }
        // A protocol switch is an HTTP/1.1 response (RFC 6455 §4.1).
        if version != Version::HTTP_11 {
            return Err(Error::protocol(
                "ws: the peer answered a protocol switch over something other than HTTP/1.1",
            ));
        }
        return Ok((status, version, headers));
    }
    Err(Error::protocol(
        "ws: the peer kept sending informational responses",
    ))
}

/// Everything a `101` must (and must not) contain.
fn validate_response(
    status: crate::courierust_http::status::StatusCode,
    headers: &HeaderMap,
    key: &str,
) -> Result<()> {
    if status != crate::courierust_http::status::StatusCode::SWITCHING_PROTOCOLS {
        return Err(Error::with_message(
            ErrorKind::Protocol,
            alloc::format!("ws: server answered {} instead of 101", status.as_u16()),
        ));
    }
    // A switched protocol has no body framing: tolerating either header
    // here is how a client ends up desynchronised with a proxy.
    for name in ["content-length", "transfer-encoding"] {
        if headers.contains_key(name) {
            return Err(Error::protocol(alloc::format!(
                "ws: 101 response carries {name}"
            )));
        }
    }
    if !header_has_token(headers, "upgrade", "websocket") {
        return Err(Error::protocol(
            "ws: 101 response is missing 'Upgrade: websocket'",
        ));
    }
    if !header_has_token(headers, "connection", "upgrade") {
        return Err(Error::protocol(
            "ws: 101 response is missing the 'upgrade' connection token",
        ));
    }
    let accepts: Vec<&HeaderValue> = headers.get_all("sec-websocket-accept").collect();
    if accepts.len() != 1 {
        return Err(Error::protocol(
            "ws: 101 response must carry exactly one Sec-WebSocket-Accept",
        ));
    }
    let expected = accept_key(key)?;
    let got = accepts[0]
        .to_str()
        .map_err(|_| Error::protocol("ws: non-ASCII Sec-WebSocket-Accept"))?;
    if got.trim() != expected {
        return Err(Error::protocol(
            "ws: Sec-WebSocket-Accept does not match the key we sent",
        ));
    }
    let protocols: Vec<&HeaderValue> = headers.get_all("sec-websocket-protocol").collect();
    if protocols.len() > 1 {
        return Err(Error::protocol(
            "ws: 101 response carries several subprotocols",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(
        status: u16,
        extra: &[(&str, &str)],
    ) -> (crate::courierust_http::status::StatusCode, HeaderMap) {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_lowercase("upgrade"),
            HeaderValue::from_static("websocket"),
        );
        headers.insert(
            HeaderName::from_lowercase("connection"),
            HeaderValue::from_static("Upgrade"),
        );
        headers.insert(
            HeaderName::from_lowercase("sec-websocket-accept"),
            HeaderValue::from_bytes(accept_key("dGhlIHNhbXBsZSBub25jZQ==").unwrap().as_bytes())
                .unwrap(),
        );
        for (n, v) in extra {
            headers.append(
                HeaderName::from_bytes(n.as_bytes()).unwrap(),
                HeaderValue::from_bytes(v.as_bytes()).unwrap(),
            );
        }
        (
            crate::courierust_http::status::StatusCode::from_u16(status),
            headers,
        )
    }

    #[test]
    fn url_scheme_mapping() {
        assert_eq!(
            normalise_url("ws://example.com/chat?x=1").unwrap(),
            (false, String::from("http://example.com/chat?x=1"))
        );
        assert_eq!(
            normalise_url("wss://example.com:8443/chat").unwrap(),
            (true, String::from("https://example.com:8443/chat"))
        );
        assert!(normalise_url("http://example.com").is_err());
        assert!(normalise_url("example.com").is_err());
    }

    #[test]
    fn a_complete_101_validates() {
        let (status, headers) = response(101, &[]);
        assert!(validate_response(status, &headers, "dGhlIHNhbXBsZSBub25jZQ==").is_ok());
    }

    #[test]
    fn wrong_accept_is_rejected() {
        let (status, mut headers) = response(101, &[]);
        headers.insert(
            HeaderName::from_lowercase("sec-websocket-accept"),
            HeaderValue::from_static("c3R1YmJlZCBhY2NlcHQgdmFsdWU="),
        );
        assert!(validate_response(status, &headers, "dGhlIHNhbXBsZSBub25jZQ==").is_err());
    }

    #[test]
    fn a_body_framed_101_is_rejected() {
        let (status, headers) = response(101, &[("content-length", "0")]);
        assert!(validate_response(status, &headers, "dGhlIHNhbXBsZSBub25jZQ==").is_err());
        let (status, headers) = response(101, &[("transfer-encoding", "chunked")]);
        assert!(validate_response(status, &headers, "dGhlIHNhbXBsZSBub25jZQ==").is_err());
    }

    #[test]
    fn missing_upgrade_tokens_are_rejected() {
        let (status, mut headers) = response(101, &[]);
        headers.remove("upgrade");
        assert!(validate_response(status, &headers, "dGhlIHNhbXBsZSBub25jZQ==").is_err());
        let (status, mut headers) = response(101, &[]);
        headers.insert(
            HeaderName::from_lowercase("connection"),
            HeaderValue::from_static("close"),
        );
        assert!(validate_response(status, &headers, "dGhlIHNhbXBsZSBub25jZQ==").is_err());
    }

    #[test]
    fn a_non_101_status_is_rejected_with_its_code() {
        let (status, headers) = response(200, &[]);
        let err = validate_response(status, &headers, "dGhlIHNhbXBsZSBub25jZQ==").unwrap_err();
        assert!(err.to_string().contains("200"), "{err}");
    }

    #[test]
    fn duplicated_accept_headers_are_rejected() {
        let (status, headers) = response(
            101,
            &[(
                "sec-websocket-accept",
                &accept_key("dGhlIHNhbXBsZSBub25jZQ==").unwrap(),
            )],
        );
        assert!(validate_response(status, &headers, "dGhlIHNhbXBsZSBub25jZQ==").is_err());
    }

    /// The offer constant must parse, and must describe exactly what the
    /// response validator is told was offered.
    #[test]
    fn the_offered_extension_matches_the_validator() {
        let offers = crate::courierust_ws::handshake::parse_extension_value(PM_DEFLATE_OFFER)
            .expect("the client's own offer must parse");
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].name, "permessage-deflate");
        assert!(offers[0].has_param("client_max_window_bits"));
        assert_eq!(offers[0].param("client_max_window_bits"), Some(None));
    }
}
