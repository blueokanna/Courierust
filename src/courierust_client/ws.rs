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
//!   client offered, and so must be every `Sec-WebSocket-Extensions`
//!   element — validated against the bytes this client actually sent, not
//!   against a constant ([`PerMessageDeflate::from_response`]).
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
    accept_key, generate_key, header_has_token, is_token, parse_extension_value, parse_extensions,
    ExtensionOffer, PerMessageDeflate, PmDeflatePolicy,
};
use crate::courierust_ws::session::{MaskSource, Role, Session, SessionConfig, Stats};
use crate::courierust_ws::writer::FrameWriter;
use crate::courierust_ws::Event;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// The extension this client drives, in the exact wire form it is
/// offered in.
const PM_DEFLATE_OFFER: &str = "permessage-deflate; client_max_window_bits";

/// How many `1xx` responses may precede the switch before the handshake
/// is abandoned (a peer that never stops sending them must not stall it).
const MAX_INFORMATIONAL: usize = 5;

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
            // Offer only HTTP/1.1: RFC 8441 WebSocket-over-HTTP/2 is a
            // different handshake, and silently negotiating h2 here would
            // produce a connection that looks established and never
            // carries a frame.
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
        let _ = conn.configure(cfg.read_timeout);
        let stream = Arc::new(conn);

        // ---- handshake ------------------------------------------------
        let key = generate_key()?;
        let mut reader = BufReader::new(stream.clone(), opts.read_buffer.max(16 * 1024));
        let mut writer = BufWriter::new(stream.clone(), 16 * 1024);
        let mut scratch = Scratch::new();

        let mut headers = HeaderMap::with_capacity(8 + opts.protocols.len());
        // An IPv6 literal keeps its brackets (RFC 3986 §3.2.2); `Url`
        // strips them from the host.
        let literal = if host.contains(':') {
            alloc::format!("[{host}]")
        } else {
            host.clone()
        };
        let host_header = if (secure && port == 443) || (!secure && port == 80) {
            literal
        } else {
            alloc::format!("{literal}:{port}")
        };
        push(&mut headers, "host", &host_header)?;
        push(&mut headers, "upgrade", "websocket")?;
        push(&mut headers, "connection", "Upgrade")?;
        push(&mut headers, "sec-websocket-key", &key)?;
        push(&mut headers, "sec-websocket-version", "13")?;
        if !opts.protocols.is_empty() {
            for p in &opts.protocols {
                if !is_token(p) {
                    return Err(Error::protocol("ws: subprotocol is not a token"));
                }
            }
            push(
                &mut headers,
                "sec-websocket-protocol",
                &opts.protocols.join(", "),
            )?;
        }
        // What actually goes on the wire: the offer above plus any the
        // caller added. The response is validated against *this*, never
        // against a constant (RFC 6455 §4.1: an extension that was not
        // offered fails the connection).
        let mut offered: Vec<ExtensionOffer> = Vec::new();
        if opts.compression {
            offered.extend(parse_extension_value(PM_DEFLATE_OFFER)?);
            push(&mut headers, "sec-websocket-extensions", PM_DEFLATE_OFFER)?;
        }
        for (name, value) in &opts.headers {
            if name.eq_ignore_ascii_case("sec-websocket-extensions") {
                offered.extend(parse_extension_value(value)?);
            }
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
        let (status, response_headers) = read_response_head(&mut reader, &mut scratch)?;
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
        for (i, ext) in parse_extensions(&response_headers)?.iter().enumerate() {
            let offer = offered.iter().find(|o| o.name == ext.name).ok_or_else(|| {
                Error::protocol("ws: the server selected an extension that was not offered")
            })?;
            if i > 0 {
                return Err(Error::protocol(
                    "ws: the server selected more than one extension",
                ));
            }
            compression = Some(PerMessageDeflate::from_response(
                offer,
                ext,
                &PmDeflatePolicy::default(),
            )?);
        }

        // A handshake read may have pulled frame bytes into the reader;
        // the session takes that reader over, so nothing is lost.
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
    /// The transport's read timeout (`ClientConfig::read_timeout`) bounds
    /// the wait and surfaces as [`ErrorKind::Timeout`].
    pub fn read_message(&mut self) -> Result<Event> {
        self.session.read_message()
    }

    /// A non-blocking poll: `Ok(None)` means “nothing complete yet”.
    pub fn poll_message(&mut self) -> Result<Option<Event>> {
        self.session.poll_message()
    }

    /// A push handle usable from another thread while this one reads.
    pub fn writer(&self) -> WsClientWriter {
        // The push handle must share the connection's Close flag with the
        // session: RFC 6455 §5.5.1 — nothing may follow a Close frame — is
        // a property of the connection, not of one writer.
        let close_flag = self.session.writer().close_flag();
        WsClientWriter {
            inner: Arc::new(std::sync::Mutex::new(FrameWriter::with_close_flag(
                self.sink.clone(),
                MaskSource::Random,
                self.session.compression(),
                close_flag,
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

    /// Change the transport's read timeout (bounds how long
    /// [`WebSocket::read_message`] blocks).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.stream.configure(timeout)
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

/// Read the response head, skipping up to [`MAX_INFORMATIONAL`] `1xx`
/// responses.
fn read_response_head(
    reader: &mut BufReader<Arc<ConnStream>>,
    scratch: &mut Scratch,
) -> Result<(crate::courierust_http::status::StatusCode, HeaderMap)> {
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
        // A protocol switch is an HTTP/1.1 response; a 1.0 status line
        // means the peer is not following §4.1.
        if version != Version::HTTP_11 {
            return Err(Error::protocol(
                "ws: the handshake response is not HTTP/1.1",
            ));
        }
        return Ok((status, headers));
    }
    Err(Error::protocol(
        "ws: too many informational responses before the switch",
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
