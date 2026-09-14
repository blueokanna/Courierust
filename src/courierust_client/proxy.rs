//! Outbound proxying: `CONNECT` tunnels (RFC 9110 §9.3.6) for secure
//! targets, absolute-form request targets (RFC 9112 §3.2.2) for
//! plaintext ones.
//!
//! The tunnel is deliberately boring: the proxy is dialled like any other
//! peer, the `CONNECT` handshake is one request/response exchange, and
//! what comes back is a socket that carries the same bytes the origin
//! would have seen. Everything above this module — TLS, HTTP/1.1,
//! HTTP/2, WebSocket — is unchanged, which is the point: a proxy is a
//! property of the *transport*.

use crate::courierust_error::{Error, ErrorKind, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Cap on the proxy's handshake response head.
///
/// The head is the only thing read here; a body after it belongs to a
/// refusal the client is going to report and drop, and a head that never
/// ends is a proxy that is stalled (`connect_timeout` ends it).
const MAX_PROXY_HEAD: usize = 16 * 1024;

/// An HTTP proxy that client requests are sent through.
///
/// Only `http://` proxies are supported. Connecting to the proxy itself
/// over TLS would need a second, nested TLS handshake, and quietly
/// sending `Proxy-Authorization` in the clear to a proxy that expects TLS
/// is exactly the kind of half-measure a proxy setting must not have; the
/// scheme is refused with a message saying so.
#[derive(Clone, PartialEq, Eq)]
pub struct Proxy {
    /// Proxy host name (or IP literal).
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// Credentials sent as `Proxy-Authorization: Basic` (RFC 7617 §2.1).
    ///
    /// They are sent to the proxy only: a `CONNECT` tunnel carries the
    /// origin's traffic untouched, and a plaintext request that passes
    /// *through* the proxy is the proxy's to strip before forwarding —
    /// stripping hop-by-hop credentials is its job, not the client's.
    pub credentials: Option<(String, String)>,
}

impl core::fmt::Debug for Proxy {
    /// Redacts the password: a proxy configuration ends up in logs and
    /// error messages, and a credential that leaks there is a credential
    /// leaked.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Proxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|(user, _)| user.as_str()),
            )
            .finish()
    }
}

impl Proxy {
    /// A proxy at `host:port`, or at `http://host:port` (the prefix is
    /// accepted and ignored). Any other scheme is refused.
    pub fn new(authority: &str) -> Result<Self> {
        let rest = match authority.split_once("://") {
            Some(("http", rest)) => rest,
            Some((other, _)) => {
                return Err(Error::protocol(format!(
                    "an {other}:// proxy needs TLS to the proxy, which this client does not \
                     implement; use an http:// proxy"
                )))
            }
            None => authority,
        };
        let rest = rest.trim_end_matches('/');
        if rest.is_empty() {
            return Err(Error::protocol("empty proxy authority"));
        }
        // `[::1]:8080` — the brackets belong to the authority form, the
        // host stored here is the bare literal that `ToSocketAddrs` takes.
        let (host, port) = if let Some(rest) = rest.strip_prefix('[') {
            let (host, rest) = rest
                .split_once(']')
                .ok_or_else(|| Error::protocol("unterminated IPv6 literal in proxy authority"))?;
            (host, rest.strip_prefix(':'))
        } else {
            match rest.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (rest, None),
            }
        };
        if host.is_empty() {
            return Err(Error::protocol("empty proxy host"));
        }
        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| Error::protocol(format!("invalid proxy port {p:?}")))?,
            None => {
                return Err(Error::protocol(
                    "a proxy needs an explicit port (for example http://127.0.0.1:8080)",
                ))
            }
        };
        if port == 0 {
            return Err(Error::protocol("proxy port 0 is not a port"));
        }
        Ok(Self {
            host: host.to_string(),
            port,
            credentials: None,
        })
    }

    /// Attach credentials for `Proxy-Authorization: Basic`.
    pub fn basic(mut self, user: &str, password: &str) -> Self {
        self.credentials = Some((user.to_string(), password.to_string()));
        self
    }

    /// The value of the `Proxy-Authorization` field, if configured.
    pub(crate) fn authorization(&self) -> Option<String> {
        let (user, password) = self.credentials.as_ref()?;
        let mut raw = String::with_capacity(user.len() + password.len() + 1);
        raw.push_str(user);
        raw.push(':');
        raw.push_str(password);
        let mut value = String::from("Basic ");
        value.push_str(&crate::courierust_crypto::base64::encode(raw.as_bytes()));
        Some(value)
    }
}

/// Connect to `host:port` directly, trying every resolved address.
///
/// A name that resolves to several addresses (the usual `localhost` case:
/// `::1` and `127.0.0.1`) must not fail because the first one is not the
/// one that is listening. Each attempt gets its own timeout and the last
/// failure is what is reported.
pub(crate) fn connect_direct(
    host: &str,
    port: u16,
    timeout: Option<Duration>,
) -> Result<(SocketAddr, TcpStream)> {
    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| Error::io(format!("cannot resolve {host}:{port}: {e}")))?
        .collect();
    if addresses.is_empty() {
        return Err(Error::io(format!("{host}:{port} resolved to no address")));
    }
    let mut last: Option<Error> = None;
    for addr in addresses {
        match crate::courierust_net::connect(&addr, timeout) {
            Ok(stream) => return Ok((addr, stream)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| Error::io(format!("cannot connect to {host}:{port}"))))
}

/// Connect to `host:port` through `proxy`, completing the `CONNECT`
/// handshake.
///
/// `target` is the origin in authority form (`host:port`, RFC 9110
/// §9.3.6). Returns the address actually connected to (the proxy, which
/// is what a caller records as the peer) and a socket positioned exactly
/// at the first tunnel byte.
pub(crate) fn connect_through(
    proxy: &Proxy,
    target: &str,
    timeout: Option<Duration>,
) -> Result<(SocketAddr, TcpStream)> {
    let (addr, mut stream) = connect_direct(&proxy.host, proxy.port, timeout)?;
    // The handshake runs under the connect timeout: a proxy that accepts
    // and then says nothing must fail this request instead of holding the
    // caller for the application read timeout.
    let _ = stream.set_read_timeout(timeout);
    let mut request = Vec::with_capacity(128);
    request.extend_from_slice(b"CONNECT ");
    request.extend_from_slice(target.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(target.as_bytes());
    request.extend_from_slice(b"\r\n");
    if let Some(authorization) = proxy.authorization() {
        request.extend_from_slice(b"Proxy-Authorization: ");
        request.extend_from_slice(authorization.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    stream.write_all(&request).map_err(Error::from)?;
    stream.flush().map_err(Error::from)?;

    // A `1xx` is not an answer to `CONNECT` (RFC 9110 §15.2): it is the
    // proxy clearing its throat, so the head after it is the real one.
    for _ in 0..=MAX_INFORMATIONAL {
        let (status, reason) = read_head(&mut stream)?;
        if (100..200).contains(&status) {
            continue;
        }
        if !(200..300).contains(&status) {
            // The proxy answered — properly — that it will not open the
            // tunnel (407 wants credentials, 403 is policy). No IO
            // failure and no protocol violation happened, so the failure
            // is reported as what it is, with the status kept in the
            // message where a caller can act on it.
            return Err(Error::with_message(
                ErrorKind::Other,
                format!("the proxy refused CONNECT {target}: {status} {reason}"),
            ));
        }
        // Back to the caller's clock discipline: the caller reconfigures
        // the socket for the phase it is about to run (handshake, then
        // application read).
        let _ = stream.set_read_timeout(None);
        let _ = stream.set_write_timeout(None);
        return Ok((addr, stream));
    }
    Err(Error::with_message(
        ErrorKind::Other,
        "the proxy sent nothing but informational responses to CONNECT",
    ))
}

/// RFC 9110 §9.3.6 authority form: `host:port`, with an IPv6 literal in
/// brackets (the colon inside it is not a port separator).
pub(crate) fn authority(host: &str, port: u16) -> String {
    let mut out = String::with_capacity(host.len() + 8);
    if host.contains(':') {
        out.push('[');
        out.push_str(host);
        out.push(']');
    } else {
        out.push_str(host);
    }
    out.push(':');
    out.push_str(&port.to_string());
    out
}

/// How many informational responses are skipped before the proxy is
/// declared to be stalling.
const MAX_INFORMATIONAL: usize = 4;

/// Read one response head and return `(status, reason)`.
///
/// Exactly the head is consumed. That matters more than it looks: the
/// next byte on this socket is the client's `ClientHello`, and a read
/// that consumed it would have nowhere to put it back — so the head is
/// examined with `peek` (which does not consume) and read out only once
/// its terminator is visible. The byte-at-a-time fallback runs only when
/// the proxy dribbles the head out, and it keeps what it consumed in
/// `seen`, so nothing is ever lost either way.
fn read_head(stream: &mut TcpStream) -> Result<(u16, String)> {
    let mut seen: Vec<u8> = Vec::new();
    let mut window = [0u8; MAX_PROXY_HEAD];
    loop {
        let n = stream.peek(&mut window).map_err(Error::from)?;
        if n == 0 {
            return Err(Error::with_message(
                ErrorKind::UnexpectedEof,
                "the proxy closed the connection during the CONNECT handshake",
            ));
        }
        let mut candidate = seen.clone();
        candidate.extend_from_slice(&window[..n]);
        if let Some(end) = find_head_end(&candidate) {
            // Consume the part of the head still in the socket, and
            // nothing after it.
            let outstanding = end - seen.len();
            stream
                .read_exact(&mut window[..outstanding])
                .map_err(Error::from)?;
            candidate.truncate(end);
            return parse_head(&candidate);
        }
        if seen.len() >= MAX_PROXY_HEAD {
            return Err(Error::with_message(
                ErrorKind::Overflow,
                "the proxy's CONNECT response head exceeds the accepted size",
            ));
        }
        // Incomplete: take one byte so the next peek can see further.
        let mut one = [0u8; 1];
        stream.read_exact(&mut one).map_err(Error::from)?;
        seen.push(one[0]);
    }
}

/// The index just past `\r\n\r\n` (or a bare `\n\n`), if present.
fn find_head_end(bytes: &[u8]) -> Option<usize> {
    for i in 0..bytes.len() {
        if bytes[i] == b'\n' {
            if i >= 3 && &bytes[i - 3..=i] == b"\r\n\r\n" {
                return Some(i + 1);
            }
            if i >= 1 && bytes[i - 1] == b'\n' {
                return Some(i + 1);
            }
        }
    }
    None
}

/// Parse `HTTP/1.x <status> <reason>` out of a complete head.
fn parse_head(head: &[u8]) -> Result<(u16, String)> {
    let line = head.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let line = core::str::from_utf8(line)
        .map_err(|_| Error::protocol("the proxy's status line is not UTF-8"))?;
    let mut parts = line.trim_end_matches('\r').splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(Error::protocol(format!(
            "the proxy answered with {version:?} instead of HTTP/1.x"
        )));
    }
    let status = parts
        .next()
        .ok_or_else(|| Error::protocol("the proxy's status line has no status code"))?
        .parse::<u16>()
        .map_err(|_| Error::protocol("the proxy's status code is not a number"))?;
    // The reason phrase is echoed into an error message: keep it short and
    // printable so it cannot smuggle control characters into a log.
    let reason: String = parts
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    Ok((status, reason))
}
