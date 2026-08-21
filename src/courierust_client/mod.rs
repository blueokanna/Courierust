//! Multi-core HTTP client: HTTP/1.1 keep-alive pool + HTTP/2
//! multiplexed connections distributed across worker threads.

pub mod h1;
pub mod h2;

use crate::courierust_body::Body;
use crate::courierust_client::h1::H1Connection;
use crate::courierust_client::h2::{H2Cmd, H2Conn};
use crate::courierust_error::{Error, Result};
use crate::courierust_h2::priority::Priority;
use crate::courierust_http::method::Method;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::uri::Url;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Client-side TLS settings for `https://` URLs.
///
/// When `None`, `https://` URLs are rejected with a clear error. Set
/// [`ClientConfig::tls`] to enable TLS 1.3 on the client.
#[derive(Debug, Clone)]
pub struct TlsSettings {
    /// Trust anchors for server certificate validation.
    pub roots: crate::courierust_tls::RootStore,
    /// Whether to validate the server certificate (and hostname).
    pub verify: bool,
    /// ALPN protocols offered (raw wire values, e.g. `h2`, `http/1.1`).
    pub alpn: Vec<Vec<u8>>,
    /// The current time (Unix seconds) used for validity checks.
    pub now: i64,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            roots: crate::courierust_tls::RootStore::new(),
            verify: true,
            // Default ALPN matches the default `ClientConfig::http2`
            // (false): speak HTTP/1.1 over TLS unless told otherwise.
            alpn: vec![b"http/1.1".to_vec()],
            now: unix_now(),
        }
    }
}

/// Current Unix time in seconds (for certificate validity checks).
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Prefer HTTP/2 (h2c prior knowledge) when true; otherwise HTTP/1.1.
    pub http2: bool,
    /// Maximum keep-alive connections cached per host (h1) / maximum h2
    /// connections per host.
    pub max_connections_per_host: usize,
    /// Connect timeout.
    pub connect_timeout: Option<Duration>,
    /// Read timeout.
    pub read_timeout: Option<Duration>,
    /// Maximum redirects to follow.
    pub max_redirects: usize,
    /// Default `User-Agent`.
    pub user_agent: Option<String>,
    /// Maximum accepted header-list size.
    pub max_header_list: usize,
    /// Maximum accepted body size.
    pub max_body: usize,
    /// TLS settings for `https://` URLs. `None` (the default) disables
    /// TLS; `https://` requests then fail with a clear error.
    pub tls: Option<TlsSettings>,
    /// h2: drop the connection if the peer does not ACK our SETTINGS
    /// within this long (`SETTINGS_TIMEOUT`, RFC 9113 §6.5.3).
    pub h2_settings_timeout: Option<Duration>,
    /// h2: send a keepalive PING after this much inbound silence.
    pub h2_ping_interval: Option<Duration>,
    /// h2: drop the connection if no frame at all arrives within this
    /// long after a keepalive PING was sent (dead-peer detection).
    pub h2_ping_timeout: Option<Duration>,
    /// h2: close a connection with no in-flight streams after this much
    /// idle time, so idle driver threads are reaped instead of
    /// accumulating with connection count.
    pub h2_idle_timeout: Option<Duration>,
    /// Use the RFC 7540 §3.2 `h2c` Upgrade handshake instead of prior
    /// knowledge when opening an h2 connection to an `http://` host
    /// (interop with servers that only support Upgrade-based h2c). The
    /// first request is sent as the upgrade request; if the server
    /// declines, the HTTP/1.1 response is returned directly.
    pub h2c_upgrade: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            http2: false,
            max_connections_per_host: 4,
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: Some(Duration::from_secs(60)),
            max_redirects: 10,
            user_agent: Some(format!("courierust/{}", env!("CARGO_PKG_VERSION"))),
            max_header_list: 1 << 20,
            max_body: 16 * 1024 * 1024,
            tls: None,
            h2_settings_timeout: Some(Duration::from_secs(10)),
            h2_ping_interval: Some(Duration::from_secs(30)),
            h2_ping_timeout: Some(Duration::from_secs(15)),
            h2_idle_timeout: Some(Duration::from_secs(300)),
            h2c_upgrade: false,
        }
    }
}

struct ClientInner {
    config: ClientConfig,
    /// Idle h1 keep-alive connections per authority.
    h1_pool: Mutex<HashMap<String, Vec<(SocketAddr, H1Connection)>>>,
    /// Live h2 connections per authority (indexed round-robin).
    h2_pool: Mutex<HashMap<String, Vec<H2Conn>>>,
    /// Round-robin cursor per authority.
    h2_cursor: Mutex<HashMap<String, usize>>,
    /// Global request sequence (instrumentation).
    seq: AtomicUsize,
}

/// An HTTP client.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// A client with default settings.
    pub fn new() -> Self {
        Self::with_config(ClientConfig::default())
    }

    /// A client with HTTPS enabled, trusting `roots` for server
    /// certificate validation. HTTP/2 is preferred (ALPN `h2`, falling
    /// back to `http/1.1` when the server only supports it).
    pub fn with_tls_roots(roots: crate::courierust_tls::RootStore) -> Self {
        Self::with_config(ClientConfig {
            http2: true,
            tls: Some(TlsSettings {
                roots,
                verify: true,
                alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                now: unix_now(),
            }),
            ..Default::default()
        })
    }

    /// A client with custom settings.
    pub fn with_config(config: ClientConfig) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                config,
                h1_pool: Mutex::new(HashMap::new()),
                h2_pool: Mutex::new(HashMap::new()),
                h2_cursor: Mutex::new(HashMap::new()),
                seq: AtomicUsize::new(0),
            }),
        }
    }

    /// Perform a GET request.
    pub fn get(&self, url: &str) -> Result<Response<Body>> {
        let req = Request::<Body>::new(Method::GET, "/");
        self.execute(url, req)
    }

    /// Perform a POST request with a body.
    pub fn post(&self, url: &str, body: impl Into<Body>) -> Result<Response<Body>> {
        let mut req = Request::<Body>::new(Method::POST, "/");
        req.body = body.into();
        self.execute(url, req)
    }

    /// Perform a request against `url`. The request's `uri` is used as the
    /// path; the URL supplies scheme/host/port.
    pub fn execute(&self, url: &str, req: Request<Body>) -> Result<Response<Body>> {
        let parsed = Url::parse(url)?;
        self.execute_with_redirects(&parsed, req, 0)
    }

    /// Like [`Client::execute`] but signals an RFC 9218 priority for h2.
    pub fn execute_priority(
        &self,
        url: &str,
        req: Request<Body>,
        priority: Priority,
    ) -> Result<Response<Body>> {
        let parsed = Url::parse(url)?;
        let raw = self.execute_h2_raw(&parsed, req, priority)?;
        Ok(Response {
            status: raw.head.status,
            version: raw.head.version,
            headers: raw.head.headers,
            body: raw.body,
            trailers: None,
        })
    }

    /// Perform an h2 request and return the raw response including
    /// trailers (used by the gRPC layer).
    pub fn execute_h2_raw(
        &self,
        url: &Url,
        req: Request<Body>,
        priority: Priority,
    ) -> Result<crate::courierust_client::h2::H2Response> {
        let tls = self.tls_for_scheme(&url.scheme)?;
        let addr = resolve_addr(&url.host, url.port)?;
        let authority = url.authority();
        self.execute_h2(url, &authority, addr, tls, req, priority)
    }

    fn execute_with_redirects(
        &self,
        url: &Url,
        req: Request<Body>,
        depth: usize,
    ) -> Result<Response<Body>> {
        // Capture the head before the request is consumed by the network.
        let orig_method = req.method.clone();
        let orig_headers = req.headers.clone();
        let resp = self.execute_inner(url, req, Priority::default())?;
        if depth >= self.inner.config.max_redirects {
            return Ok(resp);
        }
        let is_redirect = resp.status.is_redirection() && resp.status != StatusCode::NOT_MODIFIED;
        if is_redirect {
            if let Some(loc) = resp.headers.get("location").and_then(|v| v.to_str().ok()) {
                let next = resolve_redirect(url, loc)?;
                let method = match resp.status.as_u16() {
                    303 => Method::GET,
                    301 | 302 if orig_method == Method::POST => Method::GET,
                    _ => orig_method,
                };
                let mut new_req = Request::new(method, next.path_and_query.clone());
                // Never forward credentials to a different origin: a
                // malicious server could otherwise redirect a request and
                // harvest `Authorization` / `Cookie` (RFC 9110 §15.4
                // credential-leakage guidance).
                let mut headers = orig_headers;
                if next.authority() != url.authority() {
                    for name in ["authorization", "proxy-authorization", "cookie"] {
                        headers.remove(name);
                    }
                }
                new_req.headers = headers;
                new_req.body = Body::Empty;
                return self.execute_with_redirects(&next, new_req, depth + 1);
            }
        }
        Ok(resp)
    }

    fn execute_inner(
        &self,
        url: &Url,
        req: Request<Body>,
        priority: Priority,
    ) -> Result<Response<Body>> {
        // The URL supplies scheme/host/port; the request path is used
        // as-is when the caller set one (gRPC method paths, redirects,
        // explicit `execute` calls). The convenience methods `get`/`post`
        // construct requests with the default target `/`, so when the
        // path is still the default we take it from the URL — otherwise
        // `client.get("http://host/api/v1")` would silently request `/`.
        let req = if req.uri.as_str() == "/" && url.path_and_query.as_str() != "/" {
            let mut req = req;
            req.uri = url.path_and_query.clone();
            req
        } else {
            req
        };
        let tls = self.tls_for_scheme(&url.scheme)?;
        self.inner.seq.fetch_add(1, Ordering::Relaxed);
        let addr = resolve_addr(&url.host, url.port)?;
        let authority = url.authority();
        if self.inner.config.http2 {
            if self.inner.config.h2c_upgrade && url.scheme == "http" {
                // RFC 7540 §3.2 Upgrade-based h2c (falls back to HTTP/1.1
                // when the server declines).
                return self.execute_h2c_upgrade(url, &authority, addr, req);
            }
            let raw = self.execute_h2(url, &authority, addr, tls, req, priority)?;
            Ok(Response {
                status: raw.head.status,
                version: raw.head.version,
                headers: raw.head.headers,
                body: raw.body,
                trailers: None,
            })
        } else {
            self.execute_h1(url, &authority, addr, tls, req)
        }
    }

    /// Resolve the TLS connector for a scheme, or reject unsupported /
    /// unconfigured `https`.
    fn tls_for_scheme(&self, scheme: &str) -> Result<Option<crate::courierust_tls::TlsConnector>> {
        match scheme {
            "http" => Ok(None),
            "https" => match &self.inner.config.tls {
                Some(t) => Ok(Some(crate::courierust_tls::TlsConnector::new(
                    crate::courierust_tls::ClientConfig {
                        roots: t.roots.clone(),
                        verify: t.verify,
                        alpn: t.alpn.clone(),
                        now: t.now,
                    },
                ))),
                None => Err(Error::protocol(
                    "https requires TLS settings (set ClientConfig.tls)",
                )),
            },
            other => Err(Error::protocol(format!(
                "scheme {other} not supported by the built-in connector"
            ))),
        }
    }

    fn execute_h1(
        &self,
        url: &Url,
        authority: &str,
        addr: SocketAddr,
        tls: Option<crate::courierust_tls::TlsConnector>,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        let conn = {
            let mut pool = self.inner.h1_pool.lock().unwrap();
            let entry = pool.entry(authority.to_string()).or_default();
            entry
                .iter()
                .position(|(a, _)| *a == addr)
                .map(|i| entry.remove(i).1)
        };
        let hostname = url.host.clone();
        let mut owned = match conn {
            Some(c) => c,
            None => H1Connection::connect(addr, tls.as_ref(), &hostname, &self.inner.config)?,
        };
        let result = owned.send(&req, &self.inner.config, authority);
        match result {
            Ok(resp) => {
                if owned.is_reusable() {
                    let mut pool = self.inner.h1_pool.lock().unwrap();
                    let entry = pool.entry(authority.to_string()).or_default();
                    if entry.len() < self.inner.config.max_connections_per_host {
                        entry.push((addr, owned));
                    }
                }
                Ok(resp)
            }
            Err(e) => Err(e),
        }
    }

    /// Perform an h2 request with a streaming body (`Body::Channel`):
    /// the body is fed to the peer as DATA frames, enabling
    /// client-streaming / bidi gRPC calls. Fully materialized bodies use
    /// the regular [`Self::execute_h2_raw`] path.
    pub fn execute_h2_stream(
        &self,
        url: &Url,
        req: Request<Body>,
        priority: Priority,
    ) -> Result<crate::courierust_client::h2::H2Response> {
        let tls = self.tls_for_scheme(&url.scheme)?;
        let addr = resolve_addr(&url.host, url.port)?;
        let authority = url.authority();
        self.execute_h2(url, &authority, addr, tls, req, priority)
    }

    fn execute_h2(
        &self,
        url: &Url,
        authority: &str,
        addr: SocketAddr,
        tls: Option<crate::courierust_tls::TlsConnector>,
        req: Request<Body>,
        priority: Priority,
    ) -> Result<crate::courierust_client::h2::H2Response> {
        let conn = self.get_h2_conn(authority, addr, tls.as_ref(), &url.host)?;
        let fields = h2::request_fields(&req);
        let (tx, rx) = std::sync::mpsc::channel();
        let cmd = build_h2_cmd(fields, req.body, priority, tx);
        self.send_h2_cmd(conn, authority, addr, tls.as_ref(), &url.host, cmd, rx)
    }

    /// Perform a request over an h2 connection established with the RFC
    /// 7540 §3.2 `h2c` Upgrade handshake (only for `http://` hosts). A
    /// pooled, already-upgraded connection is reused when available;
    /// otherwise a fresh socket is upgraded. If the server declines the
    /// upgrade, the HTTP/1.1 response is returned directly.
    fn execute_h2c_upgrade(
        &self,
        url: &Url,
        authority: &str,
        addr: SocketAddr,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        // 1. Reuse a pooled, already-upgraded connection when available.
        let pooled = {
            let pools = self.inner.h2_pool.lock().unwrap();
            pools.get(authority).and_then(|list| {
                list.iter()
                    .find(|c| c.accepting.load(Ordering::Acquire))
                    .cloned()
            })
        };
        if let Some(conn) = pooled {
            let fields = h2::request_fields(&req);
            let (tx, rx) = std::sync::mpsc::channel();
            let cmd = build_h2_cmd(fields, req.body, Priority::default(), tx);
            return self
                .send_h2_cmd(conn, authority, addr, None, &url.host, cmd, rx)
                .map(|raw| Response {
                    status: raw.head.status,
                    version: raw.head.version,
                    headers: raw.head.headers,
                    body: raw.body,
                    trailers: None,
                });
        }

        // 2. No usable connection: perform the Upgrade handshake.
        let stream = crate::courierust_net::connect(&addr, self.inner.config.connect_timeout)?;
        crate::courierust_net::configure(&stream, self.inner.config.read_timeout)?;
        let settings_b64 = h2::upgrade_settings_b64(&self.inner.config);
        let wire = h2::build_upgrade_request(
            &req,
            authority,
            &settings_b64,
            self.inner.config.user_agent.as_deref(),
        )?;
        match h2::h2c_upgrade_handshake(&stream, &wire)? {
            h2::UpgradeOutcome::Upgraded(seed) => {
                let cs = crate::courierust_net::ConnStream::plain(stream);
                let (tx, rx) = std::sync::mpsc::channel();
                let conn = h2::start_upgraded(cs, &self.inner.config, seed, tx)?;
                {
                    let mut pools = self.inner.h2_pool.lock().unwrap();
                    let list = pools.entry(authority.to_string()).or_default();
                    if list.len() < self.inner.config.max_connections_per_host {
                        list.push(conn);
                    }
                }
                let raw = rx
                    .recv()
                    .map_err(|_| Error::canceled("h2 driver closed the channel"))??;
                Ok(Response {
                    status: raw.head.status,
                    version: raw.head.version,
                    headers: raw.head.headers,
                    body: raw.body,
                    trailers: None,
                })
            }
            h2::UpgradeOutcome::Declined(head, leftover) => {
                let cs = crate::courierust_net::ConnStream::plain(stream);
                let mut owned =
                    H1Connection::from_stream_seeded(cs, &self.inner.config, &leftover)?;
                let resp = owned.finish_response(&self.inner.config, head)?;
                if owned.is_reusable() {
                    let mut pool = self.inner.h1_pool.lock().unwrap();
                    let entry = pool.entry(authority.to_string()).or_default();
                    if entry.len() < self.inner.config.max_connections_per_host {
                        entry.push((addr, owned));
                    }
                }
                Ok(resp)
            }
        }
    }

    /// Send a driver command, retrying once on a fresh connection if the
    /// driver is gone, then wait for the reply.
    //
    // The `authority`/`addr`/`tls`/`hostname` bundle is deliberately kept
    // flat here (and in `get_h2_conn`/`open_h2_conn`) so the retry path
    // can re-open a fresh connection with exactly the same parameters.
    #[allow(clippy::too_many_arguments)]
    fn send_h2_cmd(
        &self,
        conn: H2Conn,
        authority: &str,
        addr: SocketAddr,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
        cmd: H2Cmd,
        rx: std::sync::mpsc::Receiver<Result<crate::courierust_client::h2::H2Response>>,
    ) -> Result<crate::courierust_client::h2::H2Response> {
        match conn.tx.send(cmd) {
            Ok(()) => rx
                .recv()
                .map_err(|_| Error::canceled("h2 driver closed the channel"))?,
            Err(std::sync::mpsc::SendError(cmd)) => {
                // The driver is gone; open a fresh connection and retry.
                let fresh = self.open_h2_conn(authority, addr, tls, hostname)?;
                let (tx2, rx2) = std::sync::mpsc::channel();
                let cmd2 = retarget_reply(cmd, tx2);
                fresh
                    .tx
                    .send(cmd2)
                    .map_err(|_| Error::canceled("h2 driver is gone"))?;
                rx2.recv()
                    .map_err(|_| Error::canceled("h2 driver closed the channel"))?
            }
        }
    }

    fn get_h2_conn(
        &self,
        authority: &str,
        addr: SocketAddr,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
    ) -> Result<H2Conn> {
        let mut pools = self.inner.h2_pool.lock().unwrap();
        let list = pools.entry(authority.to_string()).or_default();
        // Reuse a live connection.
        if let Some(c) = list.iter().find(|c| c.accepting.load(Ordering::Acquire)) {
            return Ok(c.clone());
        }
        // Open a new one (up to the per-host cap; beyond it, multiplex on
        // an existing connection).
        if list.len() < self.inner.config.max_connections_per_host {
            let stream = self.open_h2_stream(addr, tls, hostname)?;
            let conn = h2::start(stream, &self.inner.config)?;
            list.push(conn.clone());
            return Ok(conn);
        }
        let mut cursors = self.inner.h2_cursor.lock().unwrap();
        let cur = cursors.entry(authority.to_string()).or_insert(0);
        let idx = *cur % list.len();
        *cur += 1;
        Ok(list[idx].clone())
    }

    fn open_h2_conn(
        &self,
        authority: &str,
        addr: SocketAddr,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
    ) -> Result<H2Conn> {
        let stream = self.open_h2_stream(addr, tls, hostname)?;
        let conn = h2::start(stream, &self.inner.config)?;
        let mut pools = self.inner.h2_pool.lock().unwrap();
        let list = pools.entry(authority.to_string()).or_default();
        list.push(conn.clone());
        Ok(conn)
    }

    /// Open a raw (possibly TLS-wrapped) stream for the h2 driver.
    fn open_h2_stream(
        &self,
        addr: SocketAddr,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
    ) -> Result<crate::courierust_net::ConnStream> {
        let stream = crate::courierust_net::connect(&addr, self.inner.config.connect_timeout)?;
        match tls {
            Some(c) => {
                let conn = crate::courierust_net::ConnStream::tls_client(stream, c, hostname)?;
                // The peer's ALPN choice must agree with speaking
                // HTTP/2: a server that negotiated `http/1.1` cannot be
                // driven with the h2 codec (silent mismatch would hang).
                if let Some(alpn) = conn.alpn() {
                    if alpn.as_slice() != b"h2" {
                        return Err(Error::protocol(format!(
                            "server negotiated {:?}, not h2; set ClientConfig.tls.alpn to offer h2",
                            String::from_utf8_lossy(&alpn)
                        )));
                    }
                }
                Ok(conn)
            }
            None => Ok(crate::courierust_net::ConnStream::plain(stream)),
        }
    }
}

/// Build a driver command from a request's HPACK fields and body. A
/// channel body streams as DATA frames (`RequestStream`); anything else
/// is sent as one block with END_STREAM.
fn build_h2_cmd(
    fields: Vec<crate::courierust_hpack::HeaderField>,
    body: Body,
    priority: Priority,
    tx: std::sync::mpsc::Sender<Result<crate::courierust_client::h2::H2Response>>,
) -> H2Cmd {
    match body {
        Body::Channel(body_rx) => H2Cmd::RequestStream {
            fields,
            body: body_rx,
            priority,
            reply: tx,
        },
        other => {
            let (body, end_stream) = match other {
                Body::Empty => (None, true),
                Body::Bytes(b) => (Some(b), true),
                Body::Channel(_) => unreachable!(),
            };
            H2Cmd::Request {
                fields,
                body,
                end_stream,
                priority,
                reply: tx,
            }
        }
    }
}

/// Rebuild a driver command with a fresh reply channel (used when
/// retrying on a new connection).
fn retarget_reply(
    cmd: H2Cmd,
    reply: std::sync::mpsc::Sender<Result<crate::courierust_client::h2::H2Response>>,
) -> H2Cmd {
    match cmd {
        H2Cmd::Request {
            fields,
            body,
            end_stream,
            priority,
            ..
        } => H2Cmd::Request {
            fields,
            body,
            end_stream,
            priority,
            reply,
        },
        H2Cmd::RequestStream {
            fields,
            body,
            priority,
            ..
        } => H2Cmd::RequestStream {
            fields,
            body,
            priority,
            reply,
        },
        H2Cmd::Shutdown => H2Cmd::Shutdown,
    }
}

fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| Error::io(format!("resolve {host}: {e}")))?;
    // Prefer IPv4 to dodge IPv6 happy-eyeballs complexity.
    let mut first_v4 = None;
    for a in addrs.by_ref() {
        if a.is_ipv4() {
            first_v4 = Some(a);
            break;
        }
    }
    if let Some(a) = first_v4 {
        return Ok(a);
    }
    let _ = addrs;
    let mut it = (host, port)
        .to_socket_addrs()
        .map_err(|e| Error::io(format!("resolve {host}: {e}")))?;
    it.next()
        .ok_or_else(|| Error::io(format!("no address for {host}")))
}

fn resolve_redirect(base: &Url, location: &str) -> Result<Url> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return Url::parse(location);
    }
    // Relative or protocol-relative redirect (preserve the base scheme).
    let scheme = base.scheme.as_str();
    let mut s = format!("{scheme}://{}{}", base.authority(), location);
    if location.starts_with("//") {
        s = format!("{scheme}:{}", location);
    }
    Url::parse(&s)
}
