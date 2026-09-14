//! Multi-core HTTP client: HTTP/1.1 keep-alive pool + HTTP/2
//! multiplexed connections distributed across worker threads.

pub mod builder;
pub mod h1;
pub mod h2;
pub mod proxy;
pub mod ws;

pub use builder::RequestBuilder;
pub use proxy::Proxy;

use crate::courierust_body::Body;
use crate::courierust_client::h1::H1Connection;
use crate::courierust_client::h2::{H2Cmd, H2Conn};
use crate::courierust_error::{Error, Result};
use crate::courierust_h2::priority::Priority;
use crate::courierust_h3::runtime::{H3Cmd, H3Conn};
use crate::courierust_http::header::HeaderMap;
use crate::courierust_http::method::Method;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::uri::Url;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Client-side TLS settings for `https://` URLs.
///
/// When `None`, `https://` URLs are rejected with a clear error. Set
/// [`ClientConfig::tls`] to enable TLS on the client.
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
    /// Lowest TLS version the client will offer/negotiate.
    pub min_version: crate::courierust_tls::TlsVersion,
    /// Highest TLS version the client will offer/negotiate.
    pub max_version: crate::courierust_tls::TlsVersion,
    /// The client certificate to present when a server asks for one
    /// (mTLS). `None` (the default) answers a `CertificateRequest` with
    /// an empty certificate list.
    pub identity: Option<crate::courierust_tls::Identity>,
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
            min_version: crate::courierust_tls::TlsVersion::Tls12,
            max_version: crate::courierust_tls::TlsVersion::Tls13,
            identity: None,
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

/// Upper bound on the per-authority TLS connector cache. Each connector
/// owns a bounded resumption-session store; the cache itself is capped so
/// a client that touches a very large number of distinct hosts does not
/// accumulate connectors without bound.
const TLS_CONNECTOR_CACHE_MAX: usize = 256;

/// The TLS connector configuration derived from the client's settings —
/// fixed per client, so one configuration serves every cached connector.
fn connector_config(t: &TlsSettings) -> crate::courierust_tls::ClientConfig {
    crate::courierust_tls::ClientConfig {
        roots: t.roots.clone(),
        verify: t.verify,
        alpn: t.alpn.clone(),
        now: t.now,
        min_version: t.min_version,
        max_version: t.max_version,
        identity: t.identity.clone(),
    }
}

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Prefer HTTP/2 (h2c prior knowledge) when true; otherwise HTTP/1.1.
    pub http2: bool,
    /// Use the built-in HTTP/3/QUIC path for HTTPS requests. When enabled,
    /// HTTP/3 is attempted directly and no TCP fallback is performed.
    pub http3: bool,
    /// Maximum keep-alive connections cached per host (h1) / maximum h2
    /// connections per host.
    pub max_connections_per_host: usize,
    /// Connect timeout.
    pub connect_timeout: Option<Duration>,
    /// Read timeout.
    pub read_timeout: Option<Duration>,
    /// TLS handshake timeout: a server that accepts and then stalls
    /// mid-handshake releases the caller after this long instead of
    /// holding it for the full `read_timeout`. Without this, the HTTP/2
    /// TLS handshake had no timeout at all (a hostile server could block
    /// the caller forever). `None` falls back to `read_timeout`.
    pub handshake_timeout: Option<Duration>,
    /// Maximum redirects to follow.
    pub max_redirects: usize,
    /// Default `User-Agent`.
    pub user_agent: Option<String>,
    /// Fields added to every request this client sends.
    ///
    /// Merged in when the request is dispatched, so a field of the same
    /// name on the request itself always wins. A cross-origin redirect
    /// drops `authorization`, `proxy-authorization` and `cookie`
    /// wherever they came from — request or client — because a
    /// credential that lives in the configuration is the one most
    /// likely to be forgotten here: it is not visible at the call site
    /// that moved the request to another origin.
    pub default_headers: HeaderMap,
    /// Maximum accepted header-list size.
    pub max_header_list: usize,
    /// Maximum accepted body size.
    pub max_body: usize,
    /// TLS settings for `https://` URLs. `None` (the default) disables
    /// TLS; `https://` requests then fail with a clear error.
    pub tls: Option<TlsSettings>,
    /// Send requests through this HTTP proxy (RFC 9110 §9.3.6): a
    /// `CONNECT` tunnel for `https://` (and `wss://`) targets, the
    /// absolute request form (RFC 9112 §3.2.2) for plaintext ones.
    /// `None` (the default) connects directly.
    pub proxy: Option<Proxy>,
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
    /// h3: close a pooled QUIC connection with no in-flight requests
    /// after this long idle, so idle driver threads are reaped instead of
    /// accumulating with connection count.
    pub h3_idle_timeout: Option<Duration>,
    /// Use the RFC 7540 §3.2 `h2c` Upgrade handshake instead of prior
    /// knowledge when opening an h2 connection to an `http://` host
    /// (interop with servers that only support Upgrade-based h2c). The
    /// first request is sent as the upgrade request; if the server
    /// declines, the HTTP/1.1 response is returned directly.
    pub h2c_upgrade: bool,
    /// Optional instrumentation: when set, the h2 driver threads update
    /// these counters (connection / stream / syscall evidence for
    /// benchmarks). `None` (default) disables the accounting entirely.
    pub stats: Option<Arc<crate::courierust_net::stats::Stats>>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            http2: false,
            http3: false,
            max_connections_per_host: 4,
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: Some(Duration::from_secs(60)),
            handshake_timeout: Some(Duration::from_secs(10)),
            max_redirects: 10,
            user_agent: Some(format!("courierust/{}", env!("CARGO_PKG_VERSION"))),
            default_headers: HeaderMap::new(),
            max_header_list: 1 << 20,
            max_body: 16 * 1024 * 1024,
            tls: None,
            proxy: None,
            h2_settings_timeout: Some(Duration::from_secs(10)),
            h2_ping_interval: Some(Duration::from_secs(30)),
            h2_ping_timeout: Some(Duration::from_secs(15)),
            h2_idle_timeout: Some(Duration::from_secs(300)),
            h3_idle_timeout: Some(Duration::from_secs(300)),
            h2c_upgrade: false,
            stats: None,
        }
    }
}

/// Refuse a URL whose userinfo would have to be *dropped* to connect.
///
/// `Url::parse` keeps `user:secret@host` from being read as a host, but
/// nothing in this client turns that userinfo into an `Authorization`
/// field: connecting without the credential the URL advertises produces
/// a `401` that reads like a permissions problem. Callers pass
/// credentials explicitly (`RequestBuilder::basic_auth`), so a
/// credential in a URL is refused loudly instead of discarded.
pub(crate) fn reject_url_credentials(url: &Url) -> Result<()> {
    if url.userinfo.is_some() {
        return Err(Error::protocol(
            "URL userinfo is not sent — pass credentials explicitly (basic_auth); a credential \
             in a URL also leaks through logs and Referer",
        ));
    }
    Ok(())
}

/// Refuse a request target this client must not put on the wire.
///
/// The URL supplies the authority and the request supplies the path. An
/// *absolute* target (`http://other/…`) would ask the peer for a
/// different host than the connection was resolved and authenticated
/// for — a routing decision this client will not make on a field the
/// transport and the peer could read differently. Asterisk-form is not
/// that: `OPTIONS *` names the server itself, which is the one the URL
/// already names.
fn validate_target(url: &Url, req: &Request<Body>) -> Result<()> {
    reject_url_credentials(url)?;
    let target = req.uri.as_str();
    if target != "*" && target.contains("://") {
        return Err(Error::protocol(format!(
            "absolute request target {target:?} against {}: the URL supplies the authority and \
             the request supplies the path",
            url.authority()
        )));
    }
    Ok(())
}

/// Key of the HTTP/1.1 keep-alive pool: scheme and authority together.
///
/// The scheme is part of the key because `http://host:8443` (plaintext)
/// and `https://host:8443` (TLS) share an authority but must never reuse
/// each other's connections — reusing the plaintext one for an `https`
/// URL would silently downgrade the request. A pair rather than a
/// `format!("{}://{authority}")` keeps that distinction without an
/// allocation on every request.
#[derive(Clone, PartialEq, Eq, Hash)]
struct H1PoolKey {
    secure: bool,
    authority: String,
}

/// The pool key for a URL's scheme and authority. `secure` is `true` for
/// `https` (TLS), `false` for `http` — the one place the string is turned
/// into the flag the key stores, so a caller cannot mix the two up.
fn h1_pool_key(secure: bool, authority: &str) -> H1PoolKey {
    H1PoolKey {
        secure,
        authority: authority.to_string(),
    }
}

struct ClientInner {
    config: ClientConfig,
    /// Idle h1 keep-alive connections per authority.
    h1_pool: Mutex<HashMap<H1PoolKey, Vec<(SocketAddr, H1Connection)>>>,
    /// Live h2 connections per authority, selected by dispatch reservations.
    h2_pool: Mutex<HashMap<String, Vec<H2Conn>>>,
    /// Signaled whenever an h2 connection open lands (or fails), so
    /// callers waiting for the last connection slot wake instead of
    /// polling.
    h2_open_cv: std::sync::Condvar,
    /// h2 connections currently being opened, keyed by authority. The
    /// counters are protected independently from the pool map but are always
    /// acquired after `h2_pool`; this keeps one slow authority from
    /// blocking an unrelated host while the per-host cap remains exact.
    pending_h2_opens: Mutex<HashMap<String, usize>>,
    /// Live h3 (QUIC) connections per authority, selected by dispatch
    /// reservations. Each entry is a driver thread that multiplexes every
    /// request on one QUIC connection, so the TLS handshake is paid once
    /// per pooled connection instead of once per request.
    h3_pool: Mutex<HashMap<String, Vec<H3Conn>>>,
    /// Signaled whenever an h3 connection open lands (or fails), so
    /// callers waiting for the last connection slot wake instead of
    /// polling.
    h3_open_cv: std::sync::Condvar,
    /// h3 connections currently being opened, keyed by authority.
    pending_h3_opens: Mutex<HashMap<String, usize>>,
    /// TLS connectors per authority. Each connector owns a resumption-session
    /// store keyed by hostname, so a fresh connection to a host that already
    /// handed us a session ticket resumes (1-RTT) instead of paying a full
    /// handshake. The connector configuration (roots, verify, ALPN, version
    /// window) is fixed per client — it all comes from `ClientConfig::tls`.
    tls_connectors: Mutex<HashMap<String, Arc<crate::courierust_tls::TlsConnector>>>,
    /// Global request sequence (instrumentation).
    seq: AtomicUsize,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        // Stop every pooled h3 driver so its thread exits promptly once
        // the client is gone (they would otherwise linger until the idle
        // timeout). The driver replies with an error to anything it was
        // mid-flight on, which is unreachable anyway.
        let drivers: Vec<H3Conn> = {
            let pools = self.h3_pool.lock().unwrap();
            pools.values().flatten().cloned().collect()
        };
        for driver in drivers {
            let _ = driver.send(H3Cmd::Shutdown);
        }
    }
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
                ..Default::default()
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
                h2_open_cv: std::sync::Condvar::new(),
                pending_h2_opens: Mutex::new(HashMap::new()),
                h3_pool: Mutex::new(HashMap::new()),
                h3_open_cv: std::sync::Condvar::new(),
                pending_h3_opens: Mutex::new(HashMap::new()),
                tls_connectors: Mutex::new(HashMap::new()),
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

    /// Perform a PUT request with a body.
    pub fn put(&self, url: &str, body: impl Into<Body>) -> Result<Response<Body>> {
        let mut req = Request::<Body>::new(Method::PUT, "/");
        req.body = body.into();
        self.execute(url, req)
    }

    /// Perform a DELETE request.
    ///
    /// `DELETE` carries no body (RFC 9110 §9.3.5): a server that wants
    /// one can be asked with [`Client::request`] and an explicit body.
    pub fn delete(&self, url: &str) -> Result<Response<Body>> {
        self.execute(url, Request::<Body>::new(Method::DELETE, "/"))
    }

    /// Perform a HEAD request. The response has no body by definition
    /// (RFC 9110 §9.3.2), so the status and headers are the whole answer.
    pub fn head(&self, url: &str) -> Result<Response<Body>> {
        self.execute(url, Request::<Body>::new(Method::HEAD, "/"))
    }

    /// Perform a PATCH request with a body.
    pub fn patch(&self, url: &str, body: impl Into<Body>) -> Result<Response<Body>> {
        let mut req = Request::<Body>::new(Method::PATCH, "/");
        req.body = body.into();
        self.execute(url, req)
    }

    /// Perform an OPTIONS request.
    pub fn options(&self, url: &str) -> Result<Response<Body>> {
        self.execute(url, Request::<Body>::new(Method::OPTIONS, "/"))
    }

    /// Start building the request this builder chain will send.
    ///
    /// ```no_run
    /// # use courierust::courierust_client::Client;
    /// # use courierust::courierust_http::Method;
    /// # fn main() -> courierust::Result<()> {
    /// let client = Client::new();
    /// let resp = client
    ///     .request("http://127.0.0.1:8080/things", Method::POST)
    ///     .query([("dry_run", "1")])
    ///     .header("accept", "application/json")
    ///     .body("{}")
    ///     .send()?;
    /// # let _ = resp;
    /// # Ok(())
    /// # }
    /// ```
    pub fn request(&self, url: &str, method: Method) -> RequestBuilder<'_> {
        RequestBuilder::new(self, url.to_string(), method)
    }

    /// Perform a request against `url`. The request's `uri` is used as the
    /// path; the URL supplies scheme/host/port.
    pub fn execute(&self, url: &str, req: Request<Body>) -> Result<Response<Body>> {
        let parsed = Url::parse(url)?;
        self.execute_with_redirects(&parsed, req, Priority::default(), None, 0)
    }

    /// Dispatch a request assembled by [`RequestBuilder`].
    pub(crate) fn execute_built(
        &self,
        url: &str,
        req: Request<Body>,
        priority: Priority,
        timeout: Option<Duration>,
    ) -> Result<Response<Body>> {
        let parsed = Url::parse(url)?;
        self.execute_with_redirects(&parsed, req, priority, timeout, 0)
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
        validate_target(url, &req)?;
        let tls = self.tls_for_scheme(&url.scheme, &url.authority())?;
        let addr = self.dial_address(url)?;
        let authority = url.authority();
        self.execute_h2(url, &authority, addr, tls, req, priority, None)
    }

    fn execute_with_redirects(
        &self,
        url: &Url,
        req: Request<Body>,
        priority: Priority,
        timeout: Option<Duration>,
        depth: usize,
    ) -> Result<Response<Body>> {
        // Every hop is checked, redirect targets included: a `Location`
        // that carries credentials this client would silently drop is the
        // same bug as one in the original URL.
        validate_target(url, &req)?;
        // The client's default fields are merged into the request this
        // call initiates — and only that one. A redirect hop is a new
        // request *derived from* the original: its fields were merged
        // already, and the credential stripping below removed the ones a
        // cross-origin hop must not carry. Merging again here would put a
        // default `authorization` back on that hop, which is precisely
        // what the stripping exists to prevent.
        let req = if depth == 0 {
            self.with_default_headers(req)
        } else {
            req
        };
        // Capture the head before the request is consumed by the network.
        let orig_method = req.method.clone();
        let orig_headers = req.headers.clone();
        // A body can be replayed only if it is still in memory; a streamed
        // body has already been consumed by the first attempt.
        let replay_body = match &req.body {
            Body::Empty => Some(Body::Empty),
            Body::Bytes(b) => Some(Body::Bytes(b.clone())),
            Body::Channel(_) | Body::Stream(_) => None,
        };
        let resp = self.execute_inner(url, req, priority, timeout)?;
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
                let mut new_req = Request::new(method.clone(), next.path_and_query.clone());
                let mut headers = orig_headers;
                // Strip credentials on any cross-origin hop — either an
                // authority change OR a scheme downgrade (https→http even
                // on the same port, e.g. https://host:8443 →
                // http://host:8443). Reusing the same port keeps the
                // authority equal, so authority alone is not sufficient.
                if next.authority() != url.authority() || next.scheme != url.scheme {
                    for name in ["authorization", "proxy-authorization", "cookie"] {
                        headers.remove(name);
                    }
                }
                // RFC 9110 §15.4: 303 always becomes GET, 301/302 may turn
                // a POST into GET, and 307/308 MUST keep the method *and*
                // the content. Dropping the body while keeping the method
                // turned a redirected PUT (or a 307 POST) into a
                // different request that the origin is entitled to act on.
                let body =
                    if method == Method::GET {
                        // A GET carries no content: leaving `content-length`
                        // behind would make the peer wait for a body that is
                        // never sent.
                        headers.remove("content-length");
                        headers.remove("transfer-encoding");
                        Body::Empty
                    } else {
                        match replay_body {
                            Some(b) => b,
                            None => return Err(Error::protocol(
                                "cannot follow a redirect that must replay a streamed request body",
                            )),
                        }
                    };
                new_req.headers = headers;
                new_req.body = body;
                return self.execute_with_redirects(&next, new_req, priority, timeout, depth + 1);
            }
        }
        Ok(resp)
    }

    /// The peer a request's transport is opened against: the origin, or
    /// the configured proxy, through which the origin is reached with a
    /// `CONNECT` tunnel.
    ///
    /// The address names the socket that is actually dialled because the
    /// connection pools compare it (a pooled connection is only reused
    /// for the peer it was opened against).
    fn dial_address(&self, url: &Url) -> Result<SocketAddr> {
        match &self.inner.config.proxy {
            Some(proxy) => resolve_addr(&proxy.host, proxy.port),
            None => resolve_addr(&url.host, url.port),
        }
    }

    /// Open the TCP transport for `authority` at `addr`.
    ///
    /// With a proxy configured, a *secure* target is reached through a
    /// `CONNECT` tunnel (the proxy must not be able to see inside it) and
    /// a plaintext one is sent to the proxy itself, whose request target
    /// then names the origin — tunnelling plaintext would hide the
    /// request from the proxy that is there to see it. `addr` is the
    /// proxy in both cases.
    fn open_transport(
        &self,
        addr: SocketAddr,
        authority: &str,
        secure: bool,
    ) -> Result<std::net::TcpStream> {
        match &self.inner.config.proxy {
            Some(_) if !secure => {
                crate::courierust_net::connect(&addr, self.inner.config.connect_timeout)
            }
            Some(proxy) => {
                proxy::connect_through(proxy, authority, self.inner.config.connect_timeout)
                    .map(|(_, stream)| stream)
            }
            None => crate::courierust_net::connect(&addr, self.inner.config.connect_timeout),
        }
    }

    /// Open an h1 connection for `authority`, told which peer it is talking
    /// to: a proxy the request is addressed to, or the origin itself.
    ///
    /// Both construction sites in `execute_h1` — the first attempt and the
    /// stale-connection retry — go through here, so a retry cannot end up
    /// on a different kind of hop than the attempt it replaces.
    fn open_h1(
        &self,
        addr: SocketAddr,
        authority: &str,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
        to_proxy: bool,
    ) -> Result<H1Connection> {
        let stream = self.open_transport(addr, authority, tls.is_some())?;
        if to_proxy {
            H1Connection::from_proxy_socket(stream, tls, hostname, &self.inner.config)
        } else {
            H1Connection::from_socket(stream, tls, hostname, &self.inner.config)
        }
    }

    fn execute_inner(
        &self,
        url: &Url,
        req: Request<Body>,
        priority: Priority,
        timeout: Option<Duration>,
    ) -> Result<Response<Body>> {
        let req = if req.uri.as_str() == "/" && url.path_and_query.as_str() != "/" {
            let mut req = req;
            req.uri = url.path_and_query.clone();
            req
        } else {
            req
        };
        let authority = url.authority();
        let tls = self.tls_for_scheme(&url.scheme, &authority)?;
        self.inner.seq.fetch_add(1, Ordering::Relaxed);
        let addr = self.dial_address(url)?;
        if self.inner.config.http3 {
            if url.scheme != "https" {
                return Err(Error::protocol("HTTP/3 requires an https:// URL"));
            }
            if self.inner.config.tls.is_none() {
                return Err(Error::protocol("HTTP/3 requires TLS settings"));
            }
            if self.inner.config.proxy.is_some() {
                // QUIC is UDP; an HTTP proxy's CONNECT tunnel is TCP. A
                // half-proxy (some requests through it, some around it)
                // would silently leak the ones it does not cover, so the
                // combination is refused instead.
                return Err(Error::protocol(
                    "HTTP/3 cannot go through an HTTP proxy: QUIC is UDP, the proxy's \
                     CONNECT tunnel is TCP; disable http3 or the proxy",
                ));
            }
            return self.execute_h3(url, &authority, addr, req, timeout);
        }
        if self.inner.config.proxy.is_some() && url.scheme == "http" && self.inner.config.http2 {
            // h2c is HTTP/2 in the clear. A proxy routes plaintext by
            // reading an HTTP/1.1 request (absolute form) and would parse
            // HTTP/2 frames instead; the tunnel it could carry them in is
            // reserved for encrypted targets. Refusing says so; sending
            // the frames anyway would look like a protocol error at the
            // proxy.
            return Err(Error::protocol(
                "h2c cannot go through an HTTP proxy: the proxy speaks HTTP/1.1; use https (an h2 \
                 tunnel) or disable http2",
            ));
        }
        if self.inner.config.http2 {
            if self.inner.config.h2c_upgrade && url.scheme == "http" {
                return self.execute_h2c_upgrade(url, &authority, addr, req, timeout);
            }
            let raw = self.execute_h2(url, &authority, addr, tls, req, priority, timeout)?;
            Ok(Response {
                status: raw.head.status,
                version: raw.head.version,
                headers: raw.head.headers,
                body: raw.body,
                trailers: None,
            })
        } else {
            self.execute_h1(url, &authority, addr, tls, req, timeout)
        }
    }

    /// Merge [`ClientConfig::default_headers`] into `req`, leaving every
    /// field the request already carries untouched.
    ///
    /// Merging here — once, before dispatch — is what keeps the three
    /// protocols consistent: h1 assembles its own field list, h2 builds
    /// HPACK fields from the request, and h3 hands the request to a
    /// driver thread; only a request that already carries the defaults
    /// reaches all three the same way.
    fn with_default_headers(&self, mut req: Request<Body>) -> Request<Body> {
        for (name, value) in self.inner.config.default_headers.iter() {
            if !req.headers.contains_key(name.as_str()) {
                req.headers.append(name.clone(), value.clone());
            }
        }
        req
    }

    /// Resolve the TLS connector for a scheme, or reject unsupported /
    /// unconfigured `https`.
    ///
    /// Connectors are cached per authority (bounded), so the resumption
    /// sessions captured on one connection to a host are offered on the
    /// next fresh connection to the same host — a full TLS handshake is
    /// paid once per authority, not once per connection. Past the cache
    /// cap a new connector is created without caching (a defensive bound
    /// against unbounded growth for a client touching thousands of hosts).
    fn tls_for_scheme(
        &self,
        scheme: &str,
        authority: &str,
    ) -> Result<Option<crate::courierust_tls::TlsConnector>> {
        match scheme {
            "http" => Ok(None),
            "https" => match &self.inner.config.tls {
                Some(t) => {
                    let mut cache = self.inner.tls_connectors.lock().unwrap();
                    if cache.len() >= TLS_CONNECTOR_CACHE_MAX && !cache.contains_key(authority) {
                        return Ok(Some(crate::courierust_tls::TlsConnector::new(
                            connector_config(t),
                        )));
                    }
                    let connector = cache.entry(authority.to_string()).or_insert_with(|| {
                        Arc::new(crate::courierust_tls::TlsConnector::new(connector_config(
                            t,
                        )))
                    });
                    Ok(Some((**connector).clone()))
                }
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
        timeout: Option<Duration>,
    ) -> Result<Response<Body>> {
        let key = h1_pool_key(url.scheme == "https", authority);
        let hostname = url.host.clone();
        // Whether this connection's peer is a proxy the request is
        // addressed to: the plaintext path, where the absolute form is
        // what tells the proxy where to forward. A secure target goes
        // through a tunnel instead, and the proxy never sees the request.
        let to_proxy = self.inner.config.proxy.is_some() && url.scheme == "http";

        // Plaintext through a proxy: the proxy is the server, so the
        // request target names the origin (RFC 9112 §3.2.2 absolute
        // form) and carries the proxy's credentials. A `CONNECT` tunnel
        // and every direct request keep origin-form — there the request
        // really is for the host in `Host`.
        let req = match self.inner.config.proxy.as_ref() {
            Some(proxy) if url.scheme == "http" => {
                // The target is origin-form or asterisk-form by now
                // (`validate_target` refused anything else). In the
                // absolute form the proxy needs, an asterisk target —
                // `OPTIONS *`, which names the server itself — becomes
                // the URI with an empty path; the last proxy turns it
                // back into `*` (RFC 9110 §9.3.7).
                let target = req.uri.as_str();
                let mut absolute = String::with_capacity(authority.len() + target.len() + 8);
                absolute.push_str("http://");
                absolute.push_str(authority);
                if target != "*" {
                    absolute.push_str(target);
                }
                let mut req = req;
                req.uri =
                    crate::courierust_http::uri::PathAndQuery::from_bytes(absolute.as_bytes())?;
                // The configured credentials are a *default*: one the
                // request already carries wins, exactly as with
                // `ClientConfig::default_headers`. Appending would send
                // the proxy two `Proxy-Authorization` fields and leave it
                // to pick one.
                if !req.headers.contains_key("proxy-authorization") {
                    if let Some(authorization) = proxy.authorization() {
                        req.headers.append(
                            crate::courierust_http::header::HeaderName::from_static(
                                "proxy-authorization",
                            ),
                            crate::courierust_http::header::HeaderValue::from_bytes(
                                authorization.as_bytes(),
                            )?,
                        );
                    }
                }
                req
            }
            _ => req,
        };

        // A pooled keep-alive connection can die while it sits idle (the
        // server's own idle timeout, a proxy, a restart). Probing before
        // writing anything is what makes that free: a spent connection is
        // dropped here, so no request — not even a non-idempotent one —
        // is put on the wire to discover it.
        let mut reused = false;
        let mut owned = loop {
            let pooled = {
                let mut pool = self.inner.h1_pool.lock().unwrap();
                let entry = pool.entry(key.clone()).or_default();
                entry
                    .iter()
                    .position(|(a, _)| *a == addr)
                    .map(|i| entry.remove(i).1)
            };
            match pooled {
                Some(conn) if conn.is_alive() => {
                    reused = true;
                    break conn;
                }
                // Spent: dropped, and the next pooled connection (if any)
                // is tried before opening a new one.
                Some(_) => continue,
                None => break self.open_h1(addr, authority, tls.as_ref(), &hostname, to_proxy)?,
            }
        };

        // A per-request deadline replaces the configured read timeout for
        // this request only. The socket must end up with the configured
        // value again — the connection goes back to the pool, where the
        // next caller would otherwise inherit a stranger's deadline — so
        // the override is applied only when there is one, which also
        // keeps the steady state free of socket reconfiguration.
        let deadline = timeout.filter(|d| Some(*d) != self.inner.config.read_timeout);
        if let Some(d) = deadline {
            let _ = owned.set_read_deadline(Some(d));
        }
        let result = owned.send(&req, &self.inner.config, authority);
        if deadline.is_some() {
            let _ = owned.set_read_deadline(self.inner.config.read_timeout);
        }
        match result {
            Ok(resp) => {
                if owned.is_reusable() {
                    let mut pool = self.inner.h1_pool.lock().unwrap();
                    let entry = pool.entry(key).or_default();
                    if entry.len() < self.inner.config.max_connections_per_host {
                        entry.push((addr, owned));
                    }
                }
                Ok(resp)
            }
            Err(error) => {
                // A reused connection that failed before the peer answered
                // a single byte was almost certainly already gone when the
                // request was written: retry it once on a fresh
                // connection. Only methods that are safe to replay
                // (RFC 9110 §9.2.2) qualify — a POST may well have been
                // executed, so its error is returned instead of risking a
                // second execution.
                if reused && req.method.is_idempotent() && owned.is_stale_failure(&error) {
                    let mut retry =
                        self.open_h1(addr, authority, tls.as_ref(), &hostname, to_proxy)?;
                    if let Some(d) = deadline {
                        let _ = retry.set_read_deadline(Some(d));
                    }
                    let resp = retry.send(&req, &self.inner.config, authority);
                    if deadline.is_some() {
                        let _ = retry.set_read_deadline(self.inner.config.read_timeout);
                    }
                    let resp = resp?;
                    if retry.is_reusable() {
                        let mut pool = self.inner.h1_pool.lock().unwrap();
                        let entry = pool.entry(key).or_default();
                        if entry.len() < self.inner.config.max_connections_per_host {
                            entry.push((addr, retry));
                        }
                    }
                    return Ok(resp);
                }
                Err(error)
            }
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
        validate_target(url, &req)?;
        let tls = self.tls_for_scheme(&url.scheme, &url.authority())?;
        let addr = self.dial_address(url)?;
        let authority = url.authority();
        self.execute_h2(url, &authority, addr, tls, req, priority, None)
    }

    // The `authority`/`addr`/`tls` bundle stays flat for the same reason
    // as in `send_h2_cmd`: every retry path re-opens a connection with
    // exactly these parameters.
    #[allow(clippy::too_many_arguments)]
    fn execute_h2(
        &self,
        url: &Url,
        authority: &str,
        addr: SocketAddr,
        tls: Option<crate::courierust_tls::TlsConnector>,
        req: Request<Body>,
        priority: Priority,
        timeout: Option<Duration>,
    ) -> Result<crate::courierust_client::h2::H2Response> {
        // Both raw entry points (`execute_h2_raw`, `execute_h2_stream`)
        // and the general path land here, so this is where a request
        // picks up the client's default fields whichever one it came
        // from.
        let req = self.with_default_headers(req);
        // Body bytes feed the weighted connection-selection load: a
        // connection carrying a large upload is more expensive on the wire
        // than one carrying several header-only RPCs, so the pool weights
        // by size, not just by stream count. Unknown (streaming) bodies
        // weigh 0 — an honest "don't know", not a guess.
        let body_bytes = req.body.len().unwrap_or(0);
        let conn = self.get_h2_conn(authority, addr, tls.as_ref(), &url.host, body_bytes)?;
        let fields = h2::request_fields(&req, &url.scheme, authority);
        let (tx, rx) = std::sync::mpsc::channel();
        let cmd = build_h2_cmd(fields, req.body, priority, timeout, tx);
        self.send_h2_cmd(
            conn,
            authority,
            addr,
            tls.as_ref(),
            &url.host,
            cmd,
            rx,
            body_bytes,
        )
    }

    /// Perform a request over a pooled h3 (QUIC) connection. The first
    /// request for an authority opens a connection (QUIC handshake + TLS);
    /// subsequent requests multiplex over the pooled connection, so the
    /// per-request cost drops to a single QUIC round trip.
    fn execute_h3(
        &self,
        url: &Url,
        authority: &str,
        addr: SocketAddr,
        req: Request<Body>,
        timeout: Option<Duration>,
    ) -> Result<Response<Body>> {
        let tls = self
            .inner
            .config
            .tls
            .as_ref()
            .ok_or_else(|| Error::protocol("HTTP/3 requires TLS settings"))?;
        let options = crate::courierust_h3::runtime::ClientRequestOptions {
            roots: tls.roots.clone(),
            verify: tls.verify,
            now: tls.now,
            max_header_list: self.inner.config.max_header_list,
            max_body: self.inner.config.max_body,
            timeout: self.inner.config.read_timeout,
            stats: self.inner.config.stats.clone(),
        };
        let conn = self.get_h3_conn(authority, addr, &url.host, &options)?;
        let (tx, rx) = std::sync::mpsc::channel();
        let cmd = H3Cmd::Request {
            request: req,
            reply: tx,
            timeout,
        };
        self.send_h3_cmd(conn, authority, addr, &url.host, options, cmd, rx)
    }

    /// Select (or open) a pooled h3 connection for `authority`. Mirrors
    /// `get_h2_conn`: opens outside the pool lock, caps per-authority
    /// connections, and lets concurrent callers sleep on the condvar while
    /// the last slot is being opened.
    fn get_h3_conn(
        &self,
        authority: &str,
        addr: SocketAddr,
        hostname: &str,
        options: &crate::courierust_h3::runtime::ClientRequestOptions,
    ) -> Result<H3Conn> {
        let max_connections = self.inner.config.max_connections_per_host.max(1);
        loop {
            let mut open = false;
            let mut should_wait = false;
            {
                let mut pools = self.inner.h3_pool.lock().unwrap();
                let mut pending = self.inner.pending_h3_opens.lock().unwrap();
                let list = pools.entry(authority.to_string()).or_default();
                list.retain(|c| c.accepting.load(Ordering::Acquire));
                let least_loaded = list
                    .iter()
                    .filter(|c| c.accepting.load(Ordering::Acquire))
                    .min_by_key(|c| c.reservations())
                    .cloned();
                if let Some(conn) = least_loaded {
                    if conn.reservations() == 0 || list.len() >= max_connections {
                        conn.reserve();
                        return Ok(conn);
                    }
                }
                let pending_count = pending.get(authority).copied().unwrap_or(0);
                if list.len() + pending_count < max_connections {
                    *pending.entry(authority.to_string()).or_default() += 1;
                    open = true;
                } else if pending_count > 0 {
                    should_wait = true;
                }
            }
            if !open {
                if should_wait {
                    let guard = self.inner.h3_pool.lock().unwrap();
                    let (guard, _) = self
                        .inner
                        .h3_open_cv
                        .wait_timeout(guard, Duration::from_millis(200))
                        .expect("h3 pool lock poisoned");
                    drop(guard);
                    continue;
                }
                break;
            }

            // Open outside the pool lock (a QUIC connect + TLS handshake
            // must not serialize every concurrent requester).
            let opened = (|| -> Result<H3Conn> {
                let conn = crate::courierust_h3::runtime::start_h3_driver(
                    addr,
                    hostname.to_string(),
                    authority.to_string(),
                    options.clone(),
                    self.inner.config.h3_idle_timeout,
                )?;
                let mut pools = self.inner.h3_pool.lock().unwrap();
                let mut pending = self.inner.pending_h3_opens.lock().unwrap();
                let list = pools.entry(authority.to_string()).or_default();
                list.retain(|c| c.accepting.load(Ordering::Acquire));
                decrement_pending_h3_open(&mut pending, authority);
                if list.len() < max_connections {
                    list.push(conn.clone());
                }
                self.inner.h3_open_cv.notify_all();
                Ok(conn)
            })();
            match opened {
                Ok(conn) => {
                    conn.reserve();
                    return Ok(conn);
                }
                Err(e) => {
                    let pools = self.inner.h3_pool.lock().unwrap();
                    let mut pending = self.inner.pending_h3_opens.lock().unwrap();
                    decrement_pending_h3_open(&mut pending, authority);
                    self.inner.h3_open_cv.notify_all();
                    drop(pools);
                    return Err(e);
                }
            }
        }

        // Rare fallback after a long open race: block on the
        // least-loaded live connection (its dispatch queue drains).
        let mut pools = self.inner.h3_pool.lock().unwrap();
        let list = pools.entry(authority.to_string()).or_default();
        let conn = list
            .iter()
            .filter(|c| c.accepting.load(Ordering::Acquire))
            .min_by_key(|c| c.reservations())
            .cloned()
            .ok_or_else(|| Error::canceled("no accepting h3 connection"))?;
        conn.reserve();
        Ok(conn)
    }

    /// Send a driver command, retrying once on a fresh connection if the
    /// driver is gone, then wait for the reply.
    //
    // The `authority`/`addr`/`hostname`/`options` bundle is deliberately
    // kept flat here (and in `get_h3_conn`) so the retry path can re-open
    // a fresh connection with exactly the same parameters.
    #[allow(clippy::too_many_arguments)]
    fn send_h3_cmd(
        &self,
        conn: H3Conn,
        authority: &str,
        addr: SocketAddr,
        hostname: &str,
        options: crate::courierust_h3::runtime::ClientRequestOptions,
        cmd: H3Cmd,
        rx: std::sync::mpsc::Receiver<Result<Response<Body>>>,
    ) -> Result<Response<Body>> {
        match conn.send(cmd) {
            Ok(()) => {
                let result = rx
                    .recv()
                    .map_err(|_| Error::canceled("h3 driver closed the channel"))
                    .and_then(|result| result);
                conn.release();
                result
            }
            Err(std::sync::mpsc::SendError(cmd)) => {
                // The driver is gone; open a fresh connection and retry.
                conn.accepting.store(false, Ordering::Release);
                conn.release();
                // `get_h3_conn` already reserves for the retried request;
                // a second `reserve` here would leak one unit per retry.
                let fresh = self.get_h3_conn(authority, addr, hostname, &options)?;
                let (tx2, rx2) = std::sync::mpsc::channel();
                let cmd2 = match cmd {
                    H3Cmd::Request {
                        request, timeout, ..
                    } => H3Cmd::Request {
                        request,
                        reply: tx2,
                        timeout,
                    },
                    H3Cmd::Shutdown => H3Cmd::Shutdown,
                };
                let result = match fresh.send(cmd2) {
                    Ok(()) => rx2
                        .recv()
                        .map_err(|_| Error::canceled("h3 driver is gone"))
                        .and_then(|result| result),
                    Err(_) => Err(Error::canceled("h3 driver is gone")),
                };
                fresh.release();
                result
            }
        }
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
        timeout: Option<Duration>,
    ) -> Result<Response<Body>> {
        let req_method = req.method.clone();
        let body_bytes = req.body.len().unwrap_or(0);
        let pooled = {
            let mut pools = self.inner.h2_pool.lock().unwrap();
            pools.get_mut(authority).and_then(|list| {
                list.retain(|c| c.accepting.load(Ordering::Acquire));
                let max_connections = self.inner.config.max_connections_per_host.max(1);
                // Idle-first (see `get_h2_conn`): a free connection is
                // reused regardless of its EWMA history.
                let idle = list
                    .iter()
                    .filter(|c| c.accepting.load(Ordering::Acquire))
                    .find(|c| c.is_idle())
                    .cloned();
                let conn = idle.or_else(|| {
                    list.iter()
                        .filter(|c| c.accepting.load(Ordering::Acquire))
                        .min_by_key(|c| c.load())
                        .cloned()
                })?;
                if conn.is_idle() || list.len() >= max_connections {
                    conn.reserve(body_bytes);
                    Some(conn)
                } else {
                    None
                }
            })
        };
        if let Some(conn) = pooled {
            let fields = h2::request_fields(&req, &url.scheme, authority);
            let (tx, rx) = std::sync::mpsc::channel();
            let cmd = build_h2_cmd(fields, req.body, Priority::default(), timeout, tx);
            return self
                .send_h2_cmd(conn, authority, addr, None, &url.host, cmd, rx, body_bytes)
                .map(|raw| Response {
                    status: raw.head.status,
                    version: raw.head.version,
                    headers: raw.head.headers,
                    body: raw.body,
                    trailers: None,
                });
        }

        let stream = self.open_transport(addr, authority, false)?;
        crate::courierust_net::configure(&stream, timeout.or(self.inner.config.read_timeout))?;
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
                conn.reserve(body_bytes);
                {
                    let mut pools = self.inner.h2_pool.lock().unwrap();
                    let list = pools.entry(authority.to_string()).or_default();
                    list.retain(|c| c.accepting.load(Ordering::Acquire));
                    if list.len() < self.inner.config.max_connections_per_host.max(1) {
                        list.push(conn.clone());
                    }
                }
                let raw = rx
                    .recv()
                    .map_err(|_| Error::canceled("h2 driver closed the channel"))
                    .and_then(|result| result);
                conn.release(body_bytes);
                let raw = raw?;
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
                let resp = owned.finish_response(&self.inner.config, &req_method, head)?;
                if owned.is_reusable() {
                    let mut pool = self.inner.h1_pool.lock().unwrap();
                    let entry = pool.entry(h1_pool_key(false, authority)).or_default();
                    if entry.len() < self.inner.config.max_connections_per_host {
                        entry.push((addr, owned));
                    }
                }
                Ok(resp)
            }
        }
    }

    /// Send a driver command, retrying once on a fresh connection if the
    /// driver is gone, then wait for the reply. `body_bytes` is the same
    /// value the pool reserved with, so the weighted reservation is
    /// released exactly once on every path.
    //
    // The `authority`/`addr`/`tls`/`hostname` bundle is deliberately kept
    // flat here (and in `get_h2_conn`) so the retry path
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
        body_bytes: usize,
    ) -> Result<crate::courierust_client::h2::H2Response> {
        match conn.tx.send(cmd) {
            Ok(()) => {
                let started = Instant::now();
                let result = rx
                    .recv()
                    .map_err(|_| Error::canceled("h2 driver closed the channel"))
                    .and_then(|result| result);
                conn.note_service_us(started.elapsed().as_micros() as u64);
                conn.release(body_bytes);
                result
            }
            Err(std::sync::mpsc::SendError(cmd)) => {
                conn.accepting.store(false, Ordering::Release);
                conn.release(body_bytes);
                // `get_h2_conn` already reserves for the retried request;
                // a second `reserve` here would leak one unit per retry.
                let fresh = self.get_h2_conn(authority, addr, tls, hostname, body_bytes)?;
                let (tx2, rx2) = std::sync::mpsc::channel();
                let cmd2 = retarget_reply(cmd, tx2);
                let started = Instant::now();
                let result = match fresh.tx.send(cmd2) {
                    Ok(()) => rx2
                        .recv()
                        .map_err(|_| Error::canceled("h2 driver closed the channel"))
                        .and_then(|result| result),
                    Err(_) => Err(Error::canceled("h2 driver is gone")),
                };
                fresh.note_service_us(started.elapsed().as_micros() as u64);
                fresh.release(body_bytes);
                result
            }
        }
    }

    fn get_h2_conn(
        &self,
        authority: &str,
        addr: SocketAddr,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
        body_bytes: usize,
    ) -> Result<H2Conn> {
        let max_connections = self.inner.config.max_connections_per_host.max(1);
        // Opening a connection (TCP connect + optional TLS handshake +
        // driver thread spawn) can take milliseconds. It must NOT run
        // while holding the shared pool lock, or one slow open serializes
        // every concurrent requester (the 32-worker h2 regression). A
        // `pending_h2_opens` counter (guarded by the same lock) keeps the
        // per-authority cap exact while the connect runs unlocked, and a
        // condition variable lets concurrent callers sleep until the
        // opener lands instead of spinning or failing on a transiently
        // empty pool.
        loop {
            let mut open = false;
            let mut should_wait = false;
            {
                let mut pools = self.inner.h2_pool.lock().unwrap();
                let mut pending = self.inner.pending_h2_opens.lock().unwrap();
                let list = pools.entry(authority.to_string()).or_default();
                list.retain(|c| c.accepting.load(Ordering::Acquire));
                // An idle connection is free regardless of its latency
                // history: prefer it outright, so a stale EWMA sample can
                // never block keep-alive reuse (an idle connection's EWMA
                // only decays on new samples, so a weighted-min pick that
                // considered it would skip it forever).
                if let Some(conn) = list
                    .iter()
                    .filter(|c| c.accepting.load(Ordering::Acquire))
                    .find(|c| c.is_idle())
                    .cloned()
                {
                    conn.reserve(body_bytes);
                    return Ok(conn);
                }
                // All busy. At the per-authority cap pick the least
                // weighted load (streams + body bytes + EWMA); under the
                // cap open a fresh connection for wire parallelism.
                let least_loaded = list
                    .iter()
                    .filter(|c| c.accepting.load(Ordering::Acquire))
                    .min_by_key(|c| c.load())
                    .cloned();
                if let Some(conn) = least_loaded {
                    if list.len() >= max_connections {
                        conn.reserve(body_bytes);
                        return Ok(conn);
                    }
                }

                let pending_count = pending.get(authority).copied().unwrap_or(0);
                if list.len() + pending_count < max_connections {
                    *pending.entry(authority.to_string()).or_default() += 1;
                    open = true;
                } else if pending_count > 0 {
                    should_wait = true;
                }
            }
            if !open {
                if should_wait {
                    let guard = self.inner.h2_pool.lock().unwrap();
                    let (guard, _) = self
                        .inner
                        .h2_open_cv
                        .wait_timeout(guard, Duration::from_millis(200))
                        .expect("h2 pool lock poisoned");
                    drop(guard);
                    continue;
                }
                break;
            }

            // Open outside the pool lock.
            let opened = (|| -> Result<H2Conn> {
                let stream = self.open_h2_stream(addr, authority, tls, hostname)?;
                let conn = h2::start(stream, &self.inner.config)?;
                let mut pools = self.inner.h2_pool.lock().unwrap();
                let mut pending = self.inner.pending_h2_opens.lock().unwrap();
                let list = pools.entry(authority.to_string()).or_default();
                list.retain(|c| c.accepting.load(Ordering::Acquire));
                decrement_pending_h2_open(&mut pending, authority);
                if list.len() < max_connections {
                    list.push(conn.clone());
                }
                self.inner.h2_open_cv.notify_all();
                Ok(conn)
            })();
            match opened {
                Ok(conn) => {
                    conn.reserve(body_bytes);
                    return Ok(conn);
                }
                Err(e) => {
                    let pools = self.inner.h2_pool.lock().unwrap();
                    let mut pending = self.inner.pending_h2_opens.lock().unwrap();
                    decrement_pending_h2_open(&mut pending, authority);
                    self.inner.h2_open_cv.notify_all();
                    drop(pools);
                    return Err(e);
                }
            }
        }
        let mut pools = self.inner.h2_pool.lock().unwrap();
        let list = pools.entry(authority.to_string()).or_default();
        let conn = list
            .iter()
            .filter(|c| c.accepting.load(Ordering::Acquire))
            .min_by_key(|c| c.load())
            .cloned()
            .ok_or_else(|| Error::canceled("no accepting h2 connection"))?;
        conn.reserve(body_bytes);
        Ok(conn)
    }

    /// Open a raw (possibly TLS-wrapped) stream for the h2 driver.
    ///
    /// `authority` is the origin (`host:port`): a configured proxy is
    /// reached by tunnelling to it.
    fn open_h2_stream(
        &self,
        addr: SocketAddr,
        authority: &str,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
    ) -> Result<crate::courierust_net::ConnStream> {
        let stream = self.open_transport(addr, authority, tls.is_some())?;
        match tls {
            Some(c) => {
                let _ =
                    crate::courierust_net::configure(&stream, self.inner.config.handshake_timeout);
                let conn = crate::courierust_net::ConnStream::tls_client(stream, c, hostname)?;

                match conn.alpn() {
                    Some(alpn) if alpn.as_slice() == b"h2" => {}
                    Some(alpn) => {
                        return Err(Error::protocol(format!(
                            "server negotiated {:?}, not h2; set ClientConfig.tls.alpn to offer h2",
                            String::from_utf8_lossy(&alpn)
                        )));
                    }
                    None if self.inner.config.tls.is_some() => {
                        return Err(Error::protocol(
                            "server did not negotiate any ALPN protocol; \
                             HTTP/2 over TLS requires ALPN h2",
                        ));
                    }
                    None => {}
                }
                Ok(conn)
            }
            None => Ok(crate::courierust_net::ConnStream::plain(stream)),
        }
    }
}

fn decrement_pending_h2_open(pending: &mut HashMap<String, usize>, authority: &str) {
    let remove = match pending.get_mut(authority) {
        Some(count) => {
            *count = count.saturating_sub(1);
            *count == 0
        }
        None => false,
    };
    if remove {
        pending.remove(authority);
    }
}

fn decrement_pending_h3_open(pending: &mut HashMap<String, usize>, authority: &str) {
    let remove = match pending.get_mut(authority) {
        Some(count) => {
            *count = count.saturating_sub(1);
            *count == 0
        }
        None => false,
    };
    if remove {
        pending.remove(authority);
    }
}

/// Build a driver command from a request's HPACK fields and body. A
/// channel body streams as DATA frames (`RequestStream`); anything else
/// is sent as one block with END_STREAM.
fn build_h2_cmd(
    fields: Vec<crate::courierust_hpack::HeaderField>,
    body: Body,
    priority: Priority,
    timeout: Option<Duration>,
    tx: std::sync::mpsc::Sender<Result<crate::courierust_client::h2::H2Response>>,
) -> H2Cmd {
    match body {
        Body::Channel(body_rx) => H2Cmd::RequestStream {
            fields,
            body: body_rx,
            priority,
            timeout,
            reply: tx,
        },
        Body::Stream(stream) => H2Cmd::RequestStream {
            fields,
            body: stream.into_receiver(),
            priority,
            timeout,
            reply: tx,
        },
        Body::Empty => H2Cmd::Request {
            fields,
            body: None,
            end_stream: true,
            priority,
            timeout,
            reply: tx,
        },
        Body::Bytes(b) => H2Cmd::Request {
            fields,
            body: Some(b),
            end_stream: true,
            priority,
            timeout,
            reply: tx,
        },
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
            timeout,
            ..
        } => H2Cmd::Request {
            fields,
            body,
            end_stream,
            priority,
            timeout,
            reply,
        },
        H2Cmd::RequestStream {
            fields,
            body,
            priority,
            timeout,
            ..
        } => H2Cmd::RequestStream {
            fields,
            body,
            priority,
            timeout,
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

/// Resolve `location` against `base` (RFC 3986 §5.2) and parse the result.
///
/// A `Location` field is a URI-*reference*, not necessarily an absolute
/// URL, and the difference is load-bearing: `g` resolves against the
/// current path's directory (`/a/b/c/d` → `/a/b/c/g`, not `/g`), `?y`
/// keeps the path and replaces only the query, `#f` keeps both, and `.` /
/// `..` segments are removed before the target is used. Getting any of
/// those wrong retries a *different resource* than the server asked for —
/// and, behind a proxy whose rules were written for the normalized form,
/// one it may not expect to see.
fn resolve_redirect(base: &Url, location: &str) -> Result<Url> {
    // Fragments are not transmitted in HTTP request targets.
    let location = location.split_once('#').map_or(location, |(head, _)| head);
    if let Some(rest) = location.strip_prefix("//") {
        // Network-path reference: same scheme, different authority.
        return Url::parse(&format!("{}://{rest}", base.scheme));
    }
    if location.contains("://") {
        return Url::parse(location);
    }
    let base_target = base.path_and_query.as_str();
    let (base_path, base_query) = split_query(base_target);
    let (ref_path, ref_query) = split_query(location);
    // RFC 3986 §5.2.2: an empty reference path keeps the base path *and*
    // the base query; otherwise the reference's query (possibly none)
    // wins.
    let query = match (ref_query, ref_path.is_empty()) {
        (Some(query), _) => Some(query.to_string()),
        (None, true) => base_query.map(str::to_string),
        (None, false) => None,
    };
    let path = if ref_path.is_empty() {
        base_path.to_string()
    } else if ref_path.starts_with('/') {
        remove_dot_segments(ref_path)
    } else {
        remove_dot_segments(&merge_paths(base_path, ref_path))
    };
    let mut target = if path.is_empty() {
        String::from("/")
    } else {
        path
    };
    if let Some(query) = query {
        target.push('?');
        target.push_str(&query);
    }
    Url::parse(&format!("{}://{}{target}", base.scheme, base.authority()))
}

/// Split an origin-form target into path and query.
fn split_query(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    }
}

/// RFC 3986 §5.3: replace everything after the last `/` of the base path.
fn merge_paths(base_path: &str, reference: &str) -> String {
    match base_path.rfind('/') {
        Some(index) => format!("{}{reference}", &base_path[..=index]),
        None => format!("/{reference}"),
    }
}

/// RFC 3986 §5.2.4, for the rooted paths this resolver produces.
///
/// A leading `..` has nothing to pop (the path starts at the root) and is
/// dropped; a trailing `/`, `/.` or `/..` keeps the result
/// directory-shaped; and an empty segment is a segment — `/a//b` is not
/// `/a/b`, and silently collapsing it would change which resource is
/// requested.
fn remove_dot_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut segments = path.split('/');
    if path.starts_with('/') {
        // The first segment of an absolute path is the empty one before
        // the root slash.
        segments.next();
    }
    for segment in segments {
        match segment {
            "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    let mut result = String::from("/");
    result.push_str(&out.join("/"));
    let directory_shaped = path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    if directory_shaped && !result.ends_with('/') {
        result.push('/');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_http::header::{HeaderName, HeaderValue};

    /// Two targets this client refuses to put on the wire, and why: a URL
    /// whose userinfo it would have to *drop*, and an absolute request
    /// target naming a different host than the connection is for. Both
    /// are refused before a socket exists, so the cost is a parse rather
    /// than a request that “succeeds” against the wrong peer. Asterisk
    /// form is the contrast case: `*` names the server itself, so it
    /// passes the guard and reaches the dial.
    #[test]
    fn refuses_url_credentials_and_absolute_targets() {
        let client = Client::new();

        let err = client
            .execute(
                "http://user:secret@127.0.0.1:1/",
                Request::new(Method::GET, "/"),
            )
            .expect_err("userinfo must be refused");
        assert!(err.to_string().contains("userinfo"), "{err}");

        let err = client
            .execute(
                "http://127.0.0.1:1/",
                Request::new(
                    Method::GET,
                    crate::courierust_http::uri::PathAndQuery::from_static("http://other/"),
                ),
            )
            .expect_err("an absolute target must be refused");
        assert!(err.to_string().contains("absolute request target"), "{err}");

        let err = client
            .execute(
                "http://127.0.0.1:1/",
                Request::new(
                    Method::OPTIONS,
                    crate::courierust_http::uri::PathAndQuery::from_static("*"),
                ),
            )
            .expect_err("nothing listens on port 1");
        assert!(
            !err.to_string().contains("absolute request target"),
            "`*` names this server and must reach the dial: {err}"
        );
    }

    /// Render a URL the way the RFC 3986 vectors write it: the default
    /// port is implicit, everything else is spelled out.
    fn pretty(url: &Url) -> String {
        let default_port =
            (url.scheme == "http" && url.port == 80) || (url.scheme == "https" && url.port == 443);
        if default_port {
            format!(
                "{}://{}{}",
                url.scheme,
                url.host,
                url.path_and_query.as_str()
            )
        } else {
            format!(
                "{}://{}:{}{}",
                url.scheme,
                url.host,
                url.port,
                url.path_and_query.as_str()
            )
        }
    }

    /// RFC 3986 §5.4: the reference-resolution examples, verbatim. These
    /// are the published vectors rather than cases invented here — a
    /// `Location` that is relative must resolve *inside* the base
    /// directory, `?y` must keep the path, `#s` must keep both, and dot
    /// segments must be removed before the target is used.
    #[test]
    fn redirect_resolution_follows_rfc_3986() {
        let base = Url::parse("http://a/b/c/d;p?q").unwrap();
        let cases: &[(&str, &str)] = &[
            ("g", "http://a/b/c/g"),
            ("./g", "http://a/b/c/g"),
            ("g/", "http://a/b/c/g/"),
            ("/g", "http://a/g"),
            // The parser normalizes an empty path to `/`.
            ("//g", "http://g/"),
            ("?y", "http://a/b/c/d;p?y"),
            ("g?y", "http://a/b/c/g?y"),
            ("#s", "http://a/b/c/d;p?q"),
            ("g#s", "http://a/b/c/g"),
            ("g?y#s", "http://a/b/c/g?y"),
            (";x", "http://a/b/c/;x"),
            ("g;x", "http://a/b/c/g;x"),
            ("g;x?y#s", "http://a/b/c/g;x?y"),
            ("", "http://a/b/c/d;p?q"),
            (".", "http://a/b/c/"),
            ("./", "http://a/b/c/"),
            ("..", "http://a/b/"),
            ("../", "http://a/b/"),
            ("../g", "http://a/b/g"),
            ("../..", "http://a/"),
            ("../../", "http://a/"),
            ("../../g", "http://a/g"),
            ("../../../g", "http://a/g"),
            ("../../../../g", "http://a/g"),
            ("/./g", "http://a/g"),
            ("/../g", "http://a/g"),
            ("g.", "http://a/b/c/g."),
            (".g", "http://a/b/c/.g"),
            ("g..", "http://a/b/c/g.."),
            ("..g", "http://a/b/c/..g"),
            ("./../g", "http://a/b/g"),
            ("./g/.", "http://a/b/c/g/"),
            ("g/./h", "http://a/b/c/g/h"),
            ("g/../h", "http://a/b/c/h"),
            ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
            ("g;x=1/../y", "http://a/b/c/y"),
            ("g?y/./x", "http://a/b/c/g?y/./x"),
            ("g?y/../x", "http://a/b/c/g?y/../x"),
            ("g#s/./x", "http://a/b/c/g"),
            ("g#s/../x", "http://a/b/c/g"),
        ];
        for (reference, expected) in cases {
            let resolved = resolve_redirect(&base, reference)
                .unwrap_or_else(|e| panic!("Location: {reference:?}: {e}"));
            assert_eq!(pretty(&resolved), *expected, "Location: {reference:?}");
        }

        // An empty path segment is a segment.
        let resolved = resolve_redirect(&base, "/a//b").unwrap();
        assert_eq!(pretty(&resolved), "http://a/a//b");

        // A non-default port and an https scheme survive resolution.
        let base = Url::parse("https://h:8443/x/y").unwrap();
        let resolved = resolve_redirect(&base, "z?q=1").unwrap();
        assert_eq!(pretty(&resolved), "https://h:8443/x/z?q=1");

        // The target still has to be a URL this client can connect to.
        assert!(resolve_redirect(&base, "ftp://elsewhere/x").is_err());
    }
    use crate::courierust_http::response::Response;
    use crate::courierust_server::{Server, ServerConfig, TlsSettings as ServerTls};
    use crate::courierust_tls::testdata;

    /// TLS session resumption, wired through the public client: the first
    /// request to an authority pays a full handshake and captures a
    /// session ticket; the second request (a fresh connection — the
    /// server answers `Connection: close`, so the keep-alive pool never
    /// reuses) reuses the cached connector and resumes with 1-RTT.
    ///
    /// The server keeps a per-process ticket key (see
    /// [`ServerTls::session_ticket_key`]), which is what makes the
    /// ticket issued on connection 1 decryptable on connection 2.
    #[test]
    fn tls_session_resumption_across_client_connections() {
        let handler = |req: Request<Body>| -> Response<Body> {
            let mut resp = Response::<Body>::with_status(StatusCode::OK)
                .with_body(Body::from(format!("echo:{}", req.uri.as_str())));
            resp.headers.insert(
                HeaderName::from_static("connection"),
                HeaderValue::from_static("close"),
            );
            resp
        };
        let server = Server::bind_with_config(
            "127.0.0.1:0",
            ServerConfig {
                http2: false,
                threads: 1,
                tls: Some(ServerTls {
                    identity: testdata::server_identity(),
                    alpn: vec![b"http/1.1".to_vec()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let _handle = server.serve_background(handler).unwrap();

        let client = Client::with_config(ClientConfig {
            http2: false,
            tls: Some(TlsSettings {
                roots: testdata::root_store(),
                verify: true,
                alpn: vec![b"http/1.1".to_vec()],
                now: testdata::NOW,
                ..Default::default()
            }),
            ..Default::default()
        });

        // First request: full handshake, connector cached, ticket captured.
        let resp = client.get(&format!("https://{addr}/one")).unwrap();
        assert_eq!(resp.status.as_u16(), 200);
        {
            let cache = client.inner.tls_connectors.lock().unwrap();
            assert_eq!(cache.len(), 1, "one connector cached for the authority");
            let connector = cache.values().next().expect("connector present");
            assert!(
                connector.session_count() > 0,
                "the first handshake must capture a session ticket"
            );
        }

        // Second request: fresh TLS connection (never pooled), same
        // cached connector → the PSK is offered and the handshake resumes.
        let resp = client.get(&format!("https://{addr}/two")).unwrap();
        assert_eq!(resp.status.as_u16(), 200);
        {
            let cache = client.inner.tls_connectors.lock().unwrap();
            assert_eq!(cache.len(), 1, "connector must not be duplicated");
        }
    }
}
