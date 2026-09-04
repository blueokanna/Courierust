//! Multi-core HTTP client: HTTP/1.1 keep-alive pool + HTTP/2
//! multiplexed connections distributed across worker threads.

pub mod h1;
pub mod h2;

use crate::courierust_body::Body;
use crate::courierust_client::h1::H1Connection;
use crate::courierust_client::h2::{H2Cmd, H2Conn};
use crate::courierust_error::{Error, Result};
use crate::courierust_h2::priority::Priority;
use crate::courierust_h3::runtime::{H3Cmd, H3Conn};
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
            max_header_list: 1 << 20,
            max_body: 16 * 1024 * 1024,
            tls: None,
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

struct ClientInner {
    config: ClientConfig,
    /// Idle h1 keep-alive connections per authority.
    h1_pool: Mutex<HashMap<String, Vec<(SocketAddr, H1Connection)>>>,
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
        let tls = self.tls_for_scheme(&url.scheme, &url.authority())?;
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
        let addr = resolve_addr(&url.host, url.port)?;
        if self.inner.config.http3 {
            if url.scheme != "https" {
                return Err(Error::protocol("HTTP/3 requires an https:// URL"));
            }
            if self.inner.config.tls.is_none() {
                return Err(Error::protocol("HTTP/3 requires TLS settings"));
            }
            return self.execute_h3(url, &authority, addr, req);
        }
        if self.inner.config.http2 {
            if self.inner.config.h2c_upgrade && url.scheme == "http" {
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
    ) -> Result<Response<Body>> {
        // Pool key includes the scheme: `http://host:8443` (plain) and
        // `https://host:8443` (TLS) share an authority but must never
        // reuse each other's connections — reusing the plaintext one for
        // an https URL would silently downgrade the request.
        let key = format!("{}://{authority}", url.scheme);
        let conn = {
            let mut pool = self.inner.h1_pool.lock().unwrap();
            let entry = pool.entry(key.clone()).or_default();
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
                    let entry = pool.entry(key).or_default();
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
        let tls = self.tls_for_scheme(&url.scheme, &url.authority())?;
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
        // Body bytes feed the weighted connection-selection load: a
        // connection carrying a large upload is more expensive on the wire
        // than one carrying several header-only RPCs, so the pool weights
        // by size, not just by stream count. Unknown (streaming) bodies
        // weigh 0 — an honest "don't know", not a guess.
        let body_bytes = req.body.len().unwrap_or(0);
        let conn = self.get_h2_conn(authority, addr, tls.as_ref(), &url.host, body_bytes)?;
        let fields = h2::request_fields(&req, &url.scheme, authority);
        let (tx, rx) = std::sync::mpsc::channel();
        let cmd = build_h2_cmd(fields, req.body, priority, tx);
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
                    H3Cmd::Request { request, .. } => H3Cmd::Request {
                        request,
                        reply: tx2,
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
            let cmd = build_h2_cmd(fields, req.body, Priority::default(), tx);
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
                let stream = self.open_h2_stream(addr, tls, hostname)?;
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
    fn open_h2_stream(
        &self,
        addr: SocketAddr,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
    ) -> Result<crate::courierust_net::ConnStream> {
        let stream = crate::courierust_net::connect(&addr, self.inner.config.connect_timeout)?;
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
    let scheme = base.scheme.as_str();
    let mut s = format!("{scheme}://{}{}", base.authority(), location);
    if location.starts_with("//") {
        s = format!("{scheme}:{}", location);
    }
    Url::parse(&s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_http::header::{HeaderName, HeaderValue};
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
