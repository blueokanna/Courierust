//! Multi-core HTTP client: HTTP/1.1 keep-alive pool + HTTP/2
//! multiplexed connections distributed across worker threads.

pub mod builder;
pub mod cookies;
pub mod h1;
pub mod h2;
pub mod multipart;
pub mod ws;

pub use builder::RequestBuilder;

use crate::courierust_body::Body;
use crate::courierust_client::cookies::CookieJar;
use crate::courierust_client::h1::H1Connection;
use crate::courierust_client::h2::{H2Cmd, H2Conn};
use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_h2::priority::Priority;
use crate::courierust_h3::runtime::{H3Cmd, H3Conn};
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::method::Method;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::uri::{PathAndQuery, Url};
use std::collections::HashMap;
use std::io::{Read, Write};
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
    /// The certificate this client presents when a server asks for one
    /// (mutual TLS).
    ///
    /// `None` (the default) sends the mandated empty certificate list and
    /// lets the server decide whether that is acceptable.
    pub identity: Option<crate::courierust_tls::Identity>,
    /// A `ClientHello` parameter set to reproduce on the wire (see
    /// [`crate::courierust_fingerprint::profile::chrome_tls_profile`])
    /// instead of the built-in shape. Servers behind traffic-risk
    /// engines reject very sparse ClientHellos; a browser profile passes
    /// because it is what those engines expect. `None` (the default)
    /// keeps the built-in shape. Configured profiles disable TLS
    /// session resumption.
    pub profile: Option<crate::courierust_fingerprint::profile::TlsProfile>,
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
            profile: None,
        }
    }
}

impl TlsSettings {
    /// Settings that trust the platform's root store, offering both
    /// HTTP/2 and HTTP/1.1 over TLS.
    ///
    /// [`TlsSettings::default`] trusts *nothing* — it can only reach a
    /// server whose certificate the caller loaded by hand — so this is the
    /// constructor a client talking to the public internet wants. The roots
    /// are read from the OS (see [`crate::courierust_tls::system_roots`])
    /// rather than vendored, because a vendored bundle is a file that
    /// expires.
    pub fn with_system_roots() -> crate::courierust_tls::TlsResult<Self> {
        let mut roots = crate::courierust_tls::RootStore::new();
        crate::courierust_tls::system_roots::load_into(&mut roots)?;
        Ok(Self {
            roots,
            verify: true,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            ..Default::default()
        })
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
        profile: t.profile.clone(),
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
    /// Advertise `gzip`/`deflate` and transparently decode the response
    /// body when the server uses one of them.
    ///
    /// One setting for both halves on purpose: advertising a coding this
    /// client will not decode hands the caller bytes that look like
    /// garbage, and decoding without advertising gives up the bandwidth
    /// for nothing.
    ///
    /// A caller that sets its own `accept-encoding` header keeps it — the
    /// header is never rewritten. A coding this client *has a decoder for*
    /// is still decoded when the server sends it anyway, because that is
    /// what the caller wanted; a coding it has no decoder for (`br`, …) is
    /// left untouched with its `content-encoding` in place, so the caller
    /// can see what it is actually holding.
    ///
    /// `false` means hands off in both directions: nothing is offered, and
    /// nothing is decoded.
    ///
    /// Only a fully buffered (`Body::Bytes`) response is decoded; a
    /// streaming body is handed over untouched, with its
    /// `content-encoding` still in place so the caller can see what it is
    /// holding.
    pub accept_encoding: bool,
    /// Fields merged into every request this client *initiates*, with a
    /// field on the request itself always winning.
    ///
    /// Merged on the first hop only: a cross-origin redirect drops
    /// `authorization` / `proxy-authorization` / `cookie`, and re-merging
    /// would put a default credential back on the hop that rule exists to
    /// protect.
    pub default_headers: HeaderMap,
    /// Forward all requests through an `http://` proxy, e.g.
    /// `Some("http://user:pass@proxy.internal:3128".into())`.
    ///
    /// - `http://` targets are sent to the proxy in **absolute-form**, as
    ///   RFC 9110 §3.2.2 requires; the proxy resolves the origin name, so a
    ///   client behind a proxy does not need to be able to resolve it.
    /// - `https://` targets get a `CONNECT` tunnel first, and TLS is then
    ///   negotiated **end to end with the origin**: the proxy forwards
    ///   encrypted bytes and cannot read them or substitute a certificate.
    ///
    /// Credentials in the URL become `Proxy-Authorization: Basic …`. They
    /// are sent to the proxy only — on a `CONNECT` tunnel they never reach
    /// the origin, and on an absolute-form request the proxy consumes them.
    ///
    /// Two things are deliberately **not** supported, and both are errors
    /// rather than silent fallbacks: a proxy with `https://` (TLS to the
    /// proxy; the transport has no nested TLS) and a proxy combined with
    /// HTTP/2 without TLS or HTTP/3 (neither has a forward-proxy form that
    /// does not silently change what is sent). No environment variable
    /// (`HTTP_PROXY`, `NO_PROXY`) is read: configuration this crate cannot
    /// see is configuration it cannot be honest about.
    pub proxy: Option<String>,
    /// Hosts that bypass [`ClientConfig::proxy`], in the usual
    /// `no_proxy` spelling: `*`, `example.com`, `.example.com`,
    /// `host:port`, `[::1]`.
    ///
    /// Empty by default, and the environment is **not** read here —
    /// [`no_proxy_from_env`] is there for a caller that wants the
    /// environment's opinion and wants to say so.
    pub no_proxy: Vec<String>,
    /// A shared cookie jar. `None` (the default) stores nothing, exactly
    /// like every other implicit state this client refuses to keep.
    ///
    /// `Arc<Mutex<..>>` rather than a plain field because a `Client` is
    /// cheap to clone and a session must not be: every clone of the client
    /// shares one jar, the way a browser profile does.
    pub cookie_jar: Option<Arc<Mutex<CookieJar>>>,
    /// Automatic retry of failed requests. `None` (the default) means one
    /// attempt and no surprises.
    pub retry: Option<RetryPolicy>,
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
            accept_encoding: true,
            default_headers: HeaderMap::new(),
            proxy: None,
            no_proxy: Vec::new(),
            cookie_jar: None,
            retry: None,
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

/// Automatic retry policy for transport failures.
///
/// A transport failure is the one class of error where the client cannot
/// know whether the peer processed the request: the connection died, so the
/// answer never arrived. Retrying a `GET` that may already have been served
/// is what HTTP calls idempotent; retrying a `POST` is not, which is why
/// [`RetryPolicy::retry_non_idempotent`] exists and is off by default.
///
/// Nothing is retried that cannot be replayed: a streaming (`Body::Channel`)
/// request body is consumed by the attempt that used it, and a protocol
/// error (malformed response, header cap, size cap) will be produced again
/// by the same peer, so both are handed straight to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, including the first. `1` disables retrying.
    pub attempts: u32,
    /// Delay before the second attempt; doubled for each further attempt.
    pub base_backoff: Duration,
    /// Upper bound on that delay.
    pub max_backoff: Duration,
    /// Also retry methods that are not idempotent (`POST`, `PATCH`).
    /// Off by default: a duplicate write is worse than a reported failure.
    pub retry_non_idempotent: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(2),
            retry_non_idempotent: false,
        }
    }
}

impl RetryPolicy {
    /// Whether a failure should be retried.
    fn should_retry(&self, attempt: u32, method: &Method, error: &Error) -> bool {
        if attempt >= self.attempts {
            return false;
        }
        if !self.retry_non_idempotent && !method.is_idempotent() {
            return false;
        }
        // Only failures where the exchange did not complete: the connection
        // failed, went away, or timed out. A protocol violation, an
        // oversized message or a malformed header is a property of the peer
        // or of this request, and repeating it just burns the budget.
        matches!(
            error.kind,
            ErrorKind::Io | ErrorKind::UnexpectedEof | ErrorKind::Timeout | ErrorKind::Canceled
        )
    }

    /// The backoff before attempt `attempt` (1-based: the first retry is
    /// attempt 2).
    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1u32 << attempt.saturating_sub(2).min(16);
        self.base_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

/// The value of the `Host` field for `authority`.
///
/// RFC 9110 §7.2 allows `name:port` in `Host`, and `https://a.b:443/x`
/// and `https://a.b/x` are the same origin — but browsers never write
/// the scheme's default port, and an explicit `:443` tells risk
/// controls the request did not come from one.
fn host_header_value<'a>(scheme: &str, authority: &'a str) -> &'a str {
    let default_port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return authority,
    };
    authority.strip_suffix(default_port).unwrap_or(authority)
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
            let pools = crate::lock(&self.h3_pool);
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

    /// A client for the public internet: HTTP/2 with HTTP/1.1 fallback
    /// over TLS, trusting the platform's root store.
    ///
    /// [`Client::new`] leaves TLS unconfigured deliberately — silently
    /// trusting an implicit store is the kind of default that is only
    /// noticed during an incident, and on a host with no readable store it
    /// could not be honoured anyway — so this is the constructor a
    /// deployment wants, and the one a failure names its cause from.
    pub fn with_system_roots() -> crate::courierust_tls::TlsResult<Self> {
        Ok(Self::with_config(ClientConfig {
            http2: true,
            tls: Some(TlsSettings::with_system_roots()?),
            ..Default::default()
        }))
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

    /// The configuration this client was built with.
    ///
    /// Read-only, and the only copy: a caller that needs to open a
    /// connection this client's `execute` does not cover — a WebSocket
    /// upgrade, say — passes this to that constructor rather than building a
    /// second, subtly different `ClientConfig`.
    pub fn config(&self) -> &ClientConfig {
        &self.inner.config
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
        self.execute_with_redirects(&parsed, req, Priority::default(), None, 0)
    }

    /// Dispatch a request assembled by [`RequestBuilder`].
    ///
    /// The same path as [`Self::execute`], with an explicit RFC 9218
    /// priority and an optional per-request transport deadline in place of
    /// [`ClientConfig::read_timeout`]. The deadline has the same meaning as
    /// the configured one and applies to each attempt (a redirect chain
    /// gives every hop a full timeout); it is the *connection's* deadline
    /// that is restored afterwards, so a pooled connection never carries
    /// one caller's deadline into the next request.
    pub fn execute_built(
        &self,
        url: &str,
        req: Request<Body>,
        priority: Priority,
        timeout: Option<Duration>,
    ) -> Result<Response<Body>> {
        let parsed = Url::parse(url)?;
        self.execute_with_redirects(&parsed, req, priority, timeout, 0)
    }

    /// Start building a request for `url` with `method`.
    ///
    /// The URL — not the request's URI — decides scheme, authority and
    /// path, which is what [`Self::execute`] expects.
    pub fn request(&self, url: &str, method: Method) -> RequestBuilder<'_> {
        RequestBuilder::new(self, url.to_string(), method)
    }

    /// Perform a PUT request with a body.
    pub fn put(&self, url: &str, body: impl Into<Body>) -> Result<Response<Body>> {
        let mut req = Request::<Body>::new(Method::PUT, "/");
        req.body = body.into();
        self.execute(url, req)
    }

    /// Perform a DELETE request.
    pub fn delete(&self, url: &str) -> Result<Response<Body>> {
        let req = Request::<Body>::new(Method::DELETE, "/");
        self.execute(url, req)
    }

    /// Perform a HEAD request.
    pub fn head(&self, url: &str) -> Result<Response<Body>> {
        let req = Request::<Body>::new(Method::HEAD, "/");
        self.execute(url, req)
    }

    /// Perform a PATCH request with a body.
    pub fn patch(&self, url: &str, body: impl Into<Body>) -> Result<Response<Body>> {
        let mut req = Request::<Body>::new(Method::PATCH, "/");
        req.body = body.into();
        self.execute(url, req)
    }

    /// Perform an OPTIONS request.
    pub fn options(&self, url: &str) -> Result<Response<Body>> {
        let req = Request::<Body>::new(Method::OPTIONS, "/");
        self.execute(url, req)
    }

    /// Perform exactly one unmodified HTTP exchange.
    ///
    /// This is for in-process intermediaries which must relay the request
    /// and response as they arrived. It deliberately skips the client-facing
    /// conveniences in [`Self::execute`]: cookie-jar access, content-coding
    /// negotiation and decoding, retries, and redirect following. Transport
    /// configuration such as TLS, timeouts, connection pooling and an
    /// explicit forward proxy still applies.
    pub(crate) fn execute_unmanaged(
        &self,
        url: &str,
        req: Request<Body>,
    ) -> Result<Response<Body>> {
        let parsed = Url::parse(url)?;
        self.execute_inner(&parsed, req, Priority::default(), None)
    }

    /// Create a fresh client with the same transport policy and a different
    /// response-body cap. Intermediaries use this during construction so
    /// protocol readers can reject oversized bodies before buffering them.
    pub(crate) fn with_max_body(&self, max_body: usize) -> Self {
        let mut config = self.inner.config.clone();
        config.max_body = max_body;
        Self::with_config(config)
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
        let (addr, proxy) = self.route(url)?;
        let authority = url.authority();
        self.execute_h2(
            url,
            &authority,
            addr,
            tls,
            proxy.as_ref(),
            req,
            priority,
            None,
        )
    }

    fn execute_with_redirects(
        &self,
        url: &Url,
        mut req: Request<Body>,
        priority: Priority,
        timeout: Option<Duration>,
        depth: usize,
    ) -> Result<Response<Body>> {
        // The caller's own head, captured before this client adds anything
        // to it: a follow-up has to be rebuilt from what the caller wrote,
        // not from whatever the previous hop happened to be carrying.
        // Whether there *was* a body matters as much as what the head said —
        // `content-length` is written by the driver at send time, so a
        // caller that set the body directly has a head that describes
        // nothing.
        let orig_method = req.method.clone();
        // The client's default fields are merged into the request this call
        // initiates — and only that one. A redirect hop is a new request
        // *derived from* the original: its fields were merged already, and
        // the credential stripping below removed the ones a cross-origin
        // hop must not carry. Merging again would put a default credential
        // back on that hop.
        if depth == 0 {
            req = self.with_default_headers(req);
        }
        let orig_headers = req.headers.clone();
        let orig_had_body = !req.body.is_empty() || head_declares_body(&orig_headers);
        // What this client can read is decided in one place: the offer here
        // and the decode below are the two halves of `accept_encoding`, so a
        // server can never pick a coding the caller is not prepared for.
        self.offer_content_encodings(&mut req);
        self.attach_cookies(url, &mut req);
        let mut resp = self.execute_with_retry(url, req, priority, timeout)?;
        self.store_cookies(url, &resp);
        self.decode_content_encoding(&mut resp)?;

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
                    _ => orig_method.clone(),
                };
                // 307/308 carry the method *and* the body forward. The body
                // is gone (the exchange that produced this response consumed
                // it, and a streaming body cannot be replayed), so following
                // one would send a different request than the caller wrote.
                // Handing the redirect back lets the caller decide.
                if method == orig_method && orig_had_body {
                    return Ok(resp);
                }
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
                // The follow-up has no body, so any field that still
                // describes one is a lie the peer will act on:
                // `Content-Length: N` with no body is how a request
                // desynchronises the connection it is written on — the peer
                // waits for N bytes that never come, and the next request on
                // that connection is read as this one's body.
                headers.remove("content-length");
                headers.remove("content-type");
                headers.remove("transfer-encoding");
                new_req.headers = headers;
                new_req.body = Body::Empty;
                return self.execute_with_redirects(&next, new_req, priority, timeout, depth + 1);
            }
        }
        Ok(resp)
    }

    /// One attempt, or a bounded series of them when a policy is set.
    fn execute_with_retry(
        &self,
        url: &Url,
        req: Request<Body>,
        priority: Priority,
        timeout: Option<Duration>,
    ) -> Result<Response<Body>> {
        let Some(policy) = &self.inner.config.retry else {
            return self.execute_inner(url, req, priority, timeout);
        };
        // A streaming body is consumed by the attempt that used it, so it
        // forfeits retrying rather than being silently turned into a
        // different second request.
        if policy.attempts <= 1 || !(req.body.is_bytes() || req.body.is_empty()) {
            return self.execute_inner(url, req, priority, timeout);
        }
        // Everything the attempt needs, captured once: `Request<Body>` is
        // not `Clone` (a channel body has no second reader), so each
        // attempt is rebuilt from these four pieces. `Request` has exactly
        // these fields, so nothing is dropped in the rebuild.
        let method = req.method.clone();
        let uri = req.uri.clone();
        let version = req.version;
        let headers = req.headers.clone();
        let body = req
            .body
            .as_bytes()
            .map(crate::courierust_bytes::Bytes::from);
        let mut attempt = 1u32;
        loop {
            let mut retry_req = Request::new(method.clone(), uri.clone());
            retry_req.version = version;
            retry_req.headers = headers.clone();
            retry_req.body = match &body {
                Some(bytes) => Body::Bytes(bytes.clone()),
                None => Body::Empty,
            };
            match self.execute_inner(url, retry_req, priority, timeout) {
                Ok(resp) => return Ok(resp),
                Err(error) => {
                    if !policy.should_retry(attempt, &method, &error) {
                        return Err(error);
                    }
                    attempt += 1;
                    std::thread::sleep(policy.backoff(attempt));
                }
            }
        }
    }

    /// Merge [`ClientConfig::default_headers`] into `req`, leaving every
    /// field the request already carries untouched.
    ///
    /// A field on the request itself always wins: the defaults are a
    /// convenience for what the caller did not say, never an override of
    /// what it did.
    fn with_default_headers(&self, mut req: Request<Body>) -> Request<Body> {
        for (name, value) in self.inner.config.default_headers.iter() {
            if !req.headers.contains_key(name.as_str()) {
                req.headers.insert(name.clone(), value.clone());
            }
        }
        req
    }

    /// Add the jar's cookies to a request.
    fn attach_cookies(&self, url: &Url, req: &mut Request<Body>) {
        let Some(jar) = &self.inner.config.cookie_jar else {
            return;
        };
        // A caller that set its own `cookie` header keeps it — the same
        // rule as `accept-encoding`.
        if req.headers.contains_key("cookie") {
            return;
        }
        let Some(value) = crate::lock(jar).header_value(url) else {
            return;
        };
        if let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) {
            req.headers
                .insert(HeaderName::from_lowercase("cookie"), value);
        }
    }

    /// Store the cookies a response carries.
    fn store_cookies(&self, url: &Url, resp: &Response<Body>) {
        let Some(jar) = &self.inner.config.cookie_jar else {
            return;
        };
        let mut jar = crate::lock(jar);
        for value in resp.headers.get_all("set-cookie") {
            if let Ok(text) = value.to_str() {
                jar.store(url, text);
            }
        }
    }

    /// Advertise exactly the codings [`Self::decode_content_encoding`]
    /// understands, unless the caller already chose for itself.
    fn offer_content_encodings(&self, req: &mut Request<Body>) {
        if !self.inner.config.accept_encoding || req.headers.contains_key("accept-encoding") {
            return;
        }
        req.headers.insert(
            HeaderName::from_lowercase("accept-encoding"),
            HeaderValue::from_static(ACCEPT_ENCODING),
        );
    }

    /// Decode a body that arrived under a coding this client understands.
    ///
    /// Every coding in [`ACCEPT_ENCODING`] is decoded whenever the response
    /// is labelled with it — including when the caller picked its own
    /// `accept-encoding` and the server ignored the choice, because
    /// decoding is what the caller wanted and the alternative is handing
    /// back bytes that look like garbage. A coding this client has no
    /// decoder for is left completely alone: the response keeps its
    /// `content-encoding`, so the caller sees what it is actually holding
    /// instead of receiving data it cannot interpret.
    ///
    /// Decoding is bounded by [`ClientConfig::max_body`], which is the
    /// whole reason this is not simply "call inflate": a small body that
    /// expands without limit is how a peer turns a 8 KiB response into an
    /// out-of-memory abort.
    fn decode_content_encoding(&self, resp: &mut Response<Body>) -> Result<()> {
        if !self.inner.config.accept_encoding {
            return Ok(());
        }
        let Some(codings) = resp
            .headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(());
        };
        let codings: Vec<String> = codings
            .split(',')
            .map(|c| c.trim().to_ascii_lowercase())
            .filter(|c| !c.is_empty())
            .collect();
        if codings.iter().all(|c| c == "identity") {
            // No transform was applied; the header is still noise.
            resp.headers.remove("content-encoding");
            return Ok(());
        }
        // Only a buffered body is decoded. The alternative — buffering a
        // stream to decode it — would defeat the reason the caller asked
        // for a stream.
        let mut bytes = match &resp.body {
            Body::Bytes(b) => b.to_vec(),
            _ => return Ok(()),
        };
        if bytes.is_empty() {
            resp.headers.remove("content-encoding");
            resp.headers.remove("content-length");
            return Ok(());
        }
        // Codings apply in the order listed, so they are undone in reverse.
        for coding in codings.iter().rev() {
            bytes = match coding.as_str() {
                "gzip" | "x-gzip" => {
                    crate::courierust_deflate::gunzip(&bytes, self.inner.config.max_body)?
                }
                "deflate" => inflate_deflate(&bytes, self.inner.config.max_body)?,
                // No decoder for this one: leave the response exactly as it
                // arrived instead of guessing at its contents.
                _ => return Ok(()),
            };
        }
        resp.body = Body::Bytes(crate::courierust_bytes::Bytes::from(bytes));
        resp.headers.remove("content-encoding");
        // The wire length described the compressed bytes; leaving it in
        // place would misdescribe the body the caller now holds.
        resp.headers.remove("content-length");
        Ok(())
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
        let (addr, proxy) = self.route(url)?;
        if self.inner.config.http3 {
            if url.scheme != "https" {
                return Err(Error::protocol("HTTP/3 requires an https:// URL"));
            }
            if self.inner.config.tls.is_none() {
                return Err(Error::protocol("HTTP/3 requires TLS settings"));
            }
            return self.execute_h3(url, &authority, addr, req, timeout);
        }
        if self.inner.config.http2 {
            if self.inner.config.h2c_upgrade && url.scheme == "http" {
                return self.execute_h2c_upgrade(url, &authority, addr, req, timeout);
            }
            let raw = self.execute_h2(
                url,
                &authority,
                addr,
                tls,
                proxy.as_ref(),
                req,
                priority,
                timeout,
            )?;
            Ok(Response {
                status: raw.head.status,
                version: raw.head.version,
                headers: raw.head.headers,
                body: raw.body,
                trailers: None,
            })
        } else {
            self.execute_h1(url, &authority, addr, tls, proxy.as_ref(), req, timeout)
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
                    let mut cache = crate::lock(&self.inner.tls_connectors);
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

    /// The proxy to use for `url`, if the client is configured with one.
    ///
    /// Configuration that cannot be honoured is an **error**, not a silent
    /// bypass: a request that quietly ignores a configured proxy either
    /// leaks traffic the operator believes is proxied, or fails for a
    /// reason nobody can see.
    fn proxy_for(&self, url: &Url) -> Result<Option<Proxy>> {
        let raw = match &self.inner.config.proxy {
            Some(raw) => raw,
            None => return Ok(None),
        };
        let proxy = Proxy::parse(raw)?;
        if self.inner.config.http3 {
            return Err(Error::protocol(
                "ClientConfig.proxy is not supported with HTTP/3: a CONNECT tunnel is TCP",
            ));
        }
        // `no_proxy` is consulted before the transport difference, because
        // an exempt host must go direct whatever kind of proxy is
        // configured.
        if self
            .inner
            .config
            .no_proxy
            .iter()
            .any(|entry| no_proxy_matches(entry, &url.host, url.port))
        {
            return Ok(None);
        }
        // Clear-text HTTP/2 has no forward-proxy form here: an HTTP proxy
        // carrying h2c would have to be addressed by `:authority`, which
        // renames the origin. SOCKS5 has no such problem — it carries bytes
        // for any protocol.
        if url.scheme == "http" && self.inner.config.http2 && proxy.kind == ProxyKind::Http {
            return Err(Error::protocol(
                "ClientConfig.proxy is not supported for h2c (clear-text HTTP/2 over a proxy \
                 would have to rename the origin as the :authority); use http2: false, a \
                 socks5:// proxy, or route https:// through the proxy",
            ));
        }
        Ok(Some(proxy))
    }

    /// Where to connect, and through what.
    ///
    /// With a proxy the address is the **proxy's**: the origin name is the
    /// proxy's problem to resolve, which is the whole reason a client sits
    /// behind one.
    fn route(&self, url: &Url) -> Result<(SocketAddr, Option<Proxy>)> {
        match self.proxy_for(url)? {
            Some(p) => {
                let addr = resolve_addr(&p.host, p.port)?;
                Ok((addr, Some(p)))
            }
            None => Ok((resolve_addr(&url.host, url.port)?, None)),
        }
    }

    /// Open a transport to `addr` — through the proxy when there is one —
    /// wrapping it in TLS when the scheme calls for it.
    ///
    /// `addr` is always "the socket to open": the origin's address for a
    /// direct request, the proxy's for a proxied one. `authority` is the
    /// origin's, and is what a `CONNECT` tunnel asks the proxy for.
    fn open_transport(
        &self,
        addr: SocketAddr,
        proxy: Option<&Proxy>,
        authority: &str,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
    ) -> Result<crate::courierust_net::ConnStream> {
        let cfg = &self.inner.config;
        let (host, port) = split_authority(authority)?;
        let stream = match proxy {
            // A plain `http://` request to an HTTP proxy goes straight to
            // the proxy, which is addressed by the absolute target in the
            // request line. A tunnelled `CONNECT` would be a slower way of
            // saying the same thing, and it would stop the proxy from
            // applying its own policy to the request — the reason the
            // operator configured it.
            Some(p) if tls.is_none() && p.kind == ProxyKind::Http => {
                crate::courierust_net::connect(&addr, cfg.connect_timeout)?
            }
            // Everything else proxied is a tunnel: TLS has to be end to
            // end, and SOCKS5 has no other mode.
            Some(p) => connect_proxy_tunnel(
                p,
                addr,
                host,
                port,
                cfg.handshake_timeout.or(cfg.read_timeout),
            )?,
            None => crate::courierust_net::connect(&addr, cfg.connect_timeout)?,
        };
        match tls {
            Some(c) => {
                let _ = crate::courierust_net::configure(&stream, cfg.handshake_timeout);
                crate::courierust_net::ConnStream::tls_client(stream, c, hostname)
            }
            None => {
                let _ = crate::courierust_net::configure(&stream, cfg.read_timeout);
                Ok(crate::courierust_net::ConnStream::plain(stream))
            }
        }
    }

    // Kept flat for the same reason as `execute_h2`: the probe and retry
    // path re-opens a connection with exactly these parameters, and a
    // bundle would only be unpacked again one line later.
    #[allow(clippy::too_many_arguments)]
    fn execute_h1(
        &self,
        url: &Url,
        authority: &str,
        addr: SocketAddr,
        tls: Option<crate::courierust_tls::TlsConnector>,
        proxy: Option<&Proxy>,
        req: Request<Body>,
        timeout: Option<Duration>,
    ) -> Result<Response<Body>> {
        // Pool key includes the scheme: `http://host:8443` (plain) and
        // `https://host:8443` (TLS) share an authority but must never
        // reuse each other's connections — reusing the plaintext one for
        // an https URL would silently downgrade the request.
        let key = format!("{}://{authority}", url.scheme);
        let hostname = url.host.clone();
        // A pooled keep-alive connection can die while it sits idle (the
        // server's own idle timeout, a proxy, a restart). Probing before
        // writing anything is what makes that free: a spent connection is
        // dropped here, so no request — not even a non-idempotent one — is
        // put on the wire to discover it.
        let mut reused = false;
        let mut owned = loop {
            let pooled = {
                let mut pool = crate::lock(&self.inner.h1_pool);
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
                None => {
                    let stream =
                        self.open_transport(addr, proxy, authority, tls.as_ref(), &hostname)?;
                    if let Some(alpn) = stream.alpn() {
                        if alpn.as_slice() == b"h2" {
                            return Err(Error::protocol(
                                "server negotiated h2 via ALPN, but the client is configured for HTTP/1.1",
                            ));
                        }
                    }
                    break H1Connection::from_stream_seeded(stream, &self.inner.config, &[])?;
                }
            }
        };
        // A forward proxy is addressed by the **target**, not by the
        // origin's path: without absolute-form it answers as if it were
        // the origin itself. A tunnelled request belongs to the origin and
        // is addressed like any other.
        let to_proxy = proxy.is_some_and(|p| p.kind == ProxyKind::Http) && url.scheme == "http";
        let mut req = req;
        if to_proxy {
            req.uri = absolute_form(url, &req.uri)?;
            if let Some(auth) = proxy.and_then(|p| p.authorization.as_ref()) {
                // Sent to the proxy only; it is hop-by-hop and the proxy
                // consumes it, so the origin never sees it.
                req.headers.insert(
                    HeaderName::from_lowercase("proxy-authorization"),
                    HeaderValue::from_bytes(auth.as_bytes())?,
                );
            }
        }
        let deadline = timeout.filter(|d| Some(*d) != self.inner.config.read_timeout);
        if let Some(d) = deadline {
            let _ = owned.set_read_deadline(Some(d));
        }
        // The `Host` field omits the scheme's default port: RFC 9110
        // permits `host:443`, but browsers never send it, and carrying
        // it marks the request as non-browser traffic.
        let host_header = host_header_value(&url.scheme, authority);
        let result = owned.send(&req, &self.inner.config, host_header, to_proxy);
        if deadline.is_some() {
            let _ = owned.set_read_deadline(self.inner.config.read_timeout);
        }
        match result {
            Ok(resp) => {
                self.pool_h1(key, addr, owned);
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
                    let stream =
                        self.open_transport(addr, proxy, authority, tls.as_ref(), &hostname)?;
                    let mut retry =
                        H1Connection::from_stream_seeded(stream, &self.inner.config, &[])?;
                    if let Some(d) = deadline {
                        let _ = retry.set_read_deadline(Some(d));
                    }
                    let resp = retry.send(&req, &self.inner.config, host_header, to_proxy);
                    if deadline.is_some() {
                        let _ = retry.set_read_deadline(self.inner.config.read_timeout);
                    }
                    let resp = resp?;
                    self.pool_h1(key, addr, retry);
                    return Ok(resp);
                }
                Err(error)
            }
        }
    }

    /// Return a reusable connection to the pool (bounded per authority).
    fn pool_h1(&self, key: String, addr: SocketAddr, conn: H1Connection) {
        if !conn.is_reusable() {
            return;
        }
        let mut pool = crate::lock(&self.inner.h1_pool);
        let entry = pool.entry(key).or_default();
        if entry.len() < self.inner.config.max_connections_per_host {
            entry.push((addr, conn));
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
        let (addr, proxy) = self.route(url)?;
        let authority = url.authority();
        self.execute_h2(
            url,
            &authority,
            addr,
            tls,
            proxy.as_ref(),
            req,
            priority,
            None,
        )
    }

    // Kept flat for the same reason as `send_h2_cmd`: the retry path
    // re-opens a connection with exactly these parameters, and a bundle
    // would only be unpacked again one line later.
    #[allow(clippy::too_many_arguments)]
    fn execute_h2(
        &self,
        url: &Url,
        authority: &str,
        addr: SocketAddr,
        tls: Option<crate::courierust_tls::TlsConnector>,
        proxy: Option<&Proxy>,
        req: Request<Body>,
        priority: Priority,
        timeout: Option<Duration>,
    ) -> Result<crate::courierust_client::h2::H2Response> {
        // Body bytes feed the weighted connection-selection load: a
        // connection carrying a large upload is more expensive on the wire
        // than one carrying several header-only RPCs, so the pool weights
        // by size, not just by stream count. Unknown (streaming) bodies
        // weigh 0 — an honest "don't know", not a guess.
        let body_bytes = req.body.len().unwrap_or(0);
        let conn = self.get_h2_conn(authority, addr, tls.as_ref(), proxy, &url.host, body_bytes)?;
        let fields = h2::request_fields(&req, &url.scheme, authority);
        let (tx, rx) = std::sync::mpsc::channel();
        let cmd = build_h2_cmd(fields, req.body, priority, timeout, tx);
        self.send_h2_cmd(
            conn,
            authority,
            addr,
            tls.as_ref(),
            proxy,
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
            timeout: timeout.or(self.inner.config.read_timeout),
            stats: self.inner.config.stats.clone(),
        };
        let conn = self.get_h3_conn(authority, addr, &url.host, &options)?;
        let (tx, rx) = std::sync::mpsc::channel();
        let cmd = H3Cmd::Request {
            request: req,
            timeout,
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
                let mut pools = crate::lock(&self.inner.h3_pool);
                let mut pending = crate::lock(&self.inner.pending_h3_opens);
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
                    let guard = crate::lock(&self.inner.h3_pool);
                    let (guard, _) = self
                        .inner
                        .h3_open_cv
                        .wait_timeout(guard, Duration::from_millis(200))
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    drop(guard);
                    continue;
                }
                break;
            }

            let opened = (|| -> Result<H3Conn> {
                let conn = crate::courierust_h3::runtime::start_h3_driver(
                    addr,
                    hostname.to_string(),
                    authority.to_string(),
                    options.clone(),
                    self.inner.config.h3_idle_timeout,
                )?;
                let mut pools = crate::lock(&self.inner.h3_pool);
                let mut pending = crate::lock(&self.inner.pending_h3_opens);
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
                    let pools = crate::lock(&self.inner.h3_pool);
                    let mut pending = crate::lock(&self.inner.pending_h3_opens);
                    decrement_pending_h3_open(&mut pending, authority);
                    self.inner.h3_open_cv.notify_all();
                    drop(pools);
                    return Err(e);
                }
            }
        }

        // Rare fallback after a long open race: block on the
        // least-loaded live connection (its dispatch queue drains).
        let mut pools = crate::lock(&self.inner.h3_pool);
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
                conn.accepting.store(false, Ordering::Release);
                conn.release();
                let fresh = self.get_h3_conn(authority, addr, hostname, &options)?;
                let (tx2, rx2) = std::sync::mpsc::channel();
                let cmd2 = match cmd {
                    H3Cmd::Request {
                        request, timeout, ..
                    } => H3Cmd::Request {
                        request,
                        timeout,
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
        timeout: Option<Duration>,
    ) -> Result<Response<Body>> {
        let req_method = req.method.clone();
        let body_bytes = req.body.len().unwrap_or(0);
        let pooled = {
            let mut pools = crate::lock(&self.inner.h2_pool);
            pools.get_mut(authority).and_then(|list| {
                list.retain(|c| c.accepting.load(Ordering::Acquire));
                let max_connections = self.inner.config.max_connections_per_host.max(1);
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
                .send_h2_cmd(
                    conn, authority, addr, None, None, &url.host, cmd, rx, body_bytes,
                )
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
                    let mut pools = crate::lock(&self.inner.h2_pool);
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
                    let mut pool = crate::lock(&self.inner.h1_pool);
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
        proxy: Option<&Proxy>,
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
                let fresh = self.get_h2_conn(authority, addr, tls, proxy, hostname, body_bytes)?;
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
        proxy: Option<&Proxy>,
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
                let mut pools = crate::lock(&self.inner.h2_pool);
                let mut pending = crate::lock(&self.inner.pending_h2_opens);
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
                    let guard = crate::lock(&self.inner.h2_pool);
                    let (guard, _) = self
                        .inner
                        .h2_open_cv
                        .wait_timeout(guard, Duration::from_millis(200))
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    drop(guard);
                    continue;
                }
                break;
            }

            // Open outside the pool lock.
            let opened = (|| -> Result<H2Conn> {
                let stream = self.open_h2_stream(addr, proxy, authority, tls, hostname)?;
                let conn = h2::start(stream, &self.inner.config)?;
                let mut pools = crate::lock(&self.inner.h2_pool);
                let mut pending = crate::lock(&self.inner.pending_h2_opens);
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
                    let pools = crate::lock(&self.inner.h2_pool);
                    let mut pending = crate::lock(&self.inner.pending_h2_opens);
                    decrement_pending_h2_open(&mut pending, authority);
                    self.inner.h2_open_cv.notify_all();
                    drop(pools);
                    return Err(e);
                }
            }
        }
        let mut pools = crate::lock(&self.inner.h2_pool);
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

    /// Open a raw (possibly TLS-wrapped) stream for the h2 driver, through
    /// the proxy when one is configured.
    fn open_h2_stream(
        &self,
        addr: SocketAddr,
        proxy: Option<&Proxy>,
        authority: &str,
        tls: Option<&crate::courierust_tls::TlsConnector>,
        hostname: &str,
    ) -> Result<crate::courierust_net::ConnStream> {
        let conn = self.open_transport(addr, proxy, authority, tls, hostname)?;
        match tls {
            Some(_) => {
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
            None => Ok(conn),
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
        other => {
            let (body, end_stream) = match other {
                Body::Empty => (None, true),
                Body::Bytes(b) => (Some(b), true),
                Body::Channel(_) | Body::Stream(_) => unreachable!(),
            };
            H2Cmd::Request {
                fields,
                body,
                end_stream,
                priority,
                timeout,
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

/// What kind of proxy [`ClientConfig::proxy`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyKind {
    /// An HTTP forward proxy: absolute-form for `http://` targets, `CONNECT`
    /// for `https://`.
    Http,
    /// SOCKS5 (RFC 1928). `local_dns` distinguishes the two spellings in
    /// common use: `socks5://` resolves the origin here and sends an
    /// address, `socks5h://` sends the name and lets the proxy resolve it
    /// (the only option when the client is not allowed to leak DNS).
    Socks5 { local_dns: bool },
}

/// A forward proxy, parsed from [`ClientConfig::proxy`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Proxy {
    kind: ProxyKind,
    host: String,
    port: u16,
    /// A ready-to-send `Proxy-Authorization` value, for an HTTP proxy whose
    /// URL carried userinfo. Encoded once, at parse time.
    authorization: Option<String>,
    /// The same userinfo as a `(user, password)` pair, for SOCKS5's own
    /// sub-negotiation.
    credentials: Option<(String, String)>,
}

impl Proxy {
    fn parse(raw: &str) -> Result<Self> {
        let (scheme, rest) = raw.split_once("://").ok_or_else(|| {
            Error::protocol("proxy must be an absolute URL, e.g. http://host:3128")
        })?;
        let (kind, default_port) = if scheme.eq_ignore_ascii_case("http") {
            (ProxyKind::Http, 80)
        } else if scheme.eq_ignore_ascii_case("socks5") {
            (ProxyKind::Socks5 { local_dns: true }, 1080)
        } else if scheme.eq_ignore_ascii_case("socks5h") {
            (ProxyKind::Socks5 { local_dns: false }, 1080)
        } else {
            return Err(Error::protocol(format!(
                "proxy scheme {scheme} is not supported: http://, socks5:// and socks5h:// are \
                 (TLS to the proxy needs nested TLS, which the transport does not have)"
            )));
        };
        // A trailing path is meaningless for a forward proxy; reject it
        // rather than ignore something that suggests a misconfiguration
        // (a PAC file, a reverse-proxy path, …).
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if !path.is_empty() && path != "/" {
            return Err(Error::protocol(
                "proxy URL must not contain a path (only http://host:port)",
            ));
        }
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, hp)) => (Some(u), hp),
            None => (None, authority),
        };
        if hostport.is_empty() {
            return Err(Error::protocol("proxy URL missing host"));
        }
        let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
            let end = bracketed
                .find(']')
                .ok_or_else(|| Error::protocol("proxy IPv6 host is missing its closing bracket"))?;
            let host = &bracketed[..end];
            let suffix = &bracketed[end + 1..];
            let port = match suffix.strip_prefix(':') {
                Some(p) => parse_proxy_port(p)?,
                None if suffix.is_empty() => default_port,
                None => return Err(Error::protocol("invalid proxy authority after IPv6 host")),
            };
            (host.to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => (h.to_string(), parse_proxy_port(p)?),
                // No port: the scheme's default.
                _ if !hostport.contains(':') => (hostport.to_string(), default_port),
                _ => return Err(Error::protocol("proxy IPv6 host must be bracketed")),
            }
        };
        if host.is_empty() || host.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(Error::protocol("invalid proxy host"));
        }
        // curl's reading of a bare userinfo: the password is empty.
        let credentials = userinfo.map(|u| match u.split_once(':') {
            Some((user, pass)) => (user.to_string(), pass.to_string()),
            None => (u.to_string(), String::new()),
        });
        let authorization = credentials.as_ref().map(|(user, pass)| {
            format!(
                "Basic {}",
                crate::courierust_crypto::base64::encode(format!("{user}:{pass}").as_bytes())
            )
        });
        Ok(Self {
            kind,
            host,
            port,
            authorization,
            credentials,
        })
    }
}

/// A no-proxy list from the environment (`NO_PROXY`, then `no_proxy`).
///
/// Opt-in on purpose: the rest of this crate never reads the environment,
/// and a client that silently obeys a variable nobody set is a client whose
/// behaviour cannot be predicted from its configuration. Call it and assign
/// the result to [`ClientConfig::no_proxy`] if the environment's opinion is
/// the one you want.
pub fn no_proxy_from_env() -> Vec<String> {
    let raw = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    raw.split(',')
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// Whether a `no_proxy` entry exempts `host:port`.
///
/// The grammar is the one in common use rather than a specification: `*`
/// exempts everything, an entry may pin a port, and a name matches itself
/// and its subdomains — with the same leading-dot rule as cookie domains,
/// because `ends_with` alone would let `notexample.com` match `example.com`.
fn no_proxy_matches(entry: &str, host: &str, port: u16) -> bool {
    let entry = entry.trim();
    if entry.is_empty() {
        return false;
    }
    if entry == "*" {
        return true;
    }
    let (entry_host, entry_port) = split_optional_port(entry);
    if let Some(entry_port) = entry_port {
        if entry_port != port {
            return false;
        }
    }
    let entry_host = entry_host.trim_start_matches('.').to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    host == entry_host
        || (host.len() > entry_host.len()
            && host.ends_with(&entry_host)
            && host.as_bytes()[host.len() - entry_host.len() - 1] == b'.')
}

/// Split `[::1]:8080`, `host:8080`, `::1` or `host` into a host and an
/// optional port.
fn split_optional_port(value: &str) -> (&str, Option<u16>) {
    if let Some(bracketed) = value.strip_prefix('[') {
        if let Some(end) = bracketed.find(']') {
            let host = &bracketed[..end];
            let port = bracketed[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
        return (value, None);
    }
    match value.rsplit_once(':') {
        // More than one colon is a bare IPv6 address, not a port.
        Some((host, port)) if !host.contains(':') => match port.parse::<u16>() {
            Ok(port) => (host, Some(port)),
            Err(_) => (value, None),
        },
        _ => (value, None),
    }
}

/// Split an authority (`host:port`, IPv6 bracketed) as [`Url::authority`]
/// produces it.
fn split_authority(authority: &str) -> Result<(&str, u16)> {
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| Error::protocol("authority has no port"))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::protocol("authority port is not a number"))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Ok((host, port))
}

fn parse_proxy_port(value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| Error::protocol("invalid proxy port"))?;
    if port == 0 || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::protocol("invalid proxy port"));
    }
    Ok(port)
}

/// Open a tunnel through `proxy` to `host:port`.
///
/// An HTTP proxy gets `CONNECT`; a SOCKS5 proxy gets its own handshake. Both
/// return a raw socket that the caller may then wrap in TLS, which is what
/// keeps the origin's certificate the only one that matters.
fn connect_proxy_tunnel(
    proxy: &Proxy,
    addr: SocketAddr,
    host: &str,
    port: u16,
    timeout: Option<Duration>,
) -> Result<std::net::TcpStream> {
    match proxy.kind {
        ProxyKind::Http => connect_tunnel(proxy, addr, &format_host_port(host, port), timeout),
        ProxyKind::Socks5 { local_dns } => {
            connect_socks5(proxy, addr, host, port, timeout, local_dns)
        }
    }
}

/// The `host:port` spelling a `CONNECT` request uses.
fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// SOCKS5 `CONNECT` (RFC 1928) with optional username/password
/// authentication (RFC 1929).
fn connect_socks5(
    proxy: &Proxy,
    addr: SocketAddr,
    host: &str,
    port: u16,
    timeout: Option<Duration>,
    local_dns: bool,
) -> Result<std::net::TcpStream> {
    let mut stream = crate::courierust_net::connect(&addr, timeout)?;
    let _ = crate::courierust_net::configure(&stream, timeout);

    // Greeting. Offering both methods lets the proxy pick, which is what
    // the RFC intends; offering only `no authentication` would make a proxy
    // that requires credentials answer `no acceptable methods`.
    let greeting: &[u8] = match &proxy.credentials {
        Some(_) => &[5, 2, 0, 2],
        None => &[5, 1, 0],
    };
    stream
        .write_all(greeting)
        .map_err(|e| Error::io(format!("socks5 greeting: {e}")))?;
    stream
        .flush()
        .map_err(|e| Error::io(format!("socks5 greeting: {e}")))?;
    let mut choice = [0u8; 2];
    read_exact(&mut stream, &mut choice)?;
    if choice[0] != 5 {
        return Err(Error::protocol(format!(
            "socks5: proxy answered with version {}, not 5",
            choice[0]
        )));
    }
    match choice[1] {
        0 => {}
        2 => {
            let Some((user, pass)) = &proxy.credentials else {
                return Err(Error::protocol(
                    "socks5: the proxy demands authentication but the proxy URL carries no user",
                ));
            };
            if user.len() > 255 || pass.len() > 255 {
                return Err(Error::protocol(
                    "socks5: username and password are limited to 255 bytes each",
                ));
            }
            let mut message = Vec::with_capacity(3 + user.len() + pass.len());
            message.push(1);
            message.push(user.len() as u8);
            message.extend_from_slice(user.as_bytes());
            message.push(pass.len() as u8);
            message.extend_from_slice(pass.as_bytes());
            stream
                .write_all(&message)
                .map_err(|e| Error::io(format!("socks5 authentication: {e}")))?;
            stream
                .flush()
                .map_err(|e| Error::io(format!("socks5 authentication: {e}")))?;
            let mut reply = [0u8; 2];
            read_exact(&mut stream, &mut reply)?;
            if reply[1] != 0 {
                return Err(Error::protocol("socks5: authentication refused"));
            }
        }
        0xff => return Err(Error::protocol("socks5: no acceptable authentication method")),
        other => {
            return Err(Error::protocol(format!(
                "socks5: proxy chose authentication method {other}, which this client does not implement"
            )))
        }
    }

    // Request: CONNECT to the origin, as an address or as a name.
    let mut request = Vec::with_capacity(22);
    request.extend_from_slice(&[5, 1, 0]);
    if local_dns {
        match resolve_addr(host, port)? {
            SocketAddr::V4(v4) => {
                request.push(1);
                request.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                request.push(4);
                request.extend_from_slice(&v6.ip().octets());
            }
        }
    } else {
        if host.len() > 255 {
            return Err(Error::protocol(
                "socks5: host name is too long for the domain address type",
            ));
        }
        request.push(3);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|e| Error::io(format!("socks5 request: {e}")))?;
    stream
        .flush()
        .map_err(|e| Error::io(format!("socks5 request: {e}")))?;

    let mut head = [0u8; 4];
    read_exact(&mut stream, &mut head)?;
    if head[0] != 5 {
        return Err(Error::protocol(format!(
            "socks5: proxy answered with version {}, not 5",
            head[0]
        )));
    }
    if head[1] != 0 {
        return Err(Error::protocol(format!(
            "socks5: proxy refused the connection to {host}:{port}: {}",
            socks5_error(head[1])
        )));
    }
    // The bound address has to be consumed before the tunnel carries
    // anything else, or the first bytes of the origin's data would be read
    // as part of the reply.
    let address_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            read_exact(&mut stream, &mut len)?;
            usize::from(len[0])
        }
        other => {
            return Err(Error::protocol(format!(
                "socks5: proxy used address type {other}, which RFC 1928 does not define"
            )))
        }
    };
    let mut discard = vec![0u8; address_len + 2];
    read_exact(&mut stream, &mut discard)?;
    Ok(stream)
}

fn read_exact(stream: &mut std::net::TcpStream, buf: &mut [u8]) -> Result<()> {
    stream
        .read_exact(buf)
        .map_err(|e| Error::io(format!("proxy handshake read: {e}")))
}

/// RFC 1928 §6 reply codes.
fn socks5_error(code: u8) -> &'static str {
    match code {
        1 => "general SOCKS server failure",
        2 => "connection not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown reply code",
    }
}

/// The absolute-form request target a forward proxy expects for a plain
/// `http://` request (RFC 9110 §3.2.2). Without it the proxy answers for
/// itself instead of for the origin.
fn absolute_form(url: &Url, target: &PathAndQuery) -> Result<PathAndQuery> {
    let mut s = String::with_capacity(url.authority().len() + target.as_str().len() + 8);
    s.push_str(&url.scheme);
    s.push_str("://");
    s.push_str(&url.authority());
    s.push_str(target.as_str());
    PathAndQuery::from_bytes(s.as_bytes())
}

/// Open the TCP connection to a forward proxy and `CONNECT` through it.
///
/// The head is read **one byte at a time** on purpose: a `BufReader` would
/// read past `\r\n\r\n` and swallow the first bytes of the origin's data,
/// which after `200` are the start of the TLS `ServerHello`.
fn connect_tunnel(
    proxy: &Proxy,
    addr: SocketAddr,
    authority: &str,
    timeout: Option<Duration>,
) -> Result<std::net::TcpStream> {
    let mut stream = crate::courierust_net::connect(&addr, timeout)?;
    // The same deadline covers the read of the reply: a proxy that accepts
    // and then says nothing must not hold the caller for the full
    // `read_timeout`.
    let _ = crate::courierust_net::configure(&stream, timeout);

    let mut head = String::with_capacity(128);
    head.push_str("CONNECT ");
    head.push_str(authority);
    head.push_str(" HTTP/1.1\r\nHost: ");
    head.push_str(authority);
    head.push_str("\r\n");
    if let Some(auth) = &proxy.authorization {
        head.push_str("Proxy-Authorization: ");
        head.push_str(auth);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .map_err(|e| Error::io(format!("proxy CONNECT write: {e}")))?;
    stream
        .flush()
        .map_err(|e| Error::io(format!("proxy CONNECT flush: {e}")))?;

    let mut reply = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .map_err(|e| Error::io(format!("proxy CONNECT read: {e}")))?;
        if n == 0 {
            return Err(Error::protocol(
                "proxy closed the connection before answering CONNECT",
            ));
        }
        reply.push(byte[0]);
        if reply.len() > 8 * 1024 {
            return Err(Error::protocol("proxy CONNECT response head is too large"));
        }
        if reply.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let status = {
        let text = core::str::from_utf8(&reply)
            .map_err(|_| Error::protocol("proxy CONNECT response is not UTF-8"))?;
        text.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| Error::protocol("proxy CONNECT response has no status code"))?
    };
    if !(200..300).contains(&status) {
        return Err(Error::protocol(format!(
            "proxy refused CONNECT to {authority}: status {status}"
        )));
    }
    Ok(stream)
}

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

/// Encodings this client advertises **and** decodes.
///
/// One list for both directions: advertising a coding nothing decodes hands
/// the caller bytes that look like garbage, and decoding a coding that was
/// never advertised means guessing at data the peer chose for itself.
const ACCEPT_ENCODING: &str = "gzip, deflate";

/// Whether a request head describes a body.
///
/// The redirect path has to decide whether a follow-up can keep the
/// original method: a `307`/`308` that drops the body is a different
/// request, and a rewrite to `GET` that *keeps* `Content-Length` is a
/// framing hazard — the peer waits for a body that will never arrive, and
/// anything behind it on the same connection is read as that body.
fn head_declares_body(headers: &HeaderMap) -> bool {
    if headers.contains_key("transfer-encoding") {
        return true;
    }
    match headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    {
        // A malformed length is treated as "there is a body": the safe
        // reading of an unclear head is the one that does not silently
        // discard it.
        Some(len) => len.parse::<u64>().map(|n| n > 0).unwrap_or(true),
        None => false,
    }
}

/// Unwrap a `Content-Encoding: deflate` body.
///
/// RFC 9110 defines `deflate` as the zlib format (RFC 1950), but a large
/// part of the deployed world sends raw DEFLATE — `zlib`'s own decoder
/// accepts both for exactly this reason. A zlib stream begins with a
/// two-byte header whose value is a multiple of 31 (RFC 1950 §2.2), which
/// discriminates the two without having to guess and retry blindly.
fn inflate_deflate(body: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let zlib_wrapped = body.len() >= 6
        && body[0] & 0x0f == 8
        && (u16::from(body[0]) << 8 | u16::from(body[1])) % 31 == 0;
    if zlib_wrapped {
        // Two-byte header, four-byte Adler-32 trailer.
        if let Ok(out) = crate::courierust_deflate::inflate(&body[2..body.len() - 4], max_out) {
            return Ok(out);
        }
    }
    crate::courierust_deflate::inflate(body, max_out)
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

    fn adler32(data: &[u8]) -> u32 {
        let (mut a, mut b) = (1u32, 0u32);
        for &x in data {
            a = (a + u32::from(x)) % 65_521;
            b = (b + a) % 65_521;
        }
        (b << 16) | a
    }

    /// `Content-Encoding: deflate` means zlib, but a large part of the
    /// deployed world sends raw DEFLATE. Both must decode, and neither
    /// form may be mistaken for the other.
    #[test]
    fn deflate_bodies_decode_whether_wrapped_or_raw() {
        // Compressible, and long enough that the encoder emits a dynamic
        // Huffman block rather than a stored one.
        let payload = "the quick brown fox jumps over the lazy dog\n".repeat(96);
        let raw = crate::courierust_deflate::deflate(payload.as_bytes());
        assert!(raw.len() < payload.len(), "test payload must compress");

        let mut zlib = vec![0x78, 0x9c];
        zlib.extend_from_slice(&raw);
        zlib.extend_from_slice(&adler32(payload.as_bytes()).to_be_bytes());
        assert_eq!(
            zlib[1], 0x9c,
            "the test's own header must satisfy the check"
        );

        let want = payload.as_bytes();
        assert_eq!(inflate_deflate(&zlib, 1 << 20).unwrap(), want);
        assert_eq!(inflate_deflate(&raw, 1 << 20).unwrap(), want);
    }

    /// Whatever the bytes happen to start with, the raw form still decodes:
    /// the zlib-header test is a heuristic, so a false positive has to fall
    /// back rather than fail.
    #[test]
    fn raw_deflate_decodes_for_every_payload_shape() {
        let shapes: [&[u8]; 6] = [
            b"",
            b"a",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &[0u8; 4096],
            &[0xffu8; 4096],
            b"\x78\x9c\x00\x01\x02\x03\x04\x05\x06\x07",
        ];
        for shape in shapes {
            let raw = crate::courierust_deflate::deflate(shape);
            assert_eq!(
                inflate_deflate(&raw, 1 << 20).unwrap(),
                shape,
                "raw deflate of {shape:?} must round-trip"
            );
        }
    }

    #[test]
    fn a_head_that_declares_a_body_is_recognised() {
        let mut h = HeaderMap::new();
        assert!(!head_declares_body(&h), "a bare head declares nothing");

        h.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("0"),
        );
        assert!(!head_declares_body(&h), "an explicit zero is no body");

        h.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("1"),
        );
        assert!(head_declares_body(&h));

        // An unparsable length is treated as a body: discarding a body the
        // peer believes it sent is the failure that corrupts a connection.
        h.insert(
            HeaderName::from_static("content-length"),
            HeaderValue::from_static("not-a-number"),
        );
        assert!(head_declares_body(&h));

        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("transfer-encoding"),
            HeaderValue::from_static("chunked"),
        );
        assert!(head_declares_body(&h));
    }

    #[test]
    fn no_proxy_entries_match_the_way_they_are_written() {
        // Bare name, dotted name and IP all mean "this host, exactly".
        assert!(no_proxy_matches("example.com", "example.com", 80));
        assert!(no_proxy_matches(".example.com", "example.com", 80));
        assert!(no_proxy_matches("127.0.0.1", "127.0.0.1", 80));
        assert!(!no_proxy_matches("127.0.0.1", "127.0.0.2", 80));
        // A name covers its subdomains.
        assert!(no_proxy_matches(".example.com", "a.example.com", 80));
        assert!(no_proxy_matches("example.com", "a.b.example.com", 80));
        // The dot rule, again: a suffix is not a domain.
        assert!(!no_proxy_matches("example.com", "notexample.com", 80));
        assert!(!no_proxy_matches(
            "example.com",
            "example.com.evil.test",
            80
        ));
        // A pinned port has to match.
        assert!(no_proxy_matches("example.com:8080", "example.com", 8080));
        assert!(!no_proxy_matches("example.com:8080", "example.com", 80));
        // `*` is everything; an empty entry is nothing.
        assert!(no_proxy_matches("*", "anything.test", 1));
        assert!(!no_proxy_matches("", "anything.test", 1));
        // A bare IPv6 entry is not read as `host:port`.
        assert_eq!(
            split_optional_port("::1"),
            ("::1", None),
            "more than one colon is an address"
        );
        assert_eq!(split_optional_port("[::1]:1080"), ("::1", Some(1080)));
        assert_eq!(split_optional_port("host:1080"), ("host", Some(1080)));
        assert_eq!(split_optional_port("host"), ("host", None));
    }

    #[test]
    fn an_authority_splits_into_the_host_a_proxy_needs() {
        assert_eq!(
            split_authority("example.com:443").unwrap(),
            ("example.com", 443)
        );
        assert_eq!(
            split_authority("[2001:db8::1]:8080").unwrap(),
            ("2001:db8::1", 8080)
        );
        assert!(split_authority("example.com").is_err());
    }

    #[test]
    fn proxy_urls_are_parsed_or_refused_with_a_reason() {
        let http = Proxy::parse("http://proxy.internal:3128").unwrap();
        assert_eq!(http.kind, ProxyKind::Http);
        assert_eq!((http.host.as_str(), http.port), ("proxy.internal", 3128));
        assert!(http.authorization.is_none());
        // The default port comes from the scheme.
        assert_eq!(Proxy::parse("http://proxy").unwrap().port, 80);
        assert_eq!(Proxy::parse("socks5://proxy").unwrap().port, 1080);
        // `socks5` resolves locally, `socks5h` does not.
        assert_eq!(
            Proxy::parse("socks5://proxy").unwrap().kind,
            ProxyKind::Socks5 { local_dns: true }
        );
        assert_eq!(
            Proxy::parse("socks5h://proxy").unwrap().kind,
            ProxyKind::Socks5 { local_dns: false }
        );
        // Credentials become both a Basic header and a user/password pair.
        let authed = Proxy::parse("http://alice:s3cret@proxy:3128").unwrap();
        assert_eq!(
            authed.authorization.as_deref(),
            Some("Basic YWxpY2U6czNjcmV0")
        );
        assert_eq!(
            authed.credentials,
            Some(("alice".to_string(), "s3cret".to_string()))
        );
        // A bare user means an empty password.
        assert_eq!(
            Proxy::parse("http://alice@proxy:3128").unwrap().credentials,
            Some(("alice".to_string(), String::new()))
        );
        // Bracketed IPv6.
        assert_eq!(
            (
                Proxy::parse("http://[::1]:3128").unwrap().host.as_str(),
                3128
            ),
            ("::1", 3128)
        );
        for bad in [
            "proxy:3128",
            "https://proxy:3128",
            "http://proxy:3128/pac",
            "http://proxy:0",
            "http://:3128",
            "http://[::1:3128",
        ] {
            assert!(Proxy::parse(bad).is_err(), "{bad} must be refused");
        }
    }
}
