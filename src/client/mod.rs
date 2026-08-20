//! Multi-core HTTP client: HTTP/1.1 keep-alive pool + HTTP/2
//! multiplexed connections distributed across worker threads.

pub mod h1;
pub mod h2;

use crate::body::Body;
use crate::bytes::Bytes;
use crate::client::h1::H1Connection;
use crate::client::h2::{H2Cmd, H2Conn};
use crate::error::{Error, Result};
use crate::h2::priority::Priority;
use crate::http::method::Method;
use crate::http::request::Request;
use crate::http::response::Response;
use crate::http::status::StatusCode;
use crate::http::uri::Url;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
        })
    }

    /// Perform an h2 request and return the raw response including
    /// trailers (used by the gRPC layer).
    pub fn execute_h2_raw(
        &self,
        url: &Url,
        req: Request<Body>,
        priority: Priority,
    ) -> Result<crate::client::h2::H2Response> {
        if url.scheme != "http" {
            return Err(Error::protocol(format!(
                "scheme {} not supported by the built-in connector (TLS is external)",
                url.scheme
            )));
        }
        let addr = resolve_addr(&url.host, url.port)?;
        let authority = url.authority();
        self.execute_h2(url, &authority, addr, req, priority)
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
        if url.scheme != "http" {
            return Err(Error::protocol(format!(
                "scheme {} not supported by the built-in connector (TLS is external)",
                url.scheme
            )));
        }
        self.inner.seq.fetch_add(1, Ordering::Relaxed);
        let addr = resolve_addr(&url.host, url.port)?;
        let authority = url.authority();
        if self.inner.config.http2 {
            let raw = self.execute_h2(url, &authority, addr, req, priority)?;
            Ok(Response {
                status: raw.head.status,
                version: raw.head.version,
                headers: raw.head.headers,
                body: raw.body,
            })
        } else {
            self.execute_h1(url, &authority, addr, req)
        }
    }

    fn execute_h1(
        &self,
        _url: &Url,
        authority: &str,
        addr: SocketAddr,
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
        let mut owned = match conn {
            Some(c) => c,
            None => H1Connection::connect(addr, &self.inner.config)?,
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

    fn execute_h2(
        &self,
        _url: &Url,
        authority: &str,
        addr: SocketAddr,
        req: Request<Body>,
        priority: Priority,
    ) -> Result<crate::client::h2::H2Response> {
        let conn = self.get_h2_conn(authority, addr)?;
        let fields = h2::request_fields(&req);
        let (body, end_stream) = match req.body {
            Body::Empty => (None, true),
            Body::Bytes(b) => (Some(b), true),
            Body::Channel(rx) => {
                // Materialize a channel body for the request.
                let mut buf = Vec::new();
                while let Ok(chunk) = rx.recv() {
                    let b = chunk?;
                    buf.extend_from_slice(&b);
                }
                if buf.is_empty() {
                    (None, true)
                } else {
                    (Some(Bytes::from(buf)), true)
                }
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();
        if conn
            .tx
            .send(H2Cmd::Request {
                fields: fields.clone(),
                body: body.clone(),
                end_stream,
                priority,
                reply: tx,
            })
            .is_err()
        {
            // The driver is gone; open a fresh connection and retry once.
            let fresh = self.open_h2_conn(authority, addr)?;
            let (tx2, rx2) = std::sync::mpsc::channel();
            fresh
                .tx
                .send(H2Cmd::Request {
                    fields,
                    body,
                    end_stream,
                    priority,
                    reply: tx2,
                })
                .map_err(|_| Error::canceled("h2 driver is gone"))?;
            return rx2
                .recv()
                .map_err(|_| Error::canceled("h2 driver closed the channel"))?;
        }
        rx.recv()
            .map_err(|_| Error::canceled("h2 driver closed the channel"))?
    }

    fn get_h2_conn(&self, authority: &str, addr: SocketAddr) -> Result<H2Conn> {
        let mut pools = self.inner.h2_pool.lock().unwrap();
        let list = pools.entry(authority.to_string()).or_default();
        // Reuse a live connection.
        if let Some(c) = list.iter().find(|c| c.accepting.load(Ordering::Acquire)) {
            return Ok(c.clone());
        }
        // Open a new one (up to the per-host cap; beyond it, multiplex on
        // an existing connection).
        if list.len() < self.inner.config.max_connections_per_host {
            let stream = crate::net::connect(&addr, self.inner.config.connect_timeout)?;
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

    fn open_h2_conn(&self, authority: &str, addr: SocketAddr) -> Result<H2Conn> {
        let stream = crate::net::connect(&addr, self.inner.config.connect_timeout)?;
        let conn = h2::start(stream, &self.inner.config)?;
        let mut pools = self.inner.h2_pool.lock().unwrap();
        let list = pools.entry(authority.to_string()).or_default();
        list.push(conn.clone());
        Ok(conn)
    }
}

fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr> {
    // Fast path: literal IP.
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
    // Relative or protocol-relative redirect.
    let mut s = format!("http://{}{}", base.authority(), location);
    if location.starts_with("//") {
        s = format!("http:{}", location);
    }
    Url::parse(&s)
}
