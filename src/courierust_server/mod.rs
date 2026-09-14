//! HTTP server.
//!
//! By default connections are handled by an **event-driven** scheduler: a
//! dedicated accept thread hands sockets to an I/O event loop which parks
//! idle / partial / slow connections on a readiness poller instead of
//! holding a worker thread, so a herd of slow clients cannot exhaust the
//! pool (see [`ServerConfig::event_driven`]). The work-stealing pool runs
//! HTTP/1.1 request handlers and the blocking TLS / HTTP/2 connection
//! loops. Setting [`ServerConfig::event_driven`] to `false` restores the
//! legacy one-blocking-pool-job-per-connection model for comparison and
//! debugging.
//!
//! There are two ways in, depending on who owns the accept loop:
//!
//! * [`Server`] binds (or adopts, via [`Server::from_listener`]) a
//!   listener and runs the scheduler itself.
//! * [`serve_connection`] drives **one** accepted connection — TLS, ALPN,
//!   HTTP/1.1 / HTTP/2, WebSocket upgrades, tunnels — for a caller that
//!   accepts the socket itself: a proxy gating connections by peer
//!   address, a supervisor sharing one listener between services, or a
//!   process that must bind before dropping privileges.
//!
//! Both paths run the same engine; the difference is only who calls
//! `accept`.

pub mod h1;
pub mod h2;
pub mod tunnel;
pub mod ws;

pub(crate) mod event;

pub use tunnel::{TunnelConn, TunnelPlan, TunnelReply, TunnelService};

use crate::courierust_body::Body;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_net::stats::Stats;
use crate::courierust_pool::ThreadPool;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

/// Server-side TLS settings. When set, the server speaks HTTPS on its
/// accept loop (TLS handshakes run on the worker pool).
#[derive(Debug, Clone)]
pub struct TlsSettings {
    /// The server's certificate chain and private key.
    pub identity: crate::courierust_tls::Identity,
    /// ALPN protocols offered (the first client match wins; `h2` selects
    /// HTTP/2, anything else falls back to HTTP/1.1).
    pub alpn: Vec<Vec<u8>>,
    /// Lowest TLS version the server will negotiate.
    pub min_version: crate::courierust_tls::TlsVersion,
    /// Highest TLS version the server will negotiate.
    pub max_version: crate::courierust_tls::TlsVersion,
    /// Session-ticket encryption key for TLS 1.3 resumption. Derived
    /// randomly when these settings are built (once per server process),
    /// so a ticket issued on one connection is accepted on the next —
    /// that is what makes resumption real across pooled clients. Set a
    /// fixed key to share tickets across server instances; an all-zero
    /// key (including the one left behind when the OS entropy source
    /// fails) disables resumption rather than sealing tickets with a
    /// public constant.
    pub session_ticket_key: [u8; 32],
    /// Client authentication (mTLS): when set, the server asks every
    /// client for a certificate (RFC 8446 §4.4.2) and validates it
    /// against the roots in [`crate::courierust_tls::ClientAuth`].
    /// Implemented for TLS 1.3; an HTTP/3 listener rejects this setting
    /// at startup rather than serving QUIC without it.
    pub client_auth: Option<crate::courierust_tls::ClientAuth>,
}

impl Default for TlsSettings {
    /// [`Identity::empty`](crate::courierust_tls::Identity::empty) with
    /// the default TLS 1.2..=1.3 window and an empty ALPN list. It exists
    /// so call sites can write `TlsSettings { identity, alpn,
    /// ..Default::default() }`; prefer [`TlsSettings::from_pem_file`]. A
    /// server built on an empty identity is rejected when it is bound,
    /// not answered with a failed handshake per connection.
    fn default() -> Self {
        let mut ticket_key = [0u8; 32];
        let _ = crate::courierust_tls::crypto::rng::fill_random(&mut ticket_key);
        Self {
            identity: crate::courierust_tls::Identity::empty(),
            alpn: Vec::new(),
            min_version: crate::courierust_tls::TlsVersion::Tls12,
            max_version: crate::courierust_tls::TlsVersion::Tls13,
            session_ticket_key: ticket_key,
            client_auth: None,
        }
    }
}

impl TlsSettings {
    /// TLS settings from a PEM certificate chain and a PEM private key,
    /// with the ALPN offer a browser-facing HTTPS server wants: `h2`
    /// first, then `http/1.1`.
    ///
    /// Both documents are validated by
    /// [`Identity::from_pem`](crate::courierust_tls::Identity::from_pem) —
    /// a key that does not match the leaf certificate fails *here*, at
    /// startup, instead of failing every handshake later. Clear or replace
    /// `alpn` afterwards to change the offer; an empty list disables ALPN,
    /// and a TLS connection then never negotiates HTTP/2.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> crate::courierust_tls::TlsResult<Self> {
        Ok(Self {
            identity: crate::courierust_tls::Identity::from_pem(cert_pem, key_pem)?,
            alpn: default_alpn(),
            ..Self::default()
        })
    }

    /// [`TlsSettings::from_pem`] over two files.
    pub fn from_pem_file(
        cert_path: impl AsRef<std::path::Path>,
        key_path: impl AsRef<std::path::Path>,
    ) -> crate::courierust_tls::TlsResult<Self> {
        Ok(Self {
            identity: crate::courierust_tls::Identity::from_pem_file(cert_path, key_path)?,
            alpn: default_alpn(),
            ..Self::default()
        })
    }
}

/// The ALPN offer a TLS server starts with.
fn default_alpn() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Read timeout for connections.
    pub read_timeout: Option<Duration>,
    /// Maximum header-list size.
    pub max_header_list: usize,
    /// Maximum request body size.
    pub max_body: usize,
    /// Serve HTTP/2 (prior knowledge) in addition to HTTP/1.1.
    pub http2: bool,
    /// Enable HTTP/3 over QUIC on the same numeric port as the TCP listener.
    /// Requires [`Self::tls`].
    pub http3: bool,
    /// Number of worker threads.
    pub threads: usize,
    /// Optional TLS identity; when set, the server accepts HTTPS.
    pub tls: Option<TlsSettings>,
    /// Use the event-driven connection scheduler (default on every
    /// platform). Plain HTTP/1.1 connections park on a readiness poller
    /// when idle instead of holding a worker thread; TLS and HTTP/2
    /// connections still run on the blocking pool. When `false`, the
    /// legacy one-blocking-pool-job-per-connection model is used (a herd
    /// of idle connections can then exhaust the pool).
    pub event_driven: bool,
    /// Number of event-worker threads (0 = auto).
    pub event_workers: usize,
    /// Upper bound on how long the event loop parks inside a single poll
    /// call (milliseconds). Socket readiness (a client sending a request)
    /// and the self-pipe (a worker or the accept thread queuing a control
    /// message) both interrupt the poll immediately, so this value only
    /// bounds the wait when *nothing* is happening — it is not in the
    /// request-latency path. Larger values cut idle wakeups; 0 falls back
    /// to the 50 ms default.
    pub event_poll_timeout_ms: u64,
    /// Maximum number of concurrently open connections the server will keep.
    /// The default is finite; `0` means unlimited and is intended only for
    /// explicitly controlled deployments. New connections
    /// beyond this cap are closed immediately, bounding the file
    /// descriptors and parked slots a herd of idle / slow-loris clients
    /// can consume even before the idle timeout reaps them. This bounds
    /// the event path; TLS and HTTP/2 connections are additionally
    /// bounded by the worker pool and their idle timeouts.
    pub max_connections: usize,
    /// TLS handshake timeout: a client that connects and then stalls
    /// mid-handshake releases its pool worker after this long (instead of
    /// holding it for the full `read_timeout`). Plain connections are
    /// unaffected. `None` falls back to `read_timeout`.
    pub handshake_timeout: Option<Duration>,
    /// Close an HTTP/1.1 connection that has been parked (no bytes in
    /// either direction) for this long. Bounds the resources a herd of
    /// idle / slow-loris connections can consume. `None` disables it.
    pub idle_timeout: Option<Duration>,
    /// h2: drop the connection if the peer does not ACK our SETTINGS
    /// within this long (`SETTINGS_TIMEOUT`, RFC 9113 §6.5.3).
    pub h2_settings_timeout: Option<Duration>,
    /// h2: send a keepalive PING after this much inbound silence.
    pub h2_ping_interval: Option<Duration>,
    /// h2: drop the connection if no frame at all arrives within this
    /// long after a keepalive PING was sent (dead-peer detection).
    pub h2_ping_timeout: Option<Duration>,
    /// h2: close a connection with no in-flight streams after this much
    /// idle time, releasing the worker thread it occupied.
    pub h2_idle_timeout: Option<Duration>,
    /// h2: `SETTINGS_MAX_CONCURRENT_STREAMS` this server advertises
    /// (RFC 9113 §6.5.2; 0 = unlimited). Streams beyond this limit are
    /// rejected with `REFUSED_STREAM`.
    pub h2_max_concurrent_streams: u32,
    /// h2: return receive flow-control credit to the peer as request-body
    /// DATA frames arrive (batched by the connection). With this enabled
    /// (the default) the peer can stream arbitrarily large request bodies
    /// up to [`Self::max_body`]; with it disabled, the peer is limited to
    /// the advertised window unless the application releases credit
    /// itself.
    pub auto_release_credit: bool,
    /// Optional instrumentation: when set, the accept loop, event loop,
    /// h1 workers and h2 connections update these counters (connection /
    /// stream / reactor / syscall evidence for benchmarks). `None`
    /// (default) disables the accounting entirely.
    pub stats: Option<Arc<crate::courierust_net::stats::Stats>>,
    /// WebSocket policy: origin checks, subprotocols, limits,
    /// `permessage-deflate` and keepalive.
    pub websocket: ws::WsConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            read_timeout: Some(Duration::from_secs(120)),
            max_header_list: 1 << 20,
            max_body: 16 * 1024 * 1024,
            http2: true,
            http3: false,
            threads: 0, // 0 = bounded auto (up to eight workers)
            tls: None,
            event_driven: true,
            event_workers: 0,
            event_poll_timeout_ms: 50,
            max_connections: 1024,
            handshake_timeout: Some(Duration::from_secs(10)),
            idle_timeout: Some(Duration::from_secs(300)),
            h2_settings_timeout: Some(Duration::from_secs(10)),
            h2_ping_interval: Some(Duration::from_secs(30)),
            h2_ping_timeout: Some(Duration::from_secs(15)),
            h2_idle_timeout: Some(Duration::from_secs(300)),
            h2_max_concurrent_streams: 1024,
            auto_release_credit: true,
            stats: None,
            websocket: ws::WsConfig::default(),
        }
    }
}

/// A request handler.
pub trait Handler: Send + Sync + 'static {
    /// Handle one request and produce a response.
    fn handle(&self, req: Request<Body>) -> Response<Body>;

    /// Decide whether to accept a WebSocket upgrade.
    ///
    /// Called *before* [`Handler::handle`] for requests that carry a
    /// syntactically valid RFC 6455 upgrade, so the handler can inspect
    /// the request (path, headers, query) and either accept it, refuse it
    /// with an HTTP response, or pass it through to normal HTTP handling.
    ///
    /// The server performs the wire work — `Sec-WebSocket-Accept`, the
    /// subprotocol echo, extension negotiation, origin policy, limits —
    /// from [`ServerConfig::websocket`]; a handler never has to build a
    /// `101` by hand.
    fn websocket(&self, _req: &Request<Body>) -> ws::WsUpgradeReply {
        ws::WsUpgradeReply::Pass
    }

    /// Decide whether to tunnel this connection.
    ///
    /// Called before [`Handler::handle`] for every other request: returning
    /// [`TunnelReply::Accept`] makes the server write the plan's response
    /// head and then hand the connection — buffered bytes included — to a
    /// [`TunnelService`], which owns it until it returns. This is how
    /// `CONNECT`, `Upgrade: <token>` and gRPC-style raw pipes are served.
    fn tunnel(&self, _req: &Request<Body>) -> TunnelReply {
        TunnelReply::Pass
    }
}

impl<F> Handler for F
where
    F: Fn(Request<Body>) -> Response<Body> + Send + Sync + 'static,
{
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        self(req)
    }
}

/// Upper bound on the port draws made when an HTTP/3 server asks for an
/// ephemeral port: every draw has to satisfy both stacks, and Windows
/// reserves its UDP and TCP ranges independently.
const H3_PORT_ATTEMPTS: usize = 16;

/// Bind the TCP listener, plus the HTTP/3 UDP socket when it is enabled.
///
/// The two sockets must share a port number: a client that validated a
/// certificate for `host:port` sends its QUIC packets to that same port,
/// and nothing else would reach the identity it trusted. Windows keeps a
/// *separate* excluded range for UDP (Hyper-V / WinNAT), so a port the TCP
/// stack hands out can come back `PermissionDenied` — WSAEACCES, 10013 —
/// from UDP: a failure with nothing to fix and no port to report. With an
/// ephemeral request that leaves exactly one recovery, which is to draw
/// again. A caller that named a port gets that port or the error; a
/// silently different port would break the authority the client validated.
fn bind_listeners(
    addr: impl ToSocketAddrs,
    http3: bool,
) -> std::io::Result<(TcpListener, Option<UdpSocket>)> {
    let addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    let ephemeral = addrs.iter().any(|a| a.port() == 0);
    let attempts = if http3 && ephemeral {
        H3_PORT_ATTEMPTS
    } else {
        1
    };
    let mut last: Option<std::io::Error> = None;
    for _ in 0..attempts {
        for resolved in &addrs {
            match bind_pair(*resolved, http3) {
                Ok(pair) => return Ok(pair),
                Err(error) => last = Some(error),
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no address to bind")
    }))
}

/// One binding attempt: UDP first when HTTP/3 is on, so the port is one
/// UDP can actually take and TCP has to agree with it, rather than the
/// other way round.
fn bind_pair(addr: SocketAddr, http3: bool) -> std::io::Result<(TcpListener, Option<UdpSocket>)> {
    if !http3 {
        return Ok((TcpListener::bind(addr)?, None));
    }
    let udp = crate::courierust_net::udp::bind_udp(addr)?;
    let mut tcp_addr = addr;
    tcp_addr.set_port(udp.local_addr()?.port());
    let listener = TcpListener::bind(tcp_addr)?;
    Ok((listener, Some(udp)))
}

/// An HTTP server.
pub struct Server {
    listener: TcpListener,
    pool: Arc<ThreadPool>,
    config: ServerConfig,
    /// The HTTP/3 UDP socket, bound here rather than inside the serve
    /// thread. The two sockets must share a port number, and binding both
    /// before either is advertised is what makes that share a promise
    /// instead of a race (see [`bind_listeners`]).
    h3_socket: Option<UdpSocket>,
}

impl Server {
    /// Bind to `addr`.
    pub fn bind(addr: impl std::net::ToSocketAddrs) -> std::io::Result<Self> {
        Self::bind_with_config(addr, ServerConfig::default())
    }

    /// Bind with a custom config.
    pub fn bind_with_config(
        addr: impl std::net::ToSocketAddrs,
        config: ServerConfig,
    ) -> std::io::Result<Self> {
        let (listener, h3_socket) = bind_listeners(addr, config.http3)?;
        Self::adopt(listener, h3_socket, config)
    }

    /// Adopt a listener the caller already bound.
    ///
    /// For embedders that have to own the bind: a process that drops
    /// privileges after binding, a supervisor (systemd socket activation,
    /// a port shared between services), or a caller that wants the
    /// descriptor first. Everything else behaves exactly like
    /// [`Server::bind_with_config`], including the HTTP/3 socket: with
    /// [`ServerConfig::http3`] the UDP socket is bound here on the
    /// listener's port — the two must share it — so this call can still
    /// fail where `bind_with_config` would have drawn another port.
    pub fn from_listener(listener: TcpListener, config: ServerConfig) -> std::io::Result<Self> {
        let h3_socket = if config.http3 {
            let addr = listener.local_addr()?;
            Some(crate::courierust_net::udp::bind_udp(addr)?)
        } else {
            None
        };
        Self::adopt(listener, h3_socket, config)
    }

    /// The single place a `Server` is assembled.
    ///
    /// The identity is checked here — once, at startup — rather than in
    /// the handshake path: a TLS server with no certificate is a
    /// configuration error, and the useful place for that error is the
    /// call that created the server.
    fn adopt(
        listener: TcpListener,
        h3_socket: Option<UdpSocket>,
        config: ServerConfig,
    ) -> std::io::Result<Self> {
        if let Some(message) = identity_error(&config) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                message,
            ));
        }
        let threads = if config.threads == 0 {
            recommended_workers()
        } else {
            config.threads
        };
        Ok(Self {
            listener,
            pool: pool_for(threads),
            config,
            h3_socket,
        })
    }

    /// The bound address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve forever, blocking the calling thread.
    pub fn serve<H: Handler>(self, handler: H) -> std::io::Result<()> {
        self.serve_with_config(handler)
    }

    /// Serve with the bound config, blocking.
    pub fn serve_with_config<H: Handler>(self, handler: H) -> std::io::Result<()> {
        self.serve_inner(handler, None, ServerStop::new())
    }

    /// Serve with the bound config, blocking, until `stop` is requested.
    ///
    /// The same signal a [`ServerHandle`] carries, for a caller that wants
    /// to run the accept loop on a thread it owns.
    pub fn serve_with_stop<H: Handler>(self, handler: H, stop: ServerStop) -> std::io::Result<()> {
        self.serve_inner(handler, None, stop)
    }

    /// Shared serve implementation. When `ready` is supplied, it receives
    /// the transport-setup outcome once the reactor is running, so a
    /// background caller can start connecting without racing it. The
    /// HTTP/3 socket is already bound by then: both sockets are bound
    /// together in [`Server::bind_with_config`], so the address
    /// `local_addr` reports is one a client can use over TCP and UDP
    /// alike.
    fn serve_inner<H: Handler>(
        self,
        handler: H,
        ready: Option<&std::sync::mpsc::Sender<std::io::Result<()>>>,
        stop: ServerStop,
    ) -> std::io::Result<()> {
        let handler = Arc::new(handler);
        let config = self.config;
        let pool = self.pool;
        let h3_socket = self.h3_socket;
        let setup: std::io::Result<Option<_>> = (|| {
            if !config.http3 {
                return Ok(None);
            }
            let tls = config.tls.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ServerConfig.http3 requires a TLS identity",
                )
            })?;
            if tls.client_auth.is_some() {
                // QUIC has its own handshake driver, and it does not
                // implement client authentication: refuse at startup
                // rather than serve QUIC connections that bypass the
                // policy the operator asked for.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ServerConfig.http3 cannot enforce client authentication \
                     (mTLS is implemented for TLS 1.3 over TCP)",
                ));
            }
            let socket = h3_socket.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HTTP/3 was enabled after bind; rebuild the server with ServerConfig.http3",
                )
            })?;
            Ok(Some(
                crate::courierust_h3::runtime::spawn_server_with_socket(
                    socket,
                    tls,
                    handler.clone(),
                    config.clone(),
                )?,
            ))
        })();
        if let Some(ready) = ready {
            // Propagate a setup failure (e.g. an un-bindable HTTP/3 UDP
            // port) so a background caller never waits forever.
            let _ = ready.send(match &setup {
                Ok(_) => Ok(()),
                Err(error) => Err(std::io::Error::new(error.kind(), error.to_string())),
            });
        }
        // Keep the HTTP/3 reactor handle alive for the whole serve loop.
        let _http3 = setup?;
        if config.event_driven {
            return event::serve_event(self.listener, handler, config, pool, stop);
        }
        // Legacy pool model (event_driven = false): bound the number of
        // concurrently open connections with `max_connections`, so even
        // this deprecated path cannot be exhausted by a herd of idle /
        // slow clients. The default event path is the supported one.
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // A stop request has to reach a thread parked in `accept`: the
        // handle keeps a second reference to the listener and connects to
        // it, which makes the blocked accept return one throwaway socket.
        stop.install_listener(self.listener.try_clone()?);
        for stream in self.listener.incoming() {
            if stop.is_requested() {
                break;
            }
            match stream {
                Ok(stream) => {
                    if let Some(s) = config.stats.as_deref() {
                        s.connections_accepted
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if !try_reserve(&active, config.max_connections) {
                        drop(stream);
                        continue;
                    }
                    let h = handler.clone();
                    let c = config.clone();
                    let p = pool.clone();
                    let active = active.clone();
                    if let Some(s) = config.stats.as_deref() {
                        s.connections_active
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    let permit = ConnectionPermit {
                        active: active.clone(),
                        stats: config.stats.clone(),
                    };
                    p.spawn(move || {
                        let _permit = permit;
                        // TLS handshakes (blocking) also run on the pool.
                        let _ = serve_connection(stream, h.as_ref(), &c);
                    });
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }

    /// Serve in the background. The returned handle is only produced once
    /// the server is actually listening: the TCP listener is bound eagerly
    /// in `bind_with_config`, and an HTTP/3 server's UDP socket is bound
    /// in the server thread before this returns — so callers may connect
    /// to `local_addr()` immediately without racing the reactor.
    ///
    /// [`ServerHandle::stop`] shuts the server down; [`ServerHandle::join`]
    /// waits for it. A server is never stopped by dropping the handle, so a
    /// forgotten handle in a test cannot silently tear down a listener the
    /// test is still using.
    pub fn serve_background<H: Handler>(self, handler: H) -> std::io::Result<ServerHandle> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (tx, rx) = std::sync::mpsc::channel();
        let stop = ServerStop::new();
        let thread_stop = stop.clone();
        std::thread::Builder::new()
            .name("courierust-server".into())
            .spawn(move || {
                let res = self.serve_inner(handler, Some(&ready_tx), thread_stop);
                let _ = tx.send(res);
            })?;
        // Block until the transport is ready, propagating a bind/setup
        // failure (e.g. an un-bindable HTTP/3 UDP port) to the caller.
        ready_rx.recv().unwrap_or(Ok(()))?;
        Ok(ServerHandle { done: rx, stop })
    }
}

fn recommended_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 8))
        .unwrap_or(4)
}

/// The worker pool a server starts with.
///
/// `ThreadPool::with_size` fails only when the OS refuses the thread, and
/// a server that cannot spawn its pool cannot serve at all: fall back to
/// the smallest pool that still makes progress instead of panicking in a
/// constructor that is called before anything is listening.
fn pool_for(threads: usize) -> Arc<ThreadPool> {
    Arc::new(
        ThreadPool::with_size(threads).unwrap_or_else(|_| ThreadPool::with_size(2).expect("pool")),
    )
}

/// Why a configuration cannot serve TLS at all.
///
/// Checked by every entry point that creates a server or drives a
/// connection, so an empty identity is one clear error at startup instead
/// of one failed handshake per client.
fn identity_error(config: &ServerConfig) -> Option<&'static str> {
    match config.tls.as_ref() {
        Some(tls) if tls.identity.is_empty() => Some(
            "TLS is enabled but the identity is empty: load a certificate/key pair with \
             Identity::from_pem_file (or Identity::from_pem)",
        ),
        _ => None,
    }
}

fn try_reserve(active: &std::sync::atomic::AtomicUsize, limit: usize) -> bool {
    if limit == 0 {
        active.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        return true;
    }
    let mut current = active.load(std::sync::atomic::Ordering::Acquire);
    loop {
        if current >= limit {
            return false;
        }
        match active.compare_exchange_weak(
            current,
            current + 1,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

/// Own one legacy pool connection permit until the job exits. The pool
/// catches panics at its worker boundary, so a decrement placed after the
/// connection handler would be skipped on a panic and permanently consume
/// the configured connection limit.
struct ConnectionPermit {
    active: Arc<std::sync::atomic::AtomicUsize>,
    stats: Option<Arc<Stats>>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        Stats::decrement(&self.active, 1);
        if let Some(stats) = self.stats.as_deref() {
            Stats::decrement(&stats.connections_active, 1);
        }
    }
}

/// A stop signal for a running server.
///
/// Cloning shares one signal. It is separate from [`ServerHandle`] because
/// the two paths that have to observe it — the event reactor and the
/// blocking accept loop — live below the handle, and a caller that runs its
/// own accept thread (`serve_with_stop`) needs the same type.
#[derive(Clone)]
pub struct ServerStop {
    requested: Arc<std::sync::atomic::AtomicBool>,
    /// The reactor's self-pipe writer; nudged so a parked poll returns.
    reactor_wake: Arc<std::sync::Mutex<Option<TcpStream>>>,
    /// A second reference to the listening socket, used to wake a thread
    /// blocked in `accept` (the blocking path has no poller to wake).
    listener: Arc<std::sync::Mutex<Option<TcpListener>>>,
}

impl ServerStop {
    /// A fresh, unrequested signal.
    pub fn new() -> Self {
        Self {
            requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reactor_wake: Arc::new(std::sync::Mutex::new(None)),
            listener: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Request a shutdown. Idempotent.
    pub fn request(&self) {
        if !self
            .requested
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.wake();
        }
    }

    /// Whether a shutdown has been requested.
    pub fn is_requested(&self) -> bool {
        self.requested.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Wake whatever the server is parked on: the reactor's poll, or a
    /// blocking `accept`.
    fn wake(&self) {
        if let Ok(guard) = self.reactor_wake.lock() {
            if let Some(writer) = guard.as_ref() {
                event::wake_nudge(writer);
            }
        }
        if let Ok(guard) = self.listener.lock() {
            if let Some(listener) = guard.as_ref() {
                if let Ok(addr) = listener.local_addr() {
                    let target = match addr.ip() {
                        std::net::IpAddr::V4(ip) if ip.is_unspecified() => {
                            SocketAddr::from(([127, 0, 0, 1], addr.port()))
                        }
                        std::net::IpAddr::V6(ip) if ip.is_unspecified() => {
                            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, addr.port()))
                        }
                        _ => addr,
                    };
                    let _ = TcpStream::connect_timeout(&target, Duration::from_millis(200));
                }
            }
        }
    }

    pub(crate) fn install_reactor_wake(&self, writer: TcpStream) {
        if let Ok(mut guard) = self.reactor_wake.lock() {
            *guard = Some(writer);
        }
    }

    pub(crate) fn install_listener(&self, listener: TcpListener) {
        if let Ok(mut guard) = self.listener.lock() {
            *guard = Some(listener);
        }
    }
}

impl Default for ServerStop {
    fn default() -> Self {
        Self::new()
    }
}

/// A handle to a background server.
pub struct ServerHandle {
    done: std::sync::mpsc::Receiver<std::io::Result<()>>,
    stop: ServerStop,
}

impl ServerHandle {
    /// Ask the server to stop accepting and return. Idempotent.
    pub fn stop(&self) {
        self.stop.request();
    }

    /// Whether a stop has been requested on this handle.
    pub fn is_stopping(&self) -> bool {
        self.stop.is_requested()
    }

    /// The stop signal, for a caller that wants to observe or re-issue it.
    pub fn stop_signal(&self) -> ServerStop {
        self.stop.clone()
    }

    /// Wait for the server to stop.
    pub fn join(self) -> std::io::Result<()> {
        self.done.recv().unwrap_or(Ok(()))
    }
}

impl std::fmt::Debug for ServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandle")
            .field("stopping", &self.is_stopping())
            .finish_non_exhaustive()
    }
}

/// Serve one accepted TCP connection to completion.
///
/// The whole per-connection engine behind one call: TLS when the config
/// carries an identity, then ALPN, HTTP/1.1 / HTTP/2, WebSocket upgrades
/// and tunnels. It is public because an embedder may own the accept loop
/// — a proxy that decides on a connection before the engine sees it (peer
/// address policy, rate limits, its own logging and accounting), a
/// supervisor sharing one listener between services, a process that must
/// bind before dropping privileges. The peer address is available before
/// this call (`TcpStream::peer_addr`), and that is where per-connection
/// policy belongs: the engine is handed a socket, not an identity.
///
/// The socket is configured here: `TCP_NODELAY`, plus
/// [`ServerConfig::handshake_timeout`] while a TLS handshake runs, then
/// [`ServerConfig::read_timeout`] for the request loop.
///
/// [`ServerConfig::http3`] is rejected rather than ignored: QUIC runs on
/// the server's own UDP reactor for as long as the server lives (see
/// [`Server::serve_background`]), which a per-connection driver cannot
/// reach — serving only TCP while the config asked for HTTP/3 would be a
/// silent half-service.
pub fn serve_connection(
    stream: TcpStream,
    handler: &dyn Handler,
    config: &ServerConfig,
) -> crate::Result<()> {
    if let Some(message) = identity_error(config) {
        return Err(crate::courierust_error::Error::with_message(
            crate::courierust_error::ErrorKind::Other,
            message,
        ));
    }
    if config.http3 {
        return Err(crate::courierust_error::Error::with_message(
            crate::courierust_error::ErrorKind::Other,
            "HTTP/3 is served by the server's QUIC reactor (Server::serve_background); \
             serve_connection drives TCP only",
        ));
    }
    // A TLS handshake runs under `handshake_timeout` (short) so a
    // client that connects and then stalls mid-handshake releases its
    // pool worker instead of holding it for the full application read
    // timeout. The application timeout is restored before serving.
    if config.tls.is_some() {
        crate::courierust_net::configure(&stream, config.handshake_timeout)?;
    } else {
        crate::courierust_net::configure(&stream, config.read_timeout)?;
    }
    match &config.tls {
        Some(t) => {
            let acceptor =
                crate::courierust_tls::TlsAcceptor::new(crate::courierust_tls::ServerConfig {
                    identity: t.identity.clone(),
                    alpn: t.alpn.clone(),
                    min_version: t.min_version,
                    max_version: t.max_version,
                    // A per-process stable ticket key: tickets issued on
                    // one connection are accepted on the next, so pooled
                    // clients actually resume instead of paying a full
                    // handshake every time.
                    session_ticket_key: Some(t.session_ticket_key),
                    client_auth: t.client_auth.clone(),
                });
            let arc = Arc::new(stream);
            let peer = arc
                .peer_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
            let tls = acceptor.accept(arc.clone(), arc.clone()).map_err(|e| {
                crate::courierust_error::Error::with_message(
                    crate::courierust_error::ErrorKind::Other,
                    e.to_string(),
                )
            })?;
            let conn = crate::courierust_net::ConnStream::tls_server(tls, peer);
            let _ = conn.configure(config.read_timeout);
            dispatch(conn, handler, config)
        }
        None => dispatch(
            crate::courierust_net::ConnStream::plain(stream),
            handler,
            config,
        ),
    }
}

/// Dispatch a connection to h1 or h2. TLS connections use the ALPN
/// result when available; plain TCP connections sniff the client preface.
pub(crate) fn dispatch(
    stream: crate::courierust_net::ConnStream,
    handler: &dyn Handler,
    config: &ServerConfig,
) -> crate::Result<()> {
    let stream = Arc::new(stream);
    if let Some(alpn) = stream.alpn() {
        if config.http2 && alpn == b"h2" {
            return h2::serve(&stream, handler, config);
        }
        return h1::serve(&stream, handler, config);
    }
    let mut prefix = [0u8; 24];
    let n = stream.peek(&mut prefix).unwrap_or(0);
    if config.http2 && n == 24 && crate::courierust_h2::connection::is_preface(&prefix) {
        h2::serve(&stream, handler, config)
    } else {
        h1::serve(&stream, handler, config)
    }
}
