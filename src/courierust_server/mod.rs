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

pub mod h1;
pub mod h2;

pub(crate) mod event;

use crate::courierust_body::Body;
use crate::courierust_http::request::Request;
use crate::courierust_http::response::Response;
use crate::courierust_net::stats::Stats;
use crate::courierust_pool::ThreadPool;
use std::net::{SocketAddr, TcpListener, TcpStream};
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
        }
    }
}

/// A request handler.
pub trait Handler: Send + Sync + 'static {
    /// Handle one request and produce a response.
    fn handle(&self, req: Request<Body>) -> Response<Body>;
}

impl<F> Handler for F
where
    F: Fn(Request<Body>) -> Response<Body> + Send + Sync + 'static,
{
    fn handle(&self, req: Request<Body>) -> Response<Body> {
        self(req)
    }
}

/// An HTTP server.
pub struct Server {
    listener: TcpListener,
    pool: Arc<ThreadPool>,
    config: ServerConfig,
}

impl Server {
    /// Bind to `addr`.
    pub fn bind(addr: impl std::net::ToSocketAddrs) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self {
            listener,
            pool: Arc::new(
                ThreadPool::with_size(recommended_workers())
                    .unwrap_or_else(|_| ThreadPool::with_size(2).expect("pool")),
            ),
            config: ServerConfig::default(),
        })
    }

    /// Bind with a custom config.
    pub fn bind_with_config(
        addr: impl std::net::ToSocketAddrs,
        config: ServerConfig,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let size = if config.threads == 0 {
            recommended_workers()
        } else {
            config.threads
        };
        Ok(Self {
            listener,
            pool: Arc::new(
                ThreadPool::with_size(size)
                    .unwrap_or_else(|_| ThreadPool::with_size(2).expect("pool")),
            ),
            config,
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
        self.serve_inner(handler, None)
    }

    /// Shared serve implementation. When `ready` is supplied, it receives
    /// the transport-setup outcome once every socket is bound, so a
    /// background caller can start connecting without racing the reactor
    /// thread. This matters for HTTP/3: the UDP socket is bound inside
    /// `spawn_server`, which runs in this thread — a caller that connects
    /// before that bind lands observes `Connection refused` on a freshly
    /// bound TCP listener that has no UDP peer yet.
    fn serve_inner<H: Handler>(
        self,
        handler: H,
        ready: Option<&std::sync::mpsc::Sender<std::io::Result<()>>>,
    ) -> std::io::Result<()> {
        let handler = Arc::new(handler);
        let config = self.config;
        let pool = self.pool;
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
            Ok(Some(crate::courierust_h3::runtime::spawn_server(
                self.listener.local_addr()?,
                tls,
                handler.clone(),
                config.clone(),
            )?))
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
            return event::serve_event(self.listener, handler, config, pool);
        }
        // Legacy pool model (event_driven = false): bound the number of
        // concurrently open connections with `max_connections`, so even
        // this deprecated path cannot be exhausted by a herd of idle /
        // slow clients. The default event path is the supported one.
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for stream in self.listener.incoming() {
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
                        let _ = serve_accepted(stream, h.as_ref(), &c);
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
    pub fn serve_background<H: Handler>(self, handler: H) -> std::io::Result<ServerHandle> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("courierust-server".into())
            .spawn(move || {
                let res = self.serve_inner(handler, Some(&ready_tx));
                let _ = tx.send(res);
            })?;
        // Block until the transport is ready, propagating a bind/setup
        // failure (e.g. an un-bindable HTTP/3 UDP port) to the caller.
        ready_rx.recv().unwrap_or(Ok(()))?;
        Ok(ServerHandle { done: rx })
    }
}

fn recommended_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 8))
        .unwrap_or(4)
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

/// A handle to a background server; blocks until it exits.
pub struct ServerHandle {
    done: std::sync::mpsc::Receiver<std::io::Result<()>>,
}

impl ServerHandle {
    /// Wait for the server to stop.
    pub fn join(self) -> std::io::Result<()> {
        self.done.recv().unwrap_or(Ok(()))
    }
}

/// Configure the raw socket and run one connection (plain or TLS).
pub(crate) fn serve_accepted(
    stream: TcpStream,
    handler: &dyn Handler,
    config: &ServerConfig,
) -> crate::Result<()> {
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
            serve_connection(conn, handler, config)
        }
        None => serve_connection(
            crate::courierust_net::ConnStream::plain(stream),
            handler,
            config,
        ),
    }
}

/// Dispatch a connection to h1 or h2. TLS connections use the ALPN
/// result when available; plain TCP connections sniff the client preface.
pub(crate) fn serve_connection(
    stream: crate::courierust_net::ConnStream,
    handler: &dyn Handler,
    config: &ServerConfig,
) -> crate::Result<()> {
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
