//! HTTP server: each accepted connection becomes a job on the
//! work-stealing pool, so connection handling scales across cores.
//!
//! On Windows an optional **event-driven** mode parks idle connections on
//! a `WSAPoll` poller instead of holding a worker thread (see
//! [`ServerConfig::event_driven`]).

pub mod h1;
pub mod h2;

#[cfg(windows)]
pub(crate) mod event;

use crate::body::Body;
use crate::http::request::Request;
use crate::http::response::Response;
use crate::pool::ThreadPool;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Server-side TLS settings. When set, the server speaks HTTPS on its
/// accept loop (TLS handshakes run on the worker pool).
#[derive(Debug, Clone)]
pub struct TlsSettings {
    /// The server's certificate chain and private key.
    pub identity: crate::tls::Identity,
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
    /// Number of worker threads.
    pub threads: usize,
    /// Optional TLS identity; when set, the server accepts HTTPS.
    pub tls: Option<TlsSettings>,
    /// Use the event-driven connection scheduler (Windows). Plain
    /// HTTP/1.1 connections park on a `WSAPoll` poller when idle instead
    /// of holding a worker thread; TLS and HTTP/2 connections still use
    /// the pool model.
    pub event_driven: bool,
    /// Number of event-worker threads (0 = auto).
    pub event_workers: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            read_timeout: Some(Duration::from_secs(120)),
            max_header_list: 1 << 20,
            max_body: 16 * 1024 * 1024,
            http2: true,
            threads: 0, // 0 = auto (logical cores)
            tls: None,
            event_driven: cfg!(windows),
            event_workers: 0, // auto
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
                ThreadPool::new().unwrap_or_else(|_| ThreadPool::with_size(2).expect("pool")),
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
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
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
        let handler = Arc::new(handler);
        let config = self.config;
        let pool = self.pool;
        #[cfg(windows)]
        if config.event_driven {
            return event::serve_event(self.listener, handler, config, pool);
        }
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let h = handler.clone();
                    let c = config.clone();
                    let p = pool.clone();
                    p.spawn(move || {
                        // TLS handshakes (blocking) also run on the pool.
                        let _ = serve_accepted(stream, h.as_ref(), &c);
                    });
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }

    /// Serve in the background, returning immediately.
    pub fn serve_background<H: Handler>(self, handler: H) -> std::io::Result<ServerHandle> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("courierust-server".into())
            .spawn(move || {
                let res = self.serve_with_config(handler);
                let _ = tx.send(res);
            })?;
        Ok(ServerHandle { done: rx })
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
    crate::net::configure(&stream, config.read_timeout)?;
    match &config.tls {
        Some(t) => {
            let acceptor = crate::tls::TlsAcceptor::new(crate::tls::ServerConfig {
                identity: t.identity.clone(),
                alpn: t.alpn.clone(),
            });
            let arc = Arc::new(stream);
            let peer = arc
                .peer_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
            let tls = acceptor.accept(arc.clone(), arc.clone()).map_err(|e| {
                crate::error::Error::with_message(crate::error::ErrorKind::Other, e.to_string())
            })?;
            serve_connection(crate::net::ConnStream::tls_server(tls, peer), handler, config)
        }
        None => serve_connection(crate::net::ConnStream::plain(stream), handler, config),
    }
}

/// Dispatch a connection to h1 or h2. TLS connections use the ALPN
/// result when available; plain TCP connections sniff the client preface.
pub(crate) fn serve_connection(
    stream: crate::net::ConnStream,
    handler: &dyn Handler,
    config: &ServerConfig,
) -> crate::Result<()> {
    // TLS with ALPN: the negotiated protocol is authoritative.
    if let Some(alpn) = stream.alpn() {
        if config.http2 && alpn == b"h2" {
            return h2::serve(&stream, handler, config);
        }
        return h1::serve(&stream, handler, config);
    }
    // Plain TCP (or TLS without ALPN): sniff the h2 preface.
    let mut prefix = [0u8; 24];
    let n = stream.peek(&mut prefix).unwrap_or(0);
    if config.http2 && n == 24 && crate::h2::connection::is_preface(&prefix) {
        h2::serve(&stream, handler, config)
    } else {
        h1::serve(&stream, handler, config)
    }
}
