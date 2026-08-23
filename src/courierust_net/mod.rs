//! TCP transport adapters.
//!
//! Implements [`crate::courierust_io::Read`]/[`crate::courierust_io::Write`] for `&TcpStream`
//! so the same buffered codec drives both loopback tests and real
//! sockets. Non-blocking `WouldBlock` maps to [`crate::ErrorKind::WouldBlock`].

use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub(crate) mod poller;
pub mod stats;
pub(crate) mod udp;

impl Read for &TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match std::io::Read::read(self, buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err(Error::new(ErrorKind::WouldBlock))
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                Err(Error::new(ErrorKind::Timeout))
            }
            Err(e) if e.raw_os_error() == Some(997) => Err(Error::new(ErrorKind::WouldBlock)),
            Err(e) => Err(e.into()),
        }
    }
}

impl Write for &TcpStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match std::io::Write::write(self, buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err(Error::new(ErrorKind::WouldBlock))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn flush(&mut self) -> Result<()> {
        match std::io::Write::flush(self) {
            Ok(()) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

// `Arc<TcpStream>` mirrors the `&TcpStream` impls so a connection can
// share one socket between a reader and a writer without self-referencing
// (the h1/h2 connections keep both buffers alive for the connection's
// lifetime).
impl Read for Arc<TcpStream> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut r: &TcpStream = self;
        r.read(buf)
    }
}

impl Write for Arc<TcpStream> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut w: &TcpStream = self;
        w.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        let mut w: &TcpStream = self;
        w.flush()
    }
}

/// Re-export of the standard listener.
pub type Listener = TcpListener;

/// A transport that is either a plain TCP socket or a TLS 1.3 stream.
///
/// Both the HTTP client and server speak over [`ConnStream`], so HTTPS is
/// a drop-in: a `https://` URL wraps the socket in TLS before the HTTP
/// codec reads or writes, and a server configured with a TLS identity
/// accepts TLS on the same accept loop as plain HTTP.
pub(crate) struct ConnStream {
    peer: SocketAddr,
    inner: ConnStreamKind,
}

enum ConnStreamKind {
    Plain(TcpStream),
    Tls {
        /// The raw socket (shared with the TLS layer, used to reconfigure
        /// timeouts after the handshake).
        socket: Arc<TcpStream>,
        /// The TLS 1.3 stream. Guarded because the shared `&ConnStream`
        /// transport used by the h1/h2 codecs must reach `&mut` access.
        /// Boxed so the `Plain` variant stays small (the TLS stream is
        /// several hundred bytes).
        tls:
            Box<std::sync::Mutex<crate::courierust_tls::TlsStream<Arc<TcpStream>, Arc<TcpStream>>>>,
    },
}

impl ConnStream {
    /// Wrap a plain TCP stream.
    pub(crate) fn plain(stream: TcpStream) -> Self {
        let peer = stream
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        Self {
            peer,
            inner: ConnStreamKind::Plain(stream),
        }
    }

    /// Establish a TLS 1.3 client connection over `stream`, authenticating
    /// `hostname` against the server certificate.
    pub(crate) fn tls_client(
        stream: TcpStream,
        connector: &crate::courierust_tls::TlsConnector,
        hostname: &str,
    ) -> crate::Result<Self> {
        let peer = stream.peer_addr().map_err(|e| Error::io(e.to_string()))?;
        let socket = Arc::new(stream);
        let tls = connector
            .connect(hostname, socket.clone(), socket.clone())
            .map_err(|e| Error::io(e.to_string()))?;
        Ok(Self {
            peer,
            inner: ConnStreamKind::Tls {
                socket,
                tls: Box::new(std::sync::Mutex::new(tls)),
            },
        })
    }

    /// Wrap an already-completed server-side TLS stream.
    pub(crate) fn tls_server(
        tls: crate::courierust_tls::TlsStream<Arc<TcpStream>, Arc<TcpStream>>,
        peer: SocketAddr,
    ) -> Self {
        let socket = tls.underlying().clone();
        Self {
            peer,
            inner: ConnStreamKind::Tls {
                socket,
                tls: Box::new(std::sync::Mutex::new(tls)),
            },
        }
    }

    /// The remote address.
    pub(crate) fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The negotiated ALPN protocol (TLS connections only).
    pub(crate) fn alpn(&self) -> Option<Vec<u8>> {
        match &self.inner {
            ConnStreamKind::Tls { tls, .. } => {
                tls.lock().ok().and_then(|g| g.alpn().map(|a| a.to_vec()))
            }
            ConnStreamKind::Plain(_) => None,
        }
    }

    /// Peek bytes without consuming (plain connections only).
    pub(crate) fn peek(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &self.inner {
            ConnStreamKind::Plain(s) => s.peek(buf),
            ConnStreamKind::Tls { .. } => Err(std::io::Error::other(
                "peek is not supported on TLS streams",
            )),
        }
    }

    /// Configure nodelay + read timeout on the underlying socket.
    pub(crate) fn configure(&self, read_timeout: Option<Duration>) -> Result<()> {
        match &self.inner {
            ConnStreamKind::Plain(s) => configure(s, read_timeout),
            ConnStreamKind::Tls { socket, .. } => configure(socket, read_timeout),
        }
    }
}

impl crate::courierust_io::Read for &ConnStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match &self.inner {
            ConnStreamKind::Plain(s) => {
                let mut r: &TcpStream = s;
                crate::courierust_io::Read::read(&mut r, buf)
            }
            ConnStreamKind::Tls { tls, .. } => {
                let mut g = tls.lock().unwrap();
                crate::courierust_io::Read::read(&mut *g, buf)
            }
        }
    }
}

impl crate::courierust_io::Write for &ConnStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match &self.inner {
            ConnStreamKind::Plain(s) => {
                let mut w: &TcpStream = s;
                crate::courierust_io::Write::write(&mut w, buf)
            }
            ConnStreamKind::Tls { tls, .. } => {
                let mut g = tls.lock().unwrap();
                crate::courierust_io::Write::write(&mut *g, buf)
            }
        }
    }

    fn flush(&mut self) -> Result<()> {
        match &self.inner {
            ConnStreamKind::Plain(s) => {
                let mut w: &TcpStream = s;
                crate::courierust_io::Write::flush(&mut w)
            }
            ConnStreamKind::Tls { tls, .. } => {
                let mut g = tls.lock().unwrap();
                crate::courierust_io::Write::flush(&mut *g)
            }
        }
    }
}

impl crate::courierust_io::Read for ConnStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        (&*self).read(buf)
    }
}

impl crate::courierust_io::Write for ConnStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        (&*self).write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        (&*self).flush()
    }
}

impl crate::courierust_io::Read for Arc<ConnStream> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut r: &ConnStream = self;
        r.read(buf)
    }
}

impl crate::courierust_io::Write for Arc<ConnStream> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut w: &ConnStream = self;
        w.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        let mut w: &ConnStream = self;
        w.flush()
    }
}

/// Configure a stream for the blocking driver loops used by the client
/// and server.
pub fn configure(stream: &TcpStream, read_timeout: Option<Duration>) -> Result<()> {
    stream
        .set_nodelay(true)
        .map_err(|e| Error::io(e.to_string()))?;
    if let Some(t) = read_timeout {
        stream
            .set_read_timeout(Some(t))
            .map_err(|e| Error::io(e.to_string()))?;
    }
    Ok(())
}

/// Connect with an optional timeout.
pub fn connect(addr: &std::net::SocketAddr, timeout: Option<Duration>) -> Result<TcpStream> {
    let stream = match timeout {
        Some(t) => TcpStream::connect_timeout(addr, t),
        None => TcpStream::connect(addr),
    }
    .map_err(|e| Error::io(e.to_string()))?;
    stream
        .set_nodelay(true)
        .map_err(|e| Error::io(e.to_string()))?;
    Ok(stream)
}
