//! TCP transport adapters.
//!
//! Implements [`crate::courierust_io::Read`]/[`crate::courierust_io::Write`] for `&TcpStream`
//! so the same buffered codec drives both loopback tests and real
//! sockets. Non-blocking `WouldBlock` maps to [`crate::ErrorKind::WouldBlock`].
//!
//! A socket read timeout is *not* reported the same way by every kernel:
//! Windows fails the read with `WSAETIMEDOUT`, POSIX with `EAGAIN` — the
//! very code that otherwise means "no data right now". The connection
//! adapter therefore distinguishes the two reasons a read timeout can be
//! armed: a *deadline* (`ConnStream::set_deadline`, a request or a
//! shutdown budget, where expiry is an answer of its own) and a *poll*
//! (`ConnStream::configure`, where the h2/h3 drivers use a short timeout
//! to regain control and must keep seeing `WouldBlock`).

use crate::courierust_error::{Error, ErrorKind, Result};
use crate::courierust_io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Whether the socket timeout is a *deadline*: on expiry the read is
    /// cut short by the kernel and POSIX reports `EAGAIN`, which has to
    /// be told apart from "no data yet", so the flag decides how
    /// `WouldBlock` is classified. See the module docs.
    deadline: AtomicBool,
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
            deadline: AtomicBool::new(false),
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
            deadline: AtomicBool::new(false),
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
            deadline: AtomicBool::new(false),
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

    /// The underlying socket descriptor, for a readiness poll.
    ///
    /// A poll (unlike a read) cannot disturb a TLS stream: it observes
    /// the wire, which is exactly what a liveness probe asks about.
    pub(crate) fn raw_fd(&self) -> crate::courierust_net::poller::Fd {
        match &self.inner {
            ConnStreamKind::Plain(s) => crate::courierust_net::poller::fd_of(s),
            ConnStreamKind::Tls { socket, .. } => crate::courierust_net::poller::fd_of(socket),
        }
    }

    /// Configure nodelay + read timeout on the underlying socket, with
    /// *poll* semantics: an expiry reports `WouldBlock` so a driver that
    /// armed a short timeout to regain control can tell it apart from a
    /// real failure and go round its loop again.
    pub(crate) fn configure(&self, read_timeout: Option<Duration>) -> Result<()> {
        self.deadline.store(false, Ordering::Relaxed);
        match &self.inner {
            ConnStreamKind::Plain(s) => configure(s, read_timeout),
            ConnStreamKind::Tls { socket, .. } => configure(socket, read_timeout),
        }
    }

    /// Configure nodelay + read timeout with *deadline* semantics: the
    /// timeout is a budget whose expiry is an outcome, not a lull.
    ///
    /// On expiry the read fails with `WSAETIMEDOUT` on Windows and with
    /// `EAGAIN` on POSIX; the second is the same code a non-blocking
    /// socket uses for "nothing yet", so the adapter needs to be told
    /// which one this is. While a deadline is armed, a read that would
    /// report `WouldBlock` reports [`ErrorKind::Timeout`] instead — for
    /// every read path, including the ones buried in a buffered codec.
    pub(crate) fn set_deadline(&self, read_timeout: Option<Duration>) -> Result<()> {
        self.configure(read_timeout)?;
        self.deadline.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Drain a bounded amount of unread request data before the socket is
    /// closed, then leave the deadline in place.
    ///
    /// Closing a socket whose receive buffer still holds unread bytes
    /// makes Linux answer with a RST, and a RST can destroy the error
    /// response we just wrote — the client sees a connection reset
    /// instead of the `400` it needs to understand what went wrong. The
    /// budget and the deadline keep this from becoming a slowloris
    /// vector: it is a bounded courtesy, not a promise to read a body.
    pub(crate) fn linger_close(&self, budget: usize, deadline: Duration) {
        let _ = self.configure(Some(deadline));
        let mut sink = [0u8; 8 * 1024];
        let mut left = budget;
        while left > 0 {
            let mut reader = self;
            let want = core::cmp::min(left, sink.len());
            match crate::courierust_io::Read::read(&mut reader, &mut sink[..want]) {
                Ok(0) => break,
                Ok(n) => left = left.saturating_sub(n),
                // A timeout, a reset or a TLS error all mean the peer has
                // nothing more to say: stop waiting for it.
                Err(_) => break,
            }
        }
    }
}

impl crate::courierust_io::Read for &ConnStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = match &self.inner {
            ConnStreamKind::Plain(s) => {
                let mut r: &TcpStream = s;
                crate::courierust_io::Read::read(&mut r, buf)
            }
            ConnStreamKind::Tls { tls, .. } => {
                // A poisoned TLS lock would otherwise turn one panicking
                // handler into a connection that can never be read or
                // written again.
                let mut g = tls.lock().unwrap_or_else(|e| e.into_inner());
                crate::courierust_io::Read::read(&mut *g, buf)
            }
        };
        // A read cut short by an armed deadline is reported as a timeout
        // whichever way the kernel signals it (see the module docs).
        // Without this, POSIX callers of `timeout(..)` see `WouldBlock`,
        // and a close-delimited body treats the expiry as a clean EOF.
        read.map_err(|e| {
            if e.kind == ErrorKind::WouldBlock && self.deadline.load(Ordering::Relaxed) {
                Error::timeout("read deadline expired")
            } else {
                e
            }
        })
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
                let mut g = tls.lock().unwrap_or_else(|e| e.into_inner());
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
                let mut g = tls.lock().unwrap_or_else(|e| e.into_inner());
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
///
/// The deadline is applied **explicitly**, including when it is `None`:
/// a driver that arms a deadline for an idle wait and clears it for bulk
/// transfers has to be able to clear it, and "leave whatever was there"
/// would silently keep the slow path in place.
pub fn configure(stream: &TcpStream, read_timeout: Option<Duration>) -> Result<()> {
    stream
        .set_nodelay(true)
        .map_err(|e| Error::io(e.to_string()))?;
    stream
        .set_read_timeout(read_timeout)
        .map_err(|e| Error::io(e.to_string()))?;
    // A blocking `write` on a socket whose peer has stopped reading parks
    // until the kernel gives up — minutes, or never. Every driver loop
    // here is built around a bounded wait (it has to service timeouts,
    // ACKs and shutdown while a body is being sent), so the write side
    // gets the same deadline as the read side: a peer that stops reading
    // is a liveness failure, not a reason to freeze the thread.
    stream
        .set_write_timeout(read_timeout)
        .map_err(|e| Error::io(e.to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A read timeout armed as a *deadline* is a timeout on every
    /// platform: Windows fails the read with `WSAETIMEDOUT`, which the
    /// raw adapter already maps to [`ErrorKind::Timeout`], while POSIX
    /// fails it with `EAGAIN`, which means "no data yet" to everyone
    /// else — the deadline flag is what makes the two agree.
    #[test]
    fn deadline_read_timeout_is_reported_as_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        // The peer has to stay open for the whole wait, or the socket
        // would report a reset instead of an expiry.
        let (_peer, _) = listener.accept().unwrap();

        let stream = ConnStream::plain(client);
        stream
            .set_deadline(Some(Duration::from_millis(50)))
            .unwrap();

        let mut sink = [0u8; 16];
        let started = std::time::Instant::now();
        let mut reader: &ConnStream = &stream;
        let err = reader
            .read(&mut sink)
            .expect_err("nothing was ever sent on the connection");
        assert_eq!(err.kind, ErrorKind::Timeout, "{err:?}");
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "the read must wait out the deadline instead of failing at once"
        );
    }
}
