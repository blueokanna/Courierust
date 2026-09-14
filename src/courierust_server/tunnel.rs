//! Raw connection tunnelling.
//!
//! Some upgrade protocols are not framed by the server: `CONNECT`
//! (RFC 9110 §9.3.6), a custom `Upgrade` token, or any negotiation where the
//! two sides simply exchange bytes after a handshake. [`Handler::tunnel`]
//! lets an application take such a connection over once the server has
//! written the response head.
//!
//! [`Handler::tunnel`]: crate::courierust_server::Handler::tunnel

use crate::courierust_body::Body;
use crate::courierust_http::header::HeaderMap;
use crate::courierust_http::response::Response;
use crate::courierust_http::status::StatusCode;
use crate::courierust_io::{BufReader, Read, Write};
use crate::courierust_net::ConnStream;
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// What a handler answers when asked whether a request should tunnel.
pub enum TunnelReply {
    /// Not a tunnel request: the server handles it normally.
    Pass,
    /// Refuse the tunnel and answer with this response.
    Refuse(Response<Body>),
    /// Accept: the server writes the plan's head, then hands the connection
    /// to the plan's service.
    Accept(TunnelPlan),
}

/// An accepted tunnel: the response head plus the service that runs it.
pub struct TunnelPlan {
    /// Status of the handshake response: `200` for `CONNECT`, `101` for a
    /// protocol switch.
    pub status: StatusCode,
    /// Headers of the handshake response.
    pub headers: HeaderMap,
    /// Runs the connection once the head is on the wire.
    pub service: Arc<dyn TunnelService>,
}

impl TunnelPlan {
    /// A `200 OK` with no headers — the `CONNECT` case.
    pub fn connect(service: Arc<dyn TunnelService>) -> Self {
        Self {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            service,
        }
    }

    /// A `101 Switching Protocols` with no headers — any other upgrade.
    pub fn switching(service: Arc<dyn TunnelService>) -> Self {
        Self {
            status: StatusCode::SWITCHING_PROTOCOLS,
            headers: HeaderMap::new(),
            service,
        }
    }
}

/// Runs one tunnelled connection.
///
/// The callback owns the connection until it returns, on a thread of its
/// own — that is what makes a blocking relay legal here and is the point of
/// a tunnel. Returning ends the connection: the socket is closed and the
/// server's connection accounting is released.
pub trait TunnelService: Send + Sync + 'static {
    /// Handle the connection.
    fn run(&self, conn: TunnelConn);
}

impl<F> TunnelService for F
where
    F: Fn(TunnelConn) + Send + Sync + 'static,
{
    fn run(&self, conn: TunnelConn) {
        self(conn)
    }
}

/// A connection handed to a [`TunnelService`] after the handshake response
/// is on the wire.
///
/// Reads are served from the connection's buffer first, so bytes the peer
/// pipelined behind the request head (a TLS `ClientHello` sent immediately
/// after `CONNECT`, for instance) are delivered and never reordered or
/// dropped. Writes go straight to the transport, TLS included.
pub struct TunnelConn {
    stream: Arc<ConnStream>,
    reader: BufReader<Arc<ConnStream>>,
    secure: bool,
}

impl TunnelConn {
    pub(crate) fn new(
        stream: Arc<ConnStream>,
        reader: BufReader<Arc<ConnStream>>,
        secure: bool,
    ) -> Self {
        Self {
            stream,
            reader,
            secure,
        }
    }

    /// The remote address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.stream.peer_addr()
    }

    /// Whether the connection arrived over TLS.
    pub fn is_secure(&self) -> bool {
        self.secure
    }

    /// The negotiated ALPN protocol (TLS connections only).
    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.stream.alpn()
    }

    /// Arm a read timeout with *poll* semantics: an expiry is reported as
    /// `ErrorKind::WouldBlock`, so a driver loop can tell "no data yet" from
    /// a real failure.
    pub fn configure(&self, read_timeout: Option<Duration>) -> crate::courierust_error::Result<()> {
        self.stream.configure(read_timeout)
    }

    /// Arm a read timeout with *deadline* semantics: an expiry is reported
    /// as `ErrorKind::Timeout`.
    pub fn set_deadline(
        &self,
        read_timeout: Option<Duration>,
    ) -> crate::courierust_error::Result<()> {
        self.stream.set_deadline(read_timeout)
    }

    /// Shut down the transport's read, write or both halves, waking a thread
    /// blocked in a read on the other half.
    pub fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        self.stream.shutdown(how)
    }

    /// Drain a bounded amount of unread peer data before the socket closes,
    /// so a request the server refused is not answered with a RST.
    pub fn linger_close(&self, budget: usize, deadline: Duration) {
        self.stream.linger_close(budget, deadline);
    }
}

impl Read for TunnelConn {
    fn read(&mut self, buf: &mut [u8]) -> crate::courierust_error::Result<usize> {
        self.reader.read_direct(buf)
    }
}

impl Write for TunnelConn {
    fn write(&mut self, buf: &[u8]) -> crate::courierust_error::Result<usize> {
        let mut writer = &*self.stream;
        writer.write(buf)
    }

    fn flush(&mut self) -> crate::courierust_error::Result<()> {
        let mut writer = &*self.stream;
        writer.flush()
    }
}
