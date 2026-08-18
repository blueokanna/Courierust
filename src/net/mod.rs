//! TCP transport adapters.
//!
//! Implements [`crate::io::Read`]/[`crate::io::Write`] for `&TcpStream`
//! so the same buffered codec drives both loopback tests and real
//! sockets. Non-blocking `WouldBlock` maps to [`crate::ErrorKind::WouldBlock`].

use crate::error::{Error, ErrorKind, Result};
use crate::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

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

/// Re-export of the standard listener.
pub type Listener = TcpListener;

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
