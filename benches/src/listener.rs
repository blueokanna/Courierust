//! A blocking accept interface with cancellation that allocates no TCP port.

use std::io;
use std::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Listener for synchronous benchmark peers. Accepted sockets are blocking;
/// the accept wait itself is driven by Tokio's readiness reactor.
pub struct CancellableListener {
    runtime: tokio::runtime::Runtime,
    listener: tokio::net::TcpListener,
    stop: oneshot::Receiver<()>,
    closed: bool,
}

impl CancellableListener {
    /// Wrap a listener and return an independent shutdown sender. Sending or
    /// dropping the sender interrupts `accept`, without connecting to the peer.
    pub fn new(listener: TcpListener) -> io::Result<(Self, oneshot::Sender<()>)> {
        listener.set_nonblocking(true)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        let listener = {
            let _entered = runtime.enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let (sender, stop) = oneshot::channel();
        Ok((
            Self {
                runtime,
                listener,
                stop,
                closed: false,
            },
            sender,
        ))
    }

    /// Accept one blocking socket, or return `None` after shutdown.
    pub fn accept(&mut self) -> io::Result<Option<TcpStream>> {
        if self.closed {
            return Ok(None);
        }
        let accepted = self.runtime.block_on(async {
            tokio::select! {
                biased;
                _ = &mut self.stop => Ok(None),
                result = self.listener.accept() => result.map(|(socket, _)| Some(socket)),
            }
        })?;
        match accepted {
            Some(socket) => {
                let socket = socket.into_std()?;
                socket.set_nonblocking(false)?;
                Ok(Some(socket))
            }
            None => {
                self.closed = true;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_does_not_need_an_incoming_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut listener, stop) = CancellableListener::new(listener).unwrap();
        let (done, completed) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            assert!(listener.accept().unwrap().is_none());
            assert!(listener.accept().unwrap().is_none());
            done.send(()).unwrap();
        });
        stop.send(()).unwrap();
        completed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn dropping_shutdown_sender_also_cancels_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut listener, stop) = CancellableListener::new(listener).unwrap();
        drop(stop);
        assert!(listener.accept().unwrap().is_none());
    }
}
