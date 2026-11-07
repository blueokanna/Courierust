//! Socket readiness shared by the threaded HTTP/2 client and server.
use super::connection::Connection;
use crate::courierust_body::ChannelStream;
use crate::courierust_error::Result;
use crate::courierust_io::{Read, Write};
use crate::courierust_net::poller::{fd_of, Poller, WAKE_ID};
use crate::courierust_net::wake::{drain_wake, wake_nudge, wakeup_pair};
use crate::courierust_net::ConnStream;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn watch_body(body: &ChannelStream, wake: &Arc<TcpStream>) {
    let wake = Arc::downgrade(wake);
    body.install_wake(move || {
        if let Some(wake) = wake.upgrade() {
            wake_nudge(&wake);
        }
    });
}

pub(crate) struct Readiness {
    poller: Poller,
    reader: TcpStream,
    writer: Arc<TcpStream>,
}

impl Readiness {
    pub(crate) fn new(stream: &ConnStream) -> Result<Self> {
        let (reader, writer) = wakeup_pair()?;
        let mut poller = Poller::new();
        poller.register(1, stream.raw_fd(), false);
        Ok(Self {
            poller,
            reader,
            writer: Arc::new(writer),
        })
    }

    pub(crate) fn notifier(&self) -> Arc<TcpStream> {
        self.writer.clone()
    }

    /// Flush before parking. Internal codec/TLS input must be consumed even
    /// when the kernel has no further bytes. Plain sockets are non-blocking;
    /// TLS reads retain a bounded poll timeout and record writes remain blocking.
    pub(crate) fn poll<R: Read, W: Write>(
        &mut self,
        conn: &mut Connection<R, W>,
        stream: &ConnStream,
        wait: Duration,
    ) -> Result<bool> {
        let wrote = conn.flush_progress()?;
        if conn.buffered_input() || stream.has_pending_read() {
            return conn.poll_available(64);
        }
        if conn.transport_write_pending() {
            self.poller.register(2, stream.raw_fd(), true);
        } else {
            self.poller.unregister(2);
        }
        let millis = if wrote {
            0
        } else {
            wait.as_millis().min(i32::MAX as u128) as i32
        };
        let ready = self.poller.wait(millis, Some(fd_of(&self.reader)))?;
        if ready.contains(&WAKE_ID) {
            drain_wake(&self.reader);
        }
        if ready.contains(&1) {
            conn.poll_available(64)
        } else {
            if ready.contains(&2) {
                conn.flush_progress()?;
            }
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_data_and_end_both_notify_the_poller() {
        let (reader, writer) = wakeup_pair().unwrap();
        let writer = Arc::new(writer);
        let (sender, body) = crate::courierust_body::channel();
        let body = body.into_stream().unwrap();
        watch_body(&body, &writer);
        let mut poller = Poller::new();
        assert!(poller.wait(0, Some(fd_of(&reader))).unwrap().is_empty());
        sender.send_bytes(b"payload").unwrap();
        assert_eq!(poller.wait(1000, Some(fd_of(&reader))).unwrap(), [WAKE_ID]);
        drain_wake(&reader);
        assert_eq!(&*body.try_recv().unwrap().unwrap(), b"payload");
        drop(sender);
        assert_eq!(poller.wait(1000, Some(fd_of(&reader))).unwrap(), [WAKE_ID]);
        assert!(matches!(
            body.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected)
        ));
    }
}
