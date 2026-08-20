//! I/O readiness poller for the event-driven server.
//!
//! On Windows this wraps the Winsock2 `select()` call directly — a
//! zero-dependency way to wait on many sockets at once — which lets a
//! small worker pool park thousands of idle connections instead of
//! holding one thread per connection. On other platforms the server
//! falls back to the per-connection pool model, so this module is
//! Windows-only.
//!
//! `select` is used instead of `WSAPoll` because `WSAPoll` rejects
//! sockets with `WSAEINVAL` in some environments; `select` is the
//! battle-tested Winsock primitive. Sockets are polled in batches of
//! `FD_SETSIZE` (64).

#![cfg(windows)]
#![allow(unsafe_code)] // only the select() FFI call below

use std::collections::HashMap;
use std::os::windows::io::RawSocket;

/// `FD_SETSIZE` — the number of sockets `select` can watch per call.
const FD_SETSIZE: usize = 64;

/// `fd_set` (winsock2.h). Must match the C layout exactly.
#[repr(C)]
struct FdSet {
    fd_count: u32,
    fd_array: [RawSocket; FD_SETSIZE],
}

impl FdSet {
    fn new() -> Self {
        Self {
            fd_count: 0,
            fd_array: [0; FD_SETSIZE],
        }
    }

    fn insert(&mut self, fd: RawSocket) {
        if (self.fd_count as usize) < FD_SETSIZE {
            self.fd_array[self.fd_count as usize] = fd;
            self.fd_count += 1;
        }
    }

    /// The ready sockets as reported by `select` (compacted to the
    /// front of `fd_array`).
    fn ready(&self) -> &[RawSocket] {
        &self.fd_array[..self.fd_count as usize]
    }
}

/// `timeval` (winsock2.h).
#[repr(C)]
struct TimeVal {
    tv_sec: i32,
    tv_usec: i32,
}

#[link(name = "ws2_32")]
extern "system" {
    fn select(
        nfds: i32,
        readfds: *mut FdSet,
        writefds: *mut FdSet,
        exceptfds: *mut FdSet,
        timeout: *const TimeVal,
    ) -> i32;
}

/// A set of sockets watched for readiness. Each socket is watched in a
/// single direction: `want_write == false` waits for readability
/// (incoming request data); `want_write == true` waits for writability
/// (the peer draining our buffered response).
pub(crate) struct Poller {
    fds: Vec<(usize, RawSocket, bool)>, // (id, fd, want_write)
    index: HashMap<usize, usize>,
}

impl Poller {
    pub(crate) fn new() -> Self {
        Self {
            fds: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Register `fd` under `id` for read (`want_write = false`) or write
    /// (`want_write = true`) readiness.
    pub(crate) fn register(&mut self, id: usize, fd: RawSocket, want_write: bool) {
        self.unregister(id);
        self.fds.push((id, fd, want_write));
        self.index.insert(id, self.fds.len() - 1);
    }

    /// Remove `id` if present.
    pub(crate) fn unregister(&mut self, id: usize) {
        if let Some(&idx) = self.index.get(&id) {
            self.fds.swap_remove(idx);
            if idx < self.fds.len() {
                self.index.insert(self.fds[idx].0, idx);
            }
            self.index.remove(&id);
        }
    }

    /// Wait up to `timeout_ms` for readiness. Returns the ids of ready
    /// sockets (readable or writable per their registered direction, or
    /// errored/closed). Sockets are polled in `FD_SETSIZE`-sized batches.
    pub(crate) fn wait(&mut self, timeout_ms: i32) -> std::io::Result<Vec<usize>> {
        if self.fds.is_empty() {
            return Ok(Vec::new());
        }
        let tv = TimeVal {
            tv_sec: timeout_ms / 1000,
            tv_usec: (timeout_ms % 1000) * 1000,
        };
        let mut ready = Vec::new();
        let mut batch = 0usize;
        while batch < self.fds.len() {
            let end = core::cmp::min(batch + FD_SETSIZE, self.fds.len());
            let mut readset = FdSet::new();
            let mut writeset = FdSet::new();
            for &(_, fd, ww) in &self.fds[batch..end] {
                if ww {
                    writeset.insert(fd);
                } else {
                    readset.insert(fd);
                }
            }
            // SAFETY: `readset`/`writeset` are valid, correctly-sized
            // fd_set values; select only reads/writes within them.
            let n = unsafe { select(0, &mut readset, &mut writeset, std::ptr::null_mut(), &tv) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if n > 0 {
                for &fd in readset.ready() {
                    if let Some((id, _, _)) = self.fds[batch..end].iter().find(|(_, f, _)| *f == fd)
                    {
                        ready.push(*id);
                    }
                }
                for &fd in writeset.ready() {
                    if let Some((id, _, _)) = self.fds[batch..end].iter().find(|(_, f, _)| *f == fd)
                    {
                        ready.push(*id);
                    }
                }
            }
            batch = end;
        }
        ready.sort_unstable();
        ready.dedup();
        Ok(ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::os::windows::io::AsRawSocket;

    #[test]
    fn poll_reports_readable_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        let mut p = Poller::new();
        let fd = server.as_raw_socket();
        p.register(7, fd, false);

        // Nothing to read yet: poll should time out.
        let ready = p.wait(50).unwrap();
        assert!(ready.is_empty(), "unexpected ready: {ready:?}");

        client.write_all(b"hi").unwrap();
        let ready = p.wait(2000).unwrap();
        assert_eq!(ready, vec![7]);

        // Consume the data.
        let mut b = [0u8; 8];
        let mut s = &server;
        let n = s.read(&mut b).unwrap();
        assert_eq!(n, 2);
    }
}
