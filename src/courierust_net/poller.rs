//! I/O readiness poller for the event-driven server.
//!
//! Lets a small worker pool park thousands of idle connections instead of
//! holding one thread per connection:
//!
//! * **Windows** wraps the Winsock2 `select()` call directly — a
//!   zero-dependency way to wait on many sockets at once. `select` is
//!   used instead of `WSAPoll` because `WSAPoll` rejects sockets with
//!   `WSAEINVAL` in some environments; sockets are polled in batches of
//!   `FD_SETSIZE` (64).
//! * **Unix** wraps the POSIX `poll()` call, which has no 64-socket batch
//!   limit and does not mutate its timeout argument.
//!
//! The server falls back to the per-connection blocking pool model only
//! when `ServerConfig::event_driven` is explicitly disabled.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::net::TcpStream;

/// The platform socket descriptor type used by the poller.
#[cfg(windows)]
pub(crate) type Fd = std::os::windows::io::RawSocket;
#[cfg(not(windows))]
pub(crate) type Fd = std::os::fd::RawFd;

/// The raw descriptor of a socket, whatever the platform.
pub(crate) fn fd_of(socket: &TcpStream) -> Fd {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        socket.as_raw_socket()
    }
    #[cfg(not(windows))]
    {
        use std::os::fd::AsRawFd;
        socket.as_raw_fd()
    }
}

// ---------------------------------------------------------------------
// Platform-specific readiness primitives
// ---------------------------------------------------------------------

/// Winsock2 `fd_set` / `timeval` and `select` (batches of `FD_SETSIZE`).
#[cfg(windows)]
mod ws {
    use super::Fd;
    use std::os::windows::io::RawSocket;

    pub(super) const FD_SETSIZE: usize = 64;

    /// `fd_set` (winsock2.h). Must match the C layout exactly.
    #[repr(C)]
    pub(super) struct FdSet {
        fd_count: u32,
        fd_array: [RawSocket; FD_SETSIZE],
    }

    impl FdSet {
        pub(super) fn new() -> Self {
            Self {
                fd_count: 0,
                fd_array: [0; FD_SETSIZE],
            }
        }

        pub(super) fn insert(&mut self, fd: Fd) {
            if (self.fd_count as usize) < FD_SETSIZE {
                self.fd_array[self.fd_count as usize] = fd;
                self.fd_count += 1;
            }
        }

        /// The ready sockets as reported by `select`
        pub(super) fn ready(&self) -> &[RawSocket] {
            &self.fd_array[..self.fd_count as usize]
        }
    }

    /// `timeval` (winsock2.h).
    #[repr(C)]
    pub(super) struct TimeVal {
        pub(super) tv_sec: i32,
        pub(super) tv_usec: i32,
    }

    #[link(name = "ws2_32")]
    extern "system" {
        pub(super) fn select(
            nfds: i32,
            readfds: *mut FdSet,
            writefds: *mut FdSet,
            exceptfds: *mut FdSet,
            timeout: *const TimeVal,
        ) -> i32;
    }
}

/// POSIX `pollfd` and `poll` (no batch limit).
#[cfg(not(windows))]
mod posix {
    use super::Fd;

    pub(super) const POLLIN: i16 = 0x001;
    pub(super) const POLLOUT: i16 = 0x004;
    pub(super) const POLLERR: i16 = 0x008;
    pub(super) const POLLHUP: i16 = 0x010;
    pub(super) const POLLNVAL: i16 = 0x020;

    /// `struct pollfd` (poll.h) — identical on Linux, macOS and the BSDs.
    #[repr(C)]
    pub(super) struct PollFd {
        pub(super) fd: Fd,
        pub(super) events: i16,
        pub(super) revents: i16,
    }

    /// `nfds_t`: `unsigned long` on Linux/Android, `unsigned int`
    /// elsewhere (macOS, the BSDs, Solaris).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) type NfdsT = u64;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub(super) type NfdsT = u32;

    extern "C" {
        pub(super) fn poll(fds: *mut PollFd, nfds: NfdsT, timeout: i32) -> i32;
    }
}

// ---------------------------------------------------------------------
// Poller
// ---------------------------------------------------------------------

/// A set of sockets watched for readiness. Each socket is watched in a
/// single direction: `want_write == false` waits for readability
/// (incoming request data); `want_write == true` waits for writability
/// (the peer draining our buffered response).
pub(crate) struct Poller {
    fds: Vec<(usize, Fd, bool)>,
    index: HashMap<usize, usize>,
}

impl Poller {
    pub(crate) fn new() -> Self {
        Self {
            fds: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Whether no sockets are registered.
    pub(crate) fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }

    /// Register `fd` under `id` for read (`want_write = false`) or write
    /// (`want_write = true`) readiness.
    pub(crate) fn register(&mut self, id: usize, fd: Fd, want_write: bool) {
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
    /// errored/closed).
    pub(crate) fn wait(&mut self, timeout_ms: i32) -> std::io::Result<Vec<usize>> {
        if self.fds.is_empty() {
            return Ok(Vec::new());
        }
        #[cfg(windows)]
        {
            self.wait_select(timeout_ms)
        }
        #[cfg(not(windows))]
        {
            self.wait_poll(timeout_ms)
        }
    }

    /// Winsock `select()` implementation, polling in `FD_SETSIZE`-sized batches
    #[cfg(windows)]
    fn wait_select(&self, timeout_ms: i32) -> std::io::Result<Vec<usize>> {
        use ws::*;
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

    /// POSIX `poll()` implementation (single call; no batch limit).
    #[cfg(not(windows))]
    fn wait_poll(&self, timeout_ms: i32) -> std::io::Result<Vec<usize>> {
        use posix::*;
        let mut pfds: Vec<PollFd> = self
            .fds
            .iter()
            .map(|&(_, fd, ww)| PollFd {
                fd,
                events: if ww { POLLOUT } else { POLLIN },
                revents: 0,
            })
            .collect();
        let n = unsafe { poll(pfds.as_mut_ptr(), pfds.len() as NfdsT, timeout_ms) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut ready = Vec::new();
        for (idx, pfd) in pfds.iter().enumerate() {
            let (_, _, ww) = self.fds[idx];
            let expected = if ww { POLLOUT } else { POLLIN };
            if pfd.revents & (expected | POLLERR | POLLHUP | POLLNVAL) != 0 {
                ready.push(self.fds[idx].0);
            }
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

    #[test]
    fn poll_reports_readable_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        let mut p = Poller::new();
        let fd = fd_of(&server);
        p.register(7, fd, false);

        let ready = p.wait(50).unwrap();
        assert!(ready.is_empty(), "unexpected ready: {ready:?}");

        client.write_all(b"hi").unwrap();
        let ready = p.wait(2000).unwrap();
        assert_eq!(ready, vec![7]);

        let mut b = [0u8; 8];
        let mut s = &server;
        let n = s.read(&mut b).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn unregister_stops_reporting() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        let mut p = Poller::new();
        let fd = fd_of(&server);
        p.register(7, fd, false);
        p.unregister(7);
        assert!(p.is_empty());

        client.write_all(b"hi").unwrap();
        let ready = p.wait(100).unwrap();
        assert!(ready.is_empty(), "unregistered socket reported: {ready:?}");
    }
}
