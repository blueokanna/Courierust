//! I/O readiness poller for the event-driven server: parks thousands of
//! idle connections without one thread each.
//!
//! * **Windows**: Winsock `select` (batches of 64). Only the first batch
//!   waits for the full timeout; later batches use zero timeout so a
//!   ready socket in batch *k* is not delayed by earlier batches.
//! * **Unix**: POSIX `poll` (no batch limit).
//!
//! Both accept an optional *wake* descriptor (the event loop's
//! self-pipe) watched in every batch, so a worker or the accept thread
//! can interrupt a blocking poll with one byte — control messages never
//! wait for a poll tick.
//!
//! On Windows the process timer resolution is raised to 1 ms for its
//! lifetime (see [`ensure_high_resolution_timer`]); Winsock `select`
//! wakeups otherwise align to the coarse default system timer and add
//! multi-millisecond latency even when a datagram is already queued.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::net::{TcpStream, UdpSocket};

/// The platform socket descriptor type used by the poller.
#[cfg(windows)]
pub(crate) type Fd = std::os::windows::io::RawSocket;
#[cfg(not(windows))]
pub(crate) type Fd = std::os::fd::RawFd;

/// Reserved poller id for the wake (self-pipe) descriptor. The event
/// loop never treats this id as a connection.
pub(crate) const WAKE_ID: usize = 0;

/// Raise the Windows timer resolution to 1 ms for the process lifetime
/// (called once, idempotently, from the first `Poller`). `select()` and
/// `sleep()` wakeups otherwise align to the coarse default timer (up to
/// ~15.6 ms), which would add multi-millisecond latency to the poller
/// even when a datagram is already queued. The resolution is never
/// lowered again — the standard practice for latency-sensitive
/// processes; the cost is a slightly higher timer interrupt rate.
#[cfg(windows)]
pub(crate) fn ensure_high_resolution_timer() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: `timeBeginPeriod` is a documented Win32 multimedia
        // timer API with no preconditions and no failure mode for
        // period 1.
        unsafe {
            timeBeginPeriod(1);
        }
    });
}

#[cfg(windows)]
#[link(name = "winmm")]
extern "system" {
    fn timeBeginPeriod(period: u32) -> u32;
}

/// The raw descriptor of a TCP socket, whatever the platform.
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

/// The raw descriptor of a UDP socket, whatever the platform.
pub(crate) fn udp_fd_of(socket: &UdpSocket) -> Fd {
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
        #[cfg(windows)]
        ensure_high_resolution_timer();
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

    /// Wait up to `timeout_ms` for readiness. `wake` is an optional
    /// descriptor (the event loop's self-pipe) watched for readability in
    /// every batch; when it fires, [`WAKE_ID`] is included in the result.
    /// Returns the ids of ready sockets (readable or writable per their
    /// registered direction, or errored/closed).
    pub(crate) fn wait(
        &mut self,
        timeout_ms: i32,
        wake: Option<Fd>,
    ) -> std::io::Result<Vec<usize>> {
        if self.fds.is_empty() && wake.is_none() {
            return Ok(Vec::new());
        }
        #[cfg(windows)]
        {
            self.wait_select(timeout_ms, wake)
        }
        #[cfg(not(windows))]
        {
            self.wait_poll(timeout_ms, wake)
        }
    }

    /// Winsock `select()` implementation, polling in `FD_SETSIZE`-sized
    /// batches. Only the first batch waits for the full `timeout_ms`;
    /// every later batch uses a zero timeout so a ready socket in a late
    /// batch is reported promptly instead of being delayed by every
    /// earlier batch's timeout. The wake descriptor (when given) is added
    /// to every batch's read set, so a wakeup byte interrupts the very
    /// first batch immediately.
    #[cfg(windows)]
    fn wait_select(&self, timeout_ms: i32, wake: Option<Fd>) -> std::io::Result<Vec<usize>> {
        use ws::*;
        let full_tv = TimeVal {
            tv_sec: timeout_ms / 1000,
            tv_usec: (timeout_ms % 1000) * 1000,
        };
        let zero_tv = TimeVal {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut ready = Vec::new();
        // At least one batch always runs — when no connection fds are
        // registered, a single batch holding just the wake descriptor is
        // still polled, so the wake pipe alone can interrupt the wait.
        let batches = self.fds.len().div_ceil(FD_SETSIZE).max(1);
        for b in 0..batches {
            let start = b * FD_SETSIZE;
            let end = core::cmp::min(start + FD_SETSIZE, self.fds.len());
            let mut readset = FdSet::new();
            let mut writeset = FdSet::new();
            if let Some(w) = wake {
                readset.insert(w);
            }
            let mut wake_ready = false;
            for &(_, fd, ww) in &self.fds[start..end] {
                if ww {
                    writeset.insert(fd);
                } else {
                    readset.insert(fd);
                }
            }

            let tv = if b == 0 { &full_tv } else { &zero_tv };
            let n = unsafe { select(0, &mut readset, &mut writeset, std::ptr::null_mut(), tv) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if n > 0 {
                for &fd in readset.ready() {
                    if Some(fd) == wake {
                        wake_ready = true;
                        continue;
                    }
                    if let Some((id, _, _)) = self.fds[start..end].iter().find(|(_, f, _)| *f == fd)
                    {
                        ready.push(*id);
                    }
                }
                for &fd in writeset.ready() {
                    if let Some((id, _, _)) = self.fds[start..end].iter().find(|(_, f, _)| *f == fd)
                    {
                        ready.push(*id);
                    }
                }
            }
            if wake_ready {
                ready.push(WAKE_ID);
            }
        }
        ready.sort_unstable();
        ready.dedup();
        Ok(ready)
    }

    /// POSIX `poll()` implementation (single call; no batch limit). The
    /// wake descriptor (when given) is appended to the poll set.
    #[cfg(not(windows))]
    fn wait_poll(&self, timeout_ms: i32, wake: Option<Fd>) -> std::io::Result<Vec<usize>> {
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
        let wake_idx = match wake {
            Some(w) => {
                pfds.push(PollFd {
                    fd: w,
                    events: POLLIN,
                    revents: 0,
                });
                Some(pfds.len() - 1)
            }
            None => None,
        };
        let n = unsafe { poll(pfds.as_mut_ptr(), pfds.len() as NfdsT, timeout_ms) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut ready = Vec::new();
        for (idx, pfd) in pfds.iter().enumerate() {
            if Some(idx) == wake_idx {
                if pfd.revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL) != 0 {
                    ready.push(WAKE_ID);
                }
                continue;
            }
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

        let ready = p.wait(50, None).unwrap();
        assert!(ready.is_empty(), "unexpected ready: {ready:?}");

        client.write_all(b"hi").unwrap();
        let ready = p.wait(2000, None).unwrap();
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
        let ready = p.wait(100, None).unwrap();
        assert!(ready.is_empty(), "unregistered socket reported: {ready:?}");
    }

    #[test]
    fn wake_descriptor_interrupts_wait() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = TcpStream::connect(addr).unwrap();
        let (wake_reader, _) = listener.accept().unwrap();
        wake_reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();

        // A poll with a 10 s timeout must return as soon as a byte is
        // written to the wake pair — this is the self-pipe the event loop
        // relies on for sub-millisecond control-message wakeups.
        let mut p = Poller::new();
        let wfd = fd_of(&wake_reader);
        let mut w: &TcpStream = &writer;
        std::io::Write::write_all(&mut w, b"\x01").unwrap();
        let started = std::time::Instant::now();
        let ready = p.wait(10_000, Some(wfd)).unwrap();
        assert_eq!(ready, vec![WAKE_ID]);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "wake did not interrupt the poll"
        );
    }

    #[test]
    fn wake_latency_stays_sub_millisecond() {
        use crate::courierust_server::event::{drain_wake, wake_nudge, wakeup_pair};
        // 100 round-trips of wake → poll must each interrupt well under a
        // poll timeout. A slow self-pipe here is the worker→reactor
        // handoff stall behind the H3 tail (a lost/lagged wake parks the
        // loop for a full poll timeout).
        let (reader, writer) = wakeup_pair().unwrap();
        let mut p = Poller::new();
        let wfd = fd_of(&reader);
        let mut max = std::time::Duration::ZERO;
        for i in 0..100 {
            wake_nudge(&writer);
            let started = std::time::Instant::now();
            let ready = p.wait(1000, Some(wfd)).unwrap();
            let elapsed = started.elapsed();
            max = max.max(elapsed);
            assert!(ready.contains(&WAKE_ID), "wake {i} lost: ready={ready:?}");
            drain_wake(&reader);
        }
        assert!(
            max < std::time::Duration::from_millis(3),
            "wake latency too high: max={max:?}"
        );
    }

    #[test]
    fn wake_interrupts_already_blocked_wait() {
        use crate::courierust_server::event::{drain_wake, wake_nudge, wakeup_pair};
        use std::sync::Arc;
        use std::time::Instant;
        // The production pattern: the reactor is already parked in `wait`
        // when a worker completes and writes the wake byte. A wake that
        // only works when written *before* the poll starts would leave a
        // worker→reactor handoff parked for a full poll timeout.
        let (reader, writer) = wakeup_pair().unwrap();
        let writer = Arc::new(writer);
        let mut p = Poller::new();
        let wfd = fd_of(&reader);
        let mut max = std::time::Duration::ZERO;
        for _ in 0..100 {
            let writer = writer.clone();
            let nudger = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_micros(200));
                wake_nudge(&writer);
            });
            let started = Instant::now();
            let ready = p.wait(1000, Some(wfd)).unwrap();
            let elapsed = started.elapsed();
            max = max.max(elapsed);
            assert!(
                ready.contains(&WAKE_ID),
                "wake lost while wait was blocked: {ready:?}"
            );
            nudger.join().unwrap();
            drain_wake(&reader);
        }
        assert!(
            max < std::time::Duration::from_millis(3),
            "blocked-wait wake latency too high: max={max:?}"
        );
    }

    #[test]
    fn wake_fires_alongside_connection_ready() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        // Wake pair.
        let wl = TcpListener::bind("127.0.0.1:0").unwrap();
        let wa = wl.local_addr().unwrap();
        let mut writer = TcpStream::connect(wa).unwrap();
        let (wake_reader, _) = wl.accept().unwrap();
        wake_reader.set_nonblocking(true).unwrap();
        writer.set_nonblocking(true).unwrap();

        let mut p = Poller::new();
        p.register(7, fd_of(&server), false);
        std::io::Write::write_all(&mut writer, b"\x01").unwrap();
        client.write_all(b"hi").unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let (mut saw_conn, mut saw_wake) = (false, false);
        while !(saw_conn && saw_wake) {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for readiness: conn={saw_conn} wake={saw_wake}"
            );
            let ready = p.wait(100, Some(fd_of(&wake_reader))).unwrap();
            saw_conn |= ready.contains(&7);
            saw_wake |= ready.contains(&WAKE_ID);
        }
    }
}
