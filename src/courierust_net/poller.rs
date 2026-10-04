//! I/O readiness poller for the event-driven server: parks thousands of
//! idle connections without one thread each.
//!
//! **Windows** uses Winsock `WSAPoll`; **Unix** uses POSIX `poll`. They are
//! the same readiness model with different numbers attached — one flat array
//! of `pollfd`, no descriptor-set limit, one call — so the loop that uses
//! them is one implementation, and the platform module is only the constants
//! and the call itself.
//!
//! `WSAPoll` is the reason there is no batching here any more. Winsock
//! `select` is capped at `FD_SETSIZE` (64) descriptors, so a reactor with
//! more parked connections had to poll them in batches — and a socket in a
//! batch that was not the one waiting for the full timeout could only be
//! noticed on the *next* tick, up to a whole timeout late (measured: a probe
//! round-trip went from 91 µs to 101 ms once the fleet exceeded one batch).
//!
//! Both platforms accept an optional *wake* descriptor (the event loop's
//! self-pipe) watched alongside the connections, so a worker or the accept
//! thread can interrupt a blocking poll with one byte — control messages
//! never wait for a poll tick.
//!
//! `WSAPoll` does not report a *failed non-blocking connect* (a documented
//! Winsock defect), which is why this poller is only used for sockets whose
//! connection is already established: the server's accepted TCP sockets and
//! the QUIC runtime's bound UDP sockets. Nothing here waits for a connect to
//! complete, so the defect cannot reach a caller.
//!
//! On Windows the process timer resolution is raised to 1 ms for its
//! lifetime (see [`ensure_high_resolution_timer`]); poll wakeups otherwise
//! align to the coarse default system timer and add multi-millisecond
//! latency even when data is already queued.

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

/// Winsock `WSAPOLLFD` and `WSAPoll`.
///
/// `WSAPOLLFD` is `{ SOCKET; SHORT; SHORT }` — byte for byte the same layout
/// as POSIX `struct pollfd` with a socket descriptor — so one `PollFd` type
/// serves both platforms and only the constants and the call differ.
#[cfg(windows)]
mod ws {
    use super::Fd;

    pub(super) const READABLE: i16 = 0x0100; // POLLRDNORM
    pub(super) const WRITABLE: i16 = 0x0010; // POLLWRNORM
    pub(super) const ERR: i16 = 0x0001;
    pub(super) const HUP: i16 = 0x0002;
    pub(super) const NVAL: i16 = 0x0004;

    /// `WSAPOLLFD` (winsock2.h).
    #[repr(C)]
    pub(super) struct PollFd {
        pub(super) fd: Fd,
        pub(super) events: i16,
        pub(super) revents: i16,
    }

    /// `ULONG`: the descriptor count `WSAPoll` takes.
    pub(super) type Nfds = u32;

    #[link(name = "ws2_32")]
    extern "system" {
        pub(super) fn WSAPoll(fds: *mut PollFd, nfds: Nfds, timeout: i32) -> i32;
    }
}

/// POSIX `pollfd` and `poll`.
#[cfg(not(windows))]
mod posix {
    use super::Fd;

    pub(super) const READABLE: i16 = 0x001; // POLLIN
    pub(super) const WRITABLE: i16 = 0x004; // POLLOUT
    pub(super) const ERR: i16 = 0x008;
    pub(super) const HUP: i16 = 0x010;
    pub(super) const NVAL: i16 = 0x020;

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
    pub(super) type Nfds = u64;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub(super) type Nfds = u32;

    extern "C" {
        pub(super) fn poll(fds: *mut PollFd, nfds: Nfds, timeout: i32) -> i32;
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

    /// Forget every registration, leaving the poller empty and ready for
    /// a fresh registration pass.
    ///
    /// This is recovery, not steady state: the caller rebuilds the set
    /// from its own live-connection tables, so an entry whose descriptor
    /// was closed behind the poller's back cannot poison every later
    /// wait. `poll` reports such a descriptor as `POLLNVAL` for that one
    /// entry, but Winsock's `select` fails the *whole* call, which turns
    /// a stale entry into a reactor that never waits successfully again.
    pub(crate) fn clear(&mut self) {
        self.fds.clear();
        self.index.clear();
    }

    /// Wait up to `timeout_ms` for readiness. `wake` is an optional
    /// descriptor (the event loop's self-pipe) watched for readability
    /// alongside the connections; when it fires, [`WAKE_ID`] is included in
    /// the result. Returns the ids of ready sockets (readable or writable
    /// per their registered direction, or errored/closed).
    ///
    /// One call, one flat array: `WSAPoll` on Windows and POSIX `poll`
    /// elsewhere have no descriptor-set limit, so the whole registered set is
    /// watched at once and a socket that becomes ready during the wait is
    /// reported by *that* wait.
    pub(crate) fn wait(
        &mut self,
        timeout_ms: i32,
        wake: Option<Fd>,
    ) -> std::io::Result<Vec<usize>> {
        if self.fds.is_empty() && wake.is_none() {
            return Ok(Vec::new());
        }
        #[cfg(not(windows))]
        use posix::{poll as poll_call, Nfds, PollFd, ERR, HUP, NVAL, READABLE, WRITABLE};
        #[cfg(windows)]
        use ws::{Nfds, PollFd, WSAPoll as poll_call, ERR, HUP, NVAL, READABLE, WRITABLE};

        let mut pfds: Vec<PollFd> = self
            .fds
            .iter()
            .map(|&(_, fd, want_write)| PollFd {
                fd,
                events: if want_write { WRITABLE } else { READABLE },
                revents: 0,
            })
            .collect();
        let wake_idx = wake.map(|fd| {
            pfds.push(PollFd {
                fd,
                events: READABLE,
                revents: 0,
            });
            pfds.len() - 1
        });

        // SAFETY: `pfds` is a live, correctly-laid-out `pollfd` array for the
        // duration of the call, and its length is passed beside it. Both
        // functions only write `revents` in place.
        let n = unsafe { poll_call(pfds.as_mut_ptr(), pfds.len() as Nfds, timeout_ms) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(Vec::new());
        }
        // A descriptor that errored, hung up or was closed behind us is
        // reported as ready so the caller's recovery path runs: it rebuilds
        // the set from its own live-connection tables, which is the only
        // place that knows the descriptor should be gone.
        let bad = ERR | HUP | NVAL;
        let mut ready = Vec::new();
        for (idx, pfd) in pfds.iter().enumerate() {
            let expected = if Some(idx) == wake_idx {
                READABLE
            } else {
                pfds[idx].events
            };
            if pfd.revents & (expected | bad) != 0 {
                match Some(idx) == wake_idx {
                    true => ready.push(WAKE_ID),
                    false => ready.push(self.fds[idx].0),
                }
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

    /// A descriptor closed behind the poller's back must never wedge a
    /// wait; it has to be reported *somehow* so the reactor can react.
    ///
    /// The platforms disagree about the shape of the report, and both
    /// shapes are handled: Winsock fails the whole wait with
    /// `WSAENOTSOCK` (the caller rebuilds the set from its registries),
    /// while POSIX `poll` returns `POLLNVAL` for that one entry, which
    /// this module reports as ready so the caller drops it. What must not
    /// exist is a third shape — a wait that never returns — because the
    /// reactor's recovery path would never run.
    ///
    /// That "somehow" is why the assertions below check what an id may be
    /// and not which id it is: descriptor numbers are process-wide, and
    /// the rest of the suite runs beside this test, so the number freed by
    /// `drop` can already belong to another test's idle socket by the time
    /// `wait` looks. The poller cannot tell that apart from a registration
    /// of its own, and "not ready" is then the correct answer, not a
    /// regression.
    #[test]
    fn a_closed_descriptor_cannot_wedge_a_wait() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        let mut p = Poller::new();
        let fd = fd_of(&server);
        p.register(7, fd, false);
        drop(server);

        let started = std::time::Instant::now();
        let outcome = p.wait(200, None);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the wait did not return: a closed descriptor wedged it"
        );
        match outcome {
            // Winsock: the whole wait fails, so the caller must rebuild.
            Err(_) => {}
            // POSIX: the closed descriptor is reported as ready.
            Ok(ids) => {
                // `7` is the POSIX shape this test is named for. An empty
                // set is the other legitimate answer (see the note above:
                // the number was handed to another test's idle socket, so
                // there is nothing to report). Either way, reporting an id
                // that was never registered would be a bug.
                for id in &ids {
                    assert_eq!(*id, 7, "an unregistered descriptor was reported: {ids:?}");
                }
            }
        }
        drop(client);
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
    fn wake_interrupts_the_poll_promptly() {
        use crate::courierust_server::event::{drain_wake, wake_nudge, wakeup_pair};
        let (reader, writer) = wakeup_pair().unwrap();
        let mut p = Poller::new();
        let wfd = fd_of(&reader);
        let mut samples: Vec<std::time::Duration> = Vec::with_capacity(100);
        for i in 0..100 {
            wake_nudge(&writer);
            let started = std::time::Instant::now();
            let ready = p.wait(1000, Some(wfd)).unwrap();
            let elapsed = started.elapsed();
            samples.push(elapsed);
            assert!(ready.contains(&WAKE_ID), "wake {i} lost: ready={ready:?}");
            drain_wake(&reader);
        }
        samples.sort_unstable();
        assert!(
            samples[95] < std::time::Duration::from_millis(50),
            "p95 wake latency too high: {:#?}",
            samples[95]
        );
        assert!(
            samples[99] < std::time::Duration::from_millis(250),
            "p100 wake latency too high (wake likely lost): {:#?}",
            samples[99]
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
        let mut samples: Vec<std::time::Duration> = Vec::with_capacity(100);
        for _ in 0..100 {
            let writer = writer.clone();
            let nudger = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_micros(200));
                wake_nudge(&writer);
            });
            let started = Instant::now();
            let ready = p.wait(1000, Some(wfd)).unwrap();
            let elapsed = started.elapsed();
            samples.push(elapsed);
            assert!(
                ready.contains(&WAKE_ID),
                "wake lost while wait was blocked: {ready:?}"
            );
            nudger.join().unwrap();
            drain_wake(&reader);
        }
        samples.sort_unstable();
        // The blocked-wait variant measures thread-scheduling latency too
        // (the nudger thread must wake and write the byte), so under
        // parallel `--all-targets` load the tail is dominated by OS
        // scheduler jitter, not by the self-pipe. The assertions therefore
        // keep a modest central claim (p50 < 10 ms) and use a generous
        // p100 bound (900 ms) that still cleanly fails on the real
        // regression this test guards: a *lost* wake parks the loop for
        // the full 1000 ms poll timeout.
        assert!(
            samples[49] < std::time::Duration::from_millis(10),
            "p50 blocked-wait wake latency too high: {:#?}",
            samples[49]
        );
        assert!(
            samples[95] < std::time::Duration::from_millis(100),
            "p95 blocked-wait wake latency too high: {:#?}",
            samples[95]
        );
        assert!(
            samples[99] < std::time::Duration::from_millis(900),
            "p100 blocked-wait wake latency too high (wake likely lost): {:#?}",
            samples[99]
        );
    }

    #[test]
    fn a_socket_beyond_the_old_select_limit_is_reported_by_the_wait_that_saw_it() {
        // 70 registered sockets: more than one Winsock `select` batch (64),
        // with the interesting one registered last. Under the old batched
        // `select` only the first batch waited the timeout and later batches
        // were polled with a zero timeout, so a socket that became ready
        // *during* the wait could only be reported by the next call — one
        // whole timeout late, which is the measured 91 µs → 101 ms cliff.
        //
        // The write therefore has to come from another thread, after the
        // wait has begun: a socket already readable before `wait` is called
        // is reported correctly even by the batched version.
        use std::io::{Read as _, Write as _};
        let mut peers = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..70 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).unwrap();
            let (server, _) = listener.accept().unwrap();
            servers.push(server);
            peers.push(client);
        }
        let mut p = Poller::new();
        for (i, server) in servers.iter().enumerate() {
            p.register(i + 1, fd_of(server), false);
        }

        let writer = peers.pop().expect("one peer per socket");
        let nudge = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut w = &writer;
            w.write_all(b"x").unwrap();
        });

        let started = std::time::Instant::now();
        let ready = p.wait(2_000, None).unwrap();
        let elapsed = started.elapsed();
        nudge.join().unwrap();

        assert!(
            ready.contains(&70),
            "the socket that became ready during the wait was not reported: {ready:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(1_000),
            "the wait ran for {elapsed:?}: a ready socket was missed by the wait \
             that should have reported it"
        );
        let mut buf = [0u8; 1];
        let mut s = &servers[69];
        assert_eq!(s.read(&mut buf).unwrap(), 1);
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
