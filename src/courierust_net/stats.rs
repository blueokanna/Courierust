//! Optional runtime instrumentation for benchmarks and diagnostics.
//!
//! A [`Stats`] is a set of relaxed atomic counters. Attach one to a
//! server (`ServerConfig::stats`) or a client (`ClientConfig::stats`) to
//! turn performance claims into measured evidence: how many connections
//! were really opened, how many HTTP/2 streams ran on each, how deep the
//! event-loop control queue got, how many poll/wakeup cycles the reactor
//! burned, and how many transport `read`/`write` calls (the closest
//! portable proxy for syscall counts) happened.
//!
//! Counters are updated with relaxed ordering and never block, so
//! attaching a `Stats` costs only a few uncontended atomic
//! loads/stores — safe to leave on in production, useful in benchmarks.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Live counters for one server or client instance.
#[derive(Debug, Default)]
pub struct Stats {
    // Server accept / event-loop reactor.
    /// Total sockets accepted by the server listener.
    pub connections_accepted: Arc<AtomicUsize>,
    /// Sockets currently tracked by the server (pending or parked).
    pub connections_active: Arc<AtomicUsize>,
    /// Event-loop `poll()`/`select()` calls (one syscall each).
    pub event_poll_syscalls: Arc<AtomicUsize>,
    /// Event-loop wake-ups via the self-pipe (control messages queued).
    pub event_wakeups: Arc<AtomicUsize>,
    /// Highest number of control messages seen queued at once.
    pub event_queue_depth_peak: Arc<AtomicUsize>,
    /// HTTP/1.1 connections fully served by the event workers.
    pub h1_connections: Arc<AtomicUsize>,
    /// Event-worker transport `read` calls (h1 path).
    pub h1_read_syscalls: Arc<AtomicUsize>,
    /// Event-worker transport `write` calls (h1 path).
    pub h1_write_syscalls: Arc<AtomicUsize>,

    // HTTP/2 (server and client share the same counters).
    /// HTTP/2 connections ever established (server or client).
    pub h2_connections: Arc<AtomicUsize>,
    /// HTTP/2 connections currently alive.
    pub h2_connections_active: Arc<AtomicUsize>,
    /// HTTP/2 streams ever opened.
    pub h2_streams_total: Arc<AtomicUsize>,
    /// HTTP/2 streams currently in flight (peak tracked separately).
    pub h2_streams_active: Arc<AtomicUsize>,
    /// Highest number of concurrent HTTP/2 streams observed.
    pub h2_streams_active_peak: Arc<AtomicUsize>,
    /// Highest number of simultaneously open streams on one HTTP/2
    /// connection. Unlike `h2_streams_active_peak`, this is not aggregated
    /// across connections.
    pub h2_streams_per_connection_peak: Arc<AtomicUsize>,
    /// Transport `read` calls on h2 connections.
    pub h2_read_syscalls: Arc<AtomicUsize>,
    /// Transport `write` calls on h2 connections.
    pub h2_write_syscalls: Arc<AtomicUsize>,

    // HTTP/3 / QUIC (UDP call counts are transport-call proxies, just like
    // the TCP read/write counters above).
    /// HTTP/3 connections ever established.
    pub h3_connections: Arc<AtomicUsize>,
    /// HTTP/3 connections currently alive.
    pub h3_connections_active: Arc<AtomicUsize>,
    /// HTTP/3 request/response streams observed.
    pub h3_streams_total: Arc<AtomicUsize>,
    /// HTTP/3 streams currently tracked by the reactor.
    pub h3_streams_active: Arc<AtomicUsize>,
    /// Highest aggregate number of tracked HTTP/3 streams observed.
    pub h3_streams_active_peak: Arc<AtomicUsize>,
    /// Highest number of tracked HTTP/3 streams on one connection.
    pub h3_streams_per_connection_peak: Arc<AtomicUsize>,
    /// Highest number of response wires queued by one HTTP/3 connection.
    pub h3_queue_depth_peak: Arc<AtomicUsize>,
    /// UDP receive calls made by the HTTP/3 reactor/client.
    pub h3_udp_recv_syscalls: Arc<AtomicUsize>,
    /// UDP send calls made by the HTTP/3 reactor/client.
    pub h3_udp_send_syscalls: Arc<AtomicUsize>,
}

impl Stats {
    /// A fresh, attached-by-default counter set.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Read every counter at one instant.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            event_poll_syscalls: self.event_poll_syscalls.load(Ordering::Relaxed),
            event_wakeups: self.event_wakeups.load(Ordering::Relaxed),
            event_queue_depth_peak: self.event_queue_depth_peak.load(Ordering::Relaxed),
            h1_connections: self.h1_connections.load(Ordering::Relaxed),
            h1_read_syscalls: self.h1_read_syscalls.load(Ordering::Relaxed),
            h1_write_syscalls: self.h1_write_syscalls.load(Ordering::Relaxed),
            h2_connections: self.h2_connections.load(Ordering::Relaxed),
            h2_connections_active: self.h2_connections_active.load(Ordering::Relaxed),
            h2_streams_total: self.h2_streams_total.load(Ordering::Relaxed),
            h2_streams_active: self.h2_streams_active.load(Ordering::Relaxed),
            h2_streams_active_peak: self.h2_streams_active_peak.load(Ordering::Relaxed),
            h2_streams_per_connection_peak: self
                .h2_streams_per_connection_peak
                .load(Ordering::Relaxed),
            h2_read_syscalls: self.h2_read_syscalls.load(Ordering::Relaxed),
            h2_write_syscalls: self.h2_write_syscalls.load(Ordering::Relaxed),
            h3_connections: self.h3_connections.load(Ordering::Relaxed),
            h3_connections_active: self.h3_connections_active.load(Ordering::Relaxed),
            h3_streams_total: self.h3_streams_total.load(Ordering::Relaxed),
            h3_streams_active: self.h3_streams_active.load(Ordering::Relaxed),
            h3_streams_active_peak: self.h3_streams_active_peak.load(Ordering::Relaxed),
            h3_streams_per_connection_peak: self
                .h3_streams_per_connection_peak
                .load(Ordering::Relaxed),
            h3_queue_depth_peak: self.h3_queue_depth_peak.load(Ordering::Relaxed),
            h3_udp_recv_syscalls: self.h3_udp_recv_syscalls.load(Ordering::Relaxed),
            h3_udp_send_syscalls: self.h3_udp_send_syscalls.load(Ordering::Relaxed),
        }
    }

    /// Bump `counter` to `value` if `value` is larger (for peaks).
    pub(crate) fn bump_peak(target: &AtomicUsize, value: usize) {
        let mut current = target.load(Ordering::Relaxed);
        while value > current {
            match target.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    /// Decrement a live-count metric without allowing an inconsistent cleanup
    /// path to wrap it to `usize::MAX`. These counters are diagnostics, but a
    /// wrapped live count is more dangerous than a conservative zero because
    /// it can hide an actual resource-accounting bug in production evidence.
    pub(crate) fn decrement(target: &AtomicUsize, amount: usize) {
        if amount == 0 {
            return;
        }
        let _ = target.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(amount))
        });
    }
}

/// Keep a shared active-stream counter correct when several independent
/// connections publish into the same `Stats`. A plain `store()` lets one
/// connection erase another connection's count.
pub(crate) struct ActiveH2Streams<'a> {
    stats: Option<&'a Stats>,
    current: usize,
}

impl<'a> ActiveH2Streams<'a> {
    pub(crate) fn new(stats: Option<&'a Stats>) -> Self {
        Self { stats, current: 0 }
    }

    pub(crate) fn set(&mut self, value: usize) {
        let Some(stats) = self.stats else {
            self.current = value;
            return;
        };
        if value > self.current {
            stats
                .h2_streams_active
                .fetch_add(value - self.current, Ordering::Relaxed);
        } else if self.current > value {
            Stats::decrement(&stats.h2_streams_active, self.current - value);
        }
        self.current = value;
        Stats::bump_peak(&stats.h2_streams_active_peak, value);
        Stats::bump_peak(&stats.h2_streams_per_connection_peak, value);
    }
}

impl Drop for ActiveH2Streams<'_> {
    fn drop(&mut self) {
        if let Some(stats) = self.stats {
            Stats::decrement(&stats.h2_streams_active, self.current);
        }
    }
}

/// A plain copy of every counter at one instant.
#[derive(Debug, Default, Clone, Copy)]
pub struct StatsSnapshot {
    /// Total sockets accepted by the server listener.
    pub connections_accepted: usize,
    /// Sockets currently tracked by the server.
    pub connections_active: usize,
    /// Event-loop `poll()`/`select()` calls.
    pub event_poll_syscalls: usize,
    /// Event-loop wake-ups via the self-pipe.
    pub event_wakeups: usize,
    /// Highest control-message queue depth observed.
    pub event_queue_depth_peak: usize,
    /// HTTP/1.1 connections served by the event workers.
    pub h1_connections: usize,
    /// Event-worker transport `read` calls (h1 path).
    pub h1_read_syscalls: usize,
    /// Event-worker transport `write` calls (h1 path).
    pub h1_write_syscalls: usize,
    /// HTTP/2 connections ever established.
    pub h2_connections: usize,
    /// HTTP/2 connections currently alive.
    pub h2_connections_active: usize,
    /// HTTP/2 streams ever opened.
    pub h2_streams_total: usize,
    /// HTTP/2 streams currently in flight.
    pub h2_streams_active: usize,
    /// Highest number of concurrent HTTP/2 streams observed.
    pub h2_streams_active_peak: usize,
    /// Highest number of simultaneously open streams on one HTTP/2
    /// connection.
    pub h2_streams_per_connection_peak: usize,
    /// Transport `read` calls on h2 connections.
    pub h2_read_syscalls: usize,
    /// Transport `write` calls on h2 connections.
    pub h2_write_syscalls: usize,
    /// HTTP/3 connections ever established.
    pub h3_connections: usize,
    /// HTTP/3 connections currently alive.
    pub h3_connections_active: usize,
    /// HTTP/3 request/response streams observed.
    pub h3_streams_total: usize,
    /// HTTP/3 streams currently tracked by the reactor.
    pub h3_streams_active: usize,
    /// Highest aggregate number of tracked HTTP/3 streams observed.
    pub h3_streams_active_peak: usize,
    /// Highest number of tracked HTTP/3 streams on one connection.
    pub h3_streams_per_connection_peak: usize,
    /// Highest number of response wires queued by one HTTP/3 connection.
    pub h3_queue_depth_peak: usize,
    /// HTTP/3 UDP receive calls.
    pub h3_udp_recv_syscalls: usize,
    /// HTTP/3 UDP send calls.
    pub h3_udp_send_syscalls: usize,
}

impl StatsSnapshot {
    /// Machine-readable `|`-separated field block for benchmark output.
    pub fn render(&self) -> String {
        format!(
            "connections_accepted={}|connections_active={}|event_poll_syscalls={}|event_wakeups={}|event_queue_depth_peak={}|h1_connections={}|h1_read_syscalls={}|h1_write_syscalls={}|h2_connections={}|h2_connections_active={}|h2_streams_total={}|h2_streams_active={}|h2_streams_active_peak={}|h2_streams_per_connection_peak={}|h2_read_syscalls={}|h2_write_syscalls={}|h3_connections={}|h3_connections_active={}|h3_streams_total={}|h3_streams_active={}|h3_streams_active_peak={}|h3_streams_per_connection_peak={}|h3_queue_depth_peak={}|h3_udp_recv_syscalls={}|h3_udp_send_syscalls={}",
            self.connections_accepted,
            self.connections_active,
            self.event_poll_syscalls,
            self.event_wakeups,
            self.event_queue_depth_peak,
            self.h1_connections,
            self.h1_read_syscalls,
            self.h1_write_syscalls,
            self.h2_connections,
            self.h2_connections_active,
            self.h2_streams_total,
            self.h2_streams_active,
            self.h2_streams_active_peak,
            self.h2_streams_per_connection_peak,
            self.h2_read_syscalls,
            self.h2_write_syscalls,
            self.h3_connections,
            self.h3_connections_active,
            self.h3_streams_total,
            self.h3_streams_active,
            self.h3_streams_active_peak,
            self.h3_streams_per_connection_peak,
            self.h3_queue_depth_peak,
            self.h3_udp_recv_syscalls,
            self.h3_udp_send_syscalls,
        )
    }
}

/// Wrap a transport and count every `read()` / `write()` call — the
/// closest portable proxy for syscall counts at this layer.
pub struct Counting<S> {
    inner: S,
    reads: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}

impl<S> Counting<S> {
    /// Wrap `inner`, routing call counts into `reads` / `writes`.
    pub fn new(inner: S, reads: Arc<AtomicUsize>, writes: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            reads,
            writes,
        }
    }
}

impl<S: crate::courierust_io::Read> crate::courierust_io::Read for Counting<S> {
    fn read(&mut self, buf: &mut [u8]) -> crate::courierust_error::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.read(buf)
    }
}

impl<S: crate::courierust_io::Write> crate::courierust_io::Write for Counting<S> {
    fn write(&mut self, buf: &[u8]) -> crate::courierust_error::Result<usize> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> crate::courierust_error::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::courierust_io::{Read, Write};

    struct Sink(Vec<u8>);

    impl Read for Sink {
        fn read(&mut self, buf: &mut [u8]) -> crate::courierust_error::Result<usize> {
            let n = buf.len().min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            Ok(n)
        }
    }

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> crate::courierust_error::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> crate::courierust_error::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn counting_counts_calls() {
        let reads = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let mut counted = Counting::new(Sink(vec![1, 2, 3]), reads.clone(), writes.clone());
        let mut buf = [0u8; 4];
        assert_eq!(counted.read(&mut buf).unwrap(), 3);
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        assert_eq!(counted.read(&mut buf).unwrap(), 0);
        assert_eq!(reads.load(Ordering::Relaxed), 2);
        assert_eq!(counted.write(&[9]).unwrap(), 1);
        assert_eq!(counted.write(&[8, 7]).unwrap(), 2);
        assert_eq!(writes.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn snapshot_renders() {
        let stats = Stats::new();
        stats.connections_accepted.store(7, Ordering::Relaxed);
        let snap = stats.snapshot();
        assert!(snap.render().contains("connections_accepted=7"));
    }

    #[test]
    fn decrement_is_saturating() {
        let counter = AtomicUsize::new(2);
        Stats::decrement(&counter, 5);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
