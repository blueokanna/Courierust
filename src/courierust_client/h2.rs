//! HTTP/2 client connection: a dedicated driver thread multiplexes
//! streams over one TCP connection. Requests are submitted over a
//! channel; responses stream back through per-stream channels.

use crate::courierust_body::Body;
use crate::courierust_bytes::Bytes;
use crate::courierust_client::ClientConfig;
use crate::courierust_error::{Error, Result};
use crate::courierust_h2::connection::{Config as H2Config, Connection, Event};
use crate::courierust_h2::error::ErrorCode;
use crate::courierust_h2::priority::Priority;
use crate::courierust_hpack::HeaderField;
use crate::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use crate::courierust_http::response::ResponseHead;
use crate::courierust_http::status::StatusCode;
use crate::courierust_http::version::Version;
use crate::courierust_net::stats::{ActiveH2Streams, Counting, Stats};
use crate::courierust_net::ConnStream;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// An h2 driver connection wrapped in transport call counters (read /
/// write syscall evidence), used whenever `ClientConfig::stats` is set.
type DriverConn<'a> = Connection<Counting<&'a ConnStream>, Counting<&'a ConnStream>>;

/// A response as delivered by the h2 driver, including trailers.
pub struct H2Response {
    /// Response head.
    pub head: ResponseHead,
    /// Streaming body.
    pub body: Body,
    /// Trailers (populated once the body ends).
    pub trailers: Arc<std::sync::Mutex<Option<HeaderMap>>>,
}

/// A command submitted to the h2 driver.
pub enum H2Cmd {
    /// Open a stream and send headers (and an optional body).
    Request {
        /// HPACK header block.
        fields: Vec<HeaderField>,
        /// Optional request body (fully materialized).
        body: Option<Bytes>,
        /// Whether the stream ends after the headers/body.
        end_stream: bool,
        /// RFC 9218 priority to signal.
        priority: Priority,
        /// Reply carrying the response head + streaming body.
        reply: Sender<Result<H2Response>>,
    },
    /// Open a stream with a streaming request body (client-streaming /
    /// bidi gRPC). Body chunks are drained from the channel until it
    /// closes; the final chunk ends the stream.
    RequestStream {
        /// HPACK header block.
        fields: Vec<HeaderField>,
        /// Request-body chunks (or an error to abort the stream).
        body: Receiver<Result<Bytes>>,
        /// RFC 9218 priority to signal.
        priority: Priority,
        /// Reply carrying the response head + streaming body.
        reply: Sender<Result<H2Response>>,
    },
    /// Stop the driver.
    Shutdown,
}

/// A handle to a live h2 connection driver.
#[derive(Clone)]
pub struct H2Conn {
    /// Command channel to the driver thread.
    pub tx: Sender<H2Cmd>,
    /// Remote address.
    pub peer: SocketAddr,
    /// Whether the connection still accepts new streams (flipped by the
    /// driver on GOAWAY / close).
    pub accepting: Arc<std::sync::atomic::AtomicBool>,
    /// Number of requests currently reserved for dispatch on this driver.
    reservations: Arc<AtomicUsize>,
    /// Request-body bytes in flight, in [`H2_BODY_UNIT`] units. A
    /// connection carrying one 1 MiB upload is far more expensive on the
    /// wire than one carrying four header-only RPCs, so pool selection
    /// must see body weight, not just stream count.
    body_load: Arc<AtomicUsize>,
    /// EWMA of per-request service time (µs), updated by the pool after
    /// each completed request; 0 until the first sample. Entered into
    /// [`H2Conn::load`] with a small divisor so a genuinely slow
    /// connection is gently de-weighted without ever dominating stream /
    /// body load (which would make selection oscillate).
    ewma_service_us: Arc<AtomicU64>,
}

/// One body-load unit per 64 KiB of in-flight request body: the unit at
/// which a body starts to dominate a connection's wire usage.
const H2_BODY_UNIT: usize = 64 * 1024;
/// Clamp for a single request's body weight, so a multi-GiB body cannot
/// saturate the load counter (its wire cost is bounded by the stream in
/// any case).
const H2_BODY_WEIGHT_CAP: usize = 256;
/// Divisor (µs → load units) for the EWMA service-time term: 1 ms of
/// observed service time adds one unit, comparable to one active stream.
const H2_EWMA_DIVISOR: u64 = 1000;
/// Upper bound for the EWMA service-time term, so one pathological sample
/// cannot pin a connection as permanently slow.
const H2_EWMA_CAP_US: u64 = 10_000;

/// Body weight of `bytes` in [`H2_BODY_UNIT`] units, clamped.
fn body_weight(bytes: usize) -> usize {
    bytes.div_ceil(H2_BODY_UNIT).min(H2_BODY_WEIGHT_CAP)
}

impl H2Conn {
    pub(crate) fn reserve(&self, body_bytes: usize) {
        self.reservations.fetch_add(1, Ordering::AcqRel);
        self.body_load
            .fetch_add(body_weight(body_bytes), Ordering::AcqRel);
    }

    pub(crate) fn release(&self, body_bytes: usize) {
        let _ = self
            .reservations
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_sub(1))
            });
        let _ = self
            .body_load
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_sub(body_weight(body_bytes)))
            });
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.reservations.load(Ordering::Acquire) == 0
    }

    /// The pool's selection load: active streams plus body weight plus a
    /// bounded EWMA service-time term. Lower is less loaded. Picking the
    /// minimum at the per-authority connection cap spreads work onto the
    /// connection that is cheapest on the wire, not merely the one with
    /// the fewest concurrent streams.
    pub(crate) fn load(&self) -> usize {
        let streams = self.reservations.load(Ordering::Acquire);
        let body = self.body_load.load(Ordering::Acquire);
        let ewma = self
            .ewma_service_us
            .load(Ordering::Acquire)
            .min(H2_EWMA_CAP_US);
        streams
            .saturating_add(body)
            .saturating_add((ewma / H2_EWMA_DIVISOR) as usize)
    }

    /// Fold one completed request's service time into the EWMA. The
    /// sample is the wall time from command dispatch to response delivery
    /// (channel wait + wire + peer), so a genuinely slow peer raises the
    /// term and the connection is de-weighted at the selection cap.
    pub(crate) fn note_service_us(&self, sample_us: u64) {
        let mut current = self.ewma_service_us.load(Ordering::Relaxed);
        loop {
            let next = if current == 0 {
                sample_us.min(H2_EWMA_CAP_US)
            } else {
                ((current * 7 + sample_us) / 8).min(H2_EWMA_CAP_US)
            };
            match self.ewma_service_us.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

/// A stream awaiting its response.
struct Pending {
    /// Where the final response goes (sent when headers arrive).
    reply: Option<Sender<Result<H2Response>>>,
    /// Where body chunks go.
    body_tx: Option<Sender<Result<Bytes>>>,
    /// Where the body receiver lives (attached to the response).
    body_rx: Option<Receiver<Result<Bytes>>>,
    /// Trailers accumulator shared with the caller.
    trailers: Arc<std::sync::Mutex<Option<HeaderMap>>>,
    /// Bytes of response body received so far (enforces `max_body`).
    body_len: usize,
    /// Per-request deadline (from `ClientConfig::read_timeout`): when the
    /// response head has not arrived by then, the stream is reset with
    /// `CANCEL` and the caller receives a timeout error. Guards against a
    /// peer that acknowledges streams but never completes responses.
    deadline: Option<std::time::Instant>,
}

/// Map a configured read timeout to an absolute per-request deadline.
fn deadline_from(timeout: Option<Duration>) -> Option<std::time::Instant> {
    timeout.map(|t| std::time::Instant::now() + t)
}

/// An in-flight streaming request body being fed to the connection.
struct StreamBody {
    /// The channel the caller feeds body chunks into.
    rx: Receiver<Result<Bytes>>,
    /// A chunk that could not be queued yet (flow control) and must be
    /// retried on the next poll.
    pending_chunk: Option<Bytes>,
}

/// Maximum number of commands waiting for a free stream slot on one
/// connection. Bounds memory when the peer's
/// `SETTINGS_MAX_CONCURRENT_STREAMS` budget stays exhausted for a long
/// time (e.g. many long-lived streams); beyond this the request fails
/// with `REFUSED_STREAM` instead of queueing without bound.
const MAX_DEFERRED: usize = 1024;

/// Whether the peer's `SETTINGS_MAX_CONCURRENT_STREAMS` budget is
/// exhausted. A limit of 0 means unlimited (RFC 9113 §6.5.2). `pending`
/// tracks every client-initiated stream whose response has not yet fully
/// arrived, which is exactly the client's concurrent-stream count.
fn stream_limit_reached(conn: &DriverConn<'_>, pending: &HashMap<u32, Pending>) -> bool {
    let limit = conn.peer_settings().max_concurrent_streams as usize;
    limit != 0 && pending.len() >= limit
}

/// Start an h2 connection driver over `stream` (plain TCP or TLS).
pub(crate) fn start(stream: ConnStream, cfg: &ClientConfig) -> Result<H2Conn> {
    start_inner(stream, cfg, Vec::new(), None)
}

/// Start an h2 driver for a connection established via the RFC 7540
/// §3.2 `h2c` Upgrade handshake. `seed` holds bytes already read past
/// the `101` response (the server's SETTINGS frame); the upgraded
/// HTTP/1.1 request occupies stream 1 and its response is delivered to `reply`.
pub(crate) fn start_upgraded(
    stream: ConnStream,
    cfg: &ClientConfig,
    seed: Vec<u8>,
    reply: Sender<Result<H2Response>>,
) -> Result<H2Conn> {
    start_inner(stream, cfg, seed, Some(reply))
}

fn start_inner(
    stream: ConnStream,
    cfg: &ClientConfig,
    seed: Vec<u8>,
    upgrade_reply: Option<Sender<Result<H2Response>>>,
) -> Result<H2Conn> {
    let peer = stream.peer_addr();
    let (tx, rx) = channel::<H2Cmd>();
    let cfg = cfg.clone();
    let accepting = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let accepting2 = accepting.clone();
    let reservations = Arc::new(AtomicUsize::new(0));
    let body_load = Arc::new(AtomicUsize::new(0));
    let ewma_service_us = Arc::new(AtomicU64::new(0));
    let (reads, writes) = match cfg.stats.as_deref() {
        Some(s) => (s.h2_read_syscalls.clone(), s.h2_write_syscalls.clone()),
        None => (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))),
    };
    if let Some(s) = cfg.stats.as_deref() {
        s.h2_connections.fetch_add(1, Ordering::Relaxed);
        s.h2_connections_active.fetch_add(1, Ordering::Relaxed);
    }
    let stats = cfg.stats.clone();
    thread::Builder::new()
        .name("courierust-h2-driver".into())
        .spawn(move || {
            driver(
                stream,
                rx,
                cfg,
                accepting2,
                seed,
                upgrade_reply,
                reads,
                writes,
                stats,
            );
        })?;
    Ok(H2Conn {
        tx,
        peer,
        accepting,
        reservations,
        body_load,
        ewma_service_us,
    })
}

/// Driver socket read timeout: short enough that commands queued while
/// the driver waits for response data are served promptly (a long read
/// would cause a multi-hundred-ms P99 spike under multiplexing). 5 ms
/// bounds that stall; responses are still read the instant they arrive.
const DRIVER_READ_TIMEOUT: Duration = Duration::from_millis(5);

/// Decrements an h2 live-connection counter when the driver exits, on
/// every path (RAII).
struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        Stats::decrement(&self.0, 1);
    }
}

#[allow(clippy::too_many_arguments)]
fn driver(
    stream: ConnStream,
    rx: Receiver<H2Cmd>,
    cfg: ClientConfig,
    accepting: Arc<AtomicBool>,
    seed: Vec<u8>,
    upgrade_reply: Option<Sender<Result<H2Response>>>,
    reads: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
    stats: Option<Arc<Stats>>,
) {
    let _ = stream.configure(Some(DRIVER_READ_TIMEOUT));
    let stats = stats.as_deref();
    let _active_guard = stats.map(|s| ActiveGuard(s.h2_connections_active.clone()));
    let mut conn = if seed.is_empty() {
        Connection::new(
            Counting::new(&stream, reads.clone(), writes.clone()),
            Counting::new(&stream, reads, writes),
            h2_config(&cfg),
        )
    } else {
        Connection::new_with_seed(
            Counting::new(&stream, reads.clone(), writes.clone()),
            Counting::new(&stream, reads, writes),
            h2_config(&cfg),
            &seed,
        )
    };
    let mut pending: HashMap<u32, Pending> = HashMap::new();
    let mut stream_bodies: HashMap<u32, StreamBody> = HashMap::new();
    let mut goaway = false;
    let mut deferred: VecDeque<H2Cmd> = VecDeque::new();
    let mut stream_stats = ActiveH2Streams::new(stats);

    if let Some(reply) = upgrade_reply {
        if conn.register_upgrade_stream().is_ok() {
            let (body_tx, body_rx) = channel::<Result<Bytes>>();
            let trailers = Arc::new(std::sync::Mutex::new(None));
            pending.insert(
                1,
                Pending {
                    reply: Some(reply),
                    body_tx: Some(body_tx),
                    body_rx: Some(body_rx),
                    trailers,
                    body_len: 0,
                    deadline: deadline_from(cfg.read_timeout),
                },
            );
            if let Some(s) = stats {
                s.h2_streams_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    let started = std::time::Instant::now();
    let mut last_rx = started;
    let mut last_ping: Option<std::time::Instant> = None;

    let _ = conn.poll();

    loop {
        if !retry_deferred(
            &mut conn,
            &mut pending,
            &mut stream_bodies,
            &mut goaway,
            &mut deferred,
            cfg.read_timeout,
            stats,
        ) {
            cleanup(&mut conn, &mut pending, &mut stream_bodies);
            return;
        }
        let mut got_cmd = false;
        while let Ok(cmd) = rx.try_recv() {
            got_cmd = true;
            if !handle_cmd(
                &mut conn,
                &mut pending,
                &mut stream_bodies,
                &mut goaway,
                &mut deferred,
                cmd,
                cfg.read_timeout,
                stats,
            ) {
                cleanup(&mut conn, &mut pending, &mut stream_bodies);
                return;
            }
        }

        stream_stats.set(conn.open_stream_count());

        let has_work =
            got_cmd || !deferred.is_empty() || !pending.is_empty() || !stream_bodies.is_empty();
        if has_work {
            match conn.poll_available(64) {
                Ok(true) => last_rx = std::time::Instant::now(),
                Ok(false) => {}
                Err(e) => {
                    accepting.store(false, std::sync::atomic::Ordering::Release);
                    fail_all(&mut pending, e);
                    break;
                }
            };
            drain_events(
                &mut conn,
                &mut pending,
                &mut goaway,
                &accepting,
                cfg.max_body,
            );
            drain_stream_bodies(&mut conn, &mut stream_bodies);
            check_timeouts(&mut conn, &mut pending, stats);
            if !retry_deferred(
                &mut conn,
                &mut pending,
                &mut stream_bodies,
                &mut goaway,
                &mut deferred,
                cfg.read_timeout,
                stats,
            ) {
                cleanup(&mut conn, &mut pending, &mut stream_bodies);
                return;
            }
            if conn.is_closed() {
                accepting.store(false, std::sync::atomic::Ordering::Release);
                fail_all(&mut pending, Error::eof());
                break;
            }
            if !apply_liveness(
                &mut conn,
                &mut pending,
                &accepting,
                &cfg,
                started,
                &mut last_rx,
                &mut last_ping,
                true,
            ) {
                break;
            }
        } else {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(cmd) => {
                    if !handle_cmd(
                        &mut conn,
                        &mut pending,
                        &mut stream_bodies,
                        &mut goaway,
                        &mut deferred,
                        cmd,
                        cfg.read_timeout,
                        stats,
                    ) {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    match conn.poll_available(64) {
                        Ok(true) => last_rx = std::time::Instant::now(),
                        Ok(false) => {}
                        Err(e) => {
                            accepting.store(false, std::sync::atomic::Ordering::Release);
                            fail_all(&mut pending, e);
                            break;
                        }
                    };
                    drain_events(
                        &mut conn,
                        &mut pending,
                        &mut goaway,
                        &accepting,
                        cfg.max_body,
                    );
                    drain_stream_bodies(&mut conn, &mut stream_bodies);
                    check_timeouts(&mut conn, &mut pending, stats);
                    if !retry_deferred(
                        &mut conn,
                        &mut pending,
                        &mut stream_bodies,
                        &mut goaway,
                        &mut deferred,
                        cfg.read_timeout,
                        stats,
                    ) {
                        break;
                    }
                    if conn.is_closed() {
                        accepting.store(false, std::sync::atomic::Ordering::Release);
                        fail_all(&mut pending, Error::eof());
                        break;
                    }
                    if !apply_liveness(
                        &mut conn,
                        &mut pending,
                        &accepting,
                        &cfg,
                        started,
                        &mut last_rx,
                        &mut last_ping,
                        false,
                    ) {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }
    cleanup(&mut conn, &mut pending, &mut stream_bodies);
}

/// Apply connection liveness policies between polls:
///
/// 1. **SETTINGS_TIMEOUT** — if the peer never ACKs our SETTINGS within
///    [`ClientConfig::h2_settings_timeout`], the connection is dropped
///    with a `SETTINGS_TIMEOUT` GOAWAY (RFC 9113 §6.5.3).
/// 2. **Idle reaping** — a connection with no in-flight streams that has
///    seen no inbound traffic for [`ClientConfig::h2_idle_timeout`] is
///    closed so idle driver threads do not accumulate.
/// 3. **Keepalive PING** — after [`ClientConfig::h2_ping_interval`] of
///    inbound silence a PING is sent; if no frame at all arrives within
///    [`ClientConfig::h2_ping_timeout`] the peer is presumed dead and the
///    connection is dropped.
///
/// Returns `false` when the driver should shut down.
#[allow(clippy::too_many_arguments)]
fn apply_liveness(
    conn: &mut DriverConn<'_>,
    pending: &mut HashMap<u32, Pending>,
    accepting: &Arc<AtomicBool>,
    cfg: &ClientConfig,
    started: std::time::Instant,
    last_rx: &mut std::time::Instant,
    last_ping: &mut Option<std::time::Instant>,
    has_work: bool,
) -> bool {
    use std::sync::atomic::Ordering;
    let now = std::time::Instant::now();

    if let Some(t) = cfg.h2_settings_timeout {
        if conn.settings_ack_pending() && now.duration_since(started) >= t {
            conn.send_goaway(ErrorCode::SettingsTimeout, b"peer did not ACK SETTINGS");
            accepting.store(false, Ordering::Release);
            fail_all(
                pending,
                Error::h2(
                    ErrorCode::SettingsTimeout.as_u32(),
                    "peer did not ACK our SETTINGS",
                ),
            );
            return false;
        }
    }

    if !has_work {
        if let Some(t) = cfg.h2_idle_timeout {
            if now.duration_since(*last_rx) >= t {
                conn.send_goaway(ErrorCode::NoError, b"idle timeout");
                accepting.store(false, Ordering::Release);
                return false;
            }
        }
    }

    if let Some(interval) = cfg.h2_ping_interval {
        if now.duration_since(*last_rx) >= interval {
            match *last_ping {
                None => {
                    let nanos = now.duration_since(started).as_nanos() as u64;
                    conn.send_ping(nanos.to_be_bytes());
                    *last_ping = Some(now);
                }
                Some(sent) => {
                    if *last_rx < sent {
                        if let Some(pt) = cfg.h2_ping_timeout {
                            if now.duration_since(sent) >= pt {
                                accepting.store(false, Ordering::Release);
                                fail_all(pending, Error::eof());
                                return false;
                            }
                        }
                    } else {
                        *last_ping = None;
                    }
                }
            }
        } else {
            *last_ping = None;
        }
    }
    true
}

/// Handle one command from the caller's channel. Returns `false` when
/// the driver must shut down.
#[allow(clippy::too_many_arguments)]
fn handle_cmd(
    conn: &mut DriverConn<'_>,
    pending: &mut HashMap<u32, Pending>,
    stream_bodies: &mut HashMap<u32, StreamBody>,
    goaway: &mut bool,
    deferred: &mut VecDeque<H2Cmd>,
    cmd: H2Cmd,
    timeout: Option<Duration>,
    stats: Option<&Stats>,
) -> bool {
    match cmd {
        H2Cmd::Shutdown => {
            conn.send_goaway(ErrorCode::NoError, b"client shutdown");
            false
        }
        H2Cmd::Request {
            fields,
            body,
            end_stream,
            priority,
            reply,
        } => {
            if *goaway {
                let _ = reply.send(Err(Error::canceled("connection received GOAWAY")));
                return true;
            }
            if stream_limit_reached(conn, pending) {
                if deferred.len() < MAX_DEFERRED {
                    deferred.push_back(H2Cmd::Request {
                        fields,
                        body,
                        end_stream,
                        priority,
                        reply,
                    });
                } else {
                    let _ = reply.send(Err(Error::h2(
                        ErrorCode::RefusedStream.as_u32(),
                        "peer SETTINGS_MAX_CONCURRENT_STREAMS exhausted",
                    )));
                }
                return true;
            }
            match conn.open_request(priority) {
                Ok(sid) => {
                    if let Some(s) = stats {
                        s.h2_streams_total.fetch_add(1, Ordering::Relaxed);
                    }
                    let (body_tx, body_rx) = channel::<Result<Bytes>>();
                    let trailers = Arc::new(std::sync::Mutex::new(None));
                    let body_empty = body.is_none() && end_stream;
                    if let Err(e) = conn.send_headers(sid, &fields, body_empty) {
                        let _ = reply.send(Err(e));
                        return true;
                    }
                    if let Some(b) = body {
                        if let Err(e) = conn.send_data(sid, b, end_stream) {
                            let _ = reply.send(Err(e));
                            return true;
                        }
                    }
                    pending.insert(
                        sid,
                        Pending {
                            reply: Some(reply),
                            body_tx: Some(body_tx),
                            body_rx: Some(body_rx),
                            trailers,
                            body_len: 0,
                            deadline: deadline_from(timeout),
                        },
                    );
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            }
            true
        }
        H2Cmd::RequestStream {
            fields,
            body,
            priority,
            reply,
        } => {
            if *goaway {
                let _ = reply.send(Err(Error::canceled("connection received GOAWAY")));
                return true;
            }
            if stream_limit_reached(conn, pending) {
                if deferred.len() < MAX_DEFERRED {
                    deferred.push_back(H2Cmd::RequestStream {
                        fields,
                        body,
                        priority,
                        reply,
                    });
                } else {
                    let _ = reply.send(Err(Error::h2(
                        ErrorCode::RefusedStream.as_u32(),
                        "peer SETTINGS_MAX_CONCURRENT_STREAMS exhausted",
                    )));
                }
                return true;
            }
            match conn.open_request(priority) {
                Ok(sid) => {
                    if let Some(s) = stats {
                        s.h2_streams_total.fetch_add(1, Ordering::Relaxed);
                    }
                    let (body_tx, body_rx) = channel::<Result<Bytes>>();
                    let trailers = Arc::new(std::sync::Mutex::new(None));
                    // Headers with END_STREAM clear; the body is streamed.
                    if let Err(e) = conn.send_headers(sid, &fields, false) {
                        let _ = reply.send(Err(e));
                        return true;
                    }
                    stream_bodies.insert(
                        sid,
                        StreamBody {
                            rx: body,
                            pending_chunk: None,
                        },
                    );
                    pending.insert(
                        sid,
                        Pending {
                            reply: Some(reply),
                            body_tx: Some(body_tx),
                            body_rx: Some(body_rx),
                            trailers,
                            body_len: 0,
                            deadline: deadline_from(timeout),
                        },
                    );
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            }
            true
        }
    }
}

/// Fail every pending stream whose per-request deadline has passed:
/// reset the stream with `CANCEL` and surface a timeout to the caller.
/// The connection itself survives — only the stalled request is dropped.
fn check_timeouts(
    conn: &mut DriverConn<'_>,
    pending: &mut HashMap<u32, Pending>,
    stats: Option<&Stats>,
) {
    use std::sync::atomic::Ordering;
    let now = std::time::Instant::now();
    let timed_out: Vec<u32> = pending
        .iter()
        .filter(|(_, p)| p.deadline.is_some_and(|d| now >= d))
        .map(|(sid, _)| *sid)
        .collect();
    if timed_out.is_empty() {
        return;
    }
    if let Some(s) = stats {
        s.h2_streams_timed_out
            .fetch_add(timed_out.len(), Ordering::Relaxed);
    }
    for sid in timed_out {
        conn.send_rst(sid, ErrorCode::Cancel);
        if let Some(p) = pending.remove(&sid) {
            let err = Error::timeout("h2 response did not complete in time");
            let _ = p.body_tx.map(|tx| tx.send(Err(err.clone())));
            let _ = p.reply.map(|r| r.send(Err(err)));
        }
    }
}

/// Retry commands that were deferred because the peer's concurrent-stream
/// budget was exhausted. Stops as soon as the budget is full again.
/// Returns `false` if the driver must shut down.
fn retry_deferred(
    conn: &mut DriverConn<'_>,
    pending: &mut HashMap<u32, Pending>,
    stream_bodies: &mut HashMap<u32, StreamBody>,
    goaway: &mut bool,
    deferred: &mut VecDeque<H2Cmd>,
    timeout: Option<Duration>,
    stats: Option<&Stats>,
) -> bool {
    while let Some(cmd) = deferred.pop_front() {
        if stream_limit_reached(conn, pending) {
            deferred.push_front(cmd);
            return true;
        }
        if !handle_cmd(
            conn,
            pending,
            stream_bodies,
            goaway,
            deferred,
            cmd,
            timeout,
            stats,
        ) {
            return false;
        }
    }
    true
}

/// Feed streaming request-body chunks into the connection, respecting
/// flow control. Chunks that cannot be queued yet are held for the next
/// poll; a disconnected channel ends the stream.
fn drain_stream_bodies(conn: &mut DriverConn<'_>, bodies: &mut HashMap<u32, StreamBody>) {
    let mut done = Vec::new();
    for (&sid, b) in bodies.iter_mut() {
        if let Some(chunk) = b.pending_chunk.take() {
            match conn.send_data(sid, chunk.clone(), false) {
                Ok(_) => {}
                Err(e) if e.kind == crate::courierust_error::ErrorKind::Overflow => {
                    b.pending_chunk = Some(chunk);
                    continue;
                }
                Err(_) => {
                    // Stream closed / connection error: drop the body.
                    done.push(sid);
                    continue;
                }
            }
        }
        loop {
            match b.rx.try_recv() {
                Ok(Ok(chunk)) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    match conn.send_data(sid, chunk.clone(), false) {
                        Ok(_) => {}
                        Err(e) if e.kind == crate::courierust_error::ErrorKind::Overflow => {
                            b.pending_chunk = Some(chunk);
                            break;
                        }
                        Err(_) => {
                            done.push(sid);
                            break;
                        }
                    }
                }
                Ok(Err(_)) => {
                    let _ = conn.send_data(sid, Bytes::new(), true);
                    done.push(sid);
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    let _ = conn.send_data(sid, Bytes::new(), true);
                    done.push(sid);
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
            }
        }
    }
    for sid in done {
        bodies.remove(&sid);
    }
}

/// Drain and dispatch connection events to pending streams.
fn drain_events(
    conn: &mut DriverConn<'_>,
    pending: &mut HashMap<u32, Pending>,
    goaway: &mut bool,
    accepting: &Arc<AtomicBool>,
    max_body: usize,
) {
    while let Some(ev) = conn.next_event() {
        match ev {
            Event::Headers {
                stream_id,
                headers,
                end_stream,
                ..
            } => {
                if let Some(p) = pending.get_mut(&stream_id) {
                    match build_response(&headers) {
                        Ok(head) => {
                            if end_stream {
                                if let Some(reply) = p.reply.take() {
                                    let _ = reply.send(Ok(H2Response {
                                        head,
                                        body: Body::Empty,
                                        trailers: p.trailers.clone(),
                                    }));
                                }
                                pending.remove(&stream_id);
                            } else {
                                let body_rx = p.body_rx.take();
                                if let Some(reply) = p.reply.take() {
                                    let body = match body_rx {
                                        Some(rx) => Body::Channel(rx),
                                        None => Body::Empty,
                                    };
                                    let _ = reply.send(Ok(H2Response {
                                        head,
                                        body,
                                        trailers: p.trailers.clone(),
                                    }));
                                }
                                // Keep the pending entry so `body_tx`
                                // stays alive for the DATA frames that
                                // follow the response head.
                            }
                        }
                        Err(e) => {
                            let _ = p.reply.take().map(|r| r.send(Err(e)));
                            pending.remove(&stream_id);
                        }
                    }
                }
            }
            Event::Data {
                stream_id,
                data,
                end_stream,
            } => {
                if let Some(p) = pending.get_mut(&stream_id) {
                    p.body_len = p.body_len.saturating_add(data.len());
                    if p.body_len > max_body {
                        conn.send_rst(stream_id, ErrorCode::EnhanceYourCalm);
                        let err = Error::overflow("response body exceeds limit");
                        let _ = p.body_tx.take().map(|tx| tx.send(Err(err.clone())));
                        let _ = p.reply.take().map(|r| r.send(Err(err)));
                        pending.remove(&stream_id);
                        continue;
                    }
                    let _ = p.body_tx.as_ref().map(|tx| tx.send(Ok(data)));
                    if end_stream {
                        pending.remove(&stream_id);
                    }
                }
            }
            Event::Trailers { stream_id, headers } => {
                if let Some(p) = pending.get_mut(&stream_id) {
                    let mut map = HeaderMap::new();
                    for f in &headers {
                        map.append(f.name.clone(), f.value.clone());
                    }
                    *p.trailers.lock().unwrap() = Some(map);
                    pending.remove(&stream_id);
                }
            }
            Event::Rst {
                stream_id,
                error_code,
            } => {
                if let Some(p) = pending.remove(&stream_id) {
                    let _ = p.reply.map(|r| {
                        r.send(Err(Error::h2(error_code.as_u32(), "stream reset by peer")))
                    });
                }
            }
            Event::StreamError {
                stream_id,
                error_code,
                message,
            } => {
                // A locally-detected stream error (e.g. content-length
                // mismatch): surface it to the caller and drop the
                // stream. The connection itself stays usable. If the
                // response head was already delivered (so `reply` was
                // consumed), the error still reaches the caller through
                // the streaming body channel.
                if let Some(p) = pending.remove(&stream_id) {
                    let err = Error::h2(error_code.as_u32(), message.as_str());
                    let _ = p.body_tx.map(|tx| tx.send(Err(err.clone())));
                    let _ = p.reply.map(|r| r.send(Err(err)));
                }
            }
            Event::GoAway {
                error_code,
                last_stream_id,
                ..
            } => {
                accepting.store(false, std::sync::atomic::Ordering::Release);
                *goaway = true;
                let dead: Vec<u32> = pending
                    .keys()
                    .copied()
                    .filter(|&s| s > last_stream_id)
                    .collect();
                for sid in dead {
                    if let Some(p) = pending.remove(&sid) {
                        let _ = p.reply.map(|r| {
                            r.send(Err(Error::h2(error_code.as_u32(), "peer sent GOAWAY")))
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

/// Rebuild a response head from an h2 header block.
fn build_response(headers: &[HeaderField]) -> Result<ResponseHead> {
    let mut status = StatusCode::OK;
    let mut map = HeaderMap::new();
    for f in headers {
        if f.name.is_pseudo() {
            if f.name.as_str() == ":status" {
                let code: u16 = std::str::from_utf8(f.value.as_bytes())
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| Error::protocol("missing/invalid :status"))?;
                status = StatusCode::from_u16(code);
            }
            // Other pseudo-headers are ignored in responses.
        } else {
            map.append(f.name.clone(), f.value.clone());
        }
    }
    Ok(ResponseHead {
        status,
        version: Version::HTTP_2,
        headers: map,
    })
}

fn h2_config(cfg: &ClientConfig) -> H2Config {
    let mut c = H2Config {
        client: true,
        max_send_buffer: cfg.max_body,
        auto_release_credit: true,
        ..Default::default()
    };
    // RFC 9113 §6.5.2: a client MUST NOT advertise `SETTINGS_ENABLE_PUSH=1`.
    // This implementation does not consume server-push streams, so it
    // declares 0; a peer that pushes anyway then rightly triggers a
    // PROTOCOL_ERROR connection error instead of silently corrupting the
    // stream space.
    c.local_settings.enable_push = 0;
    if c.local_settings.initial_window_size < 256 * 1024 {
        c.local_settings.initial_window_size = 256 * 1024;
    }
    if let Ok(hl) = cfg.max_header_list.try_into() {
        c.local_settings.max_header_list_size = hl;
    }
    c
}

/// The base64url-encoded `HTTP2-Settings` value the client advertises for
/// an RFC 7540 §3.2 `h2c` Upgrade, derived from the same settings the h2
/// driver will advertise once the connection switches.
pub(crate) fn upgrade_settings_b64(cfg: &ClientConfig) -> String {
    let c = h2_config(cfg);
    base64url_encode(&c.local_settings.to_wire())
}

/// The outcome of an RFC 7540 §3.2 `h2c` Upgrade handshake.
pub(crate) enum UpgradeOutcome {
    /// Server accepted: `101 Switching Protocols`. The seed holds any
    /// bytes already read past the 101 headers (the server's h2 SETTINGS
    /// frame) and must be fed to the h2 driver.
    Upgraded(Vec<u8>),
    /// Server declined with an ordinary HTTP/1.1 response head. `leftover`
    /// holds any bytes already read past the response headers (the start
    /// of the body) and must be fed to the HTTP/1.1 response parser.
    Declined(ResponseHead, Vec<u8>),
}

/// Perform the RFC 7540 §3.2 `h2c` Upgrade handshake on a fresh socket:
/// send `request_wire` (an HTTP/1.1 request carrying `Upgrade: h2c`,
/// `Connection: Upgrade, HTTP2-Settings` and `HTTP2-Settings`) and read
/// the response head. The head is read with a bounded buffer and never
/// discards bytes past the head terminator.
pub(crate) fn h2c_upgrade_handshake(
    mut stream: &std::net::TcpStream,
    request_wire: &[u8],
) -> Result<UpgradeOutcome> {
    use std::io::{Read as _, Write as _};
    stream
        .write_all(request_wire)
        .map_err(|e| Error::io(e.to_string()))?;
    stream.flush().map_err(|e| Error::io(e.to_string()))?;

    let mut buf = [0u8; 8192];
    let mut filled = 0usize;
    let mut head_end = None;
    while filled < buf.len() {
        let n = stream
            .read(&mut buf[filled..])
            .map_err(|e| Error::io(e.to_string()))?;
        if n == 0 {
            return Err(Error::eof());
        }
        filled += n;
        if let Some(i) = find_subslice(&buf[..filled], b"\r\n\r\n") {
            head_end = Some(i + 4);
            break;
        }
    }
    let end = head_end.ok_or_else(|| Error::protocol("101 response head too large"))?;
    let (status, version, headers) = parse_head_headers(&buf[..end])?;
    let leftover = buf[end..filled].to_vec();
    if status == StatusCode::SWITCHING_PROTOCOLS {
        Ok(UpgradeOutcome::Upgraded(leftover))
    } else {
        Ok(UpgradeOutcome::Declined(
            ResponseHead {
                status,
                version,
                headers,
            },
            leftover,
        ))
    }
}

/// Build the wire bytes of the HTTP/1.1 request that carries the `h2c`
/// Upgrade headers (RFC 7540 §3.2). Hop-by-hop headers are dropped;
/// `Host` is set from `authority`; a materialized body is sent with an
/// explicit `Content-Length`.
pub(crate) fn build_upgrade_request(
    req: &crate::courierust_http::request::Request<Body>,
    authority: &str,
    settings_b64: &str,
    user_agent: Option<&str>,
) -> Result<Vec<u8>> {
    let body = match &req.body {
        Body::Empty => None,
        Body::Bytes(b) => Some(b),
        Body::Channel(_) => {
            return Err(Error::protocol(
                "streaming request bodies cannot use the h2c Upgrade",
            ));
        }
    };
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(req.method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(req.uri.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(authority.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"Connection: Upgrade, HTTP2-Settings\r\n");
    out.extend_from_slice(b"Upgrade: h2c\r\n");
    out.extend_from_slice(b"HTTP2-Settings: ");
    out.extend_from_slice(settings_b64.as_bytes());
    out.extend_from_slice(b"\r\n");
    if let Some(b) = body {
        if !b.is_empty() {
            out.extend_from_slice(b"Content-Length: ");
            let cl = crate::courierust_h1::IToA::new(b.len());
            out.extend_from_slice(cl.as_slice());
            out.extend_from_slice(b"\r\n");
        }
    }
    for (n, v) in req.headers.iter() {
        let name = n.as_str();
        if crate::courierust_h1::is_hop_by_hop(name) || name == "host" {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !req.headers.contains_key("user-agent") {
        if let Some(ua) = user_agent {
            out.extend_from_slice(b"User-Agent: ");
            out.extend_from_slice(ua.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    if let Some(b) = body {
        out.extend_from_slice(b.as_slice());
    }
    Ok(out)
}

/// Parse a complete HTTP/1.1 response head into its components
fn parse_head_headers(head: &[u8]) -> Result<(StatusCode, Version, HeaderMap)> {
    let end =
        find_subslice(head, b"\r\n").ok_or_else(|| Error::protocol("malformed response head"))?;
    let (status, version) = crate::courierust_h1::parse_status_line(&head[..end])?;
    let mut map = HeaderMap::new();
    let mut pos = end + 2;
    while pos < head.len() {
        let line_end = match find_subslice(&head[pos..], b"\r\n") {
            Some(i) => pos + i,
            None => head.len(),
        };
        let line = &head[pos..line_end];
        if line.is_empty() {
            break;
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| Error::protocol("malformed header line"))?;
        let name = crate::courierust_http::header::HeaderName::from_bytes(&line[..colon])?;
        let mut val = &line[colon + 1..];
        while val.first() == Some(&b' ') || val.first() == Some(&b'\t') {
            val = &val[1..];
        }
        map.append(
            name,
            crate::courierust_http::header::HeaderValue::from_bytes(val)?,
        );
        pos = line_end + 2;
    }
    Ok((status, version, map))
}

/// RFC 4648 base64url (no padding).
pub(crate) fn base64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

/// Locate `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn fail_all(pending: &mut HashMap<u32, Pending>, err: Error) {
    for (_, p) in pending.drain() {
        let _ = p.reply.map(|r| r.send(Err(err.clone())));
    }
}

fn cleanup(
    _conn: &mut DriverConn<'_>,
    pending: &mut HashMap<u32, Pending>,
    _bodies: &mut HashMap<u32, StreamBody>,
) {
    fail_all(pending, Error::canceled("connection closed"));
}

/// Convert a header list into the HPACK fields for an h2 request.
///
/// `scheme` is the transport scheme (`http`/`https`); `authority` is the
/// request URI's authority (`host:port`), used as the `:authority`
/// pseudo-header when the request itself carries no `authority`/`host`
/// header (RFC 9113 §8.3.1 — nginx rejects requests without it).
pub fn request_fields(
    req: &crate::courierust_http::request::Request<Body>,
    scheme: &str,
    authority: &str,
) -> Vec<HeaderField> {
    let head = crate::courierust_http::request::RequestHead {
        method: req.method.clone(),
        uri: req.uri.clone(),
        version: req.version,
        headers: req.headers.clone(),
    };
    head.to_h2_fields(scheme, Some(authority))
}

/// A helper for the driver: build the pseudo-header set manually if needed.
#[allow(dead_code)]
fn _field(name: &str, value: &str) -> HeaderField {
    HeaderField::new(
        HeaderName::from_hpack_bytes(name.as_bytes()).unwrap(),
        HeaderValue::from_bytes(value.as_bytes()).unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare `H2Conn` with inert shared state, for accounting tests that
    /// never touch the driver thread.
    fn test_conn() -> H2Conn {
        let (tx, _rx) = channel::<H2Cmd>();
        H2Conn {
            tx,
            peer: "127.0.0.1:1".parse().unwrap(),
            accepting: Arc::new(AtomicBool::new(true)),
            reservations: Arc::new(AtomicUsize::new(0)),
            body_load: Arc::new(AtomicUsize::new(0)),
            ewma_service_us: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn reserve_release_balances_to_idle() {
        let conn = test_conn();
        assert!(conn.is_idle(), "fresh connection must be idle");
        // A header-only request and a 1 MiB body request.
        conn.reserve(0);
        conn.reserve(1 << 20);
        assert!(!conn.is_idle());
        conn.release(0);
        conn.release(1 << 20);
        assert!(
            conn.is_idle(),
            "balanced reserve/release must return to idle"
        );
        assert_eq!(conn.load(), 0);
    }

    #[test]
    fn load_weights_bodies_over_stream_count() {
        let conn = test_conn();
        // One connection: a single 1 MiB upload (1 stream, ~16 body units).
        conn.reserve(1 << 20);
        let big_upload_load = conn.load();
        // Another connection: four header-only requests (4 streams, 0 body).
        conn.release(1 << 20);
        for _ in 0..4 {
            conn.reserve(0);
        }
        let four_small_load = conn.load();
        assert!(
            big_upload_load > four_small_load,
            "one 1 MiB upload must outweigh four header-only RPCs: {big_upload_load} vs {four_small_load}"
        );
        // And a header-only request is cheaper than a 64 KiB body request.
        conn.release(0);
        conn.release(0);
        conn.release(0);
        conn.release(0);
        conn.reserve(64 * 1024);
        assert_eq!(conn.load(), 2, "one stream + one 64 KiB body unit");
    }

    #[test]
    fn ewma_updates_and_caps() {
        let conn = test_conn();
        assert_eq!(conn.load(), 0, "no samples yet -> no latency term");
        conn.note_service_us(1_000); // first sample seeds the EWMA
        conn.note_service_us(1_000);
        conn.note_service_us(1_000);
        assert_eq!(conn.load(), 1, "1 ms of service time adds one unit");
        // A pathological sample is capped, so load stays bounded.
        conn.note_service_us(60_000_000);
        assert!(conn.load() <= 10 + 1, "EWMA term must stay within its cap");
    }

    #[test]
    fn idle_wins_over_stale_ewma() {
        let conn = test_conn();
        // One pathological request leaves a high EWMA term…
        conn.note_service_us(60_000_000);
        // …but once released the connection is idle again. The pool must
        // prefer it on that basis (a free connection is free regardless of
        // latency history); `load` alone would skip it forever because an
        // idle connection's EWMA only decays on new samples.
        assert!(conn.is_idle(), "released connection must be idle");
        assert!(
            conn.load() > 0,
            "the EWMA term still shows in load, which is why idle-first matters"
        );
        conn.reserve(0);
        assert!(!conn.is_idle());
        conn.release(0);
        assert!(conn.is_idle());
    }
}
