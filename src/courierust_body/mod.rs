//! Threaded-layer message bodies.
//!
//! Extends the `no_std` [`crate::courierust_http::Body`] with a channel-backed
//! streaming variant used by the client (response bodies arriving over
//! time) and the server (handlers can stream responses from another
//! thread).

use crate::courierust_bytes::Bytes;
use crate::courierust_error::{Error, ErrorKind};
use crate::Result;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};

/// A message body in the threaded layer.
#[derive(Default)]
pub enum Body {
    /// No body.
    #[default]
    Empty,
    /// A fully materialized body.
    Bytes(Bytes),
    /// A streaming body: chunks arrive on the channel until it closes.
    ///
    /// This is the raw form (any `std::sync::mpsc` pair can produce it),
    /// so it carries no producer wake: a transport parks the connection
    /// and polls the channel. Prefer [`channel`], which returns
    /// [`Body::Stream`] and delivers chunks on a wake instead.
    Channel(Receiver<Result<Bytes>>),
    /// A streaming body with a producer wake handle ([`channel`] builds
    /// this): the transport installs a callback into it and the producer
    /// fires it per chunk, so the chunk is written as soon as it exists
    /// instead of when a poll next notices it.
    Stream(ChannelStream),
}

impl Body {
    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Bytes(b) => b.is_empty(),
            Self::Channel(_) | Self::Stream(_) => false,
        }
    }

    /// Whether the body is fully materialized.
    pub fn is_bytes(&self) -> bool {
        matches!(self, Self::Bytes(_))
    }

    /// Whether the body is streamed chunk by chunk (either variant).
    pub fn is_stream(&self) -> bool {
        matches!(self, Self::Channel(_) | Self::Stream(_))
    }

    /// Take the streaming receive side, if this body is a stream.
    ///
    /// A transport consumes exactly this: one code path for both
    /// variants, with the wake handle present only for [`Body::Stream`].
    pub fn into_stream(self) -> Option<ChannelStream> {
        match self {
            Self::Channel(rx) => Some(ChannelStream::raw(rx)),
            Self::Stream(stream) => Some(stream),
            Self::Empty | Self::Bytes(_) => None,
        }
    }

    /// If fully materialized, borrow the bytes.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Pull one chunk from a channel body without blocking.
    pub fn try_next_chunk(&mut self) -> Result<Option<Bytes>> {
        match self {
            Self::Channel(rx) => try_next(rx),
            Self::Stream(stream) => try_next(&stream.rx),
            _ => Ok(None),
        }
    }

    /// Collect a channel body into a single [`Bytes`].
    pub fn collect(self) -> Result<Bytes> {
        self.collect_limited(usize::MAX)
    }

    /// Collect a channel body while enforcing a hard byte limit.
    ///
    /// The limit is checked before each allocation/copy. This matters for
    /// channel-backed bodies because their total size is otherwise unknown
    /// and a producer can keep sending indefinitely.
    pub fn collect_limited(self, max: usize) -> Result<Bytes> {
        match self {
            Self::Empty => Ok(Bytes::new()),
            Self::Bytes(b) if b.len() <= max => Ok(b),
            Self::Bytes(_) => Err(Error::overflow("body exceeds configured limit")),
            Self::Channel(rx) => drain(rx, max),
            Self::Stream(stream) => drain(stream.into_receiver(), max),
        }
    }

    /// Total length if known.
    pub fn len(&self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::Bytes(b) => Some(b.len()),
            Self::Channel(_) | Self::Stream(_) => None,
        }
    }
}

/// Reading a response in the threaded layer: the two accessors every
/// caller otherwise writes by hand around `collect`.
impl crate::courierust_http::response::Response<Body> {
    /// Consume the response and return its body bytes.
    ///
    /// A body from this crate's transports is usually already
    /// materialized (a move); a streaming one is drained to its end.
    pub fn bytes(self) -> Result<Bytes> {
        self.body.collect()
    }

    /// Consume the response and return its body as text.
    ///
    /// Refuses a body that is not valid UTF-8 rather than substituting
    /// U+FFFD for the offending bytes: an answer mangled in transit must
    /// not be able to read as a legitimate one. A caller that wants
    /// substitution can spell it out —
    /// `String::from_utf8_lossy(&resp.bytes()?)`.
    pub fn text(self) -> Result<String> {
        let bytes = self.body.collect()?;
        core::str::from_utf8(&bytes)
            .map(Into::into)
            .map_err(|_| Error::with_message(ErrorKind::Other, "response body is not valid UTF-8"))
    }
}

/// Pull one chunk without blocking (`None` also means "no chunk yet").
fn try_next(rx: &Receiver<Result<Bytes>>) -> Result<Option<Bytes>> {
    match rx.try_recv() {
        Ok(chunk) => chunk.map(Some),
        Err(TryRecvError::Empty) => Ok(None),
        Err(TryRecvError::Disconnected) => Ok(None),
    }
}

/// Collect a channel until the producer closes it, enforcing `max`.
fn drain(rx: Receiver<Result<Bytes>>, max: usize) -> Result<Bytes> {
    let mut out = Vec::new();
    while let Ok(chunk) = rx.recv() {
        let b = chunk?;
        if b.len() > max.saturating_sub(out.len()) {
            return Err(Error::overflow("body exceeds configured limit"));
        }
        out.extend_from_slice(&b);
    }
    Ok(Bytes::from(out))
}

/// The consumer side of a streaming body: the chunk channel plus the
/// producer wake handle.
///
/// Dereferences to the underlying [`Receiver`], so a consumer that only
/// wants `recv`/`recv_timeout`/`try_recv` uses it exactly like a raw
/// channel. What the extra handle buys is the wake: a transport that
/// parks the connection installs a callback into it and the producer
/// fires that callback on every chunk (see [`BodyWake`]).
pub struct ChannelStream {
    rx: Receiver<Result<Bytes>>,
    /// `Some` only for a body built by [`channel`]: a raw channel has no
    /// producer that could ever fire a wake, so claiming one would make a
    /// transport poll it at the slow cadence and delay every chunk.
    wake: Option<Arc<BodyWake>>,
}

impl ChannelStream {
    /// Wrap a raw channel. No producer can wake through it, so a parked
    /// transport falls back to polling this stream.
    pub fn raw(rx: Receiver<Result<Bytes>>) -> Self {
        Self { rx, wake: None }
    }

    /// Install the callback the producer fires after each chunk.
    ///
    /// Called by the transport that consumes the body; a no-op for a raw
    /// channel, which has no producer able to fire it. Installing twice
    /// replaces the callback (the previous one is dropped).
    pub fn install_wake(&self, wake: impl Fn() + Send + Sync + 'static) {
        if let Some(slot) = &self.wake {
            slot.install(wake);
        }
    }

    /// Drop the callback: the body is finished (or its connection is), so
    /// a late `send` from the producer must not wake anything.
    pub fn clear_wake(&self) {
        if let Some(slot) = &self.wake {
            slot.clear();
        }
    }

    /// Whether a producer wake is installed right now.
    pub fn has_wake(&self) -> bool {
        self.wake.as_ref().is_some_and(|slot| slot.is_installed())
    }

    /// The raw receiver, for consumers that own it (a relay, a pool).
    pub fn into_receiver(self) -> Receiver<Result<Bytes>> {
        self.rx
    }
}

impl Deref for ChannelStream {
    type Target = Receiver<Result<Bytes>>;

    fn deref(&self) -> &Self::Target {
        &self.rx
    }
}

impl std::fmt::Debug for ChannelStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelStream(wake={})", self.has_wake())
    }
}

impl From<ChannelStream> for Body {
    fn from(stream: ChannelStream) -> Self {
        Self::Stream(stream)
    }
}

/// The producer → transport wake handle of a streaming body.
///
/// The transport that consumes the body installs a callback; the
/// producer fires it after every chunk. That is what lets an event-driven
/// server write a chunk the moment it exists instead of waiting for the
/// next poll pass — and it stays optional by construction: a raw
/// [`Body::Channel`] simply has no handle, and the transport polls.
pub struct BodyWake {
    /// Fast path for the producer: one relaxed-free acquire load while no
    /// transport is listening (the common case for a client-side body).
    installed: AtomicBool,
    slot: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl BodyWake {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            installed: AtomicBool::new(false),
            slot: Mutex::new(None),
        })
    }

    /// The slot, recovering from a poisoned mutex: a panic elsewhere must
    /// not turn the producer's `send` into a panic.
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<Arc<dyn Fn() + Send + Sync>>> {
        self.slot
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Install (or replace) the wake callback.
    pub fn install(&self, wake: impl Fn() + Send + Sync + 'static) {
        let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(wake);
        *self.slot() = Some(wake);
        self.installed.store(true, Ordering::Release);
    }

    /// Remove the callback, so later sends wake nothing.
    pub fn clear(&self) {
        self.installed.store(false, Ordering::Release);
        *self.slot() = None;
    }

    /// Whether a callback is installed.
    pub fn is_installed(&self) -> bool {
        self.installed.load(Ordering::Acquire)
    }

    /// Fire the installed callback, if any. Called by the producer.
    ///
    /// The callback is cloned out of the slot before it runs, so a wake
    /// that re-enters the body (a transport that pumps synchronously)
    /// cannot deadlock on this mutex.
    pub fn fire(&self) {
        if !self.installed.load(Ordering::Acquire) {
            return;
        }
        let wake = self.slot().clone();
        if let Some(wake) = wake {
            wake();
        }
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Self {
        if b.is_empty() {
            Self::Empty
        } else {
            Self::Bytes(b)
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Self::from(Bytes::from(v))
    }
}

impl From<&'static [u8]> for Body {
    fn from(b: &'static [u8]) -> Self {
        Self::from(Bytes::from_static(b))
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Self {
        Self::from(Bytes::from_static(s.as_bytes()))
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Self::from(Bytes::from(s))
    }
}

impl From<Receiver<Result<Bytes>>> for Body {
    fn from(rx: Receiver<Result<Bytes>>) -> Self {
        Self::Channel(rx)
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Body::Empty"),
            Self::Bytes(b) => write!(f, "Body::Bytes({} bytes)", b.len()),
            Self::Channel(_) => write!(f, "Body::Channel"),
            Self::Stream(stream) => write!(f, "Body::Stream({stream:?})"),
        }
    }
}

/// A sender-side helper for streaming bodies.
///
/// Besides delivering chunks it carries a *cancellation* signal: the
/// transport sets it when the response is no longer wanted (the peer
/// disconnected, the deadline passed, the connection closed). A handler
/// that can block indefinitely — a server-streaming subscription, a
/// watch loop — should poll [`BodySender::is_cancelled`] between waits,
/// which is what lets its thread end instead of outliving the client.
pub struct BodySender {
    tx: Sender<Result<Bytes>>,
    cancelled: Arc<AtomicBool>,
    /// Shared with the receiver side (`Body::Stream`), which is where a
    /// transport installs its wake callback.
    wake: Arc<BodyWake>,
}

impl BodySender {
    /// Build a sender from a raw channel (used by adapters that
    /// transform the stream before it reaches the transport).
    ///
    /// The sender has no wake handle to share, so a consumer of the
    /// resulting body must poll. Use [`channel`] for a wake-capable pair.
    pub fn from_sender(tx: std::sync::mpsc::Sender<Result<Bytes>>) -> Self {
        Self {
            tx,
            cancelled: Arc::new(AtomicBool::new(false)),
            wake: BodyWake::new(),
        }
    }

    /// Whether the response has been abandoned.
    ///
    /// True once the receiving end is gone (or was told to stop). It is
    /// sticky, so a handler may test it at any point and return.
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Mark the call abandoned. The transport calls this when it stops
    /// consuming the body; an adapter that observes cancellation (a
    /// deadline timer, a disconnecting peer) may set it too.
    #[inline]
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// The shared cancellation flag, so a relay can set it from the place
    /// that actually notices the loss.
    #[inline]
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }

    /// Send a chunk.
    pub fn send(&self, chunk: Bytes) -> Result<()> {
        self.tx.send(Ok(chunk)).map_err(|_| {
            self.cancel();
            Error::canceled("body receiver dropped")
        })?;
        self.wake.fire();
        Ok(())
    }

    /// Send a chunk from a slice.
    pub fn send_bytes(&self, chunk: &[u8]) -> Result<()> {
        self.send(Bytes::from(chunk))
    }

    /// Send a raw result (a chunk or a transport error) to the receiver.
    pub fn send_result(&self, result: Result<Bytes>) -> Result<()> {
        self.tx.send(result).map_err(|_| {
            self.cancel();
            Error::canceled("body receiver dropped")
        })?;
        self.wake.fire();
        Ok(())
    }

    /// Send an error to the receiver.
    pub fn fail(&self, err: Error) {
        if self.tx.send(Err(err)).is_ok() {
            self.wake.fire();
        }
    }
}

/// Create a streaming body pair: the sender feeds the body, the receiver
/// is the [`Body::Stream`] (or [`Body::Channel`] for a raw pair).
///
/// The chunks are delivered on demand: a transport that consumes the body
/// installs a wake callback into it, so the sender's `send` — not a poll
/// timer — is what makes the chunk go out.
pub fn channel() -> (BodySender, Body) {
    let (tx, rx) = std::sync::mpsc::channel::<Result<Bytes>>();
    let wake = BodyWake::new();
    (
        BodySender {
            tx,
            cancelled: Arc::new(AtomicBool::new(false)),
            wake: wake.clone(),
        },
        Body::Stream(ChannelStream {
            rx,
            wake: Some(wake),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// The producer fires the wake once per chunk, a cleared wake stays
    /// quiet (a finished body must not wake its transport again), and a
    /// dropped receiver cancels the producer instead of swallowing chunks
    /// silently.
    #[test]
    fn body_sender_wakes_only_while_installed() {
        let (tx, body) = channel();
        let stream = body.into_stream().expect("channel() builds a stream");
        assert!(!stream.has_wake(), "no transport adopted this body yet");

        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        stream.install_wake(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        assert!(stream.has_wake());

        tx.send(Bytes::from_static(b"one")).unwrap();
        tx.send_bytes(b"two").unwrap();
        assert_eq!(hits.load(Ordering::Relaxed), 2, "one wake per chunk");
        tx.fail(Error::timeout("boom"));
        assert_eq!(hits.load(Ordering::Relaxed), 3, "a failure wakes too");

        stream.clear_wake();
        assert!(!stream.has_wake());
        tx.send_bytes(b"three").unwrap();
        assert_eq!(
            hits.load(Ordering::Relaxed),
            3,
            "a cleared wake must stay quiet"
        );

        drop(stream);
        assert!(tx.send_bytes(b"four").is_err(), "the receiver is gone");
        assert!(tx.is_cancelled(), "a dropped receiver cancels the producer");
    }

    /// A raw channel never claims a wake: nothing on the sender side can
    /// fire one, so a transport must poll it instead of waiting on it.
    #[test]
    fn raw_channel_has_no_wake_to_fire() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stream = Body::Channel(rx)
            .into_stream()
            .expect("a channel body is a stream");
        assert!(!stream.has_wake());
        stream.install_wake(|| panic!("a raw channel must not install a wake"));
        assert!(!stream.has_wake());

        tx.send(Ok(Bytes::from_static(b"x"))).unwrap();
        assert_eq!(stream.try_recv().unwrap().unwrap().len(), 1);
    }
}
