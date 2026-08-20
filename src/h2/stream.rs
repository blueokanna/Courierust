//! HTTP/2 stream state machine (RFC 9113 §5.1) and stream table.

use crate::h2::priority::Priority;
use alloc::collections::BTreeMap;

/// Stream states per RFC 9113 §5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// No stream exists yet.
    Idle,
    /// Both sides may send.
    Open,
    /// We may not send; peer may.
    HalfClosedLocal,
    /// We may send; peer may not.
    HalfClosedRemote,
    /// Terminated.
    Closed,
    /// Push-promised stream, response not yet sent.
    ReservedLocal,
    /// Push-promised stream, request not yet received.
    ReservedRemote,
}

/// A tracked stream.
#[derive(Debug, Clone)]
pub struct Stream {
    /// Stream id.
    pub id: u32,
    /// Current state.
    pub state: StreamState,
    /// Current priority.
    pub priority: Priority,
    /// Send window (credit we have to send data on this stream).
    pub send_window: i64,
    /// Receive window (credit the peer has to send us data).
    pub recv_window: i64,
    /// Bytes buffered locally, waiting for flow-control credit.
    pub send_buffered: usize,
    /// Whether the application has completed sending on this stream
    /// (END_STREAM already queued or no more data will come).
    pub send_done: bool,
    /// Whether we have delivered END_STREAM to the application.
    pub recv_ended: bool,
    /// Bytes of received data not yet released back to the peer.
    pub recv_unreleased: i64,
    /// Whether a header block has already been delivered for this
    /// stream (subsequent blocks are trailers).
    pub headers_delivered: bool,
    /// Expected message-body length from the message's `content-length`
    /// header (RFC 9113 §8.1.2.6). `None` when absent or not applicable.
    pub content_length: Option<u64>,
    /// Bytes of `DATA` payload received so far on this stream.
    pub recv_body_len: u64,
    /// Whether the message on this stream is expected to carry a body
    /// (false for HEAD/CONNECT requests and 1xx/204/304 responses).
    /// DATA on a bodyless message is a stream error; a `content-length`
    /// that does not match the data count is a stream error.
    pub body_expected: bool,
}

impl Stream {
    /// New stream.
    pub fn new(id: u32, send_window: i64, recv_window: i64, priority: Priority) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            priority,
            send_window,
            recv_window,
            send_buffered: 0,
            send_done: false,
            recv_ended: false,
            recv_unreleased: 0,
            headers_delivered: false,
            content_length: None,
            recv_body_len: 0,
            body_expected: true,
        }
    }

    /// Whether the stream is fully closed.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.state == StreamState::Closed
    }

    /// Whether the stream can still receive data from the peer.
    #[inline]
    pub fn can_recv(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal) && !self.recv_ended
    }

    /// Whether the stream can still send data.
    #[inline]
    pub fn can_send(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedRemote
        ) && !self.send_done
    }
}

/// Collection of streams with connection-level bookkeeping.
#[derive(Default)]
pub struct StreamMap {
    streams: BTreeMap<u32, Stream>,
    /// Next client-initiated stream id we will use.
    next_client_id: u32,
    /// Next server-initiated stream id we will use (push).
    #[allow(dead_code)]
    next_server_id: u32,
    /// Highest peer-initiated stream id seen.
    last_peer_id: u32,
    /// Number of open (non-closed) streams.
    open_count: usize,
}

impl StreamMap {
    /// New map for the given role.
    pub fn new(client: bool) -> Self {
        Self {
            streams: BTreeMap::new(),
            next_client_id: if client { 1 } else { 2 },
            next_server_id: if client { 2 } else { 1 },
            last_peer_id: 0,
            open_count: 0,
        }
    }

    /// Look up a stream.
    #[inline]
    pub fn get(&self, id: &u32) -> Option<&Stream> {
        self.streams.get(id)
    }

    /// Look up a stream mutably.
    #[inline]
    pub fn get_mut(&mut self, id: &u32) -> Option<&mut Stream> {
        self.streams.get_mut(id)
    }

    /// Insert a stream.
    pub fn insert(&mut self, s: Stream) {
        if !s.is_closed() {
            self.open_count += 1;
        }
        self.streams.insert(s.id, s);
    }

    /// Remove a stream (returns it). Streams are removed only once they
    /// have closed, so the open count always drops with the record.
    pub fn remove(&mut self, id: &u32) -> Option<Stream> {
        let s = self.streams.remove(id)?;
        self.open_count = self.open_count.saturating_sub(1);
        Some(s)
    }

    /// Allocate the next client-initiated stream id (odd numbers).
    pub fn allocate_client_id(&mut self) -> Option<u32> {
        let id = self.next_client_id;
        if id > 0x7fff_ffff {
            return None;
        }
        self.next_client_id = id.wrapping_add(2);
        Some(id)
    }

    /// Reserve stream 1 for an RFC 7540 §3.2 `h2c` Upgrade: the upgraded
    /// HTTP/1.1 request occupies stream 1, so the next client-initiated
    /// stream must be 3.
    pub fn reserve_upgrade_stream(&mut self) {
        if self.next_client_id == 1 {
            self.next_client_id = 3;
        }
    }

    /// The next client-initiated stream id (without allocating).
    #[inline]
    pub fn peek_client_id(&self) -> u32 {
        self.next_client_id
    }

    /// Whether `id` is valid for a peer-initiated stream (even/odd
    /// matching our role) and greater than the last one seen.
    pub fn accept_peer_id(&mut self, id: u32) -> bool {
        if id & 1 == 0 {
            // Even ids are server-initiated; a client never receives them
            // except as PUSH_PROMISE (which we disable).
            return false;
        }
        if id <= self.last_peer_id {
            return false;
        }
        self.last_peer_id = id;
        true
    }

    /// The highest peer-initiated stream id seen.
    #[inline]
    pub fn last_peer_id(&self) -> u32 {
        self.last_peer_id
    }

    /// Number of non-closed streams.
    #[inline]
    pub fn open_count(&self) -> usize {
        self.open_count
    }

    /// Iterate over all streams.
    pub fn iter(&self) -> impl Iterator<Item = &Stream> {
        self.streams.values()
    }

    /// Iterate mutably over all streams.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Stream> {
        self.streams.values_mut()
    }

    /// Number of tracked streams.
    #[inline]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether any streams are tracked.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Whether a stream id exists.
    #[inline]
    pub fn contains(&self, id: &u32) -> bool {
        self.streams.contains_key(id)
    }
}
