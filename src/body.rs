//! Threaded-layer message bodies.
//!
//! Extends the `no_std` [`crate::http::Body`] with a channel-backed
//! streaming variant used by the client (response bodies arriving over
//! time) and the server (handlers can stream responses from another
//! thread).

use crate::bytes::Bytes;
use crate::error::Error;
use crate::Result;
use std::sync::mpsc::{Receiver, TryRecvError};

/// A message body in the threaded layer.
#[derive(Default)]
pub enum Body {
    /// No body.
    #[default]
    Empty,
    /// A fully materialized body.
    Bytes(Bytes),
    /// A streaming body: chunks arrive on the channel until it closes.
    Channel(Receiver<Result<Bytes>>),
}

impl Body {
    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Bytes(b) => b.is_empty(),
            Self::Channel(_) => false,
        }
    }

    /// Whether the body is fully materialized.
    pub fn is_bytes(&self) -> bool {
        matches!(self, Self::Bytes(_))
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
            Self::Channel(rx) => match rx.try_recv() {
                Ok(chunk) => chunk.map(Some),
                Err(TryRecvError::Empty) => Ok(None),
                Err(TryRecvError::Disconnected) => Ok(None),
            },
            _ => Ok(None),
        }
    }

    /// Collect a channel body into a single [`Bytes`].
    pub fn collect(self) -> Result<Bytes> {
        match self {
            Self::Empty => Ok(Bytes::new()),
            Self::Bytes(b) => Ok(b),
            Self::Channel(rx) => {
                let mut out = Vec::new();
                while let Ok(chunk) = rx.recv() {
                    let b = chunk?;
                    out.extend_from_slice(&b);
                }
                Ok(Bytes::from(out))
            }
        }
    }

    /// Total length if known.
    pub fn len(&self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::Bytes(b) => Some(b.len()),
            Self::Channel(_) => None,
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
        }
    }
}

/// A sender-side helper for streaming bodies.
pub struct BodySender {
    tx: std::sync::mpsc::Sender<Result<Bytes>>,
}

impl BodySender {
    /// Build a sender from a raw channel (used by adapters that
    /// transform the stream before it reaches the transport).
    pub fn from_sender(tx: std::sync::mpsc::Sender<Result<Bytes>>) -> Self {
        Self { tx }
    }

    /// Send a chunk.
    pub fn send(&self, chunk: Bytes) -> Result<()> {
        self.tx
            .send(Ok(chunk))
            .map_err(|_| Error::canceled("body receiver dropped"))
    }

    /// Send a chunk from a slice.
    pub fn send_bytes(&self, chunk: &[u8]) -> Result<()> {
        self.send(Bytes::from(chunk))
    }

    /// Send a raw result (a chunk or a transport error) to the receiver.
    pub fn send_result(&self, result: Result<Bytes>) -> Result<()> {
        self.tx
            .send(result)
            .map_err(|_| Error::canceled("body receiver dropped"))
    }

    /// Send an error to the receiver.
    pub fn fail(&self, err: Error) {
        let _ = self.tx.send(Err(err));
    }
}

/// Create a streaming body pair: the sender feeds the body, the receiver
/// is the [`Body::Channel`].
pub fn channel() -> (BodySender, Body) {
    let (tx, rx) = std::sync::mpsc::channel::<Result<Bytes>>();
    (BodySender { tx }, Body::Channel(rx))
}
