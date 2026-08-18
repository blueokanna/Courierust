//! HTTP/2 flow-control windows (RFC 9113 §5.2).
//!
//! Windows are tracked in `i64` with saturating arithmetic. The wire
//! values are `u32`; an `i64` accumulator can never overflow during
//! normal operation and gives clean handling of the negative send
//! windows that `SETTINGS_INITIAL_WINDOW_SIZE` reductions can create.

/// A single flow-control window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowWindow {
    /// Current available credit.
    size: i64,
    /// Hard ceiling this window may not exceed.
    limit: i64,
}

impl FlowWindow {
    /// A window starting at `initial` with a ceiling of `limit`
    /// (usually `u32::MAX`).
    #[inline]
    pub const fn new(initial: i64, limit: i64) -> Self {
        Self {
            size: initial,
            limit,
        }
    }

    /// Available credit.
    #[inline]
    pub const fn available(&self) -> i64 {
        self.size
    }

    /// Consume `n` units of credit (sending or receiving data).
    #[inline]
    pub fn consume(&mut self, n: i64) {
        self.size = self.size.saturating_sub(n);
    }

    /// Add credit from a `WINDOW_UPDATE`. Returns `false` if the update
    /// would push the window past its ceiling (a flow-control error per
    /// RFC 9113 §6.9.1).
    pub fn increase(&mut self, n: u32) -> bool {
        let next = self.size.saturating_add(n as i64);
        if next > self.limit {
            return false;
        }
        self.size = next;
        true
    }

    /// Re-credit received bytes after the application consumed them.
    #[inline]
    pub fn release(&mut self, n: i64) {
        self.size = self.size.saturating_add(n).min(self.limit);
    }
}
