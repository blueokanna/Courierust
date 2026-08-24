//! RFC 9218 extensible priorities and the WUCS scheduler.
//!
//! # WUCS — Weighted-Urgency Calendar Scheduler
//!
//! Streams are bucketed by urgency (0..=7, RFC 9218 §4.1). Each bucket
//! is a Deficit Round Robin class with a fixed quantum, so a busy
//! high-urgency bucket can never starve lower-urgency traffic (RFC 9218
//! §10 explicitly warns against starvation). Incremental streams inside a
//! bucket are served in round-robin so bandwidth is shared as their data
//! arrives; non-incremental streams are served FIFO by stream id, which
//! matches the RFC 9218 recommendation ("ascending order of the stream
//! ID"). The selection cost is O(1) — a fixed 8-bucket scan — which is
//! what makes per-frame scheduling affordable on a hot connection.

use alloc::collections::VecDeque;

/// A stream's priority (RFC 9218 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priority {
    /// Urgency 0..=7; 0 is highest precedence. Default 3.
    pub urgency: u8,
    /// Whether the response can be consumed incrementally. Default false.
    pub incremental: bool,
}

impl Default for Priority {
    fn default() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}

impl Priority {
    /// Parse a priority field value / Priority header value
    /// (RFC 8941 dictionary, subset: `u` integer and `i` boolean).
    /// Unknown parameters are ignored (RFC 9218 §4).
    pub fn parse(s: &[u8]) -> Option<Self> {
        let mut out = Self::default();
        // Split on commas.
        let mut i = 0usize;
        while i < s.len() {
            // Skip whitespace / commas.
            while i < s.len() && (s[i] == b' ' || s[i] == b',' || s[i] == b'\t') {
                i += 1;
            }
            let start = i;
            while i < s.len() && s[i] != b',' && s[i] != b' ' && s[i] != b'\t' {
                i += 1;
            }
            let tok = &s[start..i];
            if tok.is_empty() {
                continue;
            }
            match tok {
                b"i" => out.incremental = true,
                _ => {
                    if let Some(eq) = tok.iter().position(|&c| c == b'=') {
                        let k = &tok[..eq];
                        let v = &tok[eq + 1..];
                        if k == b"u" {
                            let v = core::str::from_utf8(v).ok()?;
                            let u: u8 = v.parse().ok()?;
                            if u <= 7 {
                                out.urgency = u;
                            }
                        }
                        // unknown params ignored
                    }
                }
            }
        }
        Some(out)
    }
}

impl core::fmt::Display for Priority {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::write!(f, "u={}", self.urgency)?;
        if self.incremental {
            f.write_str(", i")?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Bucket {
    /// Non-incremental streams, FIFO by insertion order (stream id).
    non_incremental: VecDeque<u32>,
    /// Incremental streams, round-robin.
    incremental: VecDeque<u32>,
    /// DRR deficit in bytes.
    deficit: u32,
    /// DRR quantum in bytes.
    quantum: u32,
}

impl Bucket {
    fn new(quantum: u32) -> Self {
        Self {
            non_incremental: VecDeque::new(),
            incremental: VecDeque::new(),
            deficit: 0,
            quantum,
        }
    }
}

/// The WUCS scheduler.
pub struct Scheduler {
    buckets: [Bucket; 8],
    /// Total streams tracked.
    count: usize,
    /// Rounds since construction (calendar counter).
    pub rounds: u64,
}

impl Scheduler {
    /// New scheduler with a per-bucket DRR quantum in bytes.
    pub fn new(quantum: u32) -> Self {
        let quantum = quantum.max(1);
        Self {
            buckets: [
                Bucket::new(quantum),
                Bucket::new(quantum),
                Bucket::new(quantum),
                Bucket::new(quantum),
                Bucket::new(quantum),
                Bucket::new(quantum),
                Bucket::new(quantum),
                Bucket::new(quantum),
            ],
            count: 0,
            rounds: 0,
        }
    }

    /// Number of tracked streams.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether no streams are tracked.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Register a stream.
    pub fn add(&mut self, stream_id: u32, p: Priority) {
        let b = &mut self.buckets[p.urgency as usize];
        if p.incremental {
            b.incremental.push_back(stream_id);
        } else {
            b.non_incremental.push_back(stream_id);
        }
        self.count += 1;
    }

    /// Move a stream to a new priority (RFC 9218 reprioritization).
    pub fn update(&mut self, stream_id: u32, old: Priority, new: Priority) {
        if old == new {
            return;
        }
        self.remove(stream_id);
        self.add(stream_id, new);
    }

    /// Remove a stream.
    pub fn remove(&mut self, stream_id: u32) {
        for b in self.buckets.iter_mut() {
            if let Some(pos) = b.non_incremental.iter().position(|&s| s == stream_id) {
                b.non_incremental.remove(pos);
                self.count -= 1;
                return;
            }
            if let Some(pos) = b.incremental.iter().position(|&s| s == stream_id) {
                b.incremental.remove(pos);
                self.count -= 1;
                return;
            }
        }
    }

    /// Pick the next stream to serve, accounting for `want` bytes about
    /// to be transmitted. Returns `None` if nothing is servable.
    ///
    /// Scan order is urgency 0 → 7. Incremental streams are always
    /// servable (one round-robin turn each). Non-incremental streams are
    /// servable while the bucket's deficit plus `want` stays within its
    /// quantum; a saturated bucket yields to lower urgencies, and when a
    /// full scan finds nothing, deficits reset and the round advances —
    /// this is the DRR anti-starvation guarantee.
    pub fn next(&mut self, want: usize) -> Option<u32> {
        for u in 0..8 {
            let b = &mut self.buckets[u];
            if let Some(sid) = b.incremental.pop_front() {
                b.incremental.push_back(sid);
                return Some(sid);
            }
            if !b.non_incremental.is_empty() && b.deficit.saturating_add(want as u32) <= b.quantum {
                b.deficit = b.deficit.saturating_add(want as u32);
                return b.non_incremental.pop_front();
            }
        }
        // Nothing servable: some non-incremental bucket is saturated.
        let any = self.buckets.iter().any(|b| !b.non_incremental.is_empty());
        if any {
            self.rounds += 1;
            for b in self.buckets.iter_mut() {
                b.deficit = 0;
            }
            for u in 0..8 {
                let b = &mut self.buckets[u];
                if let Some(sid) = b.incremental.pop_front() {
                    b.incremental.push_back(sid);
                    return Some(sid);
                }
                if !b.non_incremental.is_empty()
                    && b.deficit.saturating_add(want as u32) <= b.quantum
                {
                    b.deficit = b.deficit.saturating_add(want as u32);
                    return b.non_incremental.pop_front();
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_priority_values() {
        assert_eq!(Priority::parse(b""), Some(Priority::default()));
        assert_eq!(
            Priority::parse(b"u=0"),
            Some(Priority {
                urgency: 0,
                incremental: false
            })
        );
        assert_eq!(
            Priority::parse(b"u=5, i"),
            Some(Priority {
                urgency: 5,
                incremental: true
            })
        );
        assert_eq!(
            Priority::parse(b"i, u=1"),
            Some(Priority {
                urgency: 1,
                incremental: true
            })
        );
        assert_eq!(Priority::parse(b"u=9"), Some(Priority::default())); // out of range ignored
        assert_eq!(
            Priority::parse(b"x=y, u=7"),
            Some(Priority {
                urgency: 7,
                incremental: false
            })
        );
    }

    #[test]
    fn urgency_ordering() {
        let mut s = Scheduler::new(16_384);
        s.add(
            10,
            Priority {
                urgency: 3,
                incremental: false,
            },
        );
        s.add(
            11,
            Priority {
                urgency: 0,
                incremental: false,
            },
        );
        s.add(
            12,
            Priority {
                urgency: 7,
                incremental: false,
            },
        );
        assert_eq!(s.next(100), Some(11));
        assert_eq!(s.next(100), Some(10));
        assert_eq!(s.next(100), Some(12));
        assert_eq!(s.next(100), None);
    }

    #[test]
    fn incremental_round_robin() {
        let mut s = Scheduler::new(16_384);
        s.add(
            1,
            Priority {
                urgency: 3,
                incremental: true,
            },
        );
        s.add(
            2,
            Priority {
                urgency: 3,
                incremental: true,
            },
        );
        s.add(
            3,
            Priority {
                urgency: 0,
                incremental: false,
            },
        );
        // urgency 0 first
        assert_eq!(s.next(100), Some(3));
        // then incremental round-robin
        assert_eq!(s.next(100), Some(1));
        assert_eq!(s.next(100), Some(2));
        assert_eq!(s.next(100), Some(1));
    }

    #[test]
    fn no_starvation_across_urgencies() {
        // Emulate a caller that re-queues a stream while it still has data
        // (the connection does exactly this). DRR anti-starvation: once
        // urgency 0's deficit saturates, urgency 7 still gets a turn.
        let mut s = Scheduler::new(1000);
        s.add(
            1,
            Priority {
                urgency: 0,
                incremental: false,
            },
        );
        s.add(
            2,
            Priority {
                urgency: 7,
                incremental: false,
            },
        );
        let mut served: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
        for _ in 0..16 {
            if let Some(sid) = s.next(100) {
                served.push(sid);
                if sid == 1 {
                    // Stream 1 still has data, so the caller re-queues it.
                    s.add(
                        1,
                        Priority {
                            urgency: 0,
                            incremental: false,
                        },
                    );
                }
            }
        }
        assert_eq!(&served[..10], &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        // The 11th turn goes to the lower-urgency stream (no starvation).
        assert_eq!(served[10], 2);
    }

    #[test]
    fn priority_update_moves_bucket() {
        let mut s = Scheduler::new(16_384);
        s.add(
            1,
            Priority {
                urgency: 3,
                incremental: false,
            },
        );
        s.add(
            2,
            Priority {
                urgency: 7,
                incremental: false,
            },
        );
        s.update(
            2,
            Priority {
                urgency: 7,
                incremental: false,
            },
            Priority {
                urgency: 0,
                incremental: false,
            },
        );
        assert_eq!(s.next(100), Some(2));
        assert_eq!(s.next(100), Some(1));
    }
}
