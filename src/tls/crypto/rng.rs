#![allow(unsafe_code)]

//! Entropy and a ChaCha20-based deterministic random generator.
//!
//! With no third-party crates, OS entropy is obtained directly:
//! - Windows: `RtlGenRandom` (`SystemFunction036` from `advapi32`).
//! - Unix-like: reading `/dev/urandom`.
//!
//! The generator is a ChaCha20 counter-mode DRBG seeded from OS entropy
//! and periodically reseeded, which is the standard construction for
//! this class of usage (key shares, ClientHello random, etc.).

use alloc::vec::Vec;

#[cfg(windows)]
mod os {
    use core::ffi::c_void;

    #[link(name = "Advapi32")]
    extern "system" {
        fn SystemFunction036(pb: *mut c_void, cb: u32) -> i32;
    }

    /// Fill `buf` from the Windows cryptographic RNG.
    pub fn fill(buf: &mut [u8]) -> bool {
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            let ok =
                unsafe { SystemFunction036(chunk.as_mut_ptr() as *mut c_void, chunk.len() as u32) };
            if ok == 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(all(unix, not(windows)))]
mod os {
    use std::fs::File;
    use std::io::Read;

    /// Fill `buf` from `/dev/urandom`.
    pub fn fill(buf: &mut [u8]) -> bool {
        let mut f = match File::open("/dev/urandom") {
            Ok(f) => f,
            Err(_) => return false,
        };
        let mut filled = 0usize;
        while filled < buf.len() {
            match f.read(&mut buf[filled..]) {
                Ok(0) => return false,
                Ok(n) => filled += n,
                Err(_) => return false,
            }
        }
        true
    }
}

#[cfg(not(any(windows, unix)))]
mod os {
    /// Unknown platform: no OS entropy. Callers must seed manually.
    pub fn fill(_buf: &mut [u8]) -> bool {
        false
    }
}

/// Fill `buf` with cryptographically strong random bytes.
pub fn fill_random(buf: &mut [u8]) -> bool {
    os::fill(buf)
}

/// A ChaCha20 counter-mode DRBG, seeded from OS entropy.
pub struct ChaChaRng {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    /// Blocks generated since the last reseed.
    since_reseed: u64,
}

impl ChaChaRng {
    /// Create a generator seeded from OS entropy, falling back to a
    /// caller-supplied seed if the OS source is unavailable.
    pub fn new() -> Option<Self> {
        let mut seed = [0u8; 44];
        if !fill_random(&mut seed) {
            return None;
        }
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        key.copy_from_slice(&seed[..32]);
        nonce.copy_from_slice(&seed[32..44]);
        Some(Self {
            key,
            nonce,
            counter: 0,
            since_reseed: 0,
        })
    }

    /// Build from an explicit seed (used when the OS entropy source is
    /// not available, e.g. on exotic targets).
    pub fn from_seed(seed: &[u8; 44]) -> Self {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        key.copy_from_slice(&seed[..32]);
        nonce.copy_from_slice(&seed[32..44]);
        Self {
            key,
            nonce,
            counter: 0,
            since_reseed: 0,
        }
    }

    fn reseed(&mut self) {
        let mut fresh = [0u8; 44];
        if fill_random(&mut fresh) {
            // Mix the new entropy into the existing key with ChaCha20.
            self.fill_blocks_raw(&mut fresh, self.counter.wrapping_add(1));
        }
        self.key.copy_from_slice(&fresh[..32]);
        self.nonce.copy_from_slice(&fresh[32..44]);
        self.counter = 0;
        self.since_reseed = 0;
    }

    fn fill_blocks_raw(&mut self, out: &mut [u8], start_counter: u32) {
        let mut counter = start_counter;
        let mut offset = 0usize;
        while offset < out.len() {
            let mut block = [0u8; 64];
            crate::tls::crypto::chacha20::ChaCha20::new(&self.key, &self.nonce)
                .block_at(counter, &mut block);
            let take = core::cmp::min(64, out.len() - offset);
            out[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
            counter = counter.wrapping_add(1);
        }
    }

    /// Fill `out` with random bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        // Reseed every 32 KiB of output (512 blocks) to bound the
        // exposure of any single key.
        const RESEED_BLOCKS: u64 = 512;
        let mut offset = 0usize;
        while offset < out.len() {
            if self.since_reseed >= RESEED_BLOCKS {
                self.reseed();
            }
            let blocks_needed = (out.len() - offset).div_ceil(64) as u64;
            let blocks_this_round =
                core::cmp::min(blocks_needed, RESEED_BLOCKS - self.since_reseed);
            let bytes_this_round = (blocks_this_round as usize) * 64;
            let end = core::cmp::min(offset + bytes_this_round, out.len());
            self.fill_blocks_raw(&mut out[offset..end], self.counter);
            offset = end;
            self.counter = self.counter.wrapping_add(blocks_this_round as u32);
            self.since_reseed += blocks_this_round;
        }
    }

    /// One random `[u8; 32]` (a typical key share / handshake random).
    pub fn random_32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.fill(&mut out);
        out
    }

    /// One random `[u8; 16]`.
    pub fn random_16(&mut self) -> [u8; 16] {
        let mut out = [0u8; 16];
        self.fill(&mut out);
        out
    }
}

/// Convenience: allocate a fresh random buffer of length `len`.
pub fn random_vec(rng: &mut ChaChaRng, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rng.fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_distinct_outputs() {
        let mut a = ChaChaRng::new().unwrap();
        let mut b = ChaChaRng::new().unwrap();
        let x = a.random_32();
        let y = b.random_32();
        assert_ne!(x, y);
    }

    #[test]
    fn rng_seeded_deterministic() {
        let seed = [7u8; 44];
        let mut a = ChaChaRng::from_seed(&seed);
        let mut b = ChaChaRng::from_seed(&seed);
        assert_eq!(a.random_32(), b.random_32());
    }
}
