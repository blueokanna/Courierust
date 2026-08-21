//! ChaCha20 stream cipher (RFC 8439 §2).
//!
//! Pure 32-bit quarter-round arithmetic — no secret-dependent branches,
//! no tables, structurally constant-time.

/// The 256-bit key plus 96-bit nonce and 32-bit counter state.
pub struct ChaCha20 {
    state: [u32; 16],
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn block(state: &[u32; 16], out: &mut [u8; 64]) {
    let mut x = *state;
    for _ in 0..10 {
        // Column rounds.
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }
    for (i, word) in x.iter_mut().enumerate() {
        *word = word.wrapping_add(state[i]);
    }
    for (i, word) in x.iter().enumerate() {
        let bytes = word.to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
}

impl ChaCha20 {
    /// Initialize from `key` (32 bytes) and `nonce` (12 bytes) at
    /// counter zero.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0u32; 16];
        state[0] = 0x6170_7865;
        state[1] = 0x3320_646e;
        state[2] = 0x7962_2d32;
        state[3] = 0x6b20_6574;
        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        state[12] = 0; // counter
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        Self { state }
    }

    /// Set the block counter.
    pub fn set_counter(&mut self, counter: u32) {
        self.state[12] = counter;
    }

    /// Generate the keystream block `n` into `out`.
    pub fn block_at(&self, n: u32, out: &mut [u8; 64]) {
        let mut state = self.state;
        state[12] = n;
        block(&state, out);
    }

    /// Encrypt/decrypt `data` in place starting at the current counter
    /// (initially 0; use [`Self::set_counter`] to start elsewhere).
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0usize;
        let mut counter = self.state[12];
        while offset < data.len() {
            let mut ks = [0u8; 64];
            self.block_at(counter, &mut ks);
            let take = core::cmp::min(64, data.len() - offset);
            for i in 0..take {
                data[offset + i] ^= ks[i];
            }
            offset += take;
            counter = counter.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_rfc8439_block() {
        // RFC 8439 §2.3.2 first 64 bytes of keystream.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let chacha = ChaCha20::new(&key, &nonce);
        let mut block = [0u8; 64];
        chacha.block_at(1, &mut block);
        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(&block[..], &expected[..]);
    }

    #[test]
    fn chacha20_rfc8439_encryption() {
        // RFC 8439 §2.4.2 (A.2): keystream for a 64-byte zero message
        // with the zero key and zero nonce.
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 64];
        let expected = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        let mut data = plaintext.to_vec();
        let mut chacha = ChaCha20::new(&key, &nonce);
        chacha.apply_keystream(&mut data);
        assert_eq!(&data[..], &expected[..]);
    }
}
