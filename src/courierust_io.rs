//! Minimal, dependency-free `Read`/`Write` traits plus buffered adapters.
//!
//! The traits are intentionally tiny so any transport (TCP, TLS stream,
//! memory pipe, ...) can be adapted in a few lines, keeping the whole
//! protocol core `no_std`-capable.

use crate::courierust_error::{Error, ErrorKind, Result};
use alloc::vec::Vec;

/// A byte source. Returns `Ok(0)` on clean EOF.
pub trait Read {
    /// Read into `buf`, returning the number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

/// A byte sink.
pub trait Write {
    /// Write as many bytes as possible; returns the count written.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Flush any buffered output.
    fn flush(&mut self) -> Result<()>;
}

impl<T: Read + ?Sized> Read for &mut T {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        (**self).read(buf)
    }
}

impl<T: Write + ?Sized> Write for &mut T {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        (**self).write(buf)
    }

    #[inline]
    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }
}

/// Buffered reader with exact-read and big-endian integer helpers.
pub struct BufReader<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
}

impl<R> BufReader<R> {
    /// Wrap `inner` with a `cap`-byte buffer.
    pub fn new(inner: R, cap: usize) -> Self {
        Self {
            inner,
            buf: vec![0u8; cap],
            pos: 0,
            cap: 0,
        }
    }

    /// Access the wrapped reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Number of bytes currently buffered.
    #[inline]
    pub fn buffered(&self) -> usize {
        self.cap - self.pos
    }

    /// Seed the buffer with bytes that were already read from the
    /// transport before this reader was created (used by the RFC 7540
    /// §3.2 `h2c` Upgrade path: the server's SETTINGS frame may already
    /// be buffered behind the `101` response). Must be called on a fresh
    /// reader; the seed must fit in the buffer.
    pub fn seed(&mut self, data: &[u8]) {
        debug_assert!(self.pos == 0 && self.cap == 0);
        let n = core::cmp::min(data.len(), self.buf.len());
        self.buf[..n].copy_from_slice(&data[..n]);
        self.cap = n;
    }
}

impl<R: Read> BufReader<R> {
    /// Fill the buffer if it is empty; returns the buffered slice.
    /// Returns `Ok(&[])` on clean EOF.
    pub fn fill_buf(&mut self) -> Result<&[u8]> {
        if self.pos == self.cap {
            self.pos = 0;
            self.cap = 0;
            let n = self.inner.read(&mut self.buf)?;
            if n == 0 {
                return Ok(&[]);
            }
            self.cap = n;
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    /// Mark `n` buffered bytes as consumed.
    pub fn consume(&mut self, n: usize) {
        debug_assert!(n <= self.cap - self.pos);
        self.pos += n;
        if self.pos == self.cap {
            self.pos = 0;
            self.cap = 0;
        }
    }

    /// Read exactly `n` bytes (fails with `UnexpectedEof` on short read).
    pub fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let b = self.fill_buf()?;
            if b.is_empty() {
                return Err(Error::eof());
            }
            let take = core::cmp::min(n - out.len(), b.len());
            out.extend_from_slice(&b[..take]);
            self.consume(take);
        }
        Ok(out)
    }

    /// Read exactly `n` bytes into `out`.
    pub fn read_exact_into(&mut self, out: &mut [u8]) -> Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            let b = self.fill_buf()?;
            if b.is_empty() {
                return Err(Error::eof());
            }
            let take = core::cmp::min(out.len() - filled, b.len());
            out[filled..filled + take].copy_from_slice(&b[..take]);
            self.consume(take);
            filled += take;
        }
        Ok(())
    }

    /// Read as much as possible into `out`, stopping on a transport
    /// timeout/would-block. Returns the number of bytes appended.
    /// Unlike [`Self::read_exact_into`], a timeout mid-read does not
    /// discard the bytes already consumed — the caller keeps the buffer
    /// and resumes on the next call. This is what makes frame decoding
    /// atomic across polls (HTTP/2).
    ///
    /// A *clean* EOF (the peer closed the connection) is reported as
    /// [`ErrorKind::UnexpectedEof`] rather than "no data yet": the h2
    /// connection layer must be able to distinguish a dead peer from a
    /// silent one, otherwise its poll loops spin forever on a closed
    /// socket (and a pool worker is never released).
    pub fn read_more(&mut self, out: &mut [u8]) -> Result<usize> {
        let mut filled = 0;
        while filled < out.len() {
            match self.fill_buf() {
                Ok([]) => return Err(Error::eof()), // clean EOF
                Ok(b) => {
                    let take = core::cmp::min(out.len() - filled, b.len());
                    out[filled..filled + take].copy_from_slice(&b[..take]);
                    self.consume(take);
                    filled += take;
                }
                Err(e) if e.kind == ErrorKind::Timeout || e.kind == ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(filled)
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        let b = self.fill_buf()?;
        if b.is_empty() {
            return Err(Error::eof());
        }
        let v = b[0];
        self.consume(1);
        Ok(v)
    }

    /// Big-endian u16.
    pub fn read_u16(&mut self) -> Result<u16> {
        let mut b = [0u8; 2];
        self.read_exact_into(&mut b)?;
        Ok(u16::from_be_bytes(b))
    }

    /// Big-endian 24-bit value.
    pub fn read_u24(&mut self) -> Result<u32> {
        let mut b = [0u8; 3];
        self.read_exact_into(&mut b)?;
        Ok(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
    }

    /// Big-endian u32.
    pub fn read_u32(&mut self) -> Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact_into(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }

    /// Big-endian u64.
    pub fn read_u64(&mut self) -> Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact_into(&mut b)?;
        Ok(u64::from_be_bytes(b))
    }

    /// Read up to `max` bytes, stopping at (and including) `delim`.
    /// Returns the bytes read including `delim` (or up to `max`).
    pub fn read_until(&mut self, delim: u8, max: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        self.read_until_into(delim, max, &mut out)?;
        Ok(out)
    }

    /// Read up to `max` bytes, stopping at (and including) `delim`,
    /// appending into a caller-provided buffer (cleared first). Reusing
    /// one buffer across calls keeps steady-state line reading
    /// allocation-free — this is the hot path for HTTP/1.1 header
    /// blocks.
    pub fn read_until_into(&mut self, delim: u8, max: usize, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        loop {
            if out.len() >= max {
                return Err(Error::overflow("read_until exceeded max"));
            }
            let b = self.fill_buf()?;
            if b.is_empty() {
                return Err(Error::eof());
            }
            let room = max - out.len();
            let scan = core::cmp::min(room, b.len());
            match b[..scan].iter().position(|&c| c == delim) {
                Some(i) => {
                    let take = i + 1;
                    out.extend_from_slice(&b[..take]);
                    self.consume(take);
                    return Ok(());
                }
                None => {
                    out.extend_from_slice(&b[..scan]);
                    self.consume(scan);
                }
            }
        }
    }
}

/// Buffered writer that coalesces small writes.
pub struct BufWriter<W> {
    inner: W,
    buf: Vec<u8>,
}

impl<W> BufWriter<W> {
    /// Wrap `inner` with a `cap`-byte buffer.
    pub fn new(inner: W, cap: usize) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(cap),
        }
    }

    /// Access the wrapped writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Number of bytes currently buffered.
    #[inline]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

impl<W: Write> BufWriter<W> {
    /// Consume the wrapper, returning the inner writer (flushes first).
    pub fn into_inner(mut self) -> Result<W> {
        self.flush()?;
        Ok(self.inner)
    }

    /// Write a whole slice, buffering as needed.
    ///
    /// A transport `write` may return a **short count** (a TCP send
    /// buffer can fill mid-write), so the direct path loops until every
    /// byte is out. Returning early on a short write would silently drop
    /// the tail of a request/response — data corruption that only shows
    /// up under real network backpressure.
    pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
        // Large writes bypass the buffer when it is empty.
        if self.buf.is_empty() && data.len() >= self.buf.capacity() {
            return self.write_loop(data);
        }
        if self.buf.len() + data.len() > self.buf.capacity() {
            self.flush()?;
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Write all of `data` to the inner writer, looping over partial
    /// writes. A transport error is fatal (callers drop the connection),
    /// so no retry/duplication can occur.
    fn write_loop(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let n = self.inner.write(data)?;
            if n == 0 {
                return Err(Error::io("write made no progress"));
            }
            data = &data[n.min(data.len())..];
        }
        Ok(())
    }

    /// Write a single byte.
    pub fn write_u8(&mut self, b: u8) -> Result<()> {
        self.write_all(&[b])
    }
}

impl<W: Write> BufWriter<W> {
    /// Flush the internal buffer to the inner writer, looping over
    /// partial writes, then flush the transport.
    pub fn flush(&mut self) -> Result<()> {
        if !self.buf.is_empty() {
            let mut written = 0usize;
            let len = self.buf.len();
            while written < len {
                let n = self.inner.write(&self.buf[written..])?;
                if n == 0 {
                    return Err(Error::io("write made no progress"));
                }
                written += n;
            }
            self.buf.clear();
        }
        self.inner.flush()
    }
}

/// Read-adaptor for an in-memory byte slice (useful for tests and
/// no-transport codecs).
pub struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    /// Wrap a slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl Read for SliceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        let n = core::cmp::min(buf.len(), self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Write-adaptor that appends into a `Vec` (useful for tests).
pub struct VecWriter(pub Vec<u8>);

impl Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A per-connection scratch buffer pool.
///
/// This is the crate's core allocation discipline: every hot decode
/// path (HTTP/1.1 header blocks, bodies, chunk framing) draws its
/// working buffers from a [`Scratch`] owned by the connection instead of
/// the global allocator. After warm-up, steady-state message processing
/// performs **zero allocations** — the buffers are recycled in place.
///
/// Keep one `Scratch` per connection (or per worker) and pass it down to
/// the codec functions that accept `&mut Scratch`.
#[derive(Default)]
pub struct Scratch {
    /// Reused for line-oriented reads ([`BufReader::read_until_into`]).
    line: Vec<u8>,
    /// Reused for body accumulation / chunk framing.
    body: Vec<u8>,
}

impl Scratch {
    /// An empty scratch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the reusable line buffer (cleared; capacity preserved).
    #[inline]
    pub fn line(&mut self) -> &mut Vec<u8> {
        self.line.clear();
        &mut self.line
    }

    /// Borrow the reusable body buffer (cleared; capacity preserved).
    #[inline]
    pub fn body(&mut self) -> &mut Vec<u8> {
        self.body.clear();
        &mut self.body
    }

    /// The line buffer capacity (informational).
    #[inline]
    pub fn line_capacity(&self) -> usize {
        self.line.capacity()
    }

    /// The body buffer capacity (informational).
    #[inline]
    pub fn body_capacity(&self) -> usize {
        self.body.capacity()
    }

    /// Total bytes currently held by the scratch (informational).
    #[inline]
    pub fn held(&self) -> usize {
        self.line.capacity() + self.body.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bufreader_exact_and_until() {
        let mut r = BufReader::new(SliceReader::new(b"hello\r\nworld"), 4);
        assert_eq!(r.read_until(b'\n', 64).unwrap(), b"hello\r\n");
        let rest = r.read_exact(5).unwrap();
        assert_eq!(rest, b"world");
    }

    #[test]
    fn bufwriter_coalesces_and_flushes() {
        let mut w = BufWriter::new(VecWriter(Vec::new()), 8);
        w.write_all(b"ab").unwrap();
        w.write_all(b"cd").unwrap();
        assert_eq!(w.buffered(), 4);
        w.flush().unwrap();
        assert_eq!(w.get_ref().0, b"abcd");
    }

    /// A transport whose `write` returns a short count — the way a real
    /// TCP send buffer fills. `write_all`/`flush` must loop until every
    /// byte is out, or large responses would be silently truncated under
    /// backpressure.
    #[test]
    fn bufwriter_loops_over_partial_writes() {
        struct ShortWriter {
            out: Vec<u8>,
            max_chunk: usize,
        }
        impl Write for ShortWriter {
            fn write(&mut self, buf: &[u8]) -> Result<usize> {
                let n = buf.len().min(self.max_chunk);
                self.out.extend_from_slice(&buf[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> Result<()> {
                Ok(())
            }
        }

        // Direct path (large write ≥ capacity).
        let mut w = BufWriter::new(
            ShortWriter {
                out: Vec::new(),
                max_chunk: 3,
            },
            8,
        );
        w.write_all(&[0x41; 100]).unwrap();
        w.flush().unwrap();
        assert_eq!(w.get_ref().out, [0x41; 100]);

        // Buffered path: small writes coalesce, then flush loops.
        let mut w = BufWriter::new(
            ShortWriter {
                out: Vec::new(),
                max_chunk: 2,
            },
            8,
        );
        for _ in 0..10 {
            w.write_all(b"ab").unwrap();
        }
        w.flush().unwrap();
        assert_eq!(w.get_ref().out, b"abababababababababab");
    }
}
