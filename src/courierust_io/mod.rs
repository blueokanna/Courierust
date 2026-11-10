//! Minimal, dependency-free `Read`/`Write` traits plus buffered adapters.
//!
//! The traits are intentionally tiny so any transport (TCP, TLS stream,
//! memory pipe, ...) can be adapted in a few lines, keeping the whole
//! protocol core `no_std`-capable.

use crate::courierust_error::{Error, ErrorKind, Result};
use alloc::vec::Vec;

/// A byte source. Returns `Ok(0)` on clean EOF.
pub trait Read {
    /// Read into `buf`, returning a count no greater than `buf.len()`.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

/// A byte sink.
pub trait Write {
    /// Write as many bytes as possible; return a count no greater than `buf.len()`.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Flush any buffered output.
    fn flush(&mut self) -> Result<()>;

    /// Write the whole buffer, looping over short writes.
    ///
    /// A transport error (including `WouldBlock` on a non-blocking
    /// socket) aborts the loop and is propagated as-is: the caller must
    /// be able to tell “nothing more fit” from “the peer vanished”,
    /// which is exactly the difference between parking and closing.
    fn write_all(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let n = self.write(data)?;
            if n == 0 {
                return Err(Error::io("write made no progress"));
            }
            if n > data.len() {
                return Err(Error::io("writer returned a count larger than its input"));
            }
            data = &data[n..];
        }
        Ok(())
    }
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
    /// Wrap `inner` with a buffer of at least one byte.
    pub fn new(inner: R, cap: usize) -> Self {
        Self {
            inner,
            buf: vec![0u8; cap.max(1)],
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
    /// be buffered behind the `101` response). Existing unread bytes
    /// precede the seed; the buffer grows rather than discarding input.
    pub fn seed(&mut self, data: &[u8]) {
        let held = self.buffered();
        let total = held.checked_add(data.len()).expect("buffer size overflow");
        self.buf.copy_within(self.pos..self.cap, 0);
        self.buf.resize(self.buf.len().max(total), 0);
        self.buf[held..total].copy_from_slice(data);
        self.pos = 0;
        self.cap = total;
    }

    /// Grow the buffer to at least `cap` bytes, preserving whatever is
    /// still buffered.
    ///
    /// Used when a connection changes protocol (an HTTP/1.1 request that
    /// upgrades to WebSocket): the framing that follows is read in much
    /// larger chunks than request headers, and re-allocating the reader
    /// would throw away bytes the parser already read past the handshake.
    pub fn ensure_capacity(&mut self, cap: usize) {
        if cap <= self.buf.len() {
            return;
        }
        let held = self.cap - self.pos;
        self.buf.copy_within(self.pos..self.cap, 0);
        self.buf.resize(cap, 0);
        self.pos = 0;
        self.cap = held;
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
            if n > self.buf.len() {
                return Err(Error::io("reader returned a count larger than its buffer"));
            }
            self.cap = n;
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    /// Mark `n` buffered bytes as consumed.
    /// Panics if `n` exceeds the number of buffered bytes.
    pub fn consume(&mut self, n: usize) {
        assert!(
            n <= self.cap - self.pos,
            "consumed more bytes than buffered"
        );
        self.pos += n;
        if self.pos == self.cap {
            self.pos = 0;
            self.cap = 0;
        }
    }

    /// Read exactly `n` bytes (fails with `UnexpectedEof` on short read).
    pub fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.try_reserve_exact(n)
            .map_err(|_| Error::new(ErrorKind::Overflow))?;
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
            if self.buffered() == 0 && out.len() - filled >= self.buf.len() {
                filled += self.read_direct(&mut out[filled..])?;
                continue;
            }
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

    /// Read as much as possible into `out`, stopping on timeout/
    /// would-block; a mid-read timeout keeps consumed bytes for the next
    /// call (atomic frame decode across polls). Clean EOF is reported as
    /// [`ErrorKind::UnexpectedEof`] so the h2 layer can tell a dead peer
    /// from a silent one (otherwise poll loops spin on a closed socket).
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

    /// Read up to `out.len()` bytes, serving from the internal buffer when
    /// it holds data and otherwise reading **straight into `out`**.
    ///
    /// Unlike [`BufReader::read_more`] this makes exactly one transport
    /// read per call and never copies through the internal buffer, which
    /// is what a protocol layer wants when it has already committed to
    /// placing the next bulk of bytes somewhere: a frame payload or a
    /// request body can land in its destination on the first attempt.
    ///
    /// Errors are returned as the transport reported them (`WouldBlock`
    /// and `Timeout` included, so a caller can distinguish "no data yet"
    /// from "this connection is gone"); a clean EOF is
    /// [`ErrorKind::UnexpectedEof`].
    pub fn read_direct(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos < self.cap {
            let take = core::cmp::min(out.len(), self.cap - self.pos);
            out[..take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.consume(take);
            return Ok(take);
        }
        match self.inner.read(out) {
            Ok(0) => Err(Error::eof()),
            Ok(n) if n > out.len() => {
                Err(Error::io("reader returned a count larger than its buffer"))
            }
            other => other,
        }
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
        self.read_until_into_with(delim, max, out, || Ok(()))
    }

    /// Like [`Self::read_until_into`], but calls `before_read` immediately
    /// before each transport read. Protocol servers use this to keep an
    /// absolute request-header deadline across a peer that drips bytes.
    pub(crate) fn read_until_into_with<F>(
        &mut self,
        delim: u8,
        max: usize,
        out: &mut Vec<u8>,
        mut before_read: F,
    ) -> Result<()>
    where
        F: FnMut() -> Result<()>,
    {
        out.clear();
        loop {
            if out.len() >= max {
                return Err(Error::overflow("read_until exceeded max"));
            }
            if self.buffered() == 0 {
                before_read()?;
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
///
/// A transport that refuses bytes — a socket send buffer that is full, a
/// `WouldBlock` from a non-blocking one — must not lose them and must
/// not see them twice. The rule here is therefore: bytes leave the
/// buffer exactly as the inner writer takes them, and whatever it
/// refuses stays for the next [`BufWriter::flush`]. Re-flushing after a
/// refusal resumes at the tail, so a driver that parks a connection and
/// retries later keeps the byte stream exact.
pub struct BufWriter<W> {
    inner: W,
    buf: Vec<u8>,
    /// Accepted prefix retained until the pending tail is fully drained.
    pos: usize,
    /// Bytes the inner writer has accepted since construction. Lets a
    /// driver tell "the peer took some of it" from "everything is
    /// parked", which is what decides whether a stalled connection is
    /// still making progress.
    written: u64,
}

impl<W> BufWriter<W> {
    /// Wrap `inner` with a `cap`-byte buffer.
    pub fn new(inner: W, cap: usize) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(cap),
            pos: 0,
            written: 0,
        }
    }

    /// Access the wrapped writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Total bytes the inner writer has accepted.
    #[inline]
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Number of bytes currently buffered.
    #[inline]
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }
}

impl<W: Write> BufWriter<W> {
    /// Consume the wrapper, returning the inner writer (flushes first).
    pub fn into_inner(mut self) -> Result<W> {
        self.flush()?;
        Ok(self.inner)
    }

    /// Write a whole slice, buffering as needed. The direct path loops
    /// over short writes (a TCP send buffer can fill mid-write; returning
    /// early would silently truncate the response).
    pub fn write_all(&mut self, data: &[u8]) -> Result<()> {
        if self.buf.is_empty() && data.len() >= self.buf.capacity() {
            return self.write_loop(data);
        }
        if data.len() > self.buf.capacity() - self.buffered() {
            self.flush()?;
        }
        // Compact only when appending, never on repeated backpressure polls.
        if self.pos != 0 {
            let pending = self.buffered();
            self.buf.copy_within(self.pos.., 0);
            self.buf.truncate(pending);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Write all of `data` to the inner writer, looping over partial
    /// writes. On an error the unwritten tail is retained, so the retry
    /// a caller makes after a refused (non-blocking) write resumes
    /// mid-slice instead of restarting it.
    fn write_loop(&mut self, data: &[u8]) -> Result<()> {
        let mut written = 0usize;
        let outcome = loop {
            if written == data.len() {
                break Ok(());
            }
            match self.inner.write(&data[written..]) {
                Ok(0) => break Err(Error::io("write made no progress")),
                Ok(n) => {
                    if n > data.len() - written {
                        break Err(Error::io("writer returned a count larger than its input"));
                    }
                    written += n;
                    self.written = self.written.saturating_add(n as u64);
                }
                Err(e) => break Err(e),
            }
        };
        if let Err(e) = outcome {
            self.buf.extend_from_slice(&data[written..]);
            return Err(e);
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
    ///
    /// Bytes the inner writer takes leave the buffer as they go, so a
    /// flush that stops half-way retries only its tail: clearing on
    /// success alone would resend the prefix and corrupt the stream.
    pub fn flush(&mut self) -> Result<()> {
        while self.pos < self.buf.len() {
            let n = self.inner.write(&self.buf[self.pos..])?;
            if n == 0 {
                return Err(Error::io("write made no progress"));
            }
            if n > self.buffered() {
                return Err(Error::io("writer returned a count larger than its input"));
            }
            self.pos += n;
            self.written = self.written.saturating_add(n as u64);
        }
        self.buf.clear();
        self.pos = 0;
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

/// Per-connection scratch buffers: hot decode paths (header blocks,
/// bodies, chunk framing) recycle these instead of the global allocator,
/// so steady-state message processing performs zero allocations. Keep
/// one per connection/worker and pass it to the codec functions.
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

    struct InvalidCount;
    impl Read for InvalidCount {
        fn read(&mut self, _: &mut [u8]) -> Result<usize> {
            Ok(usize::MAX)
        }
    }
    impl Write for InvalidCount {
        fn write(&mut self, _: &[u8]) -> Result<usize> {
            Ok(usize::MAX)
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn invalid_adapter_counts_are_errors_without_corrupting_buffer_state() {
        let mut reader = BufReader::new(InvalidCount, 8);
        assert_eq!(reader.fill_buf().unwrap_err().kind, ErrorKind::Io);
        assert_eq!(reader.buffered(), 0);
        assert_eq!(
            reader.read_direct(&mut [0; 8]).unwrap_err().kind,
            ErrorKind::Io
        );
        assert_eq!(
            Write::write_all(&mut InvalidCount, b"x").unwrap_err().kind,
            ErrorKind::Io
        );
        let mut writer = BufWriter::new(InvalidCount, 8);
        writer.write_all(b"data").unwrap();
        assert_eq!(writer.flush().unwrap_err().kind, ErrorKind::Io);
        assert_eq!(writer.buffered(), 4);
        assert_eq!(writer.written(), 0);
        let mut direct = BufWriter::new(InvalidCount, 0);
        assert_eq!(direct.write_all(b"data").unwrap_err().kind, ErrorKind::Io);
        assert_eq!(direct.buffered(), 4);
        assert_eq!(direct.written(), 0);
    }

    #[test]
    fn impossible_read_capacity_returns_an_error() {
        let mut reader = BufReader::new(SliceReader::new(b""), 8);
        assert_eq!(
            reader.read_exact(usize::MAX).unwrap_err().kind,
            ErrorKind::Overflow
        );
    }

    #[test]
    fn exact_bulk_reads_bypass_scratch_but_preserve_seeded_bytes() {
        struct RecordingReader {
            data: SliceReader<'static>,
            sizes: Vec<usize>,
        }
        impl Read for RecordingReader {
            fn read(&mut self, out: &mut [u8]) -> Result<usize> {
                self.sizes.push(out.len());
                self.data.read(out)
            }
        }
        let mut reader = BufReader::new(
            RecordingReader {
                data: SliceReader::new(b"0123456789"),
                sizes: Vec::new(),
            },
            4,
        );
        reader.seed(b"ab");
        let mut out = [0; 12];
        reader.read_exact_into(&mut out).unwrap();
        assert_eq!(&out, b"ab0123456789");
        assert_eq!(reader.get_ref().sizes, [10]);
    }

    #[test]
    fn repeated_backpressure_keeps_the_tail_in_place_and_in_order() {
        struct Drip {
            out: Vec<u8>,
            blocked: bool,
        }
        impl Write for Drip {
            fn write(&mut self, data: &[u8]) -> Result<usize> {
                self.blocked = !self.blocked;
                if !self.blocked {
                    return Err(Error::new(ErrorKind::WouldBlock));
                }
                self.out.push(data[0]);
                Ok(1)
            }
            fn flush(&mut self) -> Result<()> {
                Ok(())
            }
        }
        let input: Vec<_> = (0..=255).collect();
        let mut writer = BufWriter::new(
            Drip {
                out: Vec::new(),
                blocked: false,
            },
            512,
        );
        writer.write_all(&input).unwrap();
        for accepted in 1..input.len() {
            assert_eq!(writer.flush().unwrap_err().kind, ErrorKind::WouldBlock);
            assert_eq!(writer.buffered(), input.len() - accepted);
            assert_eq!(writer.written(), accepted as u64);
            // Previously every blocked flush shifted this entire tail.
            assert_eq!(writer.buf, input);
            assert_eq!(writer.get_ref().out, input[..accepted]);
        }
        writer.flush().unwrap();
        assert_eq!(writer.get_ref().out, input);
        assert_eq!(writer.buffered(), 0);
    }

    #[test]
    fn write_counter_saturates_without_wrapping() {
        let mut writer = BufWriter::new(VecWriter(Vec::new()), 8);
        writer.written = u64::MAX - 1;
        writer.write_all(b"abc").unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.written(), u64::MAX);
        assert_eq!(writer.get_ref().0, b"abc");
    }

    #[test]
    fn zero_capacity_reader_does_not_report_false_eof() {
        let mut reader = BufReader::new(SliceReader::new(b"data"), 0);
        assert_eq!(reader.read_exact(4).unwrap(), b"data");
    }

    #[test]
    fn protocol_handoff_preserves_every_seeded_byte() {
        let mut reader = BufReader::new(SliceReader::new(b"tail"), 2);
        reader.seed(b"abcdef");
        assert_eq!(reader.read_exact(2).unwrap(), b"ab");
        reader.seed(b"gh");
        assert_eq!(reader.read_exact(10).unwrap(), b"cdefghtail");
    }

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

    /// A transport that keeps what it took, then refuses once — the shape
    /// of a socket send buffer that fills mid-frame. The refused bytes
    /// have to stay in the buffer, and the retry must resume there: a
    /// flush that restarts from the head would send the prefix twice.
    #[test]
    fn bufwriter_resumes_after_refused_write() {
        struct Refusing {
            out: Vec<u8>,
            budget: usize,
            calls: usize,
            refuse_on_call: usize,
        }
        impl Write for Refusing {
            fn write(&mut self, buf: &[u8]) -> Result<usize> {
                self.calls += 1;
                if self.calls == self.refuse_on_call {
                    return Err(Error::new(ErrorKind::WouldBlock));
                }
                let n = buf.len().min(self.budget);
                self.out.extend_from_slice(&buf[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> Result<()> {
                Ok(())
            }
        }

        // Buffered path: the flush is triggered by a write that would
        // overrun the buffer, which is refused after it has taken its
        // first chunk.
        let mut w = BufWriter::new(
            Refusing {
                out: Vec::new(),
                budget: 4,
                calls: 0,
                refuse_on_call: 2,
            },
            8,
        );
        w.write_all(b"aaaa").unwrap();
        w.write_all(b"bbbb").unwrap();
        let err = w.write_all(b"cc").unwrap_err();
        assert_eq!(err.kind, ErrorKind::WouldBlock);
        assert_eq!(w.get_ref().out, b"aaaa", "only what the peer took is gone");
        assert_eq!(w.buffered(), 4, "the refused half stays buffered");
        w.write_all(b"cc").unwrap();
        w.flush().unwrap();
        assert_eq!(w.get_ref().out, b"aaaabbbbcc");

        // Direct path: a large slice is written straight through, so the
        // unwritten tail has to be retained by the writer itself.
        let mut w = BufWriter::new(
            Refusing {
                out: Vec::new(),
                budget: 3,
                calls: 0,
                refuse_on_call: 3,
            },
            4,
        );
        let err = w.write_all(&[0x41; 10]).unwrap_err();
        assert_eq!(err.kind, ErrorKind::WouldBlock);
        assert_eq!(w.get_ref().out.len(), 6);
        assert_eq!(w.buffered(), 4);
        w.flush().unwrap();
        assert_eq!(
            w.get_ref().out,
            [0x41; 10],
            "the stream is byte-exact after the retry"
        );
        assert_eq!(w.buffered(), 0);
    }
}
