# courierust_io

Two tiny traits — `Read` and `Write` — plus `BufReader`, `BufWriter`, and a `Scratch` line/header buffer. This is the **seam that keeps the entire protocol core `no_std`**.

## The idea

The protocol layers (h1, h2, h3, hpack) only know about `Read` and `Write`. They don't know what a socket is, what TLS is, or even what `std` is. Any transport that implements these two traits — a TCP stream, a TLS stream, a memory pipe, a test harness — can drive the whole codec stack. That's the entire trick of keeping the core dependency-free: **the codecs are transport-agnostic because the traits are tiny.**

## Why the traits are deliberately small

`std::io::Read`/`Write` drag in `std` and a whole vocabulary of combinators. These traits are:

- `read(&mut self, buf) -> Result<usize>` — byte source, `Ok(0)` on clean EOF;
- `write(&mut self, buf) -> Result<usize>` + `flush()` — byte sink.

That's it. Small enough that adapting any transport takes a few lines, and `no_std` enough that the core never sees `std`.

## What else

- `BufReader` — buffered reads with exact-read and big-endian integer helpers (the h1/h2 codecs need those).
- `BufWriter` — buffered writes.
- `Scratch` — a reusable line buffer so steady-state HTTP/1.1 keep-alive requests do **zero per-request allocation**.

The `&mut T` blanket impls mean you can pass `&mut stream` anywhere a `Read` is expected, which keeps lifetimes sane.

## Usage

```rust
use courierust::courierust_io::{Read, Write};

// Your transport just needs these two impls.
impl Read for MyPipe { /* ... */ }
impl Write for MyPipe { /* ... */ }

// Then any codec in the stack works over it, unchanged.
```
