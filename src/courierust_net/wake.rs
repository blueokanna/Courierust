//! Portable socket notifications for transport drivers.
use std::net::TcpStream;

/// Create a loopback socket pair used as a self-pipe to wake a poller
/// out of a blocking wait. Pure std, cross-platform (Windows has no
/// native `socketpair`; a loopback pair is the portable equivalent).
pub(crate) fn wakeup_pair() -> std::io::Result<(TcpStream, TcpStream)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let writer = TcpStream::connect(listener.local_addr()?)?;
    let (reader, _) = listener.accept()?;
    reader.set_nonblocking(true)?;
    writer.set_nonblocking(true)?;
    reader.set_nodelay(true)?;
    writer.set_nodelay(true)?;
    Ok((reader, writer))
}

/// Write one byte to the wake pipe (best-effort; a full or failed write
/// only loses an optimization, never correctness).
pub(crate) fn wake_nudge(w: &TcpStream) {
    let mut s: &TcpStream = w;
    loop {
        match std::io::Write::write(&mut s, &[1]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            _ => break,
        }
    }
}

/// Drain all pending wake bytes so the pipe cannot fire spuriously.
pub(crate) fn drain_wake(r: &TcpStream) {
    let mut buf = [0u8; 64];
    loop {
        let mut s: &TcpStream = r;
        match std::io::Read::read(&mut s, &mut buf) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}
