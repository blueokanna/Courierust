//! Process-wide outbound socket factory for VPN embedders.
//! Install once before issuing requests; listeners and wake sockets stay local.
use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::OnceLock;
use std::time::Duration;

/// Functions that create outbound sockets according to the embedding application's policy.
///
/// Callbacks must return blocking sockets, apply any interface binding or tunnel
/// protection before connecting, and propagate failures. They must not call this
/// module's `connect` or `udp_bind` functions recursively.
#[derive(Clone, Copy, Debug)]
pub struct SocketFactory {
    /// Connect a TCP socket before any protocol handshake.
    pub tcp: fn(&SocketAddr, Option<Duration>) -> io::Result<TcpStream>,
    /// Bind a UDP socket with the destination available for interface selection.
    pub udp: fn(SocketAddr, SocketAddr) -> io::Result<UdpSocket>,
}
static FACTORY: OnceLock<SocketFactory> = OnceLock::new();

/// Install once before starting clients; replacement is rejected.
pub fn install(factory: SocketFactory) -> Result<(), SocketFactory> {
    FACTORY.set(factory)?;
    network_changed();
    Ok(())
}

/// Connect through the installed factory, or the operating system by default.
pub fn connect(addr: &SocketAddr, timeout: Option<Duration>) -> io::Result<TcpStream> {
    if let Some(factory) = FACTORY.get() {
        return (factory.tcp)(addr, timeout);
    }
    match timeout {
        Some(timeout) => TcpStream::connect_timeout(addr, timeout),
        None => TcpStream::connect(addr),
    }
}

/// Bind an outbound datagram socket, without changing listener sockets.
pub fn udp_bind(bind: SocketAddr, destination: SocketAddr) -> io::Result<UdpSocket> {
    match FACTORY.get() {
        Some(factory) => (factory.udp)(bind, destination),
        None => UdpSocket::bind(bind),
    }
}

static NETWORK_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Current egress configuration; transports use this to expire pooled sockets.
pub fn generation() -> u64 {
    NETWORK_GENERATION.load(std::sync::atomic::Ordering::Acquire)
}
/// Notify transports that newly opened sockets use a different network path.
pub fn network_changed() {
    NETWORK_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}
