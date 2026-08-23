//! UDP socket creation.
//!
//! A server binds an HTTP/3 UDP listener on the same numeric port as its
//! TCP listener (QUIC uses the same authority as the HTTPS URL). On
//! macOS (BSD), `bind(2)` rejects a different-protocol socket on a port
//! already bound by a TCP socket unless the second socket has
//! `SO_REUSEADDR` set, so the UDP socket must be created with the option
//! applied *before* binding. Linux and Windows share a numeric port
//! freely and use a plain [`UdpSocket::bind`].

#![allow(unsafe_code)]

use std::io;
use std::net::{SocketAddr, UdpSocket};

/// Bind a UDP socket to `addr`. On macOS, `SO_REUSEADDR` is applied
/// before the bind so the socket may share its numeric port with the
/// server's TCP listener (BSD requires it for cross-protocol sharing);
/// every other platform uses a plain [`UdpSocket::bind`].
pub(crate) fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    #[cfg(target_os = "macos")]
    {
        macos::bind_udp(addr)
    }
    #[cfg(not(target_os = "macos"))]
    {
        UdpSocket::bind(addr)
    }
}

/// macOS-specific path: create the socket, set `SO_REUSEADDR`, bind, and
/// hand the descriptor to a [`UdpSocket`]. Confined to this submodule so
/// the `unsafe` FFI never leaks into the crate's deny-unsafe modules.
#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::mem::size_of;
    use std::os::unix::io::FromRawFd;

    type CInt = i32;
    type Socklen = u32;

    // macOS / BSD socket constants.
    const AF_INET: CInt = 2;
    const AF_INET6: CInt = 30;
    const SOCK_DGRAM: CInt = 2;
    const SOL_SOCKET: CInt = 0xffff;
    const SO_REUSEADDR: CInt = 0x0004;

    // macOS sockaddr_in / sockaddr_in6 (both start with a 1-byte length
    // followed by the 1-byte family; `sin_port` is network byte order).
    #[repr(C)]
    struct SockaddrIn {
        len: u8,
        family: u8,
        port: u16,
        addr: [u8; 4],
        zero: [u8; 8],
    }

    #[repr(C)]
    struct SockaddrIn6 {
        len: u8,
        family: u8,
        port: u16,
        flowinfo: u32,
        addr: [u8; 16],
        scope_id: u32,
    }

    /// A buffer large enough for either sockaddr, 8-aligned so the
    /// unaligned-byte-free structs can be written into it.
    #[repr(C, align(8))]
    struct SockaddrStorage {
        bytes: [u8; 28],
    }

    extern "C" {
        fn socket(domain: CInt, kind: CInt, protocol: CInt) -> CInt;
        fn setsockopt(fd: CInt, level: CInt, name: CInt, value: *const u8, len: Socklen) -> CInt;
        fn bind(fd: CInt, addr: *const u8, len: Socklen) -> CInt;
        fn close(fd: CInt) -> CInt;
    }

    pub(super) fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
        let family = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
        // SAFETY: `socket(2)` has no preconditions; a negative return is
        // the only failure signal and becomes `io::Error`.
        let fd = unsafe { socket(family, SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: CInt = 1;
        // SAFETY: `setsockopt` on a descriptor just created by `socket(2)`.
        let rc = unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_REUSEADDR,
                &one as *const CInt as *const u8,
                size_of::<CInt>() as Socklen,
            )
        };
        if rc != 0 {
            // SAFETY: `close` on the descriptor we own.
            unsafe { close(fd) };
            return Err(io::Error::last_os_error());
        }
        let mut storage = SockaddrStorage { bytes: [0u8; 28] };
        let (ptr, len) = sockaddr_of(addr, &mut storage);
        // SAFETY: `ptr` points at a correctly filled sockaddr of `len` bytes.
        let rc = unsafe { bind(fd, ptr, len) };
        if rc != 0 {
            unsafe { close(fd) };
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, owned, bound UDP descriptor with no
        // other owner; wrapping it transfers ownership to the `UdpSocket`.
        Ok(unsafe { UdpSocket::from_raw_fd(fd) })
    }

    /// Serialize `addr` into `storage` and return a pointer/length pair
    /// suitable for `bind(2)`.
    fn sockaddr_of(addr: SocketAddr, storage: &mut SockaddrStorage) -> (*const u8, Socklen) {
        match addr {
            SocketAddr::V4(v4) => {
                let sa = SockaddrIn {
                    len: size_of::<SockaddrIn>() as u8,
                    family: AF_INET as u8,
                    port: v4.port().to_be(),
                    addr: v4.ip().octets(),
                    zero: [0u8; 8],
                };
                // SAFETY: `storage` is 28 bytes and 8-aligned; `SockaddrIn`
                // is 16 bytes with strictly weaker alignment.
                unsafe {
                    std::ptr::write(storage as *mut SockaddrStorage as *mut SockaddrIn, sa);
                }
                (
                    storage as *const SockaddrStorage as *const u8,
                    size_of::<SockaddrIn>() as Socklen,
                )
            }
            SocketAddr::V6(v6) => {
                let sa = SockaddrIn6 {
                    len: size_of::<SockaddrIn6>() as u8,
                    family: AF_INET6 as u8,
                    port: v6.port().to_be(),
                    flowinfo: 0,
                    addr: v6.ip().octets(),
                    scope_id: v6.scope_id(),
                };
                // SAFETY: as above; `SockaddrIn6` is 28 bytes with weaker
                // alignment than the 8-aligned storage.
                unsafe {
                    std::ptr::write(storage as *mut SockaddrStorage as *mut SockaddrIn6, sa);
                }
                (
                    storage as *const SockaddrStorage as *const u8,
                    size_of::<SockaddrIn6>() as Socklen,
                )
            }
        }
    }
}
