//! Loading the operating system's trust anchors.
//!
//! A client cannot verify a public HTTPS server without the same roots the
//! platform's browsers use, and vendoring a copy of them means shipping a
//! file that expires. So the roots are read from the platform instead:
//!
//! * **Windows** — `CertOpenSystemStoreW("ROOT")`, the store the OS and
//!   every browser on the machine already maintain, enumerated with
//!   `CertEnumCertificatesInStore`. Certificates an administrator has
//!   explicitly distrusted carry a `CERT_DISALLOWED` property and are
//!   skipped: being present in the store is not the same as being trusted.
//! * **Unix** — the distribution's PEM bundle, then the hashed
//!   certificate directory as a fallback, which is what a container image
//!   that ships only the latter needs.
//!
//! [`RootStore`] stays the single owner of "what is trusted"; this module
//! only knows where a platform keeps that answer.

#![allow(unsafe_code)]

use crate::courierust_tls::x509::RootStore;
use crate::courierust_tls::{TlsError, TlsResult};

/// Load the platform's root certificates into `store`, returning how many
/// were added.
///
/// `Ok(0)` is not an outcome: no supported platform has zero trust
/// anchors, so a store that cannot be read is an `Err` naming what was
/// tried. The alternative — a silently empty store — turns every
/// `https://` into a certificate failure with no explanation, which is the
/// single most common way a from-scratch TLS client is wired up wrong.
pub fn load_into(store: &mut RootStore) -> TlsResult<usize> {
    platform_load(store)
}

/// A [`RootStore`] holding the platform's trust anchors.
pub fn load() -> TlsResult<RootStore> {
    let mut store = RootStore::new();
    load_into(&mut store)?;
    Ok(store)
}

#[cfg(windows)]
fn platform_load(store: &mut RootStore) -> TlsResult<usize> {
    use core::ffi::c_void;
    use core::ptr;

    /// `CERT_CONTEXT` (`wincrypt.h`). Only the encoding and the encoded
    /// bytes are read, but every field is carried: the API hands back a
    /// pointer into its own allocation, and a struct whose layout is one
    /// field short would make the reads below land on the wrong bytes.
    #[repr(C)]
    struct CertContext {
        encoding_type: u32,
        pb_cert_encoded: *const u8,
        cb_cert_encoded: u32,
        p_cert_info: *const c_void,
        h_cert_store: *mut c_void,
    }

    /// `CERT_DISALLOWED_PROP_ID` (`wincrypt.h`).
    const CERT_DISALLOWED_PROP_ID: u32 = 33;

    #[link(name = "crypt32")]
    extern "system" {
        fn CertOpenSystemStoreW(provider: usize, name: *const u16) -> *mut c_void;
        fn CertEnumCertificatesInStore(
            store: *mut c_void,
            previous: *const CertContext,
        ) -> *const CertContext;
        fn CertGetCertificateContextProperty(
            context: *const CertContext,
            property: u32,
            data: *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn CertCloseStore(store: *mut c_void, flags: u32) -> i32;
    }

    /// `"ROOT"` as UTF-16, NUL-terminated.
    const STORE_NAME: [u16; 5] = [b'R' as u16, b'O' as u16, b'O' as u16, b'T' as u16, 0];

    // SAFETY: the store handle is created here and closed before the
    // function returns, so it never escapes. `CertEnumCertificatesInStore`
    // frees the previously returned context on each call, so each pointer
    // is dereferenced and its certificate copied into an owned `Vec`
    // *before* the next call. None of the raw pointers outlive the block.
    unsafe {
        // The first parameter is documented as unused (pass NULL); passing
        // a legacy CSP handle here is what would break under a 64-bit host.
        let handle = CertOpenSystemStoreW(0, STORE_NAME.as_ptr());
        if handle.is_null() {
            return Err(TlsError::Protocol(
                "cannot open the Windows ROOT certificate store".into(),
            ));
        }

        let mut previous: *const CertContext = ptr::null();
        let mut added = 0usize;
        loop {
            previous = CertEnumCertificatesInStore(handle, previous);
            if previous.is_null() {
                break;
            }
            let context = &*previous;

            // A certificate the administrator removed from the trusted set
            // is still enumerable; `CERT_DISALLOWED` is how the store marks
            // it. Skipping these is the difference between "present" and
            // "trusted".
            let mut probe = 0u8;
            let mut probe_len = 1u32;
            let disallowed = CertGetCertificateContextProperty(
                previous,
                CERT_DISALLOWED_PROP_ID,
                &mut probe as *mut u8 as *mut c_void,
                &mut probe_len,
            );
            if disallowed != 0 {
                continue;
            }

            if !context.pb_cert_encoded.is_null() && context.cb_cert_encoded > 0 {
                let der = core::slice::from_raw_parts(
                    context.pb_cert_encoded,
                    context.cb_cert_encoded as usize,
                );
                store.add_der(der.to_vec());
                added += 1;
            }
        }

        CertCloseStore(handle, 0);
        Ok(added)
    }
}

#[cfg(unix)]
fn platform_load(store: &mut RootStore) -> TlsResult<usize> {
    /// The bundle locations a system administrator would expect to win, in
    /// order: Debian/Ubuntu/Arch, RHEL/Fedora, openSUSE, then the path
    /// Alpine and the BSDs use.
    const BUNDLES: [&str; 4] = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
    ];

    let mut tried = Vec::new();
    for path in BUNDLES {
        match std::fs::read_to_string(path) {
            Ok(pem) => match store.add_pem(&pem) {
                Ok(n) if n > 0 => return Ok(n),
                Ok(_) => tried.push(format!("{path} (contains no certificates)")),
                Err(e) => tried.push(format!("{path} ({e})")),
            },
            Err(e) => tried.push(format!("{path} ({e})")),
        }
    }

    // Debian's `ca-certificates` also publishes one symlink per root under
    // this directory. A slim container that ships only that directory —
    // or a host where the bundle is a dangling symlink — still works.
    if let Ok(entries) = std::fs::read_dir("/etc/ssl/certs") {
        let mut added = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            let is_pem = matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("pem" | "crt")
            );
            if !is_pem {
                continue;
            }
            if let Ok(pem) = std::fs::read_to_string(&path) {
                added += store.add_pem(&pem).unwrap_or(0);
            }
        }
        if added > 0 {
            return Ok(added);
        }
    }

    Err(TlsError::Protocol(format!(
        "no system trust store could be read: {}",
        tried.join("; ")
    )))
}

#[cfg(not(any(windows, unix)))]
fn platform_load(_store: &mut RootStore) -> TlsResult<usize> {
    Err(TlsError::Protocol(
        "this platform has no known trust store; load a PEM bundle with RootStore::add_pem".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loader must either produce a usable store or say why not. A
    /// silent zero is the one outcome worth failing on, and every root it
    /// does return has to be a real DER certificate — a `#repr` mistake in
    /// the Windows struct would show up here as garbage bytes rather than
    /// as a confusing verification failure later.
    #[test]
    fn the_system_store_loads_or_explains_itself() {
        let mut store = RootStore::new();
        match load_into(&mut store) {
            Ok(n) => {
                println!("loaded {n} system trust anchors");
                assert!(n > 0, "a successful load cannot add zero roots");
                assert_eq!(store.len(), n, "the count must match the store");
                for root in store.roots() {
                    assert_eq!(
                        root.der.first().copied(),
                        Some(0x30),
                        "a root must start with a DER SEQUENCE"
                    );
                    assert!(
                        root.der.len() > 64,
                        "a root of {} bytes is not a certificate",
                        root.der.len()
                    );
                }
            }
            Err(e) => {
                // A build host without a trust store is a legitimate
                // deployment shape (a scratch image that adds its own
                // bundle), so this is reported, not failed.
                eprintln!("no system trust store on this host: {e}");
            }
        }
    }
}
