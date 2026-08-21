//! Fingerprint demo: print the JA3 / JA4 / Chrome HTTP/2 profile that a
//! browser-shaped connection would present. No TLS library is involved —
//! these are the parameters you feed to your own TLS layer.
//!
//! Run with `cargo run --example fingerprint`.

use courierust::courierust_fingerprint::h2::ChromeH2Fingerprint;
use courierust::courierust_fingerprint::{chrome_tls_profile, ja3_hash, ja3_string, ja4};

fn main() {
    let profile = chrome_tls_profile();

    println!("TLS ClientHello profile");
    println!("  protocol           : {:?}", profile.protocol);
    println!("  tls_version        : 0x{:04x}", profile.tls_version);
    println!("  ciphers            : {:?}", profile.ciphers);
    println!("  extensions         : {:?}", profile.extensions);
    println!("  signature_algs     : {:?}", profile.signature_algorithms);
    println!("  groups             : {:?}", profile.groups);
    println!("  alpn               : {:?}", profile.alpn);

    let s = ja3_string(&profile);
    let h = ja3_hash(&profile);
    let j = ja4(&profile);
    println!();
    println!("JA3 string : {s}");
    println!("JA3 hash   : {h}");
    println!("JA4        : {j}");
    println!();
    println!("(pinned records: JA3 {h}, JA4 {j})");

    let fp = ChromeH2Fingerprint::chrome();
    println!();
    println!("Chrome HTTP/2 fingerprint");
    println!("  SETTINGS (wire order):");
    for s in fp.settings_entries() {
        println!("    id=0x{:04x} value={}", s.id, s.value);
    }
    println!(
        "  connection WINDOW_UPDATE: {}",
        fp.connection_window_update
    );
    println!("  header ordering       : pseudo-first, lowercase-sorted");
}
