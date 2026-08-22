//! QUIC v1 packet protection demo (RFC 9001 §5).
//!
//! The single innovation demonstrated here is *self-contained packet
//! protection*: the Initial keys are derived from just the connection ID
//! (HKDF → AES-128-GCM), payloads are AEAD-sealed with the packet number
//! as nonce and the header as AAD, and header protection masks the
//! packet-number bits with a ciphertext sample. No TLS, no sockets — a
//! pure codec you can also run over any external TLS layer.
//!
//! Run with `cargo run --example quic_protection`.

use courierust::courierust_quic::protection::initial_pair;

fn main() -> courierust::Result<()> {
    let dcid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (client_key, server_key) = initial_pair(&dcid)?;
    println!("Initial keys derived from dcid {:02x?}", dcid);
    println!(
        "  cipher suite: 0x{:04x} (TLS_AES_128_GCM_SHA256)",
        client_key.suite()
    );
    println!("  two per-direction keys derived (\"client in\" / \"server in\")");

    let packet_number = 2u64;
    let mut header = vec![0x40];
    header.extend_from_slice(&dcid);
    header.push(packet_number as u8);
    let pn_offset = 1 + dcid.len();

    let plaintext = b"Hello from Courierust QUIC!";
    let sealed = client_key.seal(packet_number, &header, plaintext)?;
    assert_eq!(sealed.len(), plaintext.len() + 16); // 16-byte GCM tag
    println!(
        "client seal: {} plaintext bytes -> {} ciphertext bytes",
        plaintext.len(),
        sealed.len()
    );

    let opened = client_key.open(packet_number, &header, &sealed)?;
    assert_eq!(&opened[..], plaintext);
    println!(
        "server open (client-direction key): {:?}",
        String::from_utf8_lossy(&opened)
    );

    let mut packet = header.clone();
    packet.extend_from_slice(&sealed);
    client_key.protect_header(&mut packet, pn_offset, false)?;
    assert_ne!(packet[..header.len()], header[..], "header must be masked");
    println!(
        "client protect_header -> packet[..{}] = {:02x?}",
        header.len(),
        &packet[..header.len()]
    );

    let mut received = packet.clone();
    let pn_len = client_key.unprotect_header(&mut received, pn_offset, false)?;
    assert_eq!(pn_len, 1);
    assert_eq!(&received[..header.len()], &header[..], "header restored");
    let opened = client_key.open(
        packet_number,
        &received[..header.len()],
        &received[header.len()..],
    )?;
    assert_eq!(&opened[..], plaintext);
    println!("server unprotect_header + open: packet fully restored and verified");

    let server_plaintext = b"pong from the server";
    let server_sealed = server_key.seal(1, &header, server_plaintext)?;
    let opened = server_key.open(1, &header, &server_sealed)?;
    assert_eq!(&opened[..], server_plaintext);
    println!("server->client: sealed + opened with the server-direction key");

    assert!(server_key.open(packet_number, &header, &sealed).is_err());
    assert!(client_key.open(1, &header, &server_sealed).is_err());
    println!("cross-direction open rejected (per-direction keys)");
    Ok(())
}
