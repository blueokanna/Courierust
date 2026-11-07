use super::*;
use crate::courierust_io::{Read, SliceReader, VecWriter};

fn keys() -> key_schedule::TrafficKeys {
    key_schedule::TrafficKeys {
        key: [0x42; 32],
        iv: [0x24; 12],
    }
}

fn stream<R: Read>(reader: R, version: TlsVersion) -> TlsStream<R, VecWriter> {
    let suite = key_schedule::CipherSuite::TlsAes128GcmSha256;
    TlsStream {
        io: TlsIo::new(reader, VecWriter(Vec::new())),
        version,
        suite,
        suite12: Some(tls12::Tls12Suite::EcdheRsaAes128GcmSha256),
        write_keys: keys(),
        read_keys: keys(),
        negotiated_alpn: None,
        server_name: None,
        peer_certificate: None,
        closed: false,
        pending: Vec::new(),
        pending_pos: 0,
        rec: RecState::Idle,
        resumption_master: None,
        resumed: false,
        session_store: None,
        hostname: String::new(),
        now: 0,
        write_app_secret: None,
        read_app_secret: None,
        pending_key_update: false,
        write_records: 0,
        key_use_limit: key_use_limit(suite),
        key_read_gen: 0,
        key_write_gen: 0,
    }
}

fn record_bytes(version: TlsVersion, records: &[(u8, &[u8])]) -> Vec<u8> {
    let mut sender = stream(SliceReader::new(&[]), version);
    for &(kind, bytes) in records {
        match version {
            TlsVersion::Tls13 => sender
                .io
                .write_encrypted_record(sender.suite, &keys(), kind, bytes)
                .unwrap(),
            TlsVersion::Tls12 => sender
                .io
                .write_tls12_record(sender.suite12.unwrap(), &keys(), kind, bytes)
                .unwrap(),
        }
    }
    sender.io.writer.into_inner().unwrap().0
}

#[test]
fn large_application_writes_fragment_at_the_plaintext_limit() {
    let payload = (0..65_537).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let mut sender = stream(SliceReader::new(&[]), version);
        sender.write_all(&payload).unwrap();
        sender.close_notify().unwrap();
        let wire = sender.io.writer.into_inner().unwrap().0;
        let mut receiver = stream(SliceReader::new(&wire), version);
        let mut received = Vec::new();
        let mut records = 0;
        loop {
            let fragment = receiver.read_record().unwrap();
            if fragment.is_empty() {
                break;
            }
            assert!(fragment.len() <= 16_384);
            records += 1;
            received.extend_from_slice(&fragment);
        }
        assert_eq!(records, 5);
        assert_eq!(received, payload);
    }
}

#[test]
fn a_single_write_cannot_exceed_the_tls13_key_budget() {
    let mut sender = stream(SliceReader::new(&[]), TlsVersion::Tls13);
    sender.key_use_limit = 1;
    // This fixture has no application traffic secret to derive a new key.
    // The second record must fail instead of exceeding the first key's budget.
    assert!(sender.write_all(&vec![7; 32_768]).is_err());
    assert_eq!(sender.write_records, 1);
    assert!(sender.write_all(b"retry").is_err());
    assert!(sender.read_record().is_err());
}

#[test]
fn every_truncated_record_is_an_error_including_an_empty_header() {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let wire = record_bytes(version, &[(record::CONTENT_APPLICATION_DATA, b"payload")]);
        for end in 0..wire.len() {
            let mut tls = stream(SliceReader::new(&wire[..end]), version);
            assert!(
                matches!(tls.read_record(), Err(TlsError::UnexpectedEof)),
                "{version:?}: truncated at {end}"
            );
            assert!(
                tls.read_record().is_err(),
                "a fatal read must not become clean EOF"
            );
            assert!(tls.write_all(b"after failure").is_err());
            assert!(crate::courierust_io::Write::flush(&mut tls).is_err());
        }
    }
}

#[test]
fn only_authenticated_close_notify_ends_the_stream_cleanly() {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let wire = record_bytes(version, &[(record::CONTENT_ALERT, &[1, 0])]);
        let mut tls = stream(SliceReader::new(&wire), version);
        assert!(tls.read_record().unwrap().is_empty());
        assert!(tls.read_record().unwrap().is_empty());
        assert!(
            tls.has_pending_read(),
            "a closed TLS stream cannot enter an HTTP pool"
        );
    }
}

#[test]
fn an_oversized_close_notify_is_rejected() {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let wire = record_bytes(version, &[(record::CONTENT_ALERT, &[1, 0, 0])]);
        let mut tls = stream(SliceReader::new(&wire), version);
        assert!(matches!(tls.read_record(), Err(TlsError::Protocol(_))));
    }
}

#[test]
fn authentication_failure_cannot_be_skipped_to_read_a_later_record() {
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let first = record_bytes(version, &[(record::CONTENT_APPLICATION_DATA, b"first")]);
        let mut wire = record_bytes(
            version,
            &[
                (record::CONTENT_APPLICATION_DATA, b"first"),
                (record::CONTENT_APPLICATION_DATA, b"second"),
            ],
        );
        wire[first.len() - 1] ^= 1;
        let mut tls = stream(SliceReader::new(&wire), version);
        assert!(tls.read_record().is_err());
        assert!(
            tls.read_record().is_err(),
            "a bad tag must terminate the connection"
        );
    }
}

#[test]
fn an_empty_read_never_touches_the_transport() {
    struct Unreadable;
    impl Read for Unreadable {
        fn read(&mut self, _: &mut [u8]) -> crate::Result<usize> {
            panic!("zero-length TLS read reached the transport")
        }
    }
    let mut tls = stream(Unreadable, TlsVersion::Tls13);
    assert_eq!(tls.read(&mut []).unwrap(), 0);
}

#[test]
fn a_timed_out_read_resumes_at_every_record_boundary() {
    struct PauseOnce<'a> {
        data: &'a [u8],
        position: usize,
        pause_at: usize,
        paused: bool,
    }
    impl Read for PauseOnce<'_> {
        fn read(&mut self, output: &mut [u8]) -> crate::Result<usize> {
            if self.position == self.pause_at && !self.paused {
                self.paused = true;
                return Err(crate::Error::new(crate::ErrorKind::WouldBlock));
            }
            let end = if self.paused {
                self.data.len()
            } else {
                self.pause_at
            };
            let count = output.len().min(end - self.position);
            output[..count].copy_from_slice(&self.data[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        }
    }
    for version in [TlsVersion::Tls12, TlsVersion::Tls13] {
        let wire = record_bytes(version, &[(record::CONTENT_APPLICATION_DATA, b"payload")]);
        for pause_at in 0..wire.len() {
            let reader = PauseOnce {
                data: &wire,
                position: 0,
                pause_at,
                paused: false,
            };
            let mut tls = stream(reader, version);
            assert!(
                matches!(tls.read_record(), Err(TlsError::Timeout)),
                "{version:?} at {pause_at}"
            );
            assert_eq!(tls.read_record().unwrap(), b"payload");
        }
    }
}
