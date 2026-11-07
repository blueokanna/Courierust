//! TLS-only shared-peer comparison: verified full handshakes and record echo.
//! Cipher, key exchange, certificate, ALPN and resumption policy are fixed.

use courierust::courierust_tls as tls;
use courierust_benchmark::metrics::{
    report_comparison, run_sequential, setting, Comparison, MAX_SAMPLES,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const CERT: &[u8] = include_bytes!("../certs/h3_server.der");
const KEY: &[u8] = include_bytes!("../certs/h3_server_key.der");
const CA: &[u8] = include_bytes!("../certs/h3_ca.der");
const ALPN: &[u8] = b"courierust-benchmark";

trait Transport: Read + Write + Send {}
impl<T: Read + Write + Send> Transport for T {}
#[derive(Default)]
struct IoCost {
    reads: AtomicU64,
    writes: AtomicU64,
    read_ns: AtomicU64,
    write_ns: AtomicU64,
}

// Instrument only the separate diagnostic run, not comparison rows.
struct Socket(TcpStream, Option<Arc<IoCost>>);
impl Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let started = self.1.as_ref().map(|_| Instant::now());
        let result = self.0.read(bytes);
        if let (Some(cost), Some(started)) = (&self.1, started) {
            cost.read_ns
                .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
            cost.reads.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn read_vectored(&mut self, buffers: &mut [std::io::IoSliceMut<'_>]) -> std::io::Result<usize> {
        let started = self.1.as_ref().map(|_| Instant::now());
        let result = self.0.read_vectored(buffers);
        if let (Some(cost), Some(started)) = (&self.1, started) {
            cost.read_ns
                .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
            cost.reads.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}
impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let started = self.1.as_ref().map(|_| Instant::now());
        let result = self.0.write(bytes);
        if let (Some(cost), Some(started)) = (&self.1, started) {
            cost.write_ns
                .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
            cost.writes.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    // Preserve rustls's ability to send several TLS records in one syscall.
    // Write's default implementation would silently measure only one slice.
    fn write_vectored(&mut self, buffers: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        let started = self.1.as_ref().map(|_| Instant::now());
        let result = self.0.write_vectored(buffers);
        if let (Some(cost), Some(started)) = (&self.1, started) {
            cost.write_ns
                .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
            cost.writes.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
impl courierust::courierust_io::Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> courierust::Result<usize> {
        Read::read(self, bytes).map_err(Into::into)
    }
}
impl courierust::courierust_io::Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> courierust::Result<usize> {
        Write::write(self, bytes).map_err(Into::into)
    }
    fn flush(&mut self) -> courierust::Result<()> {
        Write::flush(self).map_err(Into::into)
    }
}
struct Own(tls::TlsStream<Socket, Socket>);
impl Read for Own {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        courierust::courierust_io::Read::read(&mut self.0, bytes).map_err(std::io::Error::other)
    }
}
impl Write for Own {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .write_all(bytes)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        courierust::courierust_io::Write::flush(&mut self.0).map_err(std::io::Error::other)
    }
}

#[derive(Clone, Copy)]
struct Version {
    own: tls::TlsVersion,
    foreign: &'static rustls::SupportedProtocolVersion,
    suite: u16,
    label: &'static str,
}

impl Version {
    fn provider(self) -> Arc<rustls::crypto::CryptoProvider> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider
            .cipher_suites
            .retain(|suite| u16::from(suite.suite()) == self.suite);
        let group = if self.own == tls::TlsVersion::Tls13 {
            rustls::NamedGroup::X25519
        } else {
            rustls::NamedGroup::secp256r1
        };
        provider
            .kx_groups
            .retain(|candidate| candidate.name() == group);
        assert_eq!(provider.cipher_suites.len(), 1);
        assert_eq!(provider.kx_groups.len(), 1);
        Arc::new(provider)
    }
    fn own_client(self) -> tls::TlsConnector {
        let mut roots = tls::RootStore::new();
        roots.add_der(CA.to_vec());
        let mut profile = courierust::courierust_fingerprint::chrome_tls_profile();
        profile.ciphers = vec![self.suite];
        profile.supported_versions = vec![if self.own == tls::TlsVersion::Tls13 {
            0x0304
        } else {
            0x0303
        }];
        profile.groups = vec![if self.own == tls::TlsVersion::Tls13 {
            29
        } else {
            23
        }];
        profile.alpn = vec![String::from_utf8(ALPN.to_vec()).unwrap()];
        tls::TlsConnector::new(tls::ClientConfig {
            roots,
            verify: true,
            alpn: vec![ALPN.to_vec()],
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            min_version: self.own,
            max_version: self.own,
            profile: Some(profile),
            identity: None,
        })
    }
    fn foreign_client(self) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(CA.to_vec()))
            .unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(self.provider())
            .with_protocol_versions(&[self.foreign])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        Arc::new(config)
    }
}

fn configure(socket: &TcpStream) {
    socket.set_nodelay(true).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
}

fn connect(
    address: SocketAddr,
    version: Version,
    ours: bool,
    own: &tls::TlsConnector,
    foreign: &Arc<rustls::ClientConfig>,
    cost: Option<Arc<IoCost>>,
) -> Box<dyn Transport> {
    let socket = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    configure(&socket);
    let mut socket = Socket(socket, cost);
    if ours {
        let stream = own
            .connect(
                "localhost",
                Socket(socket.0.try_clone().unwrap(), socket.1.clone()),
                socket,
            )
            .unwrap();
        assert_eq!(stream.version(), version.own);
        assert_eq!(stream.cipher_suite(), version.suite);
        assert_eq!(stream.alpn(), Some(ALPN));
        assert!(
            !stream.resumed(),
            "full-handshake benchmark resumed a session"
        );
        Box::new(Own(stream))
    } else {
        let mut connection =
            rustls::ClientConnection::new(foreign.clone(), "localhost".try_into().unwrap())
                .unwrap();
        while connection.is_handshaking() {
            connection.complete_io(&mut socket).unwrap();
        }
        assert_eq!(connection.protocol_version(), Some(version.foreign.version));
        assert_eq!(
            u16::from(connection.negotiated_cipher_suite().unwrap().suite()),
            version.suite
        );
        assert_eq!(connection.alpn_protocol(), Some(ALPN));
        assert_eq!(
            connection.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
        Box::new(rustls::StreamOwned::new(connection, socket))
    }
}

struct Peer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        let result = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            result.expect("TLS peer failed");
        }
    }
}

fn peer(version: Version, ours: bool) -> Peer {
    let own = Arc::new(tls::TlsAcceptor::new(tls::ServerConfig {
        identity: tls::Identity::from_der(vec![CERT.to_vec()], KEY.to_vec()).unwrap(),
        alpn: vec![ALPN.to_vec()],
        min_version: version.own,
        max_version: version.own,
        ..Default::default()
    }));
    let mut config = rustls::ServerConfig::builder_with_provider(version.provider())
        .with_protocol_versions(&[version.foreign])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(CERT.to_vec())],
            rustls::pki_types::PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
        )
        .unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.send_tls13_tickets = 1;
    let foreign = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let thread = std::thread::spawn(move || {
        let mut sessions: Vec<std::thread::JoinHandle<()>> = Vec::new();
        for socket in listener.incoming() {
            if stopped.load(Ordering::Acquire) {
                break;
            }
            let mut socket = socket.unwrap();
            configure(&socket);
            let own = own.clone();
            let foreign = foreign.clone();
            sessions.push(std::thread::spawn(move || {
                let mut stream: Box<dyn Transport> = if ours {
                    Box::new(Own(own
                        .accept(
                            Socket(socket.try_clone().unwrap(), None),
                            Socket(socket, None),
                        )
                        .unwrap()))
                } else {
                    let mut connection = rustls::ServerConnection::new(foreign).unwrap();
                    while connection.is_handshaking() {
                        connection.complete_io(&mut socket).unwrap();
                    }
                    Box::new(rustls::StreamOwned::new(connection, socket))
                };
                let mut length = [0; 4];
                while stream.read_exact(&mut length).is_ok() {
                    let length = u32::from_be_bytes(length) as usize;
                    assert!(length <= 64 * 1024);
                    let mut bytes = vec![0; length];
                    stream.read_exact(&mut bytes).unwrap();
                    stream.write_all(&bytes).unwrap();
                    stream.flush().unwrap();
                }
            }));
            let mut index = 0;
            while index < sessions.len() {
                if sessions[index].is_finished() {
                    sessions.swap_remove(index).join().unwrap();
                } else {
                    index += 1;
                }
            }
        }
        for session in sessions {
            session.join().unwrap();
        }
    });
    Peer {
        address,
        stop,
        thread: Some(thread),
    }
}

fn diagnose(version: Version, requests: usize) {
    let peer = peer(version, false);
    let own = version.own_client();
    let foreign = version.foreign_client();
    let payload = (0..65_536).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    for ours in [true, false] {
        let cost = Arc::new(IoCost::default());
        let mut stream = connect(
            peer.address,
            version,
            ours,
            &own,
            &foreign,
            Some(cost.clone()),
        );
        let mut reply = vec![0; payload.len()];
        let mut operation = || {
            stream.write_all(&frame).unwrap();
            stream.flush().unwrap();
            stream.read_exact(&mut reply).unwrap();
            assert_eq!(reply, payload);
        };
        for _ in 0..8 {
            operation();
        }
        for counter in [&cost.reads, &cost.writes, &cost.read_ns, &cost.write_ns] {
            counter.store(0, Ordering::Relaxed);
        }
        let started = Instant::now();
        for _ in 0..requests {
            operation();
        }
        let total_ns = started.elapsed().as_nanos();
        let read_ns = cost.read_ns.load(Ordering::Relaxed);
        let write_ns = cost.write_ns.load(Ordering::Relaxed);
        let per_call = |ns: u128| ns as f64 / requests as f64 / 1000.0;
        println!("TLS_COST|protocol={}|client={}|server=rustls-aws-lc|bytes=65536|requests={requests}|wall_us={:.3}|socket_read_us={:.3}|socket_write_us={:.3}|outside_socket_us={:.3}|read_calls={}|write_calls={}|scope=client_after_warmup|instrumented=true",
            version.label, if ours { "courierust" } else { "rustls-aws-lc" },
            per_call(total_ns), per_call(read_ns.into()), per_call(write_ns.into()),
            per_call(total_ns.saturating_sub(u128::from(read_ns) + u128::from(write_ns))),
            cost.reads.load(Ordering::Relaxed), cost.writes.load(Ordering::Relaxed));
    }
}

fn crypto_cost(requests: usize) {
    use std::hint::black_box;
    use tls::crypto::gcm;
    let payload = vec![0xa7; 65_536];
    let started = Instant::now();
    for _ in 0..requests {
        black_box(black_box(&payload).to_vec());
    }
    println!(
        "TLS_COST|layer=allocate_copy_drop|bytes=65536|requests={requests}|us={:.3}",
        started.elapsed().as_secs_f64() * 1e6 / requests as f64
    );
    let started = Instant::now();
    let key = [0x37; 16];
    let mut sequence = 0u64;
    for _ in 0..requests {
        for chunk in payload.chunks(16_384) {
            let mut nonce = [0; 12];
            nonce[4..].copy_from_slice(&sequence.to_be_bytes());
            sequence += 1;
            let sealed = gcm::seal(black_box(&key), &nonce, b"aad12", black_box(chunk)).unwrap();
            assert_eq!(gcm::open(&key, &nonce, b"aad12", &sealed).unwrap(), chunk);
        }
    }
    println!("TLS_COST|layer=aes128gcm_seal_open|bytes=65536|records=4|requests={requests}|us={:.3}|includes=key_setup_allocation_validation|network=none", started.elapsed().as_secs_f64() * 1e6 / requests as f64);
    #[cfg(target_arch = "x86_64")]
    println!(
        "META|pclmulqdq={}|aesni={}",
        std::is_x86_feature_detected!("pclmulqdq"),
        std::is_x86_feature_detected!("aes")
    );
}

fn main() {
    let requests = setting("BENCH_REQUESTS", 100);
    let repetitions = setting("BENCH_REPETITIONS", 4);
    let warmup = setting("BENCH_WARMUP", 4);
    let diagnostics = match std::env::var("BENCH_TLS_DIAGNOSTICS").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("0") => false,
        Ok("1") => true,
        _ => panic!("BENCH_TLS_DIAGNOSTICS must be 0 or 1"),
    };
    if diagnostics {
        crypto_cost(requests);
    }
    println!("META|suite=tls|layer=tls_over_tcp|alpn=courierust-benchmark|verify=true|resumption=disabled|certificate=bench_h3_p256|courierust_clienthello=chrome_profile_with_pinned_crypto|rustls_provider=aws_lc_rs|nodelay=true|timeout_s=5|connections=1|load=closed_loop|validation=negotiated_parameters_and_full_payload|order=alternating");
    for version in [
        Version {
            own: tls::TlsVersion::Tls12,
            foreign: &rustls::version::TLS12,
            suite: 0xc02b,
            label: "tls1.2-aes128gcm-p256",
        },
        Version {
            own: tls::TlsVersion::Tls13,
            foreign: &rustls::version::TLS13,
            suite: 0x1301,
            label: "tls1.3-aes128gcm-x25519",
        },
    ] {
        if diagnostics {
            diagnose(version, requests);
            continue;
        }
        let own_client = version.own_client();
        let foreign_client = version.foreign_client();
        for server in [false, true] {
            let server_name = if server {
                "courierust"
            } else {
                "rustls-aws-lc"
            };
            let peer = peer(version, server);
            for size in [0usize, 1024, 64 * 1024] {
                for repetition in 0..repetitions {
                    for ours in if repetition % 2 == 0 {
                        [true, false]
                    } else {
                        [false, true]
                    } {
                        let make = || {
                            connect(
                                peer.address,
                                version,
                                ours,
                                &own_client,
                                &foreign_client,
                                None,
                            )
                        };
                        let mut operation: Box<dyn FnMut()> = if size == 0 {
                            Box::new(|| {
                                drop(make());
                            })
                        } else {
                            let mut stream = make();
                            let payload = (0..size)
                                .map(|index| (index % 251) as u8)
                                .collect::<Vec<_>>();
                            let mut frame = (size as u32).to_be_bytes().to_vec();
                            frame.extend_from_slice(&payload);
                            let mut reply = vec![0; size];
                            Box::new(move || {
                                stream.write_all(&frame).unwrap();
                                stream.flush().unwrap();
                                stream.read_exact(&mut reply).unwrap();
                                assert_eq!(reply, payload);
                            })
                        };
                        for _ in 0..warmup {
                            operation();
                        }
                        let timing = run_sequential(requests, MAX_SAMPLES, operation);
                        report_comparison(
                            Comparison {
                                protocol: version.label,
                                case: if size == 0 {
                                    "full_handshake"
                                } else {
                                    "record_echo"
                                },
                                client: if ours { "courierust" } else { "rustls-aws-lc" },
                                server: server_name,
                                mode: if size == 0 { "connect" } else { "reuse" },
                                bytes: size,
                                workers: 1,
                                repetition: repetition + 1,
                                warmup,
                            },
                            timing,
                        );
                    }
                }
            }
        }
    }
}
