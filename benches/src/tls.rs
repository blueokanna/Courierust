//! TLS-only shared-peer comparison: verified full handshakes and record echo.
//! Cipher, key exchange, certificate, ALPN and resumption policy are fixed.

use courierust::courierust_tls as tls;
use courierust_benchmark::metrics::{
    report_comparison, run_sequential, setting, Comparison, MAX_SAMPLES,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const CERT: &[u8] = include_bytes!("../certs/h3_server.der");
const KEY: &[u8] = include_bytes!("../certs/h3_server_key.der");
const CA: &[u8] = include_bytes!("../certs/h3_ca.der");
const ALPN: &[u8] = b"courierust-benchmark";

trait Transport: Read + Write + Send {}
impl<T: Read + Write + Send> Transport for T {}
struct Socket(TcpStream);
impl courierust::courierust_io::Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> courierust::Result<usize> {
        courierust::courierust_io::Read::read(&mut &self.0, bytes)
    }
}
impl courierust::courierust_io::Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> courierust::Result<usize> {
        courierust::courierust_io::Write::write(&mut &self.0, bytes)
    }
    fn flush(&mut self) -> courierust::Result<()> {
        courierust::courierust_io::Write::flush(&mut &self.0)
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
) -> Box<dyn Transport> {
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap();
    configure(&socket);
    if ours {
        let stream = own
            .connect(
                "localhost",
                Socket(socket.try_clone().unwrap()),
                Socket(socket),
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
                        .accept(Socket(socket.try_clone().unwrap()), Socket(socket))
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

fn main() {
    let requests = setting("BENCH_REQUESTS", 100);
    let repetitions = setting("BENCH_REPETITIONS", 4);
    let warmup = setting("BENCH_WARMUP", 4);
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
                        let make =
                            || connect(peer.address, version, ours, &own_client, &foreign_client);
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
