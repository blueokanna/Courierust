//! Same protobuf codec, four gRPC call shapes, and a two-by-two peer matrix.
//! Each measured RPC validates every message and consumes the final status.

use courierust::courierust_bytes::Bytes;
use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_grpc::{self as grpc, GrpcClient, GrpcClientConfig, GrpcServer};
use courierust::courierust_server::ServerConfig;
use courierust_benchmark::metrics::{
    report_comparison, run_sequential, setting, Comparison, MAX_SAMPLES,
};
use prost::Message;
use std::pin::Pin;
use std::time::Duration;
use tokio_stream::{wrappers::TcpListenerStream, Stream};
use tonic::{Request, Response, Status};

mod wire {
    tonic::include_proto!("courierust.benchmark");
}
use wire::{
    echo_client::EchoClient,
    echo_server::{Echo, EchoServer},
    Payload,
};

const MESSAGES: u32 = 4;
const PREFIX: &str = "/courierust.benchmark.Echo/";

impl grpc::codec::EncodeMessage for Payload {
    fn encode_message(&self) -> courierust::Result<Vec<u8>> {
        Ok(self.encode_to_vec())
    }
}
impl grpc::codec::DecodeMessage for Payload {
    fn decode_message(bytes: &[u8]) -> courierust::Result<Self> {
        Self::decode(bytes).map_err(|error| courierust::Error::protocol(error.to_string()))
    }
}

type Replies = Pin<Box<dyn Stream<Item = Result<Payload, Status>> + Send>>;

#[derive(Default)]
struct TonicEcho;

#[tonic::async_trait]
impl Echo for TonicEcho {
    async fn unary(&self, request: Request<Payload>) -> Result<Response<Payload>, Status> {
        let message = request.into_inner();
        if message.sequence == u32::MAX {
            return Err(Status::invalid_argument("rejected"));
        }
        Ok(Response::new(message))
    }
    type ServerStreamStream = Replies;
    async fn server_stream(&self, request: Request<Payload>) -> Result<Response<Replies>, Status> {
        let message = request.into_inner();
        let fail = message.sequence == u32::MAX;
        let replies = (0..MESSAGES).map(move |sequence| {
            if fail && sequence == 1 {
                Err(Status::data_loss("after first message"))
            } else {
                Ok(Payload {
                    data: message.data.clone(),
                    sequence,
                })
            }
        });
        Ok(Response::new(Box::pin(tokio_stream::iter(replies))))
    }
    async fn client_stream(
        &self,
        request: Request<tonic::Streaming<Payload>>,
    ) -> Result<Response<Payload>, Status> {
        let mut stream = request.into_inner();
        let mut last = None;
        while let Some(message) = stream.message().await? {
            last = Some(message);
        }
        last.map(Response::new)
            .ok_or_else(|| Status::invalid_argument("empty stream"))
    }
    type BidiStream = Replies;
    async fn bidi(
        &self,
        request: Request<tonic::Streaming<Payload>>,
    ) -> Result<Response<Replies>, Status> {
        Ok(Response::new(Box::pin(request.into_inner())))
    }
}

struct CourierustEcho;
impl grpc::StreamingService for CourierustEcho {
    fn serve(
        &self,
        method: &str,
        requests: &mut dyn Iterator<Item = courierust::Result<Bytes>>,
        sender: &courierust::courierust_body::BodySender,
    ) -> courierust::Result<()> {
        let decode = |bytes: Bytes| {
            Payload::decode(&*bytes).map_err(|error| {
                courierust::Error::grpc(grpc::status::INVALID_ARGUMENT, error.to_string())
            })
        };
        let send = |message: Payload| sender.send(Bytes::from(message.encode_to_vec()));
        match method.strip_prefix(PREFIX).unwrap_or(method) {
            "Unary" | "ServerStream" => {
                let message = decode(requests.next().ok_or_else(|| {
                    courierust::Error::grpc(grpc::status::INVALID_ARGUMENT, "missing request")
                })??)?;
                if requests.next().is_some() {
                    return Err(courierust::Error::grpc(
                        grpc::status::INVALID_ARGUMENT,
                        "extra request",
                    ));
                }
                if method.ends_with("/Unary") {
                    if message.sequence == u32::MAX {
                        return Err(courierust::Error::grpc(
                            grpc::status::INVALID_ARGUMENT,
                            "rejected",
                        ));
                    }
                    send(message)?;
                } else {
                    for sequence in 0..MESSAGES {
                        if message.sequence == u32::MAX && sequence == 1 {
                            return Err(courierust::Error::grpc(
                                grpc::status::DATA_LOSS,
                                "after first message",
                            ));
                        }
                        send(Payload {
                            data: message.data.clone(),
                            sequence,
                        })?;
                    }
                }
            }
            "ClientStream" => {
                let mut last = None;
                for bytes in requests {
                    last = Some(decode(bytes?)?);
                }
                send(last.ok_or_else(|| {
                    courierust::Error::grpc(grpc::status::INVALID_ARGUMENT, "empty stream")
                })?)?;
            }
            "Bidi" => {
                for bytes in requests {
                    send(decode(bytes?)?)?;
                }
            }
            _ => {
                return Err(courierust::Error::grpc(
                    grpc::status::UNIMPLEMENTED,
                    "unknown method",
                ))
            }
        }
        Ok(())
    }
}

fn payload(size: usize, sequence: u32) -> Payload {
    Payload {
        data: (0..size).map(|index| (index % 251) as u8).collect(),
        sequence,
    }
}

fn verify(message: Payload, expected: &Payload, sequence: u32) {
    assert_eq!(message.sequence, sequence, "gRPC message order changed");
    assert_eq!(message.data, expected.data, "gRPC payload corrupted");
}

fn courierust_rpc(client: &GrpcClient, shape: &str, message: &Payload) {
    let method = format!("{PREFIX}{shape}");
    if shape == "Unary" {
        let response: Payload = client
            .call_unary(&method, message)
            .expect("unary RPC including final status");
        verify(response, message, 0);
        return;
    }
    let mut stream = if shape == "ServerStream" {
        client
            .call_stream(&method, Bytes::from(message.encode_to_vec()))
            .unwrap()
    } else {
        let (sender, receiver) = std::sync::mpsc::channel();
        for sequence in 0..MESSAGES {
            sender
                .send(Ok(Bytes::from(
                    Payload {
                        data: message.data.clone(),
                        sequence,
                    }
                    .encode_to_vec(),
                )))
                .unwrap();
        }
        drop(sender);
        if shape == "ClientStream" {
            let response = client
                .client_stream(&method, receiver)
                .expect("client-streaming final status");
            verify(Payload::decode(&*response).unwrap(), message, MESSAGES - 1);
            return;
        }
        client.bidi_stream(&method, receiver).unwrap()
    };
    for sequence in 0..MESSAGES {
        let bytes = stream
            .next_message()
            .unwrap()
            .expect("missing gRPC message");
        verify(Payload::decode(&*bytes).unwrap(), message, sequence);
    }
    assert!(stream.next_message().expect("final gRPC status").is_none());
}

async fn tonic_rpc(
    client: &mut EchoClient<tonic::transport::Channel>,
    shape: &str,
    message: &Payload,
) {
    if shape == "Unary" {
        verify(
            client.unary(message.clone()).await.unwrap().into_inner(),
            message,
            0,
        );
        return;
    }
    let requests = (0..MESSAGES)
        .map(|sequence| Payload {
            data: message.data.clone(),
            sequence,
        })
        .collect::<Vec<_>>();
    let mut stream = match shape {
        "ServerStream" => client
            .server_stream(message.clone())
            .await
            .unwrap()
            .into_inner(),
        "ClientStream" => {
            let response = client
                .client_stream(tokio_stream::iter(requests))
                .await
                .unwrap()
                .into_inner();
            verify(response, message, MESSAGES - 1);
            return;
        }
        "Bidi" => client
            .bidi(tokio_stream::iter(requests))
            .await
            .unwrap()
            .into_inner(),
        _ => unreachable!(),
    };
    for sequence in 0..MESSAGES {
        verify(
            stream.message().await.unwrap().expect("missing message"),
            message,
            sequence,
        );
    }
    assert!(stream.message().await.expect("final gRPC status").is_none());
}

fn courierust_client(address: std::net::SocketAddr) -> GrpcClient {
    GrpcClient::with_config(GrpcClientConfig {
        base: format!("http://{address}"),
        max_message_size: grpc::DEFAULT_MAX_MESSAGE_SIZE,
        interceptor: Some(std::sync::Arc::new(
            |_: &str, headers: &mut courierust::courierust_http::header::HeaderMap| {
                headers.insert(
                    courierust::courierust_http::header::HeaderName::from_static(
                        "grpc-accept-encoding",
                    ),
                    courierust::courierust_http::header::HeaderValue::from_static("identity"),
                );
            },
        )),
        timeout: Some(Duration::from_secs(10)),
        compress: false,
        http_client: Client::with_config(ClientConfig {
            http2: true,
            max_connections_per_host: 1,
            read_timeout: Some(Duration::from_secs(10)),
            ..Default::default()
        }),
    })
    .unwrap()
}

fn main() {
    let requests = setting("BENCH_REQUESTS", 100);
    let repetitions = setting("BENCH_REPETITIONS", 4);
    let warmup = setting("BENCH_WARMUP", 4);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let tonic_address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let tonic_server = runtime.spawn(async move {
        tonic::transport::Server::builder()
            .add_service(EchoServer::new(TonicEcho))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let server = GrpcServer::bind_streaming_with_config(
        "127.0.0.1:0",
        CourierustEcho,
        ServerConfig {
            threads: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let courierust_address = server.local_addr().unwrap();
    let _courierust_server = server.serve_background().unwrap();
    println!("META|suite=grpc|transport=h2c|tls=off|codec=prost_shared|compression=identity|connections=1|server_threads=2|stream_messages={MESSAGES}|order=alternating|validation=bytes_sequence_final_status|load=closed_loop");

    for (server_name, address) in [("tonic", tonic_address), ("courierust", courierust_address)] {
        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5));
        let mut tonic_client = EchoClient::new(runtime.block_on(endpoint.connect()).unwrap());
        let courierust = courierust_client(address);
        let invalid = payload(32, u32::MAX);
        assert_eq!(
            runtime
                .block_on(tonic_client.unary(invalid.clone()))
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            courierust
                .call_unary::<_, Payload>(&format!("{PREFIX}Unary"), &invalid)
                .unwrap_err()
                .grpc_code(),
            Some(grpc::status::INVALID_ARGUMENT)
        );
        // A message followed by an error must remain an error in both stacks.
        let mut foreign = runtime
            .block_on(tonic_client.server_stream(invalid.clone()))
            .unwrap()
            .into_inner();
        assert!(runtime.block_on(foreign.message()).unwrap().is_some());
        assert_eq!(
            runtime.block_on(foreign.message()).unwrap_err().code(),
            tonic::Code::DataLoss
        );
        let mut own = courierust
            .call_stream(
                &format!("{PREFIX}ServerStream"),
                Bytes::from(invalid.encode_to_vec()),
            )
            .unwrap();
        assert!(own.next_message().unwrap().is_some());
        assert_eq!(
            own.next_message().unwrap_err().grpc_code(),
            Some(grpc::status::DATA_LOSS)
        );
        println!("INTEROP|case=grpc_status_both_clients_to_{server_name}|ok");

        for size in [1024, 64 * 1024] {
            let message = payload(size, 0);
            for shape in ["Unary", "ServerStream", "ClientStream", "Bidi"] {
                for repetition in 0..repetitions {
                    for ours in if repetition % 2 == 0 {
                        [true, false]
                    } else {
                        [false, true]
                    } {
                        let mut operation = || {
                            if ours {
                                courierust_rpc(&courierust, shape, &message);
                            } else {
                                runtime.block_on(tonic_rpc(&mut tonic_client, shape, &message));
                            }
                        };
                        for _ in 0..warmup {
                            operation();
                        }
                        let timing = run_sequential(requests, MAX_SAMPLES, operation);
                        report_comparison(
                            Comparison {
                                protocol: "grpc-h2",
                                case: shape,
                                client: if ours { "courierust" } else { "tonic" },
                                server: server_name,
                                mode: "reuse",
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
    stop.send(()).unwrap();
    runtime.block_on(tonic_server).unwrap();
}
