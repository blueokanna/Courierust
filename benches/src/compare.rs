//! Cross-library comparison benchmarks: Courierust vs the mainstream
//! stack (reqwest + tiny_http), plus a raw-TCP syscall floor.
//!
//! Run with `cargo bench --bench compare`. Everything is loopback.
//!
//! Each case reports `req/s` and, when the case uses the process-wide
//! counting allocator, `allocs/req`. The allocator counts every
//! allocation the whole process makes (including the benchmark harness
//! itself), so numbers are comparable across libraries.

use courierust::body::Body;
use courierust::client::{Client, ClientConfig};
use courierust::http::request::Request;
use courierust::http::response::Response;
use courierust::server::{Server, ServerConfig};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Counting global allocator
// ---------------------------------------------------------------------------

use std::alloc::{GlobalAlloc, Layout, System};

static N_ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        N_ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        N_ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.realloc(p, l, n)
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        N_ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc_zeroed(l)
    }
}

#[global_allocator]
static A: Counting = Counting;

fn alloc_snapshot() -> usize {
    N_ALLOCS.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn courierust_server() -> std::net::SocketAddr {
    let server = Server::bind_with_config("127.0.0.1:0", ServerConfig::default()).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|_req: Request<Body>| -> Response<Body> {
            let mut resp = Response::with_status(200.into());
            resp.body = Body::Bytes(courierust::bytes::Bytes::from_static(b"ok"));
            resp
        })
        .unwrap();
    std::mem::forget(handle);
    addr
}

fn tiny_http_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let server = tiny_http::Server::from_listener(listener, None).unwrap();
        for req in server.incoming_requests() {
            let resp = tiny_http::Response::from_data("ok".as_bytes().to_vec());
            let _ = req.respond(resp);
        }
    });
    addr
}

fn report(name: &str, n: usize, elapsed: std::time::Duration, before: usize, after: usize) {
    let per_sec = n as f64 / elapsed.as_secs_f64();
    let allocs = (after - before) as f64 / n as f64;
    println!(
        "{name}: {per_sec:.0} req/s ({:.3}s, n={n}) allocs/req={allocs:.1}",
        elapsed.as_secs_f64()
    );
}

/// Run `n` sequential GETs with the given closure; returns elapsed and
/// allocation delta.
fn run(n: usize, mut f: impl FnMut()) -> (std::time::Duration, usize, usize) {
    let before = alloc_snapshot();
    let start = Instant::now();
    for _ in 0..n {
        f();
    }
    let elapsed = start.elapsed();
    let after = alloc_snapshot();
    (elapsed, before, after)
}

// ---------------------------------------------------------------------------
// 1. Raw TCP floor
// ---------------------------------------------------------------------------

fn raw_tcp_floor(n: usize) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        loop {
            match std::io::Read::read(&mut s, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(k) => {
                    if std::io::Write::write_all(&mut s, &buf[..k]).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_nodelay(true).unwrap();
    // Warm up.
    s.write_all(b"hi").unwrap();
    let mut b = [0u8; 2];
    let _ = s.read(&mut b);
    let before = alloc_snapshot();
    let start = Instant::now();
    for _ in 0..n {
        s.write_all(b"ping").unwrap();
        let mut r = [0u8; 4];
        let _ = s.read(&mut r);
    }
    let elapsed = start.elapsed();
    let after = alloc_snapshot();
    report("raw_tcp_floor", n, elapsed, before, after);
    drop(s);
    let _ = handle.join();
}

// ---------------------------------------------------------------------------
// 2. HTTP/1.1 comparisons
// ---------------------------------------------------------------------------

const N: usize = 2_000;

fn courierust_full_stack() {
    let addr = courierust_server();
    let client = Client::new();
    let url = format!("http://{addr}/bench");
    let _ = client.get(&url).unwrap(); // warm up keep-alive
    let (el, b, a) = run(N, || {
        let r = client.get(&url).unwrap();
        debug_assert_eq!(r.status.as_u16(), 200);
    });
    report("h1 courierust client + courierust server", N, el, b, a);
}

fn courierust_client_vs_tinyhttp() {
    let addr = tiny_http_server();
    let client = Client::new();
    let url = format!("http://{addr}/bench");
    let _ = client.get(&url).unwrap(); // warm up
    let (el, b, a) = run(N, || {
        let r = client.get(&url).unwrap();
        debug_assert_eq!(r.status.as_u16(), 200);
    });
    report("h1 courierust client + tiny_http server", N, el, b, a);
}

fn reqwest_vs_courierust_server() {
    let addr = courierust_server();
    let client = reqwest::blocking::Client::new();
    let url = format!("http://{addr}/bench");
    let _ = client.get(&url).send().unwrap(); // warm up
    let (el, b, a) = run(N, || {
        let r = client.get(&url).send().unwrap();
        debug_assert_eq!(r.status().as_u16(), 200);
    });
    report("h1 reqwest client + courierust server", N, el, b, a);
}

fn reqwest_full_stack() {
    let addr = tiny_http_server();
    let client = reqwest::blocking::Client::new();
    let url = format!("http://{addr}/bench");
    let _ = client.get(&url).send().unwrap(); // warm up
    let (el, b, a) = run(N, || {
        let r = client.get(&url).send().unwrap();
        debug_assert_eq!(r.status().as_u16(), 200);
    });
    report("h1 reqwest client + tiny_http server", N, el, b, a);
}

// ---------------------------------------------------------------------------
// 3. HTTP/2 comparison (h2c prior knowledge)
// ---------------------------------------------------------------------------

fn courierust_h2_client() {
    let cfg = ServerConfig {
        http2: true,
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", cfg).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|_req: Request<Body>| -> Response<Body> {
            let mut resp = Response::with_status(200.into());
            resp.body = Body::Bytes(courierust::bytes::Bytes::from_static(b"ok"));
            resp
        })
        .unwrap();
    std::mem::forget(handle);

    let ccfg = ClientConfig {
        http2: true,
        ..Default::default()
    };
    let client = Client::with_config(ccfg);
    let url = format!("http://{addr}/bench");
    let _ = client.get(&url).unwrap(); // warm up (opens the h2 connection)
    let (el, b, a) = run(N, || {
        let r = client.get(&url).unwrap();
        debug_assert_eq!(r.status.as_u16(), 200);
    });
    report("h2 courierust client (h2c)", N, el, b, a);
}

fn reqwest_h2_client() {
    let cfg = ServerConfig {
        http2: true,
        ..Default::default()
    };
    let server = Server::bind_with_config("127.0.0.1:0", cfg).unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server
        .serve_background(|_req: Request<Body>| -> Response<Body> {
            let mut resp = Response::with_status(200.into());
            resp.body = Body::Bytes(courierust::bytes::Bytes::from_static(b"ok"));
            resp
        })
        .unwrap();
    std::mem::forget(handle);

    let client = reqwest::blocking::Client::builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let url = format!("http://{addr}/bench");
    let _ = client.get(&url).send().unwrap(); // warm up
    let (el, b, a) = run(N, || {
        let r = client.get(&url).send().unwrap();
        debug_assert_eq!(r.status().as_u16(), 200);
    });
    report("h2 reqwest client (h2c)", N, el, b, a);
}

// ---------------------------------------------------------------------------
// 4. Hyper server comparison (the mainstream server)
// ---------------------------------------------------------------------------

fn hyper_server(http2: bool) -> std::net::SocketAddr {
    use http_body_util::Full;
    use hyper::body::{Bytes, Incoming};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioExecutor;
    use hyper_util::rt::TokioIo;
    use hyper_util::server::conn::auto::Builder as AutoBuilder;
    use std::convert::Infallible;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                let svc = service_fn(|_req: hyper::Request<Incoming>| async {
                    Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from_static(
                        b"ok",
                    ))))
                });
                let builder = if http2 {
                    AutoBuilder::new(TokioExecutor::new()).http2_only()
                } else {
                    AutoBuilder::new(TokioExecutor::new()).http1_only()
                };
                tokio::spawn(async move {
                    let _ = builder.serve_connection(io, svc).await;
                });
            }
        });
    });
    addr
}

fn courierust_client_vs_hyper_h1() {
    let addr = hyper_server(false);
    let client = Client::new();
    let url = format!("http://{addr}/bench");
    let _ = client.get(&url).unwrap(); // warm up keep-alive
    let (el, b, a) = run(N, || {
        let r = client.get(&url).unwrap();
        debug_assert_eq!(r.status.as_u16(), 200);
    });
    report("h1 courierust client + hyper server", N, el, b, a);
}

fn courierust_h2_client_vs_hyper_h2() {
    let addr = hyper_server(true);
    let ccfg = ClientConfig {
        http2: true,
        ..Default::default()
    };
    let client = Client::with_config(ccfg);
    let url = format!("http://{addr}/bench");
    let _ = client.get(&url).unwrap(); // warm up
    let (el, b, a) = run(N, || {
        let r = client.get(&url).unwrap();
        debug_assert_eq!(r.status.as_u16(), 200);
    });
    report("h2 courierust client + hyper server (h2c)", N, el, b, a);
}

fn main() {
    println!("courierust vs mainstream (loopback, sequential keep-alive)");
    raw_tcp_floor(20_000);
    courierust_full_stack();
    courierust_client_vs_tinyhttp();
    courierust_client_vs_hyper_h1();
    reqwest_vs_courierust_server();
    reqwest_full_stack();
    courierust_h2_client();
    courierust_h2_client_vs_hyper_h2();
    reqwest_h2_client();
}
