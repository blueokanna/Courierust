//! Time- and space-complexity benchmarks.
//!
//! The other suites answer "how fast is it". This one answers the two
//! questions an engineer asks *before* trusting a number:
//!
//! 1. **Time complexity** — how does the per-operation cost grow with the
//!    input size? Every family is measured at several sizes spanning three
//!    orders of magnitude, and each point is the minimum of three repeats
//!    (noise only ever makes a measurement slower, so the minimum is the
//!    right estimator — and a noisy point would otherwise invent curvature
//!    that is not in the code). Two models are fitted: the affine model
//!    `cost = a + b·n` (a fixed per-operation term plus a per-unit term,
//!    with R²) and the *adjacent-pair exponents* whose median names the
//!    asymptotic class (the maximum is reported beside it so a single
//!    noisy pair cannot hide). The class is derived from the median
//!    exponent: `O(1)` when it is ≈ 0, `O(n)` when it is ≈ 1, `O(n^k)`
//!    otherwise (the bands are wide on purpose — over three orders of
//!    magnitude a true `O(n log n)` is indistinguishable from `O(n)`, so
//!    the exponent is reported rather than a fancier name). A range whose
//!    fixed term dwarfs its per-unit term is labelled
//!    `fixed-cost dominated`: there is no meaningful exponent inside such
//!    a range, and the label points the reader at `slope_b` instead of a
//!    sublinear-looking number that is really the constant.
//! 2. **Space complexity** — how many bytes (and how many allocation
//!    calls) one operation costs, and how the cost of one *connection*
//!    scales with the number of idle connections. A counting global
//!    allocator (this bench binary only — the library is untouched)
//!    attributes allocation bytes and calls to the exact measurement
//!    region, and a resident-set probe reports the process-level cost
//!    where the platform exposes it without a dependency (Linux
//!    `/proc/self/statm`, Windows `psapi`).
//!
//! Every family with a fair mainstream counterpart is measured against it
//! **in the same process, same build profile, same measurement region**:
//! `tungstenite 0.30` for the WebSocket frame layer, `reqwest` (hyper) for
//! HTTP/1.1. Where no fair counterpart exists in this workspace (raw
//! DEFLATE; per-connection event-loop memory against a non-Rust server)
//! the rows say so instead of inventing one.
//!
//! Output is machine-readable — `SCALE|`, `COMPLEXITY|`, `RATIO|`,
//! `MEMORY|`, `NOTE|` — so `scripts/generate_benchmark_report.sh` renders
//! it into `Github_Action_Benchmark.md`.
//!
//! Run with:
//! ```text
//! cargo bench --manifest-path benches/Cargo.toml --bench complexity
//! ```
//! `COMPLEXITY_FAMILY=codec|http|headers|connections|deflate` runs one
//! family only.

use courierust::courierust_body::Body;
use courierust::courierust_client::Client;
use courierust::courierust_deflate::{deflate_sync, Deflater, Inflater};
use courierust::courierust_http::header::{HeaderName, HeaderValue};
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_server::{Server, ServerConfig};
use courierust::courierust_ws::frame::MAX_HEADER_LEN;
use courierust::courierust_ws::frame::{FrameHeader as WsHeader, Mask};
use courierust::courierust_ws::writer::{FrameWriter, VecSink};
use courierust::courierust_ws::{FrameSink, MaskSource, OpCode, Utf8Validator};
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tungstenite::protocol::frame::coding::{Data, OpCode as TungOpCode};
use tungstenite::protocol::frame::Frame as TungFrame;

// ---------------------------------------------------------------------
// Counting allocator (this bench binary only)
// ---------------------------------------------------------------------

/// Wraps the system allocator and counts what the *program* allocates, so
/// a measurement region can be attributed per operation. It lives in the
/// bench binary, never in the library, and costs two relaxed atomic
/// operations per allocation — negligible against what it measures.
struct CountingAllocator;

static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every method forwards to `System` with the caller's own layout
// and pointer and only updates counters around it; no memory is
// reinterpreted, and the counters are statistics, not addresses.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
            if new_size >= layout.size() {
                LIVE_BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed);
            } else {
                LIVE_BYTES.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// One instant of the allocator counters.
#[derive(Clone, Copy, Default)]
struct Counters {
    calls: usize,
    bytes: usize,
    live: usize,
}

fn counters() -> Counters {
    Counters {
        calls: ALLOC_CALLS.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        live: LIVE_BYTES.load(Ordering::Relaxed),
    }
}

/// Resident set size in KiB, where the platform exposes it without a
/// dependency. On other platforms the memory rows carry an explicit
/// `reason=` instead of a guess.
fn rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // `/proc/self/statm` field 2 is the resident page count; CI
        // x86_64 runners use 4 KiB pages.
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let resident: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(resident.saturating_mul(4))
    }
    #[cfg(windows)]
    {
        // SAFETY: the struct is `#[repr(C)]`, matches
        // `PROCESS_MEMORY_COUNTERS` exactly, and is initialised before
        // the call; `GetCurrentProcess` returns the documented
        // pseudo-handle, which must not be closed.
        unsafe {
            let mut info: ProcessMemoryCounters = std::mem::zeroed();
            info.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
            let ok = K32GetProcessMemoryInfo(GetCurrentProcess(), &mut info, info.cb);
            (ok != 0).then_some((info.working_set_size / 1024) as u64)
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        None
    }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Default)]
struct ProcessMemoryCounters {
    cb: u32,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut core::ffi::c_void;
    fn K32GetProcessMemoryInfo(
        process: *mut core::ffi::c_void,
        counters: *mut ProcessMemoryCounters,
        cb: u32,
    ) -> i32;
}

// ---------------------------------------------------------------------
// Measurement, fitting, reporting
// ---------------------------------------------------------------------

/// One measurement: time per operation plus the allocator cost of one
/// operation, both attributed to the same region.
struct Sample {
    ns_per_op: f64,
    alloc_bytes_per_op: f64,
    allocs_per_op: f64,
}

/// Timed repeats per measured point.
///
/// Cache effects, loopback jitter and host load can inflate a single run by
/// a factor of two or more. Noise only ever makes a measurement *slower*, so
/// the minimum of several repeats is the right estimator for "how fast does
/// this operation actually go" — and it is the quantity an asymptotic fit
/// needs, because a noisy point invents curvature that is not in the code.
const REPEATS: usize = 3;

/// Run `ops` iterations of `f` after a discarded warmup and report the
/// per-operation cost. Buffers that `f` reuses are cleared inside `f`, so
/// only an implementation that allocates per operation shows up in the
/// allocator columns.
fn measure(ops: usize, mut f: impl FnMut()) -> Sample {
    for _ in 0..(ops / 10).max(1) {
        f();
    }
    let mut best = f64::INFINITY;
    let mut alloc_bytes = 0usize;
    let mut alloc_calls = 0usize;
    let mut captured = false;
    for _ in 0..REPEATS {
        let before = counters();
        let started = Instant::now();
        for _ in 0..ops {
            f();
        }
        let elapsed = started.elapsed();
        let after = counters();
        // Allocator traffic is a property of the operation, not of the
        // repeat, so it is read once instead of being multiplied by the
        // repeat count.
        if !captured {
            alloc_bytes = after.bytes - before.bytes;
            alloc_calls = after.calls - before.calls;
            captured = true;
        }
        best = best.min(elapsed.as_secs_f64());
    }
    Sample {
        ns_per_op: best / ops as f64 * 1e9,
        alloc_bytes_per_op: alloc_bytes as f64 / ops as f64,
        allocs_per_op: alloc_calls as f64 / ops as f64,
    }
}

/// Iterations per sample for an input of `size` bytes: enough work to
/// clear the clock resolution without taking seconds per sample.
fn ops_for(size: usize) -> usize {
    match size {
        0..=128 => 4_000,
        129..=4096 => 2_000,
        4097..=65_536 => 200,
        65_537..=1_048_576 => 40,
        _ => 8,
    }
}

/// Least-squares fit of `cost = a + b·n` over the measured points, with R².
///
/// This is the honest model for per-operation cost: a fixed term (header
/// encoding, call overhead, buffer setup) plus a per-unit term. A whole-
/// range power-law fit would be bent *below* `O(n)` by the fixed term, so
/// the asymptotic class is reported from [`local_exponent`] instead.
fn fit_affine(points: &[(f64, f64)]) -> Option<(f64, f64, f64)> {
    let usable: Vec<(f64, f64)> = points
        .iter()
        .copied()
        .filter(|(n, cost)| *n > 0.0 && *cost >= 0.0)
        .collect();
    if usable.len() < 3 {
        return None;
    }
    let count = usable.len() as f64;
    let mean_x = usable.iter().map(|(n, _)| n).sum::<f64>() / count;
    let mean_y = usable.iter().map(|(_, cost)| cost).sum::<f64>() / count;
    let mut cov = 0.0;
    let mut var_x = 0.0;
    for (n, cost) in &usable {
        cov += (n - mean_x) * (cost - mean_y);
        var_x += (n - mean_x) * (n - mean_x);
    }
    if var_x <= f64::EPSILON {
        return None;
    }
    let slope = cov / var_x;
    let intercept = mean_y - slope * mean_x;
    let mut ss_res = 0.0;
    let mut ss_tot = 0.0;
    for (n, cost) in &usable {
        let predicted = intercept + slope * n;
        ss_res += (cost - predicted) * (cost - predicted);
        ss_tot += (cost - mean_y) * (cost - mean_y);
    }
    let r2 = if ss_tot <= f64::EPSILON {
        1.0
    } else {
        1.0 - ss_res / ss_tot
    };
    Some((intercept, slope, r2))
}

/// The exponent of every adjacent size pair, sorted ascending.
///
/// A single pair can be noisy (an allocator's behaviour at a size
/// boundary, cache effects at the top of the range), so the *median* is
/// what names the class; the maximum is reported next to it so that
/// instability is visible instead of hidden.
fn adjacent_exponents(points: &[(f64, f64)]) -> Vec<f64> {
    let mut sorted: Vec<(f64, f64)> = points
        .iter()
        .copied()
        .filter(|(n, cost)| *n > 0.0 && *cost > 0.0)
        .collect();
    sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut exponents = Vec::with_capacity(sorted.len().saturating_sub(1));
    for pair in sorted.windows(2) {
        let (n_small, cost_small) = pair[0];
        let (n_large, cost_large) = pair[1];
        if n_small > 0.0 && cost_small > 0.0 {
            exponents.push((cost_large / cost_small).ln() / (n_large / n_small).ln());
        }
    }
    exponents.sort_by(f64::total_cmp);
    exponents
}

/// The measured class name for a fitted exponent (see the module docs for
/// why the bands are wide).
fn class_of(k: f64) -> String {
    if k.abs() < 0.15 {
        String::from("O(1)")
    } else if (0.85..=1.15).contains(&k) {
        String::from("O(n)")
    } else if (1.85..=2.15).contains(&k) {
        String::from("O(n^2)")
    } else {
        format!("O(n^{k:.2})")
    }
}

/// One measured point of one operation.
fn emit_scale(family: &str, implementation: &str, op: &str, metric: &str, n: usize, value: f64) {
    println!("SCALE|family={family}|impl={implementation}|op={op}|metric={metric}|n={n}|value={value:.4}");
}

/// The fitted complexity of one operation: the affine model
/// (`cost = a + b·n`), the asymptotic exponent at the top of the range,
/// and the fit quality of the affine model.
fn emit_complexity(
    family: &str,
    implementation: &str,
    op: &str,
    metric: &str,
    points: &[(f64, f64)],
) {
    let Some((intercept, slope, r2)) = fit_affine(points) else {
        println!(
            "COMPLEXITY|family={family}|impl={implementation}|op={op}|metric={metric}|class=n/a|median_k=n/a|max_k=n/a|slope_b=n/a|fixed_a=n/a|r2=n/a|points={}|model=a+b*n|reason=not_enough_points",
            points.len()
        );
        return;
    };
    let exponents = adjacent_exponents(points);
    let median = if exponents.is_empty() {
        None
    } else {
        Some(exponents[exponents.len() / 2])
    };
    let worst = exponents.last().copied();
    let fmt = |value: Option<f64>| match value {
        Some(k) => format!("{k:.3}"),
        None => String::from("n/a"),
    };
    // A measurement range where the fixed term dwarfs the per-unit term
    // (a 40 µs request with 1 KiB of payload, 4 extra headers against a
    // 37 µs round trip) has no meaningful asymptotic class *within that
    // range*: the honest label is the one that points the reader at
    // `slope_b` instead of a sublinear-looking exponent that is really
    // the constant absorbed by the fit.
    let n_max = points.iter().map(|(n, _)| *n).fold(0.0f64, f64::max);
    let per_unit_at_max = slope.max(0.0) * n_max;
    let class = if intercept > 10.0 * per_unit_at_max {
        String::from("fixed-cost dominated")
    } else {
        match median {
            Some(k) => class_of(k),
            None => String::from("n/a"),
        }
    };
    println!(
        "COMPLEXITY|family={family}|impl={implementation}|op={op}|metric={metric}|class={class}|median_k={}|max_k={}|slope_b={slope:.6}|fixed_a={intercept:.4}|r2={r2:.4}|points={}|model=a+b*n",
        fmt(median),
        fmt(worst),
        points.len()
    );
}

/// Ours versus the reference at one size: with the exponents equal, what
/// is left is the constant factor.
fn emit_ratio(family: &str, op: &str, metric: &str, n: usize, ours: f64, theirs: f64) {
    let ratio = if theirs > 0.0 {
        ours / theirs
    } else {
        f64::NAN
    };
    println!(
        "RATIO|family={family}|op={op}|metric={metric}|n={n}|a={ours:.4}|b={theirs:.4}|ratio={ratio:.3}"
    );
}

/// Per-connection cost, measured as a delta between two connection counts
/// so the fixed process/runtime overhead cancels out.
fn emit_memory(
    family: &str,
    implementation: &str,
    connections: usize,
    live_kib_per_conn: f64,
    rss_kib_per_conn: Option<f64>,
) {
    match rss_kib_per_conn {
        Some(kib) => println!(
            "MEMORY|family={family}|impl={implementation}|connections={connections}|live_kib_per_conn={live_kib_per_conn:.2}|rss_kib_per_conn={kib:.2}"
        ),
        None => println!(
            "MEMORY|family={family}|impl={implementation}|connections={connections}|live_kib_per_conn={live_kib_per_conn:.2}|rss_kib_per_conn=n/a|reason=rss_unsupported_platform"
        ),
    }
}

/// A measured zero: every sample allocated nothing, so the space class is
/// `O(1)` with an exact zero instead of a fitted value.
fn emit_zero_space(family: &str, implementation: &str, op: &str, points: usize) {
    println!(
        "COMPLEXITY|family={family}|impl={implementation}|op={op}|metric=alloc_bytes|class=O(1)|median_k=0.000|max_k=0.000|slope_b=0.000000|fixed_a=0.0000|r2=1.0000|points={points}|model=a+b*n|reason=zero_allocations_per_operation"
    );
}

fn note(text: &str) {
    println!("NOTE|{text}");
}

fn print_sample(label: &str, sample: &Sample) {
    println!(
        "  {label:<34} {:>10.1} ns/op   {:>8.1} B/op   {:>5.2} allocs/op",
        sample.ns_per_op, sample.alloc_bytes_per_op, sample.allocs_per_op
    );
}

/// Per-operation points collected for one operation, ready to be fitted.
#[derive(Default)]
struct Series {
    time: Vec<(f64, f64)>,
    alloc: Vec<(f64, f64)>,
    points: usize,
}

impl Series {
    /// Record one measured point (and emit its `SCALE|` rows).
    fn push(&mut self, family: &str, implementation: &str, op: &str, n: usize, sample: &Sample) {
        emit_scale(family, implementation, op, "time_ns", n, sample.ns_per_op);
        emit_scale(
            family,
            implementation,
            op,
            "alloc_bytes",
            n,
            sample.alloc_bytes_per_op,
        );
        emit_scale(
            family,
            implementation,
            op,
            "allocs",
            n,
            sample.allocs_per_op,
        );
        self.time.push((n as f64, sample.ns_per_op));
        if sample.alloc_bytes_per_op > 0.0 {
            self.alloc.push((n as f64, sample.alloc_bytes_per_op));
        }
        self.points += 1;
    }

    /// Emit the fitted rows for the time and the space dimensions.
    fn emit_fits(&self, family: &str, implementation: &str, op: &str) {
        emit_complexity(family, implementation, op, "time_ns", &self.time);
        if self.alloc.is_empty() {
            if self.points > 0 {
                emit_zero_space(family, implementation, op, self.points);
            }
        } else {
            emit_complexity(family, implementation, op, "alloc_bytes", &self.alloc);
        }
    }
}

// ---------------------------------------------------------------------
// Family 1: WebSocket frame layer, courierust vs tungstenite
// ---------------------------------------------------------------------

const CODEC_SIZES: [usize; 5] = [64, 1024, 16 * 1024, 256 * 1024, 1024 * 1024];

fn codec_family() {
    println!("\n== family: codec (WebSocket frame layer, no sockets) ==");
    note("codec|method=median_of_15_samples_per_size|warmup=10_percent|payload=0x5a_repeated");
    note("codec|fairness=tungstenite_frame_cloned_once_with_a_reused_output_buffer|masked_encode_allocates_a_copy_per_frame_in_tungstenite");

    let mut ours_encode = Series::default();
    let mut theirs_encode = Series::default();
    let mut ours_masked = Series::default();
    let mut theirs_masked = Series::default();

    for &size in &CODEC_SIZES {
        let payload = vec![0x5au8; size];
        let ops = ops_for(size);
        println!("payload {size} bytes ({ops} ops/sample)");

        // ---- encode, server role (unmasked) ------------------------
        let mut sink = VecSink::new();
        let ours = measure(ops, || {
            let mut head = [0u8; MAX_HEADER_LEN];
            let header = WsHeader::data(OpCode::Binary, true, payload.len() as u64);
            let written = header.write(&mut head);
            sink.bytes.clear();
            sink.write_frame(&head[..written], &payload, None).unwrap();
        });
        print_sample("courierust encode (unmasked)", &ours);
        ours_encode.push("codec", "courierust", "encode_unmasked", size, &ours);

        let theirs_frame =
            TungFrame::message(payload.clone(), TungOpCode::Data(Data::Binary), true);
        let mut theirs_out = Vec::with_capacity(size + MAX_HEADER_LEN);
        let theirs = measure(ops, || {
            theirs_out.clear();
            let _ = theirs_frame.clone().format(&mut theirs_out);
        });
        print_sample("tungstenite encode (unmasked)", &theirs);
        theirs_encode.push("codec", "tungstenite", "encode_unmasked", size, &theirs);
        emit_ratio(
            "codec",
            "encode_unmasked",
            "time_ns",
            size,
            ours.ns_per_op,
            theirs.ns_per_op,
        );
        emit_ratio(
            "codec",
            "encode_unmasked",
            "alloc_bytes",
            size,
            ours.alloc_bytes_per_op,
            theirs.alloc_bytes_per_op,
        );

        // ---- encode, client role (masked) --------------------------
        let mut writer = FrameWriter::new(VecSink::new(), MaskSource::Fixed([1, 2, 3, 4]), None);
        let ours_masked_sample = measure(ops, || {
            writer.sink_mut().bytes.clear();
            writer
                .write_frame(OpCode::Binary, &payload, true, false)
                .ok();
        });
        print_sample("courierust encode (masked)", &ours_masked_sample);
        ours_masked.push(
            "codec",
            "courierust",
            "encode_masked",
            size,
            &ours_masked_sample,
        );

        let mut theirs_masked_frame = theirs_frame.clone();
        theirs_masked_frame.header_mut().mask = Some([1, 2, 3, 4]);
        let theirs_masked_sample = measure(ops, || {
            theirs_out.clear();
            let _ = theirs_masked_frame.clone().format(&mut theirs_out);
        });
        print_sample("tungstenite encode (masked)", &theirs_masked_sample);
        theirs_masked.push(
            "codec",
            "tungstenite",
            "encode_masked",
            size,
            &theirs_masked_sample,
        );
        emit_ratio(
            "codec",
            "encode_masked",
            "time_ns",
            size,
            ours_masked_sample.ns_per_op,
            theirs_masked_sample.ns_per_op,
        );
        emit_ratio(
            "codec",
            "encode_masked",
            "alloc_bytes",
            size,
            ours_masked_sample.alloc_bytes_per_op,
            theirs_masked_sample.alloc_bytes_per_op,
        );

        // ---- masking in place --------------------------------------
        let mask = Mask::new([1, 2, 3, 4]);
        let mut raw = payload.clone();
        let ours_mask = measure(ops, || {
            mask.apply(0, &mut raw);
        });
        print_sample("courierust mask (in place)", &ours_mask);
        emit_scale(
            "codec",
            "courierust",
            "mask_in_place",
            "time_ns",
            size,
            ours_mask.ns_per_op,
        );
        emit_scale(
            "codec",
            "courierust",
            "mask_in_place",
            "alloc_bytes",
            size,
            ours_mask.alloc_bytes_per_op,
        );

        // ---- decode + unmask ---------------------------------------
        let wire = masked_frame(&payload, size);
        let mut scratch = payload.clone();
        let ours_decode = measure(ops, || {
            let header = WsHeader::parse(&wire).unwrap().unwrap();
            let body = &wire[header.header_len..];
            scratch.copy_from_slice(body);
            Mask::new(header.mask_key).apply(0, &mut scratch);
        });
        print_sample("courierust decode + unmask", &ours_decode);
        emit_scale(
            "codec",
            "courierust",
            "decode_unmask",
            "time_ns",
            size,
            ours_decode.ns_per_op,
        );
        emit_scale(
            "codec",
            "courierust",
            "decode_unmask",
            "alloc_bytes",
            size,
            ours_decode.alloc_bytes_per_op,
        );

        // ---- header parse on the reference side --------------------
        let theirs_wire = wire.clone();
        let theirs_parse = measure(ops, || {
            let mut cursor = std::io::Cursor::new(&theirs_wire);
            let (_header, len) = tungstenite::protocol::frame::FrameHeader::parse(&mut cursor)
                .unwrap()
                .unwrap();
            let start = cursor.position() as usize;
            let body = &theirs_wire[start..start + len as usize];
            std::hint::black_box(body);
        });
        print_sample("tungstenite parse header", &theirs_parse);
        emit_scale(
            "codec",
            "tungstenite",
            "parse_header",
            "time_ns",
            size,
            theirs_parse.ns_per_op,
        );
        println!();
    }

    ours_encode.emit_fits("codec", "courierust", "encode_unmasked");
    theirs_encode.emit_fits("codec", "tungstenite", "encode_unmasked");
    ours_masked.emit_fits("codec", "courierust", "encode_masked");
    theirs_masked.emit_fits("codec", "tungstenite", "encode_masked");

    // ---- UTF-8 validation over a realistic text block --------------
    // The reference is `str::from_utf8` — the platform's own validator —
    // and it is the right control: a WebSocket validator that is slower
    // than the standard library call it could be written as would be a
    // pessimisation, not a feature. What the library adds on top is
    // resume-across-frames plus a precise offset/reason, and that is
    // measured by the session tests, not by this row.
    let text = "The quick brown fox jumps over the lazy dog. 日本語テキスト 🦀 ".repeat(64);
    let bytes = text.as_bytes();
    note("codec|utf8_validate_reference=std_str_from_utf8_the_platform_baseline_ours_adds_streaming_state_and_a_precise_offset");
    let ours = measure(2000, || {
        let mut validator = Utf8Validator::new();
        validator.feed(bytes).unwrap();
    });
    let control = measure(2000, || {
        std::str::from_utf8(bytes).unwrap();
    });
    print_sample("courierust utf8 validate", &ours);
    print_sample("std str::from_utf8", &control);
    emit_scale(
        "codec",
        "courierust",
        "utf8_validate",
        "time_ns",
        bytes.len(),
        ours.ns_per_op,
    );
    emit_scale(
        "codec",
        "std",
        "utf8_validate",
        "time_ns",
        bytes.len(),
        control.ns_per_op,
    );
    emit_ratio(
        "codec",
        "utf8_validate",
        "time_ns",
        bytes.len(),
        ours.ns_per_op,
        control.ns_per_op,
    );
}

/// A masked, wire-format frame for `payload`.
fn masked_frame(payload: &[u8], size: usize) -> Vec<u8> {
    let mut wire = vec![0u8; MAX_HEADER_LEN];
    let header = WsHeader {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: OpCode::Binary,
        masked: true,
        mask_key: [1, 2, 3, 4],
        payload_len: size as u64,
        header_len: 0,
    };
    let written = header.write(&mut wire);
    wire.truncate(written);
    let mut body = payload.to_vec();
    Mask::new([1, 2, 3, 4]).apply(0, &mut body);
    wire.extend_from_slice(&body);
    wire
}

// ---------------------------------------------------------------------
// Servers used by the HTTP families
// ---------------------------------------------------------------------

fn our_server(payload: usize) -> SocketAddr {
    let server = Server::bind_with_config(
        "127.0.0.1:0",
        ServerConfig {
            threads: 4,
            ..Default::default()
        },
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let body = courierust::Bytes::from(vec![0x41u8; payload]);
    let handle = server
        .serve_background(move |_request: Request<Body>| {
            Response::<Body>::with_status(200.into()).with_body(Body::Bytes(body.clone()))
        })
        .unwrap();
    std::mem::forget(handle);
    address
}

fn hyper_server(payload: usize) -> SocketAddr {
    use http_body_util::{BodyExt, Full};
    use hyper::body::{Bytes as HyperBytes, Incoming};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;
    use std::convert::Infallible;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address = listener.local_addr().unwrap();
    let body = HyperBytes::from(vec![0x41u8; payload]);

    std::thread::spawn(move || {
        runtime.block_on(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                // TCP_NODELAY on both stacks (see `compare.rs`: without it,
                // Linux Nagle + delayed ACK stalls 64 KiB responses for no
                // protocol reason).
                let _ = stream.set_nodelay(true);
                let body = body.clone();
                let service = service_fn(move |request: hyper::Request<Incoming>| {
                    let body = body.clone();
                    async move {
                        let _ = BodyExt::collect(request.into_body()).await;
                        Ok::<_, Infallible>(hyper::Response::new(Full::new(body)))
                    }
                });
                let builder = AutoBuilder::new(TokioExecutor::new()).http1_only();
                tokio::spawn(async move {
                    let _ = builder
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
    });
    address
}

// ---------------------------------------------------------------------
// Family 2: HTTP/1.1 request/response scaling, courierust vs reqwest
// ---------------------------------------------------------------------

const HTTP_SIZES: [usize; 4] = [1024, 16 * 1024, 256 * 1024, 1024 * 1024];

fn http_family() {
    println!("\n== family: http (one GET per request, HTTP/1.1, loopback) ==");
    note("http|method=median_of_15_samples|payload=0x41_repeated|connection=keep_alive_pool");
    note("http|fairness=both_sides_pool_connections_and_consume_the_whole_body|reqwest_is_a_higher_level_client");

    let mut ours_series = Series::default();
    let mut theirs_series = Series::default();

    for &size in &HTTP_SIZES {
        let ops = ops_for(size) / 2 + 5;
        let ours_addr = our_server(size);
        let theirs_addr = hyper_server(size);

        let ours_client = Client::new();
        let ours_url = format!("http://{ours_addr}/complexity");
        assert_eq!(
            ours_client
                .get(&ours_url)
                .unwrap()
                .body
                .collect()
                .unwrap()
                .len(),
            size
        );
        let ours = measure(ops, || {
            let response = ours_client.get(&ours_url).unwrap();
            assert_eq!(response.body.collect().unwrap().len(), size);
        });

        let theirs_client = reqwest::blocking::Client::builder().build().unwrap();
        let theirs_url = format!("http://{theirs_addr}/complexity");
        assert_eq!(
            theirs_client
                .get(&theirs_url)
                .send()
                .unwrap()
                .bytes()
                .unwrap()
                .len(),
            size
        );
        let theirs = measure(ops, || {
            let response = theirs_client.get(&theirs_url).send().unwrap();
            assert_eq!(response.bytes().unwrap().len(), size);
        });

        println!("payload {size} bytes ({ops} ops/sample)");
        print_sample("courierust client + server", &ours);
        print_sample("reqwest client + hyper server", &theirs);
        ours_series.push("http", "courierust", "get_roundtrip", size, &ours);
        theirs_series.push("http", "reqwest_hyper", "get_roundtrip", size, &theirs);
        emit_ratio(
            "http",
            "get_roundtrip",
            "time_ns",
            size,
            ours.ns_per_op,
            theirs.ns_per_op,
        );
        emit_ratio(
            "http",
            "get_roundtrip",
            "alloc_bytes",
            size,
            ours.alloc_bytes_per_op,
            theirs.alloc_bytes_per_op,
        );
        println!();
    }

    ours_series.emit_fits("http", "courierust", "get_roundtrip");
    theirs_series.emit_fits("http", "reqwest_hyper", "get_roundtrip");
}

// ---------------------------------------------------------------------
// Family 3: header-count scaling
// ---------------------------------------------------------------------

const HEADER_COUNTS: [usize; 3] = [4, 16, 64];

/// Static names, because `HeaderName::from_lowercase` requires a
/// `&'static str` (names are interned by design, not built per request).
const BENCH_HEADER_NAMES: [&str; 64] = [
    "x-bench-00",
    "x-bench-01",
    "x-bench-02",
    "x-bench-03",
    "x-bench-04",
    "x-bench-05",
    "x-bench-06",
    "x-bench-07",
    "x-bench-08",
    "x-bench-09",
    "x-bench-10",
    "x-bench-11",
    "x-bench-12",
    "x-bench-13",
    "x-bench-14",
    "x-bench-15",
    "x-bench-16",
    "x-bench-17",
    "x-bench-18",
    "x-bench-19",
    "x-bench-20",
    "x-bench-21",
    "x-bench-22",
    "x-bench-23",
    "x-bench-24",
    "x-bench-25",
    "x-bench-26",
    "x-bench-27",
    "x-bench-28",
    "x-bench-29",
    "x-bench-30",
    "x-bench-31",
    "x-bench-32",
    "x-bench-33",
    "x-bench-34",
    "x-bench-35",
    "x-bench-36",
    "x-bench-37",
    "x-bench-38",
    "x-bench-39",
    "x-bench-40",
    "x-bench-41",
    "x-bench-42",
    "x-bench-43",
    "x-bench-44",
    "x-bench-45",
    "x-bench-46",
    "x-bench-47",
    "x-bench-48",
    "x-bench-49",
    "x-bench-50",
    "x-bench-51",
    "x-bench-52",
    "x-bench-53",
    "x-bench-54",
    "x-bench-55",
    "x-bench-56",
    "x-bench-57",
    "x-bench-58",
    "x-bench-59",
    "x-bench-60",
    "x-bench-61",
    "x-bench-62",
    "x-bench-63",
];

const BENCH_HEADER_VALUE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HEADERS_BODY: usize = 1024;

fn http_headers_family() {
    println!("\n== family: headers (GET with N extra request headers, 1 KiB body) ==");
    note("headers|method=median_of_15_samples|value=64_byte_header_value|request_built_inside_the_timed_region_for_both_sides");

    let ours_addr = our_server(HEADERS_BODY);
    let theirs_addr = hyper_server(HEADERS_BODY);
    let ops = 200usize;

    let mut ours_series = Series::default();
    let mut theirs_series = Series::default();

    for &count in &HEADER_COUNTS {
        let ours_client = Client::new();
        let ours_url = format!("http://{ours_addr}/complexity");
        let ours = measure(ops, || {
            let mut request = Request::get("/complexity").with_body(Body::Empty);
            for name in BENCH_HEADER_NAMES.iter().take(count) {
                request.headers.insert(
                    HeaderName::from_static(name),
                    HeaderValue::from_static(BENCH_HEADER_VALUE),
                );
            }
            let response = ours_client.execute(&ours_url, request).unwrap();
            assert_eq!(response.body.collect().unwrap().len(), HEADERS_BODY);
        });

        let theirs_client = reqwest::blocking::Client::builder().build().unwrap();
        let theirs_url = format!("http://{theirs_addr}/complexity");
        let theirs = measure(ops, || {
            let mut builder = theirs_client.get(&theirs_url);
            for name in BENCH_HEADER_NAMES.iter().take(count) {
                builder = builder.header(*name, BENCH_HEADER_VALUE);
            }
            let response = builder.send().unwrap();
            assert_eq!(response.bytes().unwrap().len(), HEADERS_BODY);
        });

        println!("{count} extra headers ({ops} ops/sample)");
        print_sample("courierust client + server", &ours);
        print_sample("reqwest client + hyper server", &theirs);
        ours_series.push("headers", "courierust", "get_with_headers", count, &ours);
        theirs_series.push(
            "headers",
            "reqwest_hyper",
            "get_with_headers",
            count,
            &theirs,
        );
        emit_ratio(
            "headers",
            "get_with_headers",
            "time_ns",
            count,
            ours.ns_per_op,
            theirs.ns_per_op,
        );
        println!();
    }

    ours_series.emit_fits("headers", "courierust", "get_with_headers");
    theirs_series.emit_fits("headers", "reqwest_hyper", "get_with_headers");
    note(
        "headers|scope=end_to_end_one_keep_alive_request_per_sample_including_request_construction",
    );
}

// ---------------------------------------------------------------------
// Family 4: per-connection memory
// ---------------------------------------------------------------------

/// Connections opened before the first snapshot.
const CONNECTION_BASE: usize = 1;
/// Additional idle connections opened between the two snapshots.
const CONNECTION_DELTA: usize = 64;

/// One HTTP/1.1 keep-alive request over a raw socket, leaving the socket
/// open: the cheapest client that still makes the server allocate its
/// per-connection state. Returns the live stream.
fn open_idle_connection(address: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_nodelay(true).unwrap();
    let request =
        format!("GET /complexity HTTP/1.1\r\nHost: {address}\r\nConnection: keep-alive\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();

    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        let read = stream.read(&mut chunk).unwrap();
        assert!(
            read > 0,
            "the server closed the connection during the request"
        );
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_head_end(&buffer) {
            break position;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let content_length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .expect("a Content-Length header on the response");
    let mut body = buffer.len() - head_end;
    while body < content_length {
        let read = stream.read(&mut chunk).unwrap();
        assert!(read > 0, "the server closed the connection mid-body");
        body += read;
    }
    stream
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn connection_family() {
    println!("\n== family: connections (space cost of one idle keep-alive connection) ==");
    note("connections|method=delta_between_1_and_65_idle_keep_alive_connections_each_after_a_real_request");
    note("connections|courierust_blocking_is_the_legacy_one_pool_job_per_connection_model_kept_as_the_control");

    measure_connections("courierust_event", || {
        let server = Server::bind_with_config(
            "127.0.0.1:0",
            ServerConfig {
                threads: 4,
                ..Default::default()
            },
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let handle = server
            .serve_background(|_request: Request<Body>| {
                Response::<Body>::with_status(200.into())
                    .with_body(Body::Bytes(courierust::Bytes::from_static(b"ok")))
            })
            .unwrap();
        std::mem::forget(handle);
        address
    });

    measure_connections("courierust_blocking", || {
        let server = Server::bind_with_config(
            "127.0.0.1:0",
            ServerConfig {
                event_driven: false,
                threads: 8 + CONNECTION_DELTA + CONNECTION_BASE,
                ..Default::default()
            },
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let handle = server
            .serve_background(|_request: Request<Body>| {
                Response::<Body>::with_status(200.into())
                    .with_body(Body::Bytes(courierust::Bytes::from_static(b"ok")))
            })
            .unwrap();
        std::mem::forget(handle);
        address
    });

    measure_connections("hyper_tokio", || {
        use http_body_util::Full;
        use hyper::body::{Bytes as HyperBytes, Incoming};
        use hyper::service::service_fn;
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto::Builder as AutoBuilder;
        use std::convert::Infallible;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            runtime.block_on(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let _ = stream.set_nodelay(true);
                    let service = service_fn(move |request: hyper::Request<Incoming>| async move {
                        let _ = http_body_util::BodyExt::collect(request.into_body()).await;
                        Ok::<_, Infallible>(hyper::Response::new(Full::new(
                            HyperBytes::from_static(b"ok"),
                        )))
                    });
                    let builder = AutoBuilder::new(TokioExecutor::new()).http1_only();
                    tokio::spawn(async move {
                        let _ = builder
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
        });
        address
    });
}

/// Measure the live-allocation and RSS delta of `CONNECTION_DELTA` idle
/// connections and report it per connection.
fn measure_connections(implementation: &str, spawn: impl Fn() -> SocketAddr) {
    let address = spawn();
    let mut idle = Vec::with_capacity(CONNECTION_BASE + CONNECTION_DELTA);

    for _ in 0..CONNECTION_BASE {
        idle.push(open_idle_connection(address));
    }
    // Let the server finish its bookkeeping before the first snapshot.
    std::thread::sleep(Duration::from_millis(200));
    let base_counters = counters();
    let base_rss = rss_kib();

    for _ in 0..CONNECTION_DELTA {
        idle.push(open_idle_connection(address));
    }
    std::thread::sleep(Duration::from_millis(500));
    let after_counters = counters();
    let after_rss = rss_kib();

    let live_delta = after_counters.live as i64 - base_counters.live as i64;
    let live_kib_per_conn = live_delta as f64 / 1024.0 / CONNECTION_DELTA as f64;
    let rss_per_conn = match (base_rss, after_rss) {
        (Some(base), Some(after)) => {
            Some(after.saturating_sub(base) as f64 / CONNECTION_DELTA as f64)
        }
        _ => None,
    };
    emit_memory(
        "connections",
        implementation,
        CONNECTION_BASE + CONNECTION_DELTA,
        live_kib_per_conn,
        rss_per_conn,
    );
    println!(
        "  {implementation:<22} live {:>8.2} KiB/conn   rss {}",
        live_kib_per_conn,
        match rss_per_conn {
            Some(kib) => format!("{kib:>8.2} KiB/conn"),
            None => String::from("     n/a"),
        }
    );
    drop(idle);
}

// ---------------------------------------------------------------------
// Family 5: DEFLATE (reused vs fresh context)
// ---------------------------------------------------------------------

const DEFLATE_SIZES: [usize; 3] = [1024, 64 * 1024, 1024 * 1024];

enum Pattern {
    Text,
    Bytes,
}

impl Pattern {
    fn build(&self, size: usize) -> Vec<u8> {
        match self {
            Pattern::Text => {
                let unit = b"the quick brown fox jumps over the lazy dog 0123456789 ";
                let mut out = Vec::with_capacity(size);
                while out.len() < size {
                    let take = (size - out.len()).min(unit.len());
                    out.extend_from_slice(&unit[..take]);
                }
                out
            }
            Pattern::Bytes => {
                // Deterministic pseudo-random bytes: no LZ77 matches, so
                // this is the match finder's worst case — nothing can be
                // compressed and the search still runs.
                let mut state = 0x2545_f491_4f6c_dd1du64;
                let mut out = Vec::with_capacity(size);
                while out.len() < size {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    out.extend_from_slice(&state.to_le_bytes());
                }
                out.truncate(size);
                out
            }
        }
    }
}

fn deflate_family() {
    println!("\n== family: deflate (permessage-deflate path: reused vs fresh context) ==");
    note("deflate|methods=courierust_deflater_reused_vs_deflate_sync_fresh|no_third_party_deflate_in_this_workspace_to_compare_against");
    note("deflate|payloads=compressible_text_and_incompressible_bytes");

    for (label, pattern) in [
        ("compressible", Pattern::Text),
        ("incompressible", Pattern::Bytes),
    ] {
        let mut reused_series = Series::default();
        let mut fresh_series = Series::default();
        let mut inflate_series = Series::default();

        for &size in &DEFLATE_SIZES {
            let payload = pattern.build(size);
            let ops = match size {
                0..=4096 => 200,
                4097..=65_536 => 40,
                _ => 10,
            };
            let mut deflater = Deflater::new();
            let mut compressed = Vec::with_capacity(size + 1024);
            // `None` is a legitimate outcome, not a failure: the payload
            // was below the threshold or compression did not pay for
            // itself, and RFC 7692 says such a message is sent with RSV1
            // clear. The cost of the decision *and* of the failed match
            // search is what the measurement reports, and the comment on
            // the row says which outcome it was.
            let compressed_outcome = deflater
                .deflate_message(&payload, &mut compressed)
                .is_some();
            let reused = measure(ops, || {
                let _ = deflater.deflate_message(&payload, &mut compressed);
            });
            let fresh = measure(ops, || {
                std::hint::black_box(deflate_sync(&payload));
            });
            // The permessage-deflate pair: the encoder strips the
            // four-octet sync-flush marker and `inflate_message` puts it
            // back (RFC 7692 §7.2.2), keeping the sliding window across
            // messages — measuring raw `inflate_into` against a
            // permessage-deflate stream would be a framing error, not a
            // speed result. A stored message has nothing to inflate.
            let mut inflater = Inflater::new(15);
            let mut inflated = Vec::with_capacity(size * 2);
            let inflate = compressed_outcome.then(|| {
                assert!(
                    deflater
                        .deflate_message(&payload, &mut compressed)
                        .is_some(),
                    "the same payload must take the same path twice"
                );
                measure(ops, || {
                    inflater
                        .inflate_message(&compressed, &mut inflated, size * 4)
                        .unwrap();
                })
            });
            if !compressed_outcome {
                note(&format!(
                    "deflate|payload={label}|size={size}|outcome=stored_uncompressed|reason=rfc7692_rsv1_clear_no_inflate_measured"
                ));
            } else {
                assert_eq!(inflated.len(), size, "inflate must reproduce the payload");
            }

            println!("{label} {size} bytes ({ops} ops/sample)");
            print_sample("deflate (reused context)", &reused);
            print_sample("deflate (fresh context)", &fresh);
            if let Some(inflate) = &inflate {
                print_sample("inflate (reused buffer)", inflate);
            }

            let reused_op = format!("deflate_reused_{label}");
            let fresh_op = format!("deflate_fresh_{label}");
            let inflate_op = format!("inflate_{label}");
            reused_series.push("deflate", "courierust", &reused_op, size, &reused);
            fresh_series.push("deflate", "courierust", &fresh_op, size, &fresh);
            if let Some(inflate) = &inflate {
                inflate_series.push("deflate", "courierust", &inflate_op, size, inflate);
            }
            emit_ratio(
                "deflate",
                &format!("fresh_vs_reused_{label}"),
                "time_ns",
                size,
                fresh.ns_per_op,
                reused.ns_per_op,
            );
            println!();
        }

        reused_series.emit_fits("deflate", "courierust", &format!("deflate_reused_{label}"));
        fresh_series.emit_fits("deflate", "courierust", &format!("deflate_fresh_{label}"));
        if !inflate_series.time.is_empty() {
            inflate_series.emit_fits("deflate", "courierust", &format!("inflate_{label}"));
        }
    }
}

// ---------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------

fn main() {
    let cores = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(0);
    println!(
        "complexity bench — time and space scaling with mainstream comparisons ({cores} logical cores)"
    );
    note("host=loopback|profile=release|allocator=counting_wrapper_over_the_system_allocator");
    note("method=class_is_named_by_the_median_adjacent_pair_exponent_unless_the_fixed_term_dominates_the_range");
    note("method=max_k_reports_the_worst_pair_and_slope_b_is_the_per_unit_cost_a_is_the_fixed_one");
    note("method=time_is_the_minimum_of_three_repeats_per_point_because_noise_only_ever_inflates_a_measurement");
    note("method=a_ratio_below_1_means_courierust_is_cheaper|rows_are_comparable_only_within_one_run");

    let family = std::env::var("COMPLEXITY_FAMILY").unwrap_or_default();
    let run_all = family.is_empty();

    if run_all || family == "codec" {
        codec_family();
    }
    if run_all || family == "http" {
        http_family();
    }
    if run_all || family == "headers" {
        http_headers_family();
    }
    if run_all || family == "connections" {
        connection_family();
    }
    if run_all || family == "deflate" {
        deflate_family();
    }

    println!("\ndone");
}
