//! Shared benchmark timing/concurrency helpers: timing, sampling, start-line coordination.

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

/// Per-case sample cap.
pub const MAX_SAMPLES: usize = 2048;

/// Explicit filters for focused studies; reject typos instead of reporting
/// success after accidentally selecting no workloads.
pub struct CaseFilter {
    cases: Vec<String>,
    sizes: Vec<String>,
    servers: Vec<String>,
    pub reverse_order: bool,
}

impl CaseFilter {
    pub fn from_env(cases: &[&str], sizes: &[usize], servers: &[&str]) -> Self {
        fn read(name: &str, allowed: &[&str]) -> Vec<String> {
            match std::env::var(name) {
                Err(std::env::VarError::NotPresent) => {
                    allowed.iter().map(|s| (*s).to_owned()).collect()
                }
                Err(error) => panic!("{name}: {error}"),
                Ok(value) => {
                    let selected: Vec<_> = value.split(',').map(str::to_owned).collect();
                    assert!(
                        selected.iter().all(|s| allowed.contains(&s.as_str())),
                        "{name}: unsupported selection {value:?}; allowed: {allowed:?}"
                    );
                    selected
                }
            }
        }
        let sizes: Vec<_> = sizes.iter().map(usize::to_string).collect();
        let filter = Self {
            cases: read("BENCH_CASES", cases),
            sizes: read(
                "BENCH_BYTES",
                &sizes.iter().map(String::as_str).collect::<Vec<_>>(),
            ),
            servers: read("BENCH_SERVERS", servers),
            reverse_order: match std::env::var("BENCH_REVERSE_ORDER").as_deref() {
                Err(std::env::VarError::NotPresent) | Ok("0") => false,
                Ok("1") => true,
                _ => panic!("BENCH_REVERSE_ORDER must be 0 or 1"),
            },
        };
        println!(
            "META|cases={}|bytes={}|servers={}|reverse_order={}",
            filter.cases.join(","),
            filter.sizes.join(","),
            filter.servers.join(","),
            filter.reverse_order
        );
        filter
    }

    pub fn includes(&self, case: &str, size: usize, server: &str) -> bool {
        self.cases.iter().any(|s| s == case)
            && self.sizes.iter().any(|s| s == &size.to_string())
            && self.servers.iter().any(|s| s == server)
    }
}

/// Stop after a request count (smoke checks) or an elapsed-time budget.
/// Time limits are checked after a complete, validated operation; transport
/// timeouts remain responsible for interrupting a stuck operation.
#[derive(Clone, Copy, Debug)]
pub enum Measurement {
    Requests(usize),
    Duration(Duration),
}

impl Measurement {
    pub fn from_env(requests: usize) -> Self {
        let milliseconds = match std::env::var("BENCH_DURATION_MS") {
            Ok(value) => value
                .parse::<u64>()
                .expect("BENCH_DURATION_MS must be an integer"),
            Err(std::env::VarError::NotPresent) => 1000,
            Err(error) => panic!("BENCH_DURATION_MS: {error}"),
        };
        assert!(
            milliseconds <= 3_600_000,
            "BENCH_DURATION_MS must not exceed one hour"
        );
        if milliseconds == 0 {
            assert!(
                requests > 0,
                "a benchmark must execute at least one request"
            );
            Self::Requests(requests)
        } else {
            Self::Duration(Duration::from_millis(milliseconds))
        }
    }

    fn fields(self) -> String {
        match self {
            Self::Requests(requests) => {
                format!("measurement=requests|target_requests={requests}|target_ms=0")
            }
            Self::Duration(duration) => format!(
                "measurement=duration|target_requests=0|target_ms={}",
                duration.as_millis()
            ),
        }
    }
}

// Algorithm R with deterministic SplitMix64 randomness. The seed is fixed for
// reproducibility, not secrecy. Rejection avoids modulo bias. Unlike sampling
// only the first N calls, this retains observations from the entire run.
struct Reservoir {
    values: Vec<Duration>,
    capacity: usize,
    seen: u64,
    random: u64,
}

impl Reservoir {
    fn new(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            capacity,
            seen: 0,
            random: 0x7265736572766f69,
        }
    }

    fn observe(&mut self, value: Duration) {
        self.seen += 1;
        if self.values.len() < self.capacity {
            self.values.push(value);
        } else if self.capacity != 0 {
            let threshold = self.seen.wrapping_neg() % self.seen;
            let position = loop {
                self.random = self.random.wrapping_add(0x9e3779b97f4a7c15);
                let mut z = self.random;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
                z ^= z >> 31;
                if z >= threshold {
                    break z % self.seen;
                }
            };
            if position < self.capacity as u64 {
                self.values[position as usize] = value;
            }
        }
    }
}

struct Window {
    offset: Duration,
    elapsed: Duration,
    requests: usize,
}

fn measure(
    mut work: impl FnMut(),
    limit: Measurement,
    max_samples: usize,
) -> (Timing, Vec<Window>) {
    match limit {
        Measurement::Requests(count) => assert!(count > 0),
        Measurement::Duration(duration) => assert!(!duration.is_zero()),
    }
    let mut reservoir = Reservoir::new(max_samples);
    let mut windows = Vec::new();
    let mut requests = 0;
    let mut window_requests = 0;
    let mut window_offset = Duration::ZERO;
    let started = Instant::now();
    let elapsed = loop {
        let request_started = Instant::now();
        work();
        let completed = Instant::now();
        reservoir.observe(completed.duration_since(request_started));
        requests += 1;
        window_requests += 1;
        let elapsed = completed.duration_since(started);
        let finished = match limit {
            Measurement::Requests(count) => requests >= count,
            Measurement::Duration(duration) => elapsed >= duration,
        };
        let window_elapsed = elapsed - window_offset;
        if window_elapsed >= Duration::from_secs(1) || finished {
            windows.push(Window {
                offset: window_offset,
                elapsed: window_elapsed,
                requests: window_requests,
            });
            window_offset = elapsed;
            window_requests = 0;
        }
        if finished {
            break elapsed;
        }
    };
    (
        Timing {
            elapsed,
            requests,
            samples: reservoir.values,
        },
        windows,
    )
}

/// Warm up, measure and emit every time window after timing has stopped.
/// Each window shares the complete case identity with its aggregate result.
pub fn measure_comparison(
    case: Comparison<'_>,
    limit: Measurement,
    max_samples: usize,
    mut work: impl FnMut(),
) {
    for _ in 0..case.warmup {
        work();
    }
    let unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis();
    let (timing, windows) = measure(work, limit, max_samples);
    for window in windows {
        println!("WINDOW|protocol={}|case={}|client={}|server={}|mode={}|bytes={}|workers={}|repetition={}|started_unix_ms={unix_ms}|offset_ms={:.3}|elapsed_ms={:.3}|requests={}|rps={:.2}",
            case.protocol, case.case, case.client, case.server, case.mode, case.bytes,
            case.workers, case.repetition, window.offset.as_secs_f64() * 1000.0,
            window.elapsed.as_secs_f64() * 1000.0, window.requests,
            window.requests as f64 / window.elapsed.as_secs_f64());
    }
    report_measured_comparison(case, timing, &limit.fields());
}

/// Timing for one benchmark case.
pub struct Timing {
    pub elapsed: Duration,
    pub requests: usize,
    pub samples: Vec<Duration>,
}

impl Timing {
    pub fn requests_per_second(&self) -> f64 {
        self.requests as f64 / self.elapsed.as_secs_f64()
    }

    pub fn response_megabytes_per_second(&self, response_bytes: usize) -> f64 {
        self.requests_per_second() * response_bytes as f64 / 1_000_000.0
    }

    /// Sorted before percentile reads; min/max/mean/stddev are order-independent.
    pub fn sort_samples(&mut self) {
        self.samples.sort_unstable();
    }

    /// Nearest-rank percentile (µs).
    pub fn percentile_us(&self, percentile: f64) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        let rank = (self.samples.len() as f64 * percentile.clamp(0.0, 1.0)).ceil() as usize;
        let position = rank.saturating_sub(1).min(self.samples.len() - 1);
        Some(self.samples[position].as_secs_f64() * 1_000_000.0)
    }

    pub fn min_us(&self) -> Option<f64> {
        self.samples
            .iter()
            .map(|d| d.as_secs_f64() * 1_000_000.0)
            .min_by(f64::total_cmp)
    }

    pub fn max_us(&self) -> Option<f64> {
        self.samples
            .iter()
            .map(|d| d.as_secs_f64() * 1_000_000.0)
            .max_by(f64::total_cmp)
    }

    /// Arithmetic mean (µs).
    pub fn mean_us(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        let sum: f64 = self.samples.iter().map(|d| d.as_secs_f64()).sum();
        Some(sum / self.samples.len() as f64 * 1_000_000.0)
    }

    /// Population stddev (µs); quantifies tail jitter.
    pub fn stddev_us(&self) -> Option<f64> {
        let mean = self.mean_us()?;
        let variance = self
            .samples
            .iter()
            .map(|d| {
                let v = d.as_secs_f64() * 1_000_000.0 - mean;
                v * v
            })
            .sum::<f64>()
            / self.samples.len() as f64;
        Some(variance.sqrt())
    }

    /// P99/P50: tail factor. ≈1 tight; >3 flags a trackable tail anomaly.
    pub fn tail_ratio(&self) -> Option<f64> {
        let p50 = self.percentile_us(0.50)?;
        let p99 = self.percentile_us(0.99)?;
        (p50 > 0.0).then(|| p99 / p50)
    }

    /// Intra-run coefficient of variation (stddev / mean): jitter within
    /// one run, complementary to the cross-run CV in [`report_repetitions`].
    pub fn cv(&self) -> Option<f64> {
        let mean = self.mean_us()?;
        let stddev = self.stddev_us()?;
        (mean > 0.0).then(|| stddev / mean)
    }
}

/// Coefficient of variation (stddev / mean) of a set of values; `None`
/// for fewer than two samples or a zero mean. Cross-run stability metric
/// for repeatability reporting (P3).
pub fn coefficient_of_variation(values: &[f64]) -> Option<f64> {
    if values.len() < 2 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean == 0.0 {
        return None;
    }
    let variance =
        values.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / values.len() as f64;
    Some(variance.sqrt() / mean)
}

/// One repetition's headline metrics, for cross-run repeatability.
#[derive(Clone, Copy)]
pub struct RunMetrics {
    pub rps: f64,
    pub p50_us: f64,
    pub p99_us: f64,
    pub p999_us: f64,
}

impl RunMetrics {
    /// Extract the headline metrics from a finished run.
    pub fn from_timing(timing: &Timing) -> Self {
        Self {
            rps: timing.requests_per_second(),
            p50_us: timing.percentile_us(0.50).unwrap_or(0.0),
            p99_us: timing.percentile_us(0.99).unwrap_or(0.0),
            p999_us: timing.percentile_us(0.999).unwrap_or(0.0),
        }
    }
}

/// Report a repeatability summary across independent runs (P3): for each
/// headline metric, the cross-run mean / min / max and the coefficient of
/// variation. One `REPSUM` row per metric; a CI job can assert a CV
/// ceiling on a key case.
pub fn report_repetitions(label: &str, runs: &[RunMetrics]) {
    fn summarize(label: &str, name: &str, values: &[f64]) {
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        println!(
            "REPSUM|suite={label}|metric={name}|runs={}|mean={mean:.3}|min={min:.3}|max={max:.3}|cv={}",
            values.len(),
            metric(coefficient_of_variation(values)),
        );
    }
    let rps: Vec<f64> = runs.iter().map(|r| r.rps).collect();
    let p50: Vec<f64> = runs.iter().map(|r| r.p50_us).collect();
    let p99: Vec<f64> = runs.iter().map(|r| r.p99_us).collect();
    let p999: Vec<f64> = runs.iter().map(|r| r.p999_us).collect();
    summarize(label, "rps", &rps);
    summarize(label, "p50_us", &p50);
    summarize(label, "p99_us", &p99);
    summarize(label, "p999_us", &p999);
}

/// Format an optional µs value (2 decimals) or `na`.
pub fn metric(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "na".to_owned())
}

/// Shared deep-stats fields appended to RESULT rows: min/mean/max/stddev/P99.9/tail-ratio.
/// All suites reuse one format; the report script parses by name.
pub fn stats_fields(timing: &Timing) -> String {
    format!(
        "min_us={}|mean_us={}|max_us={}|stddev_us={}|p999_us={}|tail_ratio={}|cv={}",
        metric(timing.min_us()),
        metric(timing.mean_us()),
        metric(timing.max_us()),
        metric(timing.stddev_us()),
        metric(timing.percentile_us(0.999)),
        metric(timing.tail_ratio()),
        metric(timing.cv()),
    )
}

/// Uniform-stride downsample plan so samples still represent the whole run.
fn sample_plan(requests: usize, max_samples: usize) -> (usize, usize) {
    let sample_count = requests.min(max_samples);
    let stride = if sample_count == 0 {
        1
    } else {
        requests.div_ceil(sample_count)
    };
    (sample_count, stride)
}

/// Sequential timing (single worker).
pub fn run_sequential<Work>(requests: usize, max_samples: usize, mut work: Work) -> Timing
where
    Work: FnMut(),
{
    let (sample_count, stride) = sample_plan(requests, max_samples);
    let mut samples = Vec::with_capacity(sample_count);

    let started = Instant::now();
    for index in 0..requests {
        let request_started = (sample_count > 0 && index % stride == 0).then(Instant::now);
        work();
        if let Some(request_started) = request_started {
            samples.push(request_started.elapsed());
        }
    }
    let elapsed = started.elapsed();

    Timing {
        elapsed,
        requests,
        samples,
    }
}

/// Concurrent timing: barrier-aligned start, requests split across workers,
/// per-worker capped sampling merged back; global cap stays worker-independent.
pub fn run_concurrent<MakeWorker>(
    requests: usize,
    workers: usize,
    max_samples: usize,
    make_worker: MakeWorker,
) -> Timing
where
    MakeWorker: Fn(usize) -> Box<dyn FnMut() + Send>,
{
    assert!(
        requests > 0,
        "a benchmark case must have at least one request"
    );
    let active_workers = workers.max(1).min(requests);
    let base = requests / active_workers;
    let remainder = requests % active_workers;
    let counts: Vec<usize> = (0..active_workers)
        .map(|index| base + usize::from(index < remainder))
        .collect();
    let jobs: Vec<Box<dyn FnMut() + Send>> = (0..active_workers).map(make_worker).collect();

    let ready = Arc::new(Barrier::new(active_workers + 1));
    let start_line = Arc::new(Barrier::new(active_workers + 1));

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(active_workers);
        for (index, (mut job, count)) in jobs.into_iter().zip(counts.iter().copied()).enumerate() {
            let ready = ready.clone();
            let start_line = start_line.clone();
            // Keep the global sampling bound independent of worker count.
            let per_worker_max =
                max_samples / active_workers + usize::from(index < max_samples % active_workers);
            let (sample_count, stride) = sample_plan(count, per_worker_max);
            handles.push(scope.spawn(move || {
                let mut samples = Vec::with_capacity(sample_count);
                ready.wait();
                start_line.wait();
                for request_index in 0..count {
                    let request_started =
                        (sample_count > 0 && request_index % stride == 0).then(Instant::now);
                    job();
                    if let Some(request_started) = request_started {
                        samples.push(request_started.elapsed());
                    }
                }
                (index, samples)
            }));
        }

        ready.wait();
        let total_samples = requests.min(max_samples);
        let mut samples = Vec::with_capacity(total_samples);

        let started = Instant::now();
        start_line.wait();
        for handle in handles {
            let (_, worker_samples) = handle.join().expect("benchmark worker panicked");
            samples.extend(worker_samples);
        }
        let elapsed = started.elapsed();

        Timing {
            elapsed,
            requests,
            samples,
        }
    })
}

/// A single independently timed repetition. Keep repetitions separate so
/// downstream reports cannot select only the fastest observation.
pub struct Comparison<'a> {
    pub protocol: &'a str,
    pub case: &'a str,
    pub client: &'a str,
    pub server: &'a str,
    pub mode: &'a str,
    pub bytes: usize,
    pub workers: usize,
    pub repetition: usize,
    pub warmup: usize,
    pub stream_messages: usize,
    pub read_delay_ms: u64,
}

pub fn report_comparison(case: Comparison<'_>, timing: Timing) {
    let fields = Measurement::Requests(timing.requests).fields();
    report_measured_comparison(case, timing, &fields);
}

fn report_measured_comparison(case: Comparison<'_>, mut timing: Timing, fields: &str) {
    timing.sort_samples();
    let stream_messages = case.stream_messages;
    let read_delay_ms = case.read_delay_ms;
    println!(
        "COMPARISON|protocol={}|case={}|client={}|server={}|mode={}|bytes={}|workers={}|repetition={}|warmup={}|status=ok|requests={}|elapsed_ms={:.3}|rps={:.2}|p50_us={}|p95_us={}|p99_us={}|samples={}|{}|{fields}|stream_messages={stream_messages}|read_delay_ms={read_delay_ms}",
        case.protocol, case.case, case.client, case.server, case.mode,
        case.bytes, case.workers, case.repetition, case.warmup,
        timing.requests, timing.elapsed.as_secs_f64() * 1000.0,
        timing.requests_per_second(), metric(timing.percentile_us(0.50)),
        metric(timing.percentile_us(0.95)), metric(timing.percentile_us(0.99)),
        timing.samples.len(), stats_fields(&timing),
    );
}

/// Positive workload settings; malformed values are errors, not silently
/// replaced with defaults that would change the claimed workload.
pub fn setting(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or_else(|| panic!("{name} must be a positive integer")),
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("{name}: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_finishes_a_validated_operation_and_accounts_for_every_window() {
        let mut calls = 0;
        let (timing, windows) = measure(
            || {
                calls += 1;
                std::thread::sleep(Duration::from_millis(2));
            },
            Measurement::Duration(Duration::from_millis(1)),
            8,
        );
        assert_eq!(calls, 1);
        assert_eq!(timing.requests, calls);
        assert!(timing.elapsed >= Duration::from_millis(1));
        assert_eq!(windows.iter().map(|w| w.requests).sum::<usize>(), calls);
        assert_eq!(
            windows.iter().map(|w| w.elapsed).sum::<Duration>(),
            timing.elapsed
        );
    }

    #[test]
    fn reservoir_is_bounded_and_includes_late_observations() {
        for capacity in [0, 1, 128, 2048] {
            let mut reservoir = Reservoir::new(capacity);
            for value in 0..100_000 {
                reservoir.observe(Duration::from_nanos(value));
            }
            assert_eq!(reservoir.values.len(), capacity);
            if capacity >= 128 {
                assert!(reservoir.values.iter().any(|v| v.as_nanos() > 50_000));
            }
        }
    }

    #[test]
    fn request_mode_keeps_the_exact_budget() {
        let (timing, windows) = measure(|| {}, Measurement::Requests(123), 10);
        assert_eq!(timing.requests, 123);
        assert_eq!(timing.samples.len(), 10);
        assert_eq!(windows.iter().map(|w| w.requests).sum::<usize>(), 123);
    }

    #[test]
    fn nearest_rank_percentiles_match_the_documented_estimator() {
        let timing = Timing {
            elapsed: Duration::from_secs(1),
            requests: 4,
            samples: [1, 2, 3, 4].map(Duration::from_micros).to_vec(),
        };
        assert_eq!(timing.percentile_us(0.50), Some(2.0));
        assert_eq!(timing.percentile_us(0.99), Some(4.0));
        assert_eq!(timing.percentile_us(0.0), Some(1.0));
    }

    #[test]
    fn concurrent_samples_respect_the_global_budget() {
        for budget in [0, 1, 3, 10, 32] {
            let timing = run_concurrent(31, 8, budget, |_| Box::new(|| {}));
            assert_eq!(timing.requests, 31);
            assert!(timing.samples.len() <= budget);
            assert_eq!(timing.samples.is_empty(), budget == 0);
        }
    }
}
