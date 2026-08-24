//! Shared benchmark timing/concurrency helpers: timing, sampling, start-line coordination.

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

/// Per-case sample cap; overshoot is downsampled with a uniform stride.
pub const MAX_SAMPLES: usize = 2048;

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
        let position =
            ((self.samples.len() - 1) as f64 * percentile.clamp(0.0, 1.0)).round() as usize;
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
    let variance = values
        .iter()
        .map(|v| (v - mean) * (v - mean))
        .sum::<f64>()
        / values.len() as f64;
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
    let sample_count = requests.min(max_samples.max(1));
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
        let request_started = (index % stride == 0).then(Instant::now);
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
            let per_worker_max = max_samples.div_ceil(active_workers);
            let (sample_count, stride) = sample_plan(count, per_worker_max);
            handles.push(scope.spawn(move || {
                let mut samples = Vec::with_capacity(sample_count);
                ready.wait();
                start_line.wait();
                for request_index in 0..count {
                    let request_started = (request_index % stride == 0).then(Instant::now);
                    job();
                    if let Some(request_started) = request_started {
                        samples.push(request_started.elapsed());
                    }
                }
                (index, samples)
            }));
        }

        ready.wait();
        let total_samples: usize = counts
            .iter()
            .map(|count| sample_plan(*count, max_samples).0)
            .sum();
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
