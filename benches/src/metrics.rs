//! Shared benchmark timing and concurrency helpers.
//!
//! This module is compiled into every bench binary (`throughput`,
//! `compare`, `concurrency`, `metrics`), and each binary only uses a
//! subset of the helpers (e.g. `throughput` does not report per-request
//! allocations). Items here are intentionally shared rather than dead.

#![allow(dead_code)]

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

pub const MAX_SAMPLES: usize = 2048;

/// Timing data for one benchmark case.
pub struct Timing {
    pub elapsed: Duration,
    pub requests: usize,
    pub samples: Vec<Duration>,
    pub allocations: usize,
}

impl Timing {
    pub fn requests_per_second(&self) -> f64 {
        self.requests as f64 / self.elapsed.as_secs_f64()
    }

    pub fn response_megabytes_per_second(&self, response_bytes: usize) -> f64 {
        self.requests_per_second() * response_bytes as f64 / 1_000_000.0
    }

    pub fn sort_samples(&mut self) {
        self.samples.sort_unstable();
    }

    pub fn percentile_us(&self, percentile: f64) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        let position =
            ((self.samples.len() - 1) as f64 * percentile.clamp(0.0, 1.0)).round() as usize;
        Some(self.samples[position].as_secs_f64() * 1_000_000.0)
    }
}

fn sample_plan(requests: usize, max_samples: usize) -> (usize, usize) {
    let sample_count = requests.min(max_samples.max(1));
    let stride = if sample_count == 0 {
        1
    } else {
        requests.div_ceil(sample_count)
    };
    (sample_count, stride)
}

/// Measure sequential work after all sample storage has been allocated.
pub fn run_sequential<Work, Reset, Snapshot>(
    requests: usize,
    max_samples: usize,
    mut work: Work,
    reset_allocations: Reset,
    snapshot_allocations: Snapshot,
) -> Timing
where
    Work: FnMut(),
    Reset: Fn(),
    Snapshot: Fn() -> usize,
{
    let (sample_count, stride) = sample_plan(requests, max_samples);
    let mut samples = Vec::with_capacity(sample_count);

    reset_allocations();
    let allocations_before = snapshot_allocations();
    let started = Instant::now();
    for index in 0..requests {
        let request_started = (index % stride == 0).then(Instant::now);
        work();
        if let Some(request_started) = request_started {
            samples.push(request_started.elapsed());
        }
    }
    let elapsed = started.elapsed();
    let allocations = snapshot_allocations().saturating_sub(allocations_before);

    Timing {
        elapsed,
        requests,
        samples,
        allocations,
    }
}

/// Measure work distributed across independent worker closures.
pub fn run_concurrent<MakeWorker, Reset, Snapshot>(
    requests: usize,
    workers: usize,
    max_samples: usize,
    make_worker: MakeWorker,
    reset_allocations: Reset,
    snapshot_allocations: Snapshot,
) -> Timing
where
    MakeWorker: Fn(usize) -> Box<dyn FnMut() + Send>,
    Reset: Fn(),
    Snapshot: Fn() -> usize,
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
            let (sample_count, stride) = sample_plan(count, max_samples);
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

        reset_allocations();
        let allocations_before = snapshot_allocations();
        let started = Instant::now();
        start_line.wait();
        for handle in handles {
            let (_, worker_samples) = handle.join().expect("benchmark worker panicked");
            samples.extend(worker_samples);
        }
        let elapsed = started.elapsed();
        let allocations = snapshot_allocations().saturating_sub(allocations_before);

        Timing {
            elapsed,
            requests,
            samples,
            allocations,
        }
    })
}
