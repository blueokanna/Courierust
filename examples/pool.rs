//! Work-stealing thread pool demo — the scheduler under every
//! server/client connection in the crate.
//!
//! The single innovation demonstrated here is *the work-stealing model
//! in isolation*: each worker keeps a private LIFO stack (hot, recently
//! submitted tasks), while a global FIFO queue lets any idle worker
//! steal work from another's tail. Tasks may also submit nested tasks.
//!
//! Run with `cargo run --example pool`.

use courierust::courierust_pool::ThreadPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() -> std::io::Result<()> {
    let pool = ThreadPool::with_size(4)?;
    println!("pool running with {} workers", pool.len());

    // --- 1. Parallel fan-out -----------------------------------------
    let counter = Arc::new(AtomicUsize::new(0));
    let jobs = 4096;
    for _ in 0..jobs {
        let c = counter.clone();
        pool.spawn(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
    }
    wait_until(|| counter.load(Ordering::SeqCst) == jobs);
    assert_eq!(counter.load(Ordering::SeqCst), jobs);
    println!("{jobs} independent jobs completed");

    // --- 2. Nested submission (a task that spawns more tasks) --------
    // ThreadPool is shared through `Arc` (it is not `Clone`); tasks may
    // submit further tasks, which is how a connection handler can fan
    // out sub-work without ever blocking a worker.
    let pool = Arc::new(pool);
    let nested = Arc::new(AtomicUsize::new(0));
    let parent_count = 8;
    let per_parent = 64;
    for _ in 0..parent_count {
        let n = nested.clone();
        let p = pool.clone();
        pool.spawn(move || {
            for _ in 0..per_parent {
                let n = n.clone();
                p.spawn(move || {
                    n.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
    }
    let expected = parent_count * per_parent;
    wait_until(|| nested.load(Ordering::SeqCst) == expected);
    assert_eq!(nested.load(Ordering::SeqCst), expected);
    println!("{parent_count} parent jobs spawned {expected} nested jobs");

    // --- 3. Concurrency: with 4 workers, 8 slow jobs overlap ---------
    // Each job sleeps 50 ms; if the pool really runs 4 jobs at once,
    // the whole batch takes ~100 ms (two waves), not 400 ms. `done`
    // (not `running`) gates the wait, so we never exit before a single
    // job has even started.
    let running = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    for _ in 0..8 {
        let running = running.clone();
        let done = done.clone();
        let peak = peak.clone();
        pool.spawn(move || {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            running.fetch_sub(1, Ordering::SeqCst);
            done.fetch_add(1, Ordering::SeqCst);
        });
    }
    wait_until(|| done.load(Ordering::SeqCst) == 8);
    let elapsed = start.elapsed();
    println!(
        "8 x 50ms jobs finished in {:?} (peak {}/4 workers busy)",
        elapsed,
        peak.load(Ordering::SeqCst)
    );
    assert!(
        peak.load(Ordering::SeqCst) >= 2,
        "the pool should overlap slow jobs across workers"
    );

    println!("pool drops cleanly (workers joined on Drop)");
    Ok(())
}

/// Spin until `cond` is true (the pool exposes no completion signal).
fn wait_until(cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !cond() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(cond(), "timed out waiting for pool jobs");
}
