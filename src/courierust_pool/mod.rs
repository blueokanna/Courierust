//! A work-stealing thread pool for multi-core connection handling.
//!
//! * Each worker keeps a **private LIFO** queue (the most recently added
//!   job is hottest in cache).
//! * A **global FIFO** queue holds externally submitted jobs; workers
//!   drain it only after their local queue is empty.
//! * When both are empty, a worker **steals** the oldest job from a
//!   random peer's local queue bottom (FIFO end — the job the owner is
//!   least likely to touch), which is the classic work-stealing policy
//!   that bounds per-worker idle time while preserving locality.
//! * Idle workers park on a condition variable, so an idle pool burns no
//!   CPU.
//!
//! Worker count defaults to the number of logical cores
//! ([`std::thread::available_parallelism`]), which is what makes
//! connection handling scale across cores.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::{self, JoinHandle};

type Job = Box<dyn FnOnce() + Send + 'static>;

/// Shared pool state visible to every worker.
struct Shared {
    /// Global FIFO of externally submitted jobs.
    global: Mutex<VecDeque<Job>>,
    /// Signaled when a job lands in the global queue or shutdown starts.
    has_work: Condvar,
    /// Weak refs to all workers (for stealing). Weak avoids a cycle.
    workers: Mutex<Vec<Weak<Worker>>>,
    /// Set when the pool is shutting down.
    shutdown: AtomicBool,
    /// Sequence number bumped each time a worker parks; used as a victim
    /// freshness hint.
    park_seq: AtomicUsize,
}

struct Worker {
    id: usize,
    shared: Arc<Shared>,
    /// Private LIFO queue (mutex protects against concurrent steals).
    local: Mutex<VecDeque<Job>>,
    /// The park-sequence value recorded when this worker last went idle.
    idle_seq: AtomicUsize,
}

impl Worker {
    fn run(&self) {
        loop {
            if self.shared.shutdown.load(Ordering::Acquire) {
                return;
            }
            // 1. Local LIFO.
            if let Some(job) = self.local.lock().unwrap().pop_back() {
                run_job(job);
                continue;
            }
            // 2. Global FIFO.
            {
                let mut g = self.shared.global.lock().unwrap();
                if let Some(job) = g.pop_front() {
                    drop(g);
                    run_job(job);
                    continue;
                }
            }
            // 3. Steal the oldest job from a peer's local queue bottom.
            if let Some(job) = self.steal() {
                run_job(job);
                continue;
            }
            // 4. Park until new work arrives or shutdown.
            self.idle_seq.store(
                self.shared.park_seq.fetch_add(1, Ordering::Relaxed) + 1,
                Ordering::Relaxed,
            );
            let mut g = self.shared.global.lock().unwrap();
            while g.is_empty() && !self.shared.shutdown.load(Ordering::Acquire) {
                g = self.shared.has_work.wait(g).unwrap();
            }
        }
    }

    /// Try to steal the oldest job from a random peer.
    fn steal(&self) -> Option<Job> {
        let workers = {
            let w = self.shared.workers.lock().unwrap();
            if w.len() <= 1 {
                return None;
            }
            w.iter()
                .filter_map(|x| x.upgrade())
                .filter(|x| x.id != self.id)
                .collect::<Vec<Arc<Worker>>>()
        };
        if workers.is_empty() {
            return None;
        }
        // Bias toward the worker that has been idle longest (smallest
        // idle_seq) — it is least likely to wake up on its own.
        let victim = workers
            .iter()
            .min_by_key(|w| w.idle_seq.load(Ordering::Relaxed))
            .unwrap();
        let stolen = victim.local.lock().unwrap().pop_front();
        stolen
    }
}

/// Run a job, containing panics so a panicking job cannot kill the
/// worker thread — a worker must survive arbitrary handler failures
/// (including application handlers panicking on crafted input).
fn run_job(job: Job) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
    if let Err(p) = result {
        let msg = p
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());
        eprintln!("courierust pool: job panicked: {msg}");
    }
}

/// A work-stealing thread pool.
pub struct ThreadPool {
    shared: Arc<Shared>,
    workers: Arc<Vec<Arc<Worker>>>,
    handles: Vec<JoinHandle<()>>,
}

impl Default for ThreadPool {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self::with_size(1).expect("pool"))
    }
}

impl ThreadPool {
    /// Create a pool with one worker per logical core.
    pub fn new() -> std::io::Result<Self> {
        let count = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self::with_size(count)
    }

    /// Create a pool with `size` workers.
    pub fn with_size(size: usize) -> std::io::Result<Self> {
        let size = size.max(1);
        let shared = Arc::new(Shared {
            global: Mutex::new(VecDeque::new()),
            has_work: Condvar::new(),
            workers: Mutex::new(Vec::new()),
            shutdown: AtomicBool::new(false),
            park_seq: AtomicUsize::new(0),
        });
        let mut handles = Vec::with_capacity(size);
        let mut worker_arcs = Vec::with_capacity(size);
        for id in 0..size {
            let worker = Arc::new(Worker {
                id,
                shared: shared.clone(),
                local: Mutex::new(VecDeque::new()),
                idle_seq: AtomicUsize::new(0),
            });
            worker_arcs.push(worker.clone());
            shared.workers.lock().unwrap().push(Arc::downgrade(&worker));
            let w2 = worker.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("courierust-worker-{id}"))
                    .spawn(move || w2.run())?,
            );
        }
        Ok(Self {
            shared,
            workers: Arc::new(worker_arcs),
            handles,
        })
    }

    /// Number of workers.
    pub fn len(&self) -> usize {
        self.workers.len()
    }

    /// Whether the pool has no workers.
    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    /// Submit a job. The job runs on whichever worker picks it up.
    pub fn spawn<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        if self.shared.shutdown.load(Ordering::Acquire) {
            return;
        }
        self.shared.global.lock().unwrap().push_back(Box::new(f));
        self.shared.has_work.notify_one();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::Release);
        self.shared.has_work.notify_all();
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn runs_jobs() {
        let pool = ThreadPool::new().unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let n = 128;
        for _ in 0..n {
            let c = counter.clone();
            pool.spawn(move || {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while counter.load(Ordering::SeqCst) < n && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(counter.load(Ordering::SeqCst), n);
    }

    #[test]
    fn jobs_can_spawn_jobs() {
        let pool = Arc::new(ThreadPool::with_size(4).unwrap());
        let counter = Arc::new(AtomicUsize::new(0));
        let n = 32;
        for _ in 0..n {
            let c = counter.clone();
            let p_inner = pool.clone();
            // Jobs that re-submit work through the same pool.
            pool.spawn(move || {
                for _ in 0..4 {
                    let c = c.clone();
                    let p2 = p_inner.clone();
                    p2.spawn(move || {
                        c.fetch_add(1, Ordering::SeqCst);
                    });
                }
            });
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while counter.load(Ordering::SeqCst) < n * 4 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(counter.load(Ordering::SeqCst), n * 4);
    }
}
