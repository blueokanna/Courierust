# courierust_pool

A work-stealing thread pool for multi-core connection handling. This is the "multi-core is explicit" part of Courierust.

## How it works

- Each worker keeps a **private LIFO** queue — the most recently submitted job is hottest in cache, so you want to run it first.
- A **global FIFO** holds externally submitted jobs; workers drain it only after their local queue is empty.
- When both are empty, a worker **steals the oldest job from a random peer's local queue bottom** — the FIFO end, the job the owner is least likely to touch. Classic work-stealing policy: bounds per-worker idle time while preserving locality.
- Idle workers park on a condition variable — **an idle pool burns zero CPU**.

Worker count defaults to `std::thread::available_parallelism()`. That's what makes connection handling actually scale across cores.

## Where it's used

- The server dispatches TLS and HTTP/2 connections (and, in the legacy model, every connection) through the pool.
- The client's h2 drivers run on it.
- Jobs can spawn jobs — a handler that needs to hand off work doesn't deadlock the pool.

## The subtle bits

- `Weak<Worker>` refs in the shared state avoid a reference cycle between the pool and its workers.
- A `park_seq` sequence number is bumped when a worker parks; stealers use it as a freshness hint to pick a victim that's been idle longest.
- Stealing from the bottom (oldest) of a peer's LIFO is deliberate: the owner is about to run the newest job anyway, so taking the oldest one races least.

## Usage

```rust
use courierust::courierust_pool::ThreadPool;

let pool = ThreadPool::new();        // defaults to logical cores
pool.spawn(move || { /* handle a connection */ });
pool.join();
```
