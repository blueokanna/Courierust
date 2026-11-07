//! Shared atomic accounting operations compatible with the crate's MSRV.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Subtract without wrapping, retrying when another thread changes the counter.
pub(crate) fn saturating_sub(counter: &AtomicUsize, amount: usize, ordering: Ordering) {
    let failure = match ordering {
        Ordering::AcqRel => Ordering::Acquire,
        Ordering::Release => Ordering::Relaxed,
        other => other,
    };
    let mut current = counter.load(failure);
    loop {
        match counter.compare_exchange_weak(
            current,
            current.saturating_sub(amount),
            ordering,
            failure,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtraction_saturates_for_every_supported_ordering() {
        for ordering in [
            Ordering::Relaxed,
            Ordering::Acquire,
            Ordering::Release,
            Ordering::AcqRel,
            Ordering::SeqCst,
        ] {
            let counter = AtomicUsize::new(7);
            saturating_sub(&counter, 0, ordering);
            assert_eq!(counter.load(Ordering::Relaxed), 7);
            saturating_sub(&counter, 3, ordering);
            assert_eq!(counter.load(Ordering::Relaxed), 4);
            saturating_sub(&counter, usize::MAX, ordering);
            assert_eq!(counter.load(Ordering::Relaxed), 0);
            saturating_sub(&counter, 1, ordering);
            assert_eq!(counter.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn concurrent_releases_are_not_lost() {
        let counter = AtomicUsize::new(8 * 10_000);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..10_000 {
                        saturating_sub(&counter, 1, Ordering::AcqRel);
                    }
                });
            }
        });
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }
}
