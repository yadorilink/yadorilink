//! A coarse log2 latency histogram for env-gated diagnostics.
//!
//! One relaxed atomic increment per recorded value, no allocation, no lock.
//! Bucket `b` holds values in `[2^(b-1), 2^b)` nanoseconds (bucket 0 holds
//! zero), so a quoted percentile is a power-of-two lower bound: coarse on
//! purpose, enough to tell microseconds from milliseconds from tens of
//! milliseconds. It lives in this leaf crate only because both the writer
//! gate's own statistics and the daemon's receive-budget counters need the
//! same primitive and this is the lowest crate both already depend on.

use std::sync::atomic::{AtomicU64, Ordering};

/// Number of buckets: zero, then one per bit of a `u64` nanosecond count.
pub const BUCKETS: usize = 65;

pub struct Log2Hist {
    buckets: [AtomicU64; BUCKETS],
}

impl Log2Hist {
    pub const fn new() -> Self {
        Self { buckets: [const { AtomicU64::new(0) }; BUCKETS] }
    }

    fn bucket_of(nanos: u64) -> usize {
        (u64::BITS - nanos.leading_zeros()) as usize
    }

    /// The smallest value bucket `bucket` can hold, in nanoseconds.
    pub fn bucket_floor(bucket: usize) -> u64 {
        if bucket == 0 {
            0
        } else {
            1u64 << (bucket - 1)
        }
    }

    #[inline]
    pub fn record(&self, nanos: u64) {
        self.buckets[Self::bucket_of(nanos)].fetch_add(1, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    /// The bucket floor holding the `q`-th quantile (`0.0..=1.0`), in
    /// nanoseconds; zero when nothing was recorded. Rank is 1-based, so a
    /// p50 of two samples is the first, never a bucket reached once.
    pub fn percentile(&self, q: f64) -> u64 {
        let counts: Vec<u64> = self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).collect();
        let total: u64 = counts.iter().sum();
        if total == 0 {
            return 0;
        }
        let target = ((q.clamp(0.0, 1.0) * total as f64).ceil() as u64).max(1);
        let mut seen = 0u64;
        for (bucket, count) in counts.iter().enumerate() {
            seen += count;
            if seen >= target {
                return Self::bucket_floor(bucket);
            }
        }
        Self::bucket_floor(BUCKETS - 1)
    }

    pub fn reset(&self) {
        for bucket in &self.buckets {
            bucket.store(0, Ordering::Relaxed);
        }
    }
}

impl Default for Log2Hist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_power_of_two_ranges() {
        assert_eq!(Log2Hist::bucket_of(0), 0);
        assert_eq!(Log2Hist::bucket_of(1), 1);
        assert_eq!(Log2Hist::bucket_of(2), 2);
        assert_eq!(Log2Hist::bucket_of(3), 2);
        assert_eq!(Log2Hist::bucket_of(4), 3);
        assert_eq!(Log2Hist::bucket_of(u64::MAX), 64);
        assert_eq!(Log2Hist::bucket_floor(0), 0);
        assert_eq!(Log2Hist::bucket_floor(3), 4);
    }

    #[test]
    fn percentiles_report_bucket_floors_with_one_based_rank() {
        let hist = Log2Hist::new();
        assert_eq!(hist.percentile(0.5), 0, "empty histogram reports zero");
        for _ in 0..98 {
            hist.record(1_000);
        }
        hist.record(1_000_000);
        hist.record(1_000_000);
        assert_eq!(hist.count(), 100);
        assert_eq!(hist.percentile(0.5), 512, "1000ns lands in [512, 1024)");
        assert_eq!(hist.percentile(0.99), 524_288, "1ms lands in [524288, 1048576)");
        hist.reset();
        assert_eq!(hist.count(), 0);
    }
}
