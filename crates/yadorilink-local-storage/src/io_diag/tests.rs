#![cfg(test)]

use super::*;

/// Bucketing must round DOWN and never cross an octave, or a
/// percentile comparison between two sweep arms reports a difference
/// the workload did not have.
#[test]
fn bucket_floors_are_monotonic_and_never_exceed_their_input() {
    let mut previous = 0;
    for nanos in [0u64, 1, 7, 8, 9, 15, 16, 1_000, 1_000_000, 3_600_000, 5_000_000, u64::MAX] {
        let bucket = hist_bucket(nanos);
        let floor = hist_bucket_floor(bucket);
        assert!(floor <= nanos, "bucket floor {floor} exceeds its own input {nanos}");
        assert!(bucket >= previous, "bucketing must be monotonic in the input");
        previous = bucket;
    }
}

/// The resolution the sweep actually depends on: 3.6ms and 5.0ms must
/// not land in the same bucket, which plain log2 bucketing would do.
#[test]
fn buckets_separate_the_latencies_this_exists_to_compare() {
    assert_ne!(hist_bucket(3_600_000), hist_bucket(5_000_000));
    let floor = hist_bucket_floor(hist_bucket(3_600_000)) as f64;
    assert!(
        (floor - 3_600_000.0).abs() / 3_600_000.0 < 0.13,
        "a reported percentile must be within ~12% of the real value, got {floor}"
    );
}
