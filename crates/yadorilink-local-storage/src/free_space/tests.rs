#![cfg(test)]

use super::*;

/// config defaults when unset — the 1 GiB floor wins on a
/// small volume, the 5% figure wins on a large one.
#[test]
fn default_headroom_is_max_of_1gib_and_5_percent() {
    let small_volume = 10 * 1024 * 1024 * 1024u64; // 10 GiB: 5% = 512 MiB < 1 GiB floor
    assert_eq!(effective_headroom_bytes(small_volume, None), DEFAULT_MIN_HEADROOM_BYTES);

    let large_volume = 100 * 1024 * 1024 * 1024u64; // 100 GiB: 5% = 5 GiB > 1 GiB floor
    let expected = (large_volume as f64 * DEFAULT_HEADROOM_PERCENT) as u64;
    assert!(expected > DEFAULT_MIN_HEADROOM_BYTES);
    assert_eq!(effective_headroom_bytes(large_volume, None), expected);
}

/// config round-trip after an explicit override — the
/// override always wins over the formula, regardless of volume size.
#[test]
fn explicit_override_wins_regardless_of_volume_size() {
    assert_eq!(effective_headroom_bytes(1_000_000_000_000, Some(42)), 42);
    assert_eq!(effective_headroom_bytes(0, Some(0)), 0);
}

/// classification boundary behavior at the ok/low/critical
/// thresholds — exercised directly against constructed `VolumeFreeSpace`
/// values (not real disk state) so the boundaries themselves are
/// deterministic.
#[test]
fn classification_boundaries() {
    let mk = |available_bytes| VolumeFreeSpace {
        available_bytes,
        total_bytes: 1_000_000,
        headroom_bytes: 1000,
    };
    assert_eq!(mk(1000).classify(), FreeSpaceState::Critical); // at headroom
    assert_eq!(mk(999).classify(), FreeSpaceState::Critical); // below headroom
    assert_eq!(mk(1001).classify(), FreeSpaceState::Low); // just above headroom
    assert_eq!(mk(2000).classify(), FreeSpaceState::Low); // exactly 2x headroom
    assert_eq!(mk(2001).classify(), FreeSpaceState::Ok); // just above 2x headroom
}

#[test]
fn would_breach_matches_the_critical_boundary() {
    let space =
        VolumeFreeSpace { available_bytes: 1500, total_bytes: 1_000_000, headroom_bytes: 1000 };
    // Writing 400 more leaves 1100 available, still above the 1000 headroom.
    assert!(!space.would_breach(400));
    // Writing 600 more leaves 900 available, below the 1000 headroom.
    assert!(space.would_breach(600));
    // Writing exactly down to the headroom boundary itself breaches
    // (available must stay strictly above headroom, matching `classify`'s
    // `<=` -> critical boundary).
    assert!(space.would_breach(500));
}

/// A real, existing directory resolves via the OS without error — this
/// doesn't assert particular numbers (real disk state), just that the
/// query itself succeeds and returns internally-consistent values.
#[test]
fn classify_volume_queries_a_real_existing_path() {
    let dir = tempfile::tempdir().unwrap();
    let space = classify_volume(dir.path(), None).unwrap();
    assert!(space.total_bytes > 0);
    assert!(space.headroom_bytes > 0);
}

/// A missing `path` must fail this query outright, never silently fall
/// back to reporting free space for whatever volume/drive happens to
/// contain it. Every caller of `classify_volume` relies on exactly
/// this to detect a vanished/unmounted block-store root as a real
/// fault (see `SegmentBlockStore::check_headroom`'s doc comment and
/// `is_source_path_vanished_error` in `yadorilink-local-capture`) --
/// without this guard, `fs2`'s underlying OS call is only path-exact
/// on Unix (`statvfs(2)` needs the exact directory) and is actually
/// volume-relative on Windows (`GetVolumePathNameW` +
/// `GetDiskFreeSpaceW` resolve up to the containing drive root
/// regardless of whether `path` itself exists), so a platform-specific
/// regression here would go undetected by every OTHER test in this
/// module, which only ever exercises a real, existing directory.
#[test]
fn classify_volume_on_a_missing_path_fails_rather_than_reporting_the_containing_volume() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("never-created");
    assert_eq!(
        classify_volume(&missing, None).unwrap_err().kind(),
        std::io::ErrorKind::NotFound,
        "a path that was never created (or was removed out from under this call, e.g. a \
         faulted block-store root) must surface as NotFound, not as a successful query of \
         its containing volume"
    );
}
