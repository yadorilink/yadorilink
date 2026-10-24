#![cfg(test)]

use super::*;

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

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// The default headroom is 1% of the volume between a 256 MiB floor and a 2 GiB cap, and
/// never more than a quarter of a tiny volume.
#[test]
fn default_headroom_is_one_percent_clamped_to_floor_and_cap() {
    // Tiny: the floor would swallow the volume, so a quarter of it.
    assert_eq!(effective_headroom_bytes(0, None), 0);
    assert_eq!(effective_headroom_bytes(100 * MIB, None), 25 * MIB);
    // Small: 4 GiB test volume gets the floor, not 1 GiB.
    assert_eq!(effective_headroom_bytes(4 * GIB, None), 256 * MIB);
    // Mid: 1% between floor and cap.
    assert_eq!(effective_headroom_bytes(100 * GIB, None), 100 * GIB / 100);
    // Large and huge: capped.
    assert_eq!(effective_headroom_bytes(228 * GIB, None), 2 * GIB);
    assert_eq!(effective_headroom_bytes(100 * 1024 * GIB, None), 2 * GIB);
}

/// Regression: a 228 GiB disk with 18 GB free used to refuse a 100 MB receive (headroom
/// 11.4 GiB); it now has room, while a receive that really does not fit is still refused.
#[test]
fn big_disk_with_room_takes_a_small_receive_and_refuses_one_that_does_not_fit() {
    let total = 228 * GIB;
    let space = VolumeFreeSpace {
        available_bytes: 18_000_000_000,
        total_bytes: total,
        headroom_bytes: effective_headroom_bytes(total, None),
    };
    assert!(!space.would_breach(100_000_000));
    assert!(space.would_breach(17_000_000_000)); // leaves less than 2 GiB
                                                 // Nearly full big disk: a small receive is refused only when it eats the margin.
    let nearly_full = VolumeFreeSpace { available_bytes: 2 * GIB + 50 * MIB, ..space };
    assert!(!nearly_full.would_breach(10 * MIB));
    assert!(nearly_full.would_breach(100 * MIB));
}

/// The status leaves "waiting" only above headroom + 25%, so free space hovering at the
/// admission line does not flip it.
#[test]
fn recovery_needs_a_margin_above_the_admission_line() {
    let mk = |available_bytes| VolumeFreeSpace {
        available_bytes,
        total_bytes: 1_000_000,
        headroom_bytes: 1000,
    };
    assert!(!mk(1000).recovered());
    assert!(!mk(1001).recovered()); // admission would pass, but not yet "recovered"
    assert!(!mk(1250).recovered());
    assert!(mk(1251).recovered());
}
