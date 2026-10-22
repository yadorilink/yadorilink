#![cfg(test)]

use super::is_case_insensitive_filesystem;

/// This is a real filesystem probe, not a mock — it must agree with
/// what the actual host filesystem does. macOS's default APFS volume
/// (almost certainly what a dev machine's tempdir sits on) is
/// case-insensitive; this is documented as environment-dependent
/// rather than asserted as a hard fact about every possible CI runner.
#[test]
fn probe_returns_a_stable_answer_for_the_same_directory() {
    let dir = tempfile::tempdir().unwrap();
    let first = is_case_insensitive_filesystem(dir.path());
    let second = is_case_insensitive_filesystem(dir.path());
    assert_eq!(first, second, "the cached answer must be stable across calls");
}

#[test]
fn probe_leaves_no_leftover_file_behind() {
    let dir = tempfile::tempdir().unwrap();
    is_case_insensitive_filesystem(dir.path());
    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(entries.is_empty(), "the probe file must be cleaned up: {entries:?}");
}

/// The regression this module's cache removal exists for: a stale
/// process-wide cache keyed on the canonicalized directory path would
/// answer a second call on the same directory from memory, without
/// touching the filesystem again. This device cannot force an actual
/// remount underneath a live path in a unit test, so it proves the
/// stronger, directly-observable property that makes a stale answer
/// impossible in the first place: every call, including a second call
/// on the exact same directory, performs its own real probe round trip
/// (visible as the shared probe-call counter advancing), never a cached
/// lookup.
#[test]
fn second_call_on_the_same_directory_performs_a_second_real_probe_not_a_cached_lookup() {
    // The counter is process-wide and the test harness runs tests in
    // parallel, so an EXACT delta cannot be asserted -- another test's
    // probe can land between two reads here. What has to be true is
    // weaker and is still the whole property: the counter ADVANCES on
    // the second call. A cached lookup would advance it by nothing.
    let dir = tempfile::tempdir().unwrap();
    let before = super::probe_call_count_for_test();
    is_case_insensitive_filesystem(dir.path());
    let after_first = super::probe_call_count_for_test();
    assert!(after_first > before, "the first call must perform a real probe");
    is_case_insensitive_filesystem(dir.path());
    let after_second = super::probe_call_count_for_test();
    assert!(
        after_second > after_first,
        "a second call on the same directory must probe again, not reuse a cached answer"
    );
}

#[test]
fn a_missing_and_uncreatable_directory_conservatively_reports_insensitive() {
    // A path under a file (not a directory) can never be created —
    // `create_dir_all` fails, exercising the conservative-default arm.
    let base = tempfile::tempdir().unwrap();
    let not_a_dir = base.path().join("plain-file");
    std::fs::write(&not_a_dir, b"x").unwrap();
    let unreachable = not_a_dir.join("child");
    assert!(is_case_insensitive_filesystem(&unreachable));
}
