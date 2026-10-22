#![cfg(test)]

use super::is_normalization_insensitive_filesystem;

/// The [`case_insensitive_probe_tests`] counterpart for the
/// normalization axis: a real filesystem probe, not a mock. macOS's
/// default APFS volume normalization-insensitively resolves a composed
/// and decomposed spelling of the same name to one entry; documented as
/// environment-dependent, same as the case-insensitivity probe's own
/// test.
#[test]
fn probe_returns_a_stable_answer_for_the_same_directory() {
    let dir = tempfile::tempdir().unwrap();
    let first = is_normalization_insensitive_filesystem(dir.path());
    let second = is_normalization_insensitive_filesystem(dir.path());
    assert_eq!(first, second, "the answer must be stable across calls");
}

#[test]
fn probe_leaves_no_leftover_file_behind() {
    let dir = tempfile::tempdir().unwrap();
    is_normalization_insensitive_filesystem(dir.path());
    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(entries.is_empty(), "the probe file must be cleaned up: {entries:?}");
}

/// Mirrors `case_insensitive_probe_tests::second_call_on_the_same_
/// directory_performs_a_second_real_probe_not_a_cached_lookup`: every
/// call, including a second one on the same directory, performs its own
/// real probe round trip rather than serving a cached answer.
#[test]
fn second_call_on_the_same_directory_performs_a_second_real_probe_not_a_cached_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let before = super::normalization_probe_call_count_for_test();
    is_normalization_insensitive_filesystem(dir.path());
    let after_first = super::normalization_probe_call_count_for_test();
    assert!(after_first > before, "the first call must perform a real probe");
    is_normalization_insensitive_filesystem(dir.path());
    let after_second = super::normalization_probe_call_count_for_test();
    assert!(
        after_second > after_first,
        "a second call on the same directory must probe again, not reuse a cached answer"
    );
}

#[test]
fn a_missing_and_uncreatable_directory_conservatively_reports_insensitive() {
    let base = tempfile::tempdir().unwrap();
    let not_a_dir = base.path().join("plain-file");
    std::fs::write(&not_a_dir, b"x").unwrap();
    let unreachable = not_a_dir.join("child");
    assert!(is_normalization_insensitive_filesystem(&unreachable));
}
