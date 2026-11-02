#![cfg(test)]

use super::{
    is_case_insensitive_filesystem, is_normalization_insensitive_filesystem, probed_folding,
    SCRATCH_DIRS_CREATED,
};

fn scratch_dirs() -> u64 {
    SCRATCH_DIRS_CREATED.with(|n| n.get())
}

/// Guard for the receive path's cost: asking for both folding axes creates and removes ONE
/// scratch directory on the user's volume, not one per axis (a directory create/remove pair
/// is the expensive part of a probe, and a bulk receive asks several times per file).
#[test]
fn both_axes_are_answered_from_one_scratch_directory() {
    let dir = tempfile::tempdir().unwrap();
    let before = scratch_dirs();
    let (case, normalization) = probed_folding(dir.path());
    assert_eq!(scratch_dirs() - before, 1, "one scratch directory for both axes");
    assert!(case.is_some() && normalization.is_some());
    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(entries.is_empty(), "the probe must clean up: {entries:?}");
}

/// The combined probe measures what the separate probes measure, and is never cached.
#[test]
fn the_combined_probe_agrees_with_the_separate_probes_and_probes_again_each_call() {
    let dir = tempfile::tempdir().unwrap();
    let (case, normalization) = probed_folding(dir.path());
    assert_eq!(case, Some(is_case_insensitive_filesystem(dir.path())));
    assert_eq!(normalization, Some(is_normalization_insensitive_filesystem(dir.path())));
    let before = scratch_dirs();
    probed_folding(dir.path());
    probed_folding(dir.path());
    assert_eq!(scratch_dirs() - before, 2, "every call probes for itself");
}

#[test]
fn an_unusable_root_leaves_both_axes_unknown() {
    let base = tempfile::tempdir().unwrap();
    let not_a_dir = base.path().join("plain-file");
    std::fs::write(&not_a_dir, b"x").unwrap();
    assert_eq!(probed_folding(&not_a_dir), (None, None));
}
