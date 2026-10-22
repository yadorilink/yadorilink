#![cfg(test)]

use super::*;

/// The non-parking status read background repair passes gate on. An
/// unknown group is not "in progress" (nothing is running for it), a
/// group mid-startup is, and either terminal phase clears it -- including
/// `Failed`, so a group whose startup genuinely failed still gets its
/// long-horizon repair passes rather than being skipped forever.
#[test]
fn group_startup_in_progress_tracks_only_the_starting_phase() {
    let registry = StartupReadinessRegistry::new();
    assert!(!registry.group_startup_in_progress("never-started"));

    let generation = registry.begin_group_startup("g");
    assert!(registry.group_startup_in_progress("g"));

    registry.mark_group_ready("g", generation);
    assert!(!registry.group_startup_in_progress("g"));

    let retry = registry.begin_group_startup("g");
    assert!(registry.group_startup_in_progress("g"), "a retry re-closes the gate");
    registry.mark_group_failed("g", retry, "disk full");
    assert!(
        !registry.group_startup_in_progress("g"),
        "a failed startup is settled, not still running"
    );
}

#[test]
fn a_group_is_startup_ready_only_after_a_successful_latest_startup() {
    let registry = StartupReadinessRegistry::new();
    assert!(!registry.group_startup_ready("never-started"));
    let first = registry.begin_group_startup("g");
    assert!(!registry.group_startup_ready("g"));
    registry.mark_group_ready("g", first);
    assert!(registry.group_startup_ready("g"));
    let retry = registry.begin_group_startup("g");
    assert!(!registry.group_startup_ready("g"), "a retry re-closes the gate");
    registry.mark_group_failed("g", retry, "disk full");
    assert!(!registry.group_startup_ready("g"));
}

/// A stale completion must not make a newer generation look settled --
/// otherwise a repair pass could run against a half-built index while the
/// current startup is still writing it.
#[test]
fn a_stale_completion_leaves_a_newer_generation_in_progress() {
    let registry = StartupReadinessRegistry::new();
    let stale = registry.begin_group_startup("g");
    let _current = registry.begin_group_startup("g");
    registry.mark_group_ready("g", stale);
    assert!(registry.group_startup_in_progress("g"));
}
