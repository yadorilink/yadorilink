#![cfg(test)]

use super::*;

#[test]
fn path_lock_reuses_the_same_lock_while_it_is_live() {
    let registry = PathLockRegistry::new();
    let first = registry.path_lock("group-1", "file.txt");
    let second = registry.path_lock("group-1", "file.txt");

    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(registry.live_lock_count(), 1);
}

/// Two paths that only differ by case must serialize through the SAME
/// lock, not two independent ones — otherwise two concurrent
/// materializations for `Photo.jpg`/`photo.jpg` can each acquire a
/// different mutex, both pass the hazard check (neither yet sees the
/// other in the index), and both then write to what is physically one
/// file on a case-insensitive volume.
#[test]
fn path_lock_is_shared_across_a_case_only_difference() {
    let registry = PathLockRegistry::new();
    let first = registry.path_lock("group-1", "Photo.jpg");
    let second = registry.path_lock("group-1", "photo.jpg");

    assert!(
        Arc::ptr_eq(&first, &second),
        "Photo.jpg and photo.jpg must share one lock, or a concurrent pair racing the \
         hazard check can both win it"
    );
    assert_eq!(registry.live_lock_count(), 1);
}

/// Same property as the case-fold test above, for Unicode
/// canonical-equivalence instead: two byte-different spellings of one
/// logical name must not get independent locks either.
#[test]
fn path_lock_is_shared_across_a_normalization_only_difference() {
    let registry = PathLockRegistry::new();
    let composed = registry.path_lock("group-1", "caf\u{e9}.txt");
    let decomposed = registry.path_lock("group-1", "cafe\u{301}.txt");

    assert!(
        Arc::ptr_eq(&composed, &decomposed),
        "the composed and decomposed spellings of the same name must share one lock"
    );
    assert_eq!(registry.live_lock_count(), 1);
}

/// The lock key must dominate `hazard::case_and_normalization_
/// collision`'s combined equivalence, not just the two single-axis
/// checks: a pair differing in BOTH case and normalization at once
/// (`hazard::canonical_fold`'s own doc comment has the reasoning) must
/// share one lock exactly as reliably as a pair differing in only one
/// axis does. `path_lock_fold_key` delegates to `canonical_fold`
/// itself rather than reimplementing an equivalent-looking fold, so
/// this is a consistency guarantee by construction -- this test pins
/// it down as a regression check rather than an implementation detail.
#[test]
fn path_lock_is_shared_across_a_combined_case_and_normalization_difference() {
    let composed_upper = "Caf\u{e9}.txt"; // "Café.txt", composed é
    let decomposed_lower = "cafe\u{301}.txt"; // "café.txt", decomposed é

    let registry = PathLockRegistry::new();
    let a = registry.path_lock("group-1", composed_upper);
    let b = registry.path_lock("group-1", decomposed_lower);
    assert!(
        Arc::ptr_eq(&a, &b),
        "a pair differing in both case and normalization at once must still share one lock"
    );
}

#[test]
fn path_lock_registry_prunes_paths_that_are_no_longer_live() {
    let registry = PathLockRegistry::new();
    let old = registry.path_lock("group-1", "deleted.txt");
    let old_weak = Arc::downgrade(&old);
    drop(old);
    assert!(old_weak.upgrade().is_none());

    let _current = registry.path_lock("group-1", "current.txt");
    assert_eq!(registry.live_lock_count(), 1);
    assert!(!registry.contains_key("group-1", "deleted.txt"));
}
