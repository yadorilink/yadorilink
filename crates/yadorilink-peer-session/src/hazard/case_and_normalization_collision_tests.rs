#![cfg(test)]

use super::{case_and_normalization_collision, case_fold_collision, normalization_collision};
use yadorilink_replica_domain::file::FileRecord;

fn record(path: &str) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    }
}

/// The pair neither single-axis check can catch alone: differs in case
/// (`C`/`c`) AND in Unicode normalization form (composed vs decomposed
/// `é`) at once. Real on a volume that is simultaneously
/// case-insensitive and normalization-insensitive (the macOS default).
#[test]
fn detects_a_pair_differing_in_both_case_and_normalization_at_once() {
    let composed_upper = "Caf\u{e9}.txt"; // "Café.txt", composed é
    let decomposed_lower = "cafe\u{301}.txt"; // "café.txt", decomposed é

    // Precondition: prove neither single-axis check catches this pair
    // -- that's the whole point of this test existing.
    let siblings = vec![record(composed_upper)];
    assert!(
        case_fold_collision(decomposed_lower, &siblings).is_none(),
        "precondition: case_fold_collision alone must NOT catch this pair (it doesn't \
         normalize)"
    );
    assert!(
        normalization_collision(decomposed_lower, &siblings).is_none(),
        "precondition: normalization_collision alone must NOT catch this pair (it doesn't \
         case-fold)"
    );

    let found = case_and_normalization_collision(decomposed_lower, &siblings).unwrap();
    assert_eq!(found.path, composed_upper);

    // Symmetric.
    let siblings = vec![record(decomposed_lower)];
    let found = case_and_normalization_collision(composed_upper, &siblings).unwrap();
    assert_eq!(found.path, decomposed_lower);
}

#[test]
fn does_not_flag_updating_the_same_path_as_a_collision_with_itself() {
    let siblings = vec![record("Caf\u{e9}.txt")];
    assert!(case_and_normalization_collision("Caf\u{e9}.txt", &siblings).is_none());
}

#[test]
fn distinct_names_never_collide() {
    let siblings = vec![record("vacation.jpg")];
    assert!(case_and_normalization_collision("Photo.jpg", &siblings).is_none());
}
