#![cfg(test)]

use super::normalization_collision;
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

/// THE case this hazard exists for: a composed `\u{e9}` ("é" as a
/// single precomposed code point) and its canonically-equivalent
/// decomposed spelling (`e` followed by the combining acute accent,
/// U+0301) are byte-different but logically the same name.
#[test]
fn detects_a_composed_vs_decomposed_collision() {
    let composed = "caf\u{e9}.txt";
    let decomposed = "cafe\u{301}.txt";
    assert_ne!(
        composed.as_bytes(),
        decomposed.as_bytes(),
        "the two spellings must actually be different byte sequences for this test to mean \
         anything"
    );

    let siblings = vec![record(composed)];
    let found = normalization_collision(decomposed, &siblings).unwrap();
    assert_eq!(found.path, composed);

    // Symmetric: the composed form must also find the decomposed one.
    let siblings = vec![record(decomposed)];
    let found = normalization_collision(composed, &siblings).unwrap();
    assert_eq!(found.path, decomposed);
}

/// The over-rejection direction: two names that merely *look* similar
/// (share a common prefix, or share the same base letter with no
/// accent at all) are not canonically equivalent and must not collide.
#[test]
fn distinct_names_never_collide() {
    let siblings = vec![record("cafe.txt")]; // plain "e", no accent at all
    assert!(normalization_collision("caf\u{e9}.txt", &siblings).is_none());

    let siblings = vec![record("vacation.jpg")];
    assert!(normalization_collision("photo.jpg", &siblings).is_none());
}

#[test]
fn does_not_flag_updating_the_same_path_as_a_collision_with_itself() {
    let siblings = vec![record("caf\u{e9}.txt")];
    assert!(normalization_collision("caf\u{e9}.txt", &siblings).is_none());
}

#[test]
fn ignores_a_normalization_match_in_a_different_directory() {
    let siblings = vec![record("other/caf\u{e9}.txt")];
    assert!(normalization_collision("cafe\u{301}.txt", &siblings).is_none());
}

#[test]
fn ignores_a_tombstoned_sibling() {
    let mut deleted = record("caf\u{e9}.txt");
    deleted.deleted = true;
    let siblings = vec![deleted];
    assert!(normalization_collision("cafe\u{301}.txt", &siblings).is_none());
}

#[test]
fn matches_within_a_nested_directory_too() {
    let siblings = vec![record("albums/Summer/caf\u{e9}.txt")];
    let found = normalization_collision("albums/Summer/cafe\u{301}.txt", &siblings).unwrap();
    assert_eq!(found.path, "albums/Summer/caf\u{e9}.txt");
}

/// Same parent-directory-itself-aliases case as
/// `case_fold_collision_tests`'s equivalent test, under normalization
/// instead of case-fold: the parent component, not just the leaf, is
/// what's canonically equivalent between the two paths.
#[test]
fn detects_a_collision_where_the_parent_directory_itself_normalizes_the_same() {
    let composed_parent = "caf\u{e9}/Report.txt";
    let decomposed_parent = "cafe\u{301}/Report.txt";
    let siblings = vec![record(composed_parent)];
    let found = normalization_collision(decomposed_parent, &siblings).unwrap();
    assert_eq!(found.path, composed_parent);
}
