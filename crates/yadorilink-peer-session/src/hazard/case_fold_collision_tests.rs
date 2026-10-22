#![cfg(test)]

use super::case_fold_collision;
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

#[test]
fn detects_a_same_directory_case_fold_collision() {
    let siblings = vec![record("Photo.jpg")];
    let found = case_fold_collision("photo.jpg", &siblings).unwrap();
    assert_eq!(found.path, "Photo.jpg");
}

#[test]
fn does_not_flag_updating_the_same_path_as_a_collision_with_itself() {
    let siblings = vec![record("photo.jpg")];
    assert!(case_fold_collision("photo.jpg", &siblings).is_none());
}

#[test]
fn ignores_a_case_fold_match_in_a_different_directory() {
    let siblings = vec![record("other/Photo.jpg")];
    assert!(case_fold_collision("photo.jpg", &siblings).is_none());
}

#[test]
fn ignores_a_tombstoned_sibling() {
    let mut deleted = record("Photo.jpg");
    deleted.deleted = true;
    let siblings = vec![deleted];
    assert!(case_fold_collision("photo.jpg", &siblings).is_none());
}

#[test]
fn distinct_names_never_collide() {
    let siblings = vec![record("vacation.jpg")];
    assert!(case_fold_collision("photo.jpg", &siblings).is_none());
}

#[test]
fn matches_within_a_nested_directory_too() {
    let siblings = vec![record("albums/Summer/Photo.jpg")];
    let found = case_fold_collision("albums/Summer/photo.jpg", &siblings).unwrap();
    assert_eq!(found.path, "albums/Summer/Photo.jpg");
}

/// The parent DIRECTORY itself can be what case-folds together, not
/// just the final component — "Docs/Report.txt" and "docs/report.txt"
/// resolve to one physical path on a case-insensitive volume even
/// though every path component differs from its counterpart. A
/// byte-exact parent comparison would exclude this pair before the
/// leaf comparison ever ran.
#[test]
fn detects_a_collision_where_the_parent_directory_itself_case_folds() {
    let siblings = vec![record("Docs/Report.txt")];
    let found = case_fold_collision("docs/report.txt", &siblings).unwrap();
    assert_eq!(found.path, "Docs/Report.txt");
}
