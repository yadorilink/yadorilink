#![cfg(test)]

use super::*;

/// The marker is top-level-only, exactly like `.yadorilinkignore`: a
/// same-named file a user keeps inside a subdirectory is their content
/// and must keep syncing.
#[test]
fn only_the_top_level_marker_is_recognized() {
    assert!(is_root_marker_relative_path(".yadorilink-root"));
    assert!(is_root_marker_relative_path("./.yadorilink-root"));
    assert!(!is_root_marker_relative_path("nested/.yadorilink-root"));
    assert!(!is_root_marker_relative_path(".yadorilink-root/inner.txt"));
    assert!(!is_root_marker_relative_path("notes.txt"));
}
