use super::*;

/// `root` is an ancestor-or-self of a path by path segment, not by string
/// prefix.
#[test]
fn an_ancestor_is_decided_by_path_segment_not_by_string_prefix() {
    assert!(is_ancestor_or_self("a", "a") && is_ancestor_or_self("a", "a/x"));
    assert!(!is_ancestor_or_self("a", "ab"), "`ab` shares a string prefix with `a`");
    assert!(!is_ancestor_or_self("a/x", "a"));
}
