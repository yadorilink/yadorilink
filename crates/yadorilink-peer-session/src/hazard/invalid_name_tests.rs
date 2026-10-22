#![cfg(test)]

use super::{invalid_name_reason, NamePolicy};

#[test]
fn posix_policy_never_holds_anything_windows_would_reject() {
    for name in ["CON", "con.txt", "COM1", "trailing.", "trailing ", "bad<name>.txt"] {
        assert_eq!(
            invalid_name_reason(NamePolicy::Posix, name),
            None,
            "{name:?} must never be held under a POSIX policy"
        );
    }
}

#[test]
fn windows_policy_holds_a_bare_reserved_name() {
    let reason = invalid_name_reason(NamePolicy::Windows, "CON").unwrap();
    assert!(reason.starts_with(super::HELD_REASON_INVALID_NAME));
}

#[test]
fn windows_policy_holds_a_reserved_name_with_an_extension() {
    // Windows reserves the device name regardless of what follows it.
    assert!(invalid_name_reason(NamePolicy::Windows, "con.txt").is_some());
    assert!(invalid_name_reason(NamePolicy::Windows, "COM1.tar.gz").is_some());
}

#[test]
fn windows_policy_holds_within_a_nested_path() {
    assert!(invalid_name_reason(NamePolicy::Windows, "docs/notes/CON.txt").is_some());
}

#[test]
fn windows_policy_does_not_hold_a_name_that_merely_contains_a_reserved_word() {
    // "CONTRACT.txt" is not "CON" — only an exact stem match reserves.
    assert_eq!(invalid_name_reason(NamePolicy::Windows, "CONTRACT.txt"), None);
    assert_eq!(invalid_name_reason(NamePolicy::Windows, "economics.txt"), None);
}

#[test]
fn windows_policy_holds_trailing_dot_or_space() {
    assert!(invalid_name_reason(NamePolicy::Windows, "notes.").is_some());
    assert!(invalid_name_reason(NamePolicy::Windows, "notes ").is_some());
}

#[test]
fn windows_policy_holds_forbidden_characters() {
    for name in ["a<b.txt", "a>b.txt", "a:b.txt", "a\"b.txt", "a|b.txt", "a?b.txt", "a*b.txt"] {
        assert!(invalid_name_reason(NamePolicy::Windows, name).is_some(), "{name:?}");
    }
}

#[test]
fn windows_policy_does_not_hold_an_ordinary_name() {
    assert_eq!(invalid_name_reason(NamePolicy::Windows, "vacation-photo.jpg"), None);
}
