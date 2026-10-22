#![cfg(test)]

use super::*;

#[test]
fn epoch_formats_correctly() {
    assert_eq!(unix_seconds_to_rfc3339(0), "1970-01-01T00:00:00Z");
}

#[test]
fn known_recent_timestamp_formats_correctly() {
    // 2025-01-01T00:00:00Z, a commonly-cited reference value.
    assert_eq!(unix_seconds_to_rfc3339(1_735_689_600), "2025-01-01T00:00:00Z");
}

#[test]
fn now_rfc3339_looks_like_rfc3339() {
    let s = now_rfc3339();
    assert_eq!(s.len(), 20);
    assert!(s.ends_with('Z'));
    assert_eq!(s.as_bytes()[4], b'-');
    assert_eq!(s.as_bytes()[10], b'T');
}
