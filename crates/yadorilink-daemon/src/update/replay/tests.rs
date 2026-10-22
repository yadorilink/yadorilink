#![cfg(test)]

use super::*;

const T1: &str = "2026-10-19T00:00:00Z";
const T2: &str = "2026-10-19T00:00:01Z";

fn store() -> (tempfile::TempDir, ReplayStore) {
    let dir = tempfile::tempdir().unwrap();
    let s = ReplayStore::new(dir.path());
    (dir, s)
}

#[test]
fn first_use_accepts_and_a_newer_one_replaces() {
    let (_d, s) = store();
    assert_eq!(s.accepted("beta"), None);
    s.accept("beta", T1, "a").unwrap();
    s.accept("beta", T2, "b").unwrap();
    assert_eq!(s.accepted("beta").unwrap().generated_at, T2);
}

#[test]
fn an_older_envelope_is_rejected_after_a_newer_one() {
    let (_d, s) = store();
    s.accept("beta", T2, "new").unwrap();
    let err = s.accept("beta", T1, "old").unwrap_err();
    assert!(matches!(err, ReplayError::Older { .. }), "{err}");
    // The rejected value changed nothing.
    assert_eq!(s.accepted("beta").unwrap().generated_at, T2);
}

#[test]
fn equal_generated_at_is_accepted_only_for_the_same_bytes() {
    let (_d, s) = store();
    s.accept("beta", T1, "same").unwrap();
    s.accept("beta", T1, "same").unwrap();
    let err = s.accept("beta", T1, "different").unwrap_err();
    assert_eq!(err, ReplayError::DifferentAtEqual(T1.into()));
}

#[test]
fn the_floor_survives_a_restart_and_is_per_channel() {
    let (d, s) = store();
    s.accept("beta", T2, "new").unwrap();
    let reopened = ReplayStore::new(d.path());
    assert!(matches!(reopened.accept("beta", T1, "old"), Err(ReplayError::Older { .. })));
    // Another channel has its own floor.
    reopened.accept("nightly", T1, "old").unwrap();
}

#[test]
fn only_the_documented_timestamp_form_is_accepted() {
    let (_d, s) = store();
    for bad in [
        "",
        "2026-10-19",
        "2026-10-19T00:00:00+00:00",
        "2026-10-19 00:00:00Z",
        "2026-13-19T00:00:00Z",
        "2026-10-19T00:00:00.5Z",
        "2026-10-19t00:00:00z",
    ] {
        assert!(
            matches!(s.accept("beta", bad, "x"), Err(ReplayError::BadGeneratedAt(_))),
            "{bad:?} must be refused"
        );
    }
    assert_eq!(s.accepted("beta"), None);
}

#[test]
fn damaged_state_fails_closed() {
    let (d, s) = store();
    std::fs::write(d.path().join("update_replay_floor.json"), "{not json").unwrap();
    assert!(matches!(s.accept("beta", T1, "x"), Err(ReplayError::Storage(_))));
    std::fs::write(
        d.path().join("update_replay_floor.json"),
        r#"{"channels":{"beta":{"generated_at":"junk","envelope_sha256":"x"}}}"#,
    )
    .unwrap();
    assert!(matches!(s.accept("beta", T1, "x"), Err(ReplayError::Storage(_))));
}

/// The comparison uses only the server-supplied timestamps: nothing here reads the clock, and a
/// far-future stored value is simply the floor.
#[test]
fn local_clock_is_not_consulted() {
    let (_d, s) = store();
    s.accept("beta", "2999-01-01T00:00:00Z", "future").unwrap();
    assert!(matches!(s.accept("beta", T2, "now"), Err(ReplayError::Older { .. })));
}
