#![cfg(test)]

use super::*;

fn store() -> (tempfile::TempDir, ConsentStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = ConsentStore::new(dir.path());
    (dir, store)
}

/// default disabled consent, and no file written just by
/// reading it.
#[test]
fn fresh_store_reports_default_disabled_state_without_writing_a_file() {
    let (dir, store) = store();
    let state = store.load().unwrap();
    assert_eq!(state, ConsentState::default());
    assert!(!dir.path().join("consent.json").exists());
    assert!(!dir.path().join("reporting").exists());
}

/// opt-in state persistence.
#[test]
fn opt_in_usage_persists_across_a_new_store_instance() {
    let (dir, store) = store();
    let state = store.opt_in_usage().unwrap();
    assert!(state.usage_submission_enabled);
    assert!(state.anonymous_reporter_id.is_some());

    let reopened = ConsentStore::new(dir.path());
    let reloaded = reopened.load().unwrap();
    assert_eq!(reloaded, state);
}

/// ID reset.
#[test]
fn reset_reporter_id_changes_the_id_and_persists_the_change() {
    let (_dir, store) = store();
    let first = store.opt_in_usage().unwrap();
    let first_id = first.anonymous_reporter_id.clone().unwrap();

    let second = store.reset_reporter_id().unwrap();
    let second_id = second.anonymous_reporter_id.clone().unwrap();

    assert_ne!(first_id, second_id);
    assert_eq!(store.load().unwrap().anonymous_reporter_id, Some(second_id));
}

/// the generated ID must never look like (or be derived
/// from) a device ID passed around elsewhere in the daemon — this is
/// mostly structural (this module never receives one), but assert the
/// generator produces a real random UUID each time as a sanity check.
#[test]
fn new_reporter_id_is_random_and_not_a_fixed_or_device_derived_value() {
    let a = new_reporter_id();
    let b = new_reporter_id();
    assert_ne!(a, b);
    assert!(uuid::Uuid::parse_str(&a).is_ok());
    let fake_device_id = "device-a";
    assert_ne!(a, fake_device_id);
}

#[test]
fn disable_all_submission_keeps_the_reporter_id() {
    let (_dir, store) = store();
    let opted_in = store.opt_in_usage().unwrap();
    let id = opted_in.anonymous_reporter_id.clone().unwrap();
    let disabled = store.disable_all_submission().unwrap();
    assert!(disabled.is_fully_disabled());
    assert_eq!(disabled.anonymous_reporter_id, Some(id));
}
