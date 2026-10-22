#![cfg(test)]

use super::*;

#[test]
fn default_state_has_no_network_submission_and_no_reporter_id() {
    let state = ConsentState::default();
    assert!(!state.usage_submission_enabled);
    assert!(!state.error_submission_enabled);
    assert!(state.anonymous_reporter_id.is_none());
    assert!(state.is_fully_disabled());
}

#[test]
fn opt_in_usage_creates_a_reporter_id_only_once() {
    let mut state = ConsentState::default();
    let mut calls = 0;
    state.opt_in_usage(|| {
        calls += 1;
        "id-1".to_string()
    });
    assert_eq!(state.anonymous_reporter_id.as_deref(), Some("id-1"));
    state.opt_in_error_reporting(|| {
        calls += 1;
        "id-2".to_string()
    });
    // Second opt-in reuses the existing ID rather than minting a new
    // one — the generator closure must not be called again.
    assert_eq!(state.anonymous_reporter_id.as_deref(), Some("id-1"));
    assert_eq!(calls, 1);
}

#[test]
fn reset_reporter_id_always_generates_a_fresh_one() {
    let mut state = ConsentState::default();
    state.opt_in_usage(|| "id-1".to_string());
    state.reset_reporter_id(|| "id-2".to_string());
    assert_eq!(state.anonymous_reporter_id.as_deref(), Some("id-2"));
}

#[test]
fn disable_all_submission_clears_flags_but_keeps_reporter_id() {
    let mut state = ConsentState::default();
    state.opt_in_usage(|| "id-1".to_string());
    state.disable_all_submission();
    assert!(state.is_fully_disabled());
    // The ID itself isn't cleared -- only an explicit reset does
    // that (`reset_reporter_id`), so re-enabling later doesn't
    // silently mint a brand new identity the user didn't ask for.
    assert_eq!(state.anonymous_reporter_id.as_deref(), Some("id-1"));
}

#[test]
fn deserializing_an_empty_json_object_yields_the_safe_default() {
    // `#[serde(default)]` on the struct plus a real `Default` impl:
    // an old config file (or one hand-edited to `{}`) must still
    // resolve to "everything off," never to Rust's derived-Default
    // all-false-and-also-prompt-off shape, which is why this isn't
    // `#[derive(Default)]`.
    let state: ConsentState = serde_json::from_str("{}").unwrap();
    assert_eq!(state, ConsentState::default());
    assert!(state.prompt_to_report_enabled);
}
