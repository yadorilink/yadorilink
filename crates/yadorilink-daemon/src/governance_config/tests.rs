#![cfg(test)]

use super::*;

fn store() -> (tempfile::TempDir, GovernanceConfigStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = GovernanceConfigStore::new(dir.path());
    (dir, store)
}

/// Config defaults when unset — no file written just by reading, and
/// the documented default (unlimited, no headroom override) is
/// returned.
#[test]
fn fresh_store_reports_defaults_without_writing_a_file() {
    let (dir, store) = store();
    let config = store.load().unwrap();
    assert_eq!(config, ResourceGovernanceConfig::default());
    assert_eq!(config.upload_limit_bytes_per_sec, 0);
    assert_eq!(config.download_limit_bytes_per_sec, 0);
    assert_eq!(config.headroom_override_bytes, None);
    assert!(!dir.path().join("resource_governance.json").exists());
}

/// Config round-trip after an explicit `limits set`.
#[test]
fn set_limits_persists_across_a_new_store_instance() {
    let (dir, store) = store();
    let config = store.set_limits(1_000_000, 2_000_000).unwrap();
    assert_eq!(config.upload_limit_bytes_per_sec, 1_000_000);
    assert_eq!(config.download_limit_bytes_per_sec, 2_000_000);

    let reopened = GovernanceConfigStore::new(dir.path());
    assert_eq!(reopened.load().unwrap(), config);
}

#[test]
fn set_headroom_override_persists_and_can_be_cleared() {
    let (_dir, store) = store();
    let config = store.set_headroom_override_bytes(Some(5_000_000_000)).unwrap();
    assert_eq!(config.headroom_override_bytes, Some(5_000_000_000));
    assert_eq!(store.load().unwrap().headroom_override_bytes, Some(5_000_000_000));

    let cleared = store.set_headroom_override_bytes(None).unwrap();
    assert_eq!(cleared.headroom_override_bytes, None);
}

/// An old/hand-edited config file that's missing fields (or entirely
/// empty) must still deserialize to the safe default for whichever
/// fields are absent, never a hard error — `#[serde(default)]` plus a
/// real `Default` impl, the same discipline `reporting::ConsentState`
/// already established.
#[test]
fn deserializing_a_partial_or_empty_json_object_fills_in_safe_defaults() {
    let (dir, store) = store();
    std::fs::write(dir.path().join("resource_governance.json"), "{}").unwrap();
    assert_eq!(store.load().unwrap(), ResourceGovernanceConfig::default());

    std::fs::write(
        dir.path().join("resource_governance.json"),
        r#"{"upload_limit_bytes_per_sec": 500}"#,
    )
    .unwrap();
    let config = store.load().unwrap();
    assert_eq!(config.upload_limit_bytes_per_sec, 500);
    assert_eq!(config.download_limit_bytes_per_sec, 0); // filled in, not a hard error
}

#[test]
fn set_limits_of_zero_restores_unlimited() {
    let (_dir, store) = store();
    store.set_limits(1000, 1000).unwrap();
    let config = store.set_limits(0, 0).unwrap();
    assert_eq!(config.upload_limit_bytes_per_sec, 0);
    assert_eq!(config.download_limit_bytes_per_sec, 0);
}
