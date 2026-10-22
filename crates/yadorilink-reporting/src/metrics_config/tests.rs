#![cfg(test)]

use super::*;

fn store() -> (tempfile::TempDir, MetricsConfigStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = MetricsConfigStore::new(dir.path());
    (dir, store)
}

/// Default off, and loopback-only if ever enabled without an
/// explicit address override.
#[test]
fn fresh_store_defaults_to_disabled_and_loopback_only() {
    let (dir, store) = store();
    let config = store.load().unwrap();
    assert!(!config.enabled);
    assert!(config.bind_addr.starts_with("127.0.0.1:"));
    assert!(!dir.path().join("metrics_config.json").exists());
}

#[test]
fn set_enables_and_persists_a_custom_bind_addr() {
    let (_dir, store) = store();
    let config = store.set(true, Some("127.0.0.1:9999".to_string())).unwrap();
    assert!(config.enabled);
    assert_eq!(config.bind_addr, "127.0.0.1:9999");

    let reloaded = store.load().unwrap();
    assert_eq!(reloaded, config);
}

#[test]
fn set_without_an_addr_keeps_the_previously_configured_one() {
    let (_dir, store) = store();
    store.set(true, Some("127.0.0.1:9999".to_string())).unwrap();
    let config = store.set(false, None).unwrap();
    assert!(!config.enabled);
    assert_eq!(config.bind_addr, "127.0.0.1:9999");
}
