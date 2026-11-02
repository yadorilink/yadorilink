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

#[cfg(unix)]
#[test]
fn the_saved_config_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, store) = store();
    store.set(true, None).unwrap();
    let mode =
        std::fs::metadata(dir.path().join("metrics_config.json")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn an_old_wide_open_config_is_tightened_when_the_store_is_opened() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("metrics_config.json");
    std::fs::write(&file, b"{}").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
    let _store = MetricsConfigStore::new(dir.path());
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        dir_mode,
        "the config directory itself is left alone"
    );
}
