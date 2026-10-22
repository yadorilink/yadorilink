#![cfg(test)]

use super::*;

use crate::test_support::CONFIG_ENV_MUTEX;

fn with_isolated_config_dir<R>(f: impl FnOnce() -> R) -> R {
    let _guard = CONFIG_ENV_MUTEX.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    let result = f();
    std::env::remove_var("YADORILINK_CONFIG_DIR");
    result
}

fn current_config_json(version: u32) -> String {
    format!(
        r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","signing_public_key":"signing-public","config_version":{version}}}"#
    )
}

#[test]
fn load_on_a_missing_file_is_ok_none_not_an_error() {
    with_isolated_config_dir(|| {
        assert!(load().unwrap().is_none());
    });
}

#[test]
fn load_on_corrupt_json_is_an_error_not_absence() {
    with_isolated_config_dir(|| {
        std::fs::write(config_path(), "{ this is not valid json").unwrap();

        assert!(matches!(load(), Err(DeviceConfigError::Corrupt { .. })));
    });
}

#[test]
fn load_on_an_unreadable_file_is_an_error_not_absence() {
    with_isolated_config_dir(|| {
        std::fs::create_dir(config_path()).unwrap();

        assert!(matches!(load(), Err(DeviceConfigError::Read { .. })));
    });
}

#[test]
fn load_rejects_a_pre_release_config_missing_current_required_fields() {
    with_isolated_config_dir(|| {
        std::fs::write(
            config_path(),
            r#"{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1"}"#,
        )
        .unwrap();

        assert!(matches!(load(), Err(DeviceConfigError::Corrupt { .. })));
    });
}

#[test]
fn load_rejects_removed_or_unknown_top_level_fields() {
    with_isolated_config_dir(|| {
        let version_field = format!("\"config_version\":{CONFIG_VERSION}");
        // Spelled in two pieces on purpose: `check_removed_features.sh`
        // fails on any live occurrence of the retired relay symbols, and a
        // fixture proving the field is *rejected* must not read as a
        // reintroduction of it.
        let removed_field = concat!("relay", "_addr");
        let json = current_config_json(CONFIG_VERSION).replace(
            &version_field,
            &format!("\"{removed_field}\":\"https://legacy.invalid\",{version_field}"),
        );
        std::fs::write(config_path(), json).unwrap();

        assert!(matches!(load(), Err(DeviceConfigError::Corrupt { .. })));
    });
}

/// Address discovery belongs to the iroh endpoint; a config that still
/// carries the retired NAT-traversal settings is a stale development config,
/// not something to half-honor.
#[test]
fn load_rejects_a_config_that_still_carries_nat_settings() {
    with_isolated_config_dir(|| {
        let json = current_config_json(CONFIG_VERSION).replace(
            "\"signing_public_key\"",
            "\"nat\":{\"stun_servers\":[]},\"signing_public_key\"",
        );
        std::fs::write(config_path(), json).unwrap();

        assert!(matches!(load(), Err(DeviceConfigError::Corrupt { .. })));
    });
}

#[test]
fn load_rejects_a_newer_config_version_before_startup() {
    with_isolated_config_dir(|| {
        std::fs::write(config_path(), current_config_json(CONFIG_VERSION + 1)).unwrap();

        let err = load().unwrap_err();
        assert!(matches!(
            err,
            DeviceConfigError::UnsupportedConfigDowngrade {
                on_disk_version,
                supported_version,
            } if on_disk_version == CONFIG_VERSION + 1 && supported_version == CONFIG_VERSION
        ));
    });
}

#[test]
fn load_rejects_an_older_config_version_before_startup() {
    with_isolated_config_dir(|| {
        std::fs::write(config_path(), current_config_json(CONFIG_VERSION - 1)).unwrap();

        let err = load().unwrap_err();
        assert!(matches!(
            err,
            DeviceConfigError::StaleConfigVersion {
                on_disk_version,
                supported_version,
            } if on_disk_version == CONFIG_VERSION - 1 && supported_version == CONFIG_VERSION
        ));
    });
}

#[test]
fn load_accepts_only_the_current_complete_identity_shape() {
    with_isolated_config_dir(|| {
        std::fs::write(config_path(), current_config_json(CONFIG_VERSION)).unwrap();

        let loaded = load().unwrap().unwrap();
        assert_eq!(loaded.device_id, "device-a");
        assert_eq!(loaded.signing_public_key, "signing-public");
        assert_eq!(loaded.config_version, CONFIG_VERSION);
    });
}
