#![cfg(test)]

use super::*;

fn with_isolated_config_dir<R>(f: impl FnOnce() -> R) -> R {
    let _guard = CONFIG_DIR_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    let result = f();
    std::env::remove_var("YADORILINK_CONFIG_DIR");
    result
}

fn current_config() -> DeviceConfig {
    DeviceConfig {
        device_id: "device-a".into(),
        coordination_addr: "http://127.0.0.1:1".into(),
        signing_public_key: "signing-public".into(),
        config_version: 0,
    }
}

#[test]
fn save_stamps_and_round_trips_the_current_shape() {
    with_isolated_config_dir(|| {
        save(&current_config()).unwrap();

        let loaded = load().unwrap();
        assert_eq!(loaded.config_version, CONFIG_VERSION);
        assert_eq!(loaded.device_id, "device-a");
        assert_eq!(loaded.signing_public_key, "signing-public");
    });
}

#[test]
fn load_rejects_a_pre_versioning_development_config() {
    with_isolated_config_dir(|| {
        std::fs::write(
            config_path().unwrap(),
            r#"{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","nat":{}}"#,
        )
        .unwrap();

        let err = load().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    });
}

#[test]
fn load_requires_the_exact_current_config_version() {
    with_isolated_config_dir(|| {
        std::fs::write(
            config_path().unwrap(),
            format!(
                r#"{{"device_id":"device-a","coordination_addr":"http://127.0.0.1:1","signing_public_key":"signing","config_version":{}}}"#,
                CONFIG_VERSION + 1
            ),
        )
        .unwrap();

        let err = load().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("requires exactly"));
    });
}

#[cfg(unix)]
#[test]
fn write_config_file_sets_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.json");

    write_config_file(&path, "{}").unwrap();

    let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[test]
fn write_config_file_tightens_existing_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.json");
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    write_config_file(&path, "{\"device_id\":\"device-1\"}").unwrap();

    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read_to_string(path).unwrap(), "{\"device_id\":\"device-1\"}");
}

/// Replacing an existing `device.json` must leave either the previous
/// document or the complete new one whichever step the write is cut at; the
/// daemon refuses to start on an empty or partial file.
#[test]
fn an_interrupted_replacement_never_damages_the_existing_config() {
    const OLD: &str = "{\"device_id\":\"the-old-identity\"}";
    const NEW: &str = "{\"device_id\":\"the-new-identity\"}";

    for cut in [WriteStep::TempWritten, WriteStep::TempSynced, WriteStep::Renamed] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.json");
        std::fs::write(&path, OLD).unwrap();

        let result = write_config_file_with(&path, NEW, &mut |step| {
            if step == cut {
                Err(std::io::Error::other("injected failure"))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err(), "the injected failure at {cut:?} must surface");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        if cut == WriteStep::Renamed {
            assert_eq!(on_disk, NEW, "a failure after the rename leaves the complete new file");
        } else {
            assert_eq!(on_disk, OLD, "a failure at {cut:?} must leave the previous file intact");
        }
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "device.json")
            .collect();
        assert!(leftovers.is_empty(), "no temporary file may remain after {cut:?}: {leftovers:?}");
    }
}
