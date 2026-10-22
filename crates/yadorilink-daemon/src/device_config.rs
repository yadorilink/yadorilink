//! Local device identity/configuration consumed by the daemon.
//!
//! YadoriLink has not shipped yet, so this file intentionally accepts only the
//! current `device.json` shape. Development revisions are not a compatibility
//! boundary: stale configs should be recreated by registering the device with
//! the current build instead of being migrated or silently defaulted.

use std::path::PathBuf;

pub use yadorilink_local_storage::device_config::{DeviceConfig, CONFIG_VERSION};

/// The state directory the running daemon uses. `DaemonConfig::from_env` and `run` refuse a
/// placement this process may not use before anything is created, so a daemon that got past
/// startup resolves the same checked directory here.
pub fn config_dir() -> PathBuf {
    yadorilink_fs_platform::state_dir::state_dir()
        .expect("the state directory was checked at daemon startup")
}

/// Where a rebootstrap keeps what it saves of the user's own changes: under the
/// daemon's state directory, outside every folder it syncs.
pub fn recovery_root() -> PathBuf {
    config_dir().join("recovery")
}

/// The part of [`recovery_root`] one device's rebootstraps use. The restart sweep removes every
/// area of a group that never reached its barrier, so two daemons sharing a state directory
/// (as in-process test daemons do) must not share an area directory either: one's sweep would
/// remove the other's rebootstrap in flight.
pub fn recovery_root_of(device_id: &str) -> PathBuf {
    recovery_root().join(device_id)
}

/// Where the versions a rebootstrap set aside stay until the user restores or discards them:
/// under the daemon's state directory, outside every folder it syncs and apart from
/// [`recovery_root`], whose areas end with their rebootstrap.
pub fn recovery_items_root() -> PathBuf {
    config_dir().join("recovery-items")
}

/// The part of [`recovery_items_root`] one device uses: its sweep removes every item directory
/// its own database does not register, so a daemon sharing the state directory must not share
/// the directories either.
pub fn recovery_items_root_of(device_id: &str) -> PathBuf {
    recovery_items_root().join(device_id)
}

/// Whether linking `local_path` would put the recovery area inside the folder or
/// the folder inside the recovery area. The area holds the user's files in a form
/// the sync must never read back as changes, so no linked folder may contain it
/// or lie within it (compared resolved and case-folded, like the other link
/// topology checks).
pub fn link_overlaps_recovery_area(
    local_path: &std::path::Path,
    recovery_root: &std::path::Path,
) -> bool {
    let resolve = |path: &std::path::Path| {
        // The area may not exist yet: resolve its nearest existing ancestor.
        let mut existing = path;
        let mut rest = Vec::new();
        while !existing.exists() {
            let Some(parent) = existing.parent() else { break };
            if let Some(name) = existing.file_name() {
                rest.push(name.to_owned());
            }
            existing = parent;
        }
        let mut resolved = existing.canonicalize().unwrap_or_else(|_| existing.to_path_buf());
        for name in rest.into_iter().rev() {
            resolved.push(name);
        }
        PathBuf::from(yadorilink_fs_platform::canonical_fold::canonical_fold(
            &resolved.to_string_lossy(),
        ))
    };
    let (link, recovery) = (resolve(local_path), resolve(recovery_root));
    link.starts_with(&recovery) || recovery.starts_with(&link)
}

pub fn config_path() -> PathBuf {
    config_dir().join("device.json")
}

#[cfg(windows)]
pub fn control_pipe_name() -> String {
    yadorilink_fs_platform::state_dir::control_pipe_name()
}

#[cfg(windows)]
pub fn shell_ipc_pipe_name() -> String {
    yadorilink_fs_platform::state_dir::shell_ipc_pipe_name()
}

/// Why an existing `device.json` could not be turned into a usable
/// [`DeviceConfig`]. Genuine absence is reported separately as `Ok(None)`.
#[derive(Debug, thiserror::Error)]
pub enum DeviceConfigError {
    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{} is not a valid current device config: {source}", path.display())]
    Corrupt {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// Retained as the explicit fail-fast error for a config written by a newer
    /// build. This is not a migration path: the daemon refuses the file before
    /// touching persistent sync state.
    #[error(
        "device.json version {on_disk_version} is newer than this build supports (supports up to version {supported_version}) — reinstall the version that wrote this file, or recreate the pre-release device registration with the current build"
    )]
    UnsupportedConfigDowngrade { on_disk_version: u32, supported_version: u32 },

    /// A config from an older development revision. There is no migration
    /// path for pre-release configs, but the device this file names is still
    /// registered — the caller must not treat this the same as a corrupt or
    /// absent config (see `UnsupportedConfigDowngrade`, above).
    #[error(
        "device.json version {on_disk_version} is older than this build supports (requires exactly version {supported_version}) — this is a pre-release build with no config migration path"
    )]
    StaleConfigVersion { on_disk_version: u32, supported_version: u32 },
}

/// Reads the current pre-release device config. No legacy fields, missing
/// identity fingerprints, or pre-versioning sentinel are accepted.
pub fn load() -> Result<Option<DeviceConfig>, DeviceConfigError> {
    let path = config_path();
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(DeviceConfigError::Read { path, source }),
    };
    let config: DeviceConfig = serde_json::from_str(&contents)
        .map_err(|source| DeviceConfigError::Corrupt { path, source })?;
    if config.config_version > CONFIG_VERSION {
        return Err(DeviceConfigError::UnsupportedConfigDowngrade {
            on_disk_version: config.config_version,
            supported_version: CONFIG_VERSION,
        });
    }
    if config.config_version < CONFIG_VERSION {
        return Err(DeviceConfigError::StaleConfigVersion {
            on_disk_version: config.config_version,
            supported_version: CONFIG_VERSION,
        });
    }
    Ok(Some(config))
}

#[cfg(test)]
mod tests;
