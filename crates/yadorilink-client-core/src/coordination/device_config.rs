//! Local config file recording this device's identity and the
//! coordination-plane address to use — written here on successful
//! `yadorilink device register`, read by `yadorilink-daemon` on startup.
//!
//! YadoriLink has not shipped yet. `device.json` therefore has one canonical
//! shape; development builds are not required to read configs written by older
//! development revisions.

use std::path::{Path, PathBuf};

pub use yadorilink_local_storage::device_config::{DeviceConfig, CONFIG_VERSION};

pub use yadorilink_fs_platform::state_dir::StateDirError;

/// The state directory, or the typed refusal when this process may not keep state where it is
/// configured (a packaged app under AppData). Every client writer starts here, before it creates
/// or writes anything.
pub fn config_dir() -> Result<PathBuf, StateDirError> {
    yadorilink_fs_platform::state_dir::state_dir()
}

pub fn config_path() -> Result<PathBuf, StateDirError> {
    Ok(config_dir()?.join("device.json"))
}

pub fn control_socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("YADORILINK_CONTROL_SOCKET") {
        return PathBuf::from(p);
    }
    // Connecting creates nothing, so a refused directory only names a socket nobody listens on.
    yadorilink_fs_platform::state_dir::resolve(
        &yadorilink_fs_platform::state_dir::Env::from_process(),
    )
    .unwrap_or_else(|_| PathBuf::from("."))
    .join("daemon.sock")
}

/// The Windows equivalent of `control_socket_path` — a pipe name, not a
/// filesystem path. Mirrors the daemon's derivation.
#[cfg(windows)]
pub fn control_pipe_name() -> String {
    yadorilink_fs_platform::state_dir::control_pipe_name()
}

pub fn save(cfg: &DeviceConfig) -> Result<(), crate::error::CoreError> {
    save_in(&config_dir()?, cfg)
}

/// [`save`] into the state directory `dir`.
pub fn save_in(dir: &Path, cfg: &DeviceConfig) -> Result<(), crate::error::CoreError> {
    let path = dir.join("device.json");
    if let Some(parent) = path.parent() {
        yadorilink_fs_platform::durable_dir::create_dir_all_durably(parent)?;
    }
    let cfg = DeviceConfig { config_version: CONFIG_VERSION, ..cfg.clone() };
    Ok(write_config_file(&path, &serde_json::to_string_pretty(&cfg)?)?)
}

/// Reads the canonical pre-release device config. No development-version
/// migration or compatibility fallback is attempted.
pub fn load() -> std::io::Result<DeviceConfig> {
    load_in(
        &config_dir().map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?,
    )
}

/// [`load`] from the state directory `dir`.
pub fn load_in(dir: &Path) -> std::io::Result<DeviceConfig> {
    let contents = std::fs::read_to_string(dir.join("device.json"))?;
    let config: DeviceConfig = serde_json::from_str(&contents)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if config.config_version != CONFIG_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "unsupported device.json version {}; this pre-release build requires exactly version {CONFIG_VERSION}. Re-register the device with the current build instead of migrating an old development config",
                config.config_version,
            ),
        ));
    }
    Ok(config)
}

/// The points in [`write_config_file`] after which a crash or I/O error can
/// strike, in order. Tests inject a failure at each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStep {
    TempWritten,
    TempSynced,
    Renamed,
}

/// Replaces `path` atomically. `device.json` is this device's registered
/// identity: the daemon refuses to start on an empty or partial file, so a
/// crash must leave either the previous document or the complete new one.
///
/// A sibling temporary file (owner-only from creation) is written and
/// fsynced, and published over the target by a durable move, so the new name
/// is on disk when this returns.
fn write_config_file(path: &Path, contents: &str) -> std::io::Result<()> {
    write_config_file_with(path, contents, &mut |_| Ok(()))
}

fn write_config_file_with(
    path: &Path,
    contents: &str,
    after: &mut dyn FnMut(WriteStep) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::io::Write;

    let name = path.file_name().map_or_else(|| "device.json".into(), |n| n.to_string_lossy());
    let temporary = path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    // A leftover from an earlier crash would make `create_new` fail forever;
    // the name carries this process's id, so it cannot be another writer's.
    let _ = std::fs::remove_file(&temporary);

    let result = (|| -> std::io::Result<()> {
        let mut file = create_owner_only(&temporary)?;
        file.write_all(contents.as_bytes())?;
        after(WriteStep::TempWritten)?;
        yadorilink_fs_platform::flush::sync_file(&file)?;
        drop(file);
        after(WriteStep::TempSynced)?;
        // A durable publish: the new name is on disk when this returns.
        yadorilink_fs_platform::durable_dir::publish_durably(
            &temporary,
            path,
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        )?;
        after(WriteStep::Renamed)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)?;
    // `mode` is masked by the umask at creation; set it explicitly too.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create_new(true).write(true).open(path)
}

/// `YADORILINK_CONFIG_DIR` is process-global and Rust runs tests concurrently.
#[cfg(test)]
pub(crate) static CONFIG_DIR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests;
