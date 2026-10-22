//! Where the host keeps its own files, and where the daemon's provider temp root is.
//!
//! The host owns one private data directory (the "container"). It reports that directory to the
//! daemon, which adopts `<container>\provider` as its provider temp root and creates the
//! `handoff`, `ingest`, `staging` and `domains` directories below it, private to the current
//! user. The host reads materialized bytes out of `handoff` and puts the copies of the user's
//! writes into `ingest`.

use std::path::PathBuf;

/// Refuses, before the host creates or writes anything, a state directory or provider temp root
/// this process may not use (under AppData while packaged). The host calls this first; the
/// accessors below resolve the same checked values afterwards.
pub fn check() -> Result<(), yadorilink_fs_platform::state_dir::StateDirError> {
    use yadorilink_fs_platform::state_dir::{process_override, PathOverride};
    yadorilink_fs_platform::state_dir::state_dir()?;
    process_override(PathOverride::ProviderTempRoot)?;
    Ok(())
}

/// The engine's state directory, outside AppData (see `yadorilink_fs_platform::state_dir`).
fn state_dir() -> PathBuf {
    yadorilink_fs_platform::state_dir::state_dir().expect("the host checked its paths at startup")
}

/// The host's private data directory.
pub fn container() -> PathBuf {
    state_dir().join("host")
}

/// The daemon's provider temp root: the explicitly configured one (the same variable the daemon
/// reads), else `<container>\provider`, which the daemon adopts from the container the host
/// reports.
pub fn temp_root() -> PathBuf {
    yadorilink_fs_platform::state_dir::process_override(
        yadorilink_fs_platform::state_dir::PathOverride::ProviderTempRoot,
    )
    .expect("the host checked its paths at startup")
    .unwrap_or_else(|| container().join("provider"))
}

/// Where the daemon puts verified bytes for the host to take.
pub fn handoff_dir() -> PathBuf {
    temp_root().join("handoff")
}

/// Where the host puts private copies of the user's writes for the daemon to ingest.
pub fn ingest_dir() -> PathBuf {
    temp_root().join("ingest")
}

/// The folder the sync roots are created in, like other sync clients' home folder.
pub fn sync_roots_parent() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join("YadoriLink")
}

/// The file recording which sync root path serves which declared root, one `<root id hex>\t<path>`
/// line each. It is what lets a restarted host reconnect the same roots at the same places, and
/// what `--unregister-all` cleans up without needing the daemon.
pub fn roots_registry_file() -> PathBuf {
    state_dir().join("cfapi_sync_roots.txt")
}
