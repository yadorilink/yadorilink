//! Shared setup for the host's integration tests.
#![allow(dead_code, reason = "each test binary uses a part of this")]

use std::time::Duration;

use tempfile::TempDir;
use yadorilink_embedded_host::{
    CredentialBackend, CredentialConfig, EngineConfig, EngineTuning, KeyMirror, ReleaseProbe,
    WitnessPlacement,
};

/// For a test that only holds in the embedded shape: true when this build is desktop-shaped
/// (a `--workspace` build unifies the daemon's `process-model` feature on) and the test should
/// return. CI's dedicated embedded-shape run sets `YADORILINK_EXPECT_EMBEDDED_SHAPE`, and there
/// a desktop-shaped build is a failure, not a skip.
pub fn desktop_shaped_skip() -> bool {
    if !yadorilink_embedded_host::ordinary_folder_links_supported() {
        return false;
    }
    assert!(
        std::env::var_os("YADORILINK_EXPECT_EMBEDDED_SHAPE").is_none(),
        "this run was to pin the embedded shape, but the daemon's process model is on"
    );
    true
}

static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A data area of its own under the process's state directory.
pub struct Area {
    pub _dir: TempDir,
    pub config: EngineConfig,
}

pub fn area() -> Area {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir_all(dir.path().join("data")).unwrap();
    let config = EngineConfig {
        // No keychain in a test process: a credential file inside the engine's own state
        // directory, and no keyring mirror. Nothing about the engine is process-global.
        credentials: CredentialConfig::new(
            CredentialBackend::File(state.join("credentials.json")),
            KeyMirror::Disabled,
        ),
        config_dir: state,
        block_store_root: dir.path().join("blocks"),
        // The database lives in a directory of its own: the witness directory may not be inside it.
        sync_db_path: dir.path().join("data/sync.sqlite3"),
        provider_temp_root: None,
        machine_id: Some("embedded-host-test-id".to_owned()),
        // The installation witness, outside the engine's data (a persistent directory, as a host keeps it).
        tuning: EngineTuning {
            witness: WitnessPlacement::Persistent(dir.path().join("witness")),
            ..EngineTuning::default()
        },
    };
    Area { _dir: dir, config }
}

pub fn serialized() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The state of a stopped engine goes away with it: poll briefly, because the last thread of
/// the dropped runtime may still be unwinding its own stack.
pub fn released(probe: &ReleaseProbe) -> bool {
    for _ in 0..100 {
        if probe.released() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}
