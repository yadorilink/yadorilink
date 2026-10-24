//! Starting over as a new device on an embedded engine, with the real installation witness: a
//! database restored alone, a witness that is missing under a persistent placement, the
//! refusals that change nothing, what the operation retires, and the next start after it.

#![allow(
    clippy::result_large_err,
    reason = "the host's own error types, as every test of the host returns them"
)]

use std::path::Path;
use std::time::Duration;

use yadorilink_client_core::coordination::device_config::{self, DeviceConfig};
use yadorilink_client_core::error::RefusalReason;
use yadorilink_embedded_host::dto::StartOverProgress;
use yadorilink_embedded_host::{
    AccountCommand, CallError, CallOptions, CancelHandle, Command, CommandOutput, DesktopError,
    EmbeddedHost,
};

mod support;
use support::{area, serialized, Area};

fn within() -> CallOptions {
    CallOptions { deadline: Some(Duration::from_secs(60)), cancel: CancelHandle::new() }
}

/// A registered device: its key and `device.json` in the engine's state directory.
fn register(area: &Area, device_id: &str) {
    let dir = &area.config.config_dir;
    std::fs::create_dir_all(dir).unwrap();
    yadorilink_transport::DeviceSigningKeyPair::load_or_generate(
        dir.join("signing_key"),
        yadorilink_transport::KeyMirror::Disabled,
    )
    .unwrap();
    device_config::save_in(
        dir,
        &DeviceConfig {
            device_id: device_id.into(),
            coordination_addr: "http://127.0.0.1:1".into(),
            signing_public_key: String::new(),
            config_version: device_config::CONFIG_VERSION,
        },
    )
    .unwrap();
}

fn run_once(area: &Area, f: impl FnOnce(&EmbeddedHost)) {
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    f(&host);
    host.stop().unwrap();
}

/// The `database_restored` category the engine reports, if it reports one.
fn restored(host: &EmbeddedHost) -> Option<String> {
    let CommandOutput::Status(status) = host.execute(Command::Status, &within()).unwrap() else {
        panic!("status")
    };
    status
        .attention_reasons
        .iter()
        .find(|reason| reason.key == "database_restored")
        .map(|reason| reason.args.iter().map(|a| a.value.clone()).collect::<Vec<_>>().join(","))
}

fn start_over(
    host: &EmbeddedHost,
    confirmed: bool,
) -> Result<StartOverProgress, Box<DesktopError>> {
    match host.execute(
        Command::Account(AccountCommand::StartOver { confirmed, device_name: "phone".into() }),
        &within(),
    ) {
        Ok(CommandOutput::StartOver(progress)) => Ok(progress),
        Err(CallError::Account(error)) => Err(error),
        other => panic!("unexpected: {other:?}"),
    }
}

fn pending(host: &EmbeddedHost) -> bool {
    let CommandOutput::Account(status) =
        host.execute(Command::Account(AccountCommand::Status), &within()).unwrap()
    else {
        panic!("account status")
    };
    status.start_over_pending
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn replace_dir(from: &Path, to: &Path) {
    std::fs::remove_dir_all(to).unwrap();
    copy_dir(from, to);
}

fn witness_files(area: &Area) -> Vec<std::path::PathBuf> {
    let dir = area._dir.path().join("witness");
    std::fs::read_dir(dir)
        .map(|entries| entries.map(|e| e.unwrap().path()).collect())
        .unwrap_or_default()
}

fn assert_refused(
    result: Result<StartOverProgress, Box<DesktopError>>,
    expected: yadorilink_client_core::error::RefusalReason,
) {
    assert!(
        matches!(result, Err(ref e) if matches!(**e, DesktopError::Refused { reason, .. } if reason == expected)),
        "{result:?}"
    );
}

/// Everything the refusal promises not to touch.
struct Identity {
    key: Vec<u8>,
    device_json: Vec<u8>,
}

impl Identity {
    fn read(area: &Area) -> Self {
        let dir = &area.config.config_dir;
        Self {
            key: std::fs::read(dir.join("signing_key")).unwrap(),
            device_json: std::fs::read(dir.join("device.json")).unwrap(),
        }
    }
}

/// The recovery end to end on a real engine: the unverifiable refusal (the database records a
/// witness, the persistent copy is gone) is reported, the operation refuses without a
/// confirmation and while nothing is refused, then retires the identity and keeps the user's
/// files, and the next engine as the new device starts clean and records the witness again.
#[test]
fn a_missing_witness_is_recovered_by_starting_over_and_the_next_start_is_clean() {
    let _serial = serialized();
    let area = area();
    register(&area, "device-1");
    let user_file = area._dir.path().join("data/photo.jpg");
    std::fs::write(&user_file, b"my photo").unwrap();

    // A healthy engine: nothing is refused, and starting over is not offered.
    run_once(&area, |host| {
        assert_eq!(restored(host), None);
        assert_refused(start_over(host, true), RefusalReason::DatabaseNotRestored);
    });
    assert!(!witness_files(&area).is_empty(), "the first start recorded the witness");

    // The persistent copy is gone beside a database that records a witness.
    for file in witness_files(&area) {
        std::fs::remove_file(file).unwrap();
    }
    let before = Identity::read(&area);
    run_once(&area, |host| {
        assert_eq!(restored(host).as_deref(), Some("unverifiable"));
        assert!(!pending(host));

        // No confirmation, no change.
        assert_refused(start_over(host, false), RefusalReason::StartOverNotConfirmed);
        let now = Identity::read(&area);
        assert_eq!(now.key, before.key);
        assert_eq!(now.device_json, before.device_json);
        assert!(!pending(host));

        let progress = start_over(host, true).expect("confirmed start over");
        assert_eq!(
            progress,
            StartOverProgress::SignInRequired { retired_device_id: "device-1".into() }
        );
        assert!(pending(host), "re-registration is pending");
    });

    // The old identity is kept under retired-devices/, the new key replaced it, and the user's
    // file is where it was.
    let state = &area.config.config_dir;
    let retired = state.join("retired-devices/device-1");
    assert_eq!(std::fs::read(retired.join("signing_key")).unwrap(), before.key);
    assert_eq!(std::fs::read(retired.join("device.json")).unwrap(), before.device_json);
    assert!(!state.join("device.json").exists());
    assert_ne!(std::fs::read(state.join("signing_key")).unwrap(), before.key);
    assert_eq!(std::fs::read(&user_file).unwrap(), b"my photo");

    // Registration (a network step) is stood in for by its local result: the new device's record.
    // The engine opens the database as that device; the witness starts over, nothing is refused.
    device_config::save_in(
        state,
        &DeviceConfig {
            device_id: "device-2".into(),
            coordination_addr: "http://127.0.0.1:1".into(),
            signing_public_key: String::new(),
            config_version: device_config::CONFIG_VERSION,
        },
    )
    .unwrap();
    run_once(&area, |host| assert_eq!(restored(host), None));
    assert!(!witness_files(&area).is_empty(), "the witness was recorded for the new identity");
    // And it stays clean on the start after that.
    run_once(&area, |host| assert_eq!(restored(host), None));
    assert_eq!(std::fs::read(&user_file).unwrap(), b"my photo");
}

/// A database restored alone (an older copy of the data put back; the witness lives elsewhere)
/// is refused as an older generation, and the same recovery ends it.
#[test]
fn a_database_restored_alone_is_recovered_by_starting_over() {
    let _serial = serialized();
    let area = area();
    register(&area, "device-1");
    let data = area._dir.path().join("data");
    let backup = area._dir.path().join("backup");

    run_once(&area, |_| {});
    copy_dir(&data, &backup);
    // Newer opens advance the witness the backup does not hold.
    run_once(&area, |_| {});
    run_once(&area, |_| {});
    replace_dir(&backup, &data);

    run_once(&area, |host| {
        assert_eq!(restored(host).as_deref(), Some("older_generation"));
        let progress = start_over(host, true).expect("confirmed start over");
        assert!(matches!(progress, StartOverProgress::SignInRequired { .. }), "{progress:?}");
    });
    device_config::save_in(
        &area.config.config_dir,
        &DeviceConfig {
            device_id: "device-2".into(),
            coordination_addr: "http://127.0.0.1:1".into(),
            signing_public_key: String::new(),
            config_version: device_config::CONFIG_VERSION,
        },
    )
    .unwrap();
    run_once(&area, |host| assert_eq!(restored(host), None));
    run_once(&area, |host| assert_eq!(restored(host), None));
}

/// Without the recovery the refusal persists for the same device: starting again changes
/// nothing (the guarantee the start over replaces: a sign-out and a registration keep the key).
#[test]
fn without_starting_over_the_refusal_persists_across_restarts() {
    let _serial = serialized();
    let area = area();
    register(&area, "device-1");
    run_once(&area, |_| {});
    for file in witness_files(&area) {
        std::fs::remove_file(file).unwrap();
    }
    run_once(&area, |host| assert_eq!(restored(host).as_deref(), Some("unverifiable")));
    run_once(&area, |host| assert_eq!(restored(host).as_deref(), Some("unverifiable")));
}
