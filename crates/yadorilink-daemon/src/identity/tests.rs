#![cfg(test)]

use super::*;
use yadorilink_ipc_proto::daemonctl::OwnershipRecordStatus as Status;

fn identity(exe: &str, source: &str, config: Option<&Path>) -> RuntimeIdentity {
    RuntimeIdentity::from_inputs(IdentityInputs {
        exe: PathBuf::from(exe),
        install_source: source.into(),
        pid: 4242,
        started_at_unix: 1_700_000_000,
        config_dir: config.map(Path::to_path_buf),
    })
}

#[test]
fn identify_reports_the_documented_fields_for_every_install_layout() {
    // (executable, install_source as detected for it, owner, install_root)
    let cases = [
        (
            "/Applications/YadoriLink.app/Contents/Library/LoginItems/D.app/Contents/MacOS/yadorilink-daemon",
            "app_bundle",
            "gui",
            "/Applications/YadoriLink.app",
        ),
        ("/home/u/.local/lib/yadorilink/1.2.3/yadorilink-daemon", "script", "cli", "/home/u/.local/lib/yadorilink/1.2.3"),
        ("/usr/bin/yadorilink-daemon", "apt", "cli", "/usr/bin"),
        ("/usr/local/bin/yadorilink-daemon", "standalone", "cli", "/usr/local/bin"),
        ("/opt/homebrew/bin/yadorilink-daemon", "homebrew", "cli", "/opt/homebrew/bin"),
        ("C:/Program Files/WindowsApps/Y_1.0/yadorilink-daemon.exe", "microsoft_store", "gui", "C:/Program Files/WindowsApps/Y_1.0"),
        ("/app/yadorilink-daemon", "container", "cli", "/app"),
    ];
    for (exe, source, owner, root) in cases {
        let report = identity(exe, source, None).report();
        assert_eq!(report.install_source, source, "{exe}");
        assert_eq!(report.owner, owner, "{exe}");
        assert_eq!(report.install_root, root, "{exe}");
        assert_eq!(report.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(report.engine_api_version, yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION);
        assert_eq!(report.pid, 4242);
        assert_eq!(report.started_at_unix, 1_700_000_000);
        assert_eq!(report.ownership_status, Status::Missing as i32);
        assert!(report.ownership_record.is_none());
        assert_eq!(report.release_id, "");
    }
}

#[test]
fn the_release_id_comes_from_the_engine_identity_beside_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    let commit = "a".repeat(40);
    let digest = "b".repeat(64);
    std::fs::write(
        dir.path().join("engine-identity.json"),
        format!(r#"{{"public_commit_sha":"{commit}","build_config_digest":"{digest}","engine_api_version":1}}"#),
    )
    .unwrap();
    let exe = dir.path().join("yadorilink-daemon");
    let report = identity(exe.to_str().unwrap(), "script", None).report();
    assert_eq!(report.release_id, format!("{commit}:{digest}"));

    std::fs::write(dir.path().join("engine-identity.json"), b"garbage").unwrap();
    assert_eq!(identity(exe.to_str().unwrap(), "script", None).report().release_id, "");
}

#[test]
fn identify_reports_the_recorded_owner_and_never_writes() {
    let config = tempfile::tempdir().unwrap();
    let me = identity("/usr/local/bin/yadorilink-daemon", "standalone", Some(config.path()));
    assert_eq!(me.report().ownership_status, Status::Missing as i32);
    assert!(!config.path().join(ownership::FILE_NAME).exists(), "identify must not write");

    ownership::write(
        config.path(),
        &OwnershipRecord {
            owner: Owner::Gui,
            install_source: "app_bundle".into(),
            install_root: "/Applications/YadoriLink.app".into(),
            release_id: "r".into(),
            written_at: 99,
        },
    )
    .unwrap();
    let report = me.report();
    assert_eq!(report.ownership_status, Status::Recorded as i32);
    let record = report.ownership_record.unwrap();
    assert_eq!(
        (record.owner.as_str(), record.install_source.as_str(), record.written_at_unix),
        ("gui", "app_bundle", 99)
    );

    std::fs::write(config.path().join(ownership::FILE_NAME), b"{").unwrap();
    let report = me.report();
    assert_eq!(report.ownership_status, Status::Unreadable as i32);
    assert!(!report.ownership_detail.is_empty());
}

#[test]
fn the_first_daemon_records_itself_and_the_same_owner_may_start_again() {
    let config = tempfile::tempdir().unwrap();
    let cli = identity("/usr/local/bin/yadorilink-daemon", "script", Some(config.path()));
    cli.gate_start(config.path()).unwrap();
    let RecordState::Present(record) = ownership::read(config.path()) else { panic!("no record") };
    assert_eq!((record.owner, record.install_source.as_str()), (Owner::Cli, "script"));
    cli.gate_start(config.path()).unwrap();
}

#[test]
fn a_second_owner_is_refused_and_the_record_is_untouched() {
    let config = tempfile::tempdir().unwrap();
    identity("/usr/local/bin/yadorilink-daemon", "script", Some(config.path()))
        .gate_start(config.path())
        .unwrap();
    let before = std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap();

    let app = identity(
        "/Applications/YadoriLink.app/Contents/Helpers/yadorilink-daemon",
        "app_bundle",
        Some(config.path()),
    );
    let refused = app.gate_start(config.path()).unwrap_err();
    assert!(matches!(refused.0, Refusal::ManagedElsewhere { .. }));
    assert!(refused.to_string().contains("script"), "{refused}");
    assert_eq!(std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap(), before);

    // And the other way round.
    let gui_dir = tempfile::tempdir().unwrap();
    app.gate_start(gui_dir.path()).unwrap();
    let refused =
        identity("/usr/bin/yadorilink-daemon", "apt", None).gate_start(gui_dir.path()).unwrap_err();
    assert!(refused.to_string().contains("YadoriLink app"), "{refused}");
}

#[test]
fn another_installation_of_the_same_owner_kind_is_refused_and_the_record_is_untouched() {
    let config = tempfile::tempdir().unwrap();
    identity("/usr/local/bin/yadorilink-daemon", "script", Some(config.path()))
        .gate_start(config.path())
        .unwrap();
    let before = std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap();
    let refused =
        identity("/usr/bin/yadorilink-daemon", "apt", None).gate_start(config.path()).unwrap_err();
    assert!(matches!(refused.0, Refusal::InstallSourceMismatch { .. }), "{refused}");
    assert_eq!(std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap(), before);

    // The same holds between the two desktop installations.
    let app_dir = tempfile::tempdir().unwrap();
    identity("/Applications/Y.app/Contents/MacOS/d", "app_bundle", None)
        .gate_start(app_dir.path())
        .unwrap();
    let refused = identity("C:/Program Files/WindowsApps/Y_1.0/d.exe", "microsoft_store", None)
        .gate_start(app_dir.path())
        .unwrap_err();
    assert!(matches!(refused.0, Refusal::InstallSourceMismatch { .. }), "{refused}");
}

#[test]
fn an_unreadable_record_refuses_every_start() {
    let config = tempfile::tempdir().unwrap();
    std::fs::write(config.path().join(ownership::FILE_NAME), b"nonsense").unwrap();
    for (exe, source) in
        [("/usr/bin/yadorilink-daemon", "apt"), ("/A.app/Contents/MacOS/d", "app_bundle")]
    {
        let refused = identity(exe, source, None).gate_start(config.path()).unwrap_err();
        assert!(matches!(refused.0, Refusal::OwnerUnknown { .. }));
    }
    assert_eq!(std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap(), b"nonsense");
}

#[test]
fn a_failed_first_record_write_refuses_the_start() {
    let root = tempfile::tempdir().unwrap();
    // The config directory does not exist, so install-owner.json cannot be created.
    let gone = root.path().join("not-created");
    let me = identity("/usr/bin/yadorilink-daemon", "apt", Some(&gone));
    let refused = me.gate_start(&gone).expect_err(
        "a start that could not record its owner must fail closed, or another install source can take the data area over later",
    );
    assert!(matches!(refused.0, Refusal::OwnerRecordUnwritable { .. }), "{refused}");
    assert!(!refused.to_string().contains("Restore or remove"), "{refused}");
}

fn install_with_identity(body: &str) -> (tempfile::TempDir, String) {
    let install = tempfile::tempdir().unwrap();
    std::fs::write(install.path().join("engine-identity.json"), body).unwrap();
    let exe = install.path().join("yadorilink-daemon").display().to_string();
    (install, exe)
}

fn identity_json(api: u32) -> String {
    format!(
        r#"{{"public_commit_sha":"{}","build_config_digest":"{}","engine_api_version":{api}}}"#,
        "a".repeat(40),
        "b".repeat(64)
    )
}

#[test]
fn a_matching_descriptor_starts_and_is_recorded() {
    let config = tempfile::tempdir().unwrap();
    let (_install, exe) =
        install_with_identity(&identity_json(yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION));
    identity(&exe, "script", Some(config.path())).gate_start(config.path()).unwrap();
    let RecordState::Present(record) = ownership::read(config.path()) else { panic!("no record") };
    assert_eq!(record.release_id, format!("{}:{}", "a".repeat(40), "b".repeat(64)));
}

#[test]
fn an_unreadable_descriptor_refuses_the_start_and_writes_nothing() {
    for body in ["garbage", r#"{"public_commit_sha":"a"}"#, ""] {
        let config = tempfile::tempdir().unwrap();
        let (_install, exe) = install_with_identity(body);
        let refused = identity(&exe, "script", Some(config.path()))
            .gate_start(config.path())
            .expect_err("an unreadable descriptor must stop the start");
        assert!(matches!(refused.0, Refusal::DescriptorUnusable { .. }), "{refused}");
        assert!(refused.to_string().contains("cannot be read"), "{refused}");
        assert!(
            std::fs::read_dir(config.path()).unwrap().next().is_none(),
            "nothing may be written"
        );
    }
}

#[test]
fn a_bundle_for_another_engine_api_refuses_the_start_even_over_a_recorded_owner() {
    let config = tempfile::tempdir().unwrap();
    // The recorded owner would otherwise be allowed to proceed.
    identity("/usr/local/bin/yadorilink-daemon", "script", Some(config.path()))
        .gate_start(config.path())
        .unwrap();
    let before = std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap();
    let (_install, exe) =
        install_with_identity(&identity_json(yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION + 1));
    let refused = identity(&exe, "script", Some(config.path()))
        .gate_start(config.path())
        .expect_err("a mixed bundle must stop the start");
    assert!(matches!(refused.0, Refusal::DescriptorUnusable { .. }), "{refused}");
    assert!(refused.to_string().contains("mixes two builds"), "{refused}");
    assert_eq!(std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap(), before);
}

/// N -> N+1 interrupted while the new daemon refreshes the release in the owner record (large-tree
/// acceptance, update case): whatever point the power fails at, the record is the old or
/// the new one with the same owner, the other owner is still refused, and the next start finishes.
#[test]
fn an_update_interrupted_while_the_record_is_refreshed_never_leaves_a_stale_owner_bypass() {
    use yadorilink_fs_platform::durable_dir::{arm_failpoint, disarm_failpoint, NsFailpoint};

    let json = |digest: &str| {
        format!(
            r#"{{"public_commit_sha":"{}","build_config_digest":"{digest}","engine_api_version":{}}}"#,
            "a".repeat(40),
            yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION
        )
    };
    for point in [NsFailpoint::AfterStage, NsFailpoint::BeforeMove, NsFailpoint::AfterMove] {
        let config = tempfile::tempdir().unwrap();
        let (_n, exe_n) = install_with_identity(&json(&"1".repeat(64)));
        let (_n1, exe_n1) = install_with_identity(&json(&"2".repeat(64)));
        identity(&exe_n, "script", Some(config.path())).gate_start(config.path()).unwrap();
        let RecordState::Present(old) = ownership::read(config.path()) else { panic!("no record") };

        arm_failpoint(point);
        let interrupted =
            identity(&exe_n1, "script", Some(config.path())).gate_start(config.path());
        disarm_failpoint();
        assert!(
            matches!(interrupted.unwrap_err().0, Refusal::OwnerRecordUnwritable { .. }),
            "{point:?}: a start whose record cannot be refreshed does not happen"
        );
        let RecordState::Present(now) = ownership::read(config.path()) else {
            panic!("{point:?}: the record must stay readable")
        };
        assert_eq!((now.owner, &now.install_source), (Owner::Cli, &"script".to_string()));
        assert!(now.release_id == old.release_id || now.release_id.contains(&"2".repeat(64)));

        let app = identity(
            "/Applications/YadoriLink.app/Contents/Helpers/yadorilink-daemon",
            "app_bundle",
            Some(config.path()),
        );
        assert!(
            matches!(
                app.gate_start(config.path()).unwrap_err().0,
                Refusal::ManagedElsewhere { .. }
            ),
            "{point:?}: the other owner is still refused"
        );
        identity(&exe_n1, "script", Some(config.path())).gate_start(config.path()).unwrap();
        let RecordState::Present(done) = ownership::read(config.path()) else { panic!("gone") };
        assert!(done.release_id.contains(&"2".repeat(64)), "{point:?}: {done:?}");
    }
}

fn open_handoff(
    config: &std::path::Path,
    phase: yadorilink_local_storage::handoff::journal::Phase,
) {
    use yadorilink_local_storage::handoff::journal::{self, Journal};
    let record = |owner, source: &str| ownership::OwnershipRecord {
        owner,
        install_source: source.into(),
        install_root: "/x".into(),
        release_id: String::new(),
        written_at: 1,
    };
    let mut j = Journal::new(
        record(Owner::Cli, "script"),
        record(Owner::Gui, "app_bundle"),
        true,
        Vec::new(),
        1,
    );
    j.phase = phase;
    journal::write(config, &j).unwrap();
}

#[test]
fn no_daemon_of_either_owner_starts_while_a_hand_off_is_half_applied() {
    use yadorilink_local_storage::handoff::journal::Phase;
    let app = || {
        identity(
            "/Applications/YadoriLink.app/Contents/Helpers/yadorilink-daemon",
            "app_bundle",
            None,
        )
    };
    let cli = || identity("/usr/local/bin/yadorilink-daemon", "script", None);
    for (owner_dir_owner, phase) in [
        (0, Phase::Switching),
        (1, Phase::Switching),
        (0, Phase::RollingBack),
        (1, Phase::RollingBack),
    ] {
        let config = tempfile::tempdir().unwrap();
        // The record on disk is whichever owner the interrupted switch got to.
        if owner_dir_owner == 0 { cli() } else { app() }.gate_start(config.path()).unwrap();
        let before = std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap();
        open_handoff(config.path(), phase);
        for refused in [cli().gate_start(config.path()), app().gate_start(config.path())] {
            let refused = refused.unwrap_err();
            assert!(matches!(refused.0, Refusal::HandoffUnfinished { .. }), "{refused}");
            assert!(refused.to_string().contains("release-to-app"), "{refused}");
        }
        assert_eq!(std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap(), before);
    }
}

#[test]
fn a_hand_off_that_changed_nothing_or_is_complete_does_not_block_a_start() {
    use yadorilink_local_storage::handoff::journal::Phase;
    for phase in [Phase::Planned, Phase::Stopped] {
        let config = tempfile::tempdir().unwrap();
        let cli = identity("/usr/local/bin/yadorilink-daemon", "script", None);
        cli.gate_start(config.path()).unwrap();
        open_handoff(config.path(), phase);
        cli.gate_start(config.path()).unwrap();
    }
    // Released: the record names the app, so the app starts and the old install does not.
    let config = tempfile::tempdir().unwrap();
    let app = identity(
        "/Applications/YadoriLink.app/Contents/Helpers/yadorilink-daemon",
        "app_bundle",
        None,
    );
    app.gate_start(config.path()).unwrap();
    open_handoff(config.path(), Phase::Switched);
    app.gate_start(config.path()).unwrap();
    let cli = identity("/usr/local/bin/yadorilink-daemon", "script", None);
    assert!(matches!(
        cli.gate_start(config.path()).unwrap_err().0,
        Refusal::ManagedElsewhere { .. }
    ));
}

fn record_of(config: &Path) -> ownership::OwnershipRecord {
    let RecordState::Present(record) = ownership::read(config) else { panic!("no record") };
    record
}

#[test]
fn a_daemon_of_a_newer_release_refreshes_the_release_in_its_own_record() {
    let config = tempfile::tempdir().unwrap();
    let (_old, old_exe) =
        install_with_identity(&identity_json(yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION));
    identity(&old_exe, "script", Some(config.path())).gate_start(config.path()).unwrap();
    let first = record_of(config.path());
    assert_eq!(first.release_id, format!("{}:{}", "a".repeat(40), "b".repeat(64)));

    // The self-updated install: same installation, another build.
    let (_new, new_exe) = install_with_identity(&format!(
        r#"{{"public_commit_sha":"{}","build_config_digest":"{}","engine_api_version":{}}}"#,
        "c".repeat(40),
        "d".repeat(64),
        yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION
    ));
    let updated = identity(&new_exe, "script", Some(config.path()));
    updated.gate_start(config.path()).unwrap();
    let refreshed = record_of(config.path());
    assert_eq!(refreshed.release_id, format!("{}:{}", "c".repeat(40), "d".repeat(64)));
    // Only the release and the time move: the owner and the installation stay what they were.
    assert_eq!(
        (refreshed.owner, &refreshed.install_source, &refreshed.install_root),
        (first.owner, &first.install_source, &first.install_root)
    );
    assert_eq!(updated.report().ownership_record.unwrap().release_id, refreshed.release_id);

    // Starting the same release again changes nothing on disk.
    let before = std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap();
    updated.gate_start(config.path()).unwrap();
    assert_eq!(std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap(), before);
}

#[test]
fn another_installation_never_rewrites_a_record_it_is_refused_by() {
    let config = tempfile::tempdir().unwrap();
    let (_install, exe) =
        install_with_identity(&identity_json(yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION));
    identity(&exe, "script", Some(config.path())).gate_start(config.path()).unwrap();
    let before = std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap();
    // Another build of another installation: refused, record untouched.
    let refused = identity("/usr/bin/yadorilink-daemon", "apt", Some(config.path()))
        .gate_start(config.path())
        .unwrap_err();
    assert!(matches!(refused.0, Refusal::InstallSourceMismatch { .. }));
    assert_eq!(std::fs::read(config.path().join(ownership::FILE_NAME)).unwrap(), before);
}

#[test]
fn an_open_hand_off_keeps_the_record_for_itself() {
    use yadorilink_local_storage::handoff::journal::Phase;
    let config = tempfile::tempdir().unwrap();
    let app = identity(
        "/Applications/YadoriLink.app/Contents/Helpers/yadorilink-daemon",
        "app_bundle",
        None,
    );
    app.gate_start(config.path()).unwrap();
    // The recorded release is not the app daemon's; the hand-off decides what the record says.
    let mut stale = record_of(config.path());
    stale.release_id = "e:f".into();
    ownership::write(config.path(), &stale).unwrap();
    open_handoff(config.path(), Phase::Switched);
    app.gate_start(config.path()).unwrap();
    assert_eq!(record_of(config.path()), stale);
}

#[cfg(unix)]
#[test]
fn a_release_that_cannot_be_recorded_refuses_the_start() {
    use std::os::unix::fs::PermissionsExt;
    let config = tempfile::tempdir().unwrap();
    let (_install, exe) =
        install_with_identity(&identity_json(yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION));
    let mut stale = ownership::OwnershipRecord {
        owner: Owner::Cli,
        install_source: "script".into(),
        install_root: "/x".into(),
        release_id: "old:release".into(),
        written_at: 1,
    };
    ownership::write(config.path(), &stale).unwrap();
    std::fs::set_permissions(config.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
    let writable_anyway = std::fs::File::create(config.path().join("probe")).is_ok();
    let result = identity(&exe, "script", Some(config.path())).gate_start(config.path());
    std::fs::set_permissions(config.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    if writable_anyway {
        return; // running as a user the permissions do not bind
    }
    let refused = result.expect_err("a record that names another release must be refreshed");
    assert!(matches!(refused.0, Refusal::OwnerRecordUnwritable { .. }), "{refused}");
    stale.written_at = 1;
    assert_eq!(record_of(config.path()), stale, "the previous record stays");
}
