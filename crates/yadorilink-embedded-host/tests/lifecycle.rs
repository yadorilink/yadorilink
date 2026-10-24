//! The embedded host's lifecycle, in one process: start, stop and restart, suspend and
//! resume, and that stopping leaves nothing behind.
//!
//! The engine resolves its state directory from the process environment, so every test runs
//! under one shared directory, one at a time; each gets its own database and block store
//! (see `support`).

use std::time::Duration;

use yadorilink_embedded_host::{EmbeddedHost, HostError, HostState, ProviderChannel, StartError};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{ListProviderFoldersRequest, ShellIpcMessage};

mod support;
use support::{area, released, serialized};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

/// Asks the engine for its provider folders over the channel and waits for the answer.
async fn list_folders(channel: &ProviderChannel) -> bool {
    channel
        .send(ShellIpcMessage {
            payload: Some(Payload::ListProviderFoldersRequest(
                ListProviderFoldersRequest::default(),
            )),
        })
        .await
        .unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(20), channel.recv())
        .await
        .expect("the engine answers")
        .expect("the channel stays open");
    matches!(
        answer.payload,
        Some(Payload::ListProviderFoldersResponse(response)) if response.snapshot_available
    )
}

#[test]
fn start_stop_and_restart_over_the_same_data() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());
    assert_eq!(host.state(), HostState::Stopped);
    let rt = runtime();

    for round in 0..2 {
        host.start().unwrap_or_else(|e| panic!("start, round {round}: {e}"));
        assert_eq!(host.state(), HostState::Running);
        let channel = host.open_provider_channel().unwrap();
        assert!(rt.block_on(list_folders(&channel)), "round {round}");
        let probe = host.release_probe().unwrap();

        host.stop().unwrap();
        assert_eq!(host.state(), HostState::Stopped);
        assert!(released(&probe), "round {round}: something still holds the engine's state");
        let closed = rt
            .block_on(async { tokio::time::timeout(Duration::from_secs(5), channel.recv()).await });
        assert!(closed.expect("a stopped engine closes its channels").is_none(), "round {round}");
    }
}

#[test]
fn suspend_tears_the_engine_down_and_resume_brings_it_back() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());
    let rt = runtime();
    host.start().unwrap();
    let probe = host.release_probe().unwrap();

    host.suspend().unwrap();
    assert_eq!(host.state(), HostState::Suspended);
    assert!(released(&probe), "a suspended host holds nothing open");
    assert!(matches!(
        host.open_provider_channel(),
        Err(HostError::WrongState { state: HostState::Suspended, .. })
    ));

    host.resume().unwrap();
    assert_eq!(host.state(), HostState::Running);
    let channel = host.open_provider_channel().unwrap();
    assert!(rt.block_on(list_folders(&channel)));
    host.stop().unwrap();
}

#[test]
fn a_call_in_the_wrong_state_is_refused_and_changes_nothing() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());

    for refused in [host.suspend(), host.resume()] {
        assert!(matches!(refused, Err(HostError::WrongState { state: HostState::Stopped, .. })));
    }
    host.stop().unwrap(); // stopping a stopped host is not an error
    assert_eq!(host.state(), HostState::Stopped);

    host.start().unwrap();
    assert!(matches!(host.start(), Err(HostError::WrongState { state: HostState::Running, .. })));
    assert!(matches!(host.resume(), Err(HostError::WrongState { state: HostState::Running, .. })));
    assert_eq!(host.state(), HostState::Running);
    host.suspend().unwrap();
    assert!(matches!(
        host.suspend(),
        Err(HostError::WrongState { state: HostState::Suspended, .. })
    ));
    assert!(matches!(host.start(), Err(HostError::WrongState { state: HostState::Suspended, .. })));
    host.stop().unwrap();
    assert_eq!(host.state(), HostState::Stopped);
}

#[test]
fn one_engine_runs_per_data_area_and_stopping_gives_the_area_up() {
    let _serial = serialized();
    let area = area();
    let first = EmbeddedHost::new(area.config.clone());
    let second = EmbeddedHost::new(area.config.clone());

    first.start().unwrap();
    assert!(matches!(second.start(), Err(HostError::Start(StartError::AlreadyRunning(_)))));
    assert_eq!(second.state(), HostState::Stopped);

    first.stop().unwrap();
    second.start().expect("the data area is free once its engine stopped");
    second.stop().unwrap();
}

#[test]
fn engines_over_different_state_directories_run_side_by_side_in_one_process() {
    let _serial = serialized();
    let (healthy, broken) = (area(), area());
    // The broken one's own credential store cannot be read; the healthy one's is untouched.
    std::fs::create_dir_all(&broken.config.config_dir).unwrap();
    std::fs::write(broken.config.config_dir.join("credentials.json"), "not a credential").unwrap();
    let (ok, refused) =
        (EmbeddedHost::new(healthy.config.clone()), EmbeddedHost::new(broken.config.clone()));

    ok.start().unwrap();
    assert!(matches!(refused.start(), Err(HostError::Start(_))), "its own store refuses it");
    assert_eq!(refused.state(), HostState::Stopped);
    assert_eq!(ok.state(), HostState::Running, "the other directory is not affected");

    std::fs::remove_file(broken.config.config_dir.join("credentials.json")).unwrap();
    refused.start().expect("both run once the broken store is fixed");
    refused.stop().unwrap();
    ok.stop().unwrap();
}

#[test]
fn dropping_a_running_host_stops_it() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    let probe = host.release_probe().unwrap();
    drop(host);
    assert!(released(&probe));
    EmbeddedHost::new(area.config.clone()).start().expect("the area is free again");
}

#[test]
fn a_second_engine_over_the_same_block_store_is_refused_even_with_another_database() {
    let _serial = serialized();
    let area = area();
    let other = tempfile::tempdir().unwrap();
    let mut shared_blocks = area.config.clone();
    shared_blocks.sync_db_path = other.path().join("other.sqlite3");
    let first = EmbeddedHost::new(area.config.clone());
    let second = EmbeddedHost::new(shared_blocks);

    first.start().unwrap();
    assert!(matches!(second.start(), Err(HostError::Start(_))));
    assert_eq!(second.state(), HostState::Stopped);

    first.stop().unwrap();
    second.start().expect("the block store is free once its engine stopped");
    second.stop().unwrap();
}

#[test]
fn the_database_is_locked_by_the_os_until_the_engine_has_stopped() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    let locked = yadorilink_local_storage::resource_lock::DataResourceLocks::acquire(
        &area.config.block_store_root,
        &area.config.sync_db_path,
    );
    assert!(locked.is_err(), "a running engine holds both locks");
    host.stop().unwrap();
    yadorilink_local_storage::resource_lock::DataResourceLocks::acquire(
        &area.config.block_store_root,
        &area.config.sync_db_path,
    )
    .expect("stopping releases both locks");
}

#[test]
fn locks_are_held_until_blocking_work_ends_and_a_restart_is_refused_meanwhile() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone()).with_drain_bound(Duration::from_millis(300));
    let other = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    let (release, hold) = std::sync::mpsc::channel::<()>();
    host.spawn_blocking_for_test(move || {
        let _ = hold.recv();
    })
    .unwrap();

    assert!(matches!(host.stop(), Err(HostError::Draining)));
    assert_eq!(host.state(), HostState::Stopping);
    assert!(matches!(host.start(), Err(HostError::WrongState { state: HostState::Stopping, .. })));
    assert!(matches!(
        host.suspend(),
        Err(HostError::WrongState { state: HostState::Stopping, .. })
    ));
    assert!(matches!(other.start(), Err(HostError::Start(_))), "the data area is still locked");

    release.send(()).unwrap();
    host.stop().expect("the drain finishes once the blocking work does");
    assert_eq!(host.state(), HostState::Stopped);
    other.start().expect("the data area is free after the drain");
    other.stop().unwrap();
}

#[test]
fn a_stop_that_never_finishes_returns_draining_within_the_bound_and_keeps_the_locks() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone()).with_drain_bound(Duration::from_millis(300));
    let other = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    let (release, stall) = std::sync::mpsc::channel::<()>();
    host.stall_stop_for_test(stall).unwrap();

    let began = std::time::Instant::now();
    assert!(matches!(host.stop(), Err(HostError::Draining)));
    assert!(began.elapsed() < Duration::from_secs(5), "the stop is bounded");
    assert_eq!(host.state(), HostState::Stopping);
    assert!(matches!(other.start(), Err(HostError::Start(_))), "the data area is still locked");

    release.send(()).unwrap();
    host.stop().expect("the drain finishes once the stall ends");
    other.start().expect("the data area is free after the drain");
    other.stop().unwrap();
}

#[test]
fn a_start_that_fails_late_has_started_nothing_and_releases_the_data_area() {
    let _serial = serialized();
    let area = area();
    std::fs::create_dir_all(&area.config.config_dir).unwrap();
    let credentials = area.config.config_dir.join("credentials.json");
    std::fs::write(&credentials, "not a credential document").unwrap();
    let host = EmbeddedHost::new(area.config.clone());

    let refused = host.start();
    std::fs::remove_file(&credentials).unwrap();
    assert!(matches!(refused, Err(HostError::Start(_))), "an unreadable credential store refuses");
    assert_eq!(host.state(), HostState::Stopped);
    yadorilink_local_storage::resource_lock::DataResourceLocks::acquire(
        &area.config.block_store_root,
        &area.config.sync_db_path,
    )
    .expect("nothing was left running over the data area");
    host.start().expect("a later start succeeds");
    host.stop().unwrap();
}

#[test]
fn the_stop_and_the_drain_share_one_deadline() {
    let _serial = serialized();
    let area = area();
    let bound = Duration::from_millis(400);
    let host = EmbeddedHost::new(area.config.clone()).with_drain_bound(bound);
    host.start().unwrap();
    let (release_stall, stall) = std::sync::mpsc::channel::<()>();
    host.stall_stop_for_test(stall).unwrap();
    let (release_work, hold) = std::sync::mpsc::channel::<()>();
    host.spawn_blocking_for_test(move || {
        let _ = hold.recv();
    })
    .unwrap();
    // The stop finishes about halfway through the bound; the drain never does.
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        release_stall.send(()).unwrap();
    });

    let began = std::time::Instant::now();
    assert!(matches!(host.stop(), Err(HostError::Draining)));
    let took = began.elapsed();
    releaser.join().unwrap();
    assert!(
        took < Duration::from_millis(700),
        "stop plus drain took {took:?} for a {bound:?} bound"
    );

    release_work.send(()).unwrap();
    host.stop().unwrap();
}

#[test]
fn a_persisted_folder_link_gets_its_runtime_or_a_visible_stop_after_start_and_after_resume() {
    let _serial = serialized();
    let area = area();
    let folder = tempfile::tempdir().unwrap();
    let folder_path = folder.path().to_str().unwrap().to_owned();
    {
        let coordinator = yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open(
            &area.config.sync_db_path,
        )
        .unwrap();
        coordinator.link_repository().add_link(&folder_path, "group").unwrap();
    }
    let host = EmbeddedHost::new(area.config.clone());

    host.start().unwrap();
    if yadorilink_embedded_host::ordinary_folder_links_supported() {
        assert!(host.has_link_runtime_for_test(&folder_path).unwrap(), "after start");
        host.suspend().unwrap();
        host.resume().unwrap();
        assert!(host.has_link_runtime_for_test(&folder_path).unwrap(), "after resume");
    } else {
        // No watcher, so no change source: the link does not run, and says why.
        for stage in ["after start", "after resume"] {
            assert!(!host.has_link_runtime_for_test(&folder_path).unwrap(), "{stage}");
            let listed = host
                .execute(
                    yadorilink_embedded_host::Command::ListFolders,
                    &yadorilink_embedded_host::CallOptions::default(),
                )
                .unwrap();
            let yadorilink_embedded_host::CommandOutput::Folders(folders) = listed else {
                panic!("expected folders")
            };
            let [folder] = folders.as_slice() else { panic!("{stage}: {folders:?}") };
            let reason =
                folder.degraded.as_deref().unwrap_or_else(|| panic!("{stage}: not degraded"));
            assert!(reason.contains("cannot watch ordinary folders"), "{stage}: {reason}");
            if stage == "after start" {
                host.suspend().unwrap();
                host.resume().unwrap();
            }
        }
    }
    host.stop().unwrap();
}

#[test]
fn link_start_removes_the_probe_artefacts_a_killed_process_left_in_the_folder() {
    let _serial = serialized();
    let area = area();
    let folder = tempfile::tempdir().unwrap();
    let folder_path = folder.path().to_str().unwrap().to_owned();
    {
        let coordinator = yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open(
            &area.config.sync_db_path,
        )
        .unwrap();
        coordinator.link_repository().add_link(&folder_path, "group").unwrap();
    }
    let residue = folder.path().join(".yadorilink-v1-probe.1-2-3-durable");
    std::fs::write(&residue, b"probe").unwrap();
    std::fs::create_dir(folder.path().join("sub")).unwrap();
    let nested = folder.path().join("sub").join(".yadorilink-v1-probe.1-2-4-nfc");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(folder.path().join("keep.txt"), b"user").unwrap();

    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    // Without a watcher the link does not run (see the test above); the sweep happens either way.
    assert_eq!(
        host.has_link_runtime_for_test(&folder_path).unwrap(),
        yadorilink_embedded_host::ordinary_folder_links_supported()
    );
    host.stop().unwrap();

    assert!(!residue.exists(), "the probe file was swept");
    assert!(!nested.exists(), "the nested probe directory was swept");
    assert!(folder.path().join("keep.txt").exists(), "user content stays");
}

/// Another host owning the data area is not this host's to inspect: stopping a host that holds
/// nothing must not trip the bounded-session check because someone else holds the area.
#[test]
fn stopping_a_stopped_host_while_another_host_owns_the_area_does_not_panic() {
    let _serial = serialized();
    let area = area();
    let first = EmbeddedHost::new(area.config.clone());
    let second = EmbeddedHost::new(area.config.clone());
    second.start().unwrap();
    first.stop().unwrap();
    first.suspend().unwrap_err();
    second.stop().unwrap();
    first.start().unwrap();
    first.stop().unwrap();
}

/// A call that returns to the host inside a SQLite write transaction breaks the same rule.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "inside a SQLite write transaction")]
fn a_call_returning_inside_a_write_transaction_is_caught() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());
    let database = yadorilink_sqlite_runtime::SyncDatabase::open_in_memory(|_| Ok(())).unwrap();
    let _ = database.write_immediate::<_, yadorilink_sqlite_runtime::DatabaseError>(|_tx| {
        let _ = host.stop();
        Ok(())
    });
}

#[test]
fn a_clean_lifecycle_passes_the_bounded_session_checks() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    host.suspend().unwrap();
    host.resume().unwrap();
    host.stop().unwrap();
    assert_eq!(host.state(), HostState::Stopped);
}
