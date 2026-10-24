//! The application commands over a real engine on a state directory of its own: what they
//! return, which refusals are typed, and which commands the engine's lack of an account and of a
//! change source refuses before anything is changed. The coordination plane is not reachable
//! here, so the share commands are exercised up to the refusals that precede it.

use std::time::Duration;

use yadorilink_embedded_host::{
    CallError, CallOptions, CancelHandle, Command, CommandErrorKind, CommandOutput, CreateShare,
    DoctorStatus, EmbeddedHost, JoinGroup, JoinShare, PauseFor, PauseLink, PreservedRef,
    PreservedRefusal, ProviderFolder, ResumeLink, ShareFolder, SpaceManagement, UnlinkFolder,
};
use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;

mod support;
use support::{area, serialized};

fn within(secs: u64) -> CallOptions {
    CallOptions { deadline: Some(Duration::from_secs(secs)), cancel: CancelHandle::new() }
}

fn running_host() -> (EmbeddedHost, support::Area) {
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    (host, area)
}

/// A host over a state with one persisted link of `group` at `key`.
fn host_with_link(key: &str, group: &str) -> (EmbeddedHost, support::Area) {
    let area = area();
    {
        let coordinator = yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open(
            &area.config.sync_db_path,
        )
        .unwrap();
        coordinator.link_repository().add_link(key, group).unwrap();
    }
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    (host, area)
}

fn refused_with(result: Result<CommandOutput, CallError>) -> (ApplicationErrorCode, String) {
    match result {
        Err(CallError::Failed(error)) => match error.kind() {
            CommandErrorKind::Refused(code) => (code, error.message().to_owned()),
            other => panic!("expected a typed refusal, got {other:?}: {}", error.message()),
        },
        other => panic!("expected a refusal: {other:?}"),
    }
}

fn paused_of(host: &EmbeddedHost, key: &str) -> bool {
    let CommandOutput::Folders(folders) = host.execute(Command::ListFolders, &within(30)).unwrap()
    else {
        panic!("folders")
    };
    folders.iter().find(|f| f.key == key).expect("the link").paused
}

#[test]
fn space_management_is_off_until_set_and_survives_a_restart_of_the_engine() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let off = CommandOutput::SpaceManagement(SpaceManagement { enabled: false });
    let on = CommandOutput::SpaceManagement(SpaceManagement { enabled: true });
    assert_eq!(host.execute(Command::SpaceManagement, &within(30)).unwrap(), off);
    assert_eq!(
        host.execute(Command::SetSpaceManagement { enabled: true }, &within(30)).unwrap(),
        on
    );
    host.suspend().unwrap();
    host.resume().unwrap();
    assert_eq!(host.execute(Command::SpaceManagement, &within(30)).unwrap(), on);
    assert_eq!(
        host.execute(Command::SetSpaceManagement { enabled: false }, &within(30)).unwrap(),
        off
    );
    host.stop().unwrap();
}

#[test]
fn a_link_is_paused_and_resumed_and_a_stale_group_changes_nothing() {
    let _serial = serialized();
    let (host, _area) = host_with_link("/folders/photos", "group-a");
    assert!(!paused_of(&host, "/folders/photos"));

    // Another group's expectation: refused with the typed code, nothing changed.
    let stale = PauseLink {
        link_key: "/folders/photos".into(),
        duration: PauseFor::UntilResumed,
        expected_group_id: Some("group-b".into()),
    };
    let (code, _) = refused_with(host.execute(Command::PauseLink(stale), &within(30)));
    assert_eq!(code, ApplicationErrorCode::GroupMismatch);
    assert!(!paused_of(&host, "/folders/photos"));

    let pause = PauseLink {
        link_key: "/folders/photos".into(),
        duration: PauseFor::OneHour,
        expected_group_id: Some("group-a".into()),
    };
    assert_eq!(host.execute(Command::PauseLink(pause), &within(30)).unwrap(), CommandOutput::Done);
    assert!(paused_of(&host, "/folders/photos"));

    let stale = ResumeLink {
        link_key: "/folders/photos".into(),
        expected_group_id: Some("group-b".into()),
    };
    let (code, _) = refused_with(host.execute(Command::ResumeLink(stale), &within(30)));
    assert_eq!(code, ApplicationErrorCode::GroupMismatch);
    assert!(paused_of(&host, "/folders/photos"));

    let resume = ResumeLink { link_key: "/folders/photos".into(), expected_group_id: None };
    assert_eq!(
        host.execute(Command::ResumeLink(resume), &within(30)).unwrap(),
        CommandOutput::Done
    );
    assert!(!paused_of(&host, "/folders/photos"));
    host.stop().unwrap();
}

#[test]
fn pausing_a_folder_that_is_not_linked_fails_with_the_engines_message() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let pause = PauseLink {
        link_key: "/not/linked".into(),
        duration: PauseFor::UntilResumed,
        expected_group_id: None,
    };
    let result = host.execute(Command::PauseLink(pause), &within(30));
    let Err(CallError::Failed(error)) = result else { panic!("expected a failure: {result:?}") };
    assert_eq!(error.kind(), CommandErrorKind::Failed);
    assert!(!error.message().is_empty());
    host.stop().unwrap();
}

#[test]
fn unlinking_checks_the_expected_group_and_the_link_before_anything_changes() {
    let _serial = serialized();
    let (host, _area) = host_with_link("/folders/docs", "group-a");

    let unknown =
        UnlinkFolder { link_key: "/not/linked".into(), force: false, expected_group_id: None };
    let result = host.execute(Command::Unlink(unknown), &within(30));
    let Err(CallError::Failed(error)) = result else { panic!("expected a failure: {result:?}") };
    assert_eq!(error.kind(), CommandErrorKind::Failed);

    let stale = UnlinkFolder {
        link_key: "/folders/docs".into(),
        force: true,
        expected_group_id: Some("group-b".into()),
    };
    let (code, _) = refused_with(host.execute(Command::Unlink(stale), &within(30)));
    assert_eq!(code, ApplicationErrorCode::GroupMismatch);

    let CommandOutput::Folders(folders) = host.execute(Command::ListFolders, &within(30)).unwrap()
    else {
        panic!("folders")
    };
    assert_eq!(folders.len(), 1, "a refused unlink removed nothing");
    host.stop().unwrap();
}

#[test]
fn status_of_a_fresh_engine_is_a_snapshot_with_no_folders_and_a_signed_out_account() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let CommandOutput::Status(snapshot) = host.execute(Command::Status, &within(30)).unwrap()
    else {
        panic!("a status snapshot")
    };
    assert!(snapshot.folders.is_empty());
    assert_eq!(snapshot.account.has_linked_folders, Some(false));
    assert!(!snapshot.account.device_registered);
    host.stop().unwrap();
}

#[test]
fn status_names_a_linked_folder() {
    let _serial = serialized();
    let (host, _area) = host_with_link("/folders/photos", "group-a");
    let CommandOutput::Status(snapshot) = host.execute(Command::Status, &within(30)).unwrap()
    else {
        panic!("a status snapshot")
    };
    assert_eq!(snapshot.folders.len(), 1);
    assert_eq!(snapshot.account.has_linked_folders, Some(true));
    host.stop().unwrap();
}

#[test]
fn the_doctor_reports_typed_rows() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let CommandOutput::Doctor(rows) = host.execute(Command::Doctor, &within(30)).unwrap() else {
        panic!("doctor rows")
    };
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|row| !row.name.is_empty() && !row.detail.is_empty()));
    assert!(rows.iter().any(|row| row.status == DoctorStatus::Ok));
    host.stop().unwrap();
}

#[test]
fn preserved_items_are_empty_on_a_fresh_engine_and_an_unknown_one_is_refused_typed() {
    let _serial = serialized();
    let (host, _area) = running_host();
    assert_eq!(
        host.execute(Command::ListPreserved, &within(30)).unwrap(),
        CommandOutput::Preserved(Vec::new())
    );
    let item = PreservedRef { group_id: "g".into(), item_id: "nope".into() };
    // Restoring authors a write, so a group this device is not a writer of is refused first;
    // discarding only needs the item to exist.
    for (command, refusal) in [
        (Command::RestorePreserved(item.clone()), PreservedRefusal::NotAWriter),
        (Command::DiscardPreserved(item.clone()), PreservedRefusal::NotFound),
    ] {
        let result = host.execute(command, &within(30));
        let Err(CallError::Failed(error)) = result else {
            panic!("expected a refusal: {result:?}")
        };
        assert_eq!(error.kind(), CommandErrorKind::Preserved(refusal));
    }
    host.stop().unwrap();
}

/// An ordinary folder cannot be captured by this build, so a share into one is refused before
/// anything is created on this device or redeemed with the coordination plane.
#[test]
fn a_share_into_an_ordinary_folder_is_refused_before_anything_happens() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("made-by-the-command");

    let create = CreateShare {
        group_name: "Photos".into(),
        folder: ShareFolder::Ordinary {
            local_path: path.to_str().unwrap().into(),
            create_if_missing: true,
        },
        on_demand: false,
        acknowledge_risks: true,
    };
    let join = JoinShare {
        invite_code: "code".into(),
        folder: ShareFolder::Ordinary {
            local_path: folder.path().to_str().unwrap().into(),
            create_if_missing: false,
        },
        on_demand: false,
        acknowledge_risks: true,
    };
    let group = JoinGroup {
        group_id: "g".into(),
        group_name: "Photos".into(),
        folder: ShareFolder::Ordinary {
            local_path: folder.path().to_str().unwrap().into(),
            create_if_missing: false,
        },
        on_demand: false,
        acknowledge_risks: true,
    };
    for command in
        [Command::CreateShare(create), Command::JoinShare(join), Command::JoinGroup(group)]
    {
        let result = host.execute(command, &within(30));
        let Err(CallError::Failed(error)) = result else {
            panic!("expected a refusal: {result:?}")
        };
        assert_eq!(error.kind(), CommandErrorKind::NoChangeSource);
    }
    assert!(!path.exists(), "the refused create did not make the folder");
    host.stop().unwrap();
}

/// A provider folder needs this device registered: with no account the refusal is the typed
/// `LocalIdentityUnavailable`, and where the OS has no provider adapter it is the preparation
/// refusal. Either way nothing was created.
#[test]
fn a_provider_share_without_an_account_is_refused_typed() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let folder = ShareFolder::Provider(ProviderFolder {
        display_name: "Photos".into(),
        request_token: "token-1".into(),
    });
    let expected = if cfg!(any(target_vendor = "apple", windows)) {
        ApplicationErrorCode::LocalIdentityUnavailable
    } else {
        ApplicationErrorCode::PreparationRejected
    };

    let create = CreateShare {
        group_name: "Photos".into(),
        folder: folder.clone(),
        on_demand: true,
        acknowledge_risks: false,
    };
    let (code, _) = refused_with(host.execute(Command::CreateShare(create), &within(30)));
    assert_eq!(code, expected);

    let join = JoinGroup {
        group_id: "g".into(),
        group_name: "Photos".into(),
        folder,
        on_demand: true,
        acknowledge_risks: false,
    };
    let (code, _) = refused_with(host.execute(Command::JoinGroup(join), &within(30)));
    assert_eq!(code, expected);

    let invite = JoinShare {
        invite_code: "code".into(),
        folder: ShareFolder::Provider(ProviderFolder {
            display_name: "Photos".into(),
            request_token: "token-2".into(),
        }),
        on_demand: true,
        acknowledge_risks: false,
    };
    let (code, _) = refused_with(host.execute(Command::JoinShare(invite), &within(30)));
    assert_eq!(code, expected);
    assert_eq!(
        host.execute(Command::ListFolders, &within(30)).unwrap(),
        CommandOutput::Folders(Vec::new())
    );
    host.stop().unwrap();
}

#[test]
fn a_cancelled_read_only_command_is_aborted_and_a_changing_one_is_left_to_finish() {
    let _serial = serialized();
    let (host, _area) = running_host();
    // Cancelled before it starts: neither command runs.
    for command in [Command::Status, Command::SetSpaceManagement { enabled: true }] {
        let options = within(30);
        options.cancel.cancel();
        assert_eq!(
            host.execute(command, &options),
            Err(CallError::Cancelled { still_running: false })
        );
    }
    assert_eq!(
        host.execute(Command::SpaceManagement, &within(30)).unwrap(),
        CommandOutput::SpaceManagement(SpaceManagement { enabled: false }),
        "a command cancelled before it started changed nothing"
    );
    host.stop().unwrap();
}
