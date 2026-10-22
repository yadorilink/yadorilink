//! The daemon enforces the link preflight acknowledgement itself: a link,
//! create, join or invite acceptance of a risky folder without
//! `acknowledge_risks` is refused here, before anything is created or
//! redeemed, whichever client sent it.

use std::sync::Arc;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    accept_invite_command_response, create_and_link_command_response,
    join_and_link_command_response, AcceptInviteCommandRequest, ApplicationCommandError,
    ApplicationErrorCode, CreateAndLinkCommandRequest, DaemonControlRequest,
    JoinAndLinkCommandRequest, LinkPreflightRequest, LinkRequest, ListLinksRequest,
};
use yadorilink_local_storage::SegmentBlockStore;

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
    // The free-space check reads the real volume: pin the reserve so a full host disk does not
    // turn every folder risky. `a_low_free_space_reading_still_needs_an_acknowledgement` pins the
    // opposite.
    state.set_link_preflight_headroom_override_for_tests(Some(0));
    state
}

async fn send(state: &Arc<DaemonState>, payload: ReqPayload) -> RespPayload {
    let context = crate::control_context::ControlContext::from_state(state.clone());
    super::handle_request(
        &context,
        DaemonControlRequest {
            payload: Some(payload),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    .payload
    .expect("a response payload")
}

fn link(path: &std::path::Path, acknowledge_risks: bool) -> ReqPayload {
    ReqPayload::Link(LinkRequest {
        local_path: path.to_string_lossy().into_owned(),
        group_id: "group-1".into(),
        on_demand: false,
        acknowledge_risks,
        pending_enrollment_operation_id: String::new(),
        pending_enrollment_kind: 0,
        pending_enrollment_device_id: String::new(),
    })
}

/// A folder with one file in it: risky (its files join the first sync).
fn non_empty_folder() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("existing.txt"), b"x").unwrap();
    dir
}

async fn linked_paths(state: &Arc<DaemonState>) -> Vec<String> {
    match send(state, ReqPayload::ListLinks(ListLinksRequest {})).await {
        RespPayload::ListLinks(list) => list.links.into_iter().map(|l| l.local_path).collect(),
        other => panic!("expected ListLinks, got {other:?}"),
    }
}

fn assert_needs_acknowledgement(error: ApplicationCommandError) {
    // Not `LOCAL_IDENTITY_UNAVAILABLE`: this daemon has no coordination
    // identity, so reaching the enrollment at all would have said so.
    assert_eq!(error.code(), ApplicationErrorCode::PreparationRejected, "{error:?}");
    assert!(error.message.contains("needs its risks acknowledged"), "{}", error.message);
    assert!(error.message.contains("folder is not empty"), "{}", error.message);
}

#[tokio::test]
async fn an_unacknowledged_risky_link_is_refused_and_creates_nothing() {
    let state = test_state();
    let dir = non_empty_folder();
    match send(&state, link(dir.path(), false)).await {
        RespPayload::Error(message) => {
            assert!(message.contains("needs its risks acknowledged"), "{message}");
            assert!(message.contains("folder is not empty"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(linked_paths(&state).await.is_empty());
}

#[tokio::test]
async fn an_acknowledged_risky_link_goes_through() {
    let state = test_state();
    let dir = non_empty_folder();
    let resp = send(&state, link(dir.path(), true)).await;
    assert!(matches!(resp, RespPayload::Link(_)), "{resp:?}");
    assert_eq!(linked_paths(&state).await, vec![dir.path().to_string_lossy().into_owned()]);
}

#[tokio::test]
async fn a_folder_with_nothing_to_acknowledge_links_without_the_flag() {
    let state = test_state();
    let dir = tempfile::tempdir().unwrap();
    let resp = send(&state, link(dir.path(), false)).await;
    assert!(matches!(resp, RespPayload::Link(_)), "{resp:?}");
}

#[tokio::test]
async fn an_unacknowledged_risky_create_is_refused_before_the_group_is_made() {
    let state = test_state();
    let dir = non_empty_folder();
    let resp = send(
        &state,
        ReqPayload::CreateAndLinkCommand(CreateAndLinkCommandRequest {
            group_name: "Photos".into(),
            local_path: dir.path().to_string_lossy().into_owned(),
            on_demand: false,
            acknowledge_risks: false,
            provider_display_name: String::new(),
            request_token: String::new(),
            create_local_path_if_missing: false,
        }),
    )
    .await;
    match resp {
        RespPayload::CreateAndLinkCommand(r) => match r.result {
            Some(create_and_link_command_response::Result::Error(e)) => {
                assert_needs_acknowledgement(e)
            }
            other => panic!("expected a refusal, got {other:?}"),
        },
        other => panic!("expected CreateAndLinkCommand, got {other:?}"),
    }
}

#[tokio::test]
async fn a_create_can_ask_the_daemon_to_make_the_missing_folder() {
    let state = test_state();
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("YadoriLink");
    for create_local_path_if_missing in [false, true] {
        let resp = send(
            &state,
            ReqPayload::CreateAndLinkCommand(CreateAndLinkCommandRequest {
                group_name: "YadoriLink Folder".into(),
                local_path: path.to_string_lossy().into_owned(),
                on_demand: false,
                acknowledge_risks: false,
                provider_display_name: String::new(),
                request_token: String::new(),
                create_local_path_if_missing,
            }),
        )
        .await;
        assert!(matches!(resp, RespPayload::CreateAndLinkCommand(_)), "{resp:?}");
        assert_eq!(
            path.is_dir(),
            create_local_path_if_missing,
            "flag {create_local_path_if_missing}"
        );
    }
}

#[tokio::test]
async fn an_unacknowledged_risky_join_is_refused_before_enrollment() {
    let state = test_state();
    let dir = non_empty_folder();
    let resp = send(
        &state,
        ReqPayload::JoinAndLinkCommand(JoinAndLinkCommandRequest {
            group_id: "group-1".into(),
            group_name: "Photos".into(),
            local_path: dir.path().to_string_lossy().into_owned(),
            on_demand: false,
            acknowledge_risks: false,
            provider_display_name: String::new(),
            request_token: String::new(),
        }),
    )
    .await;
    match resp {
        RespPayload::JoinAndLinkCommand(r) => match r.result {
            Some(join_and_link_command_response::Result::Error(e)) => {
                assert_needs_acknowledgement(e)
            }
            other => panic!("expected a refusal, got {other:?}"),
        },
        other => panic!("expected JoinAndLinkCommand, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unacknowledged_risky_invite_acceptance_is_refused_before_redeeming() {
    let state = test_state();
    let dir = non_empty_folder();
    let resp = send(
        &state,
        ReqPayload::AcceptInviteCommand(AcceptInviteCommandRequest {
            code: "abc123".into(),
            local_path: dir.path().to_string_lossy().into_owned(),
            on_demand: false,
            acknowledge_risks: false,
        }),
    )
    .await;
    match resp {
        RespPayload::AcceptInviteCommand(r) => match r.result {
            Some(accept_invite_command_response::Result::Error(e)) => {
                assert_needs_acknowledgement(e)
            }
            other => panic!("expected a refusal, got {other:?}"),
        },
        other => panic!("expected AcceptInviteCommand, got {other:?}"),
    }
}

/// With the flag set the gate stands aside, and the command reaches the
/// enrollment (which here stops at the missing coordination identity).
#[tokio::test]
async fn an_acknowledged_invite_acceptance_reaches_the_enrollment() {
    let state = test_state();
    let dir = non_empty_folder();
    let resp = send(
        &state,
        ReqPayload::AcceptInviteCommand(AcceptInviteCommandRequest {
            code: "abc123".into(),
            local_path: dir.path().to_string_lossy().into_owned(),
            on_demand: false,
            acknowledge_risks: true,
        }),
    )
    .await;
    match resp {
        RespPayload::AcceptInviteCommand(r) => match r.result {
            Some(accept_invite_command_response::Result::Error(e)) => {
                assert_eq!(e.code(), ApplicationErrorCode::LocalIdentityUnavailable, "{e:?}")
            }
            other => panic!("expected the enrollment's refusal, got {other:?}"),
        },
        other => panic!("expected AcceptInviteCommand, got {other:?}"),
    }
}

#[tokio::test]
async fn the_preflight_reports_what_the_gate_checks() {
    let state = test_state();
    let dir = non_empty_folder();
    let resp = send(
        &state,
        ReqPayload::LinkPreflight(LinkPreflightRequest {
            local_path: dir.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    let RespPayload::LinkPreflight(report) = resp else { panic!("expected a report: {resp:?}") };
    assert_eq!(report.resolved_path, std::fs::canonicalize(dir.path()).unwrap().to_string_lossy());
    assert!(report.warnings.iter().any(|w| w.contains("folder is not empty")), "{report:?}");
    assert!(report.prohibitions.is_empty(), "{report:?}");

    let empty = tempfile::tempdir().unwrap();
    let resp = send(
        &state,
        ReqPayload::LinkPreflight(LinkPreflightRequest {
            local_path: empty.path().to_string_lossy().into_owned(),
        }),
    )
    .await;
    let RespPayload::LinkPreflight(report) = resp else { panic!("expected a report: {resp:?}") };
    assert!(report.warnings.is_empty(), "{report:?}");
}

#[tokio::test]
async fn the_preflight_names_a_folder_nested_in_a_linked_one() {
    let state = test_state();
    let outer = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(outer.path()).unwrap();
    assert!(matches!(send(&state, link(&canonical, false)).await, RespPayload::Link(_)));
    let inner = canonical.join("inner");
    std::fs::create_dir(&inner).unwrap();
    let resp = send(
        &state,
        ReqPayload::LinkPreflight(LinkPreflightRequest {
            local_path: inner.to_string_lossy().into_owned(),
        }),
    )
    .await;
    let RespPayload::LinkPreflight(report) = resp else { panic!("expected a report: {resp:?}") };
    assert_eq!(report.prohibitions.len(), 1, "{report:?}");
}

#[tokio::test]
async fn the_preflight_of_a_missing_folder_is_an_error() {
    let state = test_state();
    let dir = tempfile::tempdir().unwrap();
    let resp = send(
        &state,
        ReqPayload::LinkPreflight(LinkPreflightRequest {
            local_path: dir.path().join("missing").to_string_lossy().into_owned(),
        }),
    )
    .await;
    assert!(
        matches!(&resp, RespPayload::Error(m) if m.starts_with("no such directory")),
        "{resp:?}"
    );
}

/// A folder around a linked one is refused for its topology, naming the
/// other link, rather than asked to acknowledge risks no confirmation clears.
#[tokio::test]
async fn an_unacknowledged_link_around_a_linked_folder_names_the_other_link() {
    let state = test_state();
    let outer = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(outer.path()).unwrap();
    let inner = canonical.join("inner");
    std::fs::create_dir(&inner).unwrap();
    assert!(matches!(send(&state, link(&inner, false)).await, RespPayload::Link(_)));
    let mut other_group = link(&canonical, false);
    if let ReqPayload::Link(r) = &mut other_group {
        r.group_id = "group-2".into();
    }
    match send(&state, other_group).await {
        RespPayload::CommandError(error) => {
            assert_eq!(error.code(), ApplicationErrorCode::PathNotAllowed, "{error:?}");
            assert!(error.message.contains("unsupported link topology"), "{}", error.message);
            assert!(error.message.contains(&*inner.to_string_lossy()), "{}", error.message);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The gate checks the folder a path names, not its spelling: a symlink to
/// an empty folder inside a cloud-provider folder gets that provider's
/// warning, as the folder itself would, before the invite is redeemed.
#[cfg(unix)]
#[tokio::test]
async fn the_gate_checks_the_folder_a_symlink_names() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("Dropbox").join("Photos");
    std::fs::create_dir_all(&target).unwrap();
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(&target, &alias).unwrap();

    let resp = send(
        &state,
        ReqPayload::AcceptInviteCommand(AcceptInviteCommandRequest {
            code: "abc123".into(),
            local_path: alias.to_string_lossy().into_owned(),
            on_demand: false,
            acknowledge_risks: false,
        }),
    )
    .await;
    match resp {
        RespPayload::AcceptInviteCommand(r) => match r.result {
            Some(accept_invite_command_response::Result::Error(e)) => {
                assert_eq!(e.code(), ApplicationErrorCode::PreparationRejected, "{e:?}");
                assert!(e.message.contains("Dropbox"), "{}", e.message);
            }
            other => panic!("expected a refusal, got {other:?}"),
        },
        other => panic!("expected AcceptInviteCommand, got {other:?}"),
    }
}

/// A folder inside another linked folder is refused with the typed reason, not
/// a sentence a client would have to read.
#[tokio::test]
async fn a_link_nested_in_another_linked_folder_is_refused_as_path_not_allowed() {
    let state = test_state();
    let parent = tempfile::tempdir().unwrap();
    let child = parent.path().join("inner");
    std::fs::create_dir(&child).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&parent.path().canonicalize().unwrap().to_string_lossy(), "group-0")
        .unwrap();

    match send(&state, link(&child, true)).await {
        RespPayload::CommandError(e) => {
            assert_eq!(e.code(), ApplicationErrorCode::PathNotAllowed, "{e:?}");
            assert!(e.message.contains("unsupported link topology"), "{}", e.message);
        }
        other => panic!("expected a typed refusal, got {other:?}"),
    }
}

/// The same refusal reaches an invite acceptance, before the invite is redeemed.
#[tokio::test]
async fn an_invite_acceptance_nested_in_a_linked_folder_is_refused_as_path_not_allowed() {
    let state = test_state();
    let parent = tempfile::tempdir().unwrap();
    let child = parent.path().join("inner");
    std::fs::create_dir(&child).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&parent.path().canonicalize().unwrap().to_string_lossy(), "group-0")
        .unwrap();

    let resp = send(
        &state,
        ReqPayload::AcceptInviteCommand(AcceptInviteCommandRequest {
            code: "abc123".into(),
            local_path: child.to_string_lossy().into_owned(),
            on_demand: false,
            acknowledge_risks: false,
        }),
    )
    .await;
    match resp {
        RespPayload::AcceptInviteCommand(r) => match r.result {
            Some(accept_invite_command_response::Result::Error(e)) => {
                assert_eq!(e.code(), ApplicationErrorCode::PathNotAllowed, "{e:?}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        },
        other => panic!("expected AcceptInviteCommand, got {other:?}"),
    }
}

/// Every typed enrollment refusal keeps its own code on the wire.
#[test]
fn enrollment_refusals_carry_their_typed_code() {
    use crate::application::model::{InviteRefusal, LinkRefusal};
    use crate::application::EnrollmentError as E;
    let code = |error: E| super::enrollment_error_to_proto(error).code();
    assert_eq!(
        code(E::InviteRefused { reason: InviteRefusal::Expired, detail: "x".into() }),
        ApplicationErrorCode::InviteExpired
    );
    assert_eq!(
        code(E::InviteRefused { reason: InviteRefusal::AlreadyUsed, detail: "x".into() }),
        ApplicationErrorCode::InviteAlreadyUsed
    );
    assert_eq!(
        code(E::LocalLinkFailed { detail: "x".into(), refusal: Some(LinkRefusal::DiskFull) }),
        ApplicationErrorCode::DiskFull
    );
    assert_eq!(
        code(E::LinkRefused { refusal: LinkRefusal::PathNotAllowed, detail: "x".into() }),
        ApplicationErrorCode::PathNotAllowed
    );
    assert_eq!(
        code(E::LocalLinkFailed { detail: "x".into(), refusal: None }),
        ApplicationErrorCode::LocalLinkFailed
    );
}

/// A full disk is recognized whichever layer noticed it.
#[test]
fn a_full_disk_is_a_link_refusal_from_every_layer() {
    use crate::application::model::LinkRefusal;
    use crate::error::DaemonError;
    use crate::sync_error::SyncError;
    let full = || std::io::Error::from(std::io::ErrorKind::StorageFull);
    assert_eq!(DaemonError::Io(full()).link_refusal(), Some(LinkRefusal::DiskFull));
    assert_eq!(
        DaemonError::Sync(SyncError::Io(full())).link_refusal(),
        Some(LinkRefusal::DiskFull)
    );
    assert_eq!(
        DaemonError::Sync(SyncError::DiskPressure {
            path: "p".into(),
            volume: "v".into(),
            available_bytes: 0,
            headroom_bytes: 1
        })
        .link_refusal(),
        Some(LinkRefusal::DiskFull)
    );
    let sqlite_full =
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL), None);
    assert_eq!(
        DaemonError::Sync(SyncError::Db(sqlite_full)).link_refusal(),
        Some(LinkRefusal::DiskFull)
    );
    assert_eq!(DaemonError::Config("x".into()).link_refusal(), None);
    assert_eq!(
        DaemonError::Io(std::io::Error::from(std::io::ErrorKind::NotFound)).link_refusal(),
        None
    );
}

/// The free-space check itself still gates a link: an empty folder on a volume with less than
/// the headroom free needs its risks acknowledged.
#[tokio::test]
async fn a_low_free_space_reading_still_needs_an_acknowledgement() {
    let state = test_state();
    state.set_link_preflight_headroom_override_for_tests(Some(u64::MAX / 2));
    let dir = tempfile::tempdir().unwrap();
    match send(&state, link(dir.path(), false)).await {
        RespPayload::Error(message) => {
            assert!(message.contains("needs its risks acknowledged"), "{message}");
            assert!(message.contains("low free space"), "{message}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}
