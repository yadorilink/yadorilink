#![cfg(test)]

use std::sync::Arc;

use super::{enrollment_error_to_proto, membership_error_to_proto};
use crate::queries::link_status::LinkStatusReadPort;
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::session_state::EnrollmentKind;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ApplicationErrorCode, DaemonControlRequest, LinkRequest, PendingEnrollmentKind, StatusRequest,
};
use yadorilink_local_storage::SegmentBlockStore;

use crate::daemon_state::DaemonState;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    // A registered device with no signing key fails closed (see
    // `open_group_author`) --
    // any test driving a link watch start needs one wired.
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
    state
}

fn test_link_lifecycle(state: &Arc<DaemonState>) -> crate::application::LinkLifecycleService {
    let controller =
        Arc::new(crate::adapters::runtime::link_runtime_controller::LinkRuntimeController::new(
            state.clone(),
        ));
    crate::application::LinkLifecycleService::new(
        Arc::new(crate::adapters::runtime::link_lifecycle::DaemonLinkRepositoryAdapter::new(
            state.clone(),
        )),
        Arc::new(crate::adapters::runtime::link_lifecycle::DaemonLinkWatcherAdapter::new(
            state.clone(),
            controller,
        )),
    )
}

#[test]
fn membership_ambiguity_maps_to_a_structured_application_error() {
    let error = membership_error_to_proto(
        crate::application::ReplicaMembershipError::CoordinationAmbiguous {
            detail: "response was lost".into(),
        },
    );
    assert_eq!(error.code, ApplicationErrorCode::CoordinationAmbiguous as i32);
    assert!(error.message.contains("response was lost"));
}

#[test]
fn enrollment_compensation_pending_preserves_operation_identity() {
    let error =
        enrollment_error_to_proto(crate::application::EnrollmentError::CompensationPending {
            operation_id: "operation-1".into(),
            detail: "local unlink failed".into(),
        });
    assert_eq!(error.code, ApplicationErrorCode::CompensationPending as i32);
    assert_eq!(error.operation_id, "operation-1");
}

/// A `LinkRequest` whose `pending_enrollment_operation_id` is set commits
/// the link and the marker atomically (see
/// `SyncState::add_link_with_pending_enrollment`), but `start_link_watch`
/// runs *after* that commit and can still fail. Forced here by making
/// `.yadorilinkignore` itself a directory rather than a file, so
/// `EffectiveIgnoreSet::load_for_link_root` -- the first fallible step
/// inside `start_link_watch`, run before anything is registered in
/// `DaemonState`'s in-memory maps -- hits a real (non-`NotFound`) I/O
/// error reading it. `link` must roll the already-committed link and
/// marker back on that failure -- every caller (the CLI's `share
/// create`/`share join`) treats any `Err` from this whole call as
/// "nothing was created" and only compensates the coordination-plane
/// side, so leaving local rows behind here would strand them forever
/// with no coordination-side marker retry to find them.
#[tokio::test]
async fn link_rolls_back_the_link_and_marker_when_a_post_commit_step_fails() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".yadorilinkignore")).unwrap();
    let state = test_state();
    let request = LinkRequest {
        local_path: dir.path().to_string_lossy().to_string(),
        group_id: "group-1".to_string(),
        on_demand: false,
        acknowledge_risks: true,
        pending_enrollment_operation_id: "op-1".to_string(),
        pending_enrollment_kind: PendingEnrollmentKind::Create as i32,
        pending_enrollment_device_id: "device-a".to_string(),
    };

    let result =
        test_link_lifecycle(&state).link(super::decode_link_command(request).unwrap()).await;

    assert!(
        result.is_err(),
        "a directory named .yadorilinkignore must fail to load as the ignore file"
    );
    assert!(
        state.replica_coordinator.link_repository().list_links().unwrap().is_empty(),
        "the link must be rolled back, not left behind"
    );
    assert!(
        state
            .replica_coordinator
            .enrollment_repository()
            .list_pending_enrollments()
            .unwrap()
            .is_empty(),
        "the pending-enrollment marker must be rolled back too -- otherwise nothing ever \
         resolves it, since the link it names doesn't exist"
    );
}

/// Indexes one current file record in `group_id` -- just enough for the
/// readiness gate below to have something to hand off (an empty group is
/// vacuously ready regardless of any peer, which these tests are
/// deliberately not exercising).
fn upsert_solo_file(state: &DaemonState, group_id: &str) {
    use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            group_id,
            &FileRecord {
                path: "solo.bin".into(),
                size: 4,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash: vec![1u8; 32], offset: 0, size: 4 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
}

#[test]
fn lease_acquisition_errors_are_not_reported_as_readiness_failures() {
    let demotion =
        crate::application::replica_role_service::demotion_handoff_lease_failure_message();
    let unlink = crate::application::replica_role_service::unlink_handoff_lease_failure_message(
        "/tmp/group",
    );

    for message in [&demotion, &unlink] {
        assert!(message.contains("confirmed a ready replica"));
        assert!(message.contains("could not obtain the required handoff lease"));
        assert!(
            !message.contains("no other complete copy"),
            "lease failure must not be mislabeled as readiness failure: {message}"
        );
    }
}

/// The last full-replica device for a group cannot unlink it: with no
/// other device known to store everything, unlinking would leave the group
/// with no complete copy, so the guard refuses fail-closed.
#[tokio::test]
async fn control_socket_last_full_replica_cannot_unlink() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    // A real file to hand off -- an empty group would be vacuously ready
    // regardless of any peer.
    upsert_solo_file(&state, "group-1");
    // Eager link (the default) => this device is a full replica. No peer
    // full-replica is recorded, so it is the last one.
    let err = crate::adapters::build_application_services(state.clone())
        .replica_role
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false, "group-1")
        .await
        .expect_err("unlinking the only complete copy must be refused");
    assert!(
        matches!(&err, crate::application::UnlinkError::NotProtected(m) if m.contains("no other complete copy")),
        "error should explain the readiness refusal: {err}"
    );
}

/// The unlink request refuses the last complete copy with the typed reason, not
/// a sentence a client would have to recognize.
#[tokio::test]
async fn unlink_of_the_only_complete_copy_is_refused_as_not_protected() {
    use yadorilink_ipc_proto::daemonctl::{
        ApplicationErrorCode, DaemonControlRequest, UnlinkRequest,
    };
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    upsert_solo_file(&state, "group-1");

    let context = crate::control_context::ControlContext::from_state(state.clone());
    let response = super::handle_request(
        &context,
        DaemonControlRequest {
            payload: Some(ReqPayload::Unlink(UnlinkRequest {
                local_path: "/home/alice/Photos".into(),
                force: false,
                expected_group_id: String::new(),
            })),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await;
    match response.payload {
        Some(RespPayload::CommandError(e)) => {
            assert_eq!(e.code(), ApplicationErrorCode::NotProtected, "{e:?}");
            assert!(e.message.contains("--force"), "{}", e.message);
        }
        other => panic!("expected a typed refusal, got {other:?}"),
    }
}

/// Merely recording a peer as "also a full replica" is not enough on its
/// own -- this is exactly the count-vs-readiness gap this guard closes.
/// With no connected session to that peer, its confirmation can never be
/// obtained, so unlinking must still be refused fail-closed.
#[tokio::test]
async fn recorded_peer_without_a_confirmed_ready_session_still_refused() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    upsert_solo_file(&state, "group-1");
    state.authority.set_peer_group_full_replica("device-b", "group-1", true);

    let err = crate::adapters::build_application_services(state.clone())
        .replica_role
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false, "group-1")
        .await
        .expect_err(
            "a recorded-but-unconfirmed peer must not be treated as a ready handoff target",
        );
    assert!(
        matches!(&err, crate::application::UnlinkError::NotProtected(m) if m.contains("no other complete copy")),
        "error should explain the readiness refusal: {err}"
    );
}

/// A group with no current files at all has nothing to hand off, so
/// unlinking it is vacuously allowed even with zero peers recorded.
#[tokio::test]
async fn full_replica_can_unlink_when_group_has_no_files() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();

    crate::adapters::build_application_services(state.clone())
        .replica_role
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false, "group-1")
        .await
        .expect("nothing to hand off, so unlink is vacuously allowed");
}

/// `--force` bypasses the readiness gate for a genuinely dead sole
/// replica -- the escape hatch, at the unit level (the surrounding CLI
/// plumbing is exercised in `yadorilink-cli`'s own tests).
#[tokio::test]
async fn forced_unlink_bypasses_the_readiness_gate() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    upsert_solo_file(&state, "group-1");

    crate::adapters::build_application_services(state.clone())
        .replica_role
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", true, "group-1")
        .await
        .expect("--force must bypass the readiness gate even with no ready replica");
}

/// `--force` bypassing the readiness gate latches the group's local
/// durability status to `Unknown`: the UI must not be able to
/// keep reporting the group Protected/"synced" after an override that may
/// have just discarded its only complete copy.
#[tokio::test]
async fn forced_unlink_latches_group_durability_unknown() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    upsert_solo_file(&state, "group-1");

    crate::adapters::build_application_services(state.clone())
        .replica_role
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", true, "group-1")
        .await
        .expect("--force must bypass the readiness gate even with no ready replica");

    assert_eq!(
        state.group_durability_status("group-1"),
        crate::durability_service::GroupDurabilityStatus::Unknown,
        "a force override must latch the group to Unknown, never leave it \
         reporting Protected"
    );
}

/// A normal (non-forced) unlink that succeeds without ever needing to
/// bypass the gate must NOT latch the group -- the latch is specifically
/// for when the gate was actually overridden, not every successful
/// unlink.
#[tokio::test]
async fn non_forced_unlink_does_not_latch_durability_unknown() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    // Nothing to hand off, so this succeeds vacuously without needing
    // --force at all.

    crate::adapters::build_application_services(state.clone())
        .replica_role
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false, "group-1")
        .await
        .expect("nothing to hand off, so unlink is vacuously allowed");

    // `Protected`/non-Unknown requires a fresh peer-confirmed (or
    // vacuous-empty, still peer-round-trip-confirmed) sweep round --
    // force one so this assertion tests the latch, not the unrelated
    // "never swept yet" default.
    state.refresh_custody_confirmation("group-1").await;
    assert_ne!(
        state.group_durability_status("group-1"),
        crate::durability_service::GroupDurabilityStatus::Unknown,
        "an unforced unlink must never latch the group's durability status"
    );
}

/// An on-demand device is a cache, not the group's durable holder, so it
/// may always unlink regardless of any other full replica.
#[tokio::test]
async fn on_demand_device_can_always_unlink() {
    use yadorilink_replica_domain::session_state::MaterializationPolicy;
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy("/home/alice/Photos", MaterializationPolicy::OnDemand)
        .unwrap();

    crate::adapters::build_application_services(state.clone())
        .replica_role
        .ensure_unlink_keeps_a_full_replica("/home/alice/Photos", false, "group-1")
        .await
        .expect("an on-demand device may always unlink");
}

/// The coordination plane's netmap push carries a `policyInvalidGroupIds`
/// list naming groups whose stored policy state is malformed or corrupt
/// on the coordination plane's side, so this device cannot trust
/// anything it currently believes about that group's membership/auth.
/// The daemon's netmap client never parses that list into anything (see
/// `change_auth`'s and `peer_orchestrator`'s netmap-handling tests), so
/// `mark_group_policy_stale` -- the one existing mechanism that would
/// make a group's trouble visible here -- is never called for it either.
///
/// `list_link_statuses` has no field at all carrying policy state, so a
/// group whose policy this daemon knows to be stale is reported
/// byte-for-byte identically to a perfectly healthy group: nothing
/// distinguishes "policy corrupt, do not trust this group's state" from
/// "everything is fine."
#[tokio::test]
async fn policy_invalid_group_id_surfaces_in_status() {
    let healthy_state = test_state();
    healthy_state
        .replica_coordinator
        .link_repository()
        .add_link("/home/alice/Photos", "group-1")
        .unwrap();

    let policy_invalid_state = test_state();
    policy_invalid_state
        .replica_coordinator
        .link_repository()
        .add_link("/home/alice/Photos", "group-1")
        .unwrap();
    // The closest real "policy invalid" signal the daemon can produce
    // today -- a real `policyInvalidGroupIds` entry never reaches this
    // call (that is exactly the gap), but this is the one state
    // transition `status` output would need to reflect once it does.
    policy_invalid_state.mark_group_policy_stale("group-1");

    let healthy_status =
        crate::adapters::query::link_status::DaemonLinkStatusReader::new(healthy_state)
            .list_links()
            .unwrap();
    let policy_invalid_status =
        crate::adapters::query::link_status::DaemonLinkStatusReader::new(policy_invalid_state)
            .list_links()
            .unwrap();

    assert_ne!(
        healthy_status, policy_invalid_status,
        "a policy-invalid group's status must be distinguishable from a healthy group's \
         (surfaced as something other than merely \"no peers\"), but list_link_statuses \
         carries no field for policy state at all, so the two are identical"
    );
}

/// `LatchGroupDurabilityUnknownRequest` -- the control request the
/// CLI-orchestrated force paths (`durability_force.rs`) send for each
/// group actually forced past the readiness gate, so `status` reports
/// `Unknown` for it exactly like the daemon-side forced-unlink
/// path's own latch already does. Exercised through `handle_request`
/// (the real dispatch a control-socket connection runs through), not the
/// pub `latch_group_durability_unknown` method directly.
#[tokio::test]
async fn latch_group_durability_unknown_request_latches_the_group() {
    let state = test_state();
    // Protected requires at least one confirmation sweep round
    // (real or vacuous-empty) to have run -- force one.
    state.refresh_custody_confirmation("group-1").await;
    assert_eq!(
        state.group_durability_status("group-1"),
        crate::durability_service::GroupDurabilityStatus::Protected,
        "sanity check: an untouched group with no files derives Protected"
    );

    let req = DaemonControlRequest {
        payload: Some(ReqPayload::LatchGroupDurabilityUnknown(
            yadorilink_ipc_proto::daemonctl::LatchGroupDurabilityUnknownRequest {
                group_id: "group-1".to_string(),
            },
        )),
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        req,
    )
    .await;
    assert!(
        matches!(resp.payload, Some(RespPayload::LatchGroupDurabilityUnknown(_))),
        "expected a LatchGroupDurabilityUnknown response, got {:?}",
        resp.payload
    );

    assert_eq!(
        state.group_durability_status("group-1"),
        crate::durability_service::GroupDurabilityStatus::Unknown,
        "the latch must take effect through the real request-dispatch path"
    );
}

/// `ListRecoveryOperations`/`ShowRecoveryOperation` exercised through the real dispatch path, confirming the
/// proto conversion round-trips a valid row's fields and that `show`
/// resolves the same way `list` does.
#[tokio::test]
async fn list_recovery_operations_reports_a_valid_row() {
    use yadorilink_replica_domain::session_state::EnrollmentKind;
    use yadorilink_replica_domain::session_state::{EnrollmentOperation, EnrollmentOperationState};

    let state = test_state();
    state
        .replica_coordinator
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: Some("group-1".to_string()),
            group_name: None,
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::ActivationPending,
            last_error: None,
            attempts: 2,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();

    let list_req = DaemonControlRequest {
        payload: Some(ReqPayload::ListRecoveryOperations(
            yadorilink_ipc_proto::daemonctl::ListRecoveryOperationsRequest {},
        )),
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let list_resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        list_req,
    )
    .await;
    let Some(RespPayload::ListRecoveryOperations(list)) = list_resp.payload else {
        panic!("expected a ListRecoveryOperations response, got {:?}", list_resp.payload);
    };
    assert!(list.invalid.is_empty());
    assert_eq!(list.operations.len(), 1);
    let op = &list.operations[0];
    assert_eq!(op.operation_id, "op-1");
    assert_eq!(op.domain, "enrollment");
    assert_eq!(op.action, "create");
    assert_eq!(op.state, "activation_pending");
    assert_eq!(op.severity, "pending");
    assert_eq!(op.group_ids, vec!["group-1".to_string()]);
    assert_eq!(op.device_id.as_deref(), Some("device-a"));
    assert_eq!(op.attempts, 2);
}

/// An unrecognized `domain` value is rejected explicitly, never
/// silently treated as "operation not found" and never reaching the
/// coordination-config check or a remote lookup.
#[tokio::test]
async fn show_recovery_operation_rejects_an_unknown_domain() {
    let state = test_state();
    let req = DaemonControlRequest {
        payload: Some(ReqPayload::ShowRecoveryOperation(
            yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationRequest {
                domain: "enrolment".to_string(), // typo
                operation_id: "op-1".to_string(),
            },
        )),
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        req,
    )
    .await;
    match resp.payload {
        Some(RespPayload::Error(msg)) => {
            assert!(
                msg.contains("unknown recovery domain"),
                "expected an unknown-domain error, got {msg:?}"
            );
        }
        other => panic!("expected RespPayload::Error, got {other:?}"),
    }
}

/// With no coordination-plane address/access token recorded on this
/// device, `show` must fail with a top-level operational error --
/// never fabricate remote evidence, and never even attempt a local
/// snapshot read.
#[tokio::test]
async fn show_recovery_operation_without_coordination_config_is_an_operational_error() {
    let state = test_state();
    assert!(state.coordination_client_config().is_none());

    let req = DaemonControlRequest {
        payload: Some(ReqPayload::ShowRecoveryOperation(
            yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationRequest {
                domain: "enrollment".to_string(),
                operation_id: "op-1".to_string(),
            },
        )),
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        req,
    )
    .await;
    match resp.payload {
        Some(RespPayload::Error(msg)) => {
            assert!(msg.contains("not configured"), "expected a config error, got {msg:?}");
        }
        other => panic!("expected RespPayload::Error, got {other:?}"),
    }
}

/// A `show` request naming an id that exists in no journal row of the
/// requested domain reports `not_found` as a typed outcome, never the
/// top-level `RespPayload::Error` fallback -- and never performs a
/// remote lookup (the coordination address is set but never contacted,
/// since a real server isn't even running at that address).
#[tokio::test]
async fn show_recovery_operation_reports_not_found_for_an_unknown_id() {
    let state = test_state();
    state.set_coordination_client_config(
        "http://127.0.0.1:1".to_string(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );

    let req = DaemonControlRequest {
        payload: Some(ReqPayload::ShowRecoveryOperation(
            yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationRequest {
                domain: "enrollment".to_string(),
                operation_id: "op-does-not-exist".to_string(),
            },
        )),
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        req,
    )
    .await;
    let Some(RespPayload::ShowRecoveryOperation(show)) = resp.payload else {
        panic!("expected a ShowRecoveryOperation response, got {:?}", resp.payload);
    };
    match show.result {
        Some(
            yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::NotFound(
                not_found,
            ),
        ) => {
            assert_eq!(not_found.key.unwrap().operation_id, "op-does-not-exist");
        }
        other => panic!("expected Result::NotFound, got {other:?}"),
    }
}

/// A journal row that fails strict decoding reports `invalid` as a
/// typed outcome, observed before any remote lookup is attempted.
#[tokio::test]
async fn show_recovery_operation_reports_invalid_for_a_malformed_row() {
    let state = test_state();
    state.set_coordination_client_config(
        "http://127.0.0.1:1".to_string(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    state.replica_coordinator.plant_malformed_membership_operation_for_test("op-bad").unwrap();

    let req = DaemonControlRequest {
        payload: Some(ReqPayload::ShowRecoveryOperation(
            yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationRequest {
                domain: "membership".to_string(),
                operation_id: "op-bad".to_string(),
            },
        )),
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        req,
    )
    .await;
    let Some(RespPayload::ShowRecoveryOperation(show)) = resp.payload else {
        panic!("expected a ShowRecoveryOperation response, got {:?}", resp.payload);
    };
    assert!(matches!(
        show.result,
        Some(yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::Invalid(_))
    ));
}

/// End-to-end: a real journal row, a mocked coordination-plane 404
/// (`RecordNotFound`), and the resulting `Diagnosed` outcome carrying
/// the SAME operation summary the journal row itself has.
#[tokio::test]
async fn show_recovery_operation_returns_a_stable_diagnosis() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use yadorilink_replica_domain::session_state::EnrollmentKind;
    use yadorilink_replica_domain::session_state::{EnrollmentOperation, EnrollmentOperationState};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let state = test_state();
    state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    state
        .replica_coordinator
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: Some("group-1".to_string()),
            group_name: Some("photos".to_string()),
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::ActivationPending,
            last_error: None,
            attempts: 0,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();

    let req = DaemonControlRequest {
        payload: Some(ReqPayload::ShowRecoveryOperation(
            yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationRequest {
                domain: "enrollment".to_string(),
                operation_id: "op-1".to_string(),
            },
        )),
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        req,
    )
    .await;
    let Some(RespPayload::ShowRecoveryOperation(show)) = resp.payload else {
        panic!("expected a ShowRecoveryOperation response, got {:?}", resp.payload);
    };
    match show.result {
        Some(
            yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::Diagnosed(
                diagnosis,
            ),
        ) => {
            let op = diagnosis.operation.unwrap();
            assert_eq!(op.operation_id, "op-1");
            assert_eq!(op.domain, "enrollment");
            let remote = diagnosis.remote.unwrap();
            assert_eq!(remote.status, "record_not_found");
            assert!(!diagnosis.recommendation.is_empty());
        }
        other => panic!("expected Result::Diagnosed, got {other:?}"),
    }
}

/// A request shaped exactly the way older CLI builds built one — a
/// real payload set, `protocol_version` left at its default (0)
/// rather than the current daemon's own `CONTROL_PROTOCOL_VERSION` —
/// is rejected before the payload is ever dispatched, not answered
/// using backward-compatible defaults: this repository has not
/// shipped a public release, so there is no supported skew to be
/// lenient about.
#[tokio::test]
async fn old_cli_request_with_zero_protocol_version_is_rejected() {
    let state = test_state();
    let req = DaemonControlRequest {
        payload: Some(ReqPayload::Status(StatusRequest {})),
        protocol_version: 0,
    };

    let resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        req,
    )
    .await;

    match resp.payload {
        Some(RespPayload::Error(msg)) => {
            assert!(
                msg.contains("requires exactly protocol version"),
                "expected a version-mismatch message, got {msg:?}"
            );
        }
        other => panic!("expected RespPayload::Error, got {other:?}"),
    }
    assert_eq!(
        resp.daemon_protocol_version,
        yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        "the daemon still stamps its own current version on the response even when \
         rejecting an old-shaped request"
    );
}

/// Stands in for a newer CLI build sending a request variant *this*
/// daemon build has never heard of — protobuf drops an unrecognized
/// oneof field number entirely, so from the daemon's point of view
/// that decodes as `payload: None`, exactly as constructed here,
/// alongside a `protocol_version` newer than what this daemon
/// reports. The CLI must be told to upgrade the daemon, not given the
/// same generic "empty request" a truly malformed/empty request gets
/// — and the request must never reach payload dispatch to produce
/// that message, since it's rejected by the upfront version check.
#[tokio::test]
async fn newer_client_unset_payload_reports_upgrade_the_daemon() {
    let state = test_state();
    let newer_version = yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION + 1;
    let req = DaemonControlRequest { payload: None, protocol_version: newer_version };

    let resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        req,
    )
    .await;

    match resp.payload {
        Some(RespPayload::Error(msg)) => {
            assert!(
                msg.contains("upgrade the daemon"),
                "expected an upgrade-the-daemon message, got {msg:?}"
            );
        }
        other => panic!("expected RespPayload::Error, got {other:?}"),
    }
}

/// Control case for the test above: a genuinely empty/malformed
/// request from a *version-matched* client (no payload, but the
/// correct current `protocol_version`) gets the plain "empty
/// request" message, not a version-mismatch one — the two failure
/// modes stay distinguishable once the exact-version check passes.
#[tokio::test]
async fn truly_empty_request_still_reports_generic_empty_request() {
    let state = test_state();
    let req = DaemonControlRequest {
        payload: None,
        protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    };

    let resp = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        req,
    )
    .await;

    assert_eq!(resp.payload, Some(RespPayload::Error("empty request".to_string())));
}

// --- One live link per group, at the daemon's own `link` seam -----------

fn link_request(local_path: &str, group_id: &str, acknowledge_risks: bool) -> LinkRequest {
    LinkRequest {
        local_path: local_path.to_string(),
        group_id: group_id.to_string(),
        on_demand: false,
        acknowledge_risks,
        pending_enrollment_operation_id: String::new(),
        pending_enrollment_kind: 0,
        pending_enrollment_device_id: String::new(),
    }
}

/// `--yes` must NOT buy past this. The path-overlap checks in `link` are a
/// warning gate deliberately gated on `!acknowledge_risks` -- a user may
/// knowingly accept a nested link. A second live root on one folder group
/// is not in that category at any confirmation level: each folder's scan
/// would delete the other's files on every device. Routing this rule
/// through `nested_conflicts` would silently inherit that bypass.
#[tokio::test]
async fn a_second_link_is_refused_even_with_acknowledge_risks() {
    let state = test_state();
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let link_lifecycle = test_link_lifecycle(&state);
    link_lifecycle
        .link(
            super::decode_link_command(link_request(&a.path().to_string_lossy(), "group-1", true))
                .unwrap(),
        )
        .await
        .unwrap();

    let err = link_lifecycle
        .link(
            super::decode_link_command(link_request(&b.path().to_string_lossy(), "group-1", true))
                .unwrap(),
        )
        .await
        .expect_err("--yes must not buy past the one-live-link-per-group rule");

    assert!(
        err.to_string().contains("already linked"),
        "the error must name the real problem, got {err}"
    );
    let links = state.replica_coordinator.link_repository().list_links().unwrap();
    assert_eq!(links.len(), 1, "the refusal must not add or delete a link");
    assert_eq!(links[0].key(), a.path().to_string_lossy());
}

/// Links `first` to `group-1`, then tries `second` under `group_two`, with and
/// without the risk acknowledgement; both attempts must be refused naming the
/// existing link, and nothing may be added.
async fn assert_topology_refused(first: &str, second: &str, group_two: &str) {
    let state = test_state();
    let link_lifecycle = test_link_lifecycle(&state);
    link_lifecycle
        .link(super::decode_link_command(link_request(first, "group-1", false)).unwrap())
        .await
        .unwrap();
    for acknowledge in [false, true] {
        let err = link_lifecycle
            .link(super::decode_link_command(link_request(second, group_two, acknowledge)).unwrap())
            .await
            .expect_err("an unsupported topology must be refused at every confirmation level");
        let message = err.to_string();
        assert!(
            message.contains("unsupported link topology") && message.contains(first),
            "the refusal must name the conflicting link {first}, got {message} \
             (acknowledge={acknowledge})"
        );
    }
    let links = state.replica_coordinator.link_repository().list_links().unwrap();
    assert_eq!(links.len(), 1, "a refusal must not add or delete a link");
}

#[tokio::test]
async fn a_link_nested_inside_another_is_refused_even_with_acknowledge_risks() {
    let parent = tempfile::tempdir().unwrap();
    let child = parent.path().join("child");
    std::fs::create_dir(&child).unwrap();
    assert_topology_refused(&parent.path().to_string_lossy(), &child.to_string_lossy(), "group-2")
        .await;
}

#[tokio::test]
async fn a_link_containing_another_is_refused_even_with_acknowledge_risks() {
    let parent = tempfile::tempdir().unwrap();
    let child = parent.path().join("child");
    std::fs::create_dir(&child).unwrap();
    assert_topology_refused(&child.to_string_lossy(), &parent.path().to_string_lossy(), "group-2")
        .await;
}

#[tokio::test]
async fn the_same_path_linked_to_another_group_is_refused_even_with_acknowledge_risks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_string_lossy().to_string();
    assert_topology_refused(&path, &path, "group-2").await;
}

#[cfg(unix)]
#[tokio::test]
async fn the_same_folder_through_a_symlink_is_refused_even_with_acknowledge_risks() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    assert_topology_refused(&real.to_string_lossy(), &alias.to_string_lossy(), "group-2").await;
}

#[cfg(unix)]
#[tokio::test]
async fn a_nested_folder_reached_through_a_symlink_is_refused_even_with_acknowledge_risks() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    let inner = real.join("inner");
    std::fs::create_dir_all(&inner).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    assert_topology_refused(
        &real.to_string_lossy(),
        &alias.join("inner").to_string_lossy(),
        "group-2",
    )
    .await;
}

/// Sibling folders of different groups stay linkable: only containment is
/// refused.
#[tokio::test]
async fn sibling_links_of_different_groups_are_allowed() {
    let state = test_state();
    let parent = tempfile::tempdir().unwrap();
    let a = parent.path().join("a");
    let b = parent.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    let link_lifecycle = test_link_lifecycle(&state);
    for (path, group) in [(&a, "group-1"), (&b, "group-2")] {
        link_lifecycle
            .link(
                super::decode_link_command(link_request(&path.to_string_lossy(), group, false))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    assert_eq!(state.replica_coordinator.link_repository().list_links().unwrap().len(), 2);
}

/// Re-linking the SAME folder to the same group is idempotent and must stay
/// allowed: it is exactly what a `share join` retry does after a failed
/// link's own rollback. A `!existing.is_empty()` check instead of
/// `any(|p| p != &r.local_path)` would break that retry.
#[tokio::test]
async fn an_idempotent_same_path_relink_is_not_refused() {
    let state = test_state();
    let a = tempfile::tempdir().unwrap();
    let path = a.path().to_string_lossy().to_string();
    let link_lifecycle = test_link_lifecycle(&state);
    link_lifecycle
        .link(super::decode_link_command(link_request(&path, "group-1", true)).unwrap())
        .await
        .unwrap();

    link_lifecycle
        .link(super::decode_link_command(link_request(&path, "group-1", true)).unwrap())
        .await
        .expect("re-linking the same folder to the same group must stay idempotent");

    assert_eq!(state.replica_coordinator.link_repository().list_links().unwrap().len(), 1);
}

// `classify_link_failure`/`enrollment_link_spec` tests moved to
// `crate::adapters::runtime::enrollment_link`'s own test module (Phase
// 2 Commit 2) -- that adapter now owns this classification.

/// Qualifies `recovery show` for the Enrollment domain
/// end to end -- real file-backed SQLite, closed and reopened (a real
/// crash+restart, not an in-memory stand-in), through the actual
/// control-socket dispatch path (`super::handle_request`), against a
/// mocked coordination plane, down to the wire response. No randomness,
/// no sleep-based timing, no periodic-sweep dependency: every case is
/// deterministic by construction.
mod recovery_crash_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::recovery::{LocalRecoveryEvidence, RecoveryLocalSnapshot, RecoveryOperationKey};
    use crate::replica_coordinator::ReplicaCoordinator;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Notify;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use yadorilink_replica_domain::recovery::RecoveryDomain;
    use yadorilink_replica_domain::session_state::{
        EnrollmentOperation, EnrollmentOperationState, MembershipCommitMode,
        MembershipDurabilityScope, MembershipOperation, MembershipOperationAction,
        MembershipOperationState, PendingEnrollment, RoleLossAction, RoleLossOperationParams,
        RoleLossOperationState,
    };

    use super::*;

    const DEVICE_ID: &str = "device-a";
    const LOCAL_PATH: &str = "/home/alice/Photos";
    const GROUP_ID: &str = "group-1";
    const GROUP_NAME: &str = "photos";

    fn daemon_state_for(sync_state: Arc<ReplicaCoordinator>) -> Arc<DaemonState> {
        let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
        let state = DaemonState::new(DEVICE_ID.to_string(), sync_state, store);
        // Called synchronously, before this function returns and before
        // this task's first `.await` -- see
        // `disable_membership_recovery_sweep_for_test`'s own doc comment
        // for why that makes this race-free by construction: the daemon's
        // own real-time periodic membership/role-loss reconciliation
        // sweep would otherwise mutate or delete the exact journal rows
        // this whole module plants to qualify `recovery show` against.
        state.disable_membership_recovery_sweep_for_test();
        state
    }

    fn base_operation(
        kind: EnrollmentKind,
        state: EnrollmentOperationState,
        group_id: Option<&str>,
        group_name: Option<&str>,
        storage_mode: &str,
    ) -> EnrollmentOperation {
        EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind,
            group_id: group_id.map(str::to_string),
            group_name: group_name.map(str::to_string),
            device_id: DEVICE_ID.to_string(),
            local_path: LOCAL_PATH.to_string(),
            storage_mode: storage_mode.to_string(),
            state,
            last_error: None,
            attempts: 0,
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    fn marker(kind: EnrollmentKind) -> PendingEnrollment {
        PendingEnrollment {
            operation_id: "op-1".to_string(),
            kind,
            group_id: GROUP_ID.to_string(),
            device_id: DEVICE_ID.to_string(),
            local_path: LOCAL_PATH.to_string(),
        }
    }

    fn create_body(status: &str, result_group_id: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "operationId": "op-1",
            "kind": "create",
            "status": status,
            "requestFingerprint": "fp",
            "request": { "userId": "user-1", "groupName": GROUP_NAME, "deviceId": DEVICE_ID },
            "result": result_group_id.map(|g| serde_json::json!({ "groupId": g })),
        })
    }

    fn join_body(status: &str, result_group_id: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "operationId": "op-1",
            "kind": "join",
            "status": status,
            "requestFingerprint": "fp",
            "request": {
                "userId": "user-1",
                "groupId": GROUP_ID,
                "deviceId": DEVICE_ID,
                "storageMode": "eager",
            },
            "result": result_group_id.map(|g| serde_json::json!({ "groupId": g })),
        })
    }

    /// Closes every handle to `sync_state`'s connection pool by dropping
    /// the sole `Arc`, then opens a genuinely fresh `SyncState` over the
    /// SAME file -- the actual crash-and-restart this module qualifies
    /// against, not an in-memory stand-in that never round-trips through
    /// disk at all.
    fn reopen(
        db_path: &std::path::Path,
        sync_state: Arc<ReplicaCoordinator>,
    ) -> Arc<ReplicaCoordinator> {
        drop(sync_state);
        Arc::new(ReplicaCoordinator::open(db_path).unwrap())
    }

    /// The SAME typed evidence [`diagnose_stable`] itself reads
    /// (`SyncState::recovery_local_snapshot`) -- full
    /// journal row, link observation, and pending-marker observation,
    /// not a hand-picked subset. Comparing this before/after a
    /// diagnosis is the direct read-only invariant this module
    /// qualifies, in the exact same terms `diagnose_stable`'s own race
    /// detection already uses.
    fn enrollment_evidence(sync_state: &ReplicaCoordinator) -> LocalRecoveryEvidence {
        local_recovery_evidence(sync_state, RecoveryDomain::Enrollment, "op-1")
    }

    /// Shared across all three domains -- the SAME typed evidence
    /// `diagnose_stable` itself reads for `(domain, operation_id)`.
    fn local_recovery_evidence(
        sync_state: &ReplicaCoordinator,
        domain: RecoveryDomain,
        operation_id: &str,
    ) -> LocalRecoveryEvidence {
        let key = RecoveryOperationKey { domain, operation_id: operation_id.to_string() };
        match sync_state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap() {
            RecoveryLocalSnapshot::Found(evidence) => *evidence,
            other => panic!("expected found evidence, got {other:?}"),
        }
    }

    /// Shared across all three domains -- runs the real `recovery show`
    /// request/response round trip through `handle_request` and
    /// returns the decoded `ShowRecoveryOperationResponse`.
    async fn run_show_request(
        daemon_state: &Arc<DaemonState>,
        domain: RecoveryDomain,
        operation_id: &str,
    ) -> yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationResponse {
        let req = DaemonControlRequest {
            payload: Some(ReqPayload::ShowRecoveryOperation(
                yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationRequest {
                    domain: domain.as_str().to_string(),
                    operation_id: operation_id.to_string(),
                },
            )),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let resp = super::super::handle_request(
            &crate::control_context::ControlContext::from_state(daemon_state.clone()),
            req,
        )
        .await;
        let Some(RespPayload::ShowRecoveryOperation(show)) = resp.payload else {
            panic!("expected a ShowRecoveryOperation response, got {:?}", resp.payload);
        };
        show
    }

    /// Shared across all three domains -- the common assertions every
    /// `RecoveryDiagnosis` proto qualifies on regardless of domain.
    /// Domain-specific fields (action/local_state, link/marker/
    /// remote-identity qualification) are asserted separately by each
    /// domain's own case runner.
    struct ExpectedDiagnosis {
        operation_id: &'static str,
        domain: &'static str,
        remote_state: String,
        recommendation: &'static str,
        automatic_recovery_safe: bool,
        reason_codes: &'static [&'static str],
    }

    fn assert_diagnosis(
        label: &str,
        diagnosis: &yadorilink_ipc_proto::daemonctl::RecoveryDiagnosis,
        expected: &ExpectedDiagnosis,
    ) {
        let op = diagnosis.operation.as_ref().unwrap();
        assert_eq!(op.operation_id, expected.operation_id, "[{label}] operation_id");
        assert_eq!(op.domain, expected.domain, "[{label}] domain");
        let remote = diagnosis.remote.as_ref().unwrap();
        assert_eq!(remote.status, expected.remote_state, "[{label}] remote state");
        assert_eq!(diagnosis.recommendation, expected.recommendation, "[{label}] recommendation");
        assert_eq!(
            diagnosis.automatic_recovery_safe, expected.automatic_recovery_safe,
            "[{label}] automatic_recovery_safe"
        );
        assert_eq!(diagnosis.reason_codes, expected.reason_codes, "[{label}] reason_codes");
    }

    struct Case {
        label: &'static str,
        kind: EnrollmentKind,
        state: EnrollmentOperationState,
        group_id: Option<&'static str>,
        group_name: Option<&'static str>,
        storage_mode: &'static str,
        with_link_and_marker: bool,
        remote_status: Option<&'static str>,
        remote_result_group_id: Option<&'static str>,
        expected_recommendation: &'static str,
        expected_automatic_recovery_safe: bool,
        expected_reason_codes: &'static [&'static str],
        expected_link_status: &'static str,
        expected_marker_status: &'static str,
        expected_remote_identity_status: &'static str,
    }

    async fn run_case(case: Case) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.sqlite3");

        // 1. Build a persisted journal state.
        let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
        sync_state
            .enrollment_repository()
            .try_insert_enrollment_operation(&base_operation(
                case.kind,
                case.state,
                case.group_id,
                case.group_name,
                case.storage_mode,
            ))
            .unwrap();
        if case.with_link_and_marker {
            sync_state
                .enrollment_repository()
                .add_link_with_pending_enrollment(LOCAL_PATH, GROUP_ID, &marker(case.kind))
                .unwrap();
        }

        // 2. Close, 3. reopen the SAME file -- the actual crash+restart.
        let sync_state = reopen(&db_path, sync_state);
        let before = enrollment_evidence(&sync_state);

        // 4. Mock the coordination plane's evidence.
        let server = MockServer::start().await;
        let response = match case.remote_status {
            None => ResponseTemplate::new(404),
            Some(status) => {
                let body = match case.kind {
                    EnrollmentKind::Create => create_body(status, case.remote_result_group_id),
                    EnrollmentKind::Join => join_body(status, case.remote_result_group_id),
                };
                ResponseTemplate::new(200).set_body_json(body)
            }
        };
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;

        let daemon_state = daemon_state_for(sync_state.clone());
        daemon_state.set_coordination_client_config(
            server.uri(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );

        // 5. Run the real `recovery show` path.
        let req = DaemonControlRequest {
            payload: Some(ReqPayload::ShowRecoveryOperation(
                yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationRequest {
                    domain: RecoveryDomain::Enrollment.as_str().to_string(),
                    operation_id: "op-1".to_string(),
                },
            )),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let resp = super::super::handle_request(
            &crate::control_context::ControlContext::from_state(daemon_state.clone()),
            req,
        )
        .await;

        // 6. Verify the wire outcome.
        let Some(RespPayload::ShowRecoveryOperation(show)) = resp.payload else {
            panic!(
                "[{}] expected a ShowRecoveryOperation response, got {:?}",
                case.label, resp.payload
            );
        };
        let Some(
            yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::Diagnosed(
                diagnosis,
            ),
        ) = show.result
        else {
            panic!("[{}] expected Diagnosed, got {:?}", case.label, show.result);
        };

        let op = diagnosis.operation.as_ref().unwrap();
        assert_eq!(op.operation_id, "op-1", "[{}] operation_id", case.label);
        assert_eq!(op.domain, "enrollment", "[{}] domain", case.label);
        assert_eq!(
            op.action,
            match case.kind {
                EnrollmentKind::Create => "create",
                EnrollmentKind::Join => "join",
            },
            "[{}] action",
            case.label
        );
        assert_eq!(op.state, case.state.as_db_str(), "[{}] local state", case.label);
        let remote = diagnosis.remote.as_ref().unwrap();
        let expected_remote_state = match case.remote_status {
            None => "record_not_found".to_string(),
            Some(s) => s.to_string(),
        };
        assert_eq!(remote.status, expected_remote_state, "[{}] remote state", case.label);
        assert_eq!(
            diagnosis.recommendation, case.expected_recommendation,
            "[{}] recommendation",
            case.label
        );
        assert_eq!(
            diagnosis.automatic_recovery_safe, case.expected_automatic_recovery_safe,
            "[{}] automatic_recovery_safe",
            case.label
        );
        assert_eq!(
            diagnosis.reason_codes, case.expected_reason_codes,
            "[{}] reason_codes",
            case.label
        );

        let qualification = diagnosis.qualification.as_ref().unwrap();
        let link = qualification.link.as_ref().unwrap();
        assert_eq!(link.status, case.expected_link_status, "[{}] link qualification", case.label);
        assert!(link.mismatch_fields.is_empty(), "[{}] link mismatch_fields", case.label);
        let marker = qualification.pending_marker.as_ref().unwrap();
        assert_eq!(
            marker.status, case.expected_marker_status,
            "[{}] marker qualification",
            case.label
        );
        assert!(marker.mismatch_fields.is_empty(), "[{}] marker mismatch_fields", case.label);
        let remote_identity = qualification.remote_identity.as_ref().unwrap();
        assert_eq!(
            remote_identity.status, case.expected_remote_identity_status,
            "[{}] remote identity qualification",
            case.label
        );
        assert!(
            remote_identity.mismatch_fields.is_empty(),
            "[{}] remote_identity mismatch_fields",
            case.label
        );
        assert!(
            remote_identity.not_comparable_reasons.is_empty(),
            "[{}] remote_identity not_comparable_reasons",
            case.label
        );
        let expected_not_evaluated_reason =
            case.remote_status.is_none().then(|| "record_not_found".to_string());
        assert_eq!(
            remote_identity.not_evaluated_reason, expected_not_evaluated_reason,
            "[{}] remote_identity not_evaluated_reason",
            case.label
        );

        // 7. Worker GET happened exactly once.
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1, "[{}] Worker GET count", case.label);

        // 8. Read-only: the FULL typed local recovery evidence (journal
        // row, link observation, pending-marker observation) is
        // unchanged -- not a hand-picked subset.
        let after = enrollment_evidence(&sync_state);
        assert_eq!(before, after, "[{}] local recovery evidence must not change", case.label);
    }

    #[tokio::test]
    async fn prepare_pending_no_link_no_marker_record_not_found_retries_same_request() {
        run_case(Case {
            label: "PreparePending/absent/404",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::PreparePending,
            group_id: None,
            group_name: Some(GROUP_NAME),
            storage_mode: "eager",
            with_link_and_marker: false,
            remote_status: None,
            remote_result_group_id: None,
            expected_recommendation: "retry_same_remote_request",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &["remote_record_not_found"],
            expected_link_status: "confirmed_absent",
            expected_marker_status: "confirmed_absent",
            expected_remote_identity_status: "not_evaluated",
        })
        .await;
    }

    #[tokio::test]
    async fn prepare_pending_no_link_no_marker_preparing_waits() {
        run_case(Case {
            label: "PreparePending/absent/preparing",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::PreparePending,
            group_id: None,
            group_name: Some(GROUP_NAME),
            storage_mode: "eager",
            with_link_and_marker: false,
            remote_status: Some("preparing"),
            remote_result_group_id: None,
            expected_recommendation: "wait_for_automatic_recovery",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "confirmed_absent",
            expected_marker_status: "confirmed_absent",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    #[tokio::test]
    async fn prepared_no_link_no_marker_prepared_with_result_waits() {
        run_case(Case {
            label: "Prepared/absent/prepared",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::Prepared,
            group_id: Some(GROUP_ID),
            group_name: Some(GROUP_NAME),
            storage_mode: "eager",
            with_link_and_marker: false,
            remote_status: Some("prepared"),
            remote_result_group_id: Some(GROUP_ID),
            expected_recommendation: "wait_for_automatic_recovery",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "confirmed_absent",
            expected_marker_status: "confirmed_absent",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    #[tokio::test]
    async fn local_setup_pending_exact_evidence_prepared_waits() {
        run_case(Case {
            label: "LocalSetupPending/exact/prepared",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::LocalSetupPending,
            group_id: Some(GROUP_ID),
            group_name: Some(GROUP_NAME),
            storage_mode: "eager",
            with_link_and_marker: true,
            remote_status: Some("prepared"),
            remote_result_group_id: Some(GROUP_ID),
            expected_recommendation: "wait_for_automatic_recovery",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "exact",
            expected_marker_status: "exact",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    #[tokio::test]
    async fn activation_pending_exact_evidence_prepared_retries_activation() {
        run_case(Case {
            label: "ActivationPending/exact/prepared",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::ActivationPending,
            group_id: Some(GROUP_ID),
            group_name: Some(GROUP_NAME),
            storage_mode: "eager",
            with_link_and_marker: true,
            remote_status: Some("prepared"),
            remote_result_group_id: Some(GROUP_ID),
            expected_recommendation: "retry_remote_activation",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "exact",
            expected_marker_status: "exact",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    #[tokio::test]
    async fn activation_pending_exact_evidence_active_settles() {
        run_case(Case {
            label: "ActivationPending/exact/active",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::ActivationPending,
            group_id: Some(GROUP_ID),
            group_name: Some(GROUP_NAME),
            storage_mode: "eager",
            with_link_and_marker: true,
            remote_status: Some("active"),
            remote_result_group_id: Some(GROUP_ID),
            expected_recommendation: "complete_local_settlement",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "exact",
            expected_marker_status: "exact",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    #[tokio::test]
    async fn activation_pending_no_link_no_marker_prepared_retries_cancellation() {
        run_case(Case {
            label: "ActivationPending/absent/prepared",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::ActivationPending,
            group_id: Some(GROUP_ID),
            group_name: Some(GROUP_NAME),
            storage_mode: "eager",
            with_link_and_marker: false,
            remote_status: Some("prepared"),
            remote_result_group_id: Some(GROUP_ID),
            expected_recommendation: "retry_remote_cancellation",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "confirmed_absent",
            expected_marker_status: "confirmed_absent",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    #[tokio::test]
    async fn cancel_pending_no_link_no_marker_prepared_retries_cancellation() {
        run_case(Case {
            label: "CancelPending/absent/prepared",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::CancelPending,
            group_id: Some(GROUP_ID),
            group_name: Some(GROUP_NAME),
            storage_mode: "eager",
            with_link_and_marker: false,
            remote_status: Some("prepared"),
            remote_result_group_id: Some(GROUP_ID),
            expected_recommendation: "retry_remote_cancellation",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "confirmed_absent",
            expected_marker_status: "confirmed_absent",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    #[tokio::test]
    async fn cancel_pending_no_link_no_marker_cancelled_settles() {
        run_case(Case {
            label: "CancelPending/absent/cancelled",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::CancelPending,
            group_id: Some(GROUP_ID),
            group_name: Some(GROUP_NAME),
            storage_mode: "eager",
            with_link_and_marker: false,
            remote_status: Some("cancelled"),
            remote_result_group_id: None,
            expected_recommendation: "complete_local_settlement",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "confirmed_absent",
            expected_marker_status: "confirmed_absent",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    #[tokio::test]
    async fn recovery_blocked_is_always_manual_investigation() {
        run_case(Case {
            label: "RecoveryBlocked/absent/404",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::RecoveryBlocked,
            group_id: None,
            group_name: None,
            storage_mode: "eager",
            with_link_and_marker: false,
            remote_status: None,
            remote_result_group_id: None,
            expected_recommendation: "manual_investigation",
            expected_automatic_recovery_safe: false,
            expected_reason_codes: &["recovery_blocked"],
            expected_link_status: "confirmed_absent",
            expected_marker_status: "confirmed_absent",
            expected_remote_identity_status: "not_evaluated",
        })
        .await;
    }

    /// Create's local on-demand materialization request is a different
    /// concept from the remote creator edge (always "eager") -- must
    /// stay `exact`, never a spurious identity conflict.
    #[tokio::test]
    async fn create_local_on_demand_is_not_an_identity_conflict() {
        run_case(Case {
            label: "Create/on-demand/prepared",
            kind: EnrollmentKind::Create,
            state: EnrollmentOperationState::Prepared,
            group_id: Some(GROUP_ID),
            group_name: Some(GROUP_NAME),
            storage_mode: "on-demand",
            with_link_and_marker: false,
            remote_status: Some("prepared"),
            remote_result_group_id: Some(GROUP_ID),
            expected_recommendation: "wait_for_automatic_recovery",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "confirmed_absent",
            expected_marker_status: "confirmed_absent",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    #[tokio::test]
    async fn join_activation_pending_exact_evidence_prepared_retries_activation() {
        run_case(Case {
            label: "Join/ActivationPending/exact/prepared",
            kind: EnrollmentKind::Join,
            state: EnrollmentOperationState::ActivationPending,
            group_id: Some(GROUP_ID),
            group_name: None,
            storage_mode: "eager",
            with_link_and_marker: true,
            remote_status: Some("prepared"),
            remote_result_group_id: Some(GROUP_ID),
            expected_recommendation: "retry_remote_activation",
            expected_automatic_recovery_safe: true,
            expected_reason_codes: &[],
            expected_link_status: "exact",
            expected_marker_status: "exact",
            expected_remote_identity_status: "exact",
        })
        .await;
    }

    /// A real IPC race, through `handle_request` end to end: the mocked
    /// Worker response is held open by a genuine two-way barrier -- a
    /// tiny raw TCP server that reads the request fully, signals
    /// `request_received`, and then BLOCKS on `release_response` before
    /// writing anything back -- not a fixed delay. While the response
    /// is provably still withheld, a SEPARATE `SyncState` handle (as a
    /// concurrent reconciler would use) mutates the same journal row,
    /// and only THEN is the response released. The wire outcome must be
    /// `local_evidence_changed`, never a diagnosis built from now-stale
    /// local evidence, and never a second remote lookup -- no matter
    /// how long the mutation itself takes.
    struct HeldResponseServer {
        base_url: String,
        request_received: Arc<Notify>,
        release_response: Arc<Notify>,
        request_count: Arc<AtomicUsize>,
        unexpected_request_count: Arc<AtomicUsize>,
        protocol_violation: Arc<std::sync::Mutex<Option<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl HeldResponseServer {
        /// Starts a server that expects exactly one `expected_method
        /// expected_path` request, holds its response until
        /// `release_response` is signaled, and treats every other
        /// connection attempt (wrong method/path, or a connection past
        /// the first) as a recorded failure -- never silently accepted.
        #[allow(
            clippy::excessive_nesting,
            reason = "hand-rolled single-shot HTTP test server: the accept loop, the \
                      bounded header-read loop, and the request-line validation are \
                      intentionally nested inside one spawned task so `served`, the \
                      violation slot, and the counters stay in one closure's scope. \
                      Hoisting the inner loops into helpers would move that shared \
                      mutable state behind extra Arcs without making the sequencing \
                      (one held response, every later connection recorded as \
                      unexpected) any easier to read."
        )]
        async fn start(
            expected_method: &'static str,
            expected_path: String,
            body: serde_json::Value,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let request_received = Arc::new(Notify::new());
            let release_response = Arc::new(Notify::new());
            let request_count = Arc::new(AtomicUsize::new(0));
            let unexpected_request_count = Arc::new(AtomicUsize::new(0));
            let protocol_violation: Arc<std::sync::Mutex<Option<String>>> =
                Arc::new(std::sync::Mutex::new(None));
            let body_bytes = serde_json::to_vec(&body).unwrap();

            let task_received = request_received.clone();
            let task_release = release_response.clone();
            let task_count = request_count.clone();
            let task_unexpected = unexpected_request_count.clone();
            let task_violation = protocol_violation.clone();

            let task = tokio::spawn(async move {
                // Exactly one request is ever the intended one -- served
                // sequentially so a second connection is provably
                // observed as extra, not raced against the held first
                // one.
                let mut served = false;
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else { return };
                    if served {
                        task_unexpected.fetch_add(1, Ordering::SeqCst);
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\
                                  Connection: close\r\n\r\n",
                            )
                            .await;
                        continue;
                    }

                    // Bounded read -- a GET has no body, so the header
                    // terminator ends the request; never loop
                    // unboundedly on a client that never sends one.
                    const MAX_HEADER_BYTES: usize = 16 * 1024;
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    let head_ok = loop {
                        if buf.len() > MAX_HEADER_BYTES {
                            break false;
                        }
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break false,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break true;
                        }
                    };
                    if !head_ok {
                        *task_violation.lock().unwrap() =
                            Some("request headers not received cleanly".to_string());
                        continue;
                    }

                    let line_end = buf.iter().position(|&b| b == b'\r').unwrap_or(buf.len());
                    let request_line = String::from_utf8_lossy(&buf[..line_end]).to_string();
                    let mut parts = request_line.split(' ');
                    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                    if method != expected_method || path != expected_path {
                        *task_violation.lock().unwrap() = Some(format!(
                            "unexpected request line {request_line:?} (wanted {expected_method} \
                             {expected_path})"
                        ));
                        let _ = socket
                            .write_all(
                                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\
                                  Connection: close\r\n\r\n",
                            )
                            .await;
                        continue;
                    }

                    served = true;
                    task_count.fetch_add(1, Ordering::SeqCst);
                    // The barrier: the caller only learns the request
                    // landed AFTER it is fully read and validated, and
                    // this task will not write one byte of a response
                    // until `release_response` is explicitly signaled --
                    // regardless of how long that takes.
                    task_received.notify_one();
                    task_release.notified().await;
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                         {}\r\nConnection: close\r\n\r\n",
                        body_bytes.len()
                    );
                    let _ = socket.write_all(header.as_bytes()).await;
                    let _ = socket.write_all(&body_bytes).await;
                    let _ = socket.shutdown().await;
                }
            });

            HeldResponseServer {
                base_url: format!("http://{addr}"),
                request_received,
                release_response,
                request_count,
                unexpected_request_count,
                protocol_violation,
                task,
            }
        }

        fn request_count(&self) -> usize {
            self.request_count.load(Ordering::SeqCst)
        }

        /// Asserts the server observed no malformed/mismatched request
        /// and no connection beyond the one expected -- called at the
        /// end of every race test alongside `request_count() == 1`.
        fn assert_clean(&self, label: &str) {
            assert_eq!(
                self.unexpected_request_count.load(Ordering::SeqCst),
                0,
                "[{label}] unexpected extra connection(s)"
            );
            assert_eq!(
                self.protocol_violation.lock().unwrap().clone(),
                None,
                "[{label}] protocol violation"
            );
        }
    }

    impl Drop for HeldResponseServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    #[tokio::test]
    async fn concurrent_local_mutation_during_remote_lookup_is_local_evidence_changed_on_the_wire()
    {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.sqlite3");

        let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
        sync_state
            .enrollment_repository()
            .try_insert_enrollment_operation(&base_operation(
                EnrollmentKind::Create,
                EnrollmentOperationState::ActivationPending,
                Some(GROUP_ID),
                Some(GROUP_NAME),
                "eager",
            ))
            .unwrap();
        sync_state
            .enrollment_repository()
            .add_link_with_pending_enrollment(LOCAL_PATH, GROUP_ID, &marker(EnrollmentKind::Create))
            .unwrap();
        let sync_state = reopen(&db_path, sync_state);

        let server = HeldResponseServer::start(
            "GET",
            "/devices/enrollment-operations/op-1".to_string(),
            create_body("prepared", Some(GROUP_ID)),
        )
        .await;

        let daemon_state = daemon_state_for(sync_state.clone());
        daemon_state.set_coordination_client_config(
            server.base_url.clone(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );

        // A second, independent handle onto the SAME file -- standing in
        // for a concurrent reconciler task, not the request-handling
        // task itself.
        let mutator_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());

        let req = DaemonControlRequest {
            payload: Some(ReqPayload::ShowRecoveryOperation(
                yadorilink_ipc_proto::daemonctl::ShowRecoveryOperationRequest {
                    domain: RecoveryDomain::Enrollment.as_str().to_string(),
                    operation_id: "op-1".to_string(),
                },
            )),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let handle = tokio::spawn(async move {
            super::super::handle_request(
                &crate::control_context::ControlContext::from_state(daemon_state.clone()),
                req,
            )
            .await
        });

        // The barrier: the request has been fully read by the held-
        // response server -- the remote lookup is PROVABLY in flight,
        // and its response is PROVABLY not yet written, no matter how
        // long the mutation below takes.
        server.request_received.notified().await;
        mutator_state
            .enrollment_repository()
            .mark_enrollment_operation_state(
                "op-1",
                EnrollmentOperationState::CancelPending,
                None,
                2,
            )
            .unwrap();
        server.release_response.notify_one();

        let resp = handle.await.unwrap();
        let Some(RespPayload::ShowRecoveryOperation(show)) = resp.payload else {
            panic!("expected a ShowRecoveryOperation response, got {:?}", resp.payload);
        };
        match show.result {
            Some(
                yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::LocalEvidenceChanged(
                    changed,
                ),
            ) => {
                let key = changed.key.unwrap();
                assert_eq!(key.domain, "enrollment");
                assert_eq!(key.operation_id, "op-1");
            }
            other => panic!("expected LocalEvidenceChanged, got {other:?}"),
        }

        assert_eq!(server.request_count(), 1, "exactly one Worker GET, no automatic retry");
        server.assert_clean("Enrollment race");
    }

    // ============================== Membership ==============================
    //
    // Membership has no link/marker observation of its own (the
    // `qualify_membership_remote_identity` qualification only ever
    // covers `remote_identity` -- see
    // `crate::recovery_diagnosis::model::MembershipEvidenceQualification`'s
    // own doc comment), and its remote-identity comparison never
    // produces `NotComparable` (every field it compares is always
    // present on both sides -- see `qualify_membership_remote_identity`)
    // -- both intentionally absent from this section, not overlooked.

    const MEMBERSHIP_REMOVED_DEVICE_ID: &str = "device-b";

    struct MembershipFixture {
        action: MembershipOperationAction,
        commit_mode: MembershipCommitMode,
        group_ids: &'static [&'static str],
        target_device_ids: &'static [&'static str],
        lease_ids: &'static [Option<&'static str>],
        state: MembershipOperationState,
        durability_scope: MembershipDurabilityScope,
        latch_group_ids: &'static [&'static str],
    }

    fn insert_membership_fixture(
        sync_state: &ReplicaCoordinator,
        fixture: &MembershipFixture,
    ) -> MembershipOperation {
        let group_ids: Vec<String> = fixture.group_ids.iter().map(|s| s.to_string()).collect();
        let target_device_ids: Vec<String> =
            fixture.target_device_ids.iter().map(|s| s.to_string()).collect();
        let lease_ids: Vec<Option<String>> =
            fixture.lease_ids.iter().map(|l| l.map(str::to_string)).collect();
        let latch_group_ids: Vec<String> =
            fixture.latch_group_ids.iter().map(|s| s.to_string()).collect();
        sync_state
            .membership_operation_repository()
            .try_insert_membership_operation(
                "op-1",
                fixture.action,
                fixture.commit_mode,
                MEMBERSHIP_REMOVED_DEVICE_ID,
                &group_ids,
                &target_device_ids,
                &lease_ids,
                fixture.state,
                fixture.durability_scope,
                &latch_group_ids,
                None,
                1,
            )
            .unwrap();
        sync_state
            .membership_operation_repository()
            .get_membership_operation("op-1")
            .unwrap()
            .unwrap()
    }

    fn membership_result_json(affected_group_ids: Option<&[&str]>) -> serde_json::Value {
        serde_json::json!({
            "affectedGroupIds": affected_group_ids
                .map(|ids| ids.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            "targetDeviceId": null,
            "membershipGeneration": null,
            "leaseId": null,
        })
    }

    /// Builds a wire body IDENTITY-EXACT to `operation`'s own canonical
    /// remote request (via the SAME `expected_membership_remote_request`
    /// the classifier's own qualification calls), optionally overriding
    /// `action` on BOTH the top-level and nested `request.action`
    /// fields together -- keeping them consistent is what makes an
    /// override still parse as a well-formed (if identity-mismatched)
    /// response rather than a `MalformedResponse`.
    fn membership_body(
        operation: &MembershipOperation,
        status: &str,
        result: Option<serde_json::Value>,
        action_override: Option<&str>,
    ) -> serde_json::Value {
        let expected =
            crate::application::membership_operation_identity::expected_membership_remote_request(
                operation,
            );
        let action = action_override.unwrap_or(expected.action.as_str());
        let groups: Vec<_> = expected
            .groups
            .iter()
            .map(|g| {
                serde_json::json!({
                    "groupId": g.group_id,
                    "targetDeviceId": g.target_device_id,
                    "leaseId": g.lease_id,
                })
            })
            .collect();
        serde_json::json!({
            "operationId": "op-1",
            "status": status,
            "action": action,
            "removedDeviceId": operation.removed_device_id,
            "requestFingerprint": "fp",
            "request": {
                "userId": "user-1",
                "action": action,
                "removedDeviceId": operation.removed_device_id,
                "mode": expected.mode,
                "groups": groups,
            },
            "result": result,
            "rejectionCode": null,
            "rejectionDetail": null,
        })
    }

    fn membership_evidence(sync_state: &ReplicaCoordinator) -> LocalRecoveryEvidence {
        local_recovery_evidence(sync_state, RecoveryDomain::Membership, "op-1")
    }

    struct MembershipCase {
        label: &'static str,
        fixture: MembershipFixture,
        /// `None` means a 404 (`RecordNotFound`); `Some(status, body)`
        /// mocks a 200 with that body; a bare non-2xx status is mocked
        /// via `remote_error_status` instead when the case needs
        /// `Unavailable` rather than a well-formed record.
        remote: Option<(&'static str, serde_json::Value)>,
        remote_error_status: Option<u16>,
        /// Overrides the wire `action` on BOTH the top-level and nested
        /// `request.action` fields together -- see `membership_body`'s
        /// own doc comment for why keeping them consistent is what
        /// makes this still parse as well-formed (if identity-
        /// mismatched), the way an unrelated genuine request under the
        /// same reused operation_id would.
        action_override: Option<&'static str>,
        expected: ExpectedDiagnosis,
        expected_remote_identity_status: &'static str,
        expected_remote_identity_mismatch_fields: &'static [&'static str],
    }

    async fn run_membership_case(case: MembershipCase) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.sqlite3");

        let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
        let operation = insert_membership_fixture(&sync_state, &case.fixture);
        let sync_state = reopen(&db_path, sync_state);
        let before = membership_evidence(&sync_state);

        let server = MockServer::start().await;
        let response = if let Some(status) = case.remote_error_status {
            ResponseTemplate::new(status)
        } else {
            match &case.remote {
                None => ResponseTemplate::new(404),
                Some((status, body)) => {
                    let body = membership_body(
                        &operation,
                        status,
                        Some(body.clone()),
                        case.action_override,
                    );
                    ResponseTemplate::new(200).set_body_json(body)
                }
            }
        };
        Mock::given(method("GET"))
            .and(path("/devices/membership-operations/op-1"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;

        let daemon_state = daemon_state_for(sync_state.clone());
        daemon_state.set_coordination_client_config(
            server.uri(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );

        let show = run_show_request(&daemon_state, RecoveryDomain::Membership, "op-1").await;
        let Some(
            yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::Diagnosed(
                diagnosis,
            ),
        ) = show.result
        else {
            panic!("[{}] expected Diagnosed, got {:?}", case.label, show.result);
        };

        assert_diagnosis(case.label, &diagnosis, &case.expected);
        let op = diagnosis.operation.as_ref().unwrap();
        assert_eq!(op.action, case.fixture.action.as_db_str(), "[{}] action", case.label);
        assert_eq!(op.state, case.fixture.state.as_db_str(), "[{}] local state", case.label);

        let qualification = diagnosis.qualification.as_ref().unwrap();
        assert!(qualification.link.is_none(), "[{}] membership has no link field", case.label);
        assert!(
            qualification.pending_marker.is_none(),
            "[{}] membership has no marker field",
            case.label
        );
        let remote_identity = qualification.remote_identity.as_ref().unwrap();
        assert_eq!(
            remote_identity.status, case.expected_remote_identity_status,
            "[{}] remote identity qualification",
            case.label
        );
        assert_eq!(
            remote_identity.mismatch_fields, case.expected_remote_identity_mismatch_fields,
            "[{}] remote identity mismatch_fields",
            case.label
        );
        assert!(
            remote_identity.not_comparable_reasons.is_empty(),
            "[{}] membership remote identity is never not_comparable",
            case.label
        );

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1, "[{}] Worker GET count", case.label);

        let after = membership_evidence(&sync_state);
        assert_eq!(before, after, "[{}] local recovery evidence must not change", case.label);
    }

    fn known_no_latch() -> MembershipFixture {
        MembershipFixture {
            action: MembershipOperationAction::Revoke,
            commit_mode: MembershipCommitMode::PlainRevoke,
            group_ids: &["group-1"],
            target_device_ids: &[],
            lease_ids: &[],
            state: MembershipOperationState::Prepared,
            durability_scope: MembershipDurabilityScope::Known,
            latch_group_ids: &[],
        }
    }

    #[tokio::test]
    async fn membership_prepared_record_not_found_retries_same_request() {
        run_membership_case(MembershipCase {
            label: "Membership/Prepared/RecordNotFound",
            fixture: MembershipFixture {
                state: MembershipOperationState::Prepared,
                ..known_no_latch()
            },
            remote: None,
            remote_error_status: None,
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "record_not_found".to_string(),
                recommendation: "retry_same_remote_request",
                automatic_recovery_safe: true,
                reason_codes: &["remote_record_not_found"],
            },
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_prepared_unavailable_waits_for_remote_evidence() {
        run_membership_case(MembershipCase {
            label: "Membership/Prepared/Unavailable",
            fixture: MembershipFixture {
                state: MembershipOperationState::Prepared,
                ..known_no_latch()
            },
            remote: None,
            remote_error_status: Some(500),
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "unavailable".to_string(),
                recommendation: "wait_for_remote_evidence",
                automatic_recovery_safe: false,
                reason_codes: &["remote_unavailable"],
            },
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_ambiguous_committed_settles_with_local_unsettled_reason() {
        run_membership_case(MembershipCase {
            label: "Membership/Ambiguous/Committed",
            fixture: MembershipFixture {
                state: MembershipOperationState::Ambiguous,
                ..known_no_latch()
            },
            remote: Some(("committed", membership_result_json(None))),
            remote_error_status: None,
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "committed".to_string(),
                recommendation: "complete_local_settlement",
                automatic_recovery_safe: true,
                reason_codes: &["remote_committed_local_unsettled"],
            },
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_local_settlement_pending_known_scope_unavailable_settles() {
        run_membership_case(MembershipCase {
            label: "Membership/LocalSettlementPending/Known/Unavailable",
            fixture: MembershipFixture {
                state: MembershipOperationState::LocalSettlementPending,
                ..known_no_latch()
            },
            remote: None,
            remote_error_status: Some(500),
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "unavailable".to_string(),
                recommendation: "complete_local_settlement",
                automatic_recovery_safe: true,
                reason_codes: &[],
            },
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_local_settlement_pending_unknown_scope_unavailable_waits() {
        run_membership_case(MembershipCase {
            label: "Membership/LocalSettlementPending/Unknown/Unavailable",
            fixture: MembershipFixture {
                state: MembershipOperationState::LocalSettlementPending,
                durability_scope: MembershipDurabilityScope::Unknown,
                ..known_no_latch()
            },
            remote: None,
            remote_error_status: Some(500),
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "unavailable".to_string(),
                recommendation: "wait_for_remote_evidence",
                automatic_recovery_safe: false,
                reason_codes: &["remote_unavailable", "durability_scope_unknown"],
            },
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_completed_terminal_crash_window_row_settles() {
        run_membership_case(MembershipCase {
            label: "Membership/Completed/RecordNotFound",
            fixture: MembershipFixture {
                state: MembershipOperationState::Completed,
                ..known_no_latch()
            },
            remote: None,
            remote_error_status: None,
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "record_not_found".to_string(),
                recommendation: "complete_local_settlement",
                automatic_recovery_safe: true,
                reason_codes: &[],
            },
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_definitely_rejected_terminal_crash_window_row_settles() {
        run_membership_case(MembershipCase {
            label: "Membership/DefinitelyRejected/Unavailable",
            fixture: MembershipFixture {
                state: MembershipOperationState::DefinitelyRejected,
                ..known_no_latch()
            },
            remote: None,
            remote_error_status: Some(500),
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "unavailable".to_string(),
                recommendation: "complete_local_settlement",
                automatic_recovery_safe: true,
                reason_codes: &[],
            },
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_recovery_blocked_is_always_manual_investigation() {
        run_membership_case(MembershipCase {
            label: "Membership/RecoveryBlocked",
            fixture: MembershipFixture {
                state: MembershipOperationState::RecoveryBlocked,
                ..known_no_latch()
            },
            remote: None,
            remote_error_status: None,
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "record_not_found".to_string(),
                recommendation: "manual_investigation",
                automatic_recovery_safe: false,
                reason_codes: &["recovery_blocked"],
            },
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_committed_remove_device_missing_affected_groups_is_manual() {
        run_membership_case(MembershipCase {
            label: "Membership/Committed/RemoveDevice/MissingAffectedGroups",
            fixture: MembershipFixture {
                action: MembershipOperationAction::RemoveDevice,
                commit_mode: MembershipCommitMode::PlainRemoveDevice,
                group_ids: &[],
                target_device_ids: &[],
                lease_ids: &[],
                state: MembershipOperationState::Prepared,
                durability_scope: MembershipDurabilityScope::Known,
                latch_group_ids: &[],
            },
            remote: Some(("committed", membership_result_json(None))),
            remote_error_status: None,
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "committed".to_string(),
                recommendation: "manual_investigation",
                automatic_recovery_safe: false,
                reason_codes: &["remote_result_incomplete"],
            },
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_committed_revoke_with_empty_result_is_not_malformed() {
        run_membership_case(MembershipCase {
            label: "Membership/Committed/Revoke/EmptyResult",
            fixture: MembershipFixture {
                state: MembershipOperationState::Prepared,
                ..known_no_latch()
            },
            remote: Some(("committed", membership_result_json(None))),
            remote_error_status: None,
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "committed".to_string(),
                recommendation: "complete_local_settlement",
                automatic_recovery_safe: true,
                reason_codes: &["remote_committed_local_unsettled"],
            },
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_committed_remove_device_multiple_affected_groups_settles() {
        run_membership_case(MembershipCase {
            label: "Membership/Committed/RemoveDevice/MultipleAffectedGroups",
            fixture: MembershipFixture {
                action: MembershipOperationAction::RemoveDevice,
                commit_mode: MembershipCommitMode::PlainRemoveDevice,
                group_ids: &[],
                target_device_ids: &[],
                lease_ids: &[],
                state: MembershipOperationState::LocalSettlementPending,
                durability_scope: MembershipDurabilityScope::Known,
                latch_group_ids: &[],
            },
            remote: Some(("committed", membership_result_json(Some(&["group-1", "group-2"])))),
            remote_error_status: None,
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "committed".to_string(),
                recommendation: "complete_local_settlement",
                automatic_recovery_safe: true,
                reason_codes: &[],
            },
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_latch_missing_for_known_scope_is_manual_reason_but_still_settles() {
        run_membership_case(MembershipCase {
            label: "Membership/Known/LatchMissing",
            fixture: MembershipFixture {
                action: MembershipOperationAction::RemoveDevice,
                commit_mode: MembershipCommitMode::PlainRemoveDevice,
                group_ids: &[],
                target_device_ids: &[],
                lease_ids: &[],
                state: MembershipOperationState::LocalSettlementPending,
                durability_scope: MembershipDurabilityScope::Known,
                latch_group_ids: &["group-1"],
            },
            remote: Some(("committed", membership_result_json(Some(&["group-1"])))),
            remote_error_status: None,
            action_override: None,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "committed".to_string(),
                recommendation: "complete_local_settlement",
                automatic_recovery_safe: true,
                reason_codes: &["durability_latch_missing"],
            },
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn membership_remote_identity_mismatch_is_conflict() {
        run_membership_case(MembershipCase {
            label: "Membership/IdentityMismatch",
            fixture: MembershipFixture {
                state: MembershipOperationState::Prepared,
                ..known_no_latch()
            },
            remote: Some(("committed", membership_result_json(None))),
            remote_error_status: None,
            action_override: Some("remove-device"),
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "membership",
                remote_state: "committed".to_string(),
                recommendation: "conflict",
                automatic_recovery_safe: false,
                reason_codes: &["remote_identity_mismatch"],
            },
            expected_remote_identity_status: "mismatch",
            expected_remote_identity_mismatch_fields: &["action"],
        })
        .await;
    }

    /// A malformed journal row is a typed `invalid` wire outcome
    /// observed BEFORE any remote lookup -- never `manual_investigation`
    /// (that comes from the classifier, which never even runs here).
    #[tokio::test]
    async fn membership_malformed_row_is_a_typed_invalid_outcome_before_any_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.sqlite3");
        let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
        sync_state.plant_malformed_membership_operation_for_test("op-1").unwrap();
        let sync_state = reopen(&db_path, sync_state);

        let daemon_state = daemon_state_for(sync_state.clone());
        // No coordination config at all -- a lookup would panic this
        // test if one were ever attempted.
        daemon_state.set_coordination_client_config(
            "http://127.0.0.1:1".to_string(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );

        let show = run_show_request(&daemon_state, RecoveryDomain::Membership, "op-1").await;
        assert!(
            matches!(
                show.result,
                Some(yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::Invalid(_))
            ),
            "expected Result::Invalid, got {:?}",
            show.result
        );
    }

    /// A real IPC race for Membership, through `handle_request` end to
    /// end, using the same genuine two-way barrier as the Enrollment
    /// race -- see that test's own doc comment.
    #[tokio::test]
    async fn membership_concurrent_local_mutation_during_remote_lookup_is_local_evidence_changed_on_the_wire(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.sqlite3");

        let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
        let operation = insert_membership_fixture(
            &sync_state,
            &MembershipFixture { state: MembershipOperationState::Prepared, ..known_no_latch() },
        );
        let sync_state = reopen(&db_path, sync_state);

        let body =
            membership_body(&operation, "committed", Some(membership_result_json(None)), None);
        let server = HeldResponseServer::start(
            "GET",
            "/devices/membership-operations/op-1".to_string(),
            body,
        )
        .await;

        let daemon_state = daemon_state_for(sync_state.clone());
        daemon_state.set_coordination_client_config(
            server.base_url.clone(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );

        let mutator_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());

        let daemon_state_task = daemon_state.clone();
        let handle = tokio::spawn(async move {
            run_show_request(&daemon_state_task, RecoveryDomain::Membership, "op-1").await
        });

        server.request_received.notified().await;
        mutator_state
            .membership_operation_repository()
            .mark_membership_operation_state(
                "op-1",
                MembershipOperationState::LocalSettlementPending,
                None,
                2,
            )
            .unwrap();
        server.release_response.notify_one();

        let show = handle.await.unwrap();
        match show.result {
            Some(
                yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::LocalEvidenceChanged(
                    changed,
                ),
            ) => {
                let key = changed.key.unwrap();
                assert_eq!(key.domain, "membership");
                assert_eq!(key.operation_id, "op-1");
            }
            other => panic!("expected LocalEvidenceChanged, got {other:?}"),
        }

        assert_eq!(server.request_count(), 1, "exactly one Worker GET, no automatic retry");
        server.assert_clean("Membership race");
    }

    // ============================== Role loss ================================
    //
    // Role-loss has no `not_evaluated`/`not_comparable`-vs-`Mismatch`
    // subtlety beyond what Enrollment/Membership already exercise, but
    // it has a property neither does: a local link mismatch is a
    // REASON, never a recommendation-gating conflict -- the
    // safe-direction Worker compensation this domain drives never reads
    // the local link at all (see `classify_role_loss`'s own doc
    // comment). Several cases below exist specifically to pin that.

    const ROLE_LOSS_GROUP_ID: &str = "group-1";
    const ROLE_LOSS_SOURCE_DEVICE_ID: &str = "device-c";
    const ROLE_LOSS_TARGET_DEVICE_ID: &str = "device-d";
    const ROLE_LOSS_LEASE_ID: &str = "lease-1";

    struct RoleLossFixture {
        action: RoleLossAction,
        state: RoleLossOperationState,
        worker_membership_generation: Option<i64>,
    }

    fn insert_role_loss_fixture(
        sync_state: &ReplicaCoordinator,
        fixture: &RoleLossFixture,
    ) -> yadorilink_replica_domain::session_state::RoleLossOperation {
        sync_state
            .role_loss_operation_repository()
            .insert_role_loss_operation(
                "op-1",
                ROLE_LOSS_GROUP_ID,
                RoleLossOperationParams {
                    source_device_id: ROLE_LOSS_SOURCE_DEVICE_ID,
                    target_device_id: ROLE_LOSS_TARGET_DEVICE_ID,
                    lease_id: ROLE_LOSS_LEASE_ID,
                    action: fixture.action,
                    local_path: Some(LOCAL_PATH),
                    now_unix: 1,
                },
            )
            .unwrap();
        if fixture.state != RoleLossOperationState::Prepared {
            sync_state
                .role_loss_operation_repository()
                .mark_role_loss_worker_committed(
                    "op-1",
                    fixture.worker_membership_generation.unwrap_or(4),
                    1,
                )
                .unwrap();
            if fixture.state != RoleLossOperationState::WorkerCommitted {
                sync_state
                    .role_loss_operation_repository()
                    .advance_role_loss_operation("op-1", fixture.state, 1)
                    .unwrap();
            }
        }
        sync_state
            .role_loss_operation_repository()
            .get_role_loss_operation("op-1")
            .unwrap()
            .unwrap()
    }

    enum RoleLossRemote {
        NotFound,
        Unavailable(u16),
        Found {
            action: &'static str,
            source_device_id: &'static str,
            target_device_id: &'static str,
            lease_id: Option<&'static str>,
            membership_generation: i64,
        },
    }

    impl RoleLossRemote {
        fn exact() -> Self {
            RoleLossRemote::Found {
                action: "demote",
                source_device_id: ROLE_LOSS_SOURCE_DEVICE_ID,
                target_device_id: ROLE_LOSS_TARGET_DEVICE_ID,
                lease_id: Some(ROLE_LOSS_LEASE_ID),
                membership_generation: 4,
            }
        }
    }

    fn role_loss_body(
        action: &str,
        source_device_id: &str,
        target_device_id: &str,
        lease_id: Option<&str>,
        membership_generation: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "operationId": "op-1",
            "groupId": ROLE_LOSS_GROUP_ID,
            "sourceDeviceId": source_device_id,
            "targetDeviceId": target_device_id,
            "leaseId": lease_id,
            "action": action,
            "membershipGeneration": membership_generation,
            "committedAt": 1,
        })
    }

    fn role_loss_evidence(sync_state: &ReplicaCoordinator) -> LocalRecoveryEvidence {
        local_recovery_evidence(sync_state, RecoveryDomain::RoleLoss, "op-1")
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RoleLossLink {
        Absent,
        Exact,
        GroupMismatch,
    }

    struct RoleLossCase {
        label: &'static str,
        fixture: RoleLossFixture,
        link: RoleLossLink,
        remote: RoleLossRemote,
        expected: ExpectedDiagnosis,
        expected_link_status: &'static str,
        expected_remote_identity_status: &'static str,
        expected_remote_identity_mismatch_fields: &'static [&'static str],
    }

    async fn run_role_loss_case(case: RoleLossCase) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.sqlite3");

        let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
        insert_role_loss_fixture(&sync_state, &case.fixture);
        match case.link {
            RoleLossLink::Absent => {}
            RoleLossLink::Exact => {
                sync_state.link_repository().add_link(LOCAL_PATH, ROLE_LOSS_GROUP_ID).unwrap();
            }
            RoleLossLink::GroupMismatch => {
                sync_state.link_repository().add_link(LOCAL_PATH, "group-DIFFERENT").unwrap();
            }
        }
        let sync_state = reopen(&db_path, sync_state);
        let before = role_loss_evidence(&sync_state);

        let server = MockServer::start().await;
        let response = match &case.remote {
            RoleLossRemote::NotFound => ResponseTemplate::new(404),
            RoleLossRemote::Unavailable(status) => ResponseTemplate::new(*status),
            RoleLossRemote::Found {
                action,
                source_device_id,
                target_device_id,
                lease_id,
                membership_generation,
            } => {
                let body = role_loss_body(
                    action,
                    source_device_id,
                    target_device_id,
                    *lease_id,
                    *membership_generation,
                );
                ResponseTemplate::new(200).set_body_json(body)
            }
        };
        Mock::given(method("GET"))
            .and(path("/devices/role-loss-operations/op-1"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;

        let daemon_state = daemon_state_for(sync_state.clone());
        daemon_state.set_coordination_client_config(
            server.uri(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );

        let show = run_show_request(&daemon_state, RecoveryDomain::RoleLoss, "op-1").await;
        let Some(
            yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::Diagnosed(
                diagnosis,
            ),
        ) = show.result
        else {
            panic!("[{}] expected Diagnosed, got {:?}", case.label, show.result);
        };

        assert_diagnosis(case.label, &diagnosis, &case.expected);
        let op = diagnosis.operation.as_ref().unwrap();
        assert_eq!(
            op.action,
            match case.fixture.action {
                RoleLossAction::Demote => "demote",
                RoleLossAction::Unlink => "unlink",
                RoleLossAction::Revoke => "revoke",
            },
            "[{}] action",
            case.label
        );
        assert_eq!(op.state, case.fixture.state.as_db_str(), "[{}] local state", case.label);

        let qualification = diagnosis.qualification.as_ref().unwrap();
        let link = qualification.link.as_ref().unwrap();
        assert_eq!(link.status, case.expected_link_status, "[{}] link qualification", case.label);
        assert!(
            qualification.pending_marker.is_none(),
            "[{}] role-loss has no marker field",
            case.label
        );
        let remote_identity = qualification.remote_identity.as_ref().unwrap();
        assert_eq!(
            remote_identity.status, case.expected_remote_identity_status,
            "[{}] remote identity qualification",
            case.label
        );
        assert_eq!(
            remote_identity.mismatch_fields, case.expected_remote_identity_mismatch_fields,
            "[{}] remote identity mismatch_fields",
            case.label
        );

        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1, "[{}] Worker GET count", case.label);

        let after = role_loss_evidence(&sync_state);
        assert_eq!(before, after, "[{}] local recovery evidence must not change", case.label);
    }

    #[tokio::test]
    async fn role_loss_prepared_record_not_found_continues_compensation() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/Prepared/RecordNotFound",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::Prepared,
                worker_membership_generation: None,
            },
            link: RoleLossLink::Absent,
            remote: RoleLossRemote::NotFound,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "record_not_found".to_string(),
                recommendation: "continue_automatic_compensation",
                automatic_recovery_safe: true,
                reason_codes: &[
                    "remote_record_not_found",
                    "local_link_missing",
                    "legacy_role_loss_receipt_uncertain",
                    "role_loss_compensation_required",
                ],
            },
            expected_link_status: "confirmed_absent",
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn role_loss_prepared_unavailable_continues_compensation() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/Prepared/Unavailable",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::Prepared,
                worker_membership_generation: None,
            },
            link: RoleLossLink::Exact,
            remote: RoleLossRemote::Unavailable(500),
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "unavailable".to_string(),
                recommendation: "continue_automatic_compensation",
                automatic_recovery_safe: true,
                reason_codes: &["remote_unavailable", "role_loss_compensation_required"],
            },
            expected_link_status: "exact",
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn role_loss_worker_committed_with_receipt_continues_compensation() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/WorkerCommitted/Found",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::WorkerCommitted,
                worker_membership_generation: Some(4),
            },
            link: RoleLossLink::Exact,
            remote: RoleLossRemote::exact(),
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "role_loss_committed".to_string(),
                recommendation: "continue_automatic_compensation",
                automatic_recovery_safe: true,
                reason_codes: &[],
            },
            expected_link_status: "exact",
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn role_loss_compensating_with_unavailable_remote_is_not_abandoned() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/Compensating/Unavailable",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::Compensating,
                worker_membership_generation: Some(4),
            },
            link: RoleLossLink::Exact,
            remote: RoleLossRemote::Unavailable(500),
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "unavailable".to_string(),
                recommendation: "continue_automatic_compensation",
                automatic_recovery_safe: true,
                reason_codes: &["remote_unavailable", "role_loss_compensation_required"],
            },
            expected_link_status: "exact",
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    /// Local link ABSENT never stops compensation -- see this section's
    /// own doc comment. The reason code still records it.
    #[tokio::test]
    async fn role_loss_worker_committed_with_local_link_absent_still_continues_compensation() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/WorkerCommitted/LinkAbsent",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::WorkerCommitted,
                worker_membership_generation: Some(4),
            },
            link: RoleLossLink::Absent,
            remote: RoleLossRemote::exact(),
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "role_loss_committed".to_string(),
                recommendation: "continue_automatic_compensation",
                automatic_recovery_safe: true,
                reason_codes: &["local_link_missing"],
            },
            expected_link_status: "confirmed_absent",
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    /// Local link MISMATCH (present, wrong group) also never stops
    /// compensation -- distinguishing this from Enrollment/Membership's
    /// own local-identity-mismatch handling is exactly the point.
    #[tokio::test]
    async fn role_loss_worker_committed_with_local_link_mismatch_still_continues_compensation() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/WorkerCommitted/LinkMismatch",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::WorkerCommitted,
                worker_membership_generation: Some(4),
            },
            link: RoleLossLink::GroupMismatch,
            remote: RoleLossRemote::exact(),
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "role_loss_committed".to_string(),
                recommendation: "continue_automatic_compensation",
                automatic_recovery_safe: true,
                reason_codes: &["local_link_identity_mismatch"],
            },
            expected_link_status: "mismatch",
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn role_loss_remote_identity_mismatch_is_conflict() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/IdentityMismatch",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::WorkerCommitted,
                worker_membership_generation: Some(4),
            },
            link: RoleLossLink::Exact,
            remote: RoleLossRemote::Found {
                action: "demote",
                source_device_id: "device-DIFFERENT",
                target_device_id: ROLE_LOSS_TARGET_DEVICE_ID,
                lease_id: Some(ROLE_LOSS_LEASE_ID),
                membership_generation: 4,
            },
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "role_loss_committed".to_string(),
                recommendation: "conflict",
                automatic_recovery_safe: false,
                reason_codes: &["remote_identity_mismatch"],
            },
            expected_link_status: "exact",
            expected_remote_identity_status: "mismatch",
            expected_remote_identity_mismatch_fields: &["source_device_id"],
        })
        .await;
    }

    /// The classifier's OWN generation check -- distinct from the B1
    /// identity comparison above (which never even looks at
    /// `membership_generation`): a receipt whose generation disagrees
    /// with what this device already confirmed is a genuine conflict,
    /// never trusted as this operation's own success.
    #[tokio::test]
    async fn role_loss_membership_generation_mismatch_is_conflict() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/GenerationMismatch",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::WorkerCommitted,
                worker_membership_generation: Some(2),
            },
            link: RoleLossLink::Exact,
            remote: RoleLossRemote::Found {
                action: "demote",
                source_device_id: ROLE_LOSS_SOURCE_DEVICE_ID,
                target_device_id: ROLE_LOSS_TARGET_DEVICE_ID,
                lease_id: Some(ROLE_LOSS_LEASE_ID),
                membership_generation: 99,
            },
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "role_loss_committed".to_string(),
                recommendation: "conflict",
                automatic_recovery_safe: false,
                reason_codes: &["remote_result_conflict"],
            },
            expected_link_status: "exact",
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn role_loss_local_committed_terminal_crash_window_row_settles() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/LocalCommitted",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::LocalCommitted,
                worker_membership_generation: Some(4),
            },
            link: RoleLossLink::Exact,
            remote: RoleLossRemote::exact(),
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "role_loss_committed".to_string(),
                recommendation: "complete_local_settlement",
                automatic_recovery_safe: true,
                reason_codes: &[],
            },
            expected_link_status: "exact",
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn role_loss_completed_terminal_crash_window_row_settles() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/Completed",
            fixture: RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::Completed,
                worker_membership_generation: Some(4),
            },
            link: RoleLossLink::Exact,
            remote: RoleLossRemote::exact(),
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "role_loss_committed".to_string(),
                recommendation: "complete_local_settlement",
                automatic_recovery_safe: true,
                reason_codes: &[],
            },
            expected_link_status: "exact",
            expected_remote_identity_status: "exact",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    #[tokio::test]
    async fn role_loss_unlink_action_maps_to_wire_demote_and_continues_compensation() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/Unlink",
            fixture: RoleLossFixture {
                action: RoleLossAction::Unlink,
                state: RoleLossOperationState::Prepared,
                worker_membership_generation: None,
            },
            link: RoleLossLink::Exact,
            remote: RoleLossRemote::NotFound,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "record_not_found".to_string(),
                recommendation: "continue_automatic_compensation",
                automatic_recovery_safe: true,
                reason_codes: &[
                    "remote_record_not_found",
                    "legacy_role_loss_receipt_uncertain",
                    "role_loss_compensation_required",
                ],
            },
            expected_link_status: "exact",
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    /// `Revoke` is reserved and never written by production role-loss
    /// code (only `Demote`/`Unlink` are) -- a fail-closed negative case,
    /// not a claim this shape occurs in real operation. Wins over
    /// everything else, checked before even the remote identity
    /// comparison.
    #[tokio::test]
    async fn role_loss_reserved_revoke_action_is_fail_closed_manual_investigation() {
        run_role_loss_case(RoleLossCase {
            label: "RoleLoss/ReservedRevoke",
            fixture: RoleLossFixture {
                action: RoleLossAction::Revoke,
                state: RoleLossOperationState::Prepared,
                worker_membership_generation: None,
            },
            link: RoleLossLink::Exact,
            remote: RoleLossRemote::NotFound,
            expected: ExpectedDiagnosis {
                operation_id: "op-1",
                domain: "role-loss",
                remote_state: "record_not_found".to_string(),
                recommendation: "manual_investigation",
                automatic_recovery_safe: false,
                reason_codes: &["unsupported_role_loss_action"],
            },
            expected_link_status: "exact",
            expected_remote_identity_status: "not_evaluated",
            expected_remote_identity_mismatch_fields: &[],
        })
        .await;
    }

    /// A malformed journal row is a typed `invalid` wire outcome
    /// observed BEFORE any remote lookup.
    #[tokio::test]
    async fn role_loss_malformed_row_is_a_typed_invalid_outcome_before_any_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.sqlite3");
        let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
        sync_state.plant_malformed_role_loss_operation_for_test("op-1").unwrap();
        let sync_state = reopen(&db_path, sync_state);

        let daemon_state = daemon_state_for(sync_state.clone());
        daemon_state.set_coordination_client_config(
            "http://127.0.0.1:1".to_string(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );

        let show = run_show_request(&daemon_state, RecoveryDomain::RoleLoss, "op-1").await;
        assert!(
            matches!(
                show.result,
                Some(yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::Invalid(_))
            ),
            "expected Result::Invalid, got {:?}",
            show.result
        );
    }

    /// A real IPC race for Role-loss, through `handle_request` end to
    /// end, using the same genuine two-way barrier as the Enrollment
    /// and Membership races.
    #[tokio::test]
    async fn role_loss_concurrent_local_mutation_during_remote_lookup_is_local_evidence_changed_on_the_wire(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("index.sqlite3");

        let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
        insert_role_loss_fixture(
            &sync_state,
            &RoleLossFixture {
                action: RoleLossAction::Demote,
                state: RoleLossOperationState::WorkerCommitted,
                worker_membership_generation: Some(4),
            },
        );
        sync_state.link_repository().add_link(LOCAL_PATH, ROLE_LOSS_GROUP_ID).unwrap();
        let sync_state = reopen(&db_path, sync_state);

        let body = role_loss_body(
            "demote",
            ROLE_LOSS_SOURCE_DEVICE_ID,
            ROLE_LOSS_TARGET_DEVICE_ID,
            Some(ROLE_LOSS_LEASE_ID),
            4,
        );
        let server = HeldResponseServer::start(
            "GET",
            "/devices/role-loss-operations/op-1".to_string(),
            body,
        )
        .await;

        let daemon_state = daemon_state_for(sync_state.clone());
        daemon_state.set_coordination_client_config(
            server.base_url.clone(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );

        let mutator_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());

        let daemon_state_task = daemon_state.clone();
        let handle = tokio::spawn(async move {
            run_show_request(&daemon_state_task, RecoveryDomain::RoleLoss, "op-1").await
        });

        server.request_received.notified().await;
        mutator_state
            .role_loss_operation_repository()
            .advance_role_loss_operation("op-1", RoleLossOperationState::Compensating, 2)
            .unwrap();
        server.release_response.notify_one();

        let show = handle.await.unwrap();
        match show.result {
            Some(
                yadorilink_ipc_proto::daemonctl::show_recovery_operation_response::Result::LocalEvidenceChanged(
                    changed,
                ),
            ) => {
                let key = changed.key.unwrap();
                assert_eq!(key.domain, "role-loss");
                assert_eq!(key.operation_id, "op-1");
            }
            other => panic!("expected LocalEvidenceChanged, got {other:?}"),
        }

        assert_eq!(server.request_count(), 1, "exactly one Worker GET, no automatic retry");
        server.assert_clean("RoleLoss race");
    }
}

/// `route_kind` is only meaningful when the connection is actually
/// `Connected` -- every other reachability reports `RouteKind::Unspecified`
/// -- and a connected peer's route is carried as the kind it is.
#[test]
fn reachability_to_proto_only_carries_route_kind_when_connected() {
    use yadorilink_ipc_proto::daemonctl::{PeerReachability as Wire, RouteKind as WireRoute};

    let (reachability, _, route) = super::reachability_to_proto(
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
    );
    assert_eq!(reachability, Wire::Connected);
    assert_eq!(route, WireRoute::Direct);

    let (reachability, _, route) = super::reachability_to_proto(
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Relay),
    );
    assert_eq!(reachability, Wire::Connected);
    assert_eq!(route, WireRoute::Relay);

    let (_, _, route) =
        super::reachability_to_proto(crate::peer_registry::PeerReachability::Connecting);
    assert_eq!(route, WireRoute::Unspecified);

    let (_, _, route) =
        super::reachability_to_proto(crate::peer_registry::PeerReachability::Unreachable(
            crate::peer_registry::UnreachableCategory::NoResponse,
        ));
    assert_eq!(route, WireRoute::Unspecified);
}
