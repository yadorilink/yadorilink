//! The rewind execute/status requests on the wire: refusals carry their
//! reason and the text to show, and a run reads back with its wording.

use std::sync::Arc;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::rewind_execute_response::Outcome;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, RewindExecuteRequest, RewindFailureKind, RewindRefusalReason,
    RewindRunState, RewindStatusRequest,
};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::rewind::{RewindFailureKind as Kind, RewindPlanId};

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "group-rewind";

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
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

fn execute(plan_id: Vec<u8>) -> ReqPayload {
    ReqPayload::RewindExecute(RewindExecuteRequest {
        group_id: GROUP.into(),
        target_unix_nanos: 500,
        plan_id,
    })
}

async fn outcome(state: &Arc<DaemonState>, plan_id: Vec<u8>) -> Outcome {
    match send(state, execute(plan_id)).await {
        RespPayload::RewindExecute(response) => response.outcome.expect("an outcome"),
        other => panic!("expected an execute response, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unknown_group_is_refused_with_its_reason() {
    let state = test_state();
    let Outcome::Refused(refused) = outcome(&state, vec![0; 32]).await else {
        panic!("expected a refusal")
    };
    assert_eq!(refused.reason, RewindRefusalReason::UnknownGroup as i32);
    assert!(refused.message.contains(GROUP), "{}", refused.message);
}

#[tokio::test]
async fn a_malformed_plan_id_is_an_error() {
    let state = test_state();
    assert!(matches!(send(&state, execute(vec![1, 2, 3])).await, RespPayload::Error(_)));
}

/// A plan id that is not the current plan's: nothing starts, and the
/// current plan's id comes back so a client can preview again.
#[tokio::test]
async fn a_plan_that_is_not_the_current_one_is_stale() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/rewind/root", GROUP).unwrap();
    state.authority.install_test_group_policy(
        GROUP,
        crate::change_policy::GroupPolicyState::with_members_for_tests(&[(
            "device-a",
            crate::change_policy::WriterRole::Editor,
        )]),
    );
    let Outcome::PlanStale(stale) = outcome(&state, vec![0; 32]).await else {
        panic!("expected a stale plan")
    };
    assert_eq!(stale.current_plan_id.len(), 32);
    assert_ne!(stale.current_plan_id, vec![0; 32]);
    assert_eq!(stale.message, "the folder changed since the rewind preview; preview again");
    assert!(state.replica_coordinator.rewind_run_repository().latest_run(GROUP).unwrap().is_none());
}

/// The latest run reads back with its state, kind, the offline devices and
/// the sentence to show.
#[tokio::test]
async fn the_status_of_a_transient_failure_names_the_offline_device() {
    let state = test_state();
    match send(&state, ReqPayload::RewindStatus(RewindStatusRequest { group_id: GROUP.into() }))
        .await
    {
        RespPayload::RewindStatus(status) => assert!(status.run.is_none()),
        other => panic!("expected a status, got {other:?}"),
    }

    let runs = state.replica_coordinator.rewind_run_repository();
    runs.begin_run("r1", GROUP, 500, &RewindPlanId([7; 32]), 1).unwrap();
    runs.mark_failed("r1", Kind::Transient, 0, &["nas".to_string()]).unwrap();

    let RespPayload::RewindStatus(status) =
        send(&state, ReqPayload::RewindStatus(RewindStatusRequest { group_id: GROUP.into() }))
            .await
    else {
        panic!("expected a status")
    };
    let run = status.run.expect("the run");
    assert_eq!(run.run_id, "r1");
    assert_eq!(run.state, RewindRunState::Failed as i32);
    assert_eq!(run.failure_kind, RewindFailureKind::Transient as i32);
    assert_eq!(run.offline_devices, vec!["nas".to_string()]);
    assert_eq!(
        run.message,
        "Rewind could not be prepared: nas is offline. Retry when it is available."
    );
}
