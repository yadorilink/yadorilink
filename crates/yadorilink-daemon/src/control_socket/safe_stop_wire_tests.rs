//! `request_safe_stop` through the control dispatch: the wire form of each answer.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::request_safe_stop_response::Outcome;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, RequestSafeStopRequest, SafeStopBusyReason, CONTROL_PROTOCOL_VERSION,
};
use yadorilink_local_storage::SegmentBlockStore;

use crate::application::ports::{SafeStopBusy, SafeStopOutcome};
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

fn context() -> crate::control_context::ControlContext {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    crate::control_context::ControlContext::from_state(DaemonState::new(
        "device-a".into(),
        sync_state,
        store,
    ))
}

async fn stop(
    context: &crate::control_context::ControlContext,
    version: u32,
) -> Option<RespPayload> {
    super::handle_request(
        context,
        DaemonControlRequest {
            payload: Some(ReqPayload::RequestSafeStop(RequestSafeStopRequest { deadline_secs: 0 })),
            protocol_version: version,
        },
    )
    .await
    .payload
}

#[tokio::test]
async fn a_daemon_with_nothing_in_flight_stops_and_a_repeat_says_so() {
    let context = context();
    let Some(RespPayload::RequestSafeStop(first)) = stop(&context, CONTROL_PROTOCOL_VERSION).await
    else {
        panic!("not a safe-stop answer")
    };
    let Some(Outcome::Stopping(first)) = first.outcome else { panic!("not stopping") };
    assert!(!first.already_in_progress);
    let Some(RespPayload::RequestSafeStop(again)) = stop(&context, CONTROL_PROTOCOL_VERSION).await
    else {
        panic!("not a safe-stop answer")
    };
    let Some(Outcome::Stopping(again)) = again.outcome else { panic!("not stopping") };
    assert!(again.already_in_progress);
}

#[tokio::test]
async fn a_request_from_another_generation_is_refused_and_stops_nothing() {
    let context = context();
    let response = stop(&context, CONTROL_PROTOCOL_VERSION + 1).await;
    assert!(matches!(response, Some(RespPayload::Error(_))));
    // A refused request begins no stop: the next one from the right generation is the first.
    let Some(RespPayload::RequestSafeStop(first)) = stop(&context, CONTROL_PROTOCOL_VERSION).await
    else {
        panic!("not a safe-stop answer")
    };
    assert!(matches!(first.outcome, Some(Outcome::Stopping(s)) if !s.already_in_progress));
}

#[test]
fn a_busy_answer_carries_its_reason_and_retry_hint() {
    for (reason, wire) in [
        (SafeStopBusy::WritesInProgress, SafeStopBusyReason::WritesInProgress),
        (SafeStopBusy::CheckpointFailed, SafeStopBusyReason::CheckpointFailed),
        (SafeStopBusy::AnotherRequestInProgress, SafeStopBusyReason::AnotherRequestInProgress),
    ] {
        let encoded = super::encode_safe_stop(SafeStopOutcome::Busy {
            reason,
            detail: "why".into(),
            retry_after: Duration::from_secs(5),
        });
        let Some(Outcome::Busy(busy)) = encoded.outcome else { panic!("not busy") };
        assert_eq!(busy.reason, wire as i32);
        assert_eq!(busy.retry_after_secs, 5);
        assert_eq!(busy.detail, "why");
    }
}
