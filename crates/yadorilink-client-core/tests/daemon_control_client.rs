//! The control-socket client against a stand-in daemon that answers one
//! request with a canned response, so the client's own checks are exercised
//! over a real socket rather than by building `CoreError` values directly.
#![cfg(unix)]

use yadorilink_client_core::dto::PauseDuration;
use yadorilink_client_core::error::CoreError;
use yadorilink_client_core::ops::folders::pause_folder;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ApplicationCommandError, ApplicationErrorCode, DaemonControlRequest, DaemonControlResponse,
    IdentifyResponse, PauseResponse, CONTROL_PROTOCOL_VERSION,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};

/// Tests in this file share `YADORILINK_CONTROL_SOCKET`, a process-global
/// environment variable, so they run one at a time.
static SOCKET_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What `identify` says for a daemon of the same release as this test binary.
fn matching_identify() -> IdentifyResponse {
    IdentifyResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        engine_api_version: yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION,
        install_source: "script".into(),
        ..Default::default()
    }
}

fn identify_response(report: IdentifyResponse) -> DaemonControlResponse {
    DaemonControlResponse {
        daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
        payload: Some(RespPayload::Identify(report)),
    }
}

/// Binds a socket, points the client at it, and answers every `identify` with `identify` and the
/// first other request with `response`. Returns the requests the daemon received, in order.
async fn with_daemon_identifying_as<T>(
    identify: IdentifyResponse,
    response: DaemonControlResponse,
    client: impl std::future::Future<Output = T>,
) -> (T, Vec<DaemonControlRequest>) {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);
    let daemon = tokio::spawn(async move {
        let mut seen = Vec::new();
        let Ok(accepted) =
            tokio::time::timeout(std::time::Duration::from_millis(500), listener.accept()).await
        else {
            return seen;
        };
        let (mut stream, _) = accepted.unwrap();
        // The client's release check and its request arrive on one connection.
        loop {
            let Ok(Some(request)) = read_message::<DaemonControlRequest>(&mut stream).await else {
                return seen;
            };
            let is_identify = matches!(request.payload, Some(ReqPayload::Identify(_)));
            seen.push(request);
            let answer =
                if is_identify { identify_response(identify.clone()) } else { response.clone() };
            write_message(&mut stream, &answer).await.unwrap();
            if !is_identify {
                return seen;
            }
        }
    });
    let result = client.await;
    let seen = daemon.await.unwrap();
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
    (result, seen)
}

/// [`with_daemon_identifying_as`] for a daemon of this program's own release; returns the last
/// request, the one that is not `identify`.
async fn with_canned_daemon<T>(
    response: DaemonControlResponse,
    client: impl std::future::Future<Output = T>,
) -> (T, DaemonControlRequest) {
    let (result, mut seen) =
        with_daemon_identifying_as(matching_identify(), response, client).await;
    (result, seen.pop().expect("the daemon received no request"))
}

/// A state-changing request is held back, and nothing but `identify` reaches the daemon, when
/// the daemon speaks another engine API.
#[tokio::test]
async fn a_daemon_of_another_engine_api_gets_nothing_but_identify() {
    let mut other = matching_identify();
    other.engine_api_version += 1;
    let (result, seen) = with_daemon_identifying_as(
        other,
        DaemonControlResponse {
            daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
            payload: Some(RespPayload::Pause(PauseResponse {})),
        },
        pause_folder("/folder".into(), PauseDuration::UntilResumed, None),
    )
    .await;
    match result {
        Err(CoreError::EngineMismatch { message, detail }) => {
            assert_eq!(detail.engine_api_version, detail.app_api_version + 1);
            assert_eq!(detail.kind, yadorilink_client_core::error::EngineMismatchKind::ApiVersion);
            assert_eq!(
                detail.direction,
                yadorilink_client_core::error::EngineMismatchDirection::EngineNewer
            );
            assert!(message.contains("Nothing was changed"), "{message}");
        }
        other => panic!("expected an engine mismatch, got {other:?}"),
    }
    assert_eq!(seen.len(), 1, "only identify may be sent");
    assert!(matches!(seen[0].payload, Some(ReqPayload::Identify(_))));
}

/// The same daemon still answers read-only requests, so the mismatch can be looked at.
#[tokio::test]
async fn read_only_requests_still_work_across_a_mismatch() {
    let mut other = matching_identify();
    other.engine_api_version += 1;
    other.release_id = "x:y".into();
    let (result, seen) = with_daemon_identifying_as(
        other,
        DaemonControlResponse {
            daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
            payload: Some(RespPayload::Status(Default::default())),
        },
        yadorilink_client_core::daemon::control::send(ReqPayload::Status(Default::default())),
    )
    .await;
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(seen.len(), 1);
    assert!(matches!(seen[0].payload, Some(ReqPayload::Status(_))));
}

/// A daemon from another protocol generation is refused even when its answer
/// looks like success: a pause it may not have understood must not read as
/// done.
#[tokio::test]
async fn a_success_answer_from_a_daemon_of_another_protocol_generation_is_refused() {
    let daemon = CONTROL_PROTOCOL_VERSION + 1;
    let (result, request) = with_canned_daemon(
        DaemonControlResponse {
            daemon_protocol_version: daemon,
            payload: Some(RespPayload::Pause(PauseResponse {})),
        },
        pause_folder("/folder".into(), PauseDuration::UntilResumed, None),
    )
    .await;
    assert_eq!(request.protocol_version, CONTROL_PROTOCOL_VERSION);
    assert!(matches!(request.payload, Some(ReqPayload::Pause(ref r)) if r.local_path == "/folder"));
    match result {
        Err(CoreError::DaemonProtocolMismatch { client, daemon: got }) => {
            assert_eq!((client, got), (CONTROL_PROTOCOL_VERSION, daemon));
        }
        other => panic!("expected a protocol mismatch, got {other:?}"),
    }
}

/// A plain error answer is a rejection, not a pause that went through.
#[tokio::test]
async fn a_plain_error_answer_is_a_rejection_with_the_daemons_message() {
    let (result, _) = with_canned_daemon(
        DaemonControlResponse {
            daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
            payload: Some(RespPayload::Error("no such link".into())),
        },
        pause_folder("/folder".into(), PauseDuration::UntilResumed, None),
    )
    .await;
    assert!(
        matches!(&result, Err(CoreError::DaemonRejected(m)) if m == "no such link"),
        "{result:?}"
    );
}

/// A typed refusal keeps its code, so a front end never reads the text.
#[tokio::test]
async fn a_typed_refusal_answer_keeps_its_code() {
    let (result, _) = with_canned_daemon(
        DaemonControlResponse {
            daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
            payload: Some(RespPayload::CommandError(ApplicationCommandError {
                code: ApplicationErrorCode::DiskFull as i32,
                message: "no space".into(),
                ..Default::default()
            })),
        },
        pause_folder("/folder".into(), PauseDuration::UntilResumed, None),
    )
    .await;
    assert!(
        matches!(&result, Err(e) if e.is_command_error(ApplicationErrorCode::DiskFull)),
        "{result:?}"
    );
}

/// The matching generation with the expected payload succeeds, so the two
/// refusals above are the checks and not a socket that never works.
#[tokio::test]
async fn a_matching_success_answer_succeeds() {
    let (result, _) = with_canned_daemon(
        DaemonControlResponse {
            daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
            payload: Some(RespPayload::Pause(PauseResponse {})),
        },
        pause_folder("/folder".into(), PauseDuration::UntilResumed, None),
    )
    .await;
    assert!(result.is_ok(), "{result:?}");
}
