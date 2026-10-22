//! `open_nas_admin` against a stand-in daemon on a real socket: the session
//! is held by the control connection, so closing or dropping the
//! `AdminSession` is seen by the daemon as that connection closing, and the
//! daemon closing it ends the session here.
#![cfg(unix)]

use std::time::Duration;

use tokio::io::AsyncReadExt as _;
use yadorilink_client_core::ops::nas_admin::{open_nas_admin, NasAdminOpen};
use yadorilink_client_core::wording::NasAdminFailure;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::open_nas_admin_response::Outcome;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, IdentifyResponse, NasAdminFailureKind,
    OpenNasAdminResponse, CONTROL_PROTOCOL_VERSION,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};

const STEP: Duration = Duration::from_secs(10);

/// Tests here share `YADORILINK_CONTROL_SOCKET`, so they run one at a time.
static SOCKET_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What the stand-in daemon does once it has answered.
enum Then {
    /// Waits for the client to close the connection, and reports that it did.
    AwaitClose,
    /// Closes the connection itself, as the daemon does when a session ends.
    Close,
}

/// Answers the first request with `outcome` and then does `then`. Returns
/// the device id asked for and whether the client closed the connection.
async fn with_daemon<T>(
    outcome: Outcome,
    then: Then,
    client: impl AsyncFnOnce() -> T,
) -> (T, String, bool) {
    let _guard = SOCKET_ENV_LOCK.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket);
    let daemon = tokio::spawn(async move {
        // The client first asks who the daemon is (its release check), on the same connection.
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = read_message::<DaemonControlRequest>(&mut stream).await.unwrap().unwrap();
        if matches!(request.payload, Some(ReqPayload::Identify(_))) {
            let identify = DaemonControlResponse {
                daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
                payload: Some(RespPayload::Identify(IdentifyResponse {
                    engine_api_version: yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION,
                    ..Default::default()
                })),
            };
            write_message(&mut stream, &identify).await.unwrap();
            request = read_message::<DaemonControlRequest>(&mut stream).await.unwrap().unwrap();
        }
        let Some(ReqPayload::OpenNasAdmin(open)) = request.payload else { panic!("{request:?}") };
        let response = DaemonControlResponse {
            daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
            payload: Some(RespPayload::OpenNasAdmin(OpenNasAdminResponse {
                outcome: Some(outcome),
            })),
        };
        write_message(&mut stream, &response).await.unwrap();
        let closed_by_client = match then {
            Then::AwaitClose => {
                let mut byte = [0u8; 1];
                matches!(tokio::time::timeout(STEP, stream.read(&mut byte)).await, Ok(Ok(0)))
            }
            Then::Close => false,
        };
        (open.device_id, closed_by_client)
    });
    let result = client().await;
    let (device_id, closed) = daemon.await.unwrap();
    std::env::remove_var("YADORILINK_CONTROL_SOCKET");
    (result, device_id, closed)
}

fn url() -> Outcome {
    Outcome::LocalUrl("http://127.0.0.1:49152/".into())
}

#[tokio::test]
async fn closing_the_session_closes_its_control_connection() {
    let (_, device_id, closed) = with_daemon(url(), Then::AwaitClose, async || {
        let NasAdminOpen::Opened(session) = open_nas_admin("nas-1".into()).await.unwrap() else {
            panic!("expected an open session")
        };
        assert_eq!(session.local_url(), "http://127.0.0.1:49152/");
        session.close();
        session.close();
        tokio::time::timeout(STEP, session.ended()).await.expect("closed here, so ended");
    })
    .await;
    assert_eq!(device_id, "nas-1");
    assert!(closed, "the daemon must see the connection close");
}

/// An app or CLI that exits without closing (or crashes) drops the session;
/// the daemon sees the same thing.
#[tokio::test]
async fn dropping_the_session_closes_its_control_connection() {
    let (_, _, closed) = with_daemon(url(), Then::AwaitClose, async || {
        let opened = open_nas_admin("nas-1".into()).await.unwrap();
        assert!(matches!(opened, NasAdminOpen::Opened(_)));
        drop(opened);
    })
    .await;
    assert!(closed);
}

/// The daemon ending a session (idle, device gone) ends it here too.
#[tokio::test]
async fn a_session_the_daemon_ends_reads_as_ended() {
    with_daemon(url(), Then::Close, async || {
        let NasAdminOpen::Opened(session) = open_nas_admin("nas-1".into()).await.unwrap() else {
            panic!("expected an open session")
        };
        tokio::time::timeout(STEP, session.ended()).await.expect("the daemon ended it");
    })
    .await;
}

#[tokio::test]
async fn each_failure_kind_is_one_of_the_three_failures() {
    for (kind, failure) in [
        (NasAdminFailureKind::Offline, NasAdminFailure::Offline),
        (NasAdminFailureKind::Unavailable, NasAdminFailure::Unavailable),
        (NasAdminFailureKind::CouldNotOpen, NasAdminFailure::CouldNotOpen),
        (NasAdminFailureKind::Unspecified, NasAdminFailure::CouldNotOpen),
    ] {
        let (opened, _, _) = with_daemon(Outcome::Failure(kind as i32), Then::Close, async || {
            open_nas_admin("nas-1".into()).await.unwrap()
        })
        .await;
        assert!(
            matches!(opened, NasAdminOpen::Failed(got) if got == failure),
            "{kind:?}: {opened:?}"
        );
    }
}
