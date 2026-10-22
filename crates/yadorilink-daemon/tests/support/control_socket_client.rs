//! `topology_n_m_w.rs`, `topology_storage_mode_
//! safety.rs`, and `topology_pass3_protected_availability.rs` each opened
//! a real control-socket connection to query/drive a node's own daemon
//! over the actual wire boundary (the CLI/desktop-facing surface, not
//! `DaemonState` internals), but each did so with `tokio::net::UnixStream`
//! and `control_socket::unix_transport` UNCONDITIONALLY -- both
//! `#[cfg(unix)]` only, so every one of those files failed to even COMPILE
//! on Windows (confirmed live: `cargo build --workspace --all-targets` on
//! the Windows CI runner). `control_socket.rs` already has a real,
//! production Windows transport (`windows_transport`, named pipes) --
//! this module is the one shared place that picks the right transport per
//! platform, so test files calling it stay platform-agnostic themselves.

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_ipc_proto::daemonctl::{
    daemon_control_request::Payload as ReqPayload, daemon_control_response::Payload as RespPayload,
    DaemonControlRequest, DaemonControlResponse, LinkStatus, StatusRequest,
    CONTROL_PROTOCOL_VERSION,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};

/// An opaque, already-listening control socket for one node's `DaemonState`
/// -- reconnect to it as many times as needed via [`send`]. Holding this
/// alive keeps the underlying listener (and, on Unix, its socket
/// directory) alive; dropping it does not stop the spawned server task,
/// matching every existing call site's own throwaway-per-test lifetime.
#[allow(dead_code)]
pub struct ControlSocketHandle {
    #[cfg(unix)]
    socket_path: std::path::PathBuf,
    #[cfg(unix)]
    _socket_dir: tempfile::TempDir,
    #[cfg(windows)]
    pipe_name: String,
}

/// Spawns a real control-socket server for `state` (the right transport
/// for this platform) and waits for it to be ready to accept connections.
#[allow(dead_code)]
pub async fn start(state: Arc<DaemonState>) -> ControlSocketHandle {
    #[cfg(unix)]
    {
        let socket_dir = tempfile::tempdir().unwrap();
        let socket_path = socket_dir.path().join("daemon.sock");
        let serve_path = socket_path.clone();
        tokio::spawn(async move {
            let _ = yadorilink_daemon::control_socket::unix_transport::serve(
                &serve_path,
                Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(state)),
            )
            .await;
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !socket_path.exists() {
            if std::time::Instant::now() >= deadline {
                panic!("control socket never came up within 10s");
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        ControlSocketHandle { socket_path, _socket_dir: socket_dir }
    }
    #[cfg(windows)]
    {
        use std::sync::atomic::{AtomicU32, Ordering};
        static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pipe_name = format!(r"\\.\pipe\yadorilink-test-{}-{n}", std::process::id());
        let serve_name = pipe_name.clone();
        tokio::spawn(async move {
            let _ = yadorilink_daemon::control_socket::windows_transport::serve(
                &serve_name,
                Arc::new(yadorilink_daemon::control_context::ControlContext::from_state(state)),
            )
            .await;
        });
        // Named pipes live in `\\.\pipe\`, not the filesystem -- no path to
        // poll for existence, unlike the Unix socket above. A short fixed
        // wait for the listener to create its first pipe instance matches
        // `control_socket.rs`'s own Windows test helper (`start_daemon`)
        // exactly.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        ControlSocketHandle { pipe_name }
    }
}

#[cfg(unix)]
async fn connect(handle: &ControlSocketHandle) -> tokio::net::UnixStream {
    tokio::net::UnixStream::connect(&handle.socket_path).await.unwrap()
}

#[cfg(windows)]
async fn connect(handle: &ControlSocketHandle) -> tokio::net::windows::named_pipe::NamedPipeClient {
    tokio::net::windows::named_pipe::ClientOptions::new().open(&handle.pipe_name).unwrap()
}

/// Sends one request over a fresh connection to `handle` and returns the
/// response -- the generic counterpart to [`query_link_status`] for
/// callers that need a request other than `Status` (e.g. `SetStorageMode`).
#[allow(dead_code)]
pub async fn send(handle: &ControlSocketHandle, payload: ReqPayload) -> DaemonControlResponse {
    let mut stream = connect(handle).await;
    write_message(
        &mut stream,
        &DaemonControlRequest {
            payload: Some(payload),
            protocol_version: CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    .unwrap();
    read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap()
}

/// Convenience wrapper over [`send`]: starts a control socket for `state`,
/// sends one `Status` request, and returns the `LinkStatus` entry for
/// `group_id` -- panics if the group is not present in the response,
/// matching every call site's own "the group must be there" expectation.
#[allow(dead_code)]
pub async fn query_link_status(state: Arc<DaemonState>, group_id: &str) -> LinkStatus {
    let handle = start(state).await;
    let resp = send(&handle, ReqPayload::Status(StatusRequest {})).await;
    let Some(RespPayload::Status(status)) = resp.payload else {
        panic!("expected a Status response, got {:?}", resp.payload);
    };
    status
        .links
        .into_iter()
        .find(|l| l.group_id == group_id)
        .unwrap_or_else(|| panic!("control socket did not report group {group_id}"))
}
