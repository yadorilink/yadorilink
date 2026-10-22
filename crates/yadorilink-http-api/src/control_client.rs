//! Dials the daemon's existing control socket exactly the way
//! `yadorilink-cli`'s `control_client.rs` does: the same length-prefixed
//! framing (`yadorilink_ipc_proto::framing`), the same
//! `DaemonControlRequest`/`DaemonControlResponse` wire types, and the same
//! protocol-version check. Every HTTP handler in this crate goes through
//! this one `send`, so "translate IPC into HTTP" never means anything more
//! than "encode a request, decode a response" -- no daemon business logic is
//! duplicated or reimplemented here.
//!
//! A fresh connection is opened per call, mirroring both the CLI client and
//! `control_socket.rs`'s own `handle_connection` (one request/response per
//! accepted connection) -- there is no persistent-connection state to manage
//! or get out of sync.

use std::time::Duration;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{DaemonControlRequest, DaemonControlResponse};
use yadorilink_ipc_proto::framing::{read_message, write_message};

use crate::error::ApiError;

/// Bounds one full control-socket round trip (connect, write the request,
/// read the response) so a hung daemon-side connection cannot pin an HTTP
/// handler -- and, for `/api/events`, its poller task and `sse_slots`
/// permit -- indefinitely. Generous relative to a real local Unix-socket/
/// named-pipe round trip (sub-millisecond in practice), bounded enough that
/// a caller waiting on this adapter gets a `DaemonUnavailable` response
/// rather than hanging forever. Comfortably shorter than both
/// `lib.rs::REQUEST_TIMEOUT` (30s, the outer per-request backstop this
/// timeout normally resolves well within) and `conn_limit`'s
/// connection-level idle timeout, so a hung control socket surfaces as this
/// adapter's own documented `503 DaemonUnavailable` JSON response, written
/// out over a connection neither of those longer timeouts has any reason to
/// have torn down yet.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds a [`ControlClient::send_long`] wait. Kept under `lib.rs::REQUEST_TIMEOUT`
/// (30s), so this adapter answers with its own `StillRunning` response
/// before the outer backstop drops the request.
const LONG_REQUEST_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Clone)]
pub struct ControlClient {
    #[cfg(unix)]
    socket_path: std::path::PathBuf,
    #[cfg(windows)]
    pipe_name: String,
}

impl ControlClient {
    #[cfg(unix)]
    pub fn new(socket_path: std::path::PathBuf) -> Self {
        Self { socket_path }
    }

    #[cfg(windows)]
    pub fn new(pipe_name: String) -> Self {
        Self { pipe_name }
    }

    #[cfg(unix)]
    async fn connect(&self) -> std::io::Result<tokio::net::UnixStream> {
        tokio::net::UnixStream::connect(&self.socket_path).await
    }

    /// Mirrors `yadorilink-cli`'s own `connect()` retry-on-busy-pipe loop
    /// (see that crate's `control_client.rs`) -- a fresh named-pipe instance
    /// should almost always be waiting, but a burst of concurrent HTTP
    /// requests can still race the daemon re-arming it.
    #[cfg(windows)]
    async fn connect(&self) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        use tokio::net::windows::named_pipe::ClientOptions;
        use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;

        const ERROR_PIPE_BUSY: i32 = 231;
        const MAX_ATTEMPTS: u32 = 5;
        const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

        let mut attempt = 0;
        loop {
            match ClientOptions::new()
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(&self.pipe_name)
            {
                Ok(client) => {
                    // Any local user can create this pipe first; only talk to the
                    // daemon running as this user.
                    yadorilink_ipc_proto::pipe_peer::verify_pipe_server_is_current_user(&client)?;
                    return Ok(client);
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < MAX_ATTEMPTS => {
                    attempt += 1;
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn send(&self, payload: ReqPayload) -> Result<DaemonControlResponse, ApiError> {
        match tokio::time::timeout(REQUEST_TIMEOUT, self.send_inner(payload)).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(
                    timeout_secs = REQUEST_TIMEOUT.as_secs(),
                    "control socket round trip timed out"
                );
                Err(ApiError::DaemonUnavailable)
            }
        }
    }

    /// [`Self::send`] for a request whose duration depends on the network or
    /// on the folder (linking, joining, an update check, a preflight scan).
    /// The daemon finishes such a request even when this side stops
    /// waiting, so running past [`LONG_REQUEST_TIMEOUT`] is reported as
    /// [`ApiError::StillRunning`], never as a failure.
    pub async fn send_long(&self, payload: ReqPayload) -> Result<DaemonControlResponse, ApiError> {
        match tokio::time::timeout(LONG_REQUEST_TIMEOUT, self.send_inner(payload)).await {
            Ok(result) => result,
            Err(_) => Err(ApiError::StillRunning),
        }
    }

    async fn send_inner(&self, payload: ReqPayload) -> Result<DaemonControlResponse, ApiError> {
        let mut stream = self.connect().await.map_err(|e| {
            tracing::warn!(error = %e, "control socket connect failed");
            ApiError::DaemonUnavailable
        })?;

        let protocol_version = yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION;
        write_message(
            &mut stream,
            &DaemonControlRequest { payload: Some(payload), protocol_version },
        )
        .await
        .map_err(|e| ApiError::Internal(format!("failed writing control-socket request: {e}")))?;

        let resp = read_message::<DaemonControlResponse>(&mut stream)
            .await
            .map_err(|e| {
                ApiError::Internal(format!("failed reading control-socket response: {e}"))
            })?
            .ok_or(ApiError::DaemonUnavailable)?;

        // Pre-release binaries are one release unit -- same discipline as
        // the CLI's own client: never interpret a mismatched-generation
        // response via protobuf zero/default behavior.
        if resp.daemon_protocol_version != protocol_version {
            return Err(ApiError::Internal(format!(
                "control protocol version mismatch (http-api {protocol_version}, daemon {}); \
                 the daemon and this HTTP adapter were built from different revisions",
                resp.daemon_protocol_version
            )));
        }
        if let Some(RespPayload::Error(msg)) = &resp.payload {
            return Err(ApiError::DaemonRejected(msg.clone()));
        }
        Ok(resp)
    }
}
