//! CLI ↔ daemon control protocol: one
//! request/response exchange per connection, framed as length-prefixed
//! protobuf (`yadorilink_ipc_proto::framing`) over a Unix domain socket on
//! macOS/Linux, a named pipe on Windows (Windows local IPC support).
//!
//! `handle_connection` is transport-agnostic (any `AsyncRead + AsyncWrite`
//! stream) — unlike `shell_ipc`'s persistent duplex connection, control
//! socket exchanges are a single request then a single response, so no
//! split read/write halves are needed here even on Windows, where a
//! connected named pipe already implements both traits on one handle.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::rewind_execute_response::Outcome as RewindExecuteOutcome;
use yadorilink_ipc_proto::daemonctl::{
    accept_invite_command_response, create_and_link_command_response,
    delete_group_command_response, join_and_link_command_response, mint_invite_command_response,
    remove_device_command_response, revoke_device_command_response, revoke_edge_command_response,
    AcceptInviteCommandResponse, ApplicationCommandError, ApplicationErrorCode,
    CancelTransferResponse, CheckFullReplicaHandoffReadyExcludingResponse,
    CheckFullReplicaHandoffReadyResponse, ConflictedFileInfo, ConnectionAttemptTrace,
    ConnectivityDoctorCategory, ConnectivityDoctorResponse, CreateAndLinkCommandResponse,
    DaemonControlRequest, DaemonControlResponse, DeleteGroupCommandResponse,
    EnrollmentCommandOutcome, EvictResponse, FileVersionInfo, GcResponse,
    GetSpaceManagementResponse, HandoffResult, HealthResponse, HydrateResponse, InboxFileSummary,
    InboxTransfer, JoinAndLinkCommandResponse, LatchGroupDurabilityUnknownResponse,
    LimitsSetResponse, LimitsShowResponse, LinkPreflightResponse, LinkRequest, LinkResponse,
    ListConflictsResponse, ListConnectionTracesResponse, ListInboxResponse, ListLinksResponse,
    ListQueueItemsResponse, ListRecoveryOperationsResponse, ListSentTransfersResponse,
    ListTrashResponse, ListVersionsResponse, LocalState as WireLocalState,
    LocalTransition as WireLocalTransition, MarkLinkNotRejoinedResponse,
    MaterializationStatusResponse, MembershipHandoffResult, MintInviteCommandResponse,
    MintedInviteInfo, NasAdminFailureKind, ObtainHandoffTicketResponse, OpenNasAdminResponse,
    PauseResponse, PendingEnrollmentKind, PinItemResponse, PreviewSpaceReclaimResponse, QueueItem,
    ReadoptVolumeResponse, ReceiveTransferResponse, ReleaseHandoffTicketResponse,
    RemoveDeviceCommandResponse, RemovePendingEnrollmentResponse, ReplicaMembershipCommandOutcome,
    ReportingConsentState, ReportingStatusResponse, RequestHandoffLeaseResponse,
    RestoreTrashOperationFailure, RestoreTrashOperationResponse, RestoreTrashResponse,
    RestoreVersionResponse, ResumeResponse, RetentionPolicy, RetentionState as WireRetentionState,
    RetryTransferResponse, RevokeDeviceCommandResponse, RevokeEdgeCommandResponse,
    RewindActionCounts as WireRewindActionCounts, RewindExecuteResponse,
    RewindPathEntry as WireRewindPathEntry, RewindPlanStale, RewindPreviewResponse, RewindRefused,
    RewindRenameCandidate as WireRewindRenameCandidate, RewindRun as WireRewindRun,
    RewindRunStarted, RewindStatusResponse, SendFileResponse, SentTransferEntry,
    SetSpaceManagementResponse, SetStorageModeResponse, ShowQueueItemResponse, ShutdownResponse,
    SpaceReclaimPreviewItem, TaskLiveness, TrashedFileInfo, UnlinkResponse, UnpinItemResponse,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};

use crate::enrollment_commands::{self, link_refusal_code};
use crate::pause_deadline::PauseDuration;
use crate::reporting_ipc;
use crate::status_report::encode_link_status;
#[cfg(test)]
#[allow(
    unused_imports,
    reason = "the wire tests in this module's children name these through `super`"
)]
use crate::status_report::{
    overall_status, reachability_to_proto, OverallState, UNREADABLE_FILES_LISTED,
};
use yadorilink_ipc_proto::daemonctl::PauseDuration as WirePauseDuration;

const MAX_CONTROL_CONNECTIONS: usize = 64;

async fn handle_connection<S>(
    mut stream: S,
    context: Arc<crate::control_context::ControlContext>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(mut req) = read_message::<DaemonControlRequest>(&mut stream).await? else {
        return Ok(());
    };
    // A client that must know which release it is talking to asks `identify` first and then sends
    // its request on this same connection, so the answer describes the daemon that serves it.
    if matches!(req.payload, Some(ReqPayload::Identify(_))) {
        let resp = handle_request(&context, req).await;
        write_message(&mut stream, &resp).await?;
        let Some(next) = read_message::<DaemonControlRequest>(&mut stream).await? else {
            return Ok(());
        };
        req = next;
    }
    if req.protocol_version == yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION {
        if let Some(ReqPayload::OpenNasAdmin(open)) = &req.payload {
            return serve_nas_admin(stream, &context, &open.device_id).await;
        }
    }
    let resp = handle_request(&context, req).await;
    match write_message(&mut stream, &resp).await {
        // A response too large to frame is refused by `write_message`
        // before any byte reaches the stream, so the connection is still
        // clean and the client can be told what happened instead of seeing
        // the socket close on it. Every response that can grow with the
        // size of a folder is expected to bound itself (see
        // `crate::rewind::trim_for_wire` for the worked case); this is the
        // backstop for one that does not.
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            let fallback = DaemonControlResponse {
                daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
                payload: Some(RespPayload::Error(format!(
                    "this daemon's answer is too large to send over the control socket \
                     ({error}); narrow the request and try again"
                ))),
            };
            write_message(&mut stream, &fallback).await
        }
        other => other,
    }
}

/// A management session for another device on this account. The one
/// request whose connection outlives its response: the session lives as
/// long as this connection, so a client that exits (or crashes) ends it.
async fn serve_nas_admin<S>(
    mut stream: S,
    context: &crate::control_context::ControlContext,
    device_id: &str,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use yadorilink_ipc_proto::daemonctl::open_nas_admin_response::Outcome;
    let respond = |outcome| DaemonControlResponse {
        daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        payload: Some(RespPayload::OpenNasAdmin(OpenNasAdminResponse { outcome: Some(outcome) })),
    };
    match context.application.nas_admin.open(device_id).await {
        Err(failure) => {
            let kind = nas_admin_failure_to_proto(failure);
            write_message(&mut stream, &respond(Outcome::Failure(kind as i32))).await
        }
        Ok(open) => {
            let url = open.session.local_url();
            write_message(&mut stream, &respond(Outcome::LocalUrl(url))).await?;
            crate::nas_admin_bridge::serve_for_connection(open.session, &mut stream).await;
            Ok(())
        }
    }
}

fn nas_admin_failure_to_proto(
    failure: crate::nas_admin_bridge::OpenFailure,
) -> NasAdminFailureKind {
    use crate::nas_admin_bridge::OpenFailure;
    match failure {
        OpenFailure::Offline => NasAdminFailureKind::Offline,
        OpenFailure::Unavailable => NasAdminFailureKind::Unavailable,
        OpenFailure::CouldNotOpen => NasAdminFailureKind::CouldNotOpen,
    }
}

#[cfg(unix)]
pub mod unix_transport {
    use std::path::Path;
    use std::sync::Arc;

    use tokio::net::UnixListener;
    use tokio::sync::Semaphore;

    use crate::control_context::ControlContext;

    /// `context` is built exactly once by the caller (in production,
    /// `app.rs` -- the sole composition root; see `ControlContext`'s own
    /// doc comment) and handed down through every connection, never
    /// rebuilt here.
    pub async fn serve(socket_path: &Path, context: Arc<ControlContext>) -> std::io::Result<()> {
        let _ = std::fs::remove_file(socket_path); // clean up a stale socket from a crashed prior run
        prepare_private_socket_parent(socket_path)?;
        let listener = UnixListener::bind(socket_path)?;
        // This socket accepts unauthenticated Link/Unlink/Pause/Resume/Shutdown
        // requests from anything that can connect to it — restrict to the
        // owning user so another local account can't issue them (defense in
        // depth; the config directory itself should already be private).
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(path = %socket_path.display(), "control socket listening (unix socket)");

        let connection_slots = Arc::new(Semaphore::new(super::MAX_CONTROL_CONNECTIONS));
        loop {
            let connection_slot = connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("control socket semaphore closed"))?;
            let (stream, _) = listener.accept().await?;
            let context = context.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                if let Err(e) = super::handle_connection(stream, context).await {
                    tracing::debug!(error = %e, "control connection ended");
                }
            });
        }
    }

    /// Waits until a server spawned on `socket_path` accepts connections. A fixed sleep after
    /// spawning cannot promise that on a busy machine, and the file existing is not enough: a
    /// socket left by an earlier server on the same path refuses connections.
    pub async fn wait_until_bound(socket_path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while tokio::net::UnixStream::connect(socket_path).await.is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "socket {} was not accepting connections within 10s",
                socket_path.display()
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    fn prepare_private_socket_parent(socket_path: &Path) -> std::io::Result<()> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

/// Windows named-pipe transport (Windows local IPC support): verified
/// against a real Windows 11 VM, unlike `shell_ipc`'s windows_transport
/// (written earlier with no Windows machine available to test it).
#[cfg(windows)]
pub mod windows_transport {
    use std::sync::Arc;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::sync::Semaphore;

    use crate::control_context::ControlContext;
    use crate::windows_pipe_security::PipeSecurityAttributes;

    // `PipeSecurityAttributes` holds a raw `*mut c_void` and is therefore
    // `!Send`. Constructing it (and calling `as_mut_ptr` into it) inside a
    // plain, non-async helper function — rather than as a local in `serve`'s
    // async fn body — keeps it entirely out of that fn's generator state, so
    // it can never be "live across an `.await`" no matter how the loop below
    // is restructured. `serve`'s future gets wrapped in an `async move` block
    // and passed to `essential.spawn` (`main.rs`), which requires `Send`;
    // relying on precise drop-tracking to exclude a same-named local from an
    // async fn's generator state proved fragile in practice, this sidesteps
    // the question by never giving the value an async-fn-local home at all.
    // The security descriptor only needs to be valid for the duration of the
    // CreateNamedPipe call itself — the OS copies what it needs into the pipe
    // object — so it's safe to drop at the end of this synchronous helper.
    fn create_first_pipe_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
        let mut attrs = PipeSecurityAttributes::new_current_user_and_system_only()?;
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(pipe_name, attrs.as_mut_ptr())
        }
    }

    fn create_next_pipe_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
        let mut attrs = PipeSecurityAttributes::new_current_user_and_system_only()?;
        unsafe {
            ServerOptions::new().create_with_security_attributes_raw(pipe_name, attrs.as_mut_ptr())
        }
    }

    /// `pipe_name` should look like `\\.\pipe\yadorilink-ctl-<user>`.
    ///
    /// Verified against a real Windows 11 VM: an earlier version of this
    /// function created the next pipe instance *after* `connect.await`
    /// returned, leaving a window with zero listening instances between a
    /// client connecting and the replacement instance existing — a second
    /// client connecting concurrently in that window got `ERROR_PIPE_BUSY`
    /// ("All pipe instances are busy"), caught by
    /// `windows_pipe_tests::two_concurrent_clients_are_both_served`.
    /// Creating the next instance *before* awaiting the current one's
    /// `connect` closes that window — there are always at least two
    /// listening instances in existence except right at startup.
    pub async fn serve(pipe_name: &str, context: Arc<ControlContext>) -> std::io::Result<()> {
        tracing::info!(pipe_name, "control socket listening (named pipe)");
        let mut server = create_first_pipe_server(pipe_name)?;
        let connection_slots = Arc::new(Semaphore::new(super::MAX_CONTROL_CONNECTIONS));

        loop {
            let connection_slot = connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("control socket semaphore closed"))?;
            let next_server = create_next_pipe_server(pipe_name)?;
            server.connect().await?;
            let connected = server;
            server = next_server;

            let context = context.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                if let Err(e) = super::handle_connection(connected, context).await {
                    tracing::debug!(error = %e, "control connection ended");
                }
            });
        }
    }
}

#[cfg(windows)]
const PROVIDER_LOCAL_STATE_HINT: &str =
    "this item is in a provider folder: the OS holds its local \
     state. `attrib` shows the offline attribute for an item that is not downloaded; \
     `yadorilink status` shows a folder's download progress";
#[cfg(not(windows))]
const PROVIDER_LOCAL_STATE_HINT: &str = "this item is in a File Provider folder: the OS holds its \
     local state. `ls -lO <path>` shows `dataless` for an item that is not downloaded; \
     `yadorilink status` shows a folder's download progress";

/// A request's `expected_group_id`: empty means the caller named no group to check.
fn expected_group(wire: &str) -> Option<&str> {
    (!wire.is_empty()).then_some(wire)
}

/// The typed refusal of a request whose link now belongs to another group. Nothing changed.
fn group_mismatch_response(local_path: String) -> RespPayload {
    RespPayload::CommandError(ApplicationCommandError {
        code: ApplicationErrorCode::GroupMismatch as i32,
        message: format!("the folder at {local_path} now belongs to a different group"),
        group_ids: Vec::new(),
        operation_id: String::new(),
    })
}

/// `SF_DATALESS` in `st_flags`: the OS holds the item's metadata but not its content.
#[cfg(any(target_vendor = "apple", test))]
const SF_DATALESS: u32 = 0x4000_0000;

/// The local state a File Provider item's flags show: present on this device unless dataless.
#[cfg(any(target_vendor = "apple", test))]
fn local_state_from_flags(st_flags: u32) -> WireLocalState {
    WireLocalState {
        local_object_present: st_flags & SF_DATALESS == 0,
        current_content_present: st_flags & SF_DATALESS == 0,
        transition: yadorilink_ipc_proto::daemonctl::LocalTransition::None as i32,
    }
}

/// The state of an item of a File Provider folder, read from the file itself (`lstat` never
/// downloads). `None` where the OS does not expose it or the item cannot be read.
#[cfg(target_vendor = "apple")]
fn provider_local_state(absolute_path: &str) -> Option<WireLocalState> {
    let path = std::ffi::CString::new(absolute_path).ok()?;
    // SAFETY: `lstat` fills the struct it is given; zeroed is a valid initial value, and the
    // path is a NUL-terminated string that outlives the call.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    Some(local_state_from_flags(stat.st_flags))
}

#[cfg(not(target_vendor = "apple"))]
fn provider_local_state(_absolute_path: &str) -> Option<WireLocalState> {
    None
}

/// What a download request for an item of a provider folder answers: the daemon never downloads
/// there, the operating system does, and keeping the item on this device is how to ask for it now.
fn space_settings_to_proto(
    config: &crate::space_management_config::SpaceManagementConfig,
) -> yadorilink_ipc_proto::daemonctl::SpaceManagementSettings {
    yadorilink_ipc_proto::daemonctl::SpaceManagementSettings { enabled: config.enabled }
}

const PROVIDER_DOWNLOAD_HINT: &str = "this item is in a provider folder: the operating system \
     downloads it when it is opened. To download it now and keep it on this device, use \
     `yadorilink pin <path>` (Always keep on this device)";

#[allow(
    clippy::too_many_lines,
    reason = "single exhaustive `match req.payload` dispatch table over every \
              `DaemonControlRequest` payload variant; each arm is one IPC verb's \
              call into an application service plus its response mapping. Kept in \
              one match so the compiler's exhaustiveness check is what proves every \
              wire verb is handled -- splitting it into per-group helpers would \
              require catch-all arms and let a newly added verb compile unhandled."
)]
async fn handle_request(
    context: &crate::control_context::ControlContext,
    req: DaemonControlRequest,
) -> DaemonControlResponse {
    // This repository has not shipped a public release yet, so the CLI,
    // desktop app, and daemon are always built and deployed as one unit —
    // a genuine version skew has no supported recovery path and must fail
    // clearly before touching any daemon state, not be executed anyway and
    // only surface as a mismatch once the CLI inspects the response. Absent
    // on a request that leaves it unset, `protocol_version`
    // decodes as 0, which is `!= CONTROL_PROTOCOL_VERSION` and thus rejected
    // the same as any other mismatch.
    if req.protocol_version != yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION {
        let message =
            if req.protocol_version > yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION {
                format!(
                    "this daemon (protocol version {}) does not support this request (client is \
                 protocol version {}); upgrade the daemon and try again",
                    yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
                    req.protocol_version,
                )
            } else {
                format!(
                    "this daemon requires exactly protocol version {} (client is protocol version \
                 {}); this is a pre-release build with no client/daemon compatibility path — run \
                 matching CLI and daemon binaries",
                    yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
                    req.protocol_version,
                )
            };
        return DaemonControlResponse {
            payload: Some(RespPayload::Error(message)),
            daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
    }
    let payload = match req.payload {
        Some(ReqPayload::Link(r)) => {
            match enrollment_commands::require_risks_acknowledged(
                &context.application.link_lifecycle,
                &r.local_path,
                r.acknowledge_risks,
            )
            .await
            {
                Err(error) => link_failure_payload(&error),
                Ok(()) => match decode_link_command(r) {
                    Err(message) => RespPayload::Error(message),
                    Ok(command) => match context.application.link_lifecycle.link(command).await {
                        Ok(_) => RespPayload::Link(LinkResponse {}),
                        Err(e) => link_failure_payload(&e),
                    },
                },
            }
        }

        // Served by `serve_nas_admin` on its own connection before this
        // dispatch is reached; here only for exhaustiveness.
        Some(ReqPayload::OpenNasAdmin(_)) => {
            RespPayload::Error("a management session is opened on its own connection".to_string())
        }
        Some(ReqPayload::LinkPreflight(r)) => match link_preflight(context, &r.local_path).await {
            Ok(response) => RespPayload::LinkPreflight(response),
            Err(message) => RespPayload::Error(message),
        },

        Some(ReqPayload::Unlink(r)) => {
            let application = context.application.clone();
            match application
                .replica_role
                .unlink(&r.local_path, r.force, expected_group(&r.expected_group_id))
                .await
            {
                Ok(outcome) => RespPayload::Unlink(UnlinkResponse {
                    handoff_result: outcome.handoff.map(|h| HandoffResult {
                        target_device_id: h.target_device_id,
                        root_digest: h.root_digest.to_vec(),
                        membership_generation: h.membership_generation,
                        lease_id: h.lease_id.unwrap_or_default(),
                    }),
                }),
                Err(crate::application::UnlinkError::NotProtected(message)) => {
                    RespPayload::CommandError(ApplicationCommandError {
                        code: ApplicationErrorCode::NotProtected as i32,
                        message,
                        group_ids: Vec::new(),
                        operation_id: String::new(),
                    })
                }
                Err(crate::application::UnlinkError::GroupMismatch(message)) => {
                    group_mismatch_response(message)
                }
                Err(crate::application::UnlinkError::Other(message)) => RespPayload::Error(message),
            }
        }

        Some(ReqPayload::ReadoptVolume(r)) => {
            match context.application.pause_resume.readopt_volume(&r.local_path).await {
                Ok(()) => RespPayload::ReadoptVolume(ReadoptVolumeResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::MarkLinkNotRejoined(r)) => {
            match context.application.link_lifecycle.mark_not_rejoined(&r.local_path).await {
                Ok(()) => RespPayload::MarkLinkNotRejoined(MarkLinkNotRejoinedResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::ListLinks(_)) => match context.queries.link_status.list_links() {
            Ok(links) => RespPayload::ListLinks(ListLinksResponse {
                links: links.into_iter().map(encode_link_status).collect(),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        Some(ReqPayload::Pause(r)) => {
            let duration =
                match yadorilink_ipc_proto::daemonctl::PauseDuration::try_from(r.duration) {
                    Ok(WirePauseDuration::ThirtyMinutes) => PauseDuration::ThirtyMinutes,
                    Ok(WirePauseDuration::OneHour) => PauseDuration::OneHour,
                    Ok(WirePauseDuration::UntilTomorrow) => PauseDuration::UntilTomorrow,
                    Ok(WirePauseDuration::Unspecified) | Err(_) => PauseDuration::UntilResumed,
                };
            match context.application.pause_resume.pause(
                &r.local_path,
                duration,
                expected_group(&r.expected_group_id),
            ) {
                Ok(()) => RespPayload::Pause(PauseResponse {}),
                Err(crate::sync_error::SyncError::GroupMismatch(path)) => {
                    group_mismatch_response(path)
                }
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::Resume(r)) => {
            match context
                .application
                .pause_resume
                .resume(&r.local_path, expected_group(&r.expected_group_id))
                .await
            {
                Ok(()) => RespPayload::Resume(ResumeResponse {}),
                Err(crate::sync_error::SyncError::GroupMismatch(path)) => {
                    group_mismatch_response(path)
                }
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        // Drops a pending-enrollment marker once `share create`/`share
        // join` has confirmed its own activate call directly -- an
        // optimization over waiting for the next `pending_enrollment::
        // reconcile` sweep to notice the same thing. Always succeeds: a
        // marker that's already gone (this device's own sweep beat the
        // caller to it) is a no-op, matching `remove_pending_enrollment`'s
        // own idempotent delete.
        Some(ReqPayload::RemovePendingEnrollment(r)) => {
            match context.application.enrollment_recovery.acknowledge_activation(&r.operation_id) {
                Ok(()) => RespPayload::RemovePendingEnrollment(RemovePendingEnrollmentResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        // `yadorilink versions <path>`.
        Some(ReqPayload::ListVersions(r)) => {
            match context.queries.file_history.list_versions(&r.absolute_path) {
                Ok(Some(versions)) => RespPayload::ListVersions(ListVersionsResponse {
                    versions: versions.into_iter().map(version_to_proto).collect(),
                }),
                Ok(None) => RespPayload::Error("path is not under any linked folder".into()),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        // `yadorilink restore <path> [--version <id>]`. An
        // absent `version_seq` resolves to the most recent superseded
        // version (spec "Restore without a version defaults to the most
        // recent superseded version") via `VersionRestoreService`; there
        // being none to restore to is reported as a clear error rather
        // than silently no-op'ing.
        Some(ReqPayload::RestoreVersion(r)) => {
            match context.queries.linked_path.resolve(&r.absolute_path) {
                Some((group_id, path)) => {
                    match context
                        .application
                        .version_restore
                        .restore_version(&group_id, &path, r.version_seq)
                        .await
                    {
                        Ok(true) => RespPayload::RestoreVersion(RestoreVersionResponse {}),
                        Ok(false) => {
                            RespPayload::Error("no superseded version to restore to".into())
                        }
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }

        // `yadorilink trash list`. Unlike the per-file requests
        // above, this spans every linked folder at once (no `absolute_path`
        // to resolve) — mirrors `list_link_statuses`'s own per-link
        // iteration below.
        Some(ReqPayload::ListTrash(_)) => match context.queries.file_history.list_trash() {
            Ok(files) => RespPayload::ListTrash(ListTrashResponse {
                files: files.into_iter().map(trashed_file_view_to_proto).collect(),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // `yadorilink conflicts list`. Same "spans every linked folder at
        // once" shape as `ListTrash` above.
        Some(ReqPayload::ListConflicts(_)) => match context.queries.file_history.list_conflicts() {
            Ok(files) => RespPayload::ListConflicts(ListConflictsResponse {
                files: files.into_iter().map(conflicted_file_view_to_proto).collect(),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // Keep this / Keep both: the daemon decides and performs it.
        Some(ReqPayload::ResolveConflict(r)) => {
            RespPayload::ResolveConflict(resolve_conflict(context, &r).await)
        }

        // Track Send: `yadorilink send <source_path> <target_device>`.
        Some(ReqPayload::SendFile(r)) => {
            match context.application.send_transfer.send(&r.source_path, &r.target_device).await {
                Ok(outcome) => RespPayload::SendFile(SendFileResponse {
                    transfer_id: outcome.transfer_id,
                    files_offered: outcome.files_offered,
                    total_size: outcome.total_size,
                }),
                Err(e) => RespPayload::Error(e),
            }
        }

        // Track Send: `yadorilink inbox`.
        Some(ReqPayload::ListInbox(_)) => match context.queries.inbox.list() {
            Ok(transfers) => RespPayload::ListInbox(ListInboxResponse {
                transfers: transfers
                    .into_iter()
                    .map(|t| InboxTransfer {
                        transfer_id: t.transfer_id,
                        sender_device_id: t.sender_device_id,
                        files: t
                            .files
                            .into_iter()
                            .map(|(relative_path, size)| InboxFileSummary { relative_path, size })
                            .collect(),
                        total_size: t.total_size,
                        offered_at_unix_nanos: t.offered_at_unix_nanos,
                        status: t.status.to_string(),
                        failure: t.failure.unwrap_or_default(),
                    })
                    .collect(),
            }),
            Err(e) => RespPayload::Error(e),
        },

        // Track Send: the transfers this device sent.
        Some(ReqPayload::ListSentTransfers(_)) => match context.queries.inbox.list_sent() {
            Ok(transfers) => RespPayload::ListSentTransfers(ListSentTransfersResponse {
                transfers: transfers
                    .into_iter()
                    .map(|t| SentTransferEntry {
                        transfer_id: t.transfer_id,
                        target_device_id: t.target_device_id,
                        files: t
                            .files
                            .into_iter()
                            .map(|(relative_path, size)| InboxFileSummary { relative_path, size })
                            .collect(),
                        total_size: t.total_size,
                        created_at_unix_nanos: t.created_at_unix_nanos,
                        status: t.status.to_string(),
                        failure: t.failure.unwrap_or_default(),
                        can_retry: t.can_retry,
                    })
                    .collect(),
            }),
            Err(e) => RespPayload::Error(e),
        },

        Some(ReqPayload::CancelTransfer(r)) => {
            match context.application.send_transfer.cancel(&r.transfer_id) {
                Ok(()) => RespPayload::CancelTransfer(CancelTransferResponse {}),
                Err(e) => RespPayload::Error(e),
            }
        }

        Some(ReqPayload::RetryTransfer(r)) => {
            match context.application.send_transfer.retry(&r.transfer_id, r.direction()).await {
                Ok(crate::send_transfer::RetryOutcome::Received(outcome)) => {
                    RespPayload::RetryTransfer(RetryTransferResponse {
                        destination_dir: outcome.destination_dir.to_string_lossy().into_owned(),
                        files_received: outcome.files_received,
                        bytes_received: outcome.bytes_received,
                        ..Default::default()
                    })
                }
                Ok(crate::send_transfer::RetryOutcome::Offered(outcome)) => {
                    RespPayload::RetryTransfer(RetryTransferResponse {
                        offered: true,
                        files_offered: outcome.files_offered,
                        total_size: outcome.total_size,
                        ..Default::default()
                    })
                }
                Err(e) => RespPayload::Error(e),
            }
        }

        // The setting is a small local file; an unreadable one reads as Off.
        Some(ReqPayload::GetSpaceManagement(_)) => {
            let config = crate::space_management_config::SpaceManagementStore::new(
                context.config_dir.clone(),
            )
            .load_or_off();
            RespPayload::GetSpaceManagement(GetSpaceManagementResponse {
                settings: Some(space_settings_to_proto(&config)),
            })
        }
        Some(ReqPayload::SetSpaceManagement(r)) => match r.settings {
            None => RespPayload::Error("no setting given".into()),
            Some(settings) => match crate::space_management_config::SpaceManagementStore::new(
                context.config_dir.clone(),
            )
            .set(settings.enabled)
            {
                Ok(config) => RespPayload::SetSpaceManagement(SetSpaceManagementResponse {
                    settings: Some(space_settings_to_proto(&config)),
                }),
                Err(e) => RespPayload::Error(format!("could not save the setting: {e}")),
            },
        },
        Some(ReqPayload::PreviewSpaceReclaim(_)) => match context.auto_reclaim.preview().await {
            Some(scan) => RespPayload::PreviewSpaceReclaim(PreviewSpaceReclaimResponse {
                items: scan
                    .entries
                    .iter()
                    .map(|e| SpaceReclaimPreviewItem {
                        group_id: e.group_id.clone(),
                        path: e.path.clone(),
                        verdict: e.verdict.to_wire() as i32,
                    })
                    .collect(),
                unreadable_roots: scan.unreadable_roots as u32,
            }),
            None => RespPayload::Error(
                "automatic space management is not available in this daemon".into(),
            ),
        },

        // Track Send: `yadorilink receive <transfer_id> [--to <dir>]`.
        Some(ReqPayload::ReceiveTransfer(r)) => {
            let destination_dir =
                if r.destination_dir.is_empty() { None } else { Some(r.destination_dir.as_str()) };
            match context.application.send_transfer.receive(&r.transfer_id, destination_dir).await {
                Ok(outcome) => RespPayload::ReceiveTransfer(ReceiveTransferResponse {
                    destination_dir: outcome.destination_dir.to_string_lossy().into_owned(),
                    files_received: outcome.files_received,
                    bytes_received: outcome.bytes_received,
                }),
                Err(e) => RespPayload::Error(e),
            }
        }

        // `yadorilink trash restore <path>`.
        Some(ReqPayload::RestoreTrash(r)) => {
            match context.queries.linked_path.resolve(&r.absolute_path) {
                Some((group_id, path)) => {
                    match context
                        .application
                        .version_restore
                        .restore_trashed(&group_id, &path)
                        .await
                    {
                        Ok(()) => RespPayload::RestoreTrash(RestoreTrashResponse {}),
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }

        // `yadorilink trash restore --folder <path>`.
        Some(ReqPayload::RestoreTrashOperation(r)) => {
            match context.queries.linked_path.resolve(&r.absolute_path) {
                Some((group_id, path)) => {
                    match context
                        .application
                        .version_restore
                        .restore_trashed_operation(&group_id, &path)
                        .await
                    {
                        Ok(outcome) => {
                            RespPayload::RestoreTrashOperation(RestoreTrashOperationResponse {
                                restored_paths: outcome.restored,
                                failed: outcome
                                    .failed
                                    .into_iter()
                                    .map(|(path, error)| RestoreTrashOperationFailure {
                                        path,
                                        error,
                                    })
                                    .collect(),
                                partial: outcome.partial,
                            })
                        }
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }

        // What a rebootstrap set aside: list it, restore a version as one ordinary write,
        // discard an item.
        Some(ReqPayload::ListPreserved(_)) => match context.application.preserved.list().await {
            Ok(items) => {
                RespPayload::ListPreserved(yadorilink_ipc_proto::daemonctl::ListPreservedResponse {
                    items: items.into_iter().map(preserved_item_to_proto).collect(),
                })
            }
            Err(e) => RespPayload::Error(e.to_string()),
        },
        Some(ReqPayload::RestorePreserved(r)) => {
            match context.application.preserved.restore(r.group_id, r.item_id).await {
                Ok(()) => RespPayload::RestorePreserved(
                    yadorilink_ipc_proto::daemonctl::RestorePreservedResponse {},
                ),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }
        Some(ReqPayload::RetryPreserved(r)) => {
            match context.application.preserved.retry(r.group_id, r.item_id).await {
                Ok(()) => RespPayload::RetryPreserved(
                    yadorilink_ipc_proto::daemonctl::RetryPreservedResponse {},
                ),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }
        Some(ReqPayload::DiscardPreserved(r)) => {
            match context.application.preserved.discard(r.group_id, r.item_id).await {
                Ok(()) => RespPayload::DiscardPreserved(
                    yadorilink_ipc_proto::daemonctl::DiscardPreservedResponse {},
                ),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::ListRetainedOriginals(_)) => {
            match context.application.preserved.list_retained().await {
                Ok(items) => RespPayload::ListRetainedOriginals(
                    yadorilink_ipc_proto::daemonctl::ListRetainedOriginalsResponse {
                        items: items
                            .into_iter()
                            .map(|item| yadorilink_ipc_proto::daemonctl::RetainedOriginal {
                                group_id: item.group_id,
                                group_removed: item.group_removed,
                                path: item.path,
                                recovery_id: item.recovery_id,
                                size: item.size,
                                reachable: item.reachable,
                            })
                            .collect(),
                    },
                ),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }
        Some(ReqPayload::ReleaseRetainedOriginals(r)) => {
            match context.application.preserved.release_retained(r.group_id).await {
                Ok(outcomes) => RespPayload::ReleaseRetainedOriginals(
                    yadorilink_ipc_proto::daemonctl::ReleaseRetainedOriginalsResponse {
                        releases: outcomes
                            .into_iter()
                            .map(|(path, outcome)| retained_release_to_proto(path, outcome))
                            .collect(),
                    },
                ),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::ListProviderPending(r)) => {
            match context.provider_status.pending_items(r.limit) {
                Ok(items) => RespPayload::ListProviderPending(
                    yadorilink_ipc_proto::daemonctl::ListProviderPendingResponse { items },
                ),
                Err(error) => RespPayload::Error(error),
            }
        }

        Some(ReqPayload::Status(_)) => {
            match crate::status_report::build_status(context, Some(&context.config_dir)) {
                Ok(response) => RespPayload::Status(response),
                Err(message) => RespPayload::Error(message),
            }
        }

        Some(ReqPayload::LimitsSet(r)) => {
            match context
                .application
                .governance
                .set_limits(r.upload_bytes_per_sec, r.download_bytes_per_sec)
            {
                Ok(limits) => RespPayload::LimitsSet(LimitsSetResponse {
                    upload_bytes_per_sec: limits.upload_bytes_per_sec,
                    download_bytes_per_sec: limits.download_bytes_per_sec,
                }),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        Some(ReqPayload::LimitsShow(_)) => {
            let config = context.queries.governance.limits();
            RespPayload::LimitsShow(LimitsShowResponse {
                upload_bytes_per_sec: config.upload_limit_bytes_per_sec,
                download_bytes_per_sec: config.download_limit_bytes_per_sec,
            })
        }

        Some(ReqPayload::Hydrate(r)) => match context.queries.linked_path.resolve(&r.absolute_path)
        {
            Some((group_id, path)) => {
                let application = context.application.clone();
                match application.materialization.hydrate(&group_id, &path).await {
                    Ok(downloaded) => RespPayload::Hydrate(HydrateResponse { downloaded }),
                    Err(e) => RespPayload::Error(e.to_string()),
                }
            }
            None if context.queries.linked_path.resolve_provider(&r.absolute_path).is_some() => {
                RespPayload::Error(PROVIDER_DOWNLOAD_HINT.into())
            }
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::Evict(r)) => match context.queries.linked_path.resolve(&r.absolute_path) {
            Some((group_id, path)) => {
                let application = context.application.clone();
                match application.materialization.evict(&group_id, &path) {
                    Ok(outcome) => RespPayload::Evict(EvictResponse {
                        dehydrated: outcome.dehydrated,
                        blocks_reclaimed: outcome.blocks_reclaimed,
                        bytes_reclaimed: outcome.bytes_reclaimed,
                        ..Default::default()
                    }),
                    Err(e) => RespPayload::Error(e.to_string()),
                }
            }
            None => match context.queries.linked_path.resolve_provider(&r.absolute_path) {
                // A file in a provider folder: the host drops the OS copy, and the daemon frees
                // its cached blocks when a full replica holds a durable lease on the version.
                Some((group_id, path)) => {
                    match context.provider_evict.evict(&group_id, &path).await {
                        Ok(outcome) => RespPayload::Evict(EvictResponse {
                            dehydrated: outcome.dehydrated,
                            blocks_reclaimed: outcome.reclaimed.blocks,
                            bytes_reclaimed: outcome.reclaimed.bytes,
                            retained_reason: outcome
                                .retained
                                .map(|why| why.code().to_owned())
                                .unwrap_or_default(),
                        }),
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            },
        },

        // The retention policy is local state keyed by (group, relative path), so a file in a
        // provider folder is as pinnable as one in a plain folder.
        Some(ReqPayload::PinItem(r)) => match resolve_item(context, &r.absolute_path) {
            Some((group_id, path)) => {
                let application = context.application.clone();
                match application.materialization.pin(&group_id, &path).await {
                    Ok(outcome) => RespPayload::PinItem(PinItemResponse {
                        retention: Some(retention_to_proto(outcome.retention)),
                        download_error: outcome.download_error.unwrap_or_default(),
                    }),
                    Err(e) => RespPayload::Error(e.to_string()),
                }
            }
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::UnpinItem(r)) => match resolve_item(context, &r.absolute_path) {
            Some((group_id, path)) => {
                match context.application.materialization.unpin(&group_id, &path) {
                    Ok(retention) => RespPayload::UnpinItem(UnpinItemResponse {
                        retention: Some(retention_to_proto(retention)),
                    }),
                    Err(e) => RespPayload::Error(e.to_string()),
                }
            }
            None => RespPayload::Error("path is not under any linked folder".into()),
        },

        Some(ReqPayload::MaterializationStatus(r)) => {
            // A provider folder's items live in the OS's File Provider location, and the daemon
            // does not track their local state per item: name that, rather than "not linked".
            if context.queries.linked_path.resolve(&r.absolute_path).is_none()
                && context.queries.linked_path.resolve_provider(&r.absolute_path).is_some()
            {
                // On macOS the OS marks a not-downloaded item `dataless` in the file's flags;
                // reading them does not download it.
                match provider_local_state(&r.absolute_path) {
                    Some(local_state) => {
                        let retention = context
                            .queries
                            .linked_path
                            .resolve_provider(&r.absolute_path)
                            .map_or(Ok(None), |(group_id, path)| {
                                context
                                    .application
                                    .materialization
                                    .retention(&group_id, &path)
                                    .map(Some)
                            });
                        match retention {
                            Ok(retention) => {
                                // The operating system downloads and removes downloads in a
                                // provider folder, so the root's eviction gate is open by
                                // construction.
                                let available_actions = item_actions(ItemActionInputs {
                                    path: &r.absolute_path,
                                    local_state: Some(&local_state),
                                    retention,
                                    provider_folder: true,
                                    reclaim_gate_open: true,
                                });
                                RespPayload::MaterializationStatus(MaterializationStatusResponse {
                                    known: true,
                                    local_state: Some(local_state),
                                    retention: retention.map(retention_to_proto),
                                    available_actions,
                                })
                            }
                            Err(e) => RespPayload::Error(e.to_string()),
                        }
                    }
                    None => RespPayload::Error(PROVIDER_LOCAL_STATE_HINT.into()),
                }
            } else {
                match context.queries.linked_path.resolve(&r.absolute_path) {
                    Some((group_id, path)) => {
                        let application = context.application.clone();
                        // The policy is a standing choice, so it is reported for an unindexed
                        // path too; one that cannot be read fails the query rather than
                        // reading as "reclaimable".
                        let materialization = &application.materialization;
                        match materialization.retention(&group_id, &path).and_then(|retention| {
                            materialization.status(&group_id, &path).map(|s| (retention, s))
                        }) {
                            Ok((retention, Some(status))) => {
                                let local_state = local_state_to_proto(status.state);
                                let available_actions = item_actions(ItemActionInputs {
                                    path: &r.absolute_path,
                                    local_state: Some(&local_state),
                                    retention: Some(retention),
                                    provider_folder: false,
                                    reclaim_gate_open: materialization.evict_supported(&group_id),
                                });
                                RespPayload::MaterializationStatus(MaterializationStatusResponse {
                                    known: true,
                                    local_state: Some(local_state),
                                    retention: Some(retention_to_proto(retention)),
                                    available_actions,
                                })
                            }
                            Ok((retention, None)) => {
                                RespPayload::MaterializationStatus(MaterializationStatusResponse {
                                    known: false,
                                    local_state: None,
                                    retention: Some(retention_to_proto(retention)),
                                    available_actions: Vec::new(),
                                })
                            }
                            Err(e) => RespPayload::Error(e.to_string()),
                        }
                    }
                    None => RespPayload::Error("path is not under any linked folder".into()),
                }
            }
        }

        Some(ReqPayload::Shutdown(_)) => {
            tracing::info!("shutdown requested via control socket");
            // route through the same graceful-shutdown path
            // `main.rs` uses for SIGTERM/SIGINT instead of calling
            // `std::process::exit` directly here — that used to skip
            // aborting watcher tasks, draining in-flight broadcasts, and
            // removing socket files. `main.rs`'s top-level `select!` holds
            // the matching receiver and does the actual teardown/exit
            // once it observes this; a `send` error just means every
            // receiver (i.e. `main.rs` itself) is already gone, which
            // only happens if the process is already on its way out.
            context.application.lifecycle.request_shutdown();
            RespPayload::Shutdown(ShutdownResponse {})
        }

        Some(ReqPayload::RequestSafeStop(request)) => {
            let outcome = context
                .application
                .lifecycle
                .request_safe_stop(crate::application::ports::safe_stop_deadline(
                    request.deadline_secs,
                ))
                .await;
            RespPayload::RequestSafeStop(encode_safe_stop(outcome))
        }

        Some(ReqPayload::Identify(_)) => RespPayload::Identify(context.identity.report()),

        Some(ReqPayload::Health(_)) => {
            RespPayload::Health(encode_health(context.queries.health.snapshot()))
        }

        // Dispatch into `reporting_ipc`, which owns the actual
        // translation to/from `yadorilink_reporting`/`crate::reporting`
        // types.
        Some(ReqPayload::ReportingStatus(_)) => RespPayload::ReportingStatus(
            encode_reporting_status(context.queries.reporting.status()),
        ),
        Some(ReqPayload::GenerateUsageReport(_)) => RespPayload::GenerateUsageReport(
            reporting_ipc::generate_usage_report(&*context.application.reporting),
        ),
        Some(ReqPayload::GenerateLastErrorReport(r)) => {
            match reporting_ipc::generate_last_error_report(
                &*context.application.reporting,
                r.report_id,
            ) {
                Ok(resp) => RespPayload::GenerateLastErrorReport(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::ListQueueItems(_)) => match context.queries.reporting.list_queue_items() {
            Ok(items) => RespPayload::ListQueueItems(ListQueueItemsResponse {
                items: items.into_iter().map(encode_queue_item).collect(),
            }),
            Err(e) => RespPayload::Error(e),
        },
        Some(ReqPayload::ShowQueueItem(r)) => {
            match context.queries.reporting.show_queue_item(&r.report_id) {
                Ok(Some(report_json)) => {
                    RespPayload::ShowQueueItem(ShowQueueItemResponse { report_json })
                }
                Ok(None) => {
                    RespPayload::Error(format!("no queued report found with id `{}`", r.report_id))
                }
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::DeleteQueueItem(r)) => {
            match reporting_ipc::delete_queue_item(&*context.application.reporting, &r.report_id) {
                Ok(resp) => RespPayload::DeleteQueueItem(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::FlushQueue(_)) => {
            match reporting_ipc::flush_queue(&*context.application.reporting) {
                Ok(resp) => RespPayload::FlushQueue(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::SubmitReport(r)) => {
            match reporting_ipc::submit_report(&*context.application.reporting, &r.report_json)
                .await
            {
                Ok(resp) => RespPayload::SubmitReport(resp),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::UpdateConsent(r)) => {
            match reporting_ipc::update_consent(&*context.application.reporting, r) {
                Ok(resp) => RespPayload::UpdateConsent(resp),
                Err(e) => RespPayload::Error(e),
            }
        }

        // Dispatch into `context.application.update`/`context.queries.
        // update_status`; `update_ipc` only translates to/from the wire
        // types — mirrors `reporting_ipc`'s own dispatch pattern above.
        Some(ReqPayload::UpdateStatus(_)) => RespPayload::UpdateStatus(
            crate::update_ipc::encode_update_status(context.queries.update_status.snapshot()),
        ),
        Some(ReqPayload::UpdateCheck(_)) => {
            context.application.update.check().await;
            RespPayload::UpdateCheck(crate::update_ipc::encode_check_response(
                context.queries.update_status.snapshot(),
            ))
        }
        Some(ReqPayload::UpdateVersionCheck(r)) => {
            match crate::update_ipc::decode_version_check(r) {
                Ok((kind, version)) => {
                    let outcome = context.application.update.version_check(kind, version).await;
                    RespPayload::UpdateVersionCheck(
                        crate::update_ipc::encode_version_check_response(outcome),
                    )
                }
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::UpdateVerifiedEntry(r)) => {
            match crate::update_ipc::decode_verified_entry(r) {
                Ok((item, phase)) => RespPayload::UpdateVerifiedEntry(
                    crate::update_ipc::encode_verified_entry_response(
                        context.queries.update_status.verified_entry(&item, phase),
                    ),
                ),
                Err(e) => RespPayload::Error(e),
            }
        }
        Some(ReqPayload::UpdateInstall(_)) => {
            RespPayload::UpdateInstall(crate::update_ipc::encode_download_response(
                context.application.update.download_guidance(),
                context.application.update.download_page_url(),
            ))
        }
        Some(ReqPayload::UpdateConfig(r)) => {
            match context.application.update.config(crate::update_ipc::decode_config_request(r)) {
                Ok(policy) => {
                    RespPayload::UpdateConfig(crate::update_ipc::encode_config_response(policy))
                }
                Err(e) => RespPayload::Error(e),
            }
        }

        // Dispatch into `connection_trace`.
        Some(ReqPayload::ListConnectionTraces(r)) => {
            let peer_device_id =
                (!r.peer_device_id.is_empty()).then_some(r.peer_device_id.as_str());
            let traces = context
                .queries
                .diagnostics
                .recent_connection_traces(peer_device_id)
                .into_iter()
                .map(|trace| ConnectionAttemptTrace {
                    peer_device_id: trace.peer_device_id,
                    candidate_source: trace.candidate_source.to_string(),
                    address_class: trace.address_class.to_string(),
                    outcome: trace.outcome.to_string(),
                    latency_ms: trace.latency_ms,
                    failure_category: trace.failure_category,
                    selected: trace.selected,
                    authorization_decision: trace.authorization_decision.to_string(),
                    recorded_at_unix_nanos: trace.recorded_at_unix_nanos,
                })
                .collect();
            RespPayload::ListConnectionTraces(ListConnectionTracesResponse { traces })
        }

        Some(ReqPayload::ConnectivityDoctor(_)) => {
            let categories = context
                .queries
                .diagnostics
                .connectivity_doctor()
                .into_iter()
                .map(|c| ConnectivityDoctorCategory {
                    name: c.name.to_string(),
                    status: c.status.to_string(),
                    detail: c.detail,
                })
                .collect();
            RespPayload::ConnectivityDoctor(ConnectivityDoctorResponse { categories })
        }

        // Dispatch into `diagnostics_ipc`, which owns the actual bundle
        // assembly (from existing status/config/update/recent-error
        // sources) and the bounded-time-budget handling -- mirrors
        // `reporting_ipc`/`update_ipc`'s own dispatch pattern above.
        // Preview and Export both request the exact same daemon-side
        // bundle; only the CLI-side disposition of the result differs.
        Some(ReqPayload::DiagnosticsPreview(_)) => RespPayload::DiagnosticsPreview(
            crate::diagnostics_ipc::build_bundle(&context.queries.diagnostics_bundle).await,
        ),
        Some(ReqPayload::DiagnosticsExport(_)) => RespPayload::DiagnosticsExport(
            crate::diagnostics_ipc::build_bundle(&context.queries.diagnostics_bundle).await,
        ),

        // Dispatch into `gc::run_sweep`, which owns the actual
        // mark-and-sweep, daemon-wide mutual-exclusion, and
        // never-mid-burst logic -- this arm only translates to/from the
        // wire types, mirroring
        // `reporting_ipc`/`update_ipc`/`diagnostics_ipc`'s own dispatch
        // pattern above. `GcTriggerError`'s `Display` (already a clear,
        // actionable message for `AlreadyRunning`/`SyncBurstInProgress`)
        // is surfaced directly as `DaemonControlResponse.error`, same as
        // every other fallible request in this match.
        Some(ReqPayload::Gc(r)) => match context.application.gc.run_sweep(r.dry_run).await {
            Ok(report) => RespPayload::Gc(GcResponse {
                blocks_deleted: report.blocks_deleted,
                bytes_reclaimed: report.bytes_reclaimed,
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // `yadorilink rewind <group> --at <timestamp>`: Folder Rewind's
        // read-only preview. Nothing here mutates anything -- no signed
        // change, no filesystem write, no obligation -- so it goes through
        // `queries`, not `application`, like every other read-only handler.
        Some(ReqPayload::RewindPreview(r)) => {
            match context
                .queries
                .rewind
                .preview(&r.group_id, r.at_unix_nanos, r.include_unchanged)
                .await
            {
                Ok(preview) => RespPayload::RewindPreview(rewind_preview_to_proto(preview)),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        // `yadorilink rewind ... --execute`: answered once the run is
        // recorded (or refused before anything is); the run itself goes on
        // in the background and is read back through `RewindStatus`.
        Some(ReqPayload::RewindExecute(r)) => match <[u8; 32]>::try_from(r.plan_id.as_slice()) {
            Err(_) => RespPayload::Error("plan id must be 32 bytes".to_string()),
            Ok(plan_id) => {
                let request = crate::rewind::RewindExecuteRequest {
                    group_id: r.group_id,
                    target_unix_nanos: r.target_unix_nanos,
                    plan_id: yadorilink_replica_domain::rewind::RewindPlanId(plan_id),
                };
                match context.application.rewind.execute(request).await {
                    Ok(run_id) => RespPayload::RewindExecute(RewindExecuteResponse {
                        outcome: Some(RewindExecuteOutcome::Started(RewindRunStarted { run_id })),
                    }),
                    Err(error) => rewind_execute_refusal(error),
                }
            }
        },

        Some(ReqPayload::RewindStatus(r)) => match context.queries.rewind.status(&r.group_id) {
            Ok(run) => RespPayload::RewindStatus(RewindStatusResponse {
                run: run.map(rewind_run_to_proto),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // Read-only pre-check for `yadorilink share set-storage-mode`: never
        // mutates anything, local or remote (see
        // `DaemonState::another_full_replica_is_ready`'s doc comment). The
        // authoritative, fail-closed re-check happens again in
        // `SetStorageMode` below, right before the local flip commits.
        Some(ReqPayload::CheckFullReplicaHandoffReady(r)) => {
            RespPayload::CheckFullReplicaHandoffReady(CheckFullReplicaHandoffReadyResponse {
                ready: context.queries.handoff_readiness.ready(&r.group_id).await,
            })
        }

        Some(ReqPayload::SetStorageMode(r)) => {
            let application = context.application.clone();
            match application.replica_role.set_storage_mode(&r.group_id, r.on_demand).await {
                // `root_digest` is this device's own locally-computed
                // durability-root digest at commit time -- never sent to or
                // read back from the coordination service (see
                // `HandoffCommitResult`'s doc comment), same as
                // `UnlinkResponse`'s construction above.
                Ok(handoff_result) => RespPayload::SetStorageMode(SetStorageModeResponse {
                    handoff_result: handoff_result.map(|(hr, root_digest)| HandoffResult {
                        target_device_id: hr.target_device_id,
                        root_digest: root_digest.to_vec(),
                        membership_generation: hr.membership_generation,
                        lease_id: hr.lease_id.unwrap_or_default(),
                    }),
                }),
                Err(e) => RespPayload::Error(e),
            }
        }

        // Read-only durability pre-check for `yadorilink share revoke`/
        // `yadorilink device remove`, run by the acting device's own daemon
        // BEFORE the CLI ever calls the coordination plane. See
        // `full_replica_handoff_not_ready_excluding`'s doc comment for the
        // empty-`group_id` "every affected group this daemon can see"
        // semantics and the "partial view, not a distributed proof" caveat.
        Some(ReqPayload::CheckFullReplicaHandoffReadyExcluding(r)) => {
            match context
                .queries
                .handoff_readiness
                .not_ready_excluding(&r.group_id, &r.excluded_device_id)
                .await
            {
                Ok(not_ready_group_ids) => RespPayload::CheckFullReplicaHandoffReadyExcluding(
                    CheckFullReplicaHandoffReadyExcludingResponse {
                        ready: not_ready_group_ids.is_empty(),
                        not_ready_group_ids,
                    },
                ),
                Err(e) => RespPayload::Error(format!(
                    "cannot verify complete-copy durability because the local link table could not be read: {e}"
                )),
            }
        }

        // Durable post-force durability-status latch for the
        // CLI-orchestrated force paths (`durability_force.rs`'s revoke/
        // device-remove) -- see the request's proto doc comment. Persistence
        // failure is returned rather than acknowledging a latch that would
        // disappear on restart.
        Some(ReqPayload::LatchGroupDurabilityUnknown(r)) => {
            match context.application.durability.latch_group_durability_unknown(&r.group_id) {
                Ok(()) => {
                    RespPayload::LatchGroupDurabilityUnknown(LatchGroupDurabilityUnknownResponse {})
                }
                Err(error) => RespPayload::Error(error.to_string()),
            }
        }

        // Full-replica-handoff lease request (target-side) -- see the
        // request's proto doc comment and `DaemonState::request_handoff_
        // lease` for the local-check-then-coordination-plane-request-then-
        // local-record round trip this drives.
        Some(ReqPayload::RequestHandoffLease(r)) => {
            match context.application.handoff.request_lease(&r.group_id).await {
                Some(grant) => RespPayload::RequestHandoffLease(RequestHandoffLeaseResponse {
                    requested: true,
                    lease_id: grant.lease_id,
                    expires_at_unix: grant.expires_at_unix,
                }),
                None => RespPayload::RequestHandoffLease(RequestHandoffLeaseResponse {
                    requested: false,
                    lease_id: String::new(),
                    expires_at_unix: 0,
                }),
            }
        }

        // Removed-device handoff-ticket request (operating-device-side) --
        // see the request's proto doc comment and `DaemonState::obtain_
        // handoff_ticket_from_device` for the peer round trip (offline/
        // unreachable, timeout, and "the device could not attest its own
        // roots" all collapse to `granted = false` here, matching that
        // method's own doc comment).
        Some(ReqPayload::ObtainHandoffTicket(r)) => {
            match context.application.handoff.obtain_ticket(&r.group_id, &r.device_id).await {
                Some(grant) => RespPayload::ObtainHandoffTicket(ObtainHandoffTicketResponse {
                    granted: true,
                    lease_id: grant.lease_id,
                    expires_at_unix: grant.expires_at_unix,
                    target_device_id: grant.target_device_id,
                }),
                None => RespPayload::ObtainHandoffTicket(ObtainHandoffTicketResponse {
                    granted: false,
                    lease_id: String::new(),
                    expires_at_unix: 0,
                    target_device_id: String::new(),
                }),
            }
        }

        Some(ReqPayload::ReleaseHandoffTicket(r)) => {
            context
                .application
                .handoff
                .release_ticket(&r.group_id, &r.device_id, &r.target_device_id, &r.lease_id)
                .await;
            RespPayload::ReleaseHandoffTicket(ReleaseHandoffTicketResponse {})
        }

        Some(ReqPayload::RemoveDeviceCommand(r)) => {
            let application = context.application.clone();
            let result = application
                .membership
                .remove_device(crate::application::RemoveDeviceCommand {
                    device_id: r.device_id,
                    force: r.force,
                })
                .await;
            RespPayload::RemoveDeviceCommand(RemoveDeviceCommandResponse {
                result: Some(match result {
                    Ok(outcome) => remove_device_command_response::Result::Outcome(
                        membership_outcome_to_proto(outcome),
                    ),
                    Err(error) => remove_device_command_response::Result::Error(
                        membership_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::RevokeDeviceCommand(r)) => {
            let application = context.application.clone();
            let result = application
                .membership
                .revoke_device(crate::application::RevokeDeviceCommand {
                    group_id: r.group_id,
                    device_id: r.device_id,
                    force: r.force,
                })
                .await;
            RespPayload::RevokeDeviceCommand(RevokeDeviceCommandResponse {
                result: Some(match result {
                    Ok(outcome) => revoke_device_command_response::Result::Outcome(
                        membership_outcome_to_proto(outcome),
                    ),
                    Err(error) => revoke_device_command_response::Result::Error(
                        membership_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::RevokeEdgeCommand(r)) => {
            let application = context.application.clone();
            let result = application.membership.revoke_edge(r.edge_id, r.force).await;
            RespPayload::RevokeEdgeCommand(RevokeEdgeCommandResponse {
                result: Some(match result {
                    Ok(outcome) => revoke_edge_command_response::Result::Outcome(
                        membership_outcome_to_proto(outcome),
                    ),
                    Err(error) => revoke_edge_command_response::Result::Error(
                        membership_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::DeleteGroupCommand(r)) => {
            let application = context.application.clone();
            let result = application
                .group_admin
                .delete_folder_group(&r.group_id, r.acknowledge_cross_account_members)
                .await;
            RespPayload::DeleteGroupCommand(DeleteGroupCommandResponse {
                result: Some(match result {
                    Ok(()) => delete_group_command_response::Result::Ok(true),
                    Err(error) => delete_group_command_response::Result::Error(error),
                }),
            })
        }

        Some(ReqPayload::CreateAndLinkCommand(r)) => {
            let result = enrollment_commands::create_and_link(
                &context.application,
                enrollment_commands::CreateShare {
                    group_name: r.group_name,
                    local_path: r.local_path,
                    create_local_path_if_missing: r.create_local_path_if_missing,
                    on_demand: r.on_demand,
                    acknowledge_risks: r.acknowledge_risks,
                    provider_display_name: r.provider_display_name,
                    request_token: r.request_token,
                },
            )
            .await;
            RespPayload::CreateAndLinkCommand(CreateAndLinkCommandResponse {
                result: Some(match result {
                    Ok(outcome) => create_and_link_command_response::Result::Outcome(
                        enrollment_outcome_to_proto(context, outcome),
                    ),
                    Err(error) => create_and_link_command_response::Result::Error(
                        enrollment_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::JoinAndLinkCommand(r)) => {
            let result = enrollment_commands::join_and_link(
                &context.application,
                enrollment_commands::JoinGroup {
                    group_id: r.group_id,
                    group_name: r.group_name,
                    local_path: r.local_path,
                    on_demand: r.on_demand,
                    acknowledge_risks: r.acknowledge_risks,
                    provider_display_name: r.provider_display_name,
                    request_token: r.request_token,
                },
            )
            .await;
            RespPayload::JoinAndLinkCommand(JoinAndLinkCommandResponse {
                result: Some(match result {
                    Ok(outcome) => join_and_link_command_response::Result::Outcome(
                        enrollment_outcome_to_proto(context, outcome),
                    ),
                    Err(error) => join_and_link_command_response::Result::Error(
                        enrollment_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::AcceptInviteCommand(r)) => {
            let result = enrollment_commands::accept_invite(
                &context.application,
                enrollment_commands::AcceptInvite {
                    code: r.code,
                    local_path: r.local_path,
                    on_demand: r.on_demand,
                    acknowledge_risks: r.acknowledge_risks,
                    provider_display_name: r.provider_display_name,
                    request_token: r.request_token,
                },
            )
            .await;
            RespPayload::AcceptInviteCommand(AcceptInviteCommandResponse {
                result: Some(match result {
                    Ok(outcome) => accept_invite_command_response::Result::Outcome(
                        enrollment_outcome_to_proto(context, outcome),
                    ),
                    Err(error) => accept_invite_command_response::Result::Error(
                        enrollment_error_to_proto(error),
                    ),
                }),
            })
        }

        Some(ReqPayload::MintInviteCommand(r)) => {
            let application = context.application.clone();
            let role = if r.role.is_empty() { None } else { Some(r.role.as_str()) };
            let ttl_secs = if r.ttl_secs == 0 { None } else { Some(r.ttl_secs) };
            let result = application
                .enrollment
                .mint_invite(&r.group_id, role, ttl_secs, r.requires_approval)
                .await;
            RespPayload::MintInviteCommand(MintInviteCommandResponse {
                result: Some(match result {
                    Ok(invite) => mint_invite_command_response::Result::Outcome(MintedInviteInfo {
                        code: invite.code,
                        invite_id: invite.invite_id,
                        group_id: invite.group_id,
                        role: invite.role,
                        expires_at_unix: invite.expires_at_unix,
                        // Echoed from the coordination plane's own response,
                        // never from the request: what the caller renders must
                        // describe the invite that exists.
                        requires_approval: invite.requires_approval,
                    }),
                    Err(detail) => {
                        mint_invite_command_response::Result::Error(ApplicationCommandError {
                            code: ApplicationErrorCode::CoordinationRejected as i32,
                            message: detail,
                            group_ids: Vec::new(),
                            operation_id: String::new(),
                        })
                    }
                }),
            })
        }

        // `yadorilink recovery list`/`show`.
        Some(ReqPayload::ListRecoveryOperations(_)) => match context.queries.recovery.list() {
            Ok(inv) => RespPayload::ListRecoveryOperations(ListRecoveryOperationsResponse {
                operations: inv
                    .valid
                    .iter()
                    .map(crate::recovery_diagnosis::ipc::recovery_summary_to_proto)
                    .collect(),
                invalid: inv
                    .invalid
                    .iter()
                    .map(crate::recovery_diagnosis::ipc::invalid_recovery_operation_to_proto)
                    .collect(),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },

        // `show` returns a stable diagnosis (local
        // evidence + exactly one remote lookup + a pure recommendation),
        // not just the local journal row. `domain` is required and
        // unambiguous -- see `ShowRecoveryOperationRequest`'s own doc
        // comment in the proto file.
        Some(ReqPayload::ShowRecoveryOperation(r)) => {
            let Some(domain) =
                yadorilink_replica_domain::recovery::RecoveryDomain::try_from_str(&r.domain)
            else {
                return DaemonControlResponse {
                    payload: Some(RespPayload::Error(format!(
                        "unknown recovery domain {:?}; expected one of \"enrollment\", \
                         \"membership\", \"role-loss\"",
                        r.domain
                    ))),
                    daemon_protocol_version:
                        yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
                };
            };
            let key = crate::recovery::RecoveryOperationKey {
                domain,
                operation_id: r.operation_id.clone(),
            };
            match context.queries.recovery.diagnose(&key).await {
                Ok(crate::queries::recovery::DiagnoseOutcome::Diagnosis(outcome)) => {
                    RespPayload::ShowRecoveryOperation(
                        crate::recovery_diagnosis::ipc::stable_diagnosis_outcome_to_proto(&outcome),
                    )
                }
                Ok(crate::queries::recovery::DiagnoseOutcome::CoordinationNotConfigured) => {
                    RespPayload::Error(
                        "coordination-plane address/access token not configured on this device"
                            .to_string(),
                    )
                }
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }

        None => RespPayload::Error("empty request".to_string()),
    };

    DaemonControlResponse {
        payload: Some(payload),
        daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    }
}

// `classify_link_failure`/`enrollment_link_to_request` live in
// `crate::adapters::runtime::enrollment_link::DaemonEnrollmentLinkAdapter`
// -- `application::EnrollmentService` calls `link()` through that port
// instead of a callback into this module.

fn membership_outcome_to_proto(
    outcome: crate::application::ReplicaMembershipOutcome,
) -> ReplicaMembershipCommandOutcome {
    ReplicaMembershipCommandOutcome {
        handoffs: outcome
            .handoffs
            .into_iter()
            .map(|handoff| MembershipHandoffResult {
                group_id: handoff.group_id,
                target_device_id: handoff.target_device_id,
                lease_id: handoff.lease_id,
                membership_generation: handoff.membership_generation,
            })
            .collect(),
        forced_group_ids: outcome.forced_group_ids,
        unknown_scope_operation_id: outcome.unknown_scope_operation_id.unwrap_or_default(),
    }
}

fn membership_error_to_proto(
    error: crate::application::ReplicaMembershipError,
) -> ApplicationCommandError {
    use crate::application::ReplicaMembershipError as Error;
    let (code, group_ids, operation_id) = match &error {
        Error::LocalIdentityUnavailable => {
            (ApplicationErrorCode::LocalIdentityUnavailable, Vec::new(), String::new())
        }
        Error::TargetNotFound => (ApplicationErrorCode::TargetNotFound, Vec::new(), String::new()),
        Error::ReplicaNotReady { group_ids } => {
            (ApplicationErrorCode::ReplicaNotReady, group_ids.clone(), String::new())
        }
        Error::TicketUnavailable { group_id } => {
            (ApplicationErrorCode::TicketUnavailable, vec![group_id.clone()], String::new())
        }
        Error::CoordinationRejected { .. } => {
            (ApplicationErrorCode::CoordinationRejected, Vec::new(), String::new())
        }
        Error::CoordinationAmbiguous { .. } => {
            (ApplicationErrorCode::CoordinationAmbiguous, Vec::new(), String::new())
        }
        Error::DurabilityLatchFailed { group_ids, .. } => {
            (ApplicationErrorCode::DurabilityLatchFailed, group_ids.clone(), String::new())
        }
        Error::RecoveryPending { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryPending, Vec::new(), operation_id.clone())
        }
        Error::CoordinationTransport { .. } => {
            (ApplicationErrorCode::CoordinationTransport, Vec::new(), String::new())
        }
        Error::Persistence(_) => (ApplicationErrorCode::Persistence, Vec::new(), String::new()),
        Error::OperationConflict { operation_id, .. } => {
            (ApplicationErrorCode::OperationConflict, Vec::new(), operation_id.clone())
        }
        Error::RecoveryJournalUnavailable { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryJournalUnavailable, Vec::new(), operation_id.clone())
        }
    };
    ApplicationCommandError {
        code: code as i32,
        message: error.to_string(),
        group_ids,
        operation_id,
    }
}

/// `LinkPreflightRequest`: the same report the share and link commands check before they
/// proceed, for a client to show before it asks for the acknowledgement.
async fn link_preflight(
    context: &crate::control_context::ControlContext,
    local_path: &str,
) -> Result<LinkPreflightResponse, String> {
    let links = context.application.link_lifecycle.clone();
    let requested = std::path::PathBuf::from(local_path);
    // Path resolution touches the filesystem too (a hung network mount), so
    // it runs off the async runtime together with the scan.
    let (resolved, report) = tokio::task::spawn_blocking(move || {
        if std::fs::canonicalize(&requested).is_err() {
            return Err(format!("no such directory: {}", requested.display()));
        }
        links.preflight(&requested).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("link preflight did not complete: {e}"))??;
    Ok(LinkPreflightResponse {
        resolved_path: resolved.to_string_lossy().into_owned(),
        warnings: report.warnings(),
        prohibitions: report.structural_prohibitions(),
    })
}

fn enrollment_outcome_to_proto(
    context: &crate::control_context::ControlContext,
    outcome: crate::application::EnrollmentOutcome,
) -> EnrollmentCommandOutcome {
    EnrollmentCommandOutcome {
        provider_root_id: enrollment_commands::provider_root_id(&context.queries, &outcome),
        operation_id: outcome.operation_id,
        group_id: outcome.group_id,
        local_path: outcome.local_path.to_string_lossy().to_string(),
        awaiting_approval: outcome.awaiting_approval,
        already_linked: outcome.already_linked,
    }
}

fn enrollment_error_to_proto(
    error: crate::application::EnrollmentError,
) -> ApplicationCommandError {
    let (code, operation_id) = enrollment_commands::enrollment_error_code(&error);
    ApplicationCommandError {
        code: code as i32,
        message: error.to_string(),
        group_ids: Vec::new(),
        operation_id,
    }
}

/// A link failure as the typed refusal a client branches on; failures with
/// nothing specific to say stay the plain-text `error`.
fn link_failure_payload(error: &crate::error::DaemonError) -> RespPayload {
    match error.link_refusal() {
        Some(refusal) => RespPayload::CommandError(ApplicationCommandError {
            code: link_refusal_code(refusal) as i32,
            message: error.to_string(),
            group_ids: Vec::new(),
            operation_id: String::new(),
        }),
        None => RespPayload::Error(error.to_string()),
    }
}

/// `LinkRequest` (proto) -> `LinkCommand` (application-owned). All the
/// real orchestration -- duplicate-group prevention, nested-path
/// preflight, the pending-enrollment marker's same-transaction coupling,
/// watcher setup, and rollback-on-setup-failure -- lives in
/// `LinkLifecycleService::link`; this is decode only.
fn decode_link_command(r: LinkRequest) -> Result<crate::application::LinkCommand, String> {
    let pending_enrollment = if r.pending_enrollment_operation_id.is_empty() {
        None
    } else {
        // A request naming a pending enrollment must say which kind. The CLI
        // and the daemon ship as one unit and the protocol version is checked
        // exactly, so an unset or unknown value here is a malformed request,
        // not an older client to accommodate -- and guessing `Create` for a
        // join would attach the link to the wrong enrollment.
        let kind = match PendingEnrollmentKind::try_from(r.pending_enrollment_kind) {
            Ok(PendingEnrollmentKind::Join) => crate::application::EnrollmentKind::Join,
            Ok(PendingEnrollmentKind::Create) => crate::application::EnrollmentKind::Create,
            Ok(PendingEnrollmentKind::Unspecified) | Err(_) => {
                return Err(format!(
                    "link request names pending enrollment {} but no enrollment kind",
                    r.pending_enrollment_operation_id
                ));
            }
        };
        Some(crate::application::PendingEnrollmentLinkCommand {
            operation_id: r.pending_enrollment_operation_id,
            kind,
            device_id: r.pending_enrollment_device_id,
        })
    };
    Ok(crate::application::LinkCommand {
        local_path: r.local_path,
        group_id: r.group_id,
        on_demand: r.on_demand,
        pending_enrollment,
        provider: None,
    })
}

fn retained_release_to_proto(
    path: String,
    outcome: yadorilink_sync_sqlite::native_rebootstrap_retained::RetainedOutcome,
) -> yadorilink_ipc_proto::daemonctl::RetainedRelease {
    use yadorilink_sync_sqlite::native_rebootstrap_retained::RetainedOutcome;
    let (outcome, detail) = match outcome {
        RetainedOutcome::Removed => ("removed", String::new()),
        RetainedOutcome::Gone => ("gone", String::new()),
        RetainedOutcome::StillRetained => ("still_retained", String::new()),
        RetainedOutcome::PreservedChange { removed: true } => ("saved_then_removed", String::new()),
        RetainedOutcome::PreservedChange { removed: false } => {
            ("saved_still_retained", String::new())
        }
        RetainedOutcome::Left(why) => ("left", why),
    };
    yadorilink_ipc_proto::daemonctl::RetainedRelease { path, outcome: outcome.into(), detail }
}

fn preserved_item_to_proto(
    item: crate::preserved_items::PreservedItem,
) -> yadorilink_ipc_proto::daemonctl::PreservedItem {
    use crate::preserved_items::PreservedKind;
    yadorilink_ipc_proto::daemonctl::PreservedItem {
        kind: match item.kind {
            PreservedKind::RemoteOnly => "remote_only",
            PreservedKind::BeyondClosureCutoff => "beyond_closure_cutoff",
            PreservedKind::LateEdit => "late_edit",
            PreservedKind::OwnUnit => "own_unit",
        }
        .to_owned(),
        group_id: item.group_id,
        group_removed: item.group_removed,
        item_id: item.item_id,
        path: item.path,
        paths: item.paths,
        content: item.content,
        size: item.size,
        blocks_held: item.blocks_held,
        blocks_total: item.blocks_total,
        recovery_id: item.recovery_id,
        originals_quarantined: item.originals_quarantined,
    }
}

/// `RewindPreview` (daemon) -> `RewindPreviewResponse` (proto).
///
/// A by-field mapping only: the decisions about what the listing carries --
/// the `unchanged` filter and the byte budgets that keep a response inside
/// one frame -- are made in `crate::rewind::trim_for_wire`, which this is
/// handed the result of.
///
/// `RewindPathAction::Unavailable` maps to a distinct `action` string with
/// its own `unavailable_reason`, never to `"unchanged"`: the whole point of
/// that variant is that "this device cannot answer" reaches the person
/// reading the preview as itself.
fn rewind_preview_to_proto(preview: crate::rewind::RewindPreview) -> RewindPreviewResponse {
    use yadorilink_replica_domain::rewind::RewindPathAction;
    RewindPreviewResponse {
        group_id: preview.group_id,
        target_unix_nanos: preview.target_unix_nanos,
        counts: Some(WireRewindActionCounts {
            create: preview.counts.create,
            delete: preview.counts.delete,
            replace: preview.counts.replace,
            unchanged: preview.counts.unchanged,
            unavailable: preview.counts.unavailable,
        }),
        total_entry_count: preview.total_entry_count,
        total_rename_candidate_count: preview.total_rename_candidate_count,
        listing_truncated: preview.listing_truncated,
        plan_id: preview.plan_id.0.to_vec(),
        unavailable_message: if preview.unavailable.total() == 0 {
            String::new()
        } else {
            preview.unavailable.message()
        },
        entries: preview
            .entries
            .into_iter()
            .map(|entry| {
                let (action, to_version_seq, from_version_seq, unavailable_reason) =
                    match entry.action {
                        RewindPathAction::Create { version_seq, .. } => {
                            ("create", Some(version_seq), None, None)
                        }
                        RewindPathAction::Delete => ("delete", None, None, None),
                        RewindPathAction::Replace { to_version_seq, .. } => {
                            ("replace", Some(to_version_seq), Some(entry.current_version_seq), None)
                        }
                        RewindPathAction::Unchanged => ("unchanged", None, None, None),
                        RewindPathAction::Unavailable { reason } => {
                            ("unavailable", None, None, Some(reason.message().to_string()))
                        }
                    };
                WireRewindPathEntry {
                    path: entry.path,
                    action: action.to_string(),
                    to_version_seq,
                    from_version_seq,
                    unavailable_reason,
                }
            })
            .collect(),
        rename_candidates: preview
            .rename_candidates
            .into_iter()
            .map(|candidate| WireRewindRenameCandidate {
                from_path: candidate.from_path,
                to_path: candidate.to_path,
            })
            .collect(),
    }
}

/// A rewind that did not start, as the wire's outcome. Every case here
/// recorded and changed nothing. A plan that could not be computed at all
/// (a storage failure) is an ordinary error.
fn rewind_execute_refusal(error: crate::rewind::RewindPrepareError) -> RespPayload {
    use crate::rewind::{RewindError, RewindExecuteError, RewindPrepareError as E};
    use yadorilink_ipc_proto::daemonctl::RewindRefusalReason as R;
    let message = error.to_string();
    let refused = |reason: R, count: u64| {
        RespPayload::RewindExecute(RewindExecuteResponse {
            outcome: Some(RewindExecuteOutcome::Refused(RewindRefused {
                reason: reason as i32,
                count,
                message: message.clone(),
            })),
        })
    };
    match error {
        E::Plan(RewindExecuteError::PlanStale { current_plan_id, current_counts }) => {
            RespPayload::RewindExecute(RewindExecuteResponse {
                outcome: Some(RewindExecuteOutcome::PlanStale(RewindPlanStale {
                    current_plan_id: current_plan_id.0.to_vec(),
                    current_counts: Some(WireRewindActionCounts {
                        create: current_counts.create,
                        delete: current_counts.delete,
                        replace: current_counts.replace,
                        unchanged: current_counts.unchanged,
                        unavailable: current_counts.unavailable,
                    }),
                    message: message.clone(),
                })),
            })
        }
        E::Plan(RewindExecuteError::UnavailablePaths(unavailable)) => {
            refused(R::UnavailablePaths, unavailable.total())
        }
        E::Plan(RewindExecuteError::Plan(RewindError::UnknownGroup(_))) => {
            refused(R::UnknownGroup, 0)
        }
        E::RunActive => refused(R::RunActive, 0),
        E::NotAuthorized => refused(R::NotAuthorized, 0),
        E::GroupFrozen => refused(R::GroupFrozen, 0),
        E::InsufficientSpace { missing_bytes } => refused(R::InsufficientSpace, missing_bytes),
        E::FolderSettling { .. } => refused(R::FolderSettling, 0),
        // Not reachable from `start_rewind`, which records the run before
        // gathering content and reports how that ended through the run.
        E::Plan(RewindExecuteError::Plan(RewindError::Failed(_)))
        | E::ContentUnavailable { .. }
        | E::Transient { .. }
        | E::Local { .. } => RespPayload::Error(message),
    }
}

/// A rewind journal row as the wire's `RewindRun`, with the text to show
/// for it (worded in one place, `RewindRun::message`).
fn rewind_run_to_proto(run: yadorilink_replica_domain::rewind::RewindRun) -> WireRewindRun {
    use yadorilink_ipc_proto::daemonctl::{
        RewindFailureKind as WireKind, RewindRunState as WireState,
    };
    use yadorilink_replica_domain::rewind::{RewindFailureKind as Kind, RewindRunState as State};
    let message = run.message();
    let state = match run.state {
        State::Planned => WireState::Planned,
        State::Prefetched => WireState::Prefetched,
        State::Committing => WireState::Committing,
        State::Done => WireState::Done,
        State::NeedsReplan => WireState::NeedsReplan,
        State::Failed => WireState::Failed,
    };
    let failure_kind = match run.failure_kind {
        None => WireKind::Unspecified,
        Some(Kind::ContentUnavailable) => WireKind::ContentUnavailable,
        Some(Kind::Transient) => WireKind::Transient,
        Some(Kind::FolderChanged) => WireKind::FolderChanged,
        Some(Kind::CommitRefused) => WireKind::CommitRefused,
        Some(Kind::Interrupted) => WireKind::Interrupted,
    };
    WireRewindRun {
        run_id: run.run_id,
        group_id: run.group_id,
        target_unix_nanos: run.target_unix_nanos,
        plan_id: run.plan_id.0.to_vec(),
        state: state as i32,
        chunks_total: run.chunks_total,
        chunks_done: run.chunks_done,
        restored: run.restored,
        deleted: run.deleted,
        unavailable_files: run.unavailable_files,
        failure_kind: failure_kind as i32,
        offline_devices: run.offline_devices,
        message,
    }
}

fn version_to_proto(v: yadorilink_replica_domain::session_state::VersionRecord) -> FileVersionInfo {
    FileVersionInfo {
        version_seq: v.version_seq,
        size: v.size as i64,
        mtime_unix_nanos: v.mtime_unix_nanos,
        state: v.state.as_db_str().to_string(),
        origin_device_id: v.origin_device_id.unwrap_or_default(),
        unix_mode: v.unix_mode,
        kind: entry_kind_to_proto(v.record_kind) as i32,
    }
}

fn entry_kind_to_proto(
    kind: yadorilink_replica_domain::file::RecordKind,
) -> yadorilink_ipc_proto::daemonctl::EntryKind {
    use yadorilink_ipc_proto::daemonctl::EntryKind;
    use yadorilink_replica_domain::file::RecordKind;
    match kind {
        RecordKind::File => EntryKind::File,
        RecordKind::Directory => EntryKind::Directory,
        RecordKind::Symlink => EntryKind::Symlink,
    }
}

/// `queries::reporting::ReportingStatusView` -> `ReportingStatusResponse`
/// (proto).
fn encode_reporting_status(
    view: crate::queries::reporting::ReportingStatusView,
) -> ReportingStatusResponse {
    ReportingStatusResponse {
        consent: Some(ReportingConsentState {
            usage_submission_enabled: view.consent.usage_submission_enabled,
            error_submission_enabled: view.consent.error_submission_enabled,
            prompt_to_report_enabled: view.consent.prompt_to_report_enabled,
            queue_retry_enabled: view.consent.queue_retry_enabled,
            anonymous_reporter_id: view.consent.anonymous_reporter_id,
            endpoint_override: view.consent.endpoint_override,
        }),
        queue_count: view.queue_count,
        error_candidate_count: view.error_candidate_count,
    }
}

/// `queries::reporting::QueueItemView` -> `QueueItem` (proto).
fn encode_queue_item(view: crate::queries::reporting::QueueItemView) -> QueueItem {
    QueueItem {
        report_id: view.report_id,
        report_type: match view.report_type {
            yadorilink_reporting::schema::ReportType::Usage => "usage".to_string(),
            yadorilink_reporting::schema::ReportType::Error => "error".to_string(),
        },
        queued_at: view.queued_at,
        size_bytes: view.size_bytes,
        submit_attempts: view.submit_attempts,
    }
}

/// `queries::file_history::TrashedFileView` -> `TrashedFileInfo` (proto).
fn trashed_file_view_to_proto(
    view: crate::queries::file_history::TrashedFileView,
) -> TrashedFileInfo {
    TrashedFileInfo {
        local_path: view.local_path,
        path: view.trashed.path,
        version_seq: view.trashed.version_seq,
        last_known_size: view.trashed.last_known_size as i64,
        origin_device_id: view.trashed.origin_device_id.unwrap_or_default(),
        deleted_at_unix_nanos: view.trashed.deleted_at_unix_nanos,
        kind: entry_kind_to_proto(view.trashed.record_kind) as i32,
        deleted_by_operation: view
            .trashed
            .deleted_by_operation
            .map(|operation| {
                format!("{}:{}", operation.author.as_str(), operation.operation_id.to_hex())
            })
            .unwrap_or_default(),
    }
}

/// `queries::file_history::ConflictedFileView` -> `ConflictedFileInfo` (proto).
async fn resolve_conflict(
    context: &crate::control_context::ControlContext,
    request: &yadorilink_ipc_proto::daemonctl::ResolveConflictRequest,
) -> yadorilink_ipc_proto::daemonctl::ResolveConflictResponse {
    use crate::application::ports::version_restore::{ConflictChoice, ResolveConflictError};
    use yadorilink_ipc_proto::daemonctl::resolve_conflict_response::Result as Outcome;
    use yadorilink_ipc_proto::daemonctl::ConflictResolution;
    let refusal = |code: ApplicationErrorCode, message: String| {
        Outcome::Error(ApplicationCommandError {
            code: code as i32,
            message,
            group_ids: Vec::new(),
            operation_id: String::new(),
        })
    };
    let choice = match ConflictResolution::try_from(request.resolution) {
        Ok(ConflictResolution::KeepThis) => ConflictChoice::KeepThis,
        Ok(ConflictResolution::KeepBoth) => ConflictChoice::KeepBoth,
        Ok(ConflictResolution::Unspecified) | Err(_) => {
            return yadorilink_ipc_proto::daemonctl::ResolveConflictResponse {
                result: Some(refusal(
                    ApplicationErrorCode::Unspecified,
                    "no resolution was chosen".into(),
                )),
            };
        }
    };
    let result = match context.queries.linked_path.resolve(&request.copy_path) {
        None => refusal(
            ApplicationErrorCode::TargetNotFound,
            "path is not under any linked folder".into(),
        ),
        Some((group_id, copy_path)) => {
            match context
                .application
                .version_restore
                .resolve_conflict(&group_id, &copy_path, choice)
                .await
            {
                Ok(kept) => Outcome::KeptPath(kept.to_string_lossy().into_owned()),
                Err(error) => {
                    let code = match &error {
                        ResolveConflictError::NotAConflictCopy(_) => {
                            ApplicationErrorCode::TargetNotFound
                        }
                        ResolveConflictError::NotResolvable(_) => {
                            ApplicationErrorCode::ConflictNotResolvable
                        }
                        ResolveConflictError::UnrecordedLocalChanges(_) => {
                            ApplicationErrorCode::UnrecordedLocalChanges
                        }
                        ResolveConflictError::Failed(_) => ApplicationErrorCode::Unspecified,
                    };
                    refusal(code, error.to_string())
                }
            }
        }
    };
    yadorilink_ipc_proto::daemonctl::ResolveConflictResponse { result: Some(result) }
}

fn conflicted_file_view_to_proto(
    view: crate::queries::file_history::ConflictedFileView,
) -> ConflictedFileInfo {
    ConflictedFileInfo {
        local_path: view.local_path,
        path: view.path,
        size: view.size as i64,
        mtime_unix_nanos: view.mtime_unix_nanos,
        kind: entry_kind_to_proto(view.record_kind) as i32,
        reason: match view.reason {
            crate::queries::file_history::ConflictCopyReason::ConcurrentEdit => {
                yadorilink_ipc_proto::daemonctl::ConflictReason::ConcurrentEdit
            }
            crate::queries::file_history::ConflictCopyReason::FolderAtPath => {
                yadorilink_ipc_proto::daemonctl::ConflictReason::FolderAtPath
            }
        } as i32,
        resolvable: view.resolvable,
        origin_device_id: view.origin_device_id.unwrap_or_default(),
    }
}

/// A file or folder of a linked folder, as `(group_id, path relative to its root)`: a plain
/// folder's, or a File Provider folder's.
fn resolve_item(
    context: &crate::control_context::ControlContext,
    absolute_path: &str,
) -> Option<(String, String)> {
    context
        .queries
        .linked_path
        .resolve(absolute_path)
        .or_else(|| context.queries.linked_path.resolve_provider(absolute_path))
}

/// What `item_actions` reads about one item.
struct ItemActionInputs<'a> {
    path: &'a str,
    local_state: Option<&'a WireLocalState>,
    retention: Option<crate::application::ports::RetentionState>,
    provider_folder: bool,
    reclaim_gate_open: bool,
}

/// The wire form of `file_actions::available_actions` for one item. A path that cannot be
/// inspected is not a file, so Free Up Space is never offered on a guess.
fn item_actions(inputs: ItemActionInputs<'_>) -> Vec<i32> {
    let facts = crate::file_actions::ItemFacts {
        known: inputs.local_state.is_some(),
        current_content_present: inputs.local_state.is_some_and(|s| s.current_content_present),
        in_transition: inputs
            .local_state
            .is_some_and(|s| s.transition() != WireLocalTransition::None),
        is_file: std::fs::symlink_metadata(inputs.path).is_ok_and(|m| m.is_file()),
        provider_folder: inputs.provider_folder,
        reclaim_gate_open: inputs.reclaim_gate_open,
        retention: inputs
            .retention
            .map(|r| crate::file_actions::Retention { pinned: r.pinned, explicit: r.explicit }),
    };
    crate::file_actions::available_actions(&facts).into_iter().map(|a| a as i32).collect()
}

fn retention_to_proto(retention: crate::application::ports::RetentionState) -> WireRetentionState {
    WireRetentionState {
        policy: if retention.pinned {
            RetentionPolicy::Pinned
        } else {
            RetentionPolicy::Reclaimable
        } as i32,
        explicit: retention.explicit,
    }
}

fn local_state_to_proto(state: crate::application::ports::LocalPresence) -> WireLocalState {
    use crate::application::ports::LocalTransition as Daemon;
    WireLocalState {
        local_object_present: state.object_present,
        current_content_present: state.current_content_present,
        transition: match state.transition {
            Daemon::None => WireLocalTransition::None,
            Daemon::Hydrating => WireLocalTransition::Hydrating,
            Daemon::Evicting => WireLocalTransition::Evicting,
        } as i32,
    }
}

/// `HealthView` (`crate::queries::health`, DaemonState-independent) -> the
/// IPC wire type.
pub(crate) fn encode_health(view: crate::queries::health::HealthView) -> HealthResponse {
    let tasks = view
        .tasks
        .into_iter()
        .map(|entry| TaskLiveness { name: entry.name, alive: entry.alive })
        .collect();
    HealthResponse { tasks, connected_peer_count: view.connected_peer_count }
}

// Wire conversions for recovery-journal rows/diagnoses now live in
// crate::recovery_diagnosis::ipc, not here -- see that module's own doc
// comment.

#[cfg(test)]
mod rewind_execute_wire_tests;
#[cfg(test)]
mod rewind_preview_wire_tests;

#[cfg(test)]
mod provider_flags_tests {
    use super::*;
    use yadorilink_ipc_proto::daemonctl::local_state_word;

    #[test]
    fn dataless_flag_reads_as_remote_and_otherwise_as_present() {
        assert_eq!(local_state_word(Some(&local_state_from_flags(SF_DATALESS))), "remote");
        assert_eq!(local_state_word(Some(&local_state_from_flags(0))), "local-current");
        assert_eq!(local_state_word(Some(&local_state_from_flags(0x20))), "local-current");
    }
}

#[cfg(test)]
mod entry_kind_wire_tests;

#[cfg(test)]
mod peer_status_contract_tests;

// --- Control-protocol exact-version enforcement, exercised directly
// against `handle_request` (the actual dispatch a real control-socket
// connection runs through).

#[cfg(test)]
mod migration_safety_tests;

#[cfg(test)]
mod link_risk_tests;

#[cfg(test)]
mod nas_admin_wire_tests;

/// The wire form of a safe-stop answer.
fn encode_safe_stop(
    outcome: crate::application::ports::SafeStopOutcome,
) -> yadorilink_ipc_proto::daemonctl::RequestSafeStopResponse {
    use crate::application::ports::{SafeStopBusy as Reason, SafeStopOutcome};
    use yadorilink_ipc_proto::daemonctl::request_safe_stop_response::Outcome;
    use yadorilink_ipc_proto::daemonctl::{SafeStopBusy, SafeStopBusyReason, SafeStopStopping};
    let outcome = match outcome {
        SafeStopOutcome::Stopping { already_in_progress } => {
            Outcome::Stopping(SafeStopStopping { already_in_progress })
        }
        SafeStopOutcome::Busy { reason, detail, retry_after } => Outcome::Busy(SafeStopBusy {
            reason: match reason {
                Reason::WritesInProgress => SafeStopBusyReason::WritesInProgress,
                Reason::CheckpointFailed => SafeStopBusyReason::CheckpointFailed,
                Reason::AnotherRequestInProgress => SafeStopBusyReason::AnotherRequestInProgress,
            } as i32,
            detail,
            retry_after_secs: u32::try_from(retry_after.as_secs()).unwrap_or(u32::MAX),
        }),
    };
    yadorilink_ipc_proto::daemonctl::RequestSafeStopResponse { outcome: Some(outcome) }
}

#[cfg(test)]
mod identify_wire_tests;

#[cfg(test)]
mod safe_stop_wire_tests;
