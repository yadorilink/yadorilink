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

use crate::application::ports::{LeaseRefusal, SubmitReportError};
use crate::application::replica_role_service::StorageModeError;
use crate::error::NextStep;
use yadorilink_ipc_proto::daemonctl::rewind_execute_response::Outcome as RewindExecuteOutcome;
use yadorilink_ipc_proto::daemonctl::{
    accept_invite_command_response, create_and_link_command_response,
    delete_group_command_response, join_and_link_command_response, mint_invite_command_response,
    remove_device_command_response, revoke_device_command_response, revoke_edge_command_response,
    AcceptInviteCommandResponse, ApplicationCommandError, ApplicationErrorCode,
    CancelSendLinkResponse, CancelTransferResponse, CheckFullReplicaHandoffReadyExcludingResponse,
    CheckFullReplicaHandoffReadyResponse, ConflictedFileInfo, ConnectionAttemptTrace,
    ConnectivityDoctorCategory, ConnectivityDoctorResponse, CreateAndLinkCommandResponse,
    CreateSendLinkResponse, DaemonControlRequest, DaemonControlResponse,
    DeleteGroupCommandResponse, EnrollmentCommandOutcome, EvictResponse, FileVersionInfo,
    GcResponse, GetSpaceManagementResponse, HandoffResult, HealthResponse, HydrateResponse,
    JoinAndLinkCommandResponse, LatchGroupDurabilityUnknownResponse, LimitsSetResponse,
    LimitsShowResponse, LinkPreflightResponse, LinkRequest, LinkResponse, ListActivityResponse,
    ListConflictsResponse, ListConnectionTracesResponse, ListInboxResponse, ListLinksResponse,
    ListQueueItemsResponse, ListRecoveryOperationsResponse, ListSentTransfersResponse,
    ListTrashResponse, ListVersionsResponse, LocalState as WireLocalState,
    LocalTransition as WireLocalTransition, MarkLinkNotRejoinedResponse,
    MaterializationStatusResponse, MintInviteCommandResponse, MintedInviteInfo,
    NasAdminFailureKind, ObtainHandoffTicketResponse, OpenNasAdminResponse, PauseResponse,
    PendingEnrollmentKind, PreviewSpaceReclaimResponse, QueueItem, ReadoptVolumeResponse,
    ReceiveTransferResponse, RedeemSendLinkResponse, RefusedWithNextStep,
    ReleaseHandoffTicketResponse, RemoveDeviceCommandResponse, RemovePendingEnrollmentResponse,
    ReportingConsentState, ReportingStatusResponse, RequestHandoffLeaseResponse,
    RestoreTrashOperationFailure, RestoreTrashOperationResponse, RestoreTrashResponse,
    RestoreVersionResponse, ResumeResponse, RetentionPolicy, RetentionState as WireRetentionState,
    RetryTransferResponse, RevokeDeviceCommandResponse, RevokeEdgeCommandResponse,
    RewindActionCounts as WireRewindActionCounts, RewindExecuteResponse,
    RewindPathEntry as WireRewindPathEntry, RewindPlanStale, RewindPreviewResponse, RewindRefused,
    RewindRenameCandidate as WireRewindRenameCandidate, RewindRun as WireRewindRun,
    RewindRunStarted, RewindStatusResponse, SendFileResponse, SendLinkStatusResponse,
    SetRetentionRuleResponse, SetSpaceManagementResponse, SetStorageModeResponse,
    ShowQueueItemResponse, ShutdownResponse, SpaceReclaimPreviewItem, TaskLiveness,
    TrashedFileInfo, UnlinkResponse,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};

use crate::enrollment_commands::{self, link_refusal_code};
use crate::pause_deadline::PauseDuration;
use crate::reporting_ipc;
use crate::status_report::encode_link_status;
/// A send command's refusal: typed when the failure is one a front end words itself.
fn send_failure_payload(failure: crate::send_transfer::SendFailure) -> RespPayload {
    match failure.code {
        Some(code) => RespPayload::CommandError(ApplicationCommandError {
            code: code as i32,
            message: failure.message,
            group_ids: Vec::new(),
            operation_id: String::new(),
            ..Default::default()
        }),
        None => RespPayload::Error(failure.message),
    }
}

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

    /// Waits until a server spawned on `pipe_name` accepts a connection. A fixed sleep after
    /// spawning cannot promise that on a busy machine (the pipe does not exist until the server
    /// creates its first instance, and is busy while it creates the next).
    pub async fn wait_until_bound(pipe_name: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_name).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "pipe {pipe_name} was not accepting connections within 10s"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

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

    /// How many pipe instances listen at once. A client that finds every instance connected is
    /// refused with `ERROR_PIPE_BUSY` until the daemon creates the next one, so a burst of clients
    /// (an app opens a status watch and several reads together) must not be able to outnumber
    /// the instances for the time that takes. Each listener is its own task, so one slow to
    /// loop back leaves the others accepting.
    const LISTENING_INSTANCES: usize = 4;

    /// `pipe_name` should look like `\\.\pipe\yadorilink-ctl-<user>`.
    ///
    /// Verified against a real Windows 11 VM: an earlier version of this
    /// function created the next pipe instance *after* `connect.await`
    /// returned, leaving a window with zero listening instances between a
    /// client connecting and the replacement instance existing — a second
    /// client connecting concurrently in that window got `ERROR_PIPE_BUSY`
    /// ("All pipe instances are busy"), caught by
    /// `windows_pipe_tests::two_concurrent_clients_are_both_served`.
    /// Each listener now creates its replacement instance right after its
    /// `connect` returns, before the accepted connection is served, and
    /// [`LISTENING_INSTANCES`] listeners run side by side, so at least that
    /// many instances minus one are listening at every moment.
    pub async fn serve(pipe_name: &str, context: Arc<ControlContext>) -> std::io::Result<()> {
        tracing::info!(pipe_name, "control socket listening (named pipe)");
        let connection_slots = Arc::new(Semaphore::new(super::MAX_CONTROL_CONNECTIONS));
        let mut listeners = tokio::task::JoinSet::new();
        listeners.spawn(accept_loop(
            create_first_pipe_server(pipe_name)?,
            pipe_name.to_owned(),
            connection_slots.clone(),
            context.clone(),
        ));
        for _ in 1..LISTENING_INSTANCES {
            listeners.spawn(accept_loop(
                create_next_pipe_server(pipe_name)?,
                pipe_name.to_owned(),
                connection_slots.clone(),
                context.clone(),
            ));
        }
        // A listener only ends on an error, which is the server's.
        match listeners.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(std::io::Error::other(error.to_string())),
            None => Ok(()),
        }
    }

    async fn accept_loop(
        mut server: NamedPipeServer,
        pipe_name: String,
        connection_slots: Arc<Semaphore>,
        context: Arc<ControlContext>,
    ) -> std::io::Result<()> {
        loop {
            server.connect().await?;
            // The replacement listens before the accepted connection is served.
            let next_server = create_next_pipe_server(&pipe_name)?;
            let connected = std::mem::replace(&mut server, next_server);
            // At the cap the accepted client waits here for a slot; the other listeners keep
            // accepting, and no more than MAX_CONTROL_CONNECTIONS connections are served at once.
            let connection_slot = connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("control socket semaphore closed"))?;

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
        ..Default::default()
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

/// The local state a Cloud Files item's attributes show: present on this device unless the platform
/// marks its content as remote. The same reading the provider host and the checked publish use
/// ([`yadorilink_fs_platform::cloud_files`]).
#[cfg(any(windows, test))]
fn local_state_from_attributes(attributes: u32) -> WireLocalState {
    let present = !yadorilink_fs_platform::cloud_files::content_is_remote(attributes);
    WireLocalState {
        local_object_present: present,
        current_content_present: present,
        transition: yadorilink_ipc_proto::daemonctl::LocalTransition::None as i32,
    }
}

/// The state of an item of a Cloud Files folder, read from its attributes (which never recall the
/// content). `None` where the item cannot be read. The caller must know the provider is connected:
/// with it gone the platform hides the bits this reads.
#[cfg(windows)]
fn provider_local_state(absolute_path: &str) -> Option<WireLocalState> {
    yadorilink_fs_platform::cloud_files::attributes_of(std::path::Path::new(absolute_path))
        .map(local_state_from_attributes)
}

#[cfg(not(any(target_vendor = "apple", windows)))]
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

const PROVIDER_DOWNLOAD: &str =
    "this item is in a provider folder: the operating system downloads it when it is opened";

/// A refusal in plain text that carries the next step a front end words for itself.
fn refused(message: &str, step: NextStep) -> RespPayload {
    RespPayload::Refused(RefusedWithNextStep {
        message: message.to_owned(),
        next_step: wire_step(step) as i32,
    })
}

/// The typed refusal of a command the coordination service refused until the Terms are accepted.
fn terms_consent_response(error: impl std::fmt::Display) -> RespPayload {
    RespPayload::CommandError(ApplicationCommandError {
        code: ApplicationErrorCode::TermsConsentRequired as i32,
        message: error.to_string(),
        group_ids: Vec::new(),
        operation_id: String::new(),
        ..Default::default()
    })
}

fn wire_step(step: NextStep) -> yadorilink_ipc_proto::daemonctl::NextStep {
    use yadorilink_ipc_proto::daemonctl::NextStep as Wire;
    match step {
        NextStep::CheckLinkStatus => Wire::CheckLinkStatus,
        NextStep::CheckLinkList => Wire::CheckLinkList,
        NextStep::KeepItemOnDevice => Wire::KeepItemOnDevice,
        NextStep::ShowProviderLocalState => Wire::ShowProviderLocalState,
        NextStep::CreateProviderFolder => Wire::CreateProviderFolder,
        NextStep::EnableReportSubmission => Wire::EnableReportSubmission,
        NextStep::RetryStorageModeChange => Wire::RetryStorageModeChange,
    }
}

/// The refusal for a request whose protocol version is not exactly this daemon's.
///
/// This repository has not shipped a public release yet, so the CLI, desktop app, and daemon are
/// always built and deployed as one unit — a genuine version skew has no supported recovery path
/// and must fail clearly before touching any daemon state, not be executed anyway and only
/// surface as a mismatch once the CLI inspects the response. A request that leaves
/// `protocol_version` unset decodes as 0, which is `!= CONTROL_PROTOCOL_VERSION` and thus
/// rejected the same as any other mismatch.
fn refuse_version_skew(client_version: u32) -> Option<DaemonControlResponse> {
    use yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION;
    if client_version == CONTROL_PROTOCOL_VERSION {
        return None;
    }
    let message = if client_version > CONTROL_PROTOCOL_VERSION {
        format!(
            "this daemon (protocol version {CONTROL_PROTOCOL_VERSION}) does not support this \
             request (client is protocol version {client_version}); upgrade the daemon and try \
             again"
        )
    } else {
        format!(
            "this daemon requires exactly protocol version {CONTROL_PROTOCOL_VERSION} (client is \
             protocol version {client_version}); this is a pre-release build with no \
             client/daemon compatibility path — run matching CLI and daemon binaries"
        )
    };
    Some(DaemonControlResponse {
        payload: Some(RespPayload::Error(message)),
        daemon_protocol_version: CONTROL_PROTOCOL_VERSION,
    })
}

/// The dispatch table over every `DaemonControlRequest` payload variant: each arm is one call
/// into the verb's family module. It stays one exhaustive `match`, so the compiler proves every
/// wire verb is handled; a catch-all arm would let a new verb compile unhandled.
async fn handle_request(
    context: &crate::control_context::ControlContext,
    req: DaemonControlRequest,
) -> DaemonControlResponse {
    if let Some(refusal) = refuse_version_skew(req.protocol_version) {
        return refusal;
    }
    let changes_state = !is_polled_read(&req.payload);
    let payload = match req.payload {
        Some(ReqPayload::Link(r)) => links::link(context, r).await,

        Some(ReqPayload::OpenNasAdmin(_)) => links::open_nas_admin(context).await,
        Some(ReqPayload::LinkPreflight(r)) => links::link_preflight(context, r).await,

        Some(ReqPayload::Unlink(r)) => links::unlink(context, r).await,

        Some(ReqPayload::ReadoptVolume(r)) => links::readopt_volume(context, r).await,

        Some(ReqPayload::MarkLinkNotRejoined(r)) => links::mark_link_not_rejoined(context, r).await,

        Some(ReqPayload::ListLinks(_)) => links::list_links(context).await,

        Some(ReqPayload::Pause(r)) => links::pause(context, r).await,

        Some(ReqPayload::Resume(r)) => links::resume(context, r).await,

        Some(ReqPayload::RemovePendingEnrollment(r)) => {
            links::remove_pending_enrollment(context, r).await
        }

        Some(ReqPayload::ListVersions(r)) => history::list_versions(context, r).await,

        Some(ReqPayload::RestoreVersion(r)) => history::restore_version(context, r).await,

        Some(ReqPayload::ListTrash(_)) => history::list_trash(context).await,

        Some(ReqPayload::ListConflicts(_)) => history::list_conflicts(context).await,

        Some(ReqPayload::ListActivity(r)) => history::list_activity(context, r).await,

        Some(ReqPayload::ResolveConflict(r)) => history::resolve_conflict(context, r).await,

        Some(ReqPayload::SendFile(r)) => send::send_file(context, r).await,

        Some(ReqPayload::CreateSendLink(r)) => send::create_send_link(context, r).await,
        Some(ReqPayload::RedeemSendLink(r)) => send::redeem_send_link(context, r).await,
        Some(ReqPayload::CancelSendLink(r)) => send::cancel_send_link(context, r).await,
        Some(ReqPayload::PreviewSendLink(r)) => send::preview_send_link(context, r).await,
        Some(ReqPayload::SendLinkStatus(r)) => send::send_link_status(context, r).await,

        Some(ReqPayload::ListInbox(_)) => send::list_inbox(context).await,

        Some(ReqPayload::ListSentTransfers(_)) => send::list_sent_transfers(context).await,
        Some(ReqPayload::CancelTransfer(r)) => send::cancel_transfer(context, r).await,
        Some(ReqPayload::RetryTransfer(r)) => send::retry_transfer(context, r).await,

        Some(ReqPayload::GetNetworkPolicy(_)) => network::get_network_policy(context).await,
        Some(ReqPayload::SetSyncOnMetered(r)) => network::set_sync_on_metered(context, r).await,
        Some(ReqPayload::ReportNetworkCost(r)) => network::report_network_cost(context, r).await,
        Some(ReqPayload::IgnoreRulesGet(r)) => ignore_rules::ignore_rules_get(context, r).await,
        Some(ReqPayload::IgnoreRulesSet(r)) => ignore_rules::ignore_rules_set(context, r).await,
        Some(ReqPayload::GetSpaceManagement(_)) => space::get_space_management(context).await,
        Some(ReqPayload::SetSpaceManagement(r)) => space::set_space_management(context, r).await,
        Some(ReqPayload::PreviewSpaceReclaim(_)) => space::preview_space_reclaim(context).await,
        Some(ReqPayload::ReceiveTransfer(r)) => send::receive_transfer(context, r).await,
        Some(ReqPayload::RestoreTrash(r)) => history::restore_trash(context, r).await,

        Some(ReqPayload::RestoreTrashOperation(r)) => {
            history::restore_trash_operation(context, r).await
        }

        Some(ReqPayload::ListPreserved(_)) => history::list_preserved(context).await,
        Some(ReqPayload::RestorePreserved(r)) => history::restore_preserved(context, r).await,
        Some(ReqPayload::RetryPreserved(r)) => history::retry_preserved(context, r).await,
        Some(ReqPayload::DiscardPreserved(r)) => history::discard_preserved(context, r).await,

        Some(ReqPayload::ListRetainedOriginals(_)) => {
            history::list_retained_originals(context).await
        }
        Some(ReqPayload::ReleaseRetainedOriginals(r)) => {
            history::release_retained_originals(context, r).await
        }

        Some(ReqPayload::ListProviderPending(r)) => {
            history::list_provider_pending(context, r).await
        }

        Some(ReqPayload::Status(_)) => daemon::status(context).await,

        Some(ReqPayload::LimitsSet(r)) => space::limits_set(context, r).await,

        Some(ReqPayload::LimitsShow(_)) => space::limits_show(context).await,

        Some(ReqPayload::ListAccountDevices(_)) => {
            membership_commands::list_account_devices(context).await
        }

        Some(ReqPayload::ListShareEdges(_)) => membership_commands::list_share_edges(context).await,

        Some(ReqPayload::ResolveFolder(r)) => items::resolve_folder(context, r).await,
        Some(ReqPayload::Hydrate(r)) => items::hydrate(context, r).await,

        Some(ReqPayload::Evict(r)) => items::evict(context, r).await,

        Some(ReqPayload::SetRetentionRule(r)) => items::set_retention_rule(context, r).await,

        Some(ReqPayload::MaterializationStatus(r)) => {
            items::materialization_status(context, r).await
        }

        Some(ReqPayload::Shutdown(request)) => daemon::shutdown(context, request).await,

        Some(ReqPayload::RequestSafeStop(request)) => {
            daemon::request_safe_stop(context, request).await
        }

        Some(ReqPayload::Identify(_)) => daemon::identify(context).await,

        Some(ReqPayload::Health(_)) => daemon::health(context).await,

        Some(ReqPayload::ReportingStatus(_)) => reporting::reporting_status(context).await,
        Some(ReqPayload::GenerateUsageReport(_)) => reporting::generate_usage_report(context).await,
        Some(ReqPayload::GenerateLastErrorReport(r)) => {
            reporting::generate_last_error_report(context, r).await
        }
        Some(ReqPayload::ListQueueItems(_)) => reporting::list_queue_items(context).await,
        Some(ReqPayload::ShowQueueItem(r)) => reporting::show_queue_item(context, r).await,
        Some(ReqPayload::DeleteQueueItem(r)) => reporting::delete_queue_item(context, r).await,
        Some(ReqPayload::FlushQueue(_)) => reporting::flush_queue(context).await,
        Some(ReqPayload::SubmitReport(r)) => reporting::submit_report(context, r).await,
        Some(ReqPayload::UpdateConsent(r)) => reporting::update_consent(context, r).await,

        Some(ReqPayload::UpdateStatus(_)) => update::update_status(context).await,
        Some(ReqPayload::UpdateCheck(_)) => update::update_check(context).await,
        Some(ReqPayload::UpdateVersionCheck(r)) => update::update_version_check(context, r).await,
        Some(ReqPayload::UpdateVerifiedEntry(r)) => update::update_verified_entry(context, r).await,
        Some(ReqPayload::UpdateInstall(_)) => update::update_install(context).await,
        Some(ReqPayload::UpdateConfig(r)) => update::update_config(context, r).await,

        Some(ReqPayload::ListConnectionTraces(r)) => {
            reporting::list_connection_traces(context, r).await
        }

        Some(ReqPayload::ConnectivityDoctor(_)) => reporting::connectivity_doctor(context).await,

        Some(ReqPayload::DiagnosticsPreview(_)) => reporting::diagnostics_preview(context).await,
        Some(ReqPayload::DiagnosticsExport(_)) => reporting::diagnostics_export(context).await,

        Some(ReqPayload::Gc(r)) => daemon::gc(context, r).await,

        Some(ReqPayload::RewindPreview(r)) => rewind::rewind_preview(context, r).await,

        Some(ReqPayload::RewindExecute(r)) => rewind::rewind_execute(context, r).await,

        Some(ReqPayload::RewindStatus(r)) => rewind::rewind_status(context, r).await,

        Some(ReqPayload::CheckFullReplicaHandoffReady(r)) => {
            handoff::check_full_replica_handoff_ready(context, r).await
        }

        Some(ReqPayload::SetStorageMode(r)) => handoff::set_storage_mode(context, r).await,

        Some(ReqPayload::CheckFullReplicaHandoffReadyExcluding(r)) => {
            handoff::check_full_replica_handoff_ready_excluding(context, r).await
        }

        Some(ReqPayload::LatchGroupDurabilityUnknown(r)) => {
            handoff::latch_group_durability_unknown(context, r).await
        }

        Some(ReqPayload::RequestHandoffLease(r)) => {
            handoff::request_handoff_lease(context, r).await
        }

        Some(ReqPayload::ObtainHandoffTicket(r)) => {
            handoff::obtain_handoff_ticket(context, r).await
        }

        Some(ReqPayload::ReleaseHandoffTicket(r)) => {
            handoff::release_handoff_ticket(context, r).await
        }

        Some(ReqPayload::RemoveDeviceCommand(r)) => {
            membership_commands::remove_device_command(context, r).await
        }

        Some(ReqPayload::RevokeDeviceCommand(r)) => {
            membership_commands::revoke_device_command(context, r).await
        }

        Some(ReqPayload::RevokeEdgeCommand(r)) => {
            membership_commands::revoke_edge_command(context, r).await
        }

        Some(ReqPayload::DeleteGroupCommand(r)) => {
            membership_commands::delete_group_command(context, r).await
        }

        Some(ReqPayload::CreateAndLinkCommand(r)) => {
            membership_commands::create_and_link_command(context, r).await
        }

        Some(ReqPayload::JoinAndLinkCommand(r)) => {
            membership_commands::join_and_link_command(context, r).await
        }

        Some(ReqPayload::AcceptInviteCommand(r)) => {
            membership_commands::accept_invite_command(context, r).await
        }

        Some(ReqPayload::MintInviteCommand(r)) => {
            membership_commands::mint_invite_command(context, r).await
        }

        Some(ReqPayload::ListRecoveryOperations(_)) => {
            recovery::list_recovery_operations(context).await
        }

        Some(ReqPayload::ShowRecoveryOperation(r)) => {
            recovery::show_recovery_operation(context, r).await
        }

        None => RespPayload::Error("empty request".to_string()),
    };

    // Every request counts as changing state unless it is one of the reads shells poll: a poll
    // that bumped the epoch would make the next status wait for a rebuild.
    if changes_state {
        context.status_hub.command_completed();
    }
    DaemonControlResponse {
        payload: Some(payload),
        daemon_protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
    }
}

/// The requests that only read, and that shells ask repeatedly. Anything not listed is treated as
/// changing state (see `StatusHub`), which costs at worst one extra build.
fn is_polled_read(payload: &Option<ReqPayload>) -> bool {
    matches!(
        payload,
        Some(
            ReqPayload::Status(_)
                | ReqPayload::ListLinks(_)
                | ReqPayload::Health(_)
                | ReqPayload::Identify(_)
                | ReqPayload::ListConflicts(_)
                | ReqPayload::ListAccountDevices(_)
                | ReqPayload::ListTrash(_)
                | ReqPayload::ListPreserved(_)
                | ReqPayload::ListShareEdges(_)
        )
    )
}

#[cfg(test)]
mod polled_read_tests {
    use super::*;
    use yadorilink_ipc_proto::daemonctl::{
        ListAccountDevicesRequest, ListPreservedRequest, ListTrashRequest, PauseRequest,
    };

    /// The web page asks for these on load and after actions; a read must not
    /// bump the status epoch (it would rebuild the status for every shell).
    #[test]
    fn the_dashboard_lists_are_polled_reads_and_a_command_is_not() {
        assert!(is_polled_read(&Some(ReqPayload::ListAccountDevices(
            ListAccountDevicesRequest::default()
        ))));
        assert!(is_polled_read(&Some(ReqPayload::ListTrash(ListTrashRequest::default()))));
        assert!(is_polled_read(&Some(ReqPayload::ListPreserved(ListPreservedRequest::default()))));
        assert!(!is_polled_read(&Some(ReqPayload::Pause(PauseRequest::default()))));
    }
}

// `classify_link_failure`/`enrollment_link_to_request` live in
// `crate::adapters::runtime::enrollment_link::DaemonEnrollmentLinkAdapter`
// -- `application::EnrollmentService` calls `link()` through that port
// instead of a callback into this module.

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
    let (drive_reason, file_system) = enrollment_commands::enrollment_drive_detail(&error);
    ApplicationCommandError {
        code: code as i32,
        message: error.to_string(),
        group_ids: Vec::new(),
        operation_id,
        drive_reason,
        file_system,
    }
}

/// A link failure as the typed refusal a client branches on; failures with
/// nothing specific to say stay the plain-text `error`.
fn link_failure_payload(error: &crate::error::DaemonError) -> RespPayload {
    match error.link_refusal() {
        Some(refusal) => {
            let (drive_reason, file_system) = enrollment_commands::drive_detail(Some(&refusal));
            RespPayload::CommandError(ApplicationCommandError {
                code: link_refusal_code(&refusal) as i32,
                message: error.to_string(),
                group_ids: Vec::new(),
                operation_id: String::new(),
                drive_reason,
                file_system,
            })
        }
        None => match error {
            crate::error::DaemonError::Advised { message, step } => refused(message, *step),
            _ => RespPayload::Error(error.to_string()),
        },
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

fn not_kept_to_proto(
    span: yadorilink_sync_sqlite::history_freed::FreedSpan,
) -> yadorilink_ipc_proto::daemonctl::NotKeptSpan {
    yadorilink_ipc_proto::daemonctl::NotKeptSpan {
        from_unix_nanos: span.from_unix_nanos,
        to_unix_nanos: span.to_unix_nanos,
        from_seq: span.from_seq,
        to_seq: span.to_seq,
        reason: span.reason.as_str().to_string(),
    }
}

fn version_to_proto(view: crate::queries::file_history::VersionView) -> FileVersionInfo {
    use crate::queries::file_history::VersionContent;
    use yadorilink_ipc_proto::daemonctl::VersionContent as Wire;
    let v = view.record;
    FileVersionInfo {
        content: match view.content {
            VersionContent::NotApplicable => Wire::NotApplicable,
            VersionContent::Kept => Wire::Kept,
            VersionContent::NotKept => Wire::NotKept,
        } as i32,
        version_seq: v.version_seq,
        size: v.size as i64,
        mtime_unix_nanos: v.mtime_unix_nanos,
        state: v.state.as_db_str().to_string(),
        origin_device_id: v.origin_device_id.unwrap_or_default(),
        exec: v.exec,
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
            ..Default::default()
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
    let result = match resolve_item(context, &request.copy_path) {
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
    context.queries.linked_path.resolve_any(absolute_path)
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
        is_folder: std::fs::symlink_metadata(inputs.path).is_ok_and(|m| m.is_dir()),
        provider_folder: inputs.provider_folder,
        reclaim_gate_open: inputs.reclaim_gate_open,
        retention: inputs.retention.map(|r| crate::file_actions::Retention {
            pinned: r.pinned,
            online_only: r.online_only,
            explicit: r.explicit,
        }),
    };
    crate::file_actions::available_actions(&facts).into_iter().map(|a| a as i32).collect()
}

fn retention_to_proto(retention: crate::application::ports::RetentionState) -> WireRetentionState {
    WireRetentionState {
        policy: if retention.pinned {
            RetentionPolicy::Pinned
        } else if retention.online_only {
            RetentionPolicy::OnlineOnly
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

mod daemon;
mod handoff;
mod history;
mod ignore_rules;
mod items;
mod links;
mod membership_commands;
mod network;
mod recovery;
mod reporting;
mod rewind;
mod send;
mod space;
mod update;

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

    /// The real reader, on a real file: an ordinary file carries no recall mark, so it reads as
    /// present, and a name that does not exist reads as unknown rather than as anything.
    #[cfg(windows)]
    #[test]
    fn the_windows_reader_gives_a_real_file_a_state_and_a_missing_one_none() {
        let dir = std::env::temp_dir().join(format!("yl-localstate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let state = provider_local_state(file.to_str().unwrap()).expect("a state");
        assert_eq!(local_state_word(Some(&state)), "local-current");
        assert!(provider_local_state(dir.join("missing").to_str().unwrap()).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cloud_files_item_reads_as_remote_when_any_recall_mark_is_set_and_otherwise_as_present() {
        use yadorilink_fs_platform::cloud_files::{
            OFFLINE, PINNED, RECALL_ON_DATA_ACCESS, RECALL_ON_OPEN, REPARSE_POINT,
        };
        for remote in [
            OFFLINE,
            RECALL_ON_OPEN,
            RECALL_ON_DATA_ACCESS,
            0x20 | RECALL_ON_DATA_ACCESS | REPARSE_POINT,
        ] {
            assert_eq!(
                local_state_word(Some(&local_state_from_attributes(remote))),
                "remote",
                "{remote:#x}"
            );
        }
        // A hydrated placeholder (reparse point, no recall mark) and a pinned one are on this PC.
        for local in [0x20, 0x20 | REPARSE_POINT, 0x20 | PINNED] {
            assert_eq!(
                local_state_word(Some(&local_state_from_attributes(local))),
                "local-current",
                "{local:#x}"
            );
        }
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
mod resolve_folder_tests;

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

#[cfg(test)]
mod network_wire_tests;

#[cfg(test)]
mod unsupported_drive_wire_tests {
    use super::*;
    use yadorilink_fs_platform::durable_dir::{DriveReason, UnsupportedDrive};
    use yadorilink_ipc_proto::daemonctl::UnsupportedDriveReason;

    /// A link refused because of its drive goes over the socket as its own typed code with the
    /// machine reason and the file system, plus the English sentence for the command line.
    #[test]
    fn a_link_refused_for_its_drive_carries_the_reason_key_and_the_sentence() {
        let error = crate::error::DaemonError::UnsupportedDrive(UnsupportedDrive {
            reason: DriveReason::Refs,
            file_system: "ReFS".into(),
        });
        let RespPayload::CommandError(wire) = link_failure_payload(&error) else {
            panic!("a typed command error");
        };
        assert_eq!(wire.code, ApplicationErrorCode::UnsupportedDrive as i32);
        assert_eq!(wire.drive_reason, UnsupportedDriveReason::Refs as i32);
        assert_eq!(wire.file_system, "ReFS");
        assert!(
            wire.message.contains("ReFS / Dev Drive") && wire.message.contains("NTFS"),
            "{}",
            wire.message
        );
    }
}

#[cfg(test)]
mod unpublished_edits_wire_tests {
    use std::sync::Arc;

    use crate::daemon_state::DaemonState;
    use crate::replica_coordinator::ReplicaCoordinator;
    use crate::runtime_telemetry::UnpublishedReason;

    /// Status carries the saved edits that are not published, by why: the service did not answer
    /// (a publish attempt that got no answer, or a disk edit journaled while the group's policy is
    /// not available) or this device may no longer publish.
    #[tokio::test]
    async fn status_counts_the_saved_edits_by_why_they_are_not_published() {
        let config = tempfile::tempdir().unwrap();
        let store = Arc::new(
            yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
                .unwrap(),
        );
        let state = DaemonState::new_in(
            config.path().to_path_buf(),
            "device-a".into(),
            Arc::new(ReplicaCoordinator::open_in_memory().unwrap()),
            store,
        );
        let folder = tempfile::tempdir().unwrap();
        let _canonical =
            crate::test_support::sync_stack_fixture::link_folder(&state, folder.path());
        let context = crate::control_context::ControlContext::from_state(state.clone());
        let status = |context: &crate::control_context::ControlContext| {
            crate::status_report::build_status(&context.status_sources).unwrap()
        };
        state.telemetry.pretend_started_ago_for_tests(std::time::Duration::from_secs(120));
        let none = status(&context);
        assert_eq!(
            (none.unpublished_edits_service_unreachable, none.unpublished_edits_not_authorized),
            (0, 0)
        );

        // A disk edit journaled while the group's policy is not available.
        state
            .replica_coordinator
            .dirty_path_repository()
            .record_dirty_path(
                crate::native_test_support::GROUP,
                "a.txt",
                "created_or_modified",
                1,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // A publish attempt that got no answer.
        state.telemetry.set_unpublished(
            crate::native_test_support::GROUP,
            UnpublishedReason::ServiceUnreachable,
            2,
        );
        let waiting = status(&context);
        assert_eq!(waiting.unpublished_edits_service_unreachable, 3, "2 pending + 1 journaled");
        assert_eq!(waiting.unpublished_edits_not_authorized, 0);

        // The service answered that this device may not publish.
        state.telemetry.set_unpublished(
            crate::native_test_support::GROUP,
            UnpublishedReason::NotAuthorized,
            2,
        );
        let refused = status(&context);
        assert_eq!(refused.unpublished_edits_not_authorized, 2);
        assert_eq!(refused.unpublished_edits_service_unreachable, 1, "only the journaled edit");

        // The service answered but would not publish (the Terms, a refused credential).
        state.telemetry.set_unpublished(
            crate::native_test_support::GROUP,
            UnpublishedReason::Rejected,
            4,
        );
        let rejected = status(&context);
        assert_eq!(rejected.unpublished_edits_rejected, 4);
        assert_eq!(rejected.unpublished_edits_not_authorized, 0);

        // A group that is no longer linked has nothing waiting to publish, whatever its last
        // attempt said.
        state.telemetry.set_unpublished("gone-group", UnpublishedReason::ServiceUnreachable, 5);
        assert_eq!(
            status(&context).unpublished_edits_service_unreachable,
            1,
            "only the journaled edit"
        );

        state.telemetry.clear_unpublished(crate::native_test_support::GROUP);
        assert_eq!(status(&context).unpublished_edits_not_authorized, 0);
    }
}
