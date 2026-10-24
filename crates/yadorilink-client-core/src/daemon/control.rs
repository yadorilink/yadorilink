//! The one client for the daemon's local control socket: a Unix domain
//! socket on macOS/Linux, a named pipe on Windows. Every front end sends its
//! daemon requests through [`send`].

use std::time::Duration;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, DaemonControlResponse, IdentifyRequest, IdentifyResponse,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::release_descriptor::{self, DescriptorProblem, ReleaseDescriptor};

use crate::error::{CoreError, EngineMismatchDetail, EngineMismatchDirection, EngineMismatchKind};

/// Sends one request and returns the daemon's response. A plain
/// `RespPayload::Error` answer is returned as [`CoreError::DaemonRejected`]
/// and a different protocol generation as
/// [`CoreError::DaemonProtocolMismatch`], so an `Ok` response never carries
/// either and callers match only the payload they expect.
///
/// A daemon that does not accept within [`CONNECT_BUDGET`], or does not
/// answer a quick request within [`QUICK_REPLY_BUDGET`], is returned as
/// [`CoreError::DaemonUnresponsive`]; see [`reply_budget`] for which
/// requests have no reply deadline.
pub async fn send(payload: ReqPayload) -> Result<DaemonControlResponse, CoreError> {
    let mut stream = tokio::time::timeout(CONNECT_BUDGET, connect())
        .await
        .map_err(|_| CoreError::DaemonUnresponsive)?
        .map_err(|_| CoreError::DaemonNotRunning)?;
    ensure_paired(&mut stream, &payload).await?;
    exchange(stream, payload).await
}

/// The control connection, as [`open_held`] hands it back.
#[cfg(unix)]
pub(crate) type ControlStream = tokio::net::UnixStream;
#[cfg(windows)]
pub(crate) type ControlStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// Sends a request whose connection outlives its response, and returns the
/// response with the connection still open. The daemon holds what the
/// request opened for exactly as long as that connection stays open, so
/// dropping it is how the caller lets go. The answer is due within
/// [`HELD_REPLY_BUDGET`].
pub(crate) async fn open_held(
    payload: ReqPayload,
) -> Result<(DaemonControlResponse, ControlStream), CoreError> {
    let mut stream = tokio::time::timeout(CONNECT_BUDGET, connect())
        .await
        .map_err(|_| CoreError::DaemonUnresponsive)?
        .map_err(|_| CoreError::DaemonNotRunning)?;
    ensure_paired(&mut stream, &payload).await?;
    let response = tokio::time::timeout(HELD_REPLY_BUDGET, round_trip(&mut stream, payload))
        .await
        .map_err(|_| CoreError::DaemonUnresponsive)??;
    Ok((response, stream))
}

/// Requests that change nothing, so they still work when this program and the daemon come from
/// different releases (that is how the mismatch is made visible). Everything not listed here is
/// state-changing, or unknown, and is held back by [`ensure_paired`]: fail closed.
fn is_read_only(payload: &ReqPayload) -> bool {
    matches!(
        payload,
        ReqPayload::Identify(_)
            | ReqPayload::Status(_)
            | ReqPayload::Health(_)
            | ReqPayload::ListLinks(_)
            | ReqPayload::ReportingStatus(_)
            | ReqPayload::ListQueueItems(_)
            | ReqPayload::ShowQueueItem(_)
            | ReqPayload::LimitsShow(_)
            | ReqPayload::ListVersions(_)
            | ReqPayload::ListTrash(_)
            | ReqPayload::UpdateStatus(_)
            | ReqPayload::ListConnectionTraces(_)
            | ReqPayload::ConnectivityDoctor(_)
            | ReqPayload::DiagnosticsPreview(_)
            | ReqPayload::DiagnosticsExport(_)
            | ReqPayload::RewindPreview(_)
            | ReqPayload::ListRecoveryOperations(_)
            | ReqPayload::ShowRecoveryOperation(_)
            | ReqPayload::MaterializationStatus(_)
            | ReqPayload::ListConflicts(_)
            | ReqPayload::ListInbox(_)
            | ReqPayload::ListPreserved(_)
            | ReqPayload::ListProviderPending(_)
            | ReqPayload::ListRetainedOriginals(_)
            | ReqPayload::GetSpaceManagement(_)
            | ReqPayload::RewindStatus(_)
    )
}

/// Requests that only end the daemon. They are how the owner's updater finishes an update, so
/// they are allowed across a release mismatch; a mismatched program starts, replaces and changes
/// nothing.
fn only_stops_the_daemon(payload: &ReqPayload) -> bool {
    matches!(payload, ReqPayload::Shutdown(_) | ReqPayload::RequestSafeStop(_))
}

/// This program's own descriptor, as a caller (install source is not part of the pairing).
/// `yadorilink doctor` shows it against the running daemon's.
///
/// # Errors
/// [`DescriptorProblem`] when the engine identity beside this program is unreadable or made for
/// another engine API.
pub fn local_descriptor() -> Result<ReleaseDescriptor, DescriptorProblem> {
    let exe = std::env::current_exe().unwrap_or_default();
    ReleaseDescriptor::of_program(
        env!("CARGO_PKG_VERSION"),
        "",
        yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION,
        release_descriptor::identity_dir(&exe).as_deref(),
    )
}

/// The daemon's descriptor as `identify` reports it.
fn daemon_descriptor(report: &IdentifyResponse) -> ReleaseDescriptor {
    ReleaseDescriptor {
        version: report.version.clone(),
        channel: String::new(),
        install_source: report.install_source.clone(),
        release_id: report.release_id.clone(),
        engine_api_version: report.engine_api_version,
        state_schema: None,
    }
}

/// The mismatch stop for callers: whether `local` and the daemon behind `report` come from the
/// same release.
fn check_paired(
    local: Result<ReleaseDescriptor, DescriptorProblem>,
    report: &IdentifyResponse,
) -> Result<(), CoreError> {
    let daemon = daemon_descriptor(report);
    let local = local.map_err(|problem| CoreError::EngineMismatch {
        message: problem.message(),
        detail: EngineMismatchDetail {
            kind: EngineMismatchKind::AppInstallation,
            direction: EngineMismatchDirection::Unknown,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            engine_version: daemon.version.clone(),
            app_release_id: String::new(),
            engine_release_id: daemon.release_id.clone(),
            app_api_version: yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION,
            engine_api_version: daemon.engine_api_version,
        },
    })?;
    release_descriptor::check_pair(&local, &daemon).map_err(|mismatch| {
        let (kind, direction) = match &mismatch {
            release_descriptor::PairMismatch::EngineApi { caller, daemon } => (
                EngineMismatchKind::ApiVersion,
                match daemon.cmp(caller) {
                    std::cmp::Ordering::Less => EngineMismatchDirection::EngineOlder,
                    std::cmp::Ordering::Greater => EngineMismatchDirection::EngineNewer,
                    std::cmp::Ordering::Equal => EngineMismatchDirection::Unknown,
                },
            ),
            release_descriptor::PairMismatch::Build { .. } => {
                (EngineMismatchKind::Build, EngineMismatchDirection::Unknown)
            }
        };
        CoreError::EngineMismatch {
            message: mismatch.message(&local, &daemon),
            detail: EngineMismatchDetail {
                kind,
                direction,
                app_version: local.version.clone(),
                engine_version: daemon.version.clone(),
                app_release_id: local.release_id.clone(),
                engine_release_id: daemon.release_id.clone(),
                app_api_version: local.engine_api_version,
                engine_api_version: daemon.engine_api_version,
            },
        }
    })
}

/// Holds back a state-changing request when this program and the running daemon are not the same
/// release. Asks the daemon who it is first, on the connection the request will then travel on,
/// so the daemon that was checked is the daemon that receives it; read-only requests and the stop
/// requests pass without the question.
async fn ensure_paired(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    payload: &ReqPayload,
) -> Result<(), CoreError> {
    if is_read_only(payload) || only_stops_the_daemon(payload) {
        return Ok(());
    }
    let resp = exchange(stream, ReqPayload::Identify(IdentifyRequest {})).await?;
    let Some(RespPayload::Identify(report)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    check_paired(local_descriptor(), &report)
}

/// How long the daemon may take to answer a request [`open_held`] sends. It
/// bounds its own lookup, dial and check, so a longer wait is a wedged daemon.
const HELD_REPLY_BUDGET: Duration = Duration::from_secs(90);

/// How long connecting to the control socket may take. A daemon that is
/// running accepts at once; one that is not has no socket to refuse from.
const CONNECT_BUDGET: Duration = Duration::from_secs(5);

/// How long a quick request may wait for its answer. These are the requests
/// the daemon answers from its own state without waiting on the network or a
/// bulk transfer, so a daemon that takes longer is wedged rather than busy.
pub const QUICK_REPLY_BUDGET: Duration = Duration::from_secs(15);

/// The reply deadline for `payload`: [`QUICK_REPLY_BUDGET`] for a quick
/// request (a shutdown among them: the daemon answers it before it drains),
/// `None` for one whose duration depends on the network, on peers
/// or on how much data it moves (linking, transfers, hydration, restores,
/// garbage collection, updates, group commands), which the client cannot
/// bound without failing work that is still progressing.
fn reply_budget(payload: &ReqPayload) -> Option<Duration> {
    match payload {
        ReqPayload::Status(_)
        | ReqPayload::Health(_)
        | ReqPayload::Identify(_)
        | ReqPayload::ListLinks(_)
        | ReqPayload::Pause(_)
        | ReqPayload::Resume(_)
        | ReqPayload::ListConflicts(_)
        | ReqPayload::ListInbox(_)
        | ReqPayload::ListTrash(_)
        | ReqPayload::ListVersions(_)
        | ReqPayload::MaterializationStatus(_)
        | ReqPayload::UnpinItem(_)
        | ReqPayload::LimitsShow(_)
        | ReqPayload::UpdateStatus(_)
        | ReqPayload::ReportingStatus(_)
        | ReqPayload::ListQueueItems(_)
        | ReqPayload::ShowQueueItem(_)
        | ReqPayload::ListConnectionTraces(_)
        | ReqPayload::ListRecoveryOperations(_)
        | ReqPayload::ShowRecoveryOperation(_)
        | ReqPayload::RewindStatus(_)
        | ReqPayload::Shutdown(_) => Some(QUICK_REPLY_BUDGET),
        _ => None,
    }
}

/// One request and its response over an already connected control stream.
/// A quick request that is not answered within its budget is
/// [`CoreError::DaemonUnresponsive`].
async fn exchange(
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    payload: ReqPayload,
) -> Result<DaemonControlResponse, CoreError> {
    match reply_budget(&payload) {
        Some(budget) => tokio::time::timeout(budget, round_trip(stream, payload))
            .await
            .map_err(|_| CoreError::DaemonUnresponsive)?,
        None => round_trip(stream, payload).await,
    }
}

async fn round_trip(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    payload: ReqPayload,
) -> Result<DaemonControlResponse, CoreError> {
    let protocol_version = yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION;
    write_message(&mut stream, &DaemonControlRequest { payload: Some(payload), protocol_version })
        .await?;
    let resp = read_message::<DaemonControlResponse>(&mut stream)
        .await?
        .ok_or(CoreError::DaemonNotRunning)?;

    // Pre-release binaries are one release unit. Do not interpret a response
    // from an older/newer development daemon using protobuf zero/default
    // behavior; fail fast and require matching binaries instead.
    if resp.daemon_protocol_version != protocol_version {
        return Err(CoreError::DaemonProtocolMismatch {
            client: protocol_version,
            daemon: resp.daemon_protocol_version,
        });
    }
    match &resp.payload {
        Some(RespPayload::Error(msg)) => return Err(CoreError::DaemonRejected(msg.clone())),
        Some(RespPayload::CommandError(error)) => {
            return Err(CoreError::from_command_error(error.clone()));
        }
        _ => {}
    }
    Ok(resp)
}

#[cfg(unix)]
async fn connect() -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(crate::coordination::device_config::control_socket_path()).await
}

/// On Windows, the daemon's `windows_transport`
/// pre-creates the next pipe instance before handing off each connection,
/// so a fresh instance should almost always be waiting — but a burst of
/// concurrent client invocations can still race it, so a busy pipe
/// (`ERROR_PIPE_BUSY`, raw OS error 231) gets a few short retries rather
/// than failing immediately.
#[cfg(windows)]
async fn connect() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;

    const ERROR_PIPE_BUSY: i32 = 231;
    const MAX_ATTEMPTS: u32 = 5;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

    let pipe_name = crate::coordination::device_config::control_pipe_name();
    let mut attempt = 0;
    loop {
        match ClientOptions::new().security_qos_flags(SECURITY_IDENTIFICATION).open(&pipe_name) {
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

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::{ShutdownRequest, StatusRequest};

    use super::{
        check_paired, exchange, is_read_only, only_stops_the_daemon, DescriptorProblem,
        IdentifyResponse, ReleaseDescriptor,
    };
    use crate::error::{
        CoreError, DaemonUnavailableReason, DesktopError, EngineMismatchDirection,
        EngineMismatchKind,
    };

    /// A daemon that accepts the connection and then never answers (wedged,
    /// stopped, stuck on a lock) must come back as unavailable instead of
    /// keeping the caller, and every status poll behind it, waiting forever.
    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_accepts_but_never_answers_reads_as_unavailable() {
        let (client, _daemon_that_never_answers) =
            tokio::net::UnixStream::pair().expect("socket pair");

        let answer = tokio::time::timeout(
            Duration::from_secs(600),
            exchange(client, ReqPayload::Status(StatusRequest {})),
        )
        .await
        .expect("a request to a silent daemon must give up on its own");

        let error = answer.expect_err("a silent daemon cannot have answered");
        assert!(
            matches!(
                DesktopError::from_core(error, false),
                DesktopError::DaemonUnavailable {
                    reason: DaemonUnavailableReason::Unresponsive,
                    ..
                }
            ),
            "a silent daemon must read as unresponsive, not as not running"
        );
    }

    /// Stopping is what a user reaches for when the daemon is wedged. The
    /// daemon answers a shutdown before it drains, so a silent one is
    /// unresponsive, not a request still in progress.
    #[tokio::test(start_paused = true)]
    async fn a_shutdown_the_daemon_never_answers_gives_up() {
        let (client, _daemon_that_never_answers) =
            tokio::net::UnixStream::pair().expect("socket pair");

        let answer = tokio::time::timeout(
            Duration::from_secs(600),
            exchange(client, ReqPayload::Shutdown(ShutdownRequest {})),
        )
        .await
        .expect("a shutdown sent to a silent daemon must give up on its own");

        assert!(matches!(answer, Err(CoreError::DaemonUnresponsive)), "{answer:?}");
    }

    fn local(release_id: &str) -> ReleaseDescriptor {
        ReleaseDescriptor {
            version: "1.0.0".into(),
            channel: String::new(),
            install_source: String::new(),
            release_id: release_id.into(),
            engine_api_version: yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION,
            state_schema: None,
        }
    }

    fn report(release_id: &str, api: u32) -> IdentifyResponse {
        IdentifyResponse {
            version: "1.0.0".into(),
            engine_api_version: api,
            release_id: release_id.into(),
            install_source: "app_bundle".into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_matching_daemon_pairs_and_a_different_build_or_api_does_not() {
        let api = yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION;
        assert!(check_paired(Ok(local("c:d")), &report("c:d", api)).is_ok());
        assert!(check_paired(Ok(local("")), &report("c:d", api)).is_ok());
        let build = check_paired(Ok(local("c:d")), &report("x:y", api)).unwrap_err();
        assert!(
            matches!(&build, CoreError::EngineMismatch { message, .. } if message.contains("x:y") && message.contains("YadoriLink app")),
            "{build:?}"
        );
        let other_api = check_paired(Ok(local("c:d")), &report("c:d", api + 1)).unwrap_err();
        assert!(matches!(other_api, CoreError::EngineMismatch { .. }), "{other_api:?}");
        let detail = |e: CoreError| match e {
            CoreError::EngineMismatch { detail, .. } => detail,
            other => panic!("{other:?}"),
        };
        let older = detail(check_paired(Ok(local("c:d")), &report("c:d", api - 1)).unwrap_err());
        assert_eq!(older.kind, EngineMismatchKind::ApiVersion);
        assert_eq!(older.direction, EngineMismatchDirection::EngineOlder);
        let newer = detail(other_api);
        assert_eq!(newer.direction, EngineMismatchDirection::EngineNewer);
        assert_eq!((newer.app_api_version, newer.engine_api_version), (api, api + 1));
        let build = detail(build);
        assert_eq!(build.kind, EngineMismatchKind::Build);
        assert_eq!(build.direction, EngineMismatchDirection::Unknown);
        assert_eq!(
            (build.app_release_id.as_str(), build.engine_release_id.as_str()),
            ("c:d", "x:y")
        );
    }

    #[test]
    fn an_unusable_own_descriptor_stops_every_state_changing_request() {
        let problem = DescriptorProblem::Unreadable { reason: "bad".into() };
        let api = yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION;
        let error = check_paired(Err(problem), &report("c:d", api)).unwrap_err();
        match error {
            CoreError::EngineMismatch { detail, .. } => {
                assert_eq!(detail.kind, EngineMismatchKind::AppInstallation);
                assert!(detail.app_release_id.is_empty());
                assert_eq!(detail.engine_release_id, "c:d");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn only_inspection_and_stopping_pass_the_gate() {
        use yadorilink_ipc_proto::daemonctl::{
            PauseRequest, RequestSafeStopRequest, UpdateInstallRequest,
        };
        assert!(is_read_only(&ReqPayload::Status(StatusRequest {})));
        assert!(!is_read_only(&ReqPayload::Pause(PauseRequest::default())));
        assert!(!is_read_only(&ReqPayload::UpdateInstall(UpdateInstallRequest::default())));
        assert!(!is_read_only(&ReqPayload::Shutdown(ShutdownRequest {})));
        assert!(only_stops_the_daemon(&ReqPayload::Shutdown(ShutdownRequest {})));
        assert!(only_stops_the_daemon(&ReqPayload::RequestSafeStop(
            RequestSafeStopRequest::default()
        )));
        assert!(!only_stops_the_daemon(&ReqPayload::Pause(PauseRequest::default())));
    }
}
