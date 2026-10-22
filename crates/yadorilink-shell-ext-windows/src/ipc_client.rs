//! Thin, blocking-from-the-caller's-perspective IPC client for the
//! shell-integration protocol, following
//! the exact pattern `yadorilink_daemon::shell_ipc::client` documents as the
//! reference implementation for native shell-extension shims — but
//! implemented directly against `yadorilink-ipc-proto` rather than
//! depending on the (much larger) `yadorilink-daemon` crate, since this
//! code loads into every Explorer.exe process via a shell extension DLL.
//!
//! COM shell-extension callbacks (`IsMemberOf`, `GetOverlayInfo`, etc.)
//! are inherently synchronous, so this module owns one lazily-started,
//! single-threaded Tokio runtime and blocks on it per call — the same
//! bounded-timeout, fail-soft-to-`Unspecified` contract as the reference
//! client, just without requiring Explorer's calling thread to itself be
//! async.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::runtime::Runtime;
use windows::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ContextAction, ContextActionRequest, FolderFileEntry, HydrateRequest, ListFolderFilesRequest,
    ListProviderFoldersRequest, ProviderFolder, ProviderRemoval, ShellBadge, ShellIpcMessage,
    StatusQuery, StatusResponse,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(200);
const ERROR_PIPE_BUSY: i32 = 231;
const MAX_ATTEMPTS: u32 = 5;
const RETRY_DELAY: Duration = Duration::from_millis(50);

/// On-demand sync's bounded hydration timeout is 30s
/// daemon-side (the time budget for the actual peer block fetch); this
/// client-side bound is set a little above that so the daemon's own
/// timeout has a chance to fire first and report a clean
/// `HydrateResponse { ok: false,.. }` rather than this client abandoning
/// the pipe read first and reporting a generic failure with no reason.
/// Substantially longer than `DEFAULT_TIMEOUT` (200ms, for cheap,
/// frequent status polls) and `DEFAULT_TIMEOUT * 10` (2s, for
/// context-menu actions that are usually local-only) because hydration is
/// the one shell-IPC call expected to involve real peer network I/O.
const HYDRATE_TIMEOUT: Duration = Duration::from_secs(31);

/// Folder/file enumeration (`ListOnDemandFolders`/
/// `ListFolderFiles`) runs at cfapi host startup, not on Explorer's UI
/// thread, so it can afford a more generous bound than the interactive
/// calls above without risking a visible hang anywhere.
const LIST_TIMEOUT: Duration = Duration::from_secs(5);

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the shell extension's background IPC runtime")
    })
}

/// The same name the daemon serves: both derive it from the resolved state directory.
fn pipe_name() -> String {
    yadorilink_fs_platform::state_dir::shell_ipc_pipe_name()
}

pub(crate) async fn connect() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let name = pipe_name();
    let mut attempt = 0;
    loop {
        match ClientOptions::new().security_qos_flags(SECURITY_IDENTIFICATION.0).open(&name) {
            Ok(client) => {
                verify_server_identity(&client)?;
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

#[cfg(windows)]
fn verify_server_identity(client: &NamedPipeClient) -> std::io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        EqualSid, GetTokenInformation, TokenOwner, TOKEN_OWNER, TOKEN_QUERY,
    };
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe fn owner_sid_for_process(process: HANDLE) -> std::io::Result<Vec<u8>> {
        let mut token = HANDLE::default();
        OpenProcessToken(process, TOKEN_QUERY, &mut token).map_err(win32_error)?;

        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenOwner, None, 0, &mut len);
        let mut buffer = vec![0u8; len as usize];
        let result = GetTokenInformation(
            token,
            TokenOwner,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            len,
            &mut len,
        );
        CloseHandle(token).ok();
        result.map_err(win32_error)?;
        Ok(buffer)
    }

    unsafe fn token_owner_sid(buffer: &[u8]) -> windows::Win32::Security::PSID {
        buffer.as_ptr().cast::<TOKEN_OWNER>().read_unaligned().Owner
    }

    unsafe {
        let pipe_handle = HANDLE(client.as_raw_handle());
        let mut server_pid = 0u32;
        GetNamedPipeServerProcessId(pipe_handle, &mut server_pid).map_err(win32_error)?;

        let server_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, server_pid)
            .map_err(win32_error)?;
        let server_owner = owner_sid_for_process(server_process)?;
        CloseHandle(server_process).ok();

        let current_process =
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, std::process::id())
                .map_err(win32_error)?;
        let current_owner = owner_sid_for_process(current_process)?;
        CloseHandle(current_process).ok();

        let server_sid = token_owner_sid(&server_owner);
        let current_sid = token_owner_sid(&current_owner);
        EqualSid(server_sid, current_sid).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "named-pipe server is not owned by the current user",
            )
        })
    }
}

#[cfg(windows)]
fn win32_error(err: windows::core::Error) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

/// The daemon's full status answer for `path`, or `None` when it could not be asked in time
/// (unreachable daemon, timeout, malformed answer). Never blocks Explorer for longer than
/// `DEFAULT_TIMEOUT`; every caller fails soft on `None`.
pub fn query_status(path: &str) -> Option<StatusResponse> {
    runtime().block_on(async {
        tokio::time::timeout(DEFAULT_TIMEOUT, query_status_inner(path)).await.ok().flatten()
    })
}

/// The badge the daemon chose for `path`; `Unspecified` (no overlay) on any failure. The shell
/// never derives a badge itself.
pub fn query_badge(path: &str) -> ShellBadge {
    query_status(path).map_or(ShellBadge::Unspecified, |r| r.badge())
}

async fn query_status_inner(path: &str) -> Option<StatusResponse> {
    let mut stream = connect().await.ok()?;
    let msg = ShellIpcMessage {
        payload: Some(Payload::StatusQuery(StatusQuery { path: path.to_string() })),
    };
    write_message(&mut stream, &msg).await.ok()?;
    match read_message::<ShellIpcMessage>(&mut stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::StatusResponse(r)) })) => Some(r),
        _ => None,
    }
}

/// Sends a context-menu action ("view status", "pause", "resume", "pin",
/// "evict") for `path`. Returns `true` on a confirmed success response
/// from the daemon; `false` for any failure, timeout, or unreachable
/// daemon — the caller (the context menu handler) is expected to just
/// silently no-op the menu item in that case rather than show an error
/// dialog, matching the overlay's own fail-soft contract.
pub fn send_context_action(path: &str, action: ContextAction) -> bool {
    runtime().block_on(async {
        tokio::time::timeout(DEFAULT_TIMEOUT * 10, send_context_action_inner(path, action))
            .await
            .unwrap_or(false)
    })
}

/// Requests synchronous hydration of `path`:
/// the Cloud Filter API `CF_CALLBACK_TYPE_FETCH_DATA` handler calls this
/// and blocks on the result before completing the OS callback via
/// `CfExecute`. Returns `false` on any failure, timeout, or unreachable
/// daemon — the caller is expected to complete the pending cfapi callback
/// with an I/O error in that case, never hang the calling
/// application's read.
pub fn hydrate(path: &str) -> bool {
    runtime().block_on(async {
        tokio::time::timeout(HYDRATE_TIMEOUT, hydrate_inner(path)).await.unwrap_or(false)
    })
}

async fn hydrate_inner(path: &str) -> bool {
    let Ok(mut stream) = connect().await else { return false };
    let msg = ShellIpcMessage {
        payload: Some(Payload::HydrateRequest(HydrateRequest { path: path.to_string() })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return false;
    }
    matches!(
        read_message::<ShellIpcMessage>(&mut stream).await,
        Ok(Some(ShellIpcMessage { payload: Some(Payload::HydrateResponse(r)) })) if r.ok
    )
}

/// The provider roots the daemon declares for this device, and the roots it wants removed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProviderSnapshot {
    pub folders: Vec<ProviderFolder>,
    pub removals: Vec<ProviderRemoval>,
}

/// Lists the provider roots (the reconciliation input of the host's loop). `app_group_container`
/// is the host's private data directory: the daemon adopts it once, as the place of its provider
/// temp root (`<container>\provider`).
///
/// `None` on any failure to confirm the daemon's current declarations (unreachable daemon,
/// timeout, malformed response, or an explicit `snapshot_available: false`), deliberately distinct
/// from `Some` of an empty snapshot, a confirmed "no provider roots": the caller registers and
/// unregisters sync roots against a snapshot, and must leave them untouched when it cannot
/// confirm one.
pub fn list_provider_folders(app_group_container: &str) -> Option<ProviderSnapshot> {
    runtime().block_on(async {
        tokio::time::timeout(LIST_TIMEOUT, list_provider_folders_inner(app_group_container))
            .await
            .ok()?
    })
}

async fn list_provider_folders_inner(app_group_container: &str) -> Option<ProviderSnapshot> {
    let mut stream = connect().await.ok()?;
    list_provider_folders_over(&mut stream, app_group_container).await
}

/// The stream-generic core of `list_provider_folders_inner`, split out so the load-bearing
/// `None`-versus-`Some` distinction is testable against an in-memory duplex stream.
async fn list_provider_folders_over<S>(
    stream: &mut S,
    app_group_container: &str,
) -> Option<ProviderSnapshot>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let msg = ShellIpcMessage {
        payload: Some(Payload::ListProviderFoldersRequest(ListProviderFoldersRequest {
            app_group_container: app_group_container.to_string(),
        })),
    };
    write_message(stream, &msg).await.ok()?;
    loop {
        match read_message::<ShellIpcMessage>(stream).await {
            Ok(Some(ShellIpcMessage {
                payload: Some(Payload::ListProviderFoldersResponse(r)),
            })) => {
                return r
                    .snapshot_available
                    .then_some(ProviderSnapshot { folders: r.folders, removals: r.removals });
            }
            // A status update pushed on the connection before the answer.
            Ok(Some(ShellIpcMessage { payload: Some(Payload::StatusPush(_)) })) => {}
            _ => return None,
        }
    }
}

/// Lists every non-deleted file the daemon has indexed under the OnDemand
/// folder rooted at `local_path` (same reasoning as
/// `list_on_demand_folders`), with enough metadata (`size`,
/// `mtime_unix_nanos`, `local_state`) to create or update a
/// cfapi placeholder per file. `local_path` must match a `local_path`
/// this client already got back from `list_on_demand_folders`.
///
/// `None` on any failure to confirm the listing (unreachable daemon,
/// timeout, malformed response, or an explicit `snapshot_available:
/// false`), deliberately distinct from `Some(vec![])`, a confirmed empty
/// folder -- same contract as `list_on_demand_folders` and as
/// the macOS app's `list_folder_files`. The caller
/// skips that folder's placeholder sync for the poll on `None`.
pub fn list_folder_files(local_path: &str) -> Option<Vec<FolderFileEntry>> {
    runtime().block_on(async {
        tokio::time::timeout(LIST_TIMEOUT, list_folder_files_inner(local_path)).await.ok()?
    })
}

async fn list_folder_files_inner(local_path: &str) -> Option<Vec<FolderFileEntry>> {
    let mut stream = connect().await.ok()?;
    list_folder_files_over(&mut stream, local_path).await
}

/// The stream-generic core of `list_folder_files_inner`, split out (like
/// `list_on_demand_folders_over`) so the `None`-vs-`Some(vec![])`
/// distinction is testable against an in-memory duplex stream.
async fn list_folder_files_over<S>(stream: &mut S, local_path: &str) -> Option<Vec<FolderFileEntry>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let msg = ShellIpcMessage {
        payload: Some(Payload::ListFolderFilesRequest(ListFolderFilesRequest {
            local_path: local_path.to_string(),
        })),
    };
    write_message(stream, &msg).await.ok()?;
    match read_message::<ShellIpcMessage>(stream).await {
        Ok(Some(ShellIpcMessage { payload: Some(Payload::ListFolderFilesResponse(r)) }))
            if r.snapshot_available =>
        {
            Some(r.entries)
        }
        _ => None,
    }
}

#[cfg(test)]
mod list_folder_files_tests {
    use super::*;

    async fn respond_with(response: Option<ShellIpcMessage>) -> Option<Vec<FolderFileEntry>> {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let _ = read_message::<ShellIpcMessage>(&mut server).await;
            if let Some(response) = response {
                let _ = write_message(&mut server, &response).await;
            }
        });
        let result = list_folder_files_over(&mut client, "C:\\A").await;
        server_task.await.unwrap();
        result
    }

    fn response(relative_paths: &[&str], snapshot_available: bool) -> ShellIpcMessage {
        ShellIpcMessage {
            payload: Some(Payload::ListFolderFilesResponse(
                yadorilink_ipc_proto::shellipc::ListFolderFilesResponse {
                    entries: relative_paths
                        .iter()
                        .map(|p| FolderFileEntry {
                            relative_path: p.to_string(),
                            ..Default::default()
                        })
                        .collect(),
                    snapshot_available,
                },
            )),
        }
    }

    #[tokio::test]
    async fn confirmed_listing_is_some() {
        let result = respond_with(Some(response(&["a.txt"], true))).await;
        assert_eq!(result.map(|e| e.len()), Some(1));
    }

    #[tokio::test]
    async fn confirmed_empty_listing_is_some_empty() {
        assert_eq!(respond_with(Some(response(&[], true))).await, Some(vec![]));
    }

    #[tokio::test]
    async fn unconfirmed_listing_is_none() {
        assert_eq!(respond_with(Some(response(&[], false))).await, None);
    }

    #[tokio::test]
    async fn connection_closed_without_a_response_is_none() {
        assert_eq!(respond_with(None).await, None);
    }
}

async fn send_context_action_inner(path: &str, action: ContextAction) -> bool {
    let Ok(mut stream) = connect().await else { return false };
    let msg = ShellIpcMessage {
        payload: Some(Payload::ContextActionRequest(ContextActionRequest {
            path: path.to_string(),
            action: action as i32,
        })),
    };
    if write_message(&mut stream, &msg).await.is_err() {
        return false;
    }
    matches!(
        read_message::<ShellIpcMessage>(&mut stream).await,
        Ok(Some(ShellIpcMessage { payload: Some(Payload::ContextActionResponse(r)) })) if r.ok
    )
}

#[cfg(test)]
mod list_provider_folders_tests {
    use super::*;

    async fn respond_with(response: Option<ShellIpcMessage>) -> Option<ProviderSnapshot> {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let _ = read_message::<ShellIpcMessage>(&mut server).await;
            if let Some(response) = response {
                let _ = write_message(&mut server, &response).await;
            }
        });
        let result = list_provider_folders_over(&mut client, "C:\\host").await;
        server_task.await.unwrap();
        result
    }

    fn response(folders: Vec<ProviderFolder>, snapshot_available: bool) -> ShellIpcMessage {
        ShellIpcMessage {
            payload: Some(Payload::ListProviderFoldersResponse(
                yadorilink_ipc_proto::shellipc::ListProviderFoldersResponse {
                    folders,
                    snapshot_available,
                    removals: vec![ProviderRemoval {
                        root_id: vec![2],
                        display_name: "Old".into(),
                    }],
                },
            )),
        }
    }

    fn folder(root: u8, name: &str) -> ProviderFolder {
        ProviderFolder { root_id: vec![root], display_name: name.into(), ..Default::default() }
    }

    #[tokio::test]
    async fn a_confirmed_snapshot_carries_its_folders_and_removals() {
        let snapshot = respond_with(Some(response(vec![folder(1, "Photos")], true))).await.unwrap();
        assert_eq!(snapshot.folders, vec![folder(1, "Photos")]);
        assert_eq!(snapshot.removals[0].root_id, vec![2]);
    }

    #[tokio::test]
    async fn a_confirmed_empty_snapshot_is_some_and_empty() {
        let snapshot = respond_with(Some(response(vec![], true))).await.unwrap();
        assert!(snapshot.folders.is_empty());
    }

    #[tokio::test]
    async fn snapshot_unavailable_is_none_even_with_folders_present() {
        assert_eq!(respond_with(Some(response(vec![folder(1, "Photos")], false))).await, None);
    }

    #[tokio::test]
    async fn server_closes_without_responding_is_none() {
        assert_eq!(respond_with(None).await, None);
    }

    #[tokio::test]
    async fn malformed_response_payload_is_none() {
        let msg = ShellIpcMessage { payload: Some(Payload::HydrateResponse(Default::default())) };
        assert_eq!(respond_with(Some(msg)).await, None);
    }
}
