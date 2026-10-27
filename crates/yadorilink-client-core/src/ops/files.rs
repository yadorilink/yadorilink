//! Per-file operations inside linked folders: conflicts, trash, version
//! history, and on-demand materialization (hydrate, evict).
//!
//! Paths are absolute paths under a linked folder; resolving what a person
//! typed into one is the caller's job.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ConflictedFileInfo, EvictRequest, EvictResponse, FileVersionInfo, HydrateRequest,
    ListConflictsRequest, ListTrashRequest, ListVersionsRequest, MaterializationStatusRequest,
    MaterializationStatusResponse, RestoreTrashOperationRequest, RestoreTrashOperationResponse,
    RestoreTrashRequest, RestoreVersionRequest, TrashedFileInfo,
};
use yadorilink_ipc_proto::daemonctl::{
    PinItemRequest, PinItemResponse, UnpinItemRequest, UnpinItemResponse,
};

use crate::daemon::control;
use crate::error::CoreError;

fn unexpected() -> CoreError {
    CoreError::Other("unexpected daemon response".into())
}

/// Currently-live conflicted-copy files, across every link, or only the
/// link at `local_path`.
pub async fn list_conflicts(
    local_path: Option<&str>,
) -> Result<Vec<ConflictedFileInfo>, CoreError> {
    let resp = control::send(ReqPayload::ListConflicts(ListConflictsRequest {})).await?;
    let Some(RespPayload::ListConflicts(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.files.into_iter().filter(|f| local_path.is_none_or(|p| f.local_path == p)).collect())
}

/// Currently-recoverable trashed files, across every link, or only the link
/// at `local_path`.
pub async fn list_trash(local_path: Option<&str>) -> Result<Vec<TrashedFileInfo>, CoreError> {
    let resp = control::send(ReqPayload::ListTrash(ListTrashRequest {})).await?;
    let Some(RespPayload::ListTrash(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.files.into_iter().filter(|f| local_path.is_none_or(|p| f.local_path == p)).collect())
}

/// Recovers a deleted file's last version before deletion as a new current
/// version.
pub async fn restore_from_trash(absolute_path: String) -> Result<(), CoreError> {
    control::send(ReqPayload::RestoreTrash(RestoreTrashRequest { absolute_path })).await?;
    Ok(())
}

/// Recovers, together, every trashed entry removed by the same recursive
/// delete or directory rename that removed the trashed entry at
/// `absolute_path`.
pub async fn restore_trash_operation(
    absolute_path: String,
) -> Result<RestoreTrashOperationResponse, CoreError> {
    let resp = control::send(ReqPayload::RestoreTrashOperation(RestoreTrashOperationRequest {
        absolute_path,
    }))
    .await?;
    let Some(RespPayload::RestoreTrashOperation(outcome)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(outcome)
}

/// Every retained version of one file, newest first including the current
/// one.
pub async fn list_versions(absolute_path: String) -> Result<Vec<FileVersionInfo>, CoreError> {
    let resp =
        control::send(ReqPayload::ListVersions(ListVersionsRequest { absolute_path })).await?;
    let Some(RespPayload::ListVersions(list)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(list.versions)
}

/// Restores one file to a specific prior version, or (when `version_seq` is
/// `None`) the most recently superseded one, as a new current version.
pub async fn restore_version(
    absolute_path: String,
    version_seq: Option<i64>,
) -> Result<(), CoreError> {
    control::send(ReqPayload::RestoreVersion(RestoreVersionRequest { absolute_path, version_seq }))
        .await?;
    Ok(())
}

/// One file's current materialization state and pin flag.
pub async fn materialization_status(
    absolute_path: String,
) -> Result<MaterializationStatusResponse, CoreError> {
    let resp = control::send(ReqPayload::MaterializationStatus(MaterializationStatusRequest {
        absolute_path,
    }))
    .await?;
    let Some(RespPayload::MaterializationStatus(status)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(status)
}

/// Fetches a placeholder file's real content. Returns whether the daemon downloaded anything:
/// `false` means the content was already on this device.
pub async fn hydrate_file(absolute_path: String) -> Result<bool, CoreError> {
    let resp = control::send(ReqPayload::Hydrate(HydrateRequest { absolute_path })).await?;
    let Some(RespPayload::Hydrate(hydrate)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(hydrate.downloaded)
}

/// Converts a hydrated file back into a placeholder to reclaim local disk
/// space. Returns whether the file was actually dehydrated: a request that
/// did nothing (the file is busy, not fully synced, or was just modified)
/// must never read as success.
pub async fn evict_file(absolute_path: String) -> Result<bool, CoreError> {
    Ok(evict(absolute_path).await?.dehydrated)
}

/// [`evict_file`] with the daemon's whole answer, including what the
/// eviction reclaimed.
pub async fn evict(absolute_path: String) -> Result<EvictResponse, CoreError> {
    let resp = control::send(ReqPayload::Evict(EvictRequest { absolute_path })).await?;
    let Some(RespPayload::Evict(evict)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(evict)
}

/// Why a "free up space" request left something on this device, in words a person can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvictRefusal {
    /// What stayed and why.
    pub why: &'static str,
    /// Whether asking again later can work without the person doing anything else.
    pub retryable: bool,
    /// What to do next; empty when there is nothing to do.
    pub hint: &'static str,
}

/// The wording for a `retained_reason` code of [`EvictResponse`]. `None` for the empty code (nothing
/// was kept back); an unknown code gets a generic answer rather than none.
pub fn evict_refusal(code: &str) -> Option<EvictRefusal> {
    let again = "Try again in a few seconds.";
    let (why, retryable, hint) = match code {
        "" => return None,
        "custody_not_acquired" => (
            "no other complete copy could confirm it holds this version right now, so nothing \
             was freed",
            true,
            "Try again when another device that keeps full copies is online.",
        ),
        "custody_required" => (
            "no complete copy holds this version and the local copy would be the only one",
            true,
            "Try again when another device that keeps full copies is online.",
        ),
        "custody_unsupported" => ("freeing space is not available on this platform yet", false, ""),
        "full_replica" => {
            ("this device is a complete copy of the folder and keeps its data", false, "")
        }
        "busy" => ("the file is in use by another operation", true, again),
        "host_busy" => ("a program has the file open", true, "Close it, then try again."),
        "version_moved" => ("the file changed while it was being evicted", true, again),
        "nothing_freed" => {
            ("the data is still referenced by other files on this device", false, "")
        }
        "not_downloaded" => {
            ("the file is not downloaded on this device, so there is nothing to free", false, "")
        }
        "not_confirmed" => {
            ("the download has not been confirmed yet, or the file is being updated", true, again)
        }
        "host_refused" => (
            "the system would not free it just now; it may have changes that are not shared yet",
            true,
            "Wait until it has synced, then try again.",
        ),
        _ => ("the daemon kept the data on this device", false, ""),
    };
    Some(EvictRefusal { why, retryable, hint })
}

/// Marks a file or folder "always keep on this device" and downloads what is not here yet.
pub async fn pin(absolute_path: String) -> Result<PinItemResponse, CoreError> {
    let resp = control::send(ReqPayload::PinItem(PinItemRequest { absolute_path })).await?;
    let Some(RespPayload::PinItem(pin)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(pin)
}

/// Stops keeping a file or folder. Nothing is removed: its space becomes reclaimable.
pub async fn unpin(absolute_path: String) -> Result<UnpinItemResponse, CoreError> {
    let resp = control::send(ReqPayload::UnpinItem(UnpinItemRequest { absolute_path })).await?;
    let Some(RespPayload::UnpinItem(unpin)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(unpin)
}

/// What to do with a kept copy of a file that was edited on two devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictChoice {
    /// The copy becomes the file; the other version is no longer current.
    KeepThis,
    /// The copy stays as an ordinary file beside the original, under a
    /// plain name.
    KeepBoth,
}

/// Resolves the live conflicted copy at `copy_path` (absolute) and returns the
/// absolute path of the kept content. The daemon decides and performs the
/// action when it runs, and refuses with a typed [`CoreError::DaemonCommand`]
/// (`UnrecordedLocalChanges`, `ConflictNotResolvable`, `TargetNotFound`) with
/// nothing changed.
pub async fn resolve_conflict(
    copy_path: &str,
    choice: ConflictChoice,
) -> Result<std::path::PathBuf, CoreError> {
    use yadorilink_ipc_proto::daemonctl::resolve_conflict_response::Result as Outcome;
    use yadorilink_ipc_proto::daemonctl::{ConflictResolution, ResolveConflictRequest};
    let resolution = match choice {
        ConflictChoice::KeepThis => ConflictResolution::KeepThis,
        ConflictChoice::KeepBoth => ConflictResolution::KeepBoth,
    };
    let resp = control::send(ReqPayload::ResolveConflict(ResolveConflictRequest {
        copy_path: copy_path.to_string(),
        resolution: resolution as i32,
    }))
    .await?;
    let Some(RespPayload::ResolveConflict(resolved)) = resp.payload else {
        return Err(unexpected());
    };
    match resolved.result {
        Some(Outcome::KeptPath(kept)) => Ok(kept.into()),
        Some(Outcome::Error(error)) => Err(CoreError::from_command_error(error)),
        None => Err(unexpected()),
    }
}
