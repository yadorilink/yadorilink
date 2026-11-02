//! Keep this / Keep both for a conflict copy in a provider folder.
//!
//! A provider folder has no directory the daemon can write in: the operating system owns what is
//! shown, and every change goes through the provider write path, which decides it against the
//! view the writer saw and commits it together with its operation record. A resolution is two
//! ordinary changes of that path, asked for as the daemon itself:
//!
//! * Keep this restores the copy's recorded version over the original as a new version
//!   (the original's old version stays in its history). It applies only while the original is
//!   exactly the version and generation read just before; otherwise nothing is written and the
//!   copy stays a conflict.
//! * Keep both renames the copy to the first free `name (other version N).ext`, the same name
//!   [`super::other_version_path`] gives a plain folder. A name taken in the meantime is a refusal
//!   of the rename, and the next name is tried.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use yadorilink_ipc_proto::shellipc::{
    ProviderApplyChangeRequest, ProviderApplyChangeResponse, ProviderApplyFailure,
    ProviderChangeKind, ProviderRestoreSource,
};
use yadorilink_replica_domain::conflict::conflict_copy_source_path;
use yadorilink_sync_sqlite::provider::{ItemId, ProviderDeclaration, ProviderRepository};

use super::{other_version_path, ConflictChoice, ResolveConflictError};
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;
use crate::sync_error::SyncError;

/// The root a group is shown through, when the group is a provider folder: `Ok(None)` for a plain
/// folder.
pub(super) fn provider_root_of(
    coordinator: &ReplicaCoordinator,
    group_id: &str,
) -> Result<Option<String>, ResolveConflictError> {
    match coordinator.provider_repository().declaration_for_group(group_id)? {
        ProviderDeclaration::Plain => Ok(None),
        ProviderDeclaration::Provider(root) => Ok(Some(root.root_id)),
        ProviderDeclaration::Corrupt(reason) => Err(ResolveConflictError::NotResolvable(format!(
            "the provider folder is not usable: {reason}"
        ))),
    }
}

/// Whether Keep this / Keep both can be done for a copy of a provider folder now: the root takes
/// changes, and both the copy and its original are shown items. Read for the list, so a choice
/// that would only fail when tried is not offered.
pub(super) fn resolvable_now(
    coordinator: &ReplicaCoordinator,
    root_id: &str,
    copy_path: &str,
) -> bool {
    let repo = coordinator.provider_repository();
    let ready = repo.list_declared_roots().is_ok_and(|roots| {
        roots.iter().any(|r| r.root_id == root_id && r.error_description.is_none())
    });
    let shown = |path: &str| repo.item_for_path(root_id, path).is_ok_and(|item| item.is_some());
    ready && shown(copy_path) && shown(&conflict_copy_source_path(copy_path))
}

/// The version identifier a write names as its view of `item`: the content hash, then the item's
/// generation, big endian.
fn view_of(
    repo: &ProviderRepository,
    root: &str,
    item: &ItemId,
) -> Result<Vec<u8>, ResolveConflictError> {
    let hash = repo.current_version_hash(root, item)?;
    let generation = repo.live_item_generation(root, item)?;
    let (Some(hash), Some(generation)) = (hash, generation) else {
        return Err(ResolveConflictError::NotResolvable("it is no longer shown".into()));
    };
    let mut view = hash.0.to_vec();
    view.extend_from_slice(&generation.to_be_bytes());
    Ok(view)
}

/// The one session the daemon authors resolutions under. A root keeps every session it has seen
/// (and refuses new ones past a small bound), so a resolution must not open a session of its own.
const RESOLUTION_SESSION: [u8; 16] = *b"yl-conflict-resv";

/// A sequence number above every one used before in the session, across restarts: the clock in
/// microseconds, forced to rise within the process.
fn next_operation_seq() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |since| u64::try_from(since.as_micros()).unwrap_or(u64::MAX).max(1));
    let mut last = LAST.load(Ordering::Relaxed);
    loop {
        let next = now.max(last + 1);
        match LAST.compare_exchange_weak(last, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(seen) => last = seen,
        }
    }
}

fn request(root: &str, item: &ItemId, view: Vec<u8>) -> ProviderApplyChangeRequest {
    let generation = u64::from_be_bytes(view[32..].try_into().expect("8 bytes"));
    ProviderApplyChangeRequest {
        request_id: uuid::Uuid::new_v4().as_bytes().to_vec(),
        session_id: RESOLUTION_SESSION.to_vec(),
        operation_seq: next_operation_seq(),
        root_id: hex::decode(root).unwrap_or_default(),
        kind: ProviderChangeKind::Modify as i32,
        item_id: item.to_vec(),
        base_version_hash: view,
        base_generation: Some(generation),
        ..Default::default()
    }
}

async fn apply(
    state: &Arc<DaemonState>,
    mut request: ProviderApplyChangeRequest,
) -> Result<ProviderApplyChangeResponse, ResolveConflictError> {
    let Some(applier) = state.provider_applier() else {
        return Err(ResolveConflictError::NotResolvable("the provider side is not running".into()));
    };
    let response = applier(request.clone()).await;
    // A sequence the root already counts as decided (the session's floor moved past it while this
    // resolution waited for the copy's blocks) is asked again under a new one. The change itself
    // is still decided against the view it names, so a retry cannot apply over a newer original.
    if ProviderApplyFailure::try_from(response.failure) == Ok(ProviderApplyFailure::StaleOperation)
    {
        request.request_id = uuid::Uuid::new_v4().as_bytes().to_vec();
        request.operation_seq = next_operation_seq();
        return Ok(applier(request).await);
    }
    Ok(response)
}

/// Turns a refused change into the resolution's own refusal, nothing changed.
fn refusal(response: &ProviderApplyChangeResponse, original: &str) -> ResolveConflictError {
    use ProviderApplyFailure as F;
    let failure = F::try_from(response.failure).unwrap_or(F::None);
    match failure {
        // The original (or the copy) is not what was read a moment ago.
        F::StaleView | F::KeepLocal | F::NotFound => {
            ResolveConflictError::UnrecordedLocalChanges(original.to_string())
        }
        F::NotReady | F::NotAuthorized => ResolveConflictError::NotResolvable(format!(
            "the provider folder does not take changes now: {}",
            response.error
        )),
        F::VersionUnavailable => ResolveConflictError::NotResolvable(
            "the copy's content is not held here and no reachable device has it".into(),
        ),
        _ => ResolveConflictError::Failed(SyncError::HydrationFailed(format!(
            "provider write refused ({failure:?}): {}",
            response.error
        ))),
    }
}

/// Resolves the copy at `copy_path` in the provider folder shown through `root`; answers the
/// group-relative path that holds the content afterwards.
pub(super) async fn resolve(
    state: &Arc<DaemonState>,
    root: &str,
    copy_path: &str,
    choice: ConflictChoice,
) -> Result<PathBuf, ResolveConflictError> {
    let repo = state.replica_coordinator.provider_repository();
    let original = conflict_copy_source_path(copy_path);
    let item_at = |path: &str| -> Result<ItemId, ResolveConflictError> {
        repo.item_for_path(root, path)?
            .ok_or_else(|| ResolveConflictError::NotResolvable(format!("{path} is not shown")))
    };
    let copy_item = item_at(copy_path)?;
    match choice {
        ConflictChoice::KeepThis => {
            let original_item = item_at(&original)?;
            let version = repo.current_version_hash(root, &copy_item)?.ok_or_else(|| {
                ResolveConflictError::NotResolvable("the copy is no longer shown".into())
            })?;
            let mut change = request(root, &original_item, view_of(repo, root, &original_item)?);
            change.restore_from = Some(ProviderRestoreSource {
                path: copy_path.to_string(),
                version_hash: version.0.to_vec(),
            });
            let response = apply(state, change).await?;
            if !response.ok {
                return Err(refusal(&response, &original));
            }
            Ok(PathBuf::from(original))
        }
        ConflictChoice::KeepBoth => {
            for n in 1u32.. {
                let target = other_version_path(&original, n);
                if repo.item_for_path(root, &target)?.is_some() {
                    continue;
                }
                let name = target.rsplit('/').next().unwrap_or(&target).to_string();
                let mut change = request(root, &copy_item, view_of(repo, root, &copy_item)?);
                change.name = Some(name);
                let response = apply(state, change).await?;
                if response.ok {
                    return Ok(PathBuf::from(target));
                }
                if ProviderApplyFailure::try_from(response.failure)
                    == Ok(ProviderApplyFailure::NameCollision)
                {
                    continue;
                }
                return Err(refusal(&response, copy_path));
            }
            unreachable!("the name counter does not run out before a free name")
        }
    }
}
