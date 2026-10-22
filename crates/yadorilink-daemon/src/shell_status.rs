//! Resolves an absolute filesystem path (as a shell extension would
//! report it) to a sync status, per the `shell-integration` spec's icon
//! overlay states.

use std::path::{Path, PathBuf};

use yadorilink_ipc_proto::shellipc::SyncState as ShellSyncState;

use crate::replica_coordinator::ReplicaCoordinator;

/// Canonicalizes an absolute `path`, resolving symlinks in its longest
/// existing prefix and rejoining any missing tail unchanged — e.g. a file
/// that's indexed as synced but not yet materialized to disk, or a
/// `Removed` event's path (and its removed parent directories), which are
/// already gone by the time they are processed.
///
/// Returns `None` (so the caller treats the path as matching nothing) when
/// the path cannot be resolved without guessing: it is relative, its missing
/// tail contains `.`/`..`, the first missing component is not plainly
/// absent (a dangling symlink, a symlink loop, an unreadable entry), or the
/// deepest existing ancestor is not a directory.
fn canonicalize_best_effort(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    if let Ok(resolved) = path.canonicalize() {
        return Some(resolved);
    }
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut current = path;
    loop {
        let name = match current.components().next_back()? {
            std::path::Component::Normal(name) => name,
            _ => return None,
        };
        // The component being dropped must be plainly absent, not a link we
        // cannot follow.
        match std::fs::symlink_metadata(current) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => return None,
        }
        tail.push(name);
        current = current.parent()?;
        if let Ok(mut resolved) = current.canonicalize() {
            if !resolved.is_dir() {
                return None;
            }
            resolved.extend(tail.iter().rev());
            return Some(resolved);
        }
    }
}

/// Resolves an absolute filesystem path to the `(group_id, relative_path)`
/// pair the sync index actually keys files by, per whichever linked
/// folder it falls under — shared by `resolve_status` and the shell-IPC
/// hydration request (`shell_ipc`'s handling of `HydrateRequest`), both of
/// which only ever see an absolute path, never a group_id directly.
///
/// Matches `local_change.rs`'s `process_event`: canonicalizes both the
/// stored link root *and* the queried path before comparing. Shell
/// extensions (and OS-level watchers, per `local_change.rs`) tend to
/// report fully-resolved paths (e.g. macOS's `/private/var/...` for what
/// looks like `/var/...`), while a stored `local_path` may still be in
/// whatever form it was linked with.
pub fn resolve_group_and_rel_path(
    sync_state: &ReplicaCoordinator,
    absolute_path: &str,
) -> Option<(String, String)> {
    let canonical_query = canonicalize_best_effort(Path::new(absolute_path))?;

    // Read-only overlay lookup: an unreadable link table degrades to "not a
    // synced path" (no overlay), which is the safe direction here. Surfaced
    // rather than silently collapsed -- the same shape on a write path would be
    // a data-loss bug, so it must never look routine.
    let links = sync_state.link_repository().list_links().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "cannot read link table; shell overlay will show no synced paths");
        Vec::new()
    });
    let mut matches: Vec<(&yadorilink_replica_domain::session_state::FolderLink, PathBuf)> = links
        .iter()
        .filter(|l| !l.orphaned)
        .filter_map(|l| Some((l, canonicalize_best_effort(Path::new(l.folder_path()?))?)))
        .filter(|(_, root)| canonical_query.starts_with(root))
        .collect();
    matches.sort_by_key(|(_, root)| std::cmp::Reverse(root.components().count()));
    let (link, canonical_root) = matches.first()?;
    let best_depth = canonical_root.components().count();
    if matches.iter().skip(1).any(|(_, root)| root.components().count() == best_depth) {
        tracing::warn!(
            "a path resolves equally well to multiple linked roots; refusing to choose a sync group"
        );
        return None;
    }

    let rel_path = canonical_query.strip_prefix(canonical_root).ok()?;
    let rel_path = rel_path.to_string_lossy().replace('\\', "/");
    Some((link.group_id.clone(), rel_path))
}

/// Resolves a path inside a provider folder's local location to `(group_id, relative_path)`.
///
/// A provider root has no directory of its own that the daemon reads (and no filesystem authority).
/// On macOS the OS shows it at `<home>/Library/CloudStorage/<extension name>-<display name>`, so
/// the root is found by the display name that ends that first component, never by comparing
/// against a stored path. On Windows the Cloud Files host records where it put each sync root
/// (`windows_sync_roots`), and the path is matched against those places.
pub fn resolve_provider_group_and_rel_path(
    sync_state: &ReplicaCoordinator,
    absolute_path: &str,
) -> Option<(String, String)> {
    #[cfg(windows)]
    {
        let (root_id, rel_path) = crate::windows_sync_roots::locate(absolute_path)?;
        let group_id = sync_state.provider_repository().group_of_root(&root_id).ok().flatten()?;
        Some((group_id, rel_path))
    }
    #[cfg(not(windows))]
    {
        resolve_cloud_storage_path(sync_state, absolute_path)
    }
}

#[cfg(not(windows))]
fn resolve_cloud_storage_path(
    sync_state: &ReplicaCoordinator,
    absolute_path: &str,
) -> Option<(String, String)> {
    let path = Path::new(absolute_path);
    let mut components = path.components();
    components.find(|c| c.as_os_str() == "CloudStorage")?;
    let location = components.next()?.as_os_str().to_string_lossy().into_owned();
    let rel_path: Vec<String> =
        components.map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    let roots = sync_state.provider_repository().list_declared_roots().ok()?;
    let mut claimed = roots.iter().filter(|root| {
        location.strip_suffix(root.display_name.as_str()).is_some_and(|p| p.ends_with('-'))
    });
    let root = claimed.next()?;
    if claimed.next().is_some() {
        tracing::warn!(
            "a path names more than one provider folder; refusing to choose a sync group"
        );
        return None;
    }
    Some((root.group_id.clone(), rel_path.join("/")))
}

/// The one badge a shell draws for a path: the single place the online-only rule lives. An error
/// is never hidden; otherwise a path whose local state is known, whose current content is not
/// here and that nothing is moving is online-only; otherwise the sync state decides.
pub fn shell_badge(
    state: ShellSyncState,
    local: Option<&yadorilink_ipc_proto::shellipc::LocalState>,
) -> yadorilink_ipc_proto::shellipc::ShellBadge {
    use yadorilink_ipc_proto::shellipc::{LocalTransition, ShellBadge};
    if state == ShellSyncState::Error {
        return ShellBadge::Error;
    }
    if state != ShellSyncState::Unspecified
        && local
            .is_some_and(|l| !l.current_content_present && l.transition() == LocalTransition::None)
    {
        return ShellBadge::OnlineOnly;
    }
    match state {
        ShellSyncState::Synced => ShellBadge::Synced,
        ShellSyncState::Syncing => ShellBadge::Syncing,
        ShellSyncState::Pending => ShellBadge::Pending,
        ShellSyncState::Error => ShellBadge::Error,
        ShellSyncState::Unspecified => ShellBadge::Unspecified,
    }
}

/// Whether Pause, Resume and Free Up Space can apply to the path: the daemon has a sync state
/// for it (a file or folder under a linked folder). A path it cannot place, and any failure to
/// resolve the status (`Unspecified`), offers nothing.
pub fn actions_available(state: ShellSyncState) -> bool {
    state != ShellSyncState::Unspecified
}

/// A path's sync status, with the reason the path is in that state when
/// the state alone does not say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellStatus {
    pub state: ShellSyncState,
    pub detail: Option<String>,
}

impl ShellStatus {
    fn of(state: ShellSyncState) -> Self {
        Self { state, detail: None }
    }
}

pub fn resolve_status(sync_state: &ReplicaCoordinator, absolute_path: &str) -> ShellSyncState {
    resolve_status_detail(sync_state, absolute_path).state
}

/// The status of a file or directory under a linked folder.
///
/// A directory is not always an entry of its own. The link root never is;
/// a directory that only holds synced files has no row; and an explicit
/// directory a peer deleted while a file below it still lives keeps a
/// deleted row. Each of those -- and a live explicit directory -- takes
/// the aggregate status of what is indexed live below it: an error when a
/// conflict copy is among it (the one per-file status worse than synced an
/// indexed row carries), synced otherwise, rather than pending or unknown.
/// A path's own live entry decides first, so a stale retained record never
/// masks it. A directory a delete left on disk because it holds local
/// content this device never synced is settled too: it takes the same
/// aggregate status, and the detail says why it is still there.
pub fn resolve_status_detail(sync_state: &ReplicaCoordinator, absolute_path: &str) -> ShellStatus {
    let Some((group_id, rel_path)) = resolve_group_and_rel_path(sync_state, absolute_path) else {
        return ShellStatus::of(ShellSyncState::Unspecified);
    };
    let rel_path = rel_path.trim_end_matches('/');
    if rel_path.is_empty() {
        return ShellStatus::of(aggregate_status(sync_state, &group_id, rel_path));
    }
    let own_row = match sync_state.file_index_repository().get_file(&group_id, rel_path) {
        Ok(row) => row,
        Err(_) => return ShellStatus::of(ShellSyncState::Unspecified),
    };
    if let Some(record) = own_row.as_ref().filter(|record| !record.deleted) {
        if yadorilink_replica_domain::conflict::is_conflict_copy_path(&record.path) {
            return ShellStatus::of(ShellSyncState::Error);
        }
        return ShellStatus::of(aggregate_status(sync_state, &group_id, rel_path));
    }
    match sync_state.sqlite().retained_directory_reason(&group_id, rel_path) {
        Ok(Some(reason)) => {
            return ShellStatus {
                state: aggregate_status(sync_state, &group_id, rel_path),
                detail: Some(reason),
            };
        }
        Ok(None) => {}
        Err(_) => return ShellStatus::of(ShellSyncState::Unspecified),
    }
    match sync_state.file_index_repository().has_live_descendant_row(&group_id, rel_path) {
        Ok(true) => ShellStatus::of(aggregate_status(sync_state, &group_id, rel_path)),
        // A deleted entry with nothing live below it has no status.
        Ok(false) if own_row.is_some() => ShellStatus::of(ShellSyncState::Unspecified),
        // Under a linked folder but not indexed yet — either brand new
        // (about to be picked up by the watcher) or not yet reconciled
        // with peers.
        Ok(false) => ShellStatus::of(ShellSyncState::Pending),
        Err(_) => ShellStatus::of(ShellSyncState::Unspecified),
    }
}

/// The status a directory at `rel_path` (the link root when empty) takes
/// from what is indexed live below it.
fn aggregate_status(
    sync_state: &ReplicaCoordinator,
    group_id: &str,
    rel_path: &str,
) -> ShellSyncState {
    match sync_state.file_index_repository().has_live_conflict_copy_descendant(group_id, rel_path) {
        Ok(true) => ShellSyncState::Error,
        Ok(false) => ShellSyncState::Synced,
        Err(_) => ShellSyncState::Unspecified,
    }
}

/// Whether the object at `absolute_path` holds the content of the version its
/// row names now: anything but a regular file is, and a regular file is only
/// where a usable proof names the current version. `false` for a path that is
/// not under a linked folder.
pub fn resolve_content_is_current(sync_state: &ReplicaCoordinator, absolute_path: &str) -> bool {
    let Some((group_id, rel_path)) = resolve_group_and_rel_path(sync_state, absolute_path) else {
        return false;
    };
    let kind = sync_state
        .file_index_repository()
        .get_record_kind(&group_id, &rel_path)
        .ok()
        .flatten()
        .unwrap_or_default();
    kind != yadorilink_replica_domain::file::RecordKind::File
        || sync_state.local_copy_names_current_version(&group_id, &rel_path).unwrap_or(false)
}

/// How the user's pauses apply to `absolute_path`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ItemPause {
    /// This exact item is paused (the link root counts as the empty item): Resume applies.
    pub paused: bool,
    /// An item strictly above it is paused, whether or not it is paused itself: resuming only
    /// lifts the pause of the exact item, so neither Pause nor Resume would change anything.
    pub by_ancestor: bool,
}

/// The user pauses that apply to `absolute_path` (the held paths of a rebootstrap are not a user
/// pause). All false for a path not under a linked folder, and when the paused items cannot be
/// read: the menu then offers Pause, which is idempotent, rather than a Resume that may not apply.
pub fn resolve_item_pause(sync_state: &ReplicaCoordinator, absolute_path: &str) -> ItemPause {
    let Some((group_id, rel_path)) = resolve_group_and_rel_path(sync_state, absolute_path) else {
        return ItemPause::default();
    };
    let rel_path = rel_path.trim_end_matches('/');
    let Ok(items) = sync_state.paused_item_repository().list(&group_id) else {
        return ItemPause::default();
    };
    ItemPause {
        paused: items.iter().any(|item| item == rel_path),
        by_ancestor: items.iter().any(|item| {
            item.is_empty() && !rel_path.is_empty()
                || rel_path.strip_prefix(item.as_str()).is_some_and(|rest| rest.starts_with('/'))
        }),
    }
}

/// What stands on this device for a path with this row state: the one place
/// the two facts the wire carries are derived. `exact` is whether a usable
/// proof names the version the row holds now; callers that could not read the
/// evidence pass `false`, so an unreadable proof is never "current".
pub(crate) fn local_presence(
    state: Option<yadorilink_replica_domain::session_state::MaterializationState>,
    exact: bool,
) -> Option<crate::application::ports::LocalPresence> {
    use crate::application::ports::{LocalPresence, LocalTransition};
    use yadorilink_replica_domain::session_state::MaterializationState as Row;
    let (object_present, current_content_present, transition) = match state? {
        Row::Remote => (false, false, LocalTransition::None),
        Row::Present => (true, exact, LocalTransition::None),
        Row::Hydrating => (false, false, LocalTransition::Hydrating),
        Row::Evicting => (true, false, LocalTransition::Evicting),
    };
    Some(LocalPresence { object_present, current_content_present, transition })
}

/// Resolves `absolute_path`'s materialization state (`on-demand-sync`
/// ) for the shell extension's placeholder/hydrated/hydrating
/// badge — `None` if the path isn't under any linked folder or isn't
/// indexed at all (e.g. an `Eager` folder's files are always `Present`
/// in practice, but report `None` rather than a state if never indexed).
pub fn resolve_materialization_state(
    sync_state: &ReplicaCoordinator,
    absolute_path: &str,
) -> Option<yadorilink_replica_domain::session_state::MaterializationState> {
    let (group_id, rel_path) = resolve_group_and_rel_path(sync_state, absolute_path)?;
    sync_state
        .materialization_state_repository()
        .get_materialization_state(&group_id, &rel_path)
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests;
