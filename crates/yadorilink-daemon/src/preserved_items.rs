//! What a rebootstrap set aside for the user: versions another device wrote that the replacing
//! state does not contain (recovery items), and this device's own changes that could not be
//! replayed. They are kept until the user acts: a version can be restored as one ordinary new
//! write or discarded; nothing here deletes anything on its own. The store belongs to the
//! device, not to a group: removing a group keeps its items.

use std::sync::Arc;

use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_sqlite::local_author::LocalAuthor;
use yadorilink_sync_sqlite::native_rebootstrap::Crash;
use yadorilink_sync_sqlite::native_rebootstrap_replay::{
    held_own_units, retry_replay_unit, MachinePoint, ReplayContext, RetryError,
};
use yadorilink_sync_sqlite::native_recovery_items::{
    complete_unavailable_item, discard_recovery_item, groups_with_preserved_data,
    list_recovery_items, restore_recovery_item, unavailable_items, ItemContent, ItemKind,
    RestoreError,
};
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::daemon_state::DaemonState;
use crate::native_rebootstrap::{DaemonContent, RECOVERY_FETCH_PASS_CAP};

/// The default total size of recovery items above which status warns.
pub const RECOVERY_ITEMS_WARN_BYTES_DEFAULT: u64 = 1 << 30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreservedKind {
    /// A version of another device that the replacing state does not contain.
    RemoteOnly,
    /// A version above the cutoff at which the replacing state closes its author.
    BeyondClosureCutoff,
    /// An edit made during a rebootstrap's freeze to a path whose original was removed.
    LateEdit,
    /// Own changes of this device that were not replayed on top of the replacing state.
    OwnUnit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservedItem {
    pub kind: PreservedKind,
    pub group_id: String,
    /// The group is no longer linked on this device.
    pub group_removed: bool,
    /// The item's id; for an own unit, `<recovery id>:<unit>`.
    pub item_id: String,
    /// The path of a version; the first path of an own unit.
    pub path: String,
    /// Every path an own unit touches.
    pub paths: Vec<String>,
    /// `complete`, `unavailable` or `record_unavailable`; empty for an own unit.
    pub content: String,
    pub size: u64,
    pub blocks_held: u32,
    pub blocks_total: u32,
    /// For an own unit: the recovery area that holds its signed deltas and file copies.
    pub recovery_id: String,
    /// For an own unit: its originals were moved out of the folder into that area.
    pub originals_quarantined: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreservedSummary {
    pub total: u32,
    pub content_unavailable: u32,
    pub record_unavailable: u32,
    pub bytes: u64,
    pub unreplayed_own_units: u32,
    pub warn_bytes: u64,
    /// The total size of the items is above `warn_bytes`.
    pub warn: bool,
    /// Originals a rebootstrap kept under a claim. A count only: the sizes need the files, so
    /// they are in the listing, not on the status path.
    pub retained_originals: u32,
}

/// An original a rebootstrap kept instead of unlinking, for the user's listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedItem {
    pub group_id: String,
    pub group_removed: bool,
    /// The path the original had in the folder.
    pub path: String,
    pub recovery_id: String,
    /// The bytes it takes, `0` when `reachable` is false.
    pub size: u64,
    /// Whether the folder is watched, so the kept object can be reached to measure or release.
    pub reachable: bool,
}

/// The originals the device keeps under a claim, of every group.
pub async fn list_retained(state: &Arc<DaemonState>) -> Result<Vec<RetainedItem>, PreservedError> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || list_retained_blocking(&state))
        .await
        .map_err(|e| PreservedError::Failed(e.to_string()))?
}

fn list_retained_blocking(state: &Arc<DaemonState>) -> Result<Vec<RetainedItem>, PreservedError> {
    use yadorilink_sync_sqlite::native_rebootstrap_retained::{
        groups_with_retained_originals, retained_originals,
    };
    let linked = linked_groups(state);
    let rows = state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            let mut rows = Vec::new();
            for group in groups_with_retained_originals(conn)? {
                for original in retained_originals(conn, &group)? {
                    rows.push((group.clone(), original));
                }
            }
            Ok(rows)
        })
        .map_err(PreservedError::from)?;
    Ok(rows
        .into_iter()
        .map(|(group, original)| {
            let size = crate::native_rebootstrap::retained_size(state, &group, &original);
            RetainedItem {
                group_removed: !linked.contains(&group.0),
                group_id: group.0,
                path: original.path,
                recovery_id: original.recovery_id,
                size: size.unwrap_or(0),
                reachable: size.is_some(),
            }
        })
        .collect())
}

/// Tries to release the retained originals of `group`; what cannot be proved safe stays. One
/// outcome per original, by path. The group must be one this device has a folder or retained
/// originals for.
pub async fn release_retained(
    state: &Arc<DaemonState>,
    group: &str,
) -> Result<
    Vec<(String, yadorilink_sync_sqlite::native_rebootstrap_retained::RetainedOutcome)>,
    PreservedError,
> {
    use crate::native_rebootstrap::RebootstrapError;
    let known = linked_groups(state).iter().any(|g| g == group)
        || list_retained(state).await?.iter().any(|item| item.group_id == group);
    if !known {
        return Err(PreservedError::NotFound);
    }
    let (state, group) = (state.clone(), FolderGroupId(group.to_owned()));
    tokio::task::spawn_blocking(move || {
        crate::native_rebootstrap::clean_up_retained_originals(&state, &group)
    })
    .await
    .map_err(|e| PreservedError::Failed(e.to_string()))?
    .map(|outcomes| {
        outcomes.into_iter().map(|(original, outcome)| (original.path, outcome)).collect()
    })
    .map_err(|error| match error {
        RebootstrapError::Busy => PreservedError::Busy,
        other => PreservedError::Failed(other.to_string()),
    })
}

#[derive(Debug)]
pub enum PreservedError {
    NotFound,
    /// A rebootstrap of the group is running.
    Busy,
    /// This device may not author into the group now (a viewer, revoked, or the group removed).
    NotAWriter,
    /// The item holds no version record.
    RecordUnavailable,
    /// The item holds the record but its bytes cannot be obtained.
    ContentUnavailable,
    Failed(String),
}

impl std::fmt::Display for PreservedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no such preserved item"),
            Self::Busy => {
                write!(f, "a rebootstrap of this group is running; try again when it ends")
            }
            Self::NotAWriter => write!(f, "this device may not write to the group"),
            Self::RecordUnavailable => {
                write!(f, "the item holds no record of the version, so it cannot be restored")
            }
            Self::ContentUnavailable => {
                write!(f, "the version's content is not available from any connected device")
            }
            Self::Failed(why) => write!(f, "{why}"),
        }
    }
}

impl From<SyncSqliteError> for PreservedError {
    fn from(error: SyncSqliteError) -> Self {
        match error {
            SyncSqliteError::GroupFrozen { .. } => Self::Busy,
            other => Self::Failed(other.to_string()),
        }
    }
}

fn linked_groups(state: &DaemonState) -> Vec<String> {
    state
        .replica_coordinator
        .link_repository()
        .list_links()
        .map(|links| links.into_iter().map(|link| link.group_id).collect())
        .unwrap_or_default()
}

/// Everything the device keeps for the user: the items and the units not replayed, of every
/// group including removed ones.
pub async fn list(state: &Arc<DaemonState>) -> Result<Vec<PreservedItem>, PreservedError> {
    let state = state.clone();
    tokio::task::spawn_blocking(move || list_blocking(&state))
        .await
        .map_err(|e| PreservedError::Failed(e.to_string()))?
}

fn list_blocking(state: &Arc<DaemonState>) -> Result<Vec<PreservedItem>, PreservedError> {
    let linked = linked_groups(state);
    let (items_root, recovery_root) = (
        crate::device_config::recovery_items_root_of(state.config_dir(), &state.device_id),
        crate::device_config::recovery_root_of(state.config_dir(), &state.device_id),
    );
    let mut out = Vec::new();
    state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            for group in groups_with_preserved_data(conn)? {
                let removed = !linked.contains(&group.0);
                let unavailable: std::collections::BTreeMap<String, FileVersion> =
                    unavailable_items(conn, &items_root, &group)?
                        .into_iter()
                        .map(|(item, record)| (item.item_id, record))
                        .collect();
                for item in list_recovery_items(conn, &group)? {
                    let held = item.retained_blocks.len() as u32;
                    let total = unavailable
                        .get(&item.item_id)
                        .map_or(held, |record| record.blocks.len() as u32);
                    out.push(PreservedItem {
                        kind: match item.kind {
                            ItemKind::RemoteOnly => PreservedKind::RemoteOnly,
                            ItemKind::BeyondClosureCutoff => PreservedKind::BeyondClosureCutoff,
                            ItemKind::LateEdit => PreservedKind::LateEdit,
                        },
                        group_id: group.0.clone(),
                        group_removed: removed,
                        item_id: item.item_id,
                        path: item.path.0,
                        paths: Vec::new(),
                        content: content_name(item.content).into(),
                        size: item.size,
                        blocks_held: held,
                        blocks_total: total,
                        recovery_id: item.source_recovery_id,
                        originals_quarantined: false,
                    });
                }
                for unit in held_own_units(conn, &recovery_root, &group)? {
                    out.push(PreservedItem {
                        kind: PreservedKind::OwnUnit,
                        group_id: group.0.clone(),
                        group_removed: removed,
                        item_id: format!("{}:{}", unit.recovery_id, unit.unit),
                        path: unit.paths.first().cloned().unwrap_or_default(),
                        paths: unit.paths,
                        content: String::new(),
                        size: 0,
                        blocks_held: 0,
                        blocks_total: 0,
                        recovery_id: unit.recovery_id,
                        originals_quarantined: unit.originals_quarantined,
                    });
                }
            }
            Ok(())
        })
        .map_err(PreservedError::from)?;
    Ok(out)
}

fn content_name(content: ItemContent) -> &'static str {
    match content {
        ItemContent::Complete => "complete",
        ItemContent::Unavailable => "unavailable",
        ItemContent::RecordUnavailable => "record_unavailable",
    }
}

/// What `status` reports about the device's preserved data.
pub fn summary(state: &Arc<DaemonState>) -> PreservedSummary {
    let mut summary = PreservedSummary {
        warn_bytes: state.tuning().recovery_items_warn_bytes,
        ..Default::default()
    };
    let Ok(items) = list_blocking(state) else { return summary };
    for item in items {
        match item.kind {
            PreservedKind::OwnUnit => summary.unreplayed_own_units += 1,
            _ => {
                summary.total += 1;
                summary.bytes += item.size;
                match item.content.as_str() {
                    "unavailable" => summary.content_unavailable += 1,
                    "record_unavailable" => summary.record_unavailable += 1,
                    _ => {}
                }
            }
        }
    }
    summary.warn = summary.bytes > summary.warn_bytes;
    summary.retained_originals = state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::native_rebootstrap_retained::count_retained_originals(conn)
        })
        .unwrap_or(0);
    summary
}

/// Deletes one item: its row, then its files. The only thing that ever does.
pub async fn discard(
    state: &Arc<DaemonState>,
    group: &str,
    item_id: &str,
) -> Result<(), PreservedError> {
    let (db, group, item_id) =
        (state.replica_coordinator.database(), FolderGroupId(group.to_owned()), item_id.to_owned());
    let items_root =
        crate::device_config::recovery_items_root_of(state.config_dir(), &state.device_id);
    let found = tokio::task::spawn_blocking(move || {
        db.write::<_, SyncSqliteError>(|conn| {
            discard_recovery_item(conn, &items_root, &group, &item_id)
        })
    })
    .await
    .map_err(|e| PreservedError::Failed(e.to_string()))??;
    if found {
        Ok(())
    } else {
        Err(PreservedError::NotFound)
    }
}

/// Fetches the missing blocks of every item of `group` whose bytes are incomplete, from the
/// connected peers within a time cap, and completes the ones that arrived whole. Best effort;
/// an item that cannot be completed stays as it is.
pub async fn complete_unavailable_items(state: &Arc<DaemonState>, group: &FolderGroupId) {
    let items_root =
        crate::device_config::recovery_items_root_of(state.config_dir(), &state.device_id);
    let pending = {
        let (db, group, root) =
            (state.replica_coordinator.database(), group.clone(), items_root.clone());
        match tokio::task::spawn_blocking(move || {
            db.read::<_, SyncSqliteError>(|conn| unavailable_items(conn, &root, &group))
        })
        .await
        {
            Ok(Ok(pending)) => pending,
            _ => return,
        }
    };
    if pending.is_empty() {
        return;
    }
    let content = DaemonContent::for_group(state, group, RECOVERY_FETCH_PASS_CAP);
    for (item, record) in pending {
        if record.meta.record_kind != RecordKind::File {
            continue;
        }
        content.fetch_missing(&record).await;
        // Whether the blocks arrived whole is decided here; the stream itself is opened inside
        // the write, so a retried write streams afresh.
        if !matches!(content.open_held(&record), Ok(Some(_))) {
            continue;
        }
        let content = content.clone();
        let (db, group, root) =
            (state.replica_coordinator.database(), group.clone(), items_root.clone());
        let id = item.item_id.clone();
        let completed = tokio::task::spawn_blocking(move || {
            db.write::<_, SyncSqliteError>(move |conn| {
                let held =
                    content.open_held(&record).map_err(SyncSqliteError::CorruptState)?.ok_or_else(
                        || SyncSqliteError::CorruptState("the blocks are no longer held".into()),
                    )?;
                complete_unavailable_item(conn, &root, &group, &id, held)
                    .map_err(|e| SyncSqliteError::CorruptState(format!("{e:?}")))
            })
        })
        .await;
        if !matches!(completed, Ok(Ok(()))) {
            tracing::warn!(item = %item.item_id, "recovery item: could not complete it from the fetched blocks");
        }
    }
}

/// Restores a version item as one ordinary new write at its original path, with a new
/// identity: the original author and dot are not restored. The item stays.
pub async fn restore(
    state: &Arc<DaemonState>,
    group: &str,
    item_id: &str,
) -> Result<(), PreservedError> {
    let group = FolderGroupId(group.to_owned());
    if !linked_groups(state).contains(&group.0)
        || !crate::native_rebootstrap::is_writer(state, &group)
    {
        return Err(PreservedError::NotAWriter);
    }
    // Missing blocks are asked for first: a restore completes an unavailable item when it can.
    let known = {
        let (db, g) = (state.replica_coordinator.database(), group.clone());
        tokio::task::spawn_blocking(move || {
            db.read::<_, SyncSqliteError>(|conn| list_recovery_items(conn, &g))
        })
        .await
        .map_err(|e| PreservedError::Failed(e.to_string()))??
    };
    let item = known.into_iter().find(|i| i.item_id == item_id).ok_or(PreservedError::NotFound)?;
    if item.content == ItemContent::Unavailable {
        complete_unavailable_items(state, &group).await;
    }
    let (state_for_write, group_for_write, item_id) =
        (state.clone(), group.clone(), item_id.to_owned());
    tokio::task::spawn_blocking(move || {
        restore_blocking(&state_for_write, &group_for_write, &item_id)
    })
    .await
    .map_err(|e| PreservedError::Failed(e.to_string()))??;
    // The restored write is published like any local change, and the materializer places it.
    state.flush_pending_native_checkpoint_for_group(group.as_str()).await;
    state.replica_coordinator.notify_materialization_wake();
    Ok(())
}

/// Stores a preserved version's whole content in the block store, block by block, and records
/// in the caller's open transaction that the group obtained them. Every block must hash to the
/// name its record gives it: nothing is stored that the record would not read back. The caller
/// holds the write-activity guard, so no sweep deletes the blocks before the head that
/// references them is committed.
fn import_version(
    state: &DaemonState,
    conn: &rusqlite::Connection,
    group: &FolderGroupId,
    version: &FileVersion,
    bytes: &mut dyn std::io::Read,
) -> Result<(), String> {
    use std::io::Read;
    let mut hashes = Vec::new();
    for block in &version.blocks {
        // Read as it arrives, so a record that claims a block larger than the stream holds
        // allocates only what the stream yields.
        let mut part = Vec::new();
        bytes.take(u64::from(block.size)).read_to_end(&mut part).map_err(|e| e.to_string())?;
        if part.len() != block.size as usize {
            return Err("the bytes are shorter than the version".into());
        }
        let stored = state.block_store.put(&part).map_err(|e| e.to_string())?;
        if stored != hex::encode(&block.hash.0) {
            return Err("a block of the preserved bytes does not hash to its record".into());
        }
        // A block that was already stored is reused by name: read it back, which re-hashes it, so
        // a damaged copy fails the retry instead of being referenced by the new head.
        state.block_store.get(&stored).map_err(|e| e.to_string())?;
        hashes.push(block.hash.0.clone());
    }
    if bytes.read(&mut [0u8; 1]).map_err(|e| e.to_string())? != 0 {
        return Err("the bytes are longer than the version".into());
    }
    crate::replica_coordinator::ReplicaCoordinator::record_recovered_block_provenance_in_tx(
        conn,
        group.as_str(),
        &hashes,
    )
    .map_err(|e| e.to_string())
}

fn restore_blocking(
    state: &Arc<DaemonState>,
    group: &FolderGroupId,
    item_id: &str,
) -> Result<(), PreservedError> {
    // Taken before the transaction: a running sweep is waited for, and none starts until the
    // restored write is committed.
    let _write_activity = state.begin_write_activity();
    let key = state
        .device_signing_key()
        .ok_or_else(|| PreservedError::Failed("this device has no signing key".into()))?;
    let author = state
        .replica_coordinator
        .open_local_author(&state.device_id, key)
        .map_err(|e| PreservedError::Failed(e.to_string()))?;
    let items_root =
        crate::device_config::recovery_items_root_of(state.config_dir(), &state.device_id);
    let db = state.replica_coordinator.database();
    let mut failure: Option<RestoreError> = None;
    state
        .replica_coordinator
        .with_local_author(&author, |current| {
            failure = None;
            db.write::<_, SyncSqliteError>(|conn| {
                let local = LocalAuthor::of_key(current);
                let mut import = |version: &FileVersion, bytes: &mut dyn std::io::Read| {
                    import_version(state, conn, group, version, bytes)
                };
                match restore_recovery_item(conn, &items_root, group, item_id, &local, &mut import)
                {
                    Ok(_) => Ok(()),
                    Err(RestoreError::Store(error)) => Err(error),
                    Err(other) => {
                        failure = Some(other);
                        Ok(())
                    }
                }
            })
        })
        .map_err(PreservedError::from)?;
    match failure {
        None => Ok(()),
        Some(RestoreError::NotFound) => Err(PreservedError::NotFound),
        Some(RestoreError::RecordUnavailable) => Err(PreservedError::RecordUnavailable),
        Some(RestoreError::ContentUnavailable) => Err(PreservedError::ContentUnavailable),
        Some(RestoreError::Corrupt(why) | RestoreError::Import(why)) => {
            Err(PreservedError::Failed(why))
        }
        Some(RestoreError::Store(error)) => Err(error.into()),
    }
}

/// Re-submits an own unit a rebootstrap held back (`item_id` is `<recovery id>:<unit>`) to the
/// replay's unit scheduler, as this device's current incarnation. The device must be a writer of
/// the group now; the unit is resolved in the transaction that authors it.
pub async fn retry(
    state: &Arc<DaemonState>,
    group: &str,
    item_id: &str,
) -> Result<(), PreservedError> {
    retry_with_hook(state, group, item_id, Box::new(|_| Ok(()))).await
}

/// The point hook of a retry, for tests that stop it at a boundary.
pub type RetryHook = Box<dyn FnMut(MachinePoint) -> Result<(), Crash> + Send>;

/// [`retry`] with a hook called at the replay machine's points.
pub async fn retry_with_hook(
    state: &Arc<DaemonState>,
    group: &str,
    item_id: &str,
    hook: RetryHook,
) -> Result<(), PreservedError> {
    let group = FolderGroupId(group.to_owned());
    let (recovery_id, unit) = item_id
        .rsplit_once(':')
        .and_then(|(id, unit)| Some((id.to_owned(), unit.parse::<usize>().ok()?)))
        .ok_or(PreservedError::NotFound)?;
    if !linked_groups(state).contains(&group.0) {
        return Err(PreservedError::NotAWriter);
    }
    let (state_for_write, group_for_write) = (state.clone(), group.clone());
    tokio::task::spawn_blocking(move || {
        retry_blocking(&state_for_write, &group_for_write, &recovery_id, unit, hook)
    })
    .await
    .map_err(|e| PreservedError::Failed(e.to_string()))??;
    state.flush_pending_native_checkpoint_for_group(group.as_str()).await;
    state.replica_coordinator.notify_materialization_wake();
    Ok(())
}

fn retry_blocking(
    state: &Arc<DaemonState>,
    group: &FolderGroupId,
    recovery_id: &str,
    unit: usize,
    mut hook: RetryHook,
) -> Result<(), PreservedError> {
    // The preserved bytes enter the block store and are referenced by the authored heads under
    // one write-activity guard, taken before the transaction: no sweep deletes them in between.
    let _write_activity = state.begin_write_activity();
    let key = state
        .device_signing_key()
        .ok_or_else(|| PreservedError::Failed("this device has no signing key".into()))?;
    let author = state
        .replica_coordinator
        .open_local_author(&state.device_id, key)
        .map_err(|e| PreservedError::Failed(e.to_string()))?;
    let authority =
        crate::native_rebootstrap::DaemonAuthority { state: state.clone(), group: group.clone() };
    let recovery_root =
        crate::device_config::recovery_root_of(state.config_dir(), &state.device_id);
    let db = state.replica_coordinator.database();
    let mut failure: Option<RetryError> = None;
    state
        .replica_coordinator
        .with_local_author(&author, |current| {
            failure = None;
            db.write::<_, SyncSqliteError>(|conn| {
                let local = LocalAuthor::of_key(current);
                let ctx = ReplayContext {
                    recovery_root: &recovery_root,
                    authority: &authority,
                    author: &local,
                    now_unix: crate::native_rebootstrap::now_unix(),
                };
                let mut import = |version: &FileVersion, bytes: &mut dyn std::io::Read| {
                    import_version(state, conn, group, version, bytes)
                };
                match retry_replay_unit(
                    conn,
                    &ctx,
                    group,
                    recovery_id,
                    unit,
                    &mut import,
                    &mut *hook,
                ) {
                    Ok(_) => Ok(()),
                    Err(RetryError::Store(error)) => Err(error),
                    Err(other) => {
                        failure = Some(other);
                        Ok(())
                    }
                }
            })
        })
        .map_err(PreservedError::from)?;
    match failure {
        None => Ok(()),
        Some(RetryError::NotHeld) => Err(PreservedError::NotFound),
        Some(RetryError::NotAWriter) => Err(PreservedError::NotAWriter),
        Some(RetryError::RebootstrapRunning) => Err(PreservedError::Busy),
        Some(RetryError::Refused) => Err(PreservedError::Failed(
            "the group's current state refuses these changes; they stay held".into(),
        )),
        Some(RetryError::Blocked(reason)) => Err(PreservedError::Failed(format!("{reason:?}"))),
        Some(RetryError::Import(why)) => Err(PreservedError::Failed(why)),
        Some(RetryError::Crashed) => Err(PreservedError::Failed("interrupted".into())),
        Some(RetryError::Store(error)) => Err(error.into()),
    }
}

/// The groups whose rebootstrap is replacing their state now or is waiting to be continued.
pub fn rebootstrapping_groups(state: &Arc<DaemonState>) -> Vec<String> {
    let linked = linked_groups(state);
    state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            let mut groups = Vec::new();
            for group in &linked {
                let group = FolderGroupId(group.clone());
                if yadorilink_sync_sqlite::native_rebootstrap::rebootstrap_status(conn, &group)?
                    .is_some()
                {
                    groups.push(group.0);
                }
            }
            Ok(groups)
        })
        .unwrap_or_default()
}
