//! Reclaiming the daemon's cached blocks of a provider item the operating system no longer holds.
//!
//! A provider root keeps no working-tree copy: the OS owns the local bytes, and the daemon's block
//! store holds what it fetched to hand them over. Freeing real disk space therefore has two halves
//! that must not be confused. The OS drops its copy (the user's "Remove Download", or the daemon's
//! eviction request); this module frees the block-store half, and only with exact-version custody:
//!
//! 1. under the item's path lock, ask an authorized full replica for a durable custody lease on
//!    exactly this version (the stamp). The lock is what keeps the hold reconciler from releasing
//!    the lease while this device is about to rely on it;
//! 2. the caller does whatever it does between (asks the host to evict);
//! 3. the stamp becomes a [`VerifiedCustody`] and the coordinator re-checks the exact version, the
//!    row state, the stamp's validity and every other reference to the blocks under the exclusive
//!    physical-deletion guard before one block is removed.
//!
//! Nothing here infers anything from what is or is not on disk: the decision is the committed
//! version row, the hold table and the lease. A failure at any point keeps the blocks.

use std::sync::Arc;

use yadorilink_local_storage::BlockReclamationStore;
use yadorilink_replica_domain::file::{FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_engine::custody::{CustodyStamp, FullReplicaCustody};
use yadorilink_sync_sqlite::provider::ItemId;

use crate::application::ports::BoxFuture;
use crate::daemon_state::DaemonState;
use crate::sync_error::SyncError;

/// Why the block-store copy of an item stayed. The codes are stable: they are what a status line
/// or a CLI answer shows when "Remove local copy" freed less than the user expected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Retained {
    /// Durable custody leases are not enabled in this build, so no block is ever reclaimed.
    CustodyUnsupported,
    /// This device is a full replica of the group: it is the durable holder and keeps its blocks.
    FullReplica,
    /// No authorized full replica took a durable lease on exactly this version (none reachable,
    /// none holding it, or the group's authorization moved meanwhile).
    CustodyNotAcquired,
    /// Another operation holds the item right now.
    Busy,
    /// The item is no longer a live regular file at the version the request was about.
    VersionMoved,
    /// No block was freed: every cached block is still referenced by other content of this
    /// device, or the lease no longer backed the reclaim.
    NothingFreed,
    /// Nothing of this version is cached on this device: the item is already not downloaded.
    NotDownloaded,
    /// A process holds the file open; the OS copy and the blocks stay.
    HostBusy,
    /// The OS copy is the only complete local copy and no custody lease covers the version, so
    /// dropping it would leave nothing to open from.
    CustodyRequired,
    /// The daemon cannot yet confirm that the OS holds exactly the current content (the download
    /// has only just finished, or the content is being updated); nothing was changed.
    NotConfirmed,
    /// The host declined to drop its copy (typically the file has changes that are not shared
    /// yet); the OS copy and the blocks stay.
    HostRefused,
}

impl Retained {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::CustodyUnsupported => "custody_unsupported",
            Self::FullReplica => "full_replica",
            Self::CustodyNotAcquired => "custody_not_acquired",
            Self::Busy => "busy",
            Self::VersionMoved => "version_moved",
            Self::NothingFreed => "nothing_freed",
            Self::NotDownloaded => "not_downloaded",
            Self::HostBusy => "host_busy",
            Self::CustodyRequired => "custody_required",
            Self::NotConfirmed => "not_confirmed",
            Self::HostRefused => "host_refused",
        }
    }

    /// Whether asking again later can succeed without the user doing anything: the cause is a
    /// moment in time (a file in use, a download not yet confirmed, a change still being shared),
    /// not a standing property of the folder or the build.
    pub(crate) fn retryable(self) -> bool {
        match self {
            Self::Busy
            | Self::HostBusy
            | Self::VersionMoved
            | Self::NotConfirmed
            | Self::HostRefused
            | Self::CustodyNotAcquired
            | Self::CustodyRequired => true,
            Self::CustodyUnsupported
            | Self::FullReplica
            | Self::NothingFreed
            | Self::NotDownloaded => false,
        }
    }
}

/// What was physically freed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Reclaimed {
    pub blocks: u64,
    pub bytes: u64,
}

/// The custody lease source: production asks peers, tests supply a fake.
pub(crate) trait Custody: Send + Sync {
    /// A durable lease on exactly this version, or `None`. Called with the item's path lock held.
    fn acquire<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        version_hash: VersionHash,
        blocks: &'a [VersionBlock],
    ) -> BoxFuture<'a, Option<CustodyStamp>>;

    /// Whether `stamp` still backs a reclaim of this version.
    fn still_valid(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        stamp: &CustodyStamp,
    ) -> bool;
}

/// Leases from the connected full replicas, recorded in the durable hold table.
pub(crate) struct PeerCustody(pub(crate) Arc<DaemonState>);

impl Custody for PeerCustody {
    fn acquire<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        version_hash: VersionHash,
        blocks: &'a [VersionBlock],
    ) -> BoxFuture<'a, Option<CustodyStamp>> {
        Box::pin(self.0.acquire_custody_lease_via_peer(group_id, path, version_hash, blocks))
    }

    fn still_valid(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        stamp: &CustodyStamp,
    ) -> bool {
        FullReplicaCustody::confirmation_still_valid(&*self.0, group_id, path, version_hash, stamp)
    }
}

/// A lease already acquired, as the oracle `verify_reclaim_custody` consumes: it re-issues the
/// stamp it holds and revalidates through the source.
struct Acquired<'a> {
    custody: &'a dyn Custody,
    stamp: &'a CustodyStamp,
}

impl FullReplicaCustody for Acquired<'_> {
    fn confirm_exact_version(
        &self,
        _group_id: &str,
        _path: &str,
        _version_hash: &VersionHash,
        _blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        Some(self.stamp.clone())
    }

    fn confirmation_still_valid(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        stamp: &CustodyStamp,
    ) -> bool {
        self.custody.still_valid(group_id, path, version_hash, stamp)
    }
}

/// A lease acquired for one exact version, ready to back a reclaim.
/// How many times a reclaim waits for block writers, and how long between tries.
const RECLAIM_ATTEMPTS: usize = 100;
const RECLAIM_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// The most other placeholders sharing the item's blocks that one reclaim also takes a lease for.
const MAX_CUSTODIED_SIBLINGS: usize = 16;

/// A placeholder sharing the item's blocks, leased too so that its retained copy stops rooting
/// them. Its path lock is held for the same reason as the item's own.
struct PreparedSibling {
    group_id: String,
    path: String,
    version: FileVersion,
    stamp: CustodyStamp,
    path_guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

pub(crate) struct Prepared {
    group_id: String,
    path: String,
    version: FileVersion,
    stamp: CustodyStamp,
    siblings: Vec<PreparedSibling>,
    /// The item's path lock, held from the lease to the end of the reclaim except while it waits
    /// for block writers to finish (see [`ProviderReclaim::reclaim`]). The hold reconciler needs
    /// this lock to release the lease, so while it is held the lease cannot be released between
    /// the check that backs the reclaim and the deletion.
    path_guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

type VolumeVerdict = Arc<dyn Fn(Option<&std::path::Path>) -> bool + Send + Sync>;

pub(crate) struct ProviderReclaim {
    state: Arc<DaemonState>,
    custody: Arc<dyn Custody>,
    /// Whether the volume holding the bytes a reclaim deletes (the block store's) is durable.
    volume_durable: VolumeVerdict,
    /// Tests only: take the lease flag as on, so the paths behind it can be driven.
    #[cfg(test)]
    leases_enabled_for_test: bool,
}

impl ProviderReclaim {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        let custody = Arc::new(PeerCustody(state.clone()));
        Self::with_custody(state, custody)
    }

    pub(crate) fn with_custody(state: Arc<DaemonState>, custody: Arc<dyn Custody>) -> Self {
        Self {
            state,
            custody,
            volume_durable: Arc::new(
                yadorilink_fs_platform::durable_dir::volume_offers_durable_namespace,
            ),
            #[cfg(test)]
            leases_enabled_for_test: false,
        }
    }

    /// Tests only: the verdict of each volume, in place of the probe.
    #[cfg(test)]
    pub(crate) fn with_volume_verdict_for_test(
        mut self,
        verdict: impl Fn(Option<&std::path::Path>) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.volume_durable = Arc::new(verdict);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_leases_enabled_for_test(mut self) -> Self {
        self.leases_enabled_for_test = true;
        self.volume_durable = Arc::new(|_| true);
        self
    }

    fn leases_enabled(&self) -> bool {
        let flag = yadorilink_replica_engine::custody::REMOTE_CUSTODY_LEASES_SUPPORTED;
        // Deleting local bytes needs durable namespace changes on the volume that holds them: the
        // block store's, which may differ from the sync root's. Where that volume is not known
        // durable (Windows: the global gate closed, or the probe says Unsupported/Unknown) the
        // blocks are kept.
        flag && yadorilink_fs_platform::durable_dir::all_volumes_durable(
            &*self.volume_durable,
            &[self.state.block_store.storage_root()],
        )
    }

    /// A standing reason no block of this group is ever reclaimed (no lease support on this
    /// build or volume, or this device is a full replica): a read-only check that asks nobody.
    pub(crate) fn standing_blocker(&self, group_id: &str) -> Option<Retained> {
        if !self.leases_enabled() {
            return Some(Retained::CustodyUnsupported);
        }
        if self.state.is_local_full_replica(group_id) {
            return Some(Retained::FullReplica);
        }
        None
    }

    /// Phase 1: decides whether a reclaim can happen at all and, if so, takes the lease for the
    /// item's current version. Cheap refusals come first so no lease is asked for in vain. The
    /// returned [`Prepared`] holds the item's path lock until it is dropped.
    ///
    /// `expect` pins the version the caller decided about: a different current version is
    /// [`Retained::VersionMoved`].
    pub(crate) async fn prepare(
        &self,
        group_id: &str,
        path: &str,
        expect: Option<VersionHash>,
    ) -> Result<Prepared, Retained> {
        if let Some(why) = self.standing_blocker(group_id) {
            return Err(why);
        }
        let version = self
            .current_file_version(group_id, path)
            .filter(|version| expect.is_none_or(|expected| version.version_hash == expected))
            .ok_or(Retained::VersionMoved)?;
        let path_lock = self.state.replica_coordinator.path_lock(group_id, path);
        let Ok(path_guard) = path_lock.try_lock_owned() else {
            return Err(Retained::Busy);
        };
        let stamp =
            self.custody.acquire(group_id, path, version.version_hash, &version.blocks).await;
        // An attempt that did not end in a lease may have left a request the reconciler releases.
        self.state.nudge_custody_hold_reconciler();
        let stamp = stamp.ok_or(Retained::CustodyNotAcquired)?;
        // The lease is for `version`; if the item moved on while it was awaited, it backs nothing.
        let still_current = self
            .current_file_version(group_id, path)
            .is_some_and(|now| now.version_hash == version.version_hash);
        if !still_current {
            return Err(Retained::VersionMoved);
        }
        let siblings = self.prepare_siblings(group_id, path, &version).await;
        Ok(Prepared {
            group_id: group_id.to_owned(),
            path: path.to_owned(),
            version,
            stamp,
            siblings,
            path_guard: Some(path_guard),
        })
    }

    /// Leases for the other placeholders that share blocks with `version`. Every other copy of
    /// identical content was evicted while this one still needed the blocks, kept them, and is
    /// never visited again, so without these leases the last identical file frees nothing and a
    /// sweep cannot either (a current row roots its blocks). A sibling that is busy, over the cap
    /// or not leased simply stays a reference.
    async fn prepare_siblings(
        &self,
        group_id: &str,
        path: &str,
        version: &FileVersion,
    ) -> Vec<PreparedSibling> {
        let Ok(rows) = self
            .state
            .replica_coordinator
            .materialization_state_repository()
            .remote_rows_sharing_blocks(group_id, path, &version.blocks)
        else {
            return Vec::new();
        };
        let mut siblings = Vec::new();
        for (sibling_group, sibling_path) in rows {
            if siblings.len() >= MAX_CUSTODIED_SIBLINGS {
                break;
            }
            if self.state.is_local_full_replica(&sibling_group) {
                continue;
            }
            let Some(sibling_version) = self.current_file_version(&sibling_group, &sibling_path)
            else {
                continue;
            };
            let lock = self.state.replica_coordinator.path_lock(&sibling_group, &sibling_path);
            let Ok(guard) = lock.try_lock_owned() else {
                continue;
            };
            let stamp = self
                .custody
                .acquire(
                    &sibling_group,
                    &sibling_path,
                    sibling_version.version_hash,
                    &sibling_version.blocks,
                )
                .await;
            self.state.nudge_custody_hold_reconciler();
            let Some(stamp) = stamp else {
                continue;
            };
            if !self
                .current_file_version(&sibling_group, &sibling_path)
                .is_some_and(|now| now.version_hash == sibling_version.version_hash)
            {
                continue;
            }
            siblings.push(PreparedSibling {
                group_id: sibling_group,
                path: sibling_path,
                version: sibling_version,
                stamp,
                path_guard: Some(guard),
            });
        }
        siblings
    }

    /// Phase 3: frees the blocks the lease allows. The coordinator re-checks everything under the
    /// exclusive deletion guard; a result of zero blocks is not an error.
    ///
    /// The deletion guard is taken without waiting while the item's lock is held, so the lease
    /// cannot be released between its check and the deletion. A hydration of the item holds a
    /// block-reference write while it waits for that lock, so when writers are active the lock is
    /// given up, the writers get time to finish, and the lock is taken again; the lease is then
    /// checked afresh, and one released meanwhile only refuses the reclaim.
    pub(crate) async fn reclaim(&self, mut prepared: Prepared) -> Result<Reclaimed, SyncError> {
        for _attempt in 0..RECLAIM_ATTEMPTS {
            if prepared.path_guard.is_some() {
                if let Some(freed) = self.reclaim_if_idle(&prepared)? {
                    return Ok(freed);
                }
                prepared.path_guard = None;
                for sibling in &mut prepared.siblings {
                    sibling.path_guard = None;
                }
            }
            tokio::time::sleep(RECLAIM_RETRY_INTERVAL).await;
            let lock = self.state.replica_coordinator.path_lock(&prepared.group_id, &prepared.path);
            // Someone else may have the item for a moment: wait for it like for the writers.
            if let Ok(guard) = lock.try_lock_owned() {
                prepared.path_guard = Some(guard);
            }
            for sibling in &mut prepared.siblings {
                let lock =
                    self.state.replica_coordinator.path_lock(&sibling.group_id, &sibling.path);
                sibling.path_guard = lock.try_lock_owned().ok();
            }
        }
        Ok(Reclaimed::default())
    }

    /// One attempt: `None` when block writers are active.
    fn reclaim_if_idle(&self, prepared: &Prepared) -> Result<Option<Reclaimed>, SyncError> {
        let acquired = Acquired { custody: &*self.custody, stamp: &prepared.stamp };
        let Some(verified) = self.verify(
            &acquired,
            &prepared.group_id,
            &prepared.path,
            &prepared.version.version_hash,
            &prepared.version.blocks,
        ) else {
            return Ok(Some(Reclaimed::default()));
        };
        let store = crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
            self.state.block_store.clone(),
        );
        let store: &dyn BlockReclamationStore = &store;
        let Some(deletion_guard) = self.state.try_begin_block_deletion() else {
            return Ok(None);
        };
        // Only a sibling whose lock is held again counts: the lock keeps its lease from being
        // released between the coordinator's check and the deletion.
        let sibling_oracles: Vec<(&PreparedSibling, Acquired<'_>)> = prepared
            .siblings
            .iter()
            .filter(|sibling| sibling.path_guard.is_some())
            .map(|sibling| (sibling, Acquired { custody: &*self.custody, stamp: &sibling.stamp }))
            .collect();
        let siblings: Vec<_> = sibling_oracles
            .iter()
            .filter_map(|(sibling, oracle)| {
                self.verify(
                    oracle,
                    &sibling.group_id,
                    &sibling.path,
                    &sibling.version.version_hash,
                    &sibling.version.blocks,
                )
            })
            .collect();
        let coordinator = &self.state.replica_coordinator;
        let report =
            coordinator.reclaim_cached_blocks(&deletion_guard, verified, &siblings, store)?;
        Ok(Some(Reclaimed { blocks: report.blocks_deleted, bytes: report.bytes_reclaimed }))
    }

    fn verify<'a>(
        &self,
        oracle: &'a dyn FullReplicaCustody,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<yadorilink_replica_engine::custody::VerifiedCustody<'a>> {
        #[cfg(test)]
        if self.leases_enabled_for_test {
            return yadorilink_replica_engine::custody::verify_reclaim_custody_for_test(
                oracle,
                group_id,
                path,
                version_hash,
                blocks,
            );
        }
        yadorilink_replica_engine::custody::verify_reclaim_custody(
            oracle,
            group_id,
            path,
            version_hash,
            blocks,
        )
    }

    fn current_file_version(&self, group_id: &str, path: &str) -> Option<FileVersion> {
        let record = self
            .state
            .replica_coordinator
            .sqlite()
            .dag_get_current_version_record(group_id, path)
            .ok()??;
        (!record.deleted && record.record_kind == RecordKind::File)
            .then(|| record.to_file_version())
    }

    /// Whether some block of the item's current version is in the local block store.
    pub(crate) fn has_cached_blocks(&self, group_id: &str, path: &str) -> bool {
        self.current_file_version(group_id, path).is_some_and(|version| {
            version.blocks.iter().any(|block| {
                self.state.block_store.exists(&hex::encode(&block.hash.0)).unwrap_or(false)
            })
        })
    }

    /// The no-lease fallback of an eviction: proves that the item's current version is exactly
    /// `expect` and that every one of its blocks reads back and hashes to its name, so the next
    /// open can be served without any peer or the OS copy. Index presence is not proof.
    ///
    /// Ordering: the item's path lock is taken first and the returned [`VerifiedLocalCopy`] keeps
    /// it, so the caller's host eviction runs under the same lock as the verification; the
    /// reclaim of this item (which also needs the lock) cannot remove the blocks in between. The
    /// bytes are read under a block-reference guard (see [`DaemonState::blocks_verified_locally`]),
    /// so no deletion pass takes a block mid-read; that guard is released afterwards, which is
    /// safe because the blocks of the current version are referenced and only a custody-backed
    /// reclaim, excluded by the lock, removes referenced blocks. The version is read again after
    /// the verification, so an item that moved meanwhile is refused.
    pub(crate) async fn hold_verified_local_copy(
        &self,
        group_id: &str,
        path: &str,
        expect: VersionHash,
    ) -> Result<VerifiedLocalCopy, Retained> {
        let is_expected = |version: &FileVersion| version.version_hash == expect;
        let path_lock = self.state.replica_coordinator.path_lock(group_id, path);
        let Ok(path_guard) = path_lock.try_lock_owned() else {
            return Err(Retained::Busy);
        };
        let version = self
            .current_file_version(group_id, path)
            .filter(is_expected)
            .ok_or(Retained::VersionMoved)?;
        if !self.state.blocks_verified_locally(version.blocks).await {
            return Err(Retained::CustodyRequired);
        }
        if !self.current_file_version(group_id, path).is_some_and(|now| is_expected(&now)) {
            return Err(Retained::VersionMoved);
        }
        Ok(VerifiedLocalCopy { _path_guard: path_guard })
    }
}

/// Proof, with the item's path lock held, that the daemon's own blocks can serve the next open of
/// the item's current version. Dropping it releases the lock.
pub(crate) struct VerifiedLocalCopy {
    _path_guard: tokio::sync::OwnedMutexGuard<()>,
}

/// Native evictions the daemon was told about, waiting for their block-store half.
///
/// The user can remove the OS copy without the daemon being asked (Finder's "Remove Download").
/// The host reports the item leaving the materialized set; each such item is queued here and
/// handled one at a time, so a mass eviction does not become a burst of lease requests.
pub(crate) struct ReclaimQueue {
    state: Arc<DaemonState>,
    reclaim: Arc<ProviderReclaim>,
    pending: std::sync::Mutex<Pending>,
}

#[derive(Default)]
struct Pending {
    queue: std::collections::VecDeque<(String, ItemId, VersionHash)>,
    running: bool,
}

impl ReclaimQueue {
    pub(crate) fn new(state: Arc<DaemonState>, reclaim: Arc<ProviderReclaim>) -> Self {
        Self { state, reclaim, pending: std::sync::Mutex::default() }
    }

    /// Queues the items of `root_id` that left the OS's materialized set, each with the
    /// observation stamp of the listing that held it. An item left as the version the daemon
    /// handed over only when that listing began after the handoff (`evidence_seq <= listed`):
    /// a handoff newer than the departed listing is a copy that has not left. The entry is bound
    /// to the handed-over version.
    pub(crate) fn schedule(self: &Arc<Self>, root_id: &str, departed: Vec<(ItemId, u64)>) {
        let repo = self.state.replica_coordinator.provider_repository();
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        for (item, listed) in departed {
            let Ok(Some(handoff)) = repo.handoff(root_id, &item) else { continue };
            if handoff.evidence_seq > listed {
                continue;
            }
            let entry = (root_id.to_owned(), item, handoff.version_hash);
            if !pending.queue.contains(&entry) {
                pending.queue.push_back(entry);
            }
        }
        if !pending.running && !pending.queue.is_empty() {
            pending.running = true;
            tokio::spawn(self.clone().run());
        }
    }

    async fn run(self: Arc<Self>) {
        loop {
            let next = {
                let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
                let next = pending.queue.pop_front();
                if next.is_none() {
                    pending.running = false;
                }
                next
            };
            let Some((root_id, item, version)) = next else { return };
            self.reclaim_one(&root_id, &item, version).await;
        }
    }

    async fn reclaim_one(&self, root_id: &str, item: &ItemId, version: VersionHash) {
        let repo = self.state.replica_coordinator.provider_repository();
        let (Ok(Some(group_id)), Ok(Some((path, true)))) =
            (repo.group_of_root(root_id), repo.path_for_item(root_id, item))
        else {
            return;
        };
        // Still the version that was handed over and that left: anything newer is not what the
        // OS dropped.
        if !matches!(repo.current_version_hash(root_id, item), Ok(Some(current)) if current == version)
            || !matches!(repo.handoff(root_id, item), Ok(Some(handoff)) if handoff.version_hash == version)
            || !self.reclaim.has_cached_blocks(&group_id, &path)
        {
            return;
        }
        match self.reclaim.prepare(&group_id, &path, Some(version)).await {
            Ok(prepared) => match self.reclaim.reclaim(prepared).await {
                Ok(freed) => tracing::info!(blocks = freed.blocks, "provider item reclaimed"),
                Err(error) => tracing::warn!(%error, "provider reclaim failed; blocks kept"),
            },
            Err(why) => tracing::debug!(reason = why.code(), "provider reclaim skipped"),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
