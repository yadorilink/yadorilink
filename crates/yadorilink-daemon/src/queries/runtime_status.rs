//! `Status`'s full read model -- links, peers, configured limits and
//! current measured rates, per-volume free space, embedded update status,
//! block-store usage, GC health, active transfers, and recent errors.
//! Built on top of `link_status`'s and `update_status`'s already-landed
//! slices rather than re-deriving link/update data a second way.

use std::sync::Arc;

use yadorilink_local_storage::BlockStore;

use crate::gc_state::GcState;
use crate::governance_config::GovernanceConfigStore;
use crate::peer_connectivity_runtime::{peers_with_replaced, PeerConnectivityRuntime};
use crate::peer_registry::PeerReachability;
use crate::queries::link_status::{LinkStatusQueryService, LinkStatusView};
#[cfg(feature = "process-model")]
use crate::queries::update_status::{UpdateStatusQueryService, UpdateStatusView};
use crate::runtime_telemetry::RuntimeTelemetry;
use yadorilink_peer_session::rate_limiter::RateLimiters;

#[derive(Debug, Clone)]
pub(crate) struct PeerStatusView {
    pub(crate) device_id: String,
    pub(crate) reachability: PeerReachability,
    /// Reachable, but speaks another protocol version (sync with it is paused until both match):
    /// which end is older.
    pub(crate) version_skew: Option<crate::peer_connectivity_runtime::VersionSkew>,
    /// The device that replaced this one, when the account replaced it.
    pub(crate) replaced_by_device_id: Option<String>,
    /// The last time a session with this peer was up (now while connected); 0 when never.
    pub(crate) last_connected_unix: i64,
}

/// The volume entry for the block store (the volume holding the daemon's data).
pub(crate) const BLOCK_STORE_VOLUME: &str = "<block store>";

#[derive(Debug, Clone)]
pub(crate) struct VolumeSpaceView {
    pub(crate) path: String,
    pub(crate) state: String,
    pub(crate) available_bytes: u64,
    pub(crate) headroom_bytes: u64,
    pub(crate) total_bytes: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ActiveTransferView {
    pub(crate) group_id: String,
    pub(crate) path: String,
    pub(crate) bytes_done: u64,
    pub(crate) bytes_total: u64,
    pub(crate) blocks_done: u64,
    pub(crate) blocks_total: u64,
    pub(crate) source_peer: String,
    pub(crate) started_at_unix: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct RecentErrorView {
    pub(crate) category: String,
    pub(crate) timestamp_unix: i64,
    pub(crate) coarse_context: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BlockStoreUsageView {
    pub(crate) total_bytes: u64,
    pub(crate) block_count: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct KeptHistoryView {
    pub(crate) bytes: u64,
    pub(crate) budget_bytes: u64,
}

pub(crate) struct RuntimeStatusView {
    pub(crate) links: Vec<LinkStatusView>,
    pub(crate) peers: Vec<PeerStatusView>,
    pub(crate) upload_limit_bytes_per_sec: u64,
    pub(crate) download_limit_bytes_per_sec: u64,
    pub(crate) current_upload_bytes_per_sec: u64,
    pub(crate) current_download_bytes_per_sec: u64,
    pub(crate) volumes: Vec<VolumeSpaceView>,
    #[cfg(feature = "process-model")]
    pub(crate) update: UpdateStatusView,
    pub(crate) block_store: BlockStoreUsageView,
    /// The kept-version history's bytes and the byte budget bounding them; `None` when the
    /// history could not be read.
    pub(crate) kept_history: Option<KeptHistoryView>,
    /// Edits saved on this device that could not be published because the coordination service
    /// did not answer.
    pub(crate) unpublished_edits_service_unreachable: u64,
    /// Edits saved on this device that the service refused to publish because this device may
    /// no longer publish in the folder.
    pub(crate) unpublished_edits_not_authorized: u64,
    /// Edits saved on this device that the service answered but would not publish (the Terms, a
    /// refused credential, a route it does not accept).
    pub(crate) unpublished_edits_rejected: u64,
    pub(crate) last_gc_unix: i64,
    pub(crate) gc_reclaimable_estimate_bytes: u64,
    pub(crate) active_transfers: Vec<ActiveTransferView>,
    pub(crate) recent_errors: Vec<RecentErrorView>,
    /// The replica database was restored or copied and is refused (category).
    pub(crate) database_restored: Option<&'static str>,
    /// The author identity cannot be opened (not a restored database): nothing is signed.
    pub(crate) author_unavailable: bool,
    /// Why the coordination service refuses this device although its credential is intact
    /// (the Terms are not accepted, or the session cannot be renewed); `None` when it does not.
    pub(crate) coordination_block: Option<yadorilink_fapi_client::CoordinationBlock>,
    /// Where this device's own account stands in its deletion lifecycle.
    pub(crate) account_deletion: crate::daemon_state::AccountDeletionState,
}

/// Reads the coordination block of the credential this daemon authenticates with; `None` until
/// the daemon has one.
pub(crate) type CoordinationBlockSource =
    Arc<dyn Fn() -> Option<yadorilink_fapi_client::CoordinationBlock> + Send + Sync>;

/// Reads the deletion state of this device's own account as the latest netmap reported it.
pub(crate) type AccountDeletionSource =
    Arc<dyn Fn() -> crate::daemon_state::AccountDeletionState + Send + Sync>;

/// What a status reads from the ledger, the block index and the filesystem, collected by the
/// status builder (see `crate::status_facts`).
pub(crate) struct RuntimeFacts {
    pub(crate) links: Vec<crate::queries::link_status::LinkFacts>,
    governance: crate::governance_config::ResourceGovernanceConfig,
    volumes: Vec<VolumeSpaceView>,
    block_store_usage: yadorilink_local_storage::StorageUsage,
    kept_history: Option<KeptHistoryView>,
    /// Edits journaled as dirty paths in groups whose policy this device does not have (see
    /// [`dirty_edits_without_policy`]).
    dirty_edits_without_policy: u64,
    #[cfg(feature = "process-model")]
    update: UpdateStatusView,
}

/// Disk edits saved in the dirty journal of groups whose verified policy this device does not
/// have (a restart while the service is unreachable, before the policy could be restored): they
/// are captured as deltas only once the policy arrives, so they are neither pending deltas nor
/// counted by a flush, but they are changes only on this device. Groups whose policy is present
/// are not counted: their journal is the ordinary moment between a detected edit and its capture.
///
/// A count is a lower bound (a journal is read to 10 000 paths per group), and is not made in
/// the first minute of the engine: the policy is restored as it starts, and a healthy start is not
/// an outage.
pub(crate) fn dirty_edits_without_policy(
    replica: &crate::replica_coordinator::ReplicaCoordinator,
    uptime: std::time::Duration,
) -> u64 {
    const CAP: u32 = 10_000;
    const STARTUP_GRACE: std::time::Duration = std::time::Duration::from_secs(60);
    if uptime < STARTUP_GRACE {
        return 0;
    }
    let Ok(links) = replica.link_repository().list_links() else { return 0 };
    let mut groups: Vec<String> =
        links.into_iter().filter(|l| !l.paused && !l.orphaned).map(|l| l.group_id).collect();
    groups.sort();
    groups.dedup();
    groups
        .iter()
        .filter(|group| replica.local_policy_head(group).is_err())
        .map(|group| replica.dirty_path_repository().count_dirty_paths(group, CAP).unwrap_or(0))
        .sum()
}

impl RuntimeFacts {
    pub(crate) fn volume_paths(&self) -> impl Iterator<Item = &str> {
        self.volumes.iter().map(|v| v.path.as_str())
    }
}

pub(crate) struct RuntimeStatusQueryService {
    link_status: Arc<LinkStatusQueryService>,
    #[cfg(feature = "process-model")]
    update_status: Arc<UpdateStatusQueryService>,
    peers: Arc<PeerConnectivityRuntime>,
    authority: Arc<crate::daemon_state::PeerAuthorityState>,
    telemetry: Arc<RuntimeTelemetry>,
    governance: Arc<GovernanceConfigStore>,
    block_store: Arc<dyn BlockStore + Send + Sync>,
    gc: Arc<GcState>,
    rate_limiters: Arc<RateLimiters>,
    replica: Arc<crate::replica_coordinator::ReplicaCoordinator>,
    audit: crate::index_audit::IndexAudit,
    coordination_block: CoordinationBlockSource,
    account_deletion: AccountDeletionSource,
}

impl RuntimeStatusQueryService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        link_status: Arc<LinkStatusQueryService>,
        #[cfg(feature = "process-model")] update_status: Arc<UpdateStatusQueryService>,
        peers: Arc<PeerConnectivityRuntime>,
        authority: Arc<crate::daemon_state::PeerAuthorityState>,
        telemetry: Arc<RuntimeTelemetry>,
        governance: Arc<GovernanceConfigStore>,
        block_store: Arc<dyn BlockStore + Send + Sync>,
        gc: Arc<GcState>,
        rate_limiters: Arc<RateLimiters>,
        replica: Arc<crate::replica_coordinator::ReplicaCoordinator>,
        coordination_block: CoordinationBlockSource,
        account_deletion: AccountDeletionSource,
    ) -> Self {
        Self {
            link_status,
            #[cfg(feature = "process-model")]
            update_status,
            peers,
            authority,
            telemetry,
            governance,
            block_store,
            gc,
            rate_limiters,
            replica,
            audit: crate::index_audit::IndexAudit::default(),
            coordination_block,
            account_deletion,
        }
    }

    /// Whether the status volume entry `path` is on the same physical volume as the block store.
    /// An identity that cannot be determined on either side is "no" (the safe side).
    pub(crate) fn shares_block_store_volume(&self, path: &str) -> bool {
        if path == BLOCK_STORE_VOLUME {
            return true;
        }
        let Some(root) = self.block_store.data_dir() else { return false };
        same_volume(root, std::path::Path::new(path))
    }

    pub(crate) fn telemetry(&self) -> Arc<RuntimeTelemetry> {
        self.telemetry.clone()
    }

    /// Signals when a ledger write has changed rows.
    pub(crate) fn data_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.replica.database().subscribe_data_changes()
    }

    /// Reads every ledger, block-index, filesystem and file input of a status. The status builder
    /// calls this off the request path; [`Self::snapshot_from`] answers a request from the result.
    pub(crate) fn collect(&self) -> Result<RuntimeFacts, crate::sync_error::SyncError> {
        let mut links = self.link_status.collect_links()?;
        let active_groups: Vec<String> = self
            .replica
            .link_repository()
            .list_links()
            .map(|all| {
                all.into_iter().filter(|l| !l.paused && !l.orphaned).map(|l| l.group_id).collect()
            })
            .unwrap_or_default();
        // Edits of a folder that is unlinked or paused are not waiting to be published any more.
        self.telemetry.retain_unpublished(&active_groups);
        self.audit.refresh(self.replica.file_index_repository(), &mut links);
        let governance = self.governance.load_or_default();
        let volumes = self.volumes_free_space(links.iter().map(|l| l.local_path()), &governance);
        Ok(RuntimeFacts {
            links,
            governance,
            volumes,
            #[cfg(feature = "process-model")]
            update: self.update_status.snapshot(),
            block_store_usage: self.block_store.usage().unwrap_or_default(),
            kept_history: self.kept_history(),
            dirty_edits_without_policy: dirty_edits_without_policy(
                &self.replica,
                self.telemetry.uptime(),
            ),
        })
    }

    fn kept_history(&self) -> Option<KeptHistoryView> {
        let now_unix_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_nanos()).ok())?;
        let bytes = self.replica.file_index_repository().kept_history_bytes(now_unix_nanos).ok()?;
        let budget_bytes = crate::adapters::runtime::link_runtime_controller::history_budget_bytes(
            self.block_store.free_space().ok().flatten().map(|space| space.total_bytes),
        );
        Some(KeptHistoryView { bytes, budget_bytes })
    }

    /// Joins collected facts with the in-memory ones (peers, transfers, rates, errors). Reads no
    /// ledger, file or block index. `stale`: the facts are older than a positive claim may stand
    /// on, so every link reports its protection and availability as unknown.
    pub(crate) fn snapshot_from(&self, facts: &RuntimeFacts, stale: bool) -> RuntimeStatusView {
        let mut links = self.link_status.compose_links(&facts.links);
        if stale {
            for link in &mut links {
                link.withhold_positive_claims();
            }
        }
        let peers = peers_with_replaced(self.peers.every_peer_reachability(), &self.authority)
            .into_iter()
            // A peer of another protocol version connects (the transport has one fixed ALPN) and
            // is refused at the lane hello: it stays reachable and is marked incompatible.
            .map(|(device_id, reachability)| PeerStatusView {
                last_connected_unix: self.peers.last_connected_unix(&device_id),
                version_skew: self.peers.version_skew(&device_id),
                replaced_by_device_id: self.authority.superseded_by(&device_id),
                device_id,
                reachability,
            })
            .collect();
        let governance = &facts.governance;
        let volumes = facts.volumes.clone();
        let block_store_usage = facts.block_store_usage;
        let active_transfers = self
            .telemetry
            .active_transfer_snapshot()
            .into_iter()
            .map(|t| ActiveTransferView {
                group_id: t.group_id,
                path: t.path,
                bytes_done: t.bytes_done,
                bytes_total: t.bytes_total,
                blocks_done: t.blocks_done,
                blocks_total: t.blocks_total,
                source_peer: t.source_peer,
                started_at_unix: t.started_at_unix,
            })
            .collect();
        let recent_errors = self
            .telemetry
            .recent_error_snapshot()
            .into_iter()
            .map(|e| RecentErrorView {
                category: e.category.to_string(),
                timestamp_unix: e.timestamp_unix,
                coarse_context: e.coarse_context,
            })
            .collect();
        let unpublished = self.telemetry.unpublished_totals();

        RuntimeStatusView {
            links,
            peers,
            upload_limit_bytes_per_sec: governance.upload_limit_bytes_per_sec,
            download_limit_bytes_per_sec: governance.download_limit_bytes_per_sec,
            current_upload_bytes_per_sec: self.rate_limiters.upload.current_rate_bytes_per_sec(),
            current_download_bytes_per_sec: self
                .rate_limiters
                .download
                .current_rate_bytes_per_sec(),
            volumes,
            #[cfg(feature = "process-model")]
            update: facts.update.clone(),
            block_store: BlockStoreUsageView {
                total_bytes: block_store_usage.total_bytes,
                block_count: block_store_usage.block_count,
            },
            kept_history: facts.kept_history,
            unpublished_edits_service_unreachable: unpublished.service_unreachable
                + facts.dirty_edits_without_policy,
            unpublished_edits_not_authorized: unpublished.not_authorized,
            unpublished_edits_rejected: unpublished.rejected,
            last_gc_unix: self.gc.last_run_unix(),
            gc_reclaimable_estimate_bytes: self.gc.reclaimable_estimate_bytes(),
            active_transfers,
            recent_errors,
            database_restored: self.replica.database_restored().map(|r| r.category()),
            author_unavailable: self.replica.author_unavailable(),
            coordination_block: (self.coordination_block)(),
            account_deletion: (self.account_deletion)(),
        }
    }

    /// Free-space state for every volume hosting the block store or a
    /// linked folder -- the block-store root (via `BlockStore::free_space`,
    /// `None` for a backend with no real volume concept) plus one entry
    /// per distinct link `local_path` (paths can collide if a device
    /// somehow links the same directory twice, so this dedups by path
    /// rather than by link count). Best-effort: a link whose volume can't
    /// currently be queried is silently omitted, matching every other
    /// silent-degrade in this snapshot -- `Status` reports what it can,
    /// never fails wholesale over one unreadable volume.
    pub(crate) fn volumes_free_space<'a>(
        &self,
        local_paths: impl Iterator<Item = &'a str>,
        governance: &crate::governance_config::ResourceGovernanceConfig,
    ) -> Vec<VolumeSpaceView> {
        let headroom_override = governance.headroom_override_bytes;
        let mut seen_paths = std::collections::HashSet::new();
        let mut volumes = Vec::new();

        if let Ok(Some(space)) = self.block_store.free_space() {
            volumes.push(VolumeSpaceView {
                path: BLOCK_STORE_VOLUME.to_string(),
                state: space.classify().as_str().to_string(),
                available_bytes: space.available_bytes,
                headroom_bytes: space.headroom_bytes,
                total_bytes: space.total_bytes,
            });
        }

        for local_path in local_paths {
            if !seen_paths.insert(local_path.to_string()) {
                continue;
            }
            if let Ok(space) = yadorilink_local_storage::free_space::classify_volume(
                std::path::Path::new(local_path),
                headroom_override,
            ) {
                volumes.push(VolumeSpaceView {
                    path: local_path.to_string(),
                    state: space.classify().as_str().to_string(),
                    available_bytes: space.available_bytes,
                    headroom_bytes: space.headroom_bytes,
                    total_bytes: space.total_bytes,
                });
            }
        }
        volumes
    }
}

/// Whether both directories report the same volume identity; either failing to report is "no".
fn same_volume(a: &std::path::Path, b: &std::path::Path) -> bool {
    use yadorilink_fs_platform::fs_capabilities::observe_volume_identity;
    // Resolve symlinks first: the observation describes a link itself, while storage follows it.
    let observe =
        |p: &std::path::Path| observe_volume_identity(&std::fs::canonicalize(p).ok()?).ok();
    identities_match(observe(a), observe(b))
}

/// Equal known identities match; an unknown one on either side never does.
fn identities_match(
    a: Option<yadorilink_fs_platform::fs_identity::VolumeIdentity>,
    b: Option<yadorilink_fs_platform::fs_identity::VolumeIdentity>,
) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x == y)
}

#[cfg(test)]
mod same_volume_tests {
    #[cfg(unix)]
    use super::identities_match;
    use super::same_volume;
    #[cfg(unix)]
    use yadorilink_fs_platform::fs_identity::VolumeIdentity;

    #[cfg(unix)]
    #[test]
    fn identities_match_only_when_both_known_and_equal() {
        let v = |device_id| Some(VolumeIdentity::Unix { device_id });
        assert!(identities_match(v(1), v(1)));
        assert!(!identities_match(v(1), v(2)));
        assert!(!identities_match(v(1), None));
        assert!(!identities_match(None, None));
    }

    #[test]
    fn two_directories_on_one_volume_match_and_an_unknown_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        assert!(same_volume(&a, &b));
        assert!(!same_volume(&a, &dir.path().join("missing")));
        assert!(!same_volume(&dir.path().join("missing"), &a));
        // A symlink resolves to its target's volume rather than being observed itself.
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&b, &link).unwrap();
            assert!(same_volume(&a, &link));
            assert!(!same_volume(&a, &dir.path().join("dangling-missing")));
        }
    }
}
