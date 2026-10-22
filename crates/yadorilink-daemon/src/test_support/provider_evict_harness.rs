//! The production provider eviction path (`ProviderEvictor` over the real `ProviderReclaim` and
//! its peer custody) with a scripted File Provider host, for integration binaries that pair real
//! daemons. The host is the only fake: it answers the OS-side eviction the way the menu-bar app
//! would; everything the daemon does around it is production code.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use yadorilink_replica_domain::session_state::ProviderKind;
use yadorilink_sync_sqlite::provider::ItemId;

use crate::application::ports::{BoxFuture, TempMaterialization, TempOutcome};
use crate::daemon_state::DaemonState;
use crate::provider_evict::{EvictHost, ProviderEvictor};
use crate::provider_evidence::ProviderMembership;
use crate::provider_publication::EvictOutcome as HostAnswer;
use crate::provider_reclaim::ProviderReclaim;
use crate::sync_error::SyncError;

/// What the scripted host answers to an eviction request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostReply {
    Evicted,
    NotMaterialized,
}

struct ScriptedHost {
    replies: Mutex<VecDeque<HostReply>>,
    asked: AtomicU64,
}

impl EvictHost for ScriptedHost {
    fn connected(&self) -> bool {
        true
    }

    fn evict_shown_version<'a>(
        &'a self,
        _root_id: &'a str,
        _item: ItemId,
        _target: [u8; 32],
    ) -> BoxFuture<'a, HostAnswer> {
        Box::pin(async move {
            self.asked.fetch_add(1, Ordering::SeqCst);
            match self.replies.lock().unwrap().pop_front().unwrap_or(HostReply::Evicted) {
                HostReply::Evicted => HostAnswer::Evicted,
                HostReply::NotMaterialized => HostAnswer::NotMaterialized,
            }
        })
    }
}

/// What one eviction request did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEvictResult {
    pub dehydrated: bool,
    pub blocks_reclaimed: u64,
    pub bytes_reclaimed: u64,
    /// The reason blocks stayed, empty when they were freed.
    pub retained: String,
}

pub struct ProviderEvictHarness {
    state: Arc<DaemonState>,
    root: String,
    membership: Arc<ProviderMembership>,
    host: Arc<ScriptedHost>,
    evictor: Arc<ProviderEvictor>,
    epoch: AtomicU64,
}

/// What automatic space management did with one file in a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoReclaimed {
    pub path: String,
    /// The OS copy went back to online-only.
    pub reclaimed: bool,
    pub blocks: u64,
    /// Why the file was left, empty when it was reclaimed.
    pub reason: String,
}

/// The machine facts of a pass: the host attached, the peers as the daemon sees them, and free
/// space low until the host has been asked to drop one file.
struct PressureUntilOneEviction {
    state: Arc<DaemonState>,
    host: Arc<ScriptedHost>,
    asked_before: u64,
}

impl crate::provider_auto_reclaim::ReclaimEnvironment for PressureUntilOneEviction {
    fn host_connected(&self) -> bool {
        true
    }

    fn peers_available(&self, group_id: &str) -> bool {
        !crate::hydration::candidate_sessions(&self.state, group_id).is_empty()
    }

    fn free_space(&self) -> Option<yadorilink_local_storage::free_space::FreeSpaceState> {
        use yadorilink_local_storage::free_space::FreeSpaceState;
        Some(if self.host.asked.load(Ordering::SeqCst) > self.asked_before {
            FreeSpaceState::Ok
        } else {
            FreeSpaceState::Critical
        })
    }
}

impl ProviderEvictHarness {
    /// Declares an on-demand provider root for `group_id` (whose link must already exist with the
    /// on-demand policy) and builds the production evictor over it.
    pub fn declare(state: &Arc<DaemonState>, group_id: &str) -> Self {
        let repo = state.replica_coordinator.provider_repository();
        let root = repo.declare_root(group_id, ProviderKind::MacFileProvider, "Photos").unwrap();
        repo.set_domain_registered(&root, true).unwrap();
        repo.record_extension_handshake(&root, 1).unwrap();
        let host = Arc::new(ScriptedHost { replies: Mutex::default(), asked: AtomicU64::new(0) });
        let membership = Arc::new(ProviderMembership::default());
        let evictor = Arc::new(ProviderEvictor::new(
            state.clone(),
            host.clone(),
            Arc::new(ProviderReclaim::new(state.clone())),
            membership.clone(),
        ));
        Self { state: state.clone(), root, membership, host, evictor, epoch: AtomicU64::new(1) }
    }

    pub fn reply_next(&self, reply: HostReply) {
        self.host.replies.lock().unwrap().push_back(reply);
    }

    pub fn host_was_asked(&self) -> u64 {
        self.host.asked.load(Ordering::SeqCst)
    }

    /// A published item for `path`, as the host would see it.
    pub fn item(&self, path: &str) -> ItemId {
        let repo = self.state.replica_coordinator.provider_repository();
        let item = repo.mint_item(&self.root, path).unwrap();
        let hash = repo.current_version_hash(&self.root, &item).unwrap().unwrap();
        repo.publish_first(&self.root, &item, hash).unwrap();
        item
    }

    /// The daemon's evidence that the OS holds `item` at its current version: a handoff and a
    /// host report, taken after it, that lists the item.
    pub fn host_holds(&self, item: ItemId) {
        let repo = self.state.replica_coordinator.provider_repository();
        let version = repo.current_version_hash(&self.root, &item).unwrap().unwrap();
        let seq = repo.record_handoff(&self.root, &item, version).unwrap().unwrap();
        let report = yadorilink_ipc_proto::shellipc::ProviderMaterializedReport {
            root_id: hex::decode(&self.root).unwrap(),
            reporter_epoch: self.epoch.fetch_add(1, Ordering::SeqCst),
            report_seq: 1,
            full: true,
            observed_after_seq: seq,
            upserts: vec![yadorilink_ipc_proto::shellipc::ProviderMaterializedItem {
                item_id: item.to_vec(),
            }],
            removed: Vec::new(),
            more: false,
        };
        let latest = repo.latest_evidence_seq(&self.root).unwrap().unwrap();
        assert!(
            !self.membership.apply_reporting_departures(&report, latest).0.needs_full,
            "the host report was refused"
        );
    }

    /// The production provider hydration: the current version assembled (blocks fetched from a
    /// peer if missing) into a staging file the OS would take. Returns the assembled file.
    pub async fn materialize(
        &self,
        group_id: &str,
        path: &str,
        staging: &std::path::Path,
    ) -> Result<PathBuf, SyncError> {
        match materialize_temp(&self.state, group_id, path, staging, None, None).await? {
            RangedOutcome::Assembled { file, .. } => Ok(file),
            _ => Err(SyncError::HydrationFailed(path.to_string())),
        }
    }

    /// One pass of automatic space management, with the setting On, over this harness's
    /// production eviction path, under disk pressure that lasts until one file was given back.
    pub async fn auto_reclaim_pass(&self) -> Vec<AutoReclaimed> {
        use crate::provider_auto_reclaim::{AutoReclaim, Outcome};
        let settings_dir = tempfile::tempdir().unwrap();
        let settings =
            crate::space_management_config::SpaceManagementStore::new(settings_dir.path());
        settings.set(true).unwrap();
        let environment = Arc::new(PressureUntilOneEviction {
            state: self.state.clone(),
            host: self.host.clone(),
            asked_before: self.host_was_asked(),
        });
        let auto = Arc::new(AutoReclaim::new(
            self.state.clone(),
            self.evictor.clone(),
            self.membership.clone(),
            environment,
            settings,
        ));
        auto.run_pass()
            .await
            .outcomes
            .into_iter()
            .map(|(_, path, outcome)| match outcome {
                Outcome::Reclaimed { blocks, .. } => {
                    AutoReclaimed { path, reclaimed: true, blocks, reason: String::new() }
                }
                Outcome::Skipped(why) | Outcome::Refused(why) => AutoReclaimed {
                    path,
                    reclaimed: false,
                    blocks: 0,
                    reason: why.code().to_owned(),
                },
            })
            .collect()
    }

    pub async fn evict(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ProviderEvictResult, SyncError> {
        let outcome = self.evictor.evict(group_id, path).await?;
        Ok(ProviderEvictResult {
            dehydrated: outcome.dehydrated,
            blocks_reclaimed: outcome.reclaimed.blocks,
            bytes_reclaimed: outcome.reclaimed.bytes,
            retained: outcome.retained.map(|why| why.code().to_owned()).unwrap_or_default(),
        })
    }
}

/// What a temp materialization produced.
#[derive(Debug)]
pub enum RangedOutcome {
    /// A verified file in staging: the whole version, or, for a ranged request, the window
    /// `served = (offset, len)` of it.
    Assembled {
        file: PathBuf,
        served: Option<(u64, u64)>,
        size: u64,
    },
    VersionOutOfDate,
    RangeNotSatisfiable,
}

/// The production temp materialization (the provider sink) of `path`, whole or, with `range =
/// Some((offset, len))`, only that window of the exact `version`.
pub async fn materialize_temp(
    state: &Arc<DaemonState>,
    group_id: &str,
    path: &str,
    staging: &std::path::Path,
    version: Option<[u8; 32]>,
    range: Option<(u64, u64)>,
) -> Result<RangedOutcome, SyncError> {
    let request = TempMaterialization {
        group_id,
        path,
        requested_version: version.map(yadorilink_replica_domain::ids::VersionHash),
        staging_file: staging,
        range: range.map(|(offset, len)| crate::application::ports::ByteRange { offset, len }),
        progress: None,
    };
    match crate::hydration::materialize_path(
        state,
        group_id,
        path,
        crate::hydration::Sink::Temp(&request),
    )
    .await?
    {
        crate::hydration::Materialized::Temp(TempOutcome::Assembled(assembly)) => {
            Ok(RangedOutcome::Assembled {
                file: assembly.assembled,
                served: assembly.range.map(|r| (r.offset, r.len)),
                size: assembly.size,
            })
        }
        crate::hydration::Materialized::Temp(TempOutcome::VersionOutOfDate) => {
            Ok(RangedOutcome::VersionOutOfDate)
        }
        crate::hydration::Materialized::Temp(TempOutcome::RangeNotSatisfiable) => {
            Ok(RangedOutcome::RangeNotSatisfiable)
        }
        crate::hydration::Materialized::InPlace => {
            Err(SyncError::HydrationFailed(path.to_string()))
        }
    }
}
