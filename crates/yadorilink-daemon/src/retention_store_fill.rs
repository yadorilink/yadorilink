//! The store-only fetch of an `online_only` retention rule on a full-replica (Eager) provider
//! folder.
//!
//! An online-only path loses only its COPY in the folder; the device stays a custodian, so its block
//! store must keep holding the content of those paths (it answers `VersionPresent` truthfully, the
//! handoff proofs stay valid). The Eager driver no longer asks the OS to download them (see
//! `provider_eager::Scope`), so this job brings their blocks into the block store without placing a
//! copy: the block-resolution step of hydration, which fetches and records the group's provenance
//! once a block is durable, and nothing else. It never marks `materialization_state` `Present`:
//! block availability and OS residency stay separate.
//!
//! It is a level-triggered reconcile, not a one-shot: for every current version under an
//! online-only prefix the question is "are all its blocks here with provenance?", asked again each
//! pass, so a newer version that supersedes the one being fetched, a reconnect, a restart and a
//! rule or mode change all converge without any event being remembered. Partial completion
//! resumes: a pass fetches at most [`FETCHES_PER_PASS`] versions and the next one continues. Skipped
//! entirely on a folder that is not Eager (an on-demand device is not a custodian), and paused
//! while the disk is low.
//!
//! Reclamation coordinates through block liveness alone (current heads, other references and
//! leases protect the blocks; a full replica's eviction never purges them): this job takes no lock
//! and holds nothing across passes beyond an in-memory "verified" memo.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_sync_sqlite::provider::DownloadFilter;

use crate::daemon_state::DaemonState;

/// How often the loop looks.
pub(crate) const PASS_INTERVAL: Duration = Duration::from_secs(60);
/// The most versions one pass resolves blocks for (checks plus fetches).
pub(crate) const FETCHES_PER_PASS: usize = 64;
/// Rows read per page.
const PAGE: usize = 256;
/// A verified version is trusted for this many passes, then looked at again (a block can be lost
/// to corruption).
const MEMO_PASSES: u64 = 30;
/// A version that could not be completed is left alone for this many passes.
const BACKOFF_PASSES: u64 = 5;

/// What the job needs to know about the machine.
pub(crate) trait FillEnvironment: Send + Sync {
    /// Whether the disk is low enough that nothing more should be written.
    fn low_disk(&self) -> bool;
}

/// What one pass found.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FillSummary {
    /// Versions looked at.
    pub checked: usize,
    /// Versions whose blocks are all here.
    pub complete: usize,
    /// Versions still missing blocks (no peer, or a fetch failed): the next pass tries again.
    pub incomplete: usize,
    /// The pass stopped early (budget or disk).
    pub stopped_early: bool,
}

pub(crate) struct RetentionStoreFill {
    state: Arc<DaemonState>,
    environment: Arc<dyn FillEnvironment>,
    /// (group, path) -> a digest of the version's block hashes that was complete, and the pass it
    /// was verified in.
    verified: Mutex<HashMap<(String, String), (u64, u64)>>,
    pass: std::sync::atomic::AtomicU64,
    /// (group, path) -> digest of a version that could not be completed, and the pass it failed
    /// in: not retried for [`BACKOFF_PASSES`], so unavailable files cannot use up every pass's
    /// budget and starve the ones behind them.
    failed: Mutex<HashMap<(String, String), (u64, u64)>>,
    /// Where a pass that ran out of budget stopped, per folder: the next pass resumes there, so
    /// unavailable files at the front can never keep the files behind them from being tried. A
    /// scan that reaches the end clears it and the next one starts over.
    cursor: Mutex<HashMap<String, (u64, String)>>,
}

fn digest(blocks: &[yadorilink_replica_domain::file::BlockInfo]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for block in blocks {
        block.hash.hash(&mut hasher);
    }
    hasher.finish()
}

impl RetentionStoreFill {
    pub(crate) fn new(state: Arc<DaemonState>, environment: Arc<dyn FillEnvironment>) -> Self {
        Self {
            state,
            environment,
            verified: Mutex::default(),
            pass: std::sync::atomic::AtomicU64::new(0),
            failed: Mutex::default(),
            cursor: Mutex::default(),
        }
    }

    /// One pass over every Eager provider folder that has an online-only rule.
    pub(crate) async fn run_pass(&self) -> FillSummary {
        let pass = self.pass.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut summary = FillSummary::default();
        let coordinator = &self.state.replica_coordinator;
        let roots = match coordinator.provider_repository().list_declared_roots() {
            Ok(roots) => roots,
            Err(error) => {
                tracing::warn!(%error, "provider folders could not be listed for the store fill");
                return summary;
            }
        };
        let mut fetches = 0usize;
        for root in roots {
            if self.environment.low_disk() {
                summary.stopped_early = true;
                break;
            }
            // Only a custodian fills the store for paths it does not keep a copy of.
            let policy =
                coordinator.link_repository().materialization_policy_for_group(&root.group_id);
            if !matches!(policy, Ok(Some(MaterializationPolicy::Eager))) {
                continue;
            }
            match coordinator.retention_rules().rules(&root.group_id) {
                Ok(rules) if rules.has_online_only() => {}
                _ => continue,
            }
            let mut after: Option<(u64, String)> =
                self.cursor.lock().unwrap_or_else(|p| p.into_inner()).get(&root.root_id).cloned();
            let mut prev = after.clone();
            let mut stopped = false;
            'pages: loop {
                let page = match coordinator.provider_repository().eager_page(
                    &root.root_id,
                    DownloadFilter::OnlineOnlyOnly,
                    after.as_ref().map(|(size, path)| (*size, path.as_str())),
                    PAGE,
                ) {
                    Ok(page) if !page.is_empty() => page,
                    Ok(_) => break,
                    Err(error) => {
                        tracing::warn!(%error, root_id = %root.root_id, "the store fill could not read a folder");
                        break;
                    }
                };
                after = page.last().map(|c| (c.size, c.path.clone()));
                for candidate in page {
                    let before = prev.replace((candidate.size, candidate.path.clone()));
                    let Ok(Some(record)) = coordinator
                        .file_index_repository()
                        .get_file(&root.group_id, &candidate.path)
                    else {
                        continue;
                    };
                    if record.deleted || record.blocks.is_empty() {
                        continue;
                    }
                    summary.checked += 1;
                    let key = (root.group_id.clone(), candidate.path.clone());
                    let sum = digest(&record.blocks);
                    let trusted = self
                        .verified
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .get(&key)
                        .is_some_and(|(seen, at)| {
                            *seen == sum && pass.saturating_sub(*at) < MEMO_PASSES
                        });
                    if trusted {
                        summary.complete += 1;
                        continue;
                    }
                    let backed_off = self
                        .failed
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .get(&key)
                        .is_some_and(|(seen, at)| {
                            *seen == sum && pass.saturating_sub(*at) < BACKOFF_PASSES
                        });
                    if backed_off {
                        summary.incomplete += 1;
                        continue;
                    }
                    if fetches >= FETCHES_PER_PASS || self.environment.low_disk() {
                        summary.stopped_early = true;
                        stopped = true;
                        let mut cursors = self.cursor.lock().unwrap_or_else(|p| p.into_inner());
                        match before {
                            Some(position) => cursors.insert(root.root_id.clone(), position),
                            None => cursors.remove(&root.root_id),
                        };
                        break 'pages;
                    }
                    match crate::hydration::fill_store(
                        &self.state,
                        &root.group_id,
                        &candidate.path,
                        &record.blocks,
                    )
                    .await
                    {
                        Ok(0) => {
                            summary.complete += 1;
                            self.failed.lock().unwrap_or_else(|p| p.into_inner()).remove(&key);
                            self.verified
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .insert(key, (sum, pass));
                        }
                        Ok(_) | Err(_) => {
                            summary.incomplete += 1;
                            self.failed
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .insert(key, (sum, pass));
                        }
                    }
                    // A version that was already complete costs only the presence checks; the
                    // budget counts every version that was not trusted from the memo.
                    fetches += 1;
                }
            }
            if !stopped {
                // The whole folder was seen: the next pass starts from the front.
                self.cursor.lock().unwrap_or_else(|p| p.into_inner()).remove(&root.root_id);
            }
        }
        summary
    }
}

/// The background loop.
pub(crate) async fn run(fill: Arc<RetentionStoreFill>) {
    let mut interval = tokio::time::interval(PASS_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        fill.run_pass().await;
    }
}

#[cfg(test)]
mod tests;
