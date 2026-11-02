//! Moves the losing heads of contested paths to their copy paths.
//!
//! A path is contested when its live heads are distinct file versions, or a
//! file stands where a directory is required. The author of a losing head
//! removes it and puts the same version at `copy_path(path, version)`, in an
//! ordinary delta. When that author can never act (its state is `Closed`, or
//! its device is not a writer at the verified policy point) any writer signs
//! the same delta in its place. Nothing here reads the disk or a clock.

use std::sync::Arc;

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::native_fork::fallback_may_fork;
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::daemon_state::{DaemonState, GroupPolicyResolution};

/// The result of one fork pass.
#[derive(Debug, Default)]
pub(crate) struct ForkPass {
    /// Fork deltas signed.
    pub(crate) deltas: usize,
    /// The pass stood down because a contested path appeared that was not checked; ask again.
    pub(crate) recheck: bool,
}

impl DaemonState {
    /// Forks every contested path of `group_id` this device may fork now, given the paths the
    /// caller found settled in the store (`None`: not checked, for tests). How many deltas were
    /// signed, and whether the pass stood down for a path nobody had checked.
    pub(crate) fn fork_contested_heads(
        &self,
        group_id: &str,
        checked: Option<&crate::replica_coordinator::ContestChecked>,
    ) -> ForkPass {
        let Some(author) = self.local_author() else { return ForkPass::default() };
        let writers: Option<Vec<String>> = match self.resolve_group_policy(group_id) {
            // A chain with no records yet grants no one anything: it is the
            // bootstrap window, in which no one's head is judged abandoned.
            GroupPolicyResolution::Verified(policy) if policy.current_seq == 0 => None,
            GroupPolicyResolution::Verified(policy) => {
                Some(policy.current_writers().iter().map(|w| w.device_id.clone()).collect())
            }
            // No policy yet: every member writes, so no one else's head is
            // abandoned except through closure.
            GroupPolicyResolution::Bootstrap => None,
            // The coordinator refuses to emit while the policy is withheld;
            // until it is known, no one else's head is judged abandoned.
            GroupPolicyResolution::Withhold => None,
        };
        if writers.as_ref().is_some_and(|w| !w.contains(&self.device_id)) {
            return ForkPass::default();
        }
        let eligible = |owner: &AuthorId, closed: bool| {
            let owner_is_writer = match &writers {
                Some(writers) => writers.contains(&owner.device.0),
                None => true,
            };
            fallback_may_fork(closed, owner_is_writer)
        };
        let result =
            self.replica_coordinator.author_contest_forks(&author, group_id, &eligible, checked);
        match result {
            Ok(crate::replica_coordinator::ForkOutcome { unchecked: true, .. }) => {
                ForkPass { deltas: 0, recheck: true }
            }
            Ok(crate::replica_coordinator::ForkOutcome { forked: done, .. }) => {
                if done.refused > 0 {
                    tracing::warn!(
                        group_id,
                        refused = done.refused,
                        "some contested paths cannot be forked and stay contested"
                    );
                }
                ForkPass { deltas: done.deltas, recheck: false }
            }
            Err(error) => {
                tracing::debug!(group_id, %error, "contest forks deferred");
                ForkPass::default()
            }
        }
    }

    /// One fork pass for `group_id`: the contested versions this device holds only as files are
    /// read into the store first, and the group is forked only if every one of them is settled
    /// there. A fork moves a losing head to a copy path nobody can serve if the version is not in
    /// the store, and the winner would later replace the only bytes of it, so the pass otherwise
    /// forks nothing: the path stays contested, its candidates unattempted, and another pass is
    /// scheduled, later each time and without a limit. Returns the number of deltas signed.
    pub(crate) async fn fork_contested_group(&self, group_id: &str) -> usize {
        let Some(checked) = self.keep_contested_versions_in_store(group_id).await else {
            tracing::info!(
                group_id,
                "contested paths wait: a local version is not in the block store yet"
            );
            self.native_replication.schedule_contest_retry(group_id);
            return 0;
        };
        let pass = self.fork_contested_heads(group_id, Some(&checked));
        if pass.recheck {
            self.native_replication.schedule_contest_retry(group_id);
        } else {
            self.native_replication.contest_settled(group_id);
        }
        pass.deltas
    }

    /// Reads the version this device holds at each contested path into the block store when it
    /// holds it only as its own file (received, or captured as a hash only). The paths
    /// looked at when every one of them is now settled (held in the store, or not held as bytes
    /// here at all), else `None`.
    ///
    /// A fork moves a losing head to its copy path, and every device that shows the copy fetches
    /// its blocks by hash from the author, who serves them from the store; the author itself
    /// writes the copy from the store. A version held by one file alone is neither servable at
    /// the copy path (the file is the path's, not the copy's) nor available to the author's own
    /// copy, so devices that each hold a different version of one path would all wait for bytes
    /// that none of them can hand out. This is the rule of a sync that replaces a version: it
    /// is kept in the store. A path whose file is no longer that version, cannot be read now, is
    /// being written, or fails to be read is not settled; the caller decides what to do about it.
    ///
    /// A path whose lock is held by someone else is not waited for, so that a caller that holds a
    /// path lock itself (a restore announcing its commit) cannot deadlock; it is not settled.
    pub(crate) async fn keep_contested_versions_in_store(
        &self,
        group_id: &str,
    ) -> Option<crate::replica_coordinator::ContestChecked> {
        #[cfg(any(test, feature = "test-support"))]
        if held_for_test(&self.device_id) {
            return None;
        }
        // Each path with the row this device's index holds at it before anything is read: the
        // fork is later made only over that very row.
        let paths = match self.replica_coordinator.database().read::<_, SyncSqliteError>(|conn| {
            let mut found = Vec::new();
            for path in yadorilink_sync_sqlite::native_contest_candidates::unattempted_paths(
                conn, group_id,
            )? {
                let row = yadorilink_sync_sqlite::native_contest_candidates::local_row_fingerprint(
                    conn, group_id, &path,
                )?;
                found.push((path, row));
            }
            Ok(found)
        }) {
            Ok(paths) => paths,
            Err(error) => {
                tracing::debug!(group_id, %error, "listing the contested paths failed");
                return None;
            }
        };
        let mut settled = true;
        for (path, _) in &paths {
            match crate::store_residency::bring_current_versions_into_daemon_store_with(
                self, group_id, path, false,
            )
            .await
            {
                Ok(crate::store_residency::Residency::InStore) => {}
                Ok(crate::store_residency::Residency::Pending(_)) => settled = false,
                Err(error) => {
                    tracing::debug!(group_id, path, %error, "a contested version could not be kept in the store");
                    settled = false;
                }
            }
        }
        settled.then(|| paths.into_iter().collect())
    }

    /// Makes every contested path worth another fork pass and starts one in
    /// the background: the verified policy changed, and with it who may fork
    /// whose head.
    pub(crate) fn reconsider_contests_after_policy_change(self: &Arc<Self>) {
        let Ok(links) = self.replica_coordinator.link_repository().list_links() else { return };
        for link in links {
            let group = link.group_id;
            if let Err(error) =
                self.replica_coordinator.database().write::<_, SyncSqliteError>(|conn| {
                    yadorilink_sync_sqlite::native_contest_candidates::reset_attempts(conn, &group)
                })
            {
                tracing::debug!(%error, "resetting the contest candidates failed");
            }
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let state = Arc::downgrade(self);
        runtime.spawn(async move {
            if let Some(state) = state.upgrade() {
                state.fork_contested_heads_everywhere().await;
            }
        });
    }

    /// [`Self::fork_contested_heads`] for every active link, followed by the
    /// checkpoint flush and wake of a local commit for each group that signed.
    pub(crate) async fn fork_contested_heads_everywhere(&self) {
        let Ok(links) = self.replica_coordinator.link_repository().list_links() else { return };
        let mut groups: Vec<String> = links
            .into_iter()
            .filter(|link| !link.paused && !link.orphaned)
            .map(|link| link.group_id)
            .collect();
        groups.sort();
        groups.dedup();
        for group_id in groups {
            if self.fork_contested_group(&group_id).await > 0 {
                self.on_local_native_commit(&group_id).await;
            }
        }
    }
}

/// Test-only: devices whose contested versions are reported unsettled whatever the store holds,
/// to watch that no fork runs while a version is not settled and that one runs once it is.
#[cfg(any(test, feature = "test-support"))]
static HELD_FOR_TEST: std::sync::Mutex<std::collections::BTreeSet<String>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn hold_contest_settling_for_test(device_id: &str, held: bool) {
    let mut devices = HELD_FOR_TEST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if held {
        devices.insert(device_id.to_owned());
    } else {
        devices.remove(device_id);
    }
}

#[cfg(any(test, feature = "test-support"))]
fn held_for_test(device_id: &str) -> bool {
    HELD_FOR_TEST.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains(device_id)
}
