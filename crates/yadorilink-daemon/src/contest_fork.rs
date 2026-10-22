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

impl DaemonState {
    /// Forks every contested path of `group_id` this device may fork now.
    /// The number of deltas signed.
    pub(crate) fn fork_contested_heads(&self, group_id: &str) -> usize {
        let Some(author) = self.local_author() else { return 0 };
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
            return 0;
        }
        let eligible = |owner: &AuthorId, closed: bool| {
            let owner_is_writer = match &writers {
                Some(writers) => writers.contains(&owner.device.0),
                None => true,
            };
            fallback_may_fork(closed, owner_is_writer)
        };
        let result = self.replica_coordinator.author_contest_forks(&author, group_id, &eligible);
        match result {
            Ok(done) => {
                if done.refused > 0 {
                    tracing::warn!(
                        group_id,
                        refused = done.refused,
                        "some contested paths cannot be forked and stay contested"
                    );
                }
                done.deltas
            }
            Err(error) => {
                tracing::debug!(group_id, %error, "contest forks deferred");
                0
            }
        }
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
            if self.fork_contested_heads(&group_id) > 0 {
                self.on_local_native_commit(&group_id).await;
            }
        }
    }
}
