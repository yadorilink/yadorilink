//! `ProviderChangeRetentionJob` -- bounds the change feed the OS polls (`enumerateChanges`):
//! drops the oldest events of every provider root beyond the retention, which expires the
//! anchors that fall behind it (the OS then enumerates in full). Plain SQLite, no network I/O.

use std::sync::Arc;

use crate::daemon_state::run_blocking_sweep_offloaded;
use crate::replica_coordinator::ReplicaCoordinator;

#[derive(Clone)]
pub(crate) struct ProviderChangeRetentionJob {
    coordinator: Arc<ReplicaCoordinator>,
}

impl ProviderChangeRetentionJob {
    pub(crate) fn new(coordinator: Arc<ReplicaCoordinator>) -> Self {
        Self { coordinator }
    }

    pub(crate) fn run_once(&self) {
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let result = run_blocking_sweep_offloaded(|| {
            self.coordinator.provider_repository().prune_all_change_events(now_s)
        });
        if let Err(error) = result {
            tracing::warn!(%error, "could not apply the provider change-event retention");
        }
    }
}
