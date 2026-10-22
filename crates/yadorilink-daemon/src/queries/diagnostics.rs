//! `ConnectivityDoctor`/`ListConnectionTraces`'s read model. Like
//! `crate::queries::health`, this slice's dependencies (`RuntimeTelemetry`
//! and `SyncState`) are already narrow/cheap-clone owner types, so no
//! `DaemonState` strangler adapter is needed at all.

use std::sync::Arc;

use crate::connection_trace::DoctorCategory;
use crate::replica_coordinator::ReplicaCoordinator;
use crate::runtime_telemetry::RuntimeTelemetry;

pub(crate) struct DiagnosticsQueryService {
    telemetry: Arc<RuntimeTelemetry>,
    sync_state: Arc<ReplicaCoordinator>,
    device_id: String,
    links: Arc<crate::link_registry::LinkRegistry>,
}

impl DiagnosticsQueryService {
    pub(crate) fn new(
        telemetry: Arc<RuntimeTelemetry>,
        sync_state: Arc<ReplicaCoordinator>,
        device_id: String,
        links: Arc<crate::link_registry::LinkRegistry>,
    ) -> Self {
        Self { telemetry, sync_state, device_id, links }
    }

    pub(crate) fn connectivity_doctor(&self) -> Vec<DoctorCategory> {
        let mut categories = crate::connection_trace::run_connectivity_doctor(
            &self.telemetry,
            &self.sync_state,
            &self.device_id,
        );
        categories.push(watcher_category(&self.links.watch_limited_paths()));
        categories
    }

    pub(crate) fn recent_connection_traces(
        &self,
        peer_device_id: Option<&str>,
    ) -> Vec<crate::connection_trace::ConnectionAttemptTrace> {
        self.telemetry.recent_connection_attempts(peer_device_id)
    }
}

/// The "file watcher" doctor row: warns, with the fix, while any linked
/// folder has hit the OS watch limit.
fn watcher_category(limited: &[String]) -> DoctorCategory {
    if limited.is_empty() {
        return DoctorCategory {
            name: "file watcher",
            status: "ok",
            detail: "every linked folder is watched for changes".to_string(),
        };
    }
    DoctorCategory {
        name: "file watcher",
        status: "warn",
        detail: format!(
            "OS file watch limit reached for {} linked folder(s) ({}); local edits there reach \
             other devices late (periodic rescans) or not at all. Fix: {}",
            limited.len(),
            limited.join(", "),
            crate::link_registry::WATCH_LIMIT_FIX
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_reports_the_watch_limit_with_its_fix() {
        assert_eq!(watcher_category(&[]).status, "ok");
        let row = watcher_category(&["/data/a".to_string()]);
        assert_eq!(row.status, "warn");
        assert!(row.detail.contains("fs.inotify.max_user_watches"), "{}", row.detail);
        assert!(row.detail.contains("/data/a"), "{}", row.detail);
    }
}
