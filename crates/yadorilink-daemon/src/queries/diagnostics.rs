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
    governance: Arc<crate::governance_config::GovernanceConfigStore>,
}

impl DiagnosticsQueryService {
    pub(crate) fn new(
        telemetry: Arc<RuntimeTelemetry>,
        sync_state: Arc<ReplicaCoordinator>,
        device_id: String,
        links: Arc<crate::link_registry::LinkRegistry>,
        governance: Arc<crate::governance_config::GovernanceConfigStore>,
    ) -> Self {
        Self { telemetry, sync_state, device_id, links, governance }
    }

    pub(crate) fn connectivity_doctor(&self) -> Vec<DoctorCategory> {
        let mut categories = crate::connection_trace::run_connectivity_doctor(
            &self.telemetry,
            &self.sync_state,
            &self.device_id,
        );
        categories.push(watcher_category(&self.links.watch_limited_paths()));
        categories.push(self.version_history_category());
        categories
    }

    /// What the kept version history is bounded by, and whether the disk has made it give up
    /// versions: each linked folder's free space against its headroom, and how many versions
    /// were not kept for lack of space.
    fn version_history_category(&self) -> DoctorCategory {
        let headroom_override = self.governance.load_or_default().headroom_override_bytes;
        let mut volumes = Vec::new();
        let mut not_kept_for_space = 0u32;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        let links = match self.sync_state.link_repository().list_links() {
            Ok(links) => links,
            Err(error) => {
                tracing::warn!(%error, "doctor: the linked folders could not be read");
                return DoctorCategory {
                    name: "version history",
                    status: "warn",
                    detail: "the linked folders could not be read".to_string(),
                };
            }
        };
        for link in links {
            if let Ok(space) = yadorilink_local_storage::free_space::classify_volume(
                std::path::Path::new(link.key()),
                headroom_override,
            ) {
                volumes.push((link.key().to_string(), space));
            }
            not_kept_for_space = not_kept_for_space.saturating_add(
                self.sync_state
                    .database()
                    .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                        yadorilink_sync_sqlite::history_freed::count_low_space_since(
                            conn,
                            &link.group_id,
                            now_unix - 30 * 86_400,
                        )
                    })
                    .unwrap_or(0),
            );
        }
        version_history_category(&volumes, not_kept_for_space)
    }

    pub(crate) fn recent_connection_traces(
        &self,
        peer_device_id: Option<&str>,
    ) -> Vec<crate::connection_trace::ConnectionAttemptTrace> {
        self.telemetry.recent_connection_attempts(peer_device_id)
    }
}

/// The "version history" doctor row. Warns while a linked folder's volume is at or below its
/// headroom (replaced versions are then not kept) or when versions were already not kept for
/// lack of space.
fn version_history_category(
    volumes: &[(String, yadorilink_local_storage::VolumeFreeSpace)],
    not_kept_for_space: u32,
) -> DoctorCategory {
    use yadorilink_local_storage::free_space::FreeSpaceState;
    let mib = |bytes: u64| format!("{} MiB", bytes / (1024 * 1024));
    let mut detail = format!(
        "keeps up to {} older versions of a file and everything from the last {} days; a replaced \
         version is not kept when the disk has no room for it",
        yadorilink_sync_sqlite::file_index::RETENTION_MAX_VERSIONS,
        yadorilink_sync_sqlite::file_index::RETENTION_MAX_AGE_DAYS,
    );
    for (folder, space) in volumes {
        detail.push_str(&format!(
            "; {folder}: {} free, {} kept free",
            mib(space.available_bytes),
            mib(space.headroom_bytes)
        ));
    }
    if not_kept_for_space > 0 {
        detail.push_str(&format!(
            "; {not_kept_for_space} version(s) were not kept for space in the last 30 days"
        ));
    }
    let full = volumes.iter().any(|(_, space)| space.classify() == FreeSpaceState::Critical);
    let status = if full || not_kept_for_space > 0 { "warn" } else { "ok" };
    DoctorCategory { name: "version history", status, detail }
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

    fn space(available: u64) -> yadorilink_local_storage::VolumeFreeSpace {
        const GIB: u64 = 1024 * 1024 * 1024;
        yadorilink_local_storage::VolumeFreeSpace {
            available_bytes: available,
            total_bytes: 100 * GIB,
            headroom_bytes: GIB,
        }
    }

    #[test]
    fn doctor_reports_version_history_rule_free_space_and_skips() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let healthy = version_history_category(&[("/data/a".into(), space(50 * GIB))], 0);
        assert_eq!(healthy.status, "ok");
        assert!(healthy.detail.contains("up to 10 older versions"), "{}", healthy.detail);
        assert!(healthy.detail.contains("30 days"), "{}", healthy.detail);
        assert!(healthy.detail.contains("/data/a: 51200 MiB free, 1024 MiB kept free"));

        let full = version_history_category(&[("/data/a".into(), space(GIB / 2))], 0);
        assert_eq!(full.status, "warn", "a volume below its headroom gives versions up");

        let skipped = version_history_category(&[("/data/a".into(), space(50 * GIB))], 3);
        assert_eq!(skipped.status, "warn");
        assert!(skipped
            .detail
            .contains("3 version(s) were not kept for space in the last 30 days"));
    }

    #[test]
    fn doctor_reports_the_watch_limit_with_its_fix() {
        assert_eq!(watcher_category(&[]).status, "ok");
        let row = watcher_category(&["/data/a".to_string()]);
        assert_eq!(row.status, "warn");
        assert!(row.detail.contains("fs.inotify.max_user_watches"), "{}", row.detail);
        assert!(row.detail.contains("/data/a"), "{}", row.detail);
    }
}
