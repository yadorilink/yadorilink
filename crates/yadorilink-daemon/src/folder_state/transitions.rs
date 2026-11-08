//! The named transitions of a folder's degraded and ownership state.
//!
//! These are the only writers of the link registry's degraded marks: a folder
//! enters a degraded state through [`DaemonState::degrade_link`] and its
//! specializations, loses its ownership through [`DaemonState::lose_ownership`],
//! and leaves them through the `recover_*` / `restart_*` transitions. The
//! source-scan test in `tests.rs` keeps it that way.

use crate::daemon_state::{now_unix, DaemonState};
use crate::supervise;

impl DaemonState {
    /// Marks `local_path` Degraded for `cause` (`reason` is human detail only), scheduling its
    /// next re-check via `BackoffConfig::DEGRADED_LINK_RECHECK` — a link already degraded has
    /// its backoff attempt count bumped (spacing repeated pressure further
    /// apart, "not a tight retry loop") rather than reset, and
    /// keeps its original `since_unix` onset time.
    pub fn degrade_link(
        &self,
        local_path: &str,
        cause: crate::link_registry::DegradedCause,
        reason: String,
    ) {
        self.links.mark_degraded(local_path, reason, cause, now_unix(), |backoff_attempt| {
            supervise::BackoffConfig::DEGRADED_LINK_RECHECK.next(backoff_attempt).as_secs() as i64
        });
    }

    /// Marks a link as waiting for free disk space, with `detail` as its human text only.
    pub(crate) fn wait_for_disk_space(&self, local_path: &str, detail: String) {
        self.degrade_link(
            local_path,
            crate::link_registry::DegradedCause::WaitingForDiskSpace,
            detail,
        );
    }

    /// Marks a provider link as waiting for disk space on the volume of `probe_dir`, the place
    /// its reads are staged. The link's key is not a path, so the re-check measures `probe_dir`.
    pub(crate) fn wait_for_disk_space_on_volume(
        &self,
        link_key: &str,
        probe_dir: &std::path::Path,
        reason: String,
    ) {
        self.degraded_volume_probes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(link_key.to_string(), probe_dir.to_path_buf());
        self.wait_for_disk_space(link_key, reason);
    }

    /// The path whose volume is measured to decide whether `link_key` has room again.
    pub(crate) fn space_probe_path(&self, link_key: &str) -> std::path::PathBuf {
        self.degraded_volume_probes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(link_key)
            .cloned()
            .unwrap_or_else(|| std::path::PathBuf::from(link_key))
    }

    /// Terminal OwnershipLost for `local_path`; true on the first transition only.
    pub fn lose_ownership(&self, local_path: &str) -> bool {
        self.links.mark_ownership_lost(local_path, now_unix())
    }

    /// Clears `local_path`'s Degraded state, if any — a no-op if it wasn't
    /// degraded.
    pub fn recover_link(&self, local_path: &str) {
        self.links.clear_degraded(local_path);
        self.degraded_volume_probes.lock().unwrap_or_else(|p| p.into_inner()).remove(local_path);
    }

    /// Clears `local_path`'s Degraded state if its volume is no longer Critical. An
    /// undeterminable volume stays degraded. True when it cleared.
    pub(crate) fn recover_link_if_space_recovered(&self, local_path: &str) -> bool {
        if !self.links.is_degraded(local_path) {
            return false;
        }
        let headroom_override = self.governance_config.load_or_default().headroom_override_bytes;
        match yadorilink_local_storage::free_space::classify_volume(
            &self.space_probe_path(local_path),
            headroom_override,
        ) {
            Ok(space) if space.recovered() => {
                self.recover_link(local_path);
                true
            }
            _ => false,
        }
    }

    /// A fresh link start leaves a terminal OwnershipLost mark behind.
    pub(crate) fn restart_after_ownership_loss(&self, local_path: &str) {
        self.links.clear_ownership_lost(local_path);
    }
}

/// Terminal stop of a folder whose build has no OS watcher, so it has no source of changes.
#[cfg(not(feature = "process-model"))]
pub(crate) fn stop_without_change_source(
    links: &crate::link_registry::LinkRegistry,
    local_path: &str,
) {
    links.mark_no_change_source(local_path, now_unix());
}

/// The folder is missing or off the volume recorded for it: its start is refused and it waits
/// for the volume to return.
pub(crate) fn await_volume(links: &crate::link_registry::LinkRegistry, local_path: &str) {
    links.mark_awaiting_volume(local_path);
}

/// The folder started, or was stopped and unlinked: it no longer waits for its volume.
pub(crate) fn stop_awaiting_volume(links: &crate::link_registry::LinkRegistry, local_path: &str) {
    links.clear_awaiting_volume(local_path);
}

/// The folder's watcher bound; `limit_hit` is the watcher's live flag for running out of OS
/// watches.
pub(crate) fn watcher_bound(
    links: &crate::link_registry::LinkRegistry,
    local_path: &str,
    limit_hit: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    links.track_watcher(local_path, limit_hit);
}

/// The folder's watcher could not be bound for lack of OS watches, so the folder is not running.
pub(crate) fn watch_limit_blocked_start(
    links: &crate::link_registry::LinkRegistry,
    local_path: &str,
) {
    links.record_watch_limit_startup_failure(local_path);
}

/// The folder's watcher failed for another reason: an earlier watch-limit condition no longer
/// describes it.
pub(crate) fn watch_limit_forgotten(links: &crate::link_registry::LinkRegistry, local_path: &str) {
    links.clear_watch_limit(local_path);
}
