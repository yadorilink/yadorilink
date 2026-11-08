//! One read-only answer to "may this folder advance, and if not, why not?".
//!
//! The inputs live in different places (the link row, the in-memory link
//! registry, the volume probe, the policy authority, the folder's own audit);
//! a [`FolderSnapshot`] reads them once, from the same facts the status view
//! composes, and names every reason the folder is held back as a
//! [`FolderBlocker`]. It is a view: nothing here writes, and nothing decides
//! differently from the readers it calls.

use crate::link_registry::DegradedCause;
use crate::queries::link_status::LinkFacts;

/// One reason a folder is not advancing normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FolderBlocker {
    /// The person paused the folder; both directions stop.
    Paused,
    /// The link is degraded, or no longer joined to its group; the cause is the typed one
    /// status reports (watch limit, disk space, ownership lost, not joined, stopped).
    Degraded(DegradedCause),
    /// The folder's root is no longer on the volume its index was built from.
    CaptureVolumeChanged,
    /// The folder's root is on a volume only the person can confirm as its own.
    CaptureVolumeUnconfirmed,
    /// The group's policy is distrusted; local authoring and admission fail closed.
    PolicyStale,
    /// More than one live folder is linked to the group; none syncs.
    AmbiguousLink,
    /// A stored file record cannot be read back.
    IndexDamaged,
    /// History can no longer catch up by deltas; waiting for a peer's sealed state.
    RebuildNeeded,
}

impl FolderBlocker {
    /// Stable lowercase label for diagnostics. Never a path or any user data.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Paused => "paused",
            Self::Degraded(DegradedCause::WaitingForDiskSpace) => "degraded:waiting_for_disk_space",
            Self::Degraded(DegradedCause::FileWatchLimit) => "degraded:file_watch_limit",
            Self::Degraded(DegradedCause::OwnershipLost) => "degraded:ownership_lost",
            Self::Degraded(DegradedCause::NotJoined) => "degraded:not_joined",
            Self::Degraded(DegradedCause::Stopped) => "degraded:stopped",
            Self::CaptureVolumeChanged => "capture_volume_changed",
            Self::CaptureVolumeUnconfirmed => "capture_volume_unconfirmed",
            Self::PolicyStale => "policy_stale",
            Self::AmbiguousLink => "ambiguous_link",
            Self::IndexDamaged => "index_damaged",
            Self::RebuildNeeded => "rebuild_needed",
        }
    }
}

/// Every reason one folder is held back right now, in a fixed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FolderSnapshot {
    blockers: Vec<FolderBlocker>,
    pending_local_changes: u64,
}

impl FolderSnapshot {
    /// Reads the gates for the folder `facts` describes. `degraded` and `policy_stale` are the
    /// values the caller already read for the same view, so one view never disagrees with itself.
    pub(crate) fn read(
        facts: &LinkFacts,
        degraded: Option<DegradedCause>,
        policy_stale: bool,
    ) -> Self {
        let link = &facts.link;
        let mut blockers = Vec::new();
        if link.paused {
            blockers.push(FolderBlocker::Paused);
        }
        if let Some(cause) = degraded {
            blockers.push(FolderBlocker::Degraded(cause));
        }
        if facts.capture_volume_changed {
            blockers.push(FolderBlocker::CaptureVolumeChanged);
        }
        if facts.capture_volume_unconfirmed {
            blockers.push(FolderBlocker::CaptureVolumeUnconfirmed);
        }
        if policy_stale {
            blockers.push(FolderBlocker::PolicyStale);
        }
        if facts.ambiguous_local_paths.len() > 1 {
            blockers.push(FolderBlocker::AmbiguousLink);
        }
        if facts.index_damaged_path.is_some() {
            blockers.push(FolderBlocker::IndexDamaged);
        }
        if facts.rebuild_needed {
            blockers.push(FolderBlocker::RebuildNeeded);
        }
        Self { blockers, pending_local_changes: facts.pending_local_changes }
    }

    /// Changes (deltas and captured edits, not files) made on this device that no other device
    /// is known to hold yet; 0 when the group has no other device.
    pub(crate) fn pending_local_changes(&self) -> u64 {
        self.pending_local_changes
    }

    pub(crate) fn blockers(&self) -> &[FolderBlocker] {
        &self.blockers
    }

    /// True when nothing holds the folder back.
    #[cfg(test)]
    pub(crate) fn may_advance(&self) -> bool {
        self.blockers.is_empty()
    }
}

mod transitions;
#[cfg(not(feature = "process-model"))]
pub(crate) use transitions::stop_without_change_source;
pub(crate) use transitions::{
    await_volume, stop_awaiting_volume, watch_limit_blocked_start, watch_limit_forgotten,
    watcher_bound,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod label_tests {
    use super::*;

    #[test]
    fn every_degraded_cause_has_its_own_label() {
        let causes = [
            DegradedCause::WaitingForDiskSpace,
            DegradedCause::FileWatchLimit,
            DegradedCause::OwnershipLost,
            DegradedCause::NotJoined,
            DegradedCause::Stopped,
        ];
        let labels: std::collections::HashSet<_> =
            causes.iter().map(|c| FolderBlocker::Degraded(*c).label()).collect();
        assert_eq!(labels.len(), causes.len());
    }
}
