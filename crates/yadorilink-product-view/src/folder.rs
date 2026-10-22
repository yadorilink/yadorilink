//! `FolderSummary`/`FolderMode`/`FolderState`/`FolderTransfer` — the
//! product-facing view of one linked folder, derived entirely from
//! `LinkStatus` (`daemon_control.proto`, `StatusResponse.links`).
//!
//! Pure and synchronous: building a `FolderSummary` never blocks on
//! network I/O (the coordination-plane `peer_count`/`device_summaries`
//! calls live in `device.rs` instead, precisely so a folder list can be
//! rendered from a single already-fetched `StatusResponse` without also
//! waiting on the coordination plane per row).

use yadorilink_ipc_proto::daemonctl::LinkStatus;

// Re-exported rather than re-derived — see the module doc above.
// `DurabilityStatus` gets a rename because
// the wire type's own name (`GroupDurabilityStatus`) reads oddly once it's
// a field on a `Folder`-scoped DTO that already has `full_replica_device_ids`
// next to it; `LocalStorageState`/`FetchAvailability` keep their wire names
// as-is since those already read naturally in UI code.
pub use yadorilink_ipc_proto::daemonctl::FetchAvailability;
pub use yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus as DurabilityStatus;
pub use yadorilink_ipc_proto::daemonctl::LocalStorageState;

/// A linked folder's short display name: its last path segment, so a long
/// path doesn't blow out a menu's width or a window's heading. Falls back
/// to the whole path when there is no final segment (a filesystem root).
/// The folder's name for display: a provider folder's own name (it has no path), else the last
/// segment of its path.
pub fn link_name(link: &LinkStatus) -> String {
    if link.provider_display_name.is_empty() {
        display_name(&link.local_path)
    } else {
        link.provider_display_name.clone()
    }
}

pub fn display_name(local_path: &str) -> String {
    std::path::Path::new(local_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| local_path.to_string())
}

/// The configured target for a folder's local materialization — what this
/// device is trying to become, not what it currently holds (that's
/// `LocalStorageState`, kept as its own field on `FolderSummary`). Derived
/// straight from `LinkStatus.materialization_policy`, matching the
/// `== "ondemand"` check every other reader of this field already uses
/// (`yadorilink-cli`'s `status.rs`/`link.rs`, `share.rs`) — an unrecognized
/// future policy value reads as `Synced`, the same default those call
/// sites already apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FolderMode {
    Synced,
    Selective,
}

impl FolderMode {
    pub fn from_link(link: &LinkStatus) -> Self {
        if link.materialization_policy == "ondemand" {
            FolderMode::Selective
        } else {
            FolderMode::Synced
        }
    }
}

/// A folder's coarse product-facing state, built **only** from
/// `LinkStatus`'s own fields (never from peer reachability). Unlike a
/// `Synced|Selective|Disconnected` / `UpToDate|Syncing|Offline|Attention`
/// shape, there is no
/// `Disconnected` *mode* (folders are unconditionally bidirectional on the
/// wire) and no `Offline` *state* (that would require peer reachability).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FolderState {
    UpToDate,
    Syncing,
    Paused,
    /// This folder group is linked at more than one local folder and
    /// therefore syncs nothing at all — see `LinkStatus.ambiguous`'s own
    /// doc comment for why. Named for what a Home/Folder screen's copy
    /// would say, not for the wire field.
    Blocked,
    Attention,
}

impl FolderState {
    /// Precedence: ambiguous > paused > (degraded or a conflict) > actively
    /// syncing > up to date. This is intentionally the same precedence as
    /// `status_model::folder_menu_label`'s own suffix chain — `status_model.rs`
    /// now derives its suffix from this function instead of keeping an
    /// independent copy of the ordering.
    pub fn from_link(link: &LinkStatus) -> Self {
        if link.ambiguous {
            FolderState::Blocked
        } else if link.paused {
            FolderState::Paused
        } else if link.degraded || link.conflict_count > 0 {
            FolderState::Attention
        } else if link.has_active_transfer {
            FolderState::Syncing
        } else {
            FolderState::UpToDate
        }
    }
}

/// Live-transfer byte/block progress for one folder, passed through from
/// the daemon's own already-computed rollup — never re-derived from
/// anything lower-level (no block/native-state inspection here). `Some` iff
/// `LinkStatus.has_active_transfer`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderTransfer {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub blocks_done: u64,
    pub blocks_total: u64,
    pub eta_seconds: u64,
}

/// The product-facing view of one linked folder. `files_total`/
/// `bytes_total`/`peer_count` are deliberately **not** flat fields here
/// (the peer count comes from the coordination plane, see `device.rs`).
#[derive(Clone, Debug, PartialEq)]
pub struct FolderSummary {
    pub group_id: String,
    pub name: String,
    pub local_path: String,
    pub mode: FolderMode,
    pub state: FolderState,
    pub paused: bool,
    pub conflict_count: u64,
    pub files_hydrated: u64,
    pub files_placeholder: u64,
    pub files_hydrating: u64,
    pub held_file_count: u64,
    pub skipped_symlink_count: u64,
    pub transfer: Option<FolderTransfer>,
    pub durability_status: DurabilityStatus,
    pub local_storage_state: LocalStorageState,
    pub fetch_availability: FetchAvailability,
    pub full_replica_device_ids: Vec<String>,
    pub policy_stale: bool,
    pub ambiguous: bool,
    pub ambiguous_local_paths: Vec<String>,
    pub degraded: bool,
    pub degraded_reason: String,
}

impl From<&LinkStatus> for FolderSummary {
    fn from(link: &LinkStatus) -> Self {
        let transfer = if link.has_active_transfer {
            Some(FolderTransfer {
                bytes_done: link.transfer_bytes_done,
                bytes_total: link.transfer_bytes_total,
                blocks_done: link.transfer_blocks_done,
                blocks_total: link.transfer_blocks_total,
                eta_seconds: link.transfer_eta_seconds,
            })
        } else {
            None
        };

        FolderSummary {
            group_id: link.group_id.clone(),
            name: link_name(link),
            local_path: link.local_path.clone(),
            mode: FolderMode::from_link(link),
            state: FolderState::from_link(link),
            paused: link.paused,
            conflict_count: link.conflict_count,
            files_hydrated: link.hydrated_count,
            files_placeholder: link.placeholder_count,
            files_hydrating: link.hydrating_count,
            held_file_count: link.held_file_count,
            skipped_symlink_count: link.skipped_symlink_count,
            transfer,
            durability_status: link.durability_status(),
            local_storage_state: link.local_storage_state(),
            fetch_availability: link.fetch_availability(),
            full_replica_device_ids: link.full_replica_device_ids.clone(),
            policy_stale: link.policy_stale,
            ambiguous: link.ambiguous,
            ambiguous_local_paths: link.ambiguous_local_paths.clone(),
            degraded: link.degraded,
            degraded_reason: link.degraded_reason.clone(),
        }
    }
}

impl FolderSummary {
    /// `files_hydrated + files_placeholder + files_hydrating` — the "one
    /// number" total a UI can compute trivially at the call site (deliberately
    /// not a stored field: baking it in risks it going stale relative to the
    /// three source counts).
    pub fn files_total(&self) -> u64 {
        self.files_hydrated + self.files_placeholder + self.files_hydrating
    }
}

#[cfg(test)]
mod tests;
