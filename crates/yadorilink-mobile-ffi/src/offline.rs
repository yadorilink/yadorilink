//! Keeping items on the device on the embedded engine: pin, unpin, an item's policy, freeing its
//! local copy, and a preview of what automatic space management would free. Each method is one
//! command of `yadorilink-embedded-host`, which runs the service the desktop daemon runs for the
//! same request. Items are named as the provider surface names them (`root_id`, `item_id`).
//! Downloading is not a method: the operating system downloads an item when it is opened.

use yadorilink_embedded_host as host;

use crate::{CallFailure, CancelHandle, MobileHost};

fn unexpected(command: &str, output: &host::CommandOutput) -> CallFailure {
    CallFailure::Failed {
        reason: crate::FailureReason::Unspecified,
        message: format!("{command} returned {output:?}"),
    }
}

/// The retention policy in force at one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ItemRetention {
    /// Local space for the item must not be reclaimed.
    pub pinned: bool,
    /// The folder holds no copy of the item (an online-only rule).
    pub online_only: bool,
    /// The rule was set at exactly this item; otherwise a folder above holds it.
    pub explicit: bool,
}

impl From<host::ItemRetention> for ItemRetention {
    fn from(r: host::ItemRetention) -> Self {
        Self { pinned: r.pinned, online_only: r.online_only, explicit: r.explicit }
    }
}

/// What a person chooses for an item's copy on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RetentionRule {
    Keep,
    OnlineOnly,
    /// Remove the rule set at exactly this item.
    Default,
}

impl From<RetentionRule> for host::RetentionRule {
    fn from(rule: RetentionRule) -> Self {
        match rule {
            RetentionRule::Keep => Self::Keep,
            RetentionRule::OnlineOnly => Self::OnlineOnly,
            RetentionRule::Default => Self::Default,
        }
    }
}

/// What setting a rule on an item did. The rule stands even when `download_error` is set.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PinOutcome {
    pub retention: ItemRetention,
    /// Why the content could not be fetched just now, when it could not.
    pub download_error: Option<String>,
    /// Why a file beneath the item is not yet held (`changing_retry`: pin again once it settles;
    /// `not_kept_error`: could not be checked), when one is not.
    pub history_not_kept_reason: Option<String>,
}

/// What freeing the local copy of an item did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EvictOutcome {
    /// The operating system dropped its copy.
    pub dehydrated: bool,
    pub blocks_reclaimed: u64,
    pub bytes_reclaimed: u64,
    /// Why the engine's cached blocks stayed, when they did (a stable code).
    pub retained_reason: Option<String>,
}

/// What automatic space management would do with one item now.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SpaceReclaimItem {
    pub root_id: Vec<u8>,
    pub item_id: Vec<u8>,
    pub path: String,
    /// `eligible`, `pinned`, `unsupported_root`, `custody_unavailable`, `busy`, `changed` or
    /// `safety_blocked`.
    pub verdict: String,
}

/// What automatic space management would free now.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SpaceReclaimPreview {
    pub items: Vec<SpaceReclaimItem>,
    /// Folders that could not be read; their items are missing from `items`.
    pub unreadable_roots: u32,
}

/// Why a conflict copy exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConflictReason {
    /// Concurrent changes to the same path; the copy holds the version that did not win.
    ConcurrentEdit,
    /// The original name is a folder now, so the file was moved aside.
    FolderAtPath,
}

/// How to settle a conflict copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConflictResolution {
    /// The copy's content becomes the file under the original name; the copy stays.
    KeepThis,
    /// The copy is kept beside the original under a free name.
    KeepBoth,
}

/// One conflict copy of a provider folder.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ConflictedFile {
    pub root_id: Vec<u8>,
    /// What `resolve_conflict` names.
    pub item_id: Vec<u8>,
    pub path: String,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub reason: ConflictReason,
    /// Keep this / Keep both is offered.
    pub resolvable: bool,
    pub origin_device_id: Option<String>,
}

/// A change waiting on the operating system.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingPublication {
    pub root_id: String,
    pub path: String,
    pub age_ms: u64,
}

#[uniffi::export]
impl MobileHost {
    /// Sets the retention rule at an item: keep it on this device, keep nothing of it in the
    /// folder, or remove the rule set there. Recorded first; stands even when a download it starts
    /// fails.
    ///
    /// # Errors
    /// `Failed` for an unknown root or item, or a rule that does not apply to the folder; the
    /// other [`CallFailure`] cases.
    pub fn set_retention_rule(
        &self,
        root_id: Vec<u8>,
        item_id: Vec<u8>,
        rule: RetentionRule,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<PinOutcome, CallFailure> {
        match self.run(
            host::Command::SetRetentionRule { root_id, item_id, rule: rule.into() },
            cancel,
            deadline_ms,
        )? {
            host::CommandOutput::Pinned(outcome) => Ok(PinOutcome {
                retention: outcome.retention.into(),
                download_error: outcome.download_error,
                history_not_kept_reason: outcome.history_not_kept_reason,
            }),
            other => Err(unexpected("set_retention_rule", &other)),
        }
    }

    /// The retention policy in force at one item. Read-only.
    ///
    /// # Errors
    /// `Failed` for an unknown root or item; the other [`CallFailure`] cases.
    pub fn item_retention(
        &self,
        root_id: Vec<u8>,
        item_id: Vec<u8>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<ItemRetention, CallFailure> {
        match self.run(host::Command::ItemRetention { root_id, item_id }, cancel, deadline_ms)? {
            host::CommandOutput::Retention(r) => Ok(r.into()),
            other => Err(unexpected("item_retention", &other)),
        }
    }

    /// Frees the local copy of one item.
    ///
    /// # Errors
    /// `Failed` for an unknown root or item, or a refused eviction; the other [`CallFailure`]
    /// cases.
    pub fn evict_item(
        &self,
        root_id: Vec<u8>,
        item_id: Vec<u8>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<EvictOutcome, CallFailure> {
        match self.run(host::Command::EvictItem { root_id, item_id }, cancel, deadline_ms)? {
            host::CommandOutput::Evicted(o) => Ok(EvictOutcome {
                dehydrated: o.dehydrated,
                blocks_reclaimed: o.blocks_reclaimed,
                bytes_reclaimed: o.bytes_reclaimed,
                retained_reason: o.retained_reason,
            }),
            other => Err(unexpected("evict_item", &other)),
        }
    }

    /// What automatic space management would free now, without freeing anything. Read-only.
    ///
    /// # Errors
    /// `Failed` when automatic space management is not available; the other [`CallFailure`] cases.
    pub fn preview_space_reclaim(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<SpaceReclaimPreview, CallFailure> {
        match self.run(host::Command::PreviewSpaceReclaim, cancel, deadline_ms)? {
            host::CommandOutput::SpaceReclaim(p) => Ok(SpaceReclaimPreview {
                items: p
                    .items
                    .into_iter()
                    .map(|i| SpaceReclaimItem {
                        root_id: i.root_id,
                        item_id: i.item_id,
                        path: i.path,
                        verdict: i.verdict,
                    })
                    .collect(),
                unreadable_roots: p.unreadable_roots,
            }),
            other => Err(unexpected("preview_space_reclaim", &other)),
        }
    }

    /// The conflict copies of the provider folders. Read-only.
    ///
    /// # Errors
    /// `Failed` when the index cannot be read; the other [`CallFailure`] cases.
    pub fn list_conflicts(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<ConflictedFile>, CallFailure> {
        match self.run(host::Command::ListConflicts, cancel, deadline_ms)? {
            host::CommandOutput::Conflicts(files) => Ok(files
                .into_iter()
                .map(|f| ConflictedFile {
                    root_id: f.root_id,
                    item_id: f.item_id,
                    path: f.path,
                    size: f.size,
                    mtime_unix_nanos: f.mtime_unix_nanos,
                    reason: match f.reason {
                        host::ConflictReason::ConcurrentEdit => ConflictReason::ConcurrentEdit,
                        host::ConflictReason::FolderAtPath => ConflictReason::FolderAtPath,
                    },
                    resolvable: f.resolvable,
                    origin_device_id: f.origin_device_id,
                })
                .collect()),
            other => Err(unexpected("list_conflicts", &other)),
        }
    }

    /// Settles one conflict copy and returns where its content is afterwards. Every precondition
    /// is read again while it runs; a copy that is gone or no longer resolvable is a typed
    /// refusal and nothing changes.
    ///
    /// # Errors
    /// `Refused` with `TargetNotFound`, `ConflictNotResolvable` or `UnrecordedLocalChanges`;
    /// the other [`CallFailure`] cases.
    pub fn resolve_conflict(
        &self,
        root_id: Vec<u8>,
        item_id: Vec<u8>,
        resolution: ConflictResolution,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<String, CallFailure> {
        let resolution = match resolution {
            ConflictResolution::KeepThis => host::ConflictResolution::KeepThis,
            ConflictResolution::KeepBoth => host::ConflictResolution::KeepBoth,
        };
        let command = host::Command::ResolveConflict { root_id, item_id, resolution };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::ConflictResolved(path) => Ok(path),
            other => Err(unexpected("resolve_conflict", &other)),
        }
    }

    /// Up to `limit` changes per folder waiting on the operating system, oldest first. Read-only.
    ///
    /// # Errors
    /// `Failed` when the read fails (never an empty list); the other [`CallFailure`] cases.
    pub fn list_provider_pending(
        &self,
        limit: u32,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<PendingPublication>, CallFailure> {
        match self.run(host::Command::ListProviderPending { limit }, cancel, deadline_ms)? {
            host::CommandOutput::ProviderPending(items) => Ok(items
                .into_iter()
                .map(|p| PendingPublication { root_id: p.root_id, path: p.path, age_ms: p.age_ms })
                .collect()),
            other => Err(unexpected("list_provider_pending", &other)),
        }
    }
}
