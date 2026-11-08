//! Writes from the app (Dropbox-style): upload a file, make a folder, rename, move, delete, and
//! know whether what this phone wrote has reached a device that keeps a full replica.
//!
//! Four calls, each one command of `yadorilink-embedded-host`:
//!
//! - [`MobileHost::stage_upload`] puts a file into the engine's ingest directory by move, clone
//!   or copy and returns what the write must name (`ingest_name`, `size`, `sha256`). It is flushed
//!   before it returns. Free space is checked before a copy reads anything.
//! - [`MobileHost::apply_change`] is one change to a provider folder: create, modify (new
//!   contents, rename, move) or delete. It is the engine's provider write path (the one the Mac
//!   File Provider uses), answered with a typed [`WriteResult`]: applied (with the outcome the
//!   engine decided, `Concurrent` and `FileSurvived` keeping both versions) or refused (a typed
//!   [`WriteRefusal`]).
//! - [`MobileHost::discard_staged_upload`] removes a staged file the app gave up on.
//! - [`MobileHost::version_delivery`] asks, for versions this device authored, whether a device
//!   that keeps a full replica holds exactly that version. Only that is "saved".
//!
//! # The operation identity
//!
//! `(session_id, operation_seq)` names ONE logical operation and the app owns it: it generates
//! the pair when the user acts, persists it with the pending operation (its upload queue) and
//! sends the same pair on every retry. `session_id` is 1 to 64 bytes (16 random bytes minted once
//! per installation is the model), `operation_seq` starts at 1 and increases per session. A retry
//! after a lost response, a kill between commit and acknowledgement or a cancelled call returns
//! the stored outcome (`replayed: true`) and authors nothing again; the same pair with different
//! content or target is `OperationMismatch`. `request_id` is per attempt and only echoed.
//!
//! # Durable before acknowledged
//!
//! `Applied` is returned only after the change is committed in the engine's database with the
//! drive cache flushed, and its blocks stored durably. If the app is killed first, nothing was
//! acknowledged, and the retry either finds the stored outcome or authors it once.
//!
//! # What the engine refuses
//!
//! `NotAuthorized`: this device is not a writer of the folder's group (a Reader, a folder whose
//! group policy is not verified yet, a folder another account shared without write access).
//! Check `ProviderFolder.read_only` (the wire listing) before offering write actions.
//! `StaleView`: a generation the change was made against moved; nothing was authored, refresh and
//! retry. `NameCollision`: the name exists; the app chooses (replace as a new version, keep both
//! under another name, cancel). `KeepLocal`: the item was retired or is unknown; the bytes are
//! kept, and `suggested_name` is the name to create them under as a new item.
//!
//! # Cancelling
//!
//! `apply_change` and `stage_upload` change state, so cancelling the call or running out of time
//! leaves them running (`still_running`): call `apply_change` again with the same operation
//! identity to learn the outcome. Do not cancel a stage; give it a generous deadline. A staged
//! file nothing claims is removed by the engine after a safety age.

use yadorilink_embedded_host as host;
use yadorilink_ipc_proto::shellipc as wire;

use crate::{CallFailure, CancelHandle, MobileHost};

fn unexpected(command: &str, output: &host::CommandOutput) -> CallFailure {
    CallFailure::Failed {
        reason: crate::FailureReason::Unspecified,
        message: format!("{command} returned {output:?}"),
    }
}

// ---- stage ---------------------------------------------------------------------------------

/// How a file reaches the engine's ingest directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum StageMode {
    /// Rename: no bytes are copied and the source is gone. Falls back to a copy (and then removes
    /// the source) only where a rename cannot work (another volume, other hard links).
    Move,
    /// A copy-on-write clone where the file system has one, else a copy. The source stays.
    Clone,
    /// A streamed copy. The source stays.
    Copy,
}

impl From<StageMode> for host::StageMode {
    fn from(mode: StageMode) -> Self {
        match mode {
            StageMode::Move => Self::Move,
            StageMode::Clone => Self::Clone,
            StageMode::Copy => Self::Copy,
        }
    }
}

/// What is staged.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum StageSource {
    /// A regular file by absolute path (not through a final symlink).
    Path { path: String },
    /// An open descriptor of a regular file. The engine duplicates it; the caller keeps and
    /// closes its own. The file is cloned or copied, never moved.
    Descriptor { fd: i32 },
}

/// How the staged file was made: `Moved` and `Cloned` copied no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum StagedHow {
    Moved,
    Cloned,
    Copied,
}

/// A file staged in the engine's ingest directory, to be named by a following change.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StagedUpload {
    pub ingest_name: String,
    pub size: u64,
    /// SHA-256 of the whole file (32 bytes).
    pub sha256: Vec<u8>,
    pub how: StagedHow,
}

/// The answer of `stage_upload`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum StageResult {
    Staged {
        upload: StagedUpload,
    },
    /// `LowDisk` (nothing was read), `IngestRejected` (not a regular file this process owns),
    /// `IngestUnstable` (missing, or it changed while staged), `NotReady` (the engine has no
    /// temp root) or `Retry`.
    Refused {
        code: WriteRefusal,
        message: String,
    },
}

// ---- apply ---------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WriteKind {
    /// A new file or folder under `parent_item_id` (empty: the folder's root).
    Create,
    /// An existing item: new contents (`content`), a new name (`name`), a new place
    /// (`parent_item_id`), or several in one request.
    Modify,
    /// An existing item (a folder with `recursive`).
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WriteEntryKind {
    File,
    Directory,
}

/// The staged bytes of a create or modify: exactly what `stage_upload` returned.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WriteContent {
    pub ingest_name: String,
    pub size: u64,
    pub sha256: Vec<u8>,
}

/// One change. Ids are the bytes the engine returned (`ProviderFolder.root_id`, the applied
/// item's `item_id`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WriteChange {
    /// Per attempt; echoed in nothing the app needs to match. Any non-empty bytes.
    pub request_id: Vec<u8>,
    /// The operation identity; see the module docs.
    pub session_id: Vec<u8>,
    pub operation_seq: u64,
    pub root_id: Vec<u8>,
    pub kind: WriteKind,
    /// Modify, delete: the item. Create: empty.
    pub item_id: Vec<u8>,
    /// Create: the folder to create in (`Some(empty)` or `None`: the root). Modify: set only to
    /// move.
    pub parent_item_id: Option<Vec<u8>>,
    /// Create: the name. Modify: set only to rename. One path component.
    pub name: Option<String>,
    /// Create only.
    pub entry_kind: WriteEntryKind,
    /// Modify, delete: the 40-byte version identifier (`content_version`) the user saw. Empty:
    /// none known; an edit is then kept beside the file and a delete leaves it.
    pub base_version: Vec<u8>,
    /// Create a file, modify with new contents.
    pub content: Option<WriteContent>,
    /// Absent: the engine's clock.
    pub mtime_unix_nanos: Option<i64>,
    /// Whether the item is executable; absent leaves it as it is (iOS cannot express it).
    pub exec: Option<bool>,
    /// Delete of a folder with children.
    pub recursive: bool,
    /// The item's generation the change was made against (the one inside `base_version`, when
    /// set, must agree).
    pub base_generation: Option<u64>,
    /// The generation of the folder a rename or move LEAVES.
    pub parent_generation: Option<u64>,
    pub observed_revision: Option<u64>,
    /// A restore: take the new contents from a retained version instead of `content` (which must
    /// then be unset). Modify of a live item restores an earlier version of it; Create brings a
    /// deleted file or folder back under `name` and `parent_item_id`. `None`: an ordinary change.
    #[uniffi(default = None)]
    pub restore_from: Option<RestoreSource>,
}

/// A retained version to restore, as `list_versions` or `list_deleted` returned it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RestoreSource {
    /// The group-relative path the version is stored at.
    pub path: String,
    /// The 32-byte version hash.
    pub version_hash: Vec<u8>,
}

/// What the engine decided about an applied change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WriteOutcome {
    Applied,
    /// A concurrent edit from another device: both versions are kept, the item in the result is
    /// the one the engine reports.
    Concurrent,
    /// The change lost to a delete elsewhere; the file survived.
    FileSurvived,
}

/// The item a change left.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WrittenItem {
    pub item_id: Vec<u8>,
    /// Empty: the root.
    pub parent_item_id: Vec<u8>,
    pub name: String,
    pub entry_kind: WriteEntryKind,
    /// The 40-byte version identifier to use as the next `base_version`, and to ask
    /// `version_delivery` about.
    pub content_version: Vec<u8>,
    pub metadata_version: Vec<u8>,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub exec: bool,
    /// `content_version` is also the engine's current version of the item.
    pub current: bool,
    pub namespace_revision: u64,
    pub parent_generation: u64,
}

/// Why the engine refused a change (or a stage). Nothing was authored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WriteRefusal {
    /// The item, its folder or the root is unknown here.
    NotFound,
    /// No temp root, or the root has an error of its own; try again later.
    NotReady,
    InvalidName,
    NameCollision,
    DirectoryNotEmpty,
    IngestRejected,
    /// The staged file is missing or changed while it was read: stage it again.
    IngestUnstable,
    /// More blocks than a version may have.
    TooLarge,
    /// The phone is out of space (nothing, or no more, was read).
    LowDisk,
    /// This device is not a writer of the folder's group.
    NotAuthorized,
    Cancelled,
    /// Transient: send the same operation again.
    Retry,
    InvalidBase,
    /// The item was retired or is unknown; `suggested_name` names the bytes' copy.
    KeepLocal,
    /// The operation identity was used for another change.
    OperationMismatch,
    /// The operation is older than ones the engine already processed for the session.
    StaleOperation,
    /// A generation moved: refresh the view and retry.
    StaleView,
    /// A restore's version is not retained any more, or no reachable device holds its bytes.
    /// Nothing was authored; try again when a device that has the file is online.
    VersionUnavailable,
    /// The folder is publish-only on this device: a modify or delete is refused, nothing changed.
    PublishOnly,
}

impl From<wire::ProviderApplyFailure> for WriteRefusal {
    fn from(failure: wire::ProviderApplyFailure) -> Self {
        use wire::ProviderApplyFailure as F;
        match failure {
            F::NotFound | F::None => Self::NotFound,
            F::NotReady => Self::NotReady,
            F::InvalidName => Self::InvalidName,
            F::NameCollision => Self::NameCollision,
            F::DirectoryNotEmpty => Self::DirectoryNotEmpty,
            F::IngestRejected => Self::IngestRejected,
            F::IngestUnstable => Self::IngestUnstable,
            F::TooLarge => Self::TooLarge,
            F::LowDisk => Self::LowDisk,
            F::NotAuthorized => Self::NotAuthorized,
            F::Cancelled => Self::Cancelled,
            F::Retry => Self::Retry,
            F::InvalidBase => Self::InvalidBase,
            F::KeepLocal => Self::KeepLocal,
            F::OperationMismatch => Self::OperationMismatch,
            F::StaleOperation => Self::StaleOperation,
            F::StaleView => Self::StaleView,
            F::VersionUnavailable => Self::VersionUnavailable,
            F::PublishOnly => Self::PublishOnly,
        }
    }
}

/// The answer of `apply_change`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum WriteResult {
    Applied {
        outcome: WriteOutcome,
        /// The item after the change (absent for a delete).
        item: Option<WrittenItem>,
        /// The stored outcome of an operation decided before; nothing was authored now.
        replayed: bool,
    },
    Refused {
        code: WriteRefusal,
        /// Human-readable and may quote a name; not for matching.
        message: String,
        /// `KeepLocal`: the name to create the kept bytes under.
        suggested_name: Option<String>,
    },
}

fn wire_entry(kind: WriteEntryKind) -> wire::EntryKind {
    match kind {
        WriteEntryKind::File => wire::EntryKind::File,
        WriteEntryKind::Directory => wire::EntryKind::Directory,
    }
}

impl From<WriteChange> for wire::ProviderApplyChangeRequest {
    fn from(change: WriteChange) -> Self {
        Self {
            request_id: change.request_id,
            session_id: change.session_id,
            operation_seq: change.operation_seq,
            root_id: change.root_id,
            kind: match change.kind {
                WriteKind::Create => wire::ProviderChangeKind::Create,
                WriteKind::Modify => wire::ProviderChangeKind::Modify,
                WriteKind::Delete => wire::ProviderChangeKind::Delete,
            } as i32,
            item_id: change.item_id,
            parent_item_id: change.parent_item_id,
            name: change.name,
            entry_kind: wire_entry(change.entry_kind) as i32,
            base_version_hash: change.base_version,
            content: change.content.map(|c| wire::ProviderContentSource {
                ingest_name: c.ingest_name,
                size: c.size,
                sha256: c.sha256,
            }),
            symlink_target: Vec::new(),
            metadata: Some(wire::ProviderItemMetadata {
                exec: change.exec,
                mtime_unix_nanos: change.mtime_unix_nanos,
            }),
            recursive: change.recursive,
            base_generation: change.base_generation,
            parent_generation: change.parent_generation,
            observed_revision: change.observed_revision,
            restore_from: change.restore_from.map(|source| wire::ProviderRestoreSource {
                path: source.path,
                version_hash: source.version_hash,
            }),
        }
    }
}

impl From<wire::ProviderAppliedItem> for WrittenItem {
    fn from(item: wire::ProviderAppliedItem) -> Self {
        Self {
            item_id: item.item_id,
            parent_item_id: item.parent_item_id,
            name: item.name,
            entry_kind: if item.entry_kind == wire::EntryKind::Directory as i32 {
                WriteEntryKind::Directory
            } else {
                WriteEntryKind::File
            },
            content_version: item.content_version,
            metadata_version: item.metadata_version,
            size: item.size,
            mtime_unix_nanos: item.mtime_unix_nanos,
            exec: item.exec,
            current: item.current,
            namespace_revision: item.namespace_revision,
            parent_generation: item.parent_generation,
        }
    }
}

impl From<wire::ProviderApplyChangeResponse> for WriteResult {
    fn from(response: wire::ProviderApplyChangeResponse) -> Self {
        if response.ok {
            let outcome = match wire::ProviderApplyOutcome::try_from(response.outcome) {
                Ok(wire::ProviderApplyOutcome::Concurrent) => WriteOutcome::Concurrent,
                Ok(wire::ProviderApplyOutcome::FileSurvived) => WriteOutcome::FileSurvived,
                _ => WriteOutcome::Applied,
            };
            Self::Applied {
                outcome,
                item: response.item.map(Into::into),
                replayed: response.replayed,
            }
        } else {
            Self::Refused {
                code: wire::ProviderApplyFailure::try_from(response.failure)
                    .map_or(WriteRefusal::Retry, Into::into),
                message: response.error,
                suggested_name: (!response.suggested_name.is_empty())
                    .then_some(response.suggested_name),
            }
        }
    }
}

// ---- delivery ------------------------------------------------------------------------------

/// One item to ask about: what the write returned.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeliveryItem {
    pub root_id: Vec<u8>,
    pub item_id: Vec<u8>,
    /// The item's `content_version` from the write (40 bytes).
    pub content_version: Vec<u8>,
}

/// A device that confirmed holding the version.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeliveredDevice {
    pub device_id: String,
    /// Absent when the account's device list could not be read (signed out or offline).
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DeliveryState {
    /// A device that keeps a full replica confirmed, just now, that it durably holds exactly
    /// this version. This is "saved".
    Delivered { devices: Vec<DeliveredDevice> },
    /// No such device confirmed: none is online, none answered in time or none holds the
    /// version. As far as this phone can tell the version is only here.
    NotDelivered,
    /// The item's current version is no longer this one (edited, replaced, deleted): there is
    /// nothing to attest. Ask about the newer version instead.
    Superseded,
    /// A folder: it has no content to deliver.
    NotApplicable,
    /// The root or the item is not known to the engine.
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemDelivery {
    pub item: DeliveryItem,
    pub state: DeliveryState,
}

/// The answer of `version_delivery`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeliveryReport {
    /// In the order asked.
    pub items: Vec<ItemDelivery>,
    /// How many of the asked items are `NotDelivered`: the data only on this phone, for the
    /// items the app tracks.
    pub undelivered_count: u32,
    /// When the check ran (Unix seconds).
    pub checked_at_unix: i64,
}

impl From<DeliveryItem> for host::DeliveryItem {
    fn from(item: DeliveryItem) -> Self {
        Self { root_id: item.root_id, item_id: item.item_id, content_version: item.content_version }
    }
}

impl From<host::DeliveryItem> for DeliveryItem {
    fn from(item: host::DeliveryItem) -> Self {
        Self { root_id: item.root_id, item_id: item.item_id, content_version: item.content_version }
    }
}

fn delivery_report(outcome: host::DeliveryOutcome) -> DeliveryReport {
    let host::DeliveryOutcome { report, device_names } = outcome;
    DeliveryReport {
        items: report
            .items
            .into_iter()
            .map(|entry| ItemDelivery {
                item: entry.item.into(),
                state: match entry.state {
                    host::DeliveryState::Delivered { device_ids } => DeliveryState::Delivered {
                        devices: device_ids
                            .into_iter()
                            .map(|device_id| DeliveredDevice {
                                name: device_names.get(&device_id).cloned(),
                                device_id,
                            })
                            .collect(),
                    },
                    host::DeliveryState::NotDelivered => DeliveryState::NotDelivered,
                    host::DeliveryState::Superseded => DeliveryState::Superseded,
                    host::DeliveryState::NotApplicable => DeliveryState::NotApplicable,
                    host::DeliveryState::NotFound => DeliveryState::NotFound,
                },
            })
            .collect(),
        undelivered_count: report.undelivered_count,
        checked_at_unix: report.checked_at_unix,
    }
}

// ---- version history and deleted items ----------------------------------------------------

/// What a version or a deleted entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HistoryEntryKind {
    File,
    Directory,
    Symlink,
}

impl From<host::HistoryEntryKind> for HistoryEntryKind {
    fn from(kind: host::HistoryEntryKind) -> Self {
        match kind {
            host::HistoryEntryKind::File => Self::File,
            host::HistoryEntryKind::Directory => Self::Directory,
            host::HistoryEntryKind::Symlink => Self::Symlink,
        }
    }
}

/// Where a retained version stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HistoryVersionState {
    /// The live version.
    Current,
    /// An earlier version a later edit replaced.
    Superseded,
    /// The last content before the item was deleted.
    Trashed,
}

/// One retained version of an item.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemVersion {
    /// Orders the versions of one item; the newest has the highest.
    pub version_seq: i64,
    /// Name it in `RestoreSource.version_hash`.
    pub version_hash: Vec<u8>,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub state: HistoryVersionState,
    /// The device that authored it; `None` when unknown.
    pub origin_device_id: Option<String>,
    /// Its name, when the account's device list could be read.
    pub origin_device_name: Option<String>,
    pub kind: HistoryEntryKind,
    /// A restore is offered: a file version other than the live one.
    pub restorable: bool,
}

/// The retained versions of one item, newest first.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemHistory {
    /// The path to put in `RestoreSource.path`.
    pub path: String,
    /// The item is live; a deleted item still lists its history.
    pub live: bool,
    pub versions: Vec<ItemVersion>,
}

/// Where a deleted item would come back to.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DeletedParent {
    /// The folder's root: `parent_item_id` empty.
    Root,
    /// This live folder: its item id is the `parent_item_id` of the create.
    Item { item_id: Vec<u8> },
    /// The folder it was in is deleted too: restore that folder first.
    Gone,
}

/// A deleted file or folder that can still be brought back.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeletedItem {
    /// The path to put in `RestoreSource.path`.
    pub path: String,
    /// The `name` of the create.
    pub name: String,
    pub parent: DeletedParent,
    pub version_seq: i64,
    /// Name it in `RestoreSource.version_hash`.
    pub version_hash: Vec<u8>,
    /// Its size before the deletion (0 for a folder).
    pub size: u64,
    pub deleted_at_unix_nanos: i64,
    pub origin_device_id: Option<String>,
    pub origin_device_name: Option<String>,
    pub kind: HistoryEntryKind,
    /// A restore is offered (a file or a folder).
    pub restorable: bool,
    /// Entries with the same value were removed by one recursive delete or folder rename: bring
    /// the folder back first, then what was in it.
    pub operation: Option<String>,
}

/// The deleted items of one provider folder, newest deletion first.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeletedItems {
    pub items: Vec<DeletedItem>,
    /// There are more than the engine lists; the oldest are missing.
    pub truncated: bool,
}

fn device_name(
    names: &std::collections::HashMap<String, String>,
    id: &Option<String>,
) -> Option<String> {
    id.as_ref().and_then(|id| names.get(id).cloned())
}

fn item_history(outcome: host::HistoryOutcome<host::ItemHistory>) -> ItemHistory {
    let host::HistoryOutcome { listing, device_names } = outcome;
    ItemHistory {
        path: listing.path,
        live: listing.live,
        versions: listing
            .versions
            .into_iter()
            .map(|v| ItemVersion {
                version_seq: v.version_seq,
                version_hash: v.version_hash,
                size: v.size,
                mtime_unix_nanos: v.mtime_unix_nanos,
                state: match v.state {
                    host::HistoryVersionState::Current => HistoryVersionState::Current,
                    host::HistoryVersionState::Superseded => HistoryVersionState::Superseded,
                    host::HistoryVersionState::Trashed => HistoryVersionState::Trashed,
                },
                origin_device_name: device_name(&device_names, &v.origin_device_id),
                origin_device_id: v.origin_device_id,
                kind: v.kind.into(),
                restorable: v.restorable,
            })
            .collect(),
    }
}

fn deleted_items(outcome: host::HistoryOutcome<host::DeletedItems>) -> DeletedItems {
    let host::HistoryOutcome { listing, device_names } = outcome;
    DeletedItems {
        truncated: listing.truncated,
        items: listing
            .items
            .into_iter()
            .map(|d| DeletedItem {
                path: d.path,
                name: d.name,
                parent: match d.parent {
                    host::DeletedParent::Root => DeletedParent::Root,
                    host::DeletedParent::Item(item_id) => DeletedParent::Item { item_id },
                    host::DeletedParent::Gone => DeletedParent::Gone,
                },
                version_seq: d.version_seq,
                version_hash: d.version_hash,
                size: d.size,
                deleted_at_unix_nanos: d.deleted_at_unix_nanos,
                origin_device_name: device_name(&device_names, &d.origin_device_id),
                origin_device_id: d.origin_device_id,
                kind: d.kind.into(),
                restorable: d.restorable,
                operation: d.operation,
            })
            .collect(),
    }
}

#[cfg(test)]
pub(crate) fn item_history_for_tests(
    outcome: host::HistoryOutcome<host::ItemHistory>,
) -> ItemHistory {
    item_history(outcome)
}

#[cfg(test)]
pub(crate) fn deleted_items_for_tests(
    outcome: host::HistoryOutcome<host::DeletedItems>,
) -> DeletedItems {
    deleted_items(outcome)
}

// ---- the calls -----------------------------------------------------------------------------

/// Every call takes a cancel handle (one per call) and an optional deadline, as elsewhere. The
/// writes change state and keep running when cancelled (see the module docs).
#[uniffi::export]
impl MobileHost {
    /// Puts a file into the engine's ingest directory, for the `content` of a following
    /// `apply_change`. A refusal is a [`StageResult::Refused`], not an error.
    ///
    /// # Errors
    /// A [`CallFailure`] when the call itself failed (not running, cancelled, out of time).
    pub fn stage_upload(
        &self,
        source: StageSource,
        mode: StageMode,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<StageResult, CallFailure> {
        let source = match source {
            StageSource::Path { path } => host::StageSource::Path(path.into()),
            StageSource::Descriptor { fd } => host::StageSource::Descriptor(fd),
        };
        let command = host::Command::StageUpload { source, mode: mode.into() };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Staged(Ok(upload)) => Ok(StageResult::Staged {
                upload: StagedUpload {
                    ingest_name: upload.ingest_name,
                    size: upload.size,
                    sha256: upload.sha256.to_vec(),
                    how: match upload.how {
                        host::StagedHow::Moved => StagedHow::Moved,
                        host::StagedHow::Cloned => StagedHow::Cloned,
                        host::StagedHow::Copied => StagedHow::Copied,
                    },
                },
            }),
            host::CommandOutput::Staged(Err(refused)) => {
                Ok(StageResult::Refused { code: refused.code.into(), message: refused.message })
            }
            other => Err(unexpected("stage_upload", &other)),
        }
    }

    /// Removes a staged file no change will use. Idempotent.
    ///
    /// # Errors
    /// `Failed` for a name `stage_upload` did not issue; the other [`CallFailure`] cases.
    pub fn discard_staged_upload(
        &self,
        ingest_name: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        match self.run(host::Command::DiscardStagedUpload { ingest_name }, cancel, deadline_ms)? {
            host::CommandOutput::Done => Ok(()),
            other => Err(unexpected("discard_staged_upload", &other)),
        }
    }

    /// Applies one change to a provider folder. A refusal is a [`WriteResult::Refused`], not an
    /// error. Asking again with the same operation identity returns the stored outcome.
    ///
    /// # Errors
    /// A [`CallFailure`] when the call itself failed; for `Cancelled` and `DeadlineExceeded`
    /// with `still_running`, ask again with the same identity.
    pub fn apply_change(
        &self,
        change: WriteChange,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<WriteResult, CallFailure> {
        let command = host::Command::ApplyChange(Box::new(host::ApplyChange(change.into())));
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Applied(response) => Ok(response.0.into()),
            other => Err(unexpected("apply_change", &other)),
        }
    }

    /// The retained versions of one item of a provider folder, newest first: the info sheet's
    /// history. A deleted item still lists its history. Restore one with `apply_change`
    /// (Modify of the live item, `restore_from` naming the version). Read-only.
    ///
    /// # Errors
    /// `Failed` for an unknown root or item; the other [`CallFailure`] cases.
    pub fn list_versions(
        &self,
        root_id: Vec<u8>,
        item_id: Vec<u8>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<ItemHistory, CallFailure> {
        match self.run(host::Command::ListItemVersions { root_id, item_id }, cancel, deadline_ms)? {
            host::CommandOutput::ItemVersions(outcome) => Ok(item_history(*outcome)),
            other => Err(unexpected("list_versions", &other)),
        }
    }

    /// The deleted files and folders of a provider folder that can still be brought back, newest
    /// deletion first: the undo after the session. Bring one back with `apply_change` (Create
    /// under the entry's `name` and parent, `restore_from` naming the entry's version). Read-only.
    ///
    /// # Errors
    /// `Failed` for an unknown root; the other [`CallFailure`] cases.
    pub fn list_deleted(
        &self,
        root_id: Vec<u8>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<DeletedItems, CallFailure> {
        match self.run(host::Command::ListDeletedItems { root_id }, cancel, deadline_ms)? {
            host::CommandOutput::DeletedItems(outcome) => Ok(deleted_items(*outcome)),
            other => Err(unexpected("list_deleted", &other)),
        }
    }

    /// Brings back everything the folder delete or rename that removed the deleted entry at
    /// `path` (a listed entry's `path`) removed. Each entry that fails is named; the rest are
    /// still restored. One deleted file or folder is brought back with `apply_change`.
    ///
    /// # Errors
    /// `Failed` for an unknown root, a path that is not deleted, or one deleted on its own rather
    /// than by a folder operation; the other [`CallFailure`] cases.
    pub fn restore_deleted_operation(
        &self,
        root_id: Vec<u8>,
        path: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<FolderRestore, CallFailure> {
        let command = host::Command::RestoreDeletedOperation { root_id, path };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::FolderRestored(outcome) => Ok(outcome.into()),
            other => Err(unexpected("restore_deleted_operation", &other)),
        }
    }

    /// Marks a provider folder publish-only on this device, or clears it. A publish-only folder
    /// takes new files but refuses (`PublishOnly`) every modify and delete this device would
    /// author, so a bug of the app cannot remove what it backed up. Changes from other devices
    /// still arrive. Persisted.
    ///
    /// # Errors
    /// `Failed` for an unknown root; the other [`CallFailure`] cases.
    pub fn set_publish_only(
        &self,
        root_id: Vec<u8>,
        publish_only: bool,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        match self.run(
            host::Command::SetPublishOnly { root_id, publish_only },
            cancel,
            deadline_ms,
        )? {
            host::CommandOutput::Done => Ok(()),
            other => Err(unexpected("set_publish_only", &other)),
        }
    }

    /// For each item, whether a device that keeps a full replica holds exactly that version now.
    /// At most 256 items per call. Read-only; asked afresh every time, so a version that a
    /// device lost reads `NotDelivered` again.
    ///
    /// # Errors
    /// `Failed` for more than 256 items; the other [`CallFailure`] cases.
    pub fn version_delivery(
        &self,
        items: Vec<DeliveryItem>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<DeliveryReport, CallFailure> {
        let command =
            host::Command::VersionDelivery { items: items.into_iter().map(Into::into).collect() };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Delivery(outcome) => Ok(delivery_report(*outcome)),
            other => Err(unexpected("version_delivery", &other)),
        }
    }
}

/// What a folder restore from the deleted items brought back.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FolderRestore {
    /// Relative to the folder root, in path order.
    pub restored_paths: Vec<String>,
    pub failed: Vec<FolderRestoreFailure>,
    /// Not every part of the operation has reached this device, so what it removed elsewhere
    /// could not be restored here.
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FolderRestoreFailure {
    pub path: String,
    pub error: String,
}

impl From<host::dto::FolderRestoreOutcome> for FolderRestore {
    fn from(outcome: host::dto::FolderRestoreOutcome) -> Self {
        Self {
            restored_paths: outcome.restored_paths,
            failed: outcome
                .failed
                .into_iter()
                .map(|f| FolderRestoreFailure { path: f.path, error: f.error })
                .collect(),
            partial: outcome.partial,
        }
    }
}
