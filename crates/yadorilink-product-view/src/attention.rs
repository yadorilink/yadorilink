//! The semantic meaning of everything that needs the user, shared by every product shell.
//!
//! The daemon reports problems as coarse `code[:subject]` strings (the `overall_status` rollup
//! and the held-file reasons). This module is the one place those strings are read: each becomes
//! an [`AttentionItem`] with an affected [`AttentionScope`], an [`AttentionKind`] and the
//! [`ProductAction`]s a shell may offer. It carries no wording: each shell maps an item to its own
//! localized text and decides how to perform an action.
//!
//! The sets are closed on purpose. A code this build does not know becomes
//! [`AttentionItem::Unrecognized`] (a newer daemon), never a guess.

/// What the user can be offered to do about an item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductAction {
    /// Try the failed work again.
    Retry,
    ReviewConflict,
    /// Look at the requests to join a folder group that wait for this account to decide.
    ReviewApproval,
    FreeUpSpace,
    /// Show the file or folder the problem is about.
    RevealPath,
    /// Open the place where the setting or permission lives.
    OpenSettings,
    DownloadUpdate,
    /// Confirm that the disk now at the folder's place is the folder's disk.
    ConfirmDisk,
    /// Start a paused folder again. Offered for the paused state, never for a problem report.
    Resume,
    /// Show what is known about the problem.
    ViewDetails,
    /// Retire this computer's device identity and register it again as a new device, keeping its
    /// files. Offered when the replica database was restored or copied.
    StartOverAsNewDevice,
}

/// Whether time alone can fix an item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttentionKind {
    /// Something outside the user's hands has to come back (a device, a connection).
    Waiting,
    /// The work is tried again; trying again may succeed.
    Retryable,
    /// Nothing changes until the user acts.
    Permanent,
}

/// How much an item matters, for ordering and emphasis. `Critical` is exactly what the daemon's
/// rollup files under its degraded state, `Info` is a wait for something outside the user's
/// hands, everything else is `Warning`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttentionSeverity {
    Info,
    Warning,
    Critical,
}

/// What a problem is about, as the id the daemon reported it with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttentionScope {
    /// A linked folder group.
    Folder(String),
    ProviderFolder(String),
    Device(String),
    /// A disk volume, by path.
    Volume(String),
    /// Nothing specific (an update, a recent error).
    General,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttentionItem {
    /// The folder stopped on a problem and will try again.
    FolderStopped,
    /// The folder group is linked at more than one place, so nothing syncs.
    LinkedTwice,
    OwnershipLost,
    /// The folder is no longer on the disk it was set up on.
    VolumeChanged,
    /// The folder's disk cannot be recognised after it was mounted again (a
    /// filesystem without a stable identity): only the user can confirm it.
    VolumeUnconfirmed,
    /// No second copy of the data exists anywhere.
    NoSafeCopy,
    SafeCopyUnconfirmed,
    /// Files that are not here cannot be fetched now.
    ContentUnavailable,
    ContentAvailabilityUnknown,
    ConflictNeedsReview,
    /// Other accounts' devices asked to join a folder group this account owns and wait for a
    /// decision. Nothing happens until the owner admits or turns them down.
    ApprovalPending,
    FileHeld,
    /// A file name that cannot be used on this device, or collides with another one.
    UnsupportedFilename,
    /// The file already here cannot be read, so the incoming update was not applied.
    FileNotReadable,
    StrandedDirectory,
    /// Files in the folder cannot be read (permission refused, no longer a regular file): they
    /// are skipped, never read as deleted, and picked up again by the next scan once readable.
    UnreadableFiles,
    ProviderNotReady,
    ProviderFilesFailing,
    /// Edits kept beside a file instead of replacing it.
    EditsKeptBeside,
    ProviderOrphan,
    DiskFull,
    DiskLow,
    PeerUnavailable,
    RetryableFailure,
    UpdateFailed,
    /// A device runs another version (scope: the device), or this device is older than the
    /// release line's minimum supported version (scope: general). Either way the fix is to
    /// update, not to wait: the device is online, it just cannot sync until versions match.
    UpdateRequired,
    /// The Windows host read its sync-root record from an older generation because the newest
    /// one is torn; folders added since may be missing from what it serves until it is rewritten.
    ProviderRegistryRestored,
    /// The replica database was restored from a backup or copied, so this device cannot sync
    /// under its identity. The engine never reuses the old author state: the device starts over as
    /// a new device (`ProductAction::StartOverAsNewDevice`), keeping its files.
    DatabaseRestored,
    /// The folder is not joined to its folder group (start over could not join it again, or its
    /// authorization is gone): it takes no part in sync, its files are kept, and only joining the
    /// group again (a new invite) or unlinking the folder settles it.
    NotJoined,
    /// This device cannot open the identity it signs its changes with (for example the record
    /// that detects a restored database cannot be written), so nothing it edits syncs.
    AuthorUnavailable,
    /// A start over replaced a device that may have held the only complete copy of some folder
    /// group, and the service has not confirmed the new device yet. Retried automatically; status
    /// is never healthy meanwhile. Keyed-only, like the items above.
    ReplacementUnconfirmed,
    /// The confirmation above was refused for lack of a valid sign-in: signing in again lets it go
    /// through.
    ReplacementSignInRequired,
    /// Why the confirmation above is still waiting (the subject carries the reason). Retried
    /// automatically; shown beside [`Self::ReplacementUnconfirmed`] so a wait is not mistaken for
    /// a stall.
    ReplacementWaiting,
    /// A code this build does not know.
    Unrecognized,
}

impl AttentionScope {
    /// The name a shell finds the subject under in its sentence: `folder`, `provider_folder`,
    /// `device`, `volume`, or `category` for what has no place of its own.
    #[must_use]
    pub fn arg_name(&self) -> &'static str {
        match self {
            Self::Folder(_) => "folder",
            Self::ProviderFolder(_) => "provider_folder",
            Self::Device(_) => "device",
            Self::Volume(_) => "volume",
            Self::General => "category",
        }
    }
}

impl AttentionItem {
    /// Stable snake_case id for platform resource lookup.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::FolderStopped => "folder_stopped",
            Self::LinkedTwice => "linked_twice",
            Self::OwnershipLost => "ownership_lost",
            Self::VolumeChanged => "volume_changed",
            Self::VolumeUnconfirmed => "volume_unconfirmed",
            Self::NoSafeCopy => "no_safe_copy",
            Self::SafeCopyUnconfirmed => "safe_copy_unconfirmed",
            Self::ContentUnavailable => "content_unavailable",
            Self::ContentAvailabilityUnknown => "content_availability_unknown",
            Self::ConflictNeedsReview => "conflict_needs_review",
            Self::ApprovalPending => "approval_pending",
            Self::FileHeld => "file_held",
            Self::UnsupportedFilename => "unsupported_filename",
            Self::FileNotReadable => "file_not_readable",
            Self::StrandedDirectory => "stranded_directory",
            Self::ProviderNotReady => "provider_not_ready",
            Self::ProviderFilesFailing => "provider_files_failing",
            Self::EditsKeptBeside => "edits_kept_beside",
            Self::ProviderOrphan => "provider_orphan",
            Self::DiskFull => "disk_full",
            Self::DiskLow => "disk_low",
            Self::PeerUnavailable => "peer_unavailable",
            Self::RetryableFailure => "retryable_failure",
            Self::UpdateFailed => "update_failed",
            Self::UpdateRequired => "update_required",
            Self::ProviderRegistryRestored => "provider_registry_restored",
            Self::DatabaseRestored => "database_restored",
            Self::AuthorUnavailable => "author_unavailable",
            Self::ReplacementUnconfirmed => "replacement_unconfirmed",
            Self::ReplacementSignInRequired => "replacement_unconfirmed_sign_in_required",
            Self::ReplacementWaiting => "replacement_unconfirmed_waiting",
            Self::NotJoined => "not_joined",
            Self::UnreadableFiles => "unreadable_files",
            Self::Unrecognized => "unrecognized",
        }
    }

    #[must_use]
    pub fn kind(self) -> AttentionKind {
        match self {
            Self::SafeCopyUnconfirmed
            | Self::ContentUnavailable
            | Self::ContentAvailabilityUnknown
            | Self::ReplacementUnconfirmed
            | Self::ReplacementWaiting
            | Self::PeerUnavailable => AttentionKind::Waiting,
            Self::FolderStopped
            | Self::ProviderFilesFailing
            | Self::RetryableFailure
            | Self::UpdateFailed => AttentionKind::Retryable,
            Self::LinkedTwice
            | Self::OwnershipLost
            | Self::NotJoined
            | Self::VolumeChanged
            | Self::VolumeUnconfirmed
            | Self::NoSafeCopy
            | Self::ConflictNeedsReview
            | Self::ApprovalPending
            | Self::FileHeld
            | Self::UnsupportedFilename
            | Self::FileNotReadable
            | Self::StrandedDirectory
            | Self::UnreadableFiles
            | Self::ProviderNotReady
            | Self::ProviderRegistryRestored
            | Self::DatabaseRestored
            | Self::AuthorUnavailable
            | Self::ReplacementSignInRequired
            | Self::EditsKeptBeside
            | Self::ProviderOrphan
            | Self::DiskFull
            | Self::DiskLow
            | Self::UpdateRequired
            | Self::Unrecognized => AttentionKind::Permanent,
        }
    }

    #[must_use]
    pub fn severity(self) -> AttentionSeverity {
        match self {
            Self::FolderStopped
            | Self::LinkedTwice
            | Self::OwnershipLost
            | Self::NotJoined
            | Self::NoSafeCopy
            | Self::DatabaseRestored
            | Self::AuthorUnavailable
            | Self::DiskFull => AttentionSeverity::Critical,
            _ if self.kind() == AttentionKind::Waiting => AttentionSeverity::Info,
            _ => AttentionSeverity::Warning,
        }
    }

    #[must_use]
    pub fn primary_action(self) -> ProductAction {
        match self {
            Self::FolderStopped
            | Self::ProviderFilesFailing
            | Self::RetryableFailure
            | Self::UpdateFailed => ProductAction::Retry,
            Self::ConflictNeedsReview => ProductAction::ReviewConflict,
            Self::ApprovalPending => ProductAction::ReviewApproval,
            Self::DiskFull | Self::DiskLow => ProductAction::FreeUpSpace,
            Self::UnsupportedFilename | Self::FileNotReadable => ProductAction::RevealPath,
            Self::ProviderNotReady | Self::ProviderOrphan => ProductAction::OpenSettings,
            Self::UpdateRequired => ProductAction::DownloadUpdate,
            Self::VolumeUnconfirmed => ProductAction::ConfirmDisk,
            Self::LinkedTwice
            | Self::OwnershipLost
            | Self::NotJoined
            | Self::VolumeChanged
            | Self::NoSafeCopy
            | Self::SafeCopyUnconfirmed
            | Self::ContentUnavailable
            | Self::ContentAvailabilityUnknown
            | Self::FileHeld
            | Self::StrandedDirectory
            | Self::UnreadableFiles
            | Self::ProviderRegistryRestored
            | Self::AuthorUnavailable
            | Self::ReplacementUnconfirmed
            | Self::ReplacementWaiting
            | Self::ReplacementSignInRequired
            | Self::EditsKeptBeside
            | Self::PeerUnavailable
            | Self::Unrecognized => ProductAction::ViewDetails,
            Self::DatabaseRestored => ProductAction::StartOverAsNewDevice,
        }
    }

    /// The action to offer given what this device can actually do now: `FreeUpSpace` only where
    /// a reclaim can succeed (`reclaim_available`), otherwise the item's details. Every other item
    /// is as [`Self::primary_action`].
    #[must_use]
    pub fn offered_action(self, reclaim_available: bool) -> ProductAction {
        match self.primary_action() {
            ProductAction::FreeUpSpace if !reclaim_available => ProductAction::ViewDetails,
            action => action,
        }
    }

    /// A second action, only where the first does not always settle it.
    #[must_use]
    pub fn secondary_action(self) -> Option<ProductAction> {
        match self.kind() {
            AttentionKind::Retryable => Some(ProductAction::ViewDetails),
            _ if matches!(self, Self::UnsupportedFilename | Self::VolumeUnconfirmed) => {
                Some(ProductAction::ViewDetails)
            }
            _ => None,
        }
    }
}

/// One thing that needs the user: what it is and what it is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attention {
    pub item: AttentionItem,
    pub scope: AttentionScope,
}

impl Attention {
    /// Reads one `code[:subject]` string from the daemon's overall-status rollup. Only the first
    /// colon splits, so a subject may contain one.
    #[must_use]
    pub fn from_reason(raw: &str) -> Self {
        let (code, subject) = raw.split_once(':').unwrap_or((raw, ""));
        let subject = subject.to_owned();
        let folder = |item| (item, AttentionScope::Folder(subject.clone()));
        let provider = |item| (item, AttentionScope::ProviderFolder(subject.clone()));
        let (item, scope) = match code {
            "degraded" => folder(AttentionItem::FolderStopped),
            "ambiguous" => folder(AttentionItem::LinkedTwice),
            "ownership_lost" => folder(AttentionItem::OwnershipLost),
            "not_joined" => folder(AttentionItem::NotJoined),
            "unreadable_files" => folder(AttentionItem::UnreadableFiles),
            "volume_changed" => folder(AttentionItem::VolumeChanged),
            "volume_unconfirmed" => folder(AttentionItem::VolumeUnconfirmed),
            "durability_at_risk" => folder(AttentionItem::NoSafeCopy),
            "durability_unknown" => folder(AttentionItem::SafeCopyUnconfirmed),
            "fetch_unavailable" => folder(AttentionItem::ContentUnavailable),
            "fetch_availability_unknown" => folder(AttentionItem::ContentAvailabilityUnknown),
            "conflict" | "conflict_pending" => folder(AttentionItem::ConflictNeedsReview),
            "approval_pending" => folder(AttentionItem::ApprovalPending),
            "held" => folder(AttentionItem::FileHeld),
            "stranded_directory" => folder(AttentionItem::StrandedDirectory),
            "provider_not_ready" => provider(AttentionItem::ProviderNotReady),
            "provider_stuck" => provider(AttentionItem::ProviderFilesFailing),
            "kept_edits" => provider(AttentionItem::EditsKeptBeside),
            "provider_orphan_domain" => provider(AttentionItem::ProviderOrphan),
            "low_disk_critical" => (AttentionItem::DiskFull, AttentionScope::Volume(subject)),
            "low_disk" => (AttentionItem::DiskLow, AttentionScope::Volume(subject)),
            "peer_disconnected" => {
                (AttentionItem::PeerUnavailable, AttentionScope::Device(subject))
            }
            // A peer of another version: online, but sync with it is paused until both match.
            "peer_update_required" => {
                (AttentionItem::UpdateRequired, AttentionScope::Device(subject))
            }
            // This device is older than the minimum supported version.
            "update_required" => (AttentionItem::UpdateRequired, AttentionScope::General),
            "recent_error" => (AttentionItem::RetryableFailure, AttentionScope::General),
            "update_failed" => (AttentionItem::UpdateFailed, AttentionScope::General),
            "provider_registry_restored" => {
                (AttentionItem::ProviderRegistryRestored, AttentionScope::General)
            }
            "database_restored" => (AttentionItem::DatabaseRestored, AttentionScope::General),
            "author_unavailable" => (AttentionItem::AuthorUnavailable, AttentionScope::General),
            "replacement_unconfirmed" => {
                (AttentionItem::ReplacementUnconfirmed, AttentionScope::General)
            }
            "replacement_unconfirmed_waiting" => {
                (AttentionItem::ReplacementWaiting, AttentionScope::General)
            }
            "replacement_unconfirmed_sign_in_required" => {
                (AttentionItem::ReplacementSignInRequired, AttentionScope::General)
            }
            _ => (AttentionItem::Unrecognized, AttentionScope::General),
        };
        Attention { item, scope }
    }

    /// Reads one held-file reason (`code` or `code: detail`). The scope is the file's folder, which
    /// the caller already knows, so none is attached.
    #[must_use]
    pub fn from_held_reason(raw: &str) -> Self {
        let code = raw.split_once(':').map_or(raw, |(code, _)| code);
        let item = match code {
            "case_collision"
            | "normalization_collision"
            | "case_and_normalization_collision"
            | "invalid_name" => AttentionItem::UnsupportedFilename,
            "metadata_unprovable" => AttentionItem::FileNotReadable,
            _ => AttentionItem::FileHeld,
        };
        Attention { item, scope: AttentionScope::General }
    }
}

#[cfg(test)]
mod tests;
