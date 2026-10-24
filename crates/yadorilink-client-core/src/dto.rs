//! The product types a desktop front end sees: records and enums with owned
//! fields only, no protocol types, no paths (paths are strings), times as
//! [`SystemTime`] and spans as [`Duration`].
//!
//! Every type here is what [`crate::ClientCore`] returns or takes. They carry
//! meaning (enums, numbers, ids), never user-facing sentences; the only text
//! fields are identifiers, raw values kept for tooltips, and diagnostic
//! `message`/`reason` strings. Enums that mirror a server or daemon string keep
//! an `Other`/`Unknown { raw }` case so a newer peer never breaks decoding.
//!
//! With the `ffi` feature every type also derives its foreign-language binding.

use std::time::{Duration, SystemTime};

use crate::error::DesktopError;

mod convert;

pub use convert::{
    account_deletion_impact, account_deletion_status, appcast_item_check, attention_reason,
    conflict_summary, daemon_identity, file_availability, file_retention, file_version,
    file_versions, folder_detail, folder_restore_outcome, folder_summary, gc_report,
    handoff_summary, incoming_transfer, invite_summary, member_summary, membership_outcome,
    outgoing_transfer, pending_approval_summary, pending_invite_summary, pin_outcome,
    preflight_result, received_transfer, retained_original, retained_release, rewind_preview,
    rewind_run, rewind_run_missing, rewind_start, safe_stop_outcome, sent_transfer, share_summary,
    space_management, space_reclaim_preview, start_over_progress, status_dimensions_json,
    status_snapshot, trashed_file, update_config, update_download_guidance, update_status,
    RUN_MISSING_MESSAGE,
};

// ---- construction -------------------------------------------------------

/// How [`crate::ClientCore::start_daemon`] brings the daemon up when nothing
/// answers the control socket.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DaemonLaunch {
    /// Spawn `yadorilink-daemon` from `path`, else from next to the current
    /// executable, else from PATH.
    SpawnBinary { path: Option<String> },
    /// Ask launchd to start the named LaunchAgent (`launchctl kickstart`).
    /// Never searches PATH.
    LaunchAgent { label: String },
    /// Ask the Windows Task Scheduler to run the named task (`schtasks /Run /TN`), the logon task
    /// that supervises the daemon. Never searches PATH and never falls back to spawning a binary:
    /// a missing or disabled task fails the launch.
    ScheduledTask { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct CoreConfig {
    pub daemon_launch: DaemonLaunch,
}

// ---- account ------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum SignInState {
    SignedOut,
    SignedIn,
    /// A credential store exists and cannot be used. Signing in again would
    /// leave it in place, so this is a state of its own.
    CredentialStoreUnusable {
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AccountStatus {
    pub sign_in: SignInState,
    pub client_id: Option<String>,
    pub this_device_id: Option<String>,
    pub device_registered: bool,
    pub default_device_name: String,
    /// `None` when the daemon is not reachable.
    pub has_linked_folders: Option<bool>,
    /// A start over as a new device was begun and is not finished: sign in if signed out, then
    /// call `start_over_as_new_device` again to register and join the folders again.
    pub start_over_pending: bool,
}

/// How far `start_over_as_new_device` got.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum StartOverProgress {
    /// The old identity is retired and this computer is signed out. Sign in, then call
    /// `start_over_as_new_device` again.
    SignInRequired {
        retired_device_id: String,
    },
    Finished {
        report: StartOverReport,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct StartOverReport {
    pub retired_device_id: String,
    pub new_device_id: String,
    /// Folders joined again, by local path.
    pub rejoined: Vec<String>,
    /// Folders that were not: a group this account does not own, a provider folder, or a failure.
    pub not_rejoined: Vec<NotRejoined>,
    /// Nothing is left to retry. When false, call `start_over_as_new_device` again.
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct NotRejoined {
    pub local_path: String,
    pub group_id: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum SignOutKind {
    Revoked { grants_revoked: u32 },
    AlreadyRevoked,
    ConfirmedRevokedAfterRejection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct SignOutOutcome {
    pub kind: SignOutKind,
    /// Set when the device key's copy in the OS credential store could not be removed. The
    /// sign-out itself is complete.
    pub key_cleanup_warning: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DeviceRegistration {
    pub device_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AccountDeletionState {
    Active,
    Requested,
    Grace,
    Other { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AccountDeletionStatus {
    pub state: AccountDeletionState,
    pub grace_expires_at: Option<SystemTime>,
    pub remaining: Option<Duration>,
}

/// A folder group that deleting the account affects.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AccountDeletionImpactGroup {
    pub group_id: String,
    pub name: String,
    /// Devices of other accounts in a group this account owns; `None` for a foreign group.
    pub guest_devices: Option<u32>,
}

/// What deleting the account does to other people's access and data custody. When either list
/// is non-empty, `request_account_deletion` is refused (`DurabilityBlocked`, `can_force`) until
/// the person acknowledges it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AccountDeletionImpact {
    /// Groups owned by someone else where this account's devices are the only full replicas.
    pub foreign_groups_at_risk: Vec<AccountDeletionImpactGroup>,
    /// Groups this account owns that other accounts' devices belong to.
    pub owned_groups_with_guests: Vec<AccountDeletionImpactGroup>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AccountDeletionRequest {
    /// Shown once; confirming the deletion requires it.
    pub confirmation_token: String,
}

// ---- sign-in ------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum LoginFlow {
    /// The browser comes back to a loopback listener on this machine.
    Loopback,
    /// The device-authorization grant: a code entered on another page.
    DeviceCode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct LoginOptions {
    pub flow: LoginFlow,
    /// Ends the flow with a network failure when it has not finished in
    /// time. `None` waits as long as each step allows.
    pub overall_timeout: Option<Duration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum BrowserPurpose {
    ApproveDevice,
    SignIn,
}

/// One step of a sign-in, in order.
///
/// Loopback: `Enrolling`, `OpenBrowser{ApproveDevice}`, `WaitingForApproval`,
/// `OpenBrowser{SignIn}`, `WaitingForAuthorization`, `SignedIn`.
/// Device code: `Enrolling`, `OpenBrowser{ApproveDevice}`,
/// `WaitingForApproval`, `ShowDeviceCode`, `SignedIn`. Any step may instead
/// end the stream with `Failed` or `Cancelled`.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum LoginEvent {
    Enrolling,
    OpenBrowser {
        url: String,
        purpose: BrowserPurpose,
    },
    WaitingForApproval {
        expires_in: Duration,
    },
    WaitingForAuthorization,
    /// `verification_uri` is the page to open: the link with the code filled in when the
    /// server offered one. `user_code` is shown as well, to check against the page.
    ShowDeviceCode {
        verification_uri: String,
        user_code: String,
    },
    SignedIn {
        account: AccountStatus,
    },
    Failed {
        error: DesktopError,
    },
    Cancelled,
}

impl LoginEvent {
    /// Whether this event ends the stream.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            LoginEvent::SignedIn { .. } | LoginEvent::Failed { .. } | LoginEvent::Cancelled
        )
    }
}

// ---- status -------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum OverallState {
    Healthy,
    Attention,
    Degraded,
    Unknown,
}

/// The categories the daemon's overall-status rollup reports, one per
/// `category:subject` reason prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AttentionCategory {
    Degraded,
    DurabilityAtRisk,
    DurabilityUnknown,
    FetchUnavailable,
    FetchAvailabilityUnknown,
    Conflict,
    Held,
    StrandedDirectory,
    LowDiskCritical,
    LowDisk,
    PeerDisconnected,
    RecentError,
    UpdateFailed,
    /// The folder group is linked at more than one place on this device.
    Ambiguous,
    OwnershipLost,
    VolumeChanged,
    /// The folder's disk was mounted again and only the user can confirm it.
    VolumeUnconfirmed,
    ProviderNotReady,
    ProviderStuck,
    KeptEdits,
    ProviderOrphanDomain,
    /// A device runs another version (or this one is below the minimum supported version): the
    /// user updates; nothing is waiting to come back.
    UpdateRequired,
    Unrecognized,
}

/// Whether time alone can fix an attention item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AttentionKind {
    /// Something outside the user's hands has to come back.
    Waiting,
    /// The work is tried again; trying again may succeed.
    Retryable,
    /// Nothing changes until the user acts.
    Permanent,
}

/// What the user can be offered to do about an attention item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ProductAction {
    Retry,
    ReviewConflict,
    FreeUpSpace,
    RevealPath,
    OpenSettings,
    DownloadUpdate,
    ViewDetails,
    /// Confirm that the folder's disk is the right one (`readopt_folder`).
    ConfirmDisk,
    /// Start a paused folder again (`resume`). Offered for the paused state only.
    Resume,
    /// Retire this computer's device identity and register it again as a new device, keeping its
    /// files (`start_over_as_new_device`). Offered for a restored or copied replica database.
    StartOverAsNewDevice,
    /// Look at the requests to join a folder group that wait for this account's decision
    /// (`list_pending_approvals`, then `approve_request` or `deny_request`).
    ReviewApproval,
    /// Sign in again as this installation (the step-up sign-in); the browser shows the Terms
    /// consent screen when it is due. Offered for `terms_consent_required` and
    /// `sign_in_required`; nothing local is removed.
    SignIn,
}

/// How much an attention reason matters. Critical is what the daemon's rollup calls degraded;
/// info is a wait for something outside the user's hands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AttentionSeverity {
    Info,
    Warning,
    Critical,
}

/// A named value a shell puts into the sentence for an attention key.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AttentionArg {
    /// `folder` (group id), `folder_path`, `provider_folder`, `device`, `volume` or `category`.
    pub name: String,
    pub value: String,
}

/// The five states a user sees, in the order that decides which one wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ProductState {
    UpToDate,
    Syncing,
    Waiting,
    NeedsAttention,
    Paused,
}

/// One scope's product state: the global one on the snapshot, or one folder's.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ProductSummary {
    pub state: ProductState,
    /// Folders needing attention, paused, syncing and waiting; a folder with several
    /// conditions counts under each, `state` picks by precedence.
    pub attention_count: u64,
    pub paused_count: u64,
    pub syncing_count: u64,
    pub waiting_count: u64,
    /// Bytes left in the active transfers; `None` unless every total is known, so no figure or
    /// percentage is invented.
    pub bytes_remaining: Option<u64>,
    /// The one action to offer for `state`: resume when paused, the most severe problem's
    /// action when something needs the user, otherwise none.
    pub next_action: Option<ProductAction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AttentionReason {
    pub category: AttentionCategory,
    /// A group id, volume path, device id or error category, by category.
    pub subject: String,
    /// The linked folder a folder-scoped reason is about, when its group is
    /// linked here.
    pub folder_local_path: Option<String>,
    /// The daemon's own `category:subject` text.
    pub raw: String,
    pub kind: AttentionKind,
    pub primary_action: ProductAction,
    pub secondary_action: Option<ProductAction>,
    /// Stable snake_case id of the condition, for the shell's string lookup. The daemon sends no
    /// sentences; an id a shell has no string for falls back to its generic text.
    pub key: String,
    /// What the sentence for `key` is about, by name.
    pub args: Vec<AttentionArg>,
    pub severity: AttentionSeverity,
    /// Opaque, stable identity of this condition (`key:subject`): the same on every poll and
    /// after a restart while the problem holds, different for another folder, device or volume.
    /// A shell that notifies remembers the identities it has notified for and forgets one once it
    /// is no longer reported, so a problem that clears and returns notifies again. Never shown.
    pub identity: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FolderMode {
    /// Every file is kept on this device.
    KeepAll,
    /// Files are fetched when opened.
    OnDemand,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FolderState {
    UpToDate,
    Syncing,
    Paused,
    /// The folder group is linked at more than one local folder and syncs
    /// nothing.
    Blocked,
    Attention,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DurabilityStatus {
    Protected,
    Protecting,
    AtRisk,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DurabilityEvidence {
    None,
    CorroboratedIndex,
    VerifiedPayload,
    Unknown,
}

/// Why a folder is degraded. The attention key of each cause is its snake_case name
/// (`stopped` is `folder_stopped`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DegradedCause {
    /// Stopped with no more specific cause; it retries.
    Stopped,
    /// Waits for free space on its disk; resumes by itself.
    WaitingForDiskSpace,
    /// The OS file-watch limit is hit; only the user can raise it.
    FileWatchLimit,
    /// The ownership marker is gone; re-link or restart.
    OwnershipLost,
    /// No longer joined to its folder group.
    NotJoined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum LocalStorageState {
    FullCopy,
    PartiallyMaterialized,
    OnDemand,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FetchAvailability {
    AvailableNow,
    UnavailableNow,
    Unknown,
}

/// Whether the exact content needed can be fetched now. Independent of [`Protection`].
/// Several folders aggregate to the least available one (update required, waiting for exact
/// content, waiting for a device, unknown, available); available only when all are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum Availability {
    Available,
    /// A device holding the content is online but runs another protocol version and no
    /// compatible device can serve it: updating is the remedy, waiting is not.
    UpdateRequired,
    /// A device holding the content is offline or unreachable.
    WaitingForPeer,
    /// Devices are reachable but none is known to hold the exact version.
    WaitingForExactContent,
    Unknown,
}

/// The availability with the other devices it concerns: those recorded as full copies of the
/// folder, split by whether they are reachable now. Ids are for lookup, never for display.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AvailabilitySummary {
    pub availability: Availability,
    pub reachable_device_ids: Vec<String>,
    pub offline_device_ids: Vec<String>,
    /// Online devices that hold a copy but run another protocol version; in neither list above.
    pub update_required_device_ids: Vec<String>,
}

/// Whether the data is still elsewhere if this device is lost. Independent of [`Availability`]:
/// a copy on an offline device still counts. Several folders aggregate to the least protected
/// one (at risk, pending, unknown, protected); protected only when all are provably so, and
/// unknown is never read as protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum Protection {
    Protected,
    /// Confirmed: only this device holds the current content.
    AtRisk,
    /// A copy is being made or a confirmation is still awaited.
    Pending,
    Unknown,
}

/// The protection with the other devices it concerns: those that confirmed holding the data when
/// protected, those a confirmation is awaited from when pending, none otherwise. Ids are for
/// lookup, never for display.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ProtectionSummary {
    pub protection: Protection,
    pub device_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderTransferProgress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub blocks_done: u64,
    pub blocks_total: u64,
    /// `None` when the daemon has no estimate.
    pub eta: Option<Duration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FreeSpaceState {
    Ok,
    Low,
    Critical,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct VolumeSummary {
    pub path: String,
    pub state: FreeSpaceState,
    pub available_bytes: u64,
    pub headroom_bytes: u64,
    /// What freeing up space would give back on this volume now; non-zero only on the volume the
    /// space management frees (the one holding the daemon's data) while its space is low.
    pub reclaimable_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderSummary {
    /// The identity key: the daemon keys links by path.
    pub local_path: String,
    pub group_id: String,
    pub name: String,
    pub mode: FolderMode,
    pub state: FolderState,
    pub paused: bool,
    /// When a timed pause ends by itself; `None` when not paused or paused until resumed.
    pub paused_until: Option<SystemTime>,
    pub conflict_count: u64,
    pub hydrated_file_count: u64,
    pub placeholder_file_count: u64,
    pub hydrating_file_count: u64,
    pub held_file_count: u64,
    pub skipped_symlink_count: u64,
    pub transfer: Option<FolderTransferProgress>,
    pub durability: DurabilityStatus,
    pub durability_evidence: DurabilityEvidence,
    pub local_storage: LocalStorageState,
    pub fetch_availability: FetchAvailability,
    pub availability: AvailabilitySummary,
    pub protection: ProtectionSummary,
    pub product: ProductSummary,
    pub full_replica_device_ids: Vec<String>,
    pub policy_stale: bool,
    pub ambiguous: bool,
    pub ambiguous_local_paths: Vec<String>,
    pub degraded: bool,
    /// Diagnostic text for a tooltip.
    pub degraded_reason: Option<String>,
    /// Typed cause of `degraded` (`None` when the folder is not degraded). `degraded_reason` is
    /// human detail only; never match its text.
    pub degraded_cause: Option<DegradedCause>,
    pub volume: Option<VolumeSummary>,
    /// A provider-backed folder: it has no directory, so `local_path` is only its identity key and
    /// nothing may reveal, open or restore into it as a path.
    pub provider: bool,
    /// The provider root's own status (macOS File Provider); `None` for a plain folder and for a
    /// provider folder the daemon reports no root line for.
    pub provider_status: Option<ProviderRootStatus>,
    /// Requests to join this folder's group that wait for this account's approval. Nonzero only on
    /// the account that owns the group.
    pub pending_approvals: u32,
    /// Bytes that freeing up space would give back in this folder now (what the eviction path
    /// would accept). Nonzero only while free space is low; the one condition for offering the
    /// free-up-space action.
    pub reclaimable_bytes: u64,
    /// Files the scan cannot read that wait for the person (capped; see
    /// [`MAX_UNREADABLE_FILES`]). Nothing is deleted or emptied for them. The folder is in
    /// attention whenever any exists, listed or not.
    pub unreadable_files: Vec<UnreadableFile>,
    /// How many more unreadable files exist than `unreadable_files` names. The total is
    /// `unreadable_files.len() + unreadable_files_more`.
    pub unreadable_files_more: u64,
}

/// Most unreadable files a folder summary names; `unreadable_files_more` counts the rest.
pub const MAX_UNREADABLE_FILES: usize = 50;

/// Why the scan cannot read a file, as the daemon classifies it. A reason this build does not know
/// is `Unknown`, never a guess.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum UnreadableFileReason {
    /// The system refused access; the person has to allow it.
    PermissionDenied,
    /// The path is no longer a regular file (a socket, a device, a changed type).
    NotARegularFile,
    /// Reading keeps failing.
    ReadFailed,
    Unknown,
}

impl UnreadableFileReason {
    /// The localization key for the advice on this reason: the shell words it in its own
    /// language; the core never supplies the text.
    #[must_use]
    pub fn advice_key(self) -> &'static str {
        match self {
            Self::PermissionDenied => "unreadable_file.advice.permission_denied",
            Self::NotARegularFile => "unreadable_file.advice.not_a_regular_file",
            Self::ReadFailed => "unreadable_file.advice.read_failed",
            Self::Unknown => "unreadable_file.advice.unknown",
        }
    }
}

/// One file the scan cannot read.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UnreadableFile {
    /// Relative to the folder, `/`-separated. Never absolute and never contains `..`.
    pub path: String,
    pub reason: UnreadableFileReason,
    /// Localization key of the advice for `reason` (`UnreadableFileReason::advice_key`).
    pub advice_key: String,
}

/// One provider root: why it is not ready, and the counters of what it still has to do.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ProviderRootStatus {
    /// The first 8 hex digits of the root id.
    pub root_id: String,
    pub display_name: String,
    /// "ready", or why not, in the daemon's words.
    pub readiness: String,
    /// The folder the operating system shows this root in (the Windows sync root, under
    /// `%USERPROFILE%\YadoriLink`), as the host registered it. `None` when the host has not
    /// registered it yet or the platform has no such folder. The folder's `local_path` is only an
    /// identity key for a provider folder, so this is the place to match an item against.
    pub sync_root_path: Option<String>,
    /// `None` when the counters could not be read: they are unknown, never zero.
    pub counters: Option<ProviderCounters>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ProviderCounters {
    /// Eager roots only.
    pub eager: Option<ProviderEagerProgress>,
    pub stuck: Vec<ProviderStuckFile>,
    /// Edits kept beside a file instead of replacing it.
    pub kept_edits: ProviderCount,
    /// New versions waiting to be published to the OS.
    pub pending_publications: ProviderCount,
    /// Released but not yet confirmed by the OS fetching them.
    pub unconfirmed_publications: ProviderCount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ProviderEagerProgress {
    /// "running", "paused (low disk)", "waiting for peers", "waiting for File Provider" or "done".
    pub state: String,
    /// Wanted files with no current content on the OS.
    pub remote: u64,
    /// Handed out and not settled.
    pub hydrating: u64,
    /// Files whose current content is on the OS.
    pub current: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ProviderStuckFile {
    pub path: String,
    pub failures: u32,
}

/// A count and the age of its oldest item (`None` when the count is zero).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ProviderCount {
    pub count: u64,
    pub oldest: Option<Duration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum PeerReachability {
    Connecting,
    Connected,
    Unreachable,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum UnreachableCategory {
    NoCandidates,
    NoResponse,
    UdpBlocked,
    HandshakeRefused,
    /// The account replaced this device with another one; it is refused for good.
    DeviceReplaced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RouteKind {
    Direct,
    Relay,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PeerSummary {
    pub device_id: String,
    pub reachability: PeerReachability,
    pub unreachable_category: Option<UnreachableCategory>,
    pub route: RouteKind,
}

/// One active sync transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TransferSummary {
    pub group_id: String,
    pub folder_local_path: Option<String>,
    pub path: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub blocks_done: u64,
    pub blocks_total: u64,
    pub source_device_id: String,
    pub started_at: Option<SystemTime>,
}

/// What to do with a kept copy of a file that was edited on two devices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ConflictChoice {
    /// The copy becomes the file; the other version is no longer current.
    KeepThis,
    /// The copy stays beside the original as an ordinary file under a plain name.
    KeepBoth,
}

/// An original file kept after a reset replaced it, until the user releases it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct RetainedOriginal {
    pub group_id: String,
    /// The path the original had in the folder.
    pub path: String,
    /// Bytes it takes; 0 when it is not reachable.
    pub size: u64,
    /// Whether the folder is watched, so the kept file can be reached.
    pub reachable: bool,
    pub group_removed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RetainedReleaseOutcome {
    Removed,
    Gone,
    StillRetained,
    SavedThenRemoved,
    SavedStillRetained,
    /// Left in place; `detail` says why.
    Left,
    /// A value this build does not know.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct RetainedRelease {
    pub path: String,
    pub outcome: RetainedReleaseOutcome,
    /// Why an original was left; empty otherwise.
    pub detail: String,
}

/// Automatic space management for provider folders: while free disk space is low, downloaded
/// files that are safe to give back are given back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct SpaceManagement {
    pub enabled: bool,
}

/// What automatic space management says about one downloaded item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum SpaceReclaimVerdict {
    /// Would be given back now.
    Eligible,
    /// The user keeps it on this device.
    Pinned,
    /// This folder never gives space back automatically.
    UnsupportedRoot,
    /// No other device can confirm it holds this version right now.
    CustodyUnavailable,
    /// Another operation, a program or the file system holds the item at the moment.
    Busy,
    /// The content is new, being updated or not confirmed by the system yet.
    Changed,
    /// Something makes freeing unsafe or unprovable, or the daemon answered with a value this
    /// build does not know.
    SafetyBlocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct SpaceReclaimPreviewItem {
    pub group_id: String,
    /// Path relative to the folder.
    pub path: String,
    pub verdict: SpaceReclaimVerdict,
}

/// The dry run: nothing was removed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct SpaceReclaimPreview {
    pub items: Vec<SpaceReclaimPreviewItem>,
    /// Folders that could not be read; their items are missing.
    pub unreadable_roots: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct BandwidthLimits {
    /// `None` is unlimited.
    pub upload_bytes_per_sec: Option<u64>,
    pub download_bytes_per_sec: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct BandwidthStatus {
    pub limits: BandwidthLimits,
    pub current_upload_bytes_per_sec: u64,
    pub current_download_bytes_per_sec: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct StorageSummary {
    pub block_store_total_bytes: u64,
    pub block_count: u64,
    /// `None` when no collection has run.
    pub last_gc_at: Option<SystemTime>,
    pub reclaimable_estimate_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum UpdateState {
    Idle,
    Checking,
    Available,
    HeldBack,
    KillSwitched,
    Downloading,
    Downloaded,
    Verified,
    Installing,
    Failed,
    Deferred,
    UpToDate,
    Unknown { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UpdateBadge {
    pub state: UpdateState,
    pub available_version: Option<String>,
    pub mandatory: bool,
    pub last_error_category: Option<String>,
    pub channel: String,
    pub install_source: String,
    pub holdback_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct RecentError {
    pub category: String,
    pub at: Option<SystemTime>,
    pub context: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct StatusSnapshot {
    pub captured_at: SystemTime,
    pub overall: OverallState,
    pub attention_reasons: Vec<AttentionReason>,
    pub this_device_id: Option<String>,
    /// The account state read in the same step as the snapshot, so a shell needs no second call
    /// that could disagree with it.
    pub account: AccountStatus,
    /// The engine API version the running daemon reports; `None` when it reports none.
    /// Compare with `ClientCore::engine_api_version` of the library the app loaded.
    pub engine_api_version: Option<u32>,
    pub folders: Vec<FolderSummary>,
    /// All folders together, by the aggregation rules on [`Availability`] and [`Protection`].
    pub availability: AvailabilitySummary,
    pub protection: ProtectionSummary,
    /// All folders together: the state, counts and next action no shell recomputes.
    pub product: ProductSummary,
    pub peers: Vec<PeerSummary>,
    pub transfers: Vec<TransferSummary>,
    pub bandwidth: BandwidthStatus,
    pub volumes: Vec<VolumeSummary>,
    pub storage: StorageSummary,
    pub update: UpdateBadge,
    pub recent_errors: Vec<RecentError>,
}

/// One result of the status poll loop.
// Kept inline rather than boxed: the foreign binding lowers the variant's
// fields directly and has no boxed form, and one value lives per watch.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum StatusUpdate {
    Snapshot {
        snapshot: StatusSnapshot,
    },
    /// The daemon could not be asked; replaces the snapshot.
    Unavailable {
        error: DesktopError,
    },
}

// ---- folder detail and files ------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct HeldFile {
    pub path: String,
    pub reason: String,
    pub held_since: Option<SystemTime>,
}

/// One device holding a complete copy of a folder, with this device's
/// current connection to it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ReplicaCopy {
    pub device_id: String,
    pub reachability: PeerReachability,
    pub route: RouteKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderDetail {
    pub summary: FolderSummary,
    pub held_files: Vec<HeldFile>,
    pub complete_copies: Vec<ReplicaCopy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ConflictSummary {
    /// The linked folder's root.
    pub local_path: String,
    /// The conflicted copy, relative to the root.
    pub path: String,
    pub size: u64,
    pub modified_at: Option<SystemTime>,
    /// The file the copy conflicts with, relative to the root.
    pub current_path: String,
    pub loser_device_id: Option<String>,
    pub conflict_timestamp: Option<String>,
    pub kind: EntryKind,
    pub reason: ConflictReason,
    /// Whether Keep this / Keep both is offered for this copy. The daemon
    /// checks the same predicate when the action runs.
    pub can_resolve: bool,
    /// The device whose version the copy holds, when this device knows it.
    pub origin_device_id: Option<String>,
    /// Opaque, stable identity of this one conflict (`conflict_needs_review:` plus the folder root
    /// and the copy's own path): the same on every list and after a restart while the copy exists,
    /// different for every copy. A shell that notifies per conflict remembers the identities it
    /// told the person about and forgets one once the list no longer has it. Never shown.
    pub identity: String,
}

/// Why a conflict copy is kept under its own name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ConflictReason {
    /// Devices changed the same file at the same time; the copy holds the
    /// version that did not keep the name.
    ConcurrentEdit,
    /// The name the copy came from is a folder now, so the file was moved
    /// aside instead of replacing the folder.
    FolderAtPath,
}

/// What kind of filesystem entry a record is. A directory carries no size
/// or modification time of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct TrashedFile {
    pub local_path: String,
    pub path: String,
    pub version_seq: i64,
    pub last_known_size: u64,
    pub origin_device_id: Option<String>,
    pub deleted_at: Option<SystemTime>,
    pub kind: EntryKind,
    /// The recursive delete or directory rename that removed this entry;
    /// every trashed entry sharing it is restored together by
    /// [`crate::ClientCore::restore_trash_operation`]. `None` for an entry
    /// deleted on its own.
    pub deleted_by_operation: Option<String>,
}

/// What restoring a folder from the trash brought back.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderRestoreOutcome {
    /// Relative to the folder root, in path order.
    pub restored_paths: Vec<String>,
    pub failed: Vec<FolderRestoreFailure>,
    /// Not every part of the operation has reached this device, so what it
    /// removed elsewhere in the folder could not be restored here.
    pub partial: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FolderRestoreFailure {
    pub path: String,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FileVersion {
    pub version_seq: i64,
    pub size: u64,
    pub modified_at: Option<SystemTime>,
    /// The daemon's own state value, for a tooltip.
    pub state: String,
    pub origin_device_id: Option<String>,
    pub unix_mode: Option<u32>,
    /// The highest `version_seq` of the file.
    pub is_current: bool,
    pub kind: EntryKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum MaterializationState {
    Hydrated,
    Placeholder,
    Hydrating,
    Evicting,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FileAvailability {
    pub tracked: bool,
    pub state: MaterializationState,
    /// The actions the engine offers for the item right now, in presentation order. A front end
    /// offers exactly these and derives no eligibility of its own.
    pub actions: Vec<FileAction>,
}

/// An action on one file that the engine currently allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum FileAction {
    Download,
    FreeUpSpace,
    KeepOnDevice,
    StopKeeping,
}

/// Whether local space for a file or folder may be reclaimed, apart from whether its content is
/// on this device now. Local to this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RetentionPolicy {
    Reclaimable,
    /// "Always keep on this device".
    Pinned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FileRetention {
    pub policy: RetentionPolicy,
    /// Pinned only because a folder above is; unpinning this path alone changes nothing.
    pub inherited: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PinOutcome {
    pub retention: FileRetention,
    /// Why the content could not be downloaded just now; the pin stands regardless.
    pub download_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct EvictOutcome {
    pub evicted: bool,
    pub blocks_reclaimed: u64,
    pub bytes_reclaimed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct HandoffSummary {
    pub target_device_id: String,
    pub membership_generation: i64,
    pub lease_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UnlinkOutcome {
    pub handoff: Option<HandoffSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct StorageModeOutcome {
    /// `false` when the folder was already in the requested mode.
    pub changed: bool,
    pub handoff: Option<HandoffSummary>,
}

// ---- devices and membership -------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DeviceSummary {
    pub device_id: String,
    pub display_name: String,
    pub online: bool,
    /// `None` when the listing does not report it.
    pub last_seen: Option<SystemTime>,
    pub is_this_device: bool,
    /// On the same account as this one (a folder shared with someone else
    /// lists their devices too).
    pub is_caller_account: bool,
    /// The engine says this device can be administered from here (see
    /// `yadorilink_product_view::can_manage_device`). `false` when that cannot be told.
    pub can_manage: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct MembershipHandoff {
    pub group_id: String,
    pub target_device_id: String,
    pub lease_id: String,
    pub membership_generation: u64,
}

/// What a membership removal did. A front end must show the data-loss
/// warning when `forced_group_ids` is non-empty, and the unknown-scope
/// warning when `unknown_scope_operation_id` is set.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct MembershipOutcome {
    pub handoffs: Vec<MembershipHandoff>,
    pub forced_group_ids: Vec<String>,
    pub unknown_scope_operation_id: Option<String>,
}

// ---- shares -------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct GroupSummary {
    pub group_id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ShareRole {
    Owner,
    Editor,
    Viewer,
    Other { raw: String },
}

/// The roles a member can be changed to or invited with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AssignableRole {
    Viewer,
    Editor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum MemberRelationship {
    You,
    YourOtherDevice,
    OwnersDevice,
    Invited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum MemberStorage {
    FullCopy,
    OnDemand,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct MemberSummary {
    pub device_id: String,
    pub device_name: String,
    pub role: ShareRole,
    pub relationship: MemberRelationship,
    pub storage: MemberStorage,
    pub online: bool,
    pub last_seen: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PendingApprovalSummary {
    pub group_id: String,
    pub group_name: String,
    pub device_id: String,
    pub requested_role: Option<ShareRole>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ShareEdgeState {
    Active,
    PendingApproval,
    Other { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ShareSummary {
    pub edge_id: String,
    pub group_id: String,
    pub group_name: String,
    pub device_id: String,
    pub state: ShareEdgeState,
    pub role: Option<ShareRole>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ApproveOutcome {
    Approved,
    AlreadyActive,
    Unrecognized { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RevokeEdgeOutcome {
    Revoked { outcome: MembershipOutcome },
    AlreadyRevoked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct InviteSummary {
    pub invite_id: String,
    pub code: String,
    /// `yadorilink://invite/<code>`, built here so no front end assembles it.
    pub url: String,
    pub group_id: String,
    pub role: ShareRole,
    pub expires_at: SystemTime,
    pub requires_approval: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum InviteStatus {
    Pending,
    Other { raw: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PendingInviteSummary {
    pub invite_id: String,
    pub group_id: String,
    pub group_name: String,
    pub role: ShareRole,
    pub expires_at: SystemTime,
    pub status: InviteStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AcceptInviteOutcome {
    pub group_id: String,
    pub local_path: String,
    /// The folder is linked but syncs nothing until the owner approves.
    pub awaiting_approval: bool,
}

// ---- linking ------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FreeSpace {
    pub available_bytes: u64,
    pub total_bytes: u64,
    pub headroom_bytes: u64,
    pub state: FreeSpaceState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum NestedLinkRelation {
    Ancestor,
    Descendant,
    Same,
}

/// One risky condition a link preflight found, in the order the preflight
/// reports them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum PreflightIssue {
    PathMissing,
    IgnoreRulesUnreadable,
    NotEmpty { entry_count: u64, scan_truncated: bool },
    LowFreeSpace { available_bytes: u64, headroom_bytes: u64 },
    CriticalFreeSpace { available_bytes: u64, headroom_bytes: u64 },
    NestedLink { other_path: String, relation: NestedLinkRelation },
    CloudProviderFolder { provider: String },
    FilesystemRoot,
    HomeDirectory,
    ReservedName { path: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct PreflightResult {
    pub resolved_path: String,
    pub path_exists: bool,
    pub is_directory: bool,
    pub entry_count: u64,
    pub ignored_entry_count: u64,
    pub total_size_bytes: u64,
    pub scan_truncated: bool,
    pub free_space: Option<FreeSpace>,
    pub issues: Vec<PreflightIssue>,
    /// The daemon refuses the link unless the risks are acknowledged.
    pub requires_acknowledgement: bool,
}

/// Where and under what name the default "YadoriLink Folder" is created.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DefaultFolder {
    /// The folder group's name.
    pub name: String,
    /// The directory it is linked at.
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct LinkOutcome {
    pub group_id: String,
    pub local_path: String,
    pub mode: FolderMode,
}

/// A provider-backed folder just created: it has no local path, the File Provider domain is the folder.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ProviderFolderOutcome {
    pub group_id: String,
    pub root_id: String,
    pub display_name: String,
    pub mode: FolderMode,
    /// The request was a retry of one that had already completed.
    pub already_existed: bool,
}

/// An invite redeemed as a provider-backed folder: it has no local path, the operating system's
/// root is the folder.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ProviderInviteOutcome {
    pub group_id: String,
    pub root_id: String,
    pub display_name: String,
    pub mode: FolderMode,
    /// The folder exists but syncs nothing until the group owner approves.
    pub awaiting_approval: bool,
}

// ---- send and receive, storage, settings, updates ---------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct SentTransfer {
    pub transfer_id: String,
    pub files_offered: Vec<String>,
    pub total_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct IncomingFile {
    pub relative_path: String,
    pub size: u64,
}

/// Why a transfer stopped, as a closed set a shell words itself.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum TransferFailure {
    /// The other device could not be reached.
    Unreachable,
    /// The receiving device declined the offer.
    Declined,
    /// The sending device canceled the transfer.
    SenderCanceled,
    /// The sending device does not hold the offer as accepted.
    NotAccepted,
    /// The other device refused for another reason.
    Rejected,
    /// What arrived did not match what was offered.
    VerificationFailed,
    /// This device could not store what arrived.
    LocalStorage,
    /// The other device stopped reading what this device was sending it; the serve ended. The
    /// other device can fetch it again, or the transfer can be stopped.
    Stalled,
    /// The transfer stopped without a clearer reason.
    Interrupted,
    Other {
        raw: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum IncomingTransferStatus {
    Pending,
    InProgress,
    Completed,
    /// The receive stopped on an error, or the daemon restarted during it.
    Failed,
    Canceled,
    Other {
        raw: String,
    },
}

/// How long a pause lasts. The daemon computes the deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum PauseDuration {
    /// Until the user resumes.
    UntilResumed,
    ThirtyMinutes,
    OneHour,
    /// Until the next local midnight.
    UntilTomorrow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct IncomingTransfer {
    pub transfer_id: String,
    pub sender_device_id: String,
    pub files: Vec<IncomingFile>,
    pub total_size: u64,
    pub offered_at: Option<SystemTime>,
    pub status: IncomingTransferStatus,
    /// Why a failed transfer stopped, when the daemon has it on record.
    pub failure: Option<TransferFailure>,
    /// Whether `retry_transfer` is offered: the transfer failed or was canceled.
    pub can_retry: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum OutgoingTransferStatus {
    /// Not answered yet: the other device has not been reached or has not replied.
    Offered,
    /// The other device accepted it and may fetch it.
    Accepted,
    /// The other device reported that it received everything.
    Completed,
    /// The other device declined it.
    Declined,
    Canceled,
    Other {
        raw: String,
    },
}

/// A transfer this device sent. The list holds every one still going and the most recent finished
/// ones; history is bounded and survives a restart.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct OutgoingTransfer {
    pub transfer_id: String,
    pub target_device_id: String,
    pub files: Vec<IncomingFile>,
    pub total_size: u64,
    pub created_at: Option<SystemTime>,
    pub status: OutgoingTransferStatus,
    /// Why it stopped, when the daemon has it on record.
    pub failure: Option<TransferFailure>,
    /// Whether `retry_sent_transfer` is offered. A retry checks the offered files are unchanged
    /// and asks for a new authorization; it never reuses an old one.
    pub can_retry: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct ReceivedTransfer {
    pub destination_dir: String,
    pub files_received: Vec<String>,
    pub bytes_received: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct GcReport {
    pub dry_run: bool,
    pub blocks_deleted: u64,
    pub bytes_reclaimed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DiagnosticsCollectionMode {
    /// Assembled by the daemon.
    Daemon,
    /// Assembled by the daemon, which ran out of its time budget.
    DaemonPartial,
    /// The daemon was not reachable; a limited bundle from this process.
    OfflineFallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DiagnosticsExport {
    pub path: String,
    pub collection_mode: DiagnosticsCollectionMode,
    pub redaction_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DaemonStartOutcome {
    AlreadyRunning,
    Started,
}

/// Update preferences. Updates are installed by the user (or a package
/// manager or store), never by YadoriLink, so the only setting is whether it
/// checks for a newer version by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UpdateConfig {
    pub automatic_checks: bool,
}

/// Why a safe stop did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum SafeStopBusyReason {
    /// A write did not reach a safe point within the deadline.
    WritesInProgress,
    /// A database could not be checkpointed.
    CheckpointFailed,
    /// Another safe-stop request was still working.
    AnotherRequestInProgress,
}

/// How a safe-stop request ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum SafeStopOutcome {
    /// The daemon is at a safe point, its databases are checkpointed and it has begun to exit
    /// with success. Wait for the process to end (or the data-area lock to become free).
    Stopping { already_in_progress: bool },
    /// The daemon did not stop and is running normally. Retry after `retry_after_secs`.
    Busy { reason: SafeStopBusyReason, retry_after_secs: u32, detail: String },
}

/// The distribution that owns a daemon or a data area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DaemonOwner {
    /// The headless distribution: the one-liner, a package manager, a container.
    Cli,
    /// The desktop distribution: the macOS app bundle or the Windows Store package.
    Gui,
}

/// What the owner's installer recorded for the data area.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct OwnershipRecordSummary {
    pub owner: DaemonOwner,
    pub install_source: String,
    pub install_root: String,
    pub release_id: Option<String>,
    pub written_at: Option<SystemTime>,
}

/// The data area's recorded owner, as the daemon sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum DataAreaOwnership {
    Recorded {
        record: OwnershipRecordSummary,
    },
    /// No owner has been recorded yet.
    NotRecorded,
    /// A record exists and cannot be read: the owner is unknown and nothing may take over.
    Unreadable {
        detail: String,
    },
}

/// The read-only answer of `identify`: who the running daemon is.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct DaemonIdentity {
    pub version: String,
    /// Compare with `ClientCore::engine_api_version`.
    pub engine_api_version: u32,
    /// The exact engine build; `None` when the installation carries no engine identity.
    pub release_id: Option<String>,
    /// `script`, `standalone`, `app_bundle`, `microsoft_store`, `app_store`, `homebrew`, `apt`, `winget` or
    /// `container`.
    pub install_source: String,
    pub install_root: String,
    pub owner: DaemonOwner,
    pub ownership: DataAreaOwnership,
    pub pid: u32,
    pub started_at: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UpdateStatus {
    pub current_version: String,
    pub channel: String,
    pub install_source: String,
    pub last_checked_at: Option<SystemTime>,
    /// The last check that accepted a manifest; a failed check does not move it.
    pub last_successful_check_at: Option<SystemTime>,
    /// `expires_at` of the manifest the last check saw, as the publisher wrote it.
    pub manifest_expires_at: Option<String>,
    /// The last check refused the channel manifest as expired. Only update checks stop; sync
    /// and running apps are unaffected.
    pub manifest_expired: bool,
    pub state: UpdateState,
    pub available_version: Option<String>,
    pub release_notes_url: Option<String>,
    pub mandatory: bool,
    pub holdback_reason: Option<String>,
    pub last_error_category: Option<String>,
    pub last_error_message: Option<String>,
    /// A package manager or store owns this install, so the new version
    /// comes with steps to follow, not a page to open.
    pub package_managed: bool,
    pub config: UpdateConfig,
}

/// How to get the new version. Nothing is downloaded or installed by
/// YadoriLink: `guidance` is the sentence to show (the download page, or the
/// package-manager steps for a package-managed install), and `url` is the
/// official page to open, only when there is one to open.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct UpdateDownloadGuidance {
    pub guidance: String,
    pub url: Option<String>,
}

/// An appcast item as the app sees it, to check against the verified channel manifest.
/// `version`, `sparkle_build` (the item's `sparkle:version`, a positive integer), `url` (the
/// whole enclosure URL) and `length` (the enclosure length) are required in both phases; an
/// empty or zero one is refused, never skipped. `channel` is compared when given. `sha256` is
/// the downloaded file's digest and is required by [`AppcastItemPhase::Downloaded`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AppcastItem {
    pub version: String,
    pub sparkle_build: u64,
    pub channel: Option<String>,
    pub url: String,
    pub length: u64,
    pub sha256: Option<String>,
}

/// Which of the two checks is being made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AppcastItemPhase {
    /// Before the download, from the appcast alone (version, build, URL, length).
    Enclosure,
    /// The file is on disk and its sha256 is known; before the updater installs it.
    Downloaded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AppcastItemOutcome {
    /// Every field the phase requires equals what the verified manifest serves to this install.
    /// After `Enclosure` this does not cover the file's bytes; only `Downloaded` does.
    Allowed,
    /// The manifest is known and does not cover the item: do not hand it to the updater.
    Refused,
    /// No fresh, unexpired verified manifest: nothing is known to be wrong. Do not hand the item
    /// to the updater; show "cannot confirm", never "update required".
    CannotConfirm,
    Unknown {
        raw: String,
    },
}

/// Why an item was not allowed. The first four mean `CannotConfirm`, the rest `Refused`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum AppcastItemReason {
    /// No manifest was verified since the daemon started or the channel changed.
    NotChecked,
    /// The last verified manifest is too old to rely on.
    Stale,
    ManifestExpired,
    /// The channel has no manifest.
    NoManifest,
    InvalidVersion,
    Withdrawn,
    KillSwitched,
    BelowMinimum,
    /// The manifest has no `app_bundle` entry for this install.
    NotOffered,
    VersionMismatch,
    HeldBack,
    StateIncompatible,
    ChannelMismatch,
    BuildMissing,
    BuildNotDeclared,
    BuildMismatch,
    UrlMissing,
    UrlMismatch,
    LengthMissing,
    LengthMismatch,
    /// The `Downloaded` phase needs the file's sha256.
    Sha256Missing,
    Sha256Mismatch,
    Unknown {
        raw: String,
    },
}

/// The verified `app_bundle` entry for this install, for the app to cache.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct VerifiedAppEntry {
    pub channel: String,
    pub version: String,
    /// `None` when the manifest declares none.
    pub sparkle_build: Option<u64>,
    pub minimum_supported_version: String,
    pub file: String,
    pub sha256: String,
    pub size: u64,
    pub kill_switch: bool,
    pub rollout_percentage: u32,
    pub generated_at: String,
    /// When the entry stops being valid, as the publisher wrote it (`YYYY-MM-DDTHH:MM:SSZ`).
    pub expires_at: String,
    /// This build is below `minimum_supported_version`.
    pub update_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct AppcastItemCheck {
    pub outcome: AppcastItemOutcome,
    /// `None` when allowed.
    pub reason: Option<AppcastItemReason>,
    /// The daemon's wording of the reason, for diagnostics.
    pub message: Option<String>,
    /// Set whenever a fresh verified manifest has an entry for this install, also when refused;
    /// never set for `CannotConfirm`.
    pub entry: Option<VerifiedAppEntry>,
}

#[cfg(test)]
mod tests;

// ---- folder rewind ------------------------------------------------------

/// What rewinding a folder to `target_unix_nanos` would change. Nothing was
/// changed. `unavailable_message` is the daemon's wording of the unavailable
/// files grouped by cause, empty when there are none; the rewind cannot
/// start while `unavailable_count` is above zero.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct RewindPreview {
    /// Echo of the requested time on the daemon's clock; the execution is
    /// named by this value and `plan_id`, never by a relative time.
    pub target_unix_nanos: i64,
    /// Files that would come back or be rolled back to the earlier content.
    pub restore_count: u64,
    /// Files that would be removed.
    pub remove_count: u64,
    pub unavailable_count: u64,
    pub unavailable_message: String,
    /// Identifies this preview; kept for the execution, not for display.
    pub plan_id: Vec<u8>,
}

/// Why a request to start a rewind was refused. Nothing was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RewindRefusal {
    UnavailableFiles,
    RunActive,
    NotAuthorized,
    FolderFrozen,
    UnknownFolder,
    InsufficientSpace,
    FolderSettling,
    Other,
}

/// How a request to start the rewind a preview showed was answered.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RewindStartOutcome {
    Started {
        run_id: String,
    },
    /// The folder changed since the preview; nothing was started.
    FolderChanged {
        message: String,
    },
    Refused {
        reason: RewindRefusal,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RewindRunState {
    /// Gathering the content the rewind needs; nothing changed yet.
    Gathering,
    /// Changing the folder, one step at a time.
    Rewinding,
    Done,
    /// Stopped after some changes were made; they stay as ordinary changes.
    Interrupted,
    /// Stopped before anything changed.
    Failed,
}

/// Why a rewind stopped before anything changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum RewindFailure {
    ContentUnavailable,
    DevicesOffline,
    FolderChanged,
    CannotChangeFolder,
    Interrupted,
}

/// A folder's latest rewind run. `message` is the daemon's wording for the
/// run as it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct RewindRun {
    pub run_id: String,
    pub state: RewindRunState,
    /// Set exactly when `state` is `Failed`.
    pub failure: Option<RewindFailure>,
    pub steps_total: u64,
    pub steps_done: u64,
    pub restored: u64,
    pub removed: u64,
    pub message: String,
}
