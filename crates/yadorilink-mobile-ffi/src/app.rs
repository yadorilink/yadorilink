//! The application commands of the embedded host as exported records and methods: shares,
//! link lifecycle, status, preserved items, space management and the account. Each method is
//! one command of `yadorilink-embedded-host`, run with the call's cancel handle and optional
//! deadline; the records mirror the host's typed requests and responses and the errors are the
//! typed ones of [`CallFailure`](crate::CallFailure). Nothing here decides anything.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use yadorilink_embedded_host as host;
use yadorilink_embedded_host::dto;

use crate::{options, CallFailure, CancelHandle, MobileHost};

/// A command returned an output of another kind than it must: a bug of the bridge, reported
/// as a failure rather than a crash.
fn unexpected(command: &str, output: &host::CommandOutput) -> CallFailure {
    CallFailure::Failed {
        reason: crate::FailureReason::Unspecified,
        message: format!("{command} returned {output:?}"),
    }
}

// ---- errors ----------------------------------------------------------------------------

/// Why the engine refused a command; the same codes the desktop daemon answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RefusalCode {
    Unspecified,
    LocalIdentityUnavailable,
    TargetNotFound,
    ReplicaNotReady,
    TicketUnavailable,
    CoordinationRejected,
    CoordinationAmbiguous,
    DurabilityLatchFailed,
    RecoveryPending,
    CoordinationTransport,
    Persistence,
    PreparationRejected,
    LocalLinkFailed,
    ActivationRejected,
    ActivationAmbiguous,
    CompensationPending,
    OperationConflict,
    RecoveryJournalUnavailable,
    UnrecordedLocalChanges,
    ConflictNotResolvable,
    DiskFull,
    PathNotAllowed,
    /// Unlinking would leave the group without a confirmed complete copy elsewhere.
    NotProtected,
    InviteExpired,
    InviteAlreadyUsed,
    /// The folder now belongs to a different group than the caller expected.
    GroupMismatch,
    AccessDenied,
    /// The account has not accepted the current Terms: signing in again shows them.
    TermsConsentRequired,
    /// Send links. The sender's own view tells expired, used and cancelled apart; a redeemer
    /// only ever learns `SendLinkInvalid`.
    SendLinkExpired,
    SendLinkAlreadyUsed,
    SendLinkCancelled,
    SendLinkInvalid,
    SendPeerUnreachable,
    SendNoSpace,
    SendInterrupted,
    /// The service has Send links switched off.
    SendLinksDisabled,
    /// This device's operating system refused to send to the local network (macOS Local Network
    /// privacy, a firewall, a VPN); a device on the same network could not be reached.
    SendLocalNetworkBlocked,
    /// The file list of a Send link does not open with its code (altered, or sealed for another
    /// link): do not show a list. The link itself is still valid and can be redeemed.
    SendPreviewUnverified,
}

impl From<yadorilink_ipc_proto::daemonctl::ApplicationErrorCode> for RefusalCode {
    fn from(code: yadorilink_ipc_proto::daemonctl::ApplicationErrorCode) -> Self {
        use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode as C;
        match code {
            C::Unspecified => Self::Unspecified,
            C::LocalIdentityUnavailable => Self::LocalIdentityUnavailable,
            C::TargetNotFound => Self::TargetNotFound,
            C::ReplicaNotReady => Self::ReplicaNotReady,
            C::TicketUnavailable => Self::TicketUnavailable,
            C::CoordinationRejected => Self::CoordinationRejected,
            C::CoordinationAmbiguous => Self::CoordinationAmbiguous,
            C::DurabilityLatchFailed => Self::DurabilityLatchFailed,
            C::RecoveryPending => Self::RecoveryPending,
            C::CoordinationTransport => Self::CoordinationTransport,
            C::Persistence => Self::Persistence,
            C::PreparationRejected => Self::PreparationRejected,
            C::LocalLinkFailed => Self::LocalLinkFailed,
            C::ActivationRejected => Self::ActivationRejected,
            C::ActivationAmbiguous => Self::ActivationAmbiguous,
            C::CompensationPending => Self::CompensationPending,
            C::OperationConflict => Self::OperationConflict,
            C::RecoveryJournalUnavailable => Self::RecoveryJournalUnavailable,
            C::UnrecordedLocalChanges => Self::UnrecordedLocalChanges,
            C::ConflictNotResolvable => Self::ConflictNotResolvable,
            C::DiskFull => Self::DiskFull,
            // A phone links no plain folder, so a refused drive never reaches it; the nearest
            // existing refusal if it ever does.
            C::PathNotAllowed | C::UnsupportedDrive => Self::PathNotAllowed,
            C::NotProtected => Self::NotProtected,
            C::InviteExpired => Self::InviteExpired,
            C::InviteAlreadyUsed => Self::InviteAlreadyUsed,
            C::GroupMismatch => Self::GroupMismatch,
            C::AccessDenied => Self::AccessDenied,
            C::TermsConsentRequired => Self::TermsConsentRequired,
            C::SendLinkExpired => Self::SendLinkExpired,
            C::SendLinkAlreadyUsed => Self::SendLinkAlreadyUsed,
            C::SendLinkCancelled => Self::SendLinkCancelled,
            C::SendLinkInvalid => Self::SendLinkInvalid,
            C::SendPeerUnreachable => Self::SendPeerUnreachable,
            C::SendNoSpace => Self::SendNoSpace,
            C::SendInterrupted => Self::SendInterrupted,
            C::SendLinksDisabled => Self::SendLinksDisabled,
            C::SendLocalNetworkBlocked => Self::SendLocalNetworkBlocked,
            C::SendPreviewUnverified => Self::SendPreviewUnverified,
        }
    }
}

/// Why an operation on a preserved item was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PreservedRefusal {
    NotFound,
    /// A rebootstrap of the group is running.
    Busy,
    /// This device may not author into the group now.
    NotAWriter,
    /// The item holds no version record.
    RecordUnavailable,
    /// The item holds the record but its bytes cannot be obtained.
    ContentUnavailable,
}

impl From<host::PreservedRefusal> for PreservedRefusal {
    fn from(reason: host::PreservedRefusal) -> Self {
        match reason {
            host::PreservedRefusal::NotFound => Self::NotFound,
            host::PreservedRefusal::Busy => Self::Busy,
            host::PreservedRefusal::NotAWriter => Self::NotAWriter,
            host::PreservedRefusal::RecordUnavailable => Self::RecordUnavailable,
            host::PreservedRefusal::ContentUnavailable => Self::ContentUnavailable,
        }
    }
}

/// Why a re-adoption of a marked folder was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ReadoptRefusal {
    /// This engine has no folder of the group.
    GroupUnknown,
    /// The folder of the group is not marked as needing action: it already syncs.
    NotMarked,
    /// The folder of the group is an ordinary folder; only a provider folder is re-adopted.
    NotAProviderFolder,
    /// The engine still runs as the retired device: restart it (`suspend`, `resume`) first.
    RestartRequired,
}

impl From<host::ReadoptRefusal> for ReadoptRefusal {
    fn from(reason: host::ReadoptRefusal) -> Self {
        match reason {
            host::ReadoptRefusal::GroupUnknown => Self::GroupUnknown,
            host::ReadoptRefusal::NotMarked => Self::NotMarked,
            host::ReadoptRefusal::NotAProviderFolder => Self::NotAProviderFolder,
            host::ReadoptRefusal::RestartRequired => Self::RestartRequired,
        }
    }
}

/// What kind of failure an account command had.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AccountErrorKind {
    NotSignedIn,
    /// The coordination service could not be reached or did not answer in time.
    Network,
    PermissionDenied,
    /// The action needs an interactive confirmation made in the last few minutes (account
    /// deletion after a stale sign-in): call `begin_sign_in` with `reauthenticate` set, wait
    /// for its `SignedIn`, then repeat the refused action once. Never an ordinary sign-in.
    ReauthenticationRequired,
    /// The account has not accepted the current Terms (`terms_consent_required`). Nothing local
    /// changed and the folders keep their state: call `begin_sign_in` with `reauthenticate` set
    /// (the browser shows the consent screen), wait for its `SignedIn`, then repeat the action.
    TermsConsentRequired,
    /// Refused because a shared folder would be left without a confirmed complete copy;
    /// `can_force` says whether repeating the call with the acknowledgement is offered.
    DurabilityBlocked,
    InvalidInput,
    /// The service refused for a reason the person can act on.
    Refused,
    /// `start_over` was refused because a start over already finished on this engine and it has
    /// not been restarted since (it still reports `database_restored`): `suspend` and `resume`
    /// the engine, then offer start over again only if the item is still there.
    StartOverRestartRequired,
    /// A local daemon is not part of this build; kept for the product's own taxonomy.
    DaemonUnavailable,
    Internal,
    /// The pairing code of `begin_pairing_sign_in` is not accepted: never issued, expired
    /// (ten minutes) or already used; the service does not say which. Nothing changed; the
    /// person makes a new code on the web page. Declared last so the other kinds keep their
    /// order.
    PairingCodeInvalid,
    /// A primary-ownership hand-over call was refused, one kind per reason (nothing
    /// changed). The caller's account is not the folder's primary owner.
    PrimaryTransferNotPrimary,
    /// The chosen device is not an active member of the folder.
    PrimaryTransferTargetNotMember,
    /// The chosen device is on the caller's own account: choose a device of another person.
    PrimaryTransferTargetSameAccount,
    /// The offer lapsed (offers last seven days).
    PrimaryTransferOfferExpired,
    /// The folder is being created, handed off or deleted right now: try again shortly.
    PrimaryTransferGroupNotActive,
    /// Another offer is pending, this one was already settled or replaced, or the folder
    /// changed owner or kept changing: list the pending offers and decide again.
    PrimaryTransferConflict,
    /// No such folder or offer for this account.
    PrimaryTransferNotFound,
    /// The service's abuse budget refused the request: wait `retry_after_secs` (when present),
    /// then repeat. Nothing changed. Declared last so the other kinds keep their order.
    RateLimited,
}

/// The typed error of an account command.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountError {
    pub kind: AccountErrorKind,
    pub message: String,
    /// The groups a `DurabilityBlocked` refusal is about.
    pub group_ids: Vec<String>,
    pub can_force: bool,
    /// For `RateLimited`: the service's own wait in seconds, when it gave one.
    pub retry_after_secs: Option<u64>,
}

impl From<host::DesktopError> for AccountError {
    fn from(error: host::DesktopError) -> Self {
        use host::DesktopError as E;
        let plain = |kind, message| Self {
            kind,
            message,
            group_ids: Vec::new(),
            can_force: false,
            retry_after_secs: None,
        };
        match error {
            E::NotSignedIn { message } => plain(AccountErrorKind::NotSignedIn, message),
            E::DaemonUnavailable { message, .. } => {
                plain(AccountErrorKind::DaemonUnavailable, message)
            }
            E::Network {
                message,
                kind: host::NetworkErrorKind::RateLimited { retry_after_secs },
            } => Self { retry_after_secs, ..plain(AccountErrorKind::RateLimited, message) },
            E::Network { message, .. } => plain(AccountErrorKind::Network, message),
            E::PermissionDenied {
                message,
                reason: host::PermissionDeniedReason::ReauthenticationRequired,
            } => plain(AccountErrorKind::ReauthenticationRequired, message),
            E::PermissionDenied {
                message,
                reason: host::PermissionDeniedReason::TermsConsentRequired,
            } => plain(AccountErrorKind::TermsConsentRequired, message),
            E::PermissionDenied { message, .. } => {
                plain(AccountErrorKind::PermissionDenied, message)
            }
            E::DurabilityBlocked { message, group_ids, can_force, .. } => Self {
                kind: AccountErrorKind::DurabilityBlocked,
                message,
                group_ids,
                can_force,
                retry_after_secs: None,
            },
            E::InvalidInput { message, .. } => plain(AccountErrorKind::InvalidInput, message),
            E::Internal { message, .. } => plain(AccountErrorKind::Internal, message),
            E::UnsupportedDrive { message, .. } => plain(AccountErrorKind::Refused, message),
            E::Refused { message, reason: host::RefusalReason::StartOverRestartRequired } => {
                plain(AccountErrorKind::StartOverRestartRequired, message)
            }
            E::Refused { message, reason: host::RefusalReason::PairingCodeInvalid } => {
                plain(AccountErrorKind::PairingCodeInvalid, message)
            }
            E::Refused { message, reason } => {
                use host::RefusalReason as R;
                let kind = match reason {
                    R::PrimaryTransferNotPrimary => AccountErrorKind::PrimaryTransferNotPrimary,
                    R::PrimaryTransferTargetNotMember => {
                        AccountErrorKind::PrimaryTransferTargetNotMember
                    }
                    R::PrimaryTransferTargetSameAccount => {
                        AccountErrorKind::PrimaryTransferTargetSameAccount
                    }
                    R::PrimaryTransferOfferExpired => AccountErrorKind::PrimaryTransferOfferExpired,
                    R::PrimaryTransferGroupNotActive => {
                        AccountErrorKind::PrimaryTransferGroupNotActive
                    }
                    R::PrimaryTransferConflict => AccountErrorKind::PrimaryTransferConflict,
                    R::PrimaryTransferNotFound => AccountErrorKind::PrimaryTransferNotFound,
                    _ => AccountErrorKind::Refused,
                };
                plain(kind, message)
            }
        }
    }
}

// ---- primary-ownership hand-over ----------------------------------

/// Which side of an ownership offer this account is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PrimaryTransferDirection {
    /// This account offered its folder to another account.
    Outgoing,
    /// Another account offered its folder to this one.
    Incoming,
    /// A direction a newer service added.
    Unrecognized,
}

/// Where an ownership offer stands. A listed offer is `Pending`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PrimaryTransferStatus {
    Pending,
    Accepted,
    Cancelled,
    Declined,
    /// A status a newer service added.
    Other {
        raw: String,
    },
}

/// An offer to hand a folder's primary ownership to another account. It names no account, email
/// or person: `to_device_id` is the device the primary chose. Offers last seven days.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PrimaryTransfer {
    pub transfer_id: String,
    pub group_id: String,
    pub group_name: String,
    pub direction: PrimaryTransferDirection,
    pub status: PrimaryTransferStatus,
    pub to_device_id: String,
    /// Seconds since the Unix epoch.
    pub created_at_unix: u64,
    /// Seconds since the Unix epoch.
    pub expires_at_unix: u64,
}

/// What accepting an offer produced: this account is now the folder's primary owner.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PrimaryTransferAccepted {
    pub transfer_id: String,
    pub group_id: String,
    /// The folder's membership generation after the hand-over.
    pub membership_generation: u64,
}

fn unix_secs(time: std::time::SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl From<dto::PrimaryTransferSummary> for PrimaryTransfer {
    fn from(t: dto::PrimaryTransferSummary) -> Self {
        Self {
            transfer_id: t.transfer_id,
            group_id: t.group_id,
            group_name: t.group_name,
            direction: match t.direction {
                dto::PrimaryTransferDirection::Outgoing => PrimaryTransferDirection::Outgoing,
                dto::PrimaryTransferDirection::Incoming => PrimaryTransferDirection::Incoming,
                dto::PrimaryTransferDirection::Unrecognized => {
                    PrimaryTransferDirection::Unrecognized
                }
            },
            status: match t.status {
                dto::PrimaryTransferStatus::Pending => PrimaryTransferStatus::Pending,
                dto::PrimaryTransferStatus::Accepted => PrimaryTransferStatus::Accepted,
                dto::PrimaryTransferStatus::Cancelled => PrimaryTransferStatus::Cancelled,
                dto::PrimaryTransferStatus::Declined => PrimaryTransferStatus::Declined,
                dto::PrimaryTransferStatus::Other { raw } => PrimaryTransferStatus::Other { raw },
            },
            to_device_id: t.to_device_id,
            created_at_unix: unix_secs(t.created_at),
            expires_at_unix: unix_secs(t.expires_at),
        }
    }
}

impl From<dto::PrimaryTransferAccepted> for PrimaryTransferAccepted {
    fn from(a: dto::PrimaryTransferAccepted) -> Self {
        Self {
            transfer_id: a.transfer_id,
            group_id: a.group_id,
            membership_generation: a.membership_generation,
        }
    }
}

// ---- shares ----------------------------------------------------------------------------

/// Where a share's folder is. An ordinary folder needs an OS watcher, which the mobile build
/// does not have: the engine refuses it with `NoChangeSource` before anything is created.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ShareFolder {
    Ordinary {
        local_path: String,
        create_if_missing: bool,
    },
    /// A File Provider folder: the name the OS shows, and the app's retry identity (the same
    /// token with the same request reaches the same folder).
    Provider {
        display_name: String,
        request_token: String,
    },
}

impl From<ShareFolder> for host::ShareFolder {
    fn from(folder: ShareFolder) -> Self {
        match folder {
            ShareFolder::Ordinary { local_path, create_if_missing } => {
                Self::Ordinary { local_path, create_if_missing }
            }
            ShareFolder::Provider { display_name, request_token } => {
                Self::Provider(host::ProviderFolder { display_name, request_token })
            }
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CreateShareRequest {
    pub group_name: String,
    pub folder: ShareFolder,
    /// Keep content in the cloud and fetch it on open.
    pub on_demand: bool,
    /// The user confirmed the risks the folder's preflight found.
    pub acknowledge_risks: bool,
}

/// A folder group of this account that can be joined on this device. Identity only.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct JoinableGroup {
    pub group_id: String,
    pub name: String,
    /// The device the group was created on; `None` for a group created before it was recorded.
    pub created_by_device: Option<GroupCreatorDevice>,
}

/// The device a group was created on.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GroupCreatorDevice {
    pub device_id: String,
    /// `None` once that device was removed.
    pub name: Option<String>,
    pub platform: Option<String>,
}

/// An invite just minted: what the service created, not what was asked.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MintedInvite {
    pub invite_id: String,
    pub code: String,
    /// The link that carries the code.
    pub url: String,
    pub group_id: String,
    /// `owner`, `editor` or `viewer`; any other role the service names comes as it wrote it.
    pub role: String,
    pub expires_at: SystemTime,
    pub requires_approval: bool,
}

impl From<dto::InviteSummary> for MintedInvite {
    fn from(invite: dto::InviteSummary) -> Self {
        Self {
            invite_id: invite.invite_id,
            code: invite.code,
            url: invite.url,
            group_id: invite.group_id,
            role: match invite.role {
                dto::ShareRole::Owner => "owner".into(),
                dto::ShareRole::Editor => "editor".into(),
                dto::ShareRole::Viewer => "viewer".into(),
                dto::ShareRole::Other { raw } => raw,
            },
            expires_at: invite.expires_at,
            requires_approval: invite.requires_approval,
        }
    }
}

impl From<dto::GroupSummary> for JoinableGroup {
    fn from(group: dto::GroupSummary) -> Self {
        Self {
            group_id: group.group_id,
            name: group.name,
            created_by_device: group.created_by_device.map(|d| GroupCreatorDevice {
                device_id: d.device_id,
                name: d.name,
                platform: d.platform,
            }),
        }
    }
}

/// One device of a folder group, for choosing a destination: an upload may only target a group
/// that has a full-replica device (`full_replica`), preferably one that can write and is online.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GroupDevice {
    pub device_id: String,
    pub device_name: String,
    /// The device keeps a full copy (Eager). An unrecognized mode reads as `false`.
    pub full_replica: bool,
    /// The device may author changes (owner or editor). A full replica that is not a writer
    /// does not count as a delivery target.
    pub can_write: bool,
    pub online: bool,
    /// Last seen, seconds since the Unix epoch; `None` when never.
    pub last_seen_unix: Option<u64>,
    /// This device itself.
    pub is_this_device: bool,
    /// The member's role in the group.
    pub role: MemberRole,
    /// How the member relates to the person looking: the same rule as the desktop's member list.
    pub relationship: MemberRelationship,
}

/// What a membership removal did. Show the data-loss warning when `forced_group_ids` is not
/// empty, and a pending-recovery warning when `unknown_scope_operation_id` is set.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MembershipOutcome {
    /// Groups left without a confirmed complete copy by a forced removal.
    pub forced_group_ids: Vec<String>,
    pub unknown_scope_operation_id: Option<String>,
}

impl From<dto::MembershipOutcome> for MembershipOutcome {
    fn from(outcome: dto::MembershipOutcome) -> Self {
        Self {
            forced_group_ids: outcome.forced_group_ids,
            unknown_scope_operation_id: outcome.unknown_scope_operation_id,
        }
    }
}

/// A member's role in a folder group.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MemberRole {
    Owner,
    Editor,
    Viewer,
    /// A role this build does not know; shown as it came.
    Other {
        raw: String,
    },
}

/// How a member relates to the person looking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MemberRelationship {
    /// This device.
    You,
    /// Another device of the person's account.
    YourOtherDevice,
    /// A device of the account that owns the group (its primary owner).
    OwnersDevice,
    /// A device of another account that was invited.
    Invited,
}

impl From<dto::MemberSummary> for GroupDevice {
    fn from(member: dto::MemberSummary) -> Self {
        Self {
            device_id: member.device_id,
            device_name: member.device_name,
            full_replica: member.storage == dto::MemberStorage::FullCopy,
            can_write: matches!(member.role, dto::ShareRole::Owner | dto::ShareRole::Editor),
            online: member.online,
            last_seen_unix: member
                .last_seen
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
            is_this_device: member.relationship == dto::MemberRelationship::You,
            role: match member.role {
                dto::ShareRole::Owner => MemberRole::Owner,
                dto::ShareRole::Editor => MemberRole::Editor,
                dto::ShareRole::Viewer => MemberRole::Viewer,
                dto::ShareRole::Other { raw } => MemberRole::Other { raw },
            },
            relationship: match member.relationship {
                dto::MemberRelationship::You => MemberRelationship::You,
                dto::MemberRelationship::YourOtherDevice => MemberRelationship::YourOtherDevice,
                dto::MemberRelationship::OwnersDevice => MemberRelationship::OwnersDevice,
                dto::MemberRelationship::Invited => MemberRelationship::Invited,
            },
        }
    }
}

/// What happened to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ActivityKind {
    Added,
    Updated,
    Deleted,
    Conflict,
    Restored,
}

/// Whose changes the Activity list shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Enum)]
pub enum ActivityOrigin {
    #[default]
    Any,
    ThisDevice,
    OtherDevices,
}

/// Narrows the Activity list. No kinds = every kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct ActivityFilter {
    pub kinds: Vec<ActivityKind>,
    pub origin: ActivityOrigin,
}

/// One file event of the Activity list.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ActivityEvent {
    /// Paging cursor: pass the page's `next_cursor` as `before_cursor` for the next page.
    pub cursor: i64,
    /// The linked folder's root.
    pub local_path: String,
    /// The file, relative to the root.
    pub path: String,
    pub kind: ActivityKind,
    pub origin_device_id: Option<String>,
    /// Its name, when the account's device list could be read.
    pub origin_device_name: Option<String>,
    /// For a conflict: the device whose version holds the original path now (the other side of the
    /// conflict). `None` for any other event or when it is not known here.
    pub other_origin_device_id: Option<String>,
    /// Its name, when the account's device list could be read.
    pub other_origin_device_name: Option<String>,
    pub is_this_device: bool,
    pub at: Option<SystemTime>,
}

/// One page of the Activity list, newest first.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ActivityPage {
    pub events: Vec<ActivityEvent>,
    /// `before_cursor` of the next page; `None` when this page ended the list.
    pub next_cursor: Option<i64>,
}

impl From<ActivityKind> for dto::ActivityKind {
    fn from(kind: ActivityKind) -> Self {
        match kind {
            ActivityKind::Added => Self::Added,
            ActivityKind::Updated => Self::Updated,
            ActivityKind::Deleted => Self::Deleted,
            ActivityKind::Conflict => Self::Conflict,
            ActivityKind::Restored => Self::Restored,
        }
    }
}

impl From<dto::ActivityKind> for ActivityKind {
    fn from(kind: dto::ActivityKind) -> Self {
        match kind {
            dto::ActivityKind::Added => Self::Added,
            dto::ActivityKind::Updated => Self::Updated,
            dto::ActivityKind::Deleted => Self::Deleted,
            dto::ActivityKind::Conflict => Self::Conflict,
            dto::ActivityKind::Restored => Self::Restored,
        }
    }
}

impl From<ActivityFilter> for dto::ActivityFilter {
    fn from(filter: ActivityFilter) -> Self {
        Self {
            kinds: filter.kinds.into_iter().map(Into::into).collect(),
            origin: match filter.origin {
                ActivityOrigin::Any => dto::ActivityOrigin::Any,
                ActivityOrigin::ThisDevice => dto::ActivityOrigin::ThisDevice,
                ActivityOrigin::OtherDevices => dto::ActivityOrigin::OtherDevices,
            },
        }
    }
}

impl From<dto::ActivityPage> for ActivityPage {
    fn from(page: dto::ActivityPage) -> Self {
        Self {
            events: page
                .events
                .into_iter()
                .map(|e| ActivityEvent {
                    cursor: e.cursor,
                    local_path: e.local_path,
                    path: e.path,
                    kind: e.kind.into(),
                    origin_device_id: e.origin_device_id,
                    origin_device_name: e.origin_device_name,
                    other_origin_device_id: e.other_origin_device_id,
                    other_origin_device_name: e.other_origin_device_name,
                    is_this_device: e.is_this_device,
                    at: e.at,
                })
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// Join a share of this account.
#[derive(Debug, Clone, uniffi::Record)]
pub struct JoinGroupRequest {
    pub group_id: String,
    pub group_name: String,
    pub folder: ShareFolder,
    pub on_demand: bool,
    pub acknowledge_risks: bool,
}

/// Join a share by an invite another account minted.
#[derive(Debug, Clone, uniffi::Record)]
pub struct JoinShareRequest {
    pub invite_code: String,
    pub folder: ShareFolder,
    pub on_demand: bool,
    pub acknowledge_risks: bool,
}

/// What a share command did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ShareOutcome {
    pub operation_id: String,
    pub group_id: String,
    /// The link's identity key: a path, or a provider folder's locator.
    pub link_key: String,
    pub provider_root_id: Option<String>,
    /// The membership waits for the group owner's approval and grants nothing until then.
    pub awaiting_approval: bool,
    /// The folder was already linked to this group: nothing changed.
    pub already_linked: bool,
}

impl From<host::ShareOutcome> for ShareOutcome {
    fn from(outcome: host::ShareOutcome) -> Self {
        Self {
            operation_id: outcome.operation_id,
            group_id: outcome.group_id,
            link_key: outcome.link_key,
            provider_root_id: outcome.provider_root_id,
            awaiting_approval: outcome.awaiting_approval,
            already_linked: outcome.already_linked,
        }
    }
}

// ---- network policy -------------------------------------------------------------------

fn policy_call(
    app: &MobileHost,
    name: &str,
    command: host::Command,
    cancel: &CancelHandle,
    deadline_ms: Option<u64>,
) -> Result<NetworkPolicy, CallFailure> {
    match app.run(command, cancel, deadline_ms)? {
        host::CommandOutput::NetworkPolicy(state) => Ok(state.into()),
        other => Err(unexpected(name, &other)),
    }
}

/// What the OS says the connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NetworkCost {
    /// The host cannot tell; treated as not metered.
    Unknown,
    Unmetered,
    /// Cellular or otherwise metered.
    Metered,
}

impl From<NetworkCost> for host::NetworkCost {
    fn from(cost: NetworkCost) -> Self {
        match cost {
            NetworkCost::Unknown => Self::Unknown,
            NetworkCost::Unmetered => Self::Unmetered,
            NetworkCost::Metered => Self::Metered,
        }
    }
}

impl From<host::NetworkCost> for NetworkCost {
    fn from(cost: host::NetworkCost) -> Self {
        match cost {
            host::NetworkCost::Unknown => Self::Unknown,
            host::NetworkCost::Unmetered => Self::Unmetered,
            host::NetworkCost::Metered => Self::Metered,
        }
    }
}

/// Whether peer traffic may flow on the connection the host reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct NetworkPolicy {
    /// The user's setting: sync even on a metered connection. Off by default.
    pub sync_on_metered: bool,
    /// What the host last reported (`Unknown` until it does, and after an engine restart).
    pub cost: NetworkCost,
    /// Sync with peers is paused right now because the connection is metered.
    pub paused_on_metered: bool,
}

impl From<host::PolicyState> for NetworkPolicy {
    fn from(state: host::PolicyState) -> Self {
        Self {
            sync_on_metered: state.sync_on_metered,
            cost: state.cost.into(),
            paused_on_metered: state.paused_on_metered(),
        }
    }
}

// ---- link lifecycle --------------------------------------------------------------------

/// How long a pause lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PauseFor {
    UntilResumed,
    TwoHours,
    EightHours,
    TwentyFourHours,
}

impl From<PauseFor> for host::PauseFor {
    fn from(duration: PauseFor) -> Self {
        match duration {
            PauseFor::UntilResumed => Self::UntilResumed,
            PauseFor::TwoHours => Self::TwoHours,
            PauseFor::EightHours => Self::EightHours,
            PauseFor::TwentyFourHours => Self::TwentyFourHours,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PauseLinkRequest {
    pub link_key: String,
    pub duration: PauseFor,
    /// Refuse (`GroupMismatch`), changing nothing, unless the link still belongs to this group.
    pub expected_group_id: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ResumeLinkRequest {
    pub link_key: String,
    pub expected_group_id: Option<String>,
}

/// Re-adopt the provider folder of a group that a start over marked as needing action.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ReadoptRequest {
    pub group_id: String,
}

/// What a re-adoption did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ReadoptOutcome {
    pub group_id: String,
    pub link_key: String,
    pub provider_root_id: Option<String>,
    /// The folder is now a full replica (a replacement the service calls unconfirmed waits for
    /// this group).
    pub promoted_to_eager: bool,
}

/// Unlink a folder after the custody checks; `force` skips a refusal and risks data loss.
#[derive(Debug, Clone, uniffi::Record)]
pub struct UnlinkRequest {
    pub link_key: String,
    pub force: bool,
    pub expected_group_id: Option<String>,
}

/// The custody hand-off an unlink committed.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HandoffInfo {
    pub target_device_id: String,
    pub root_digest: Vec<u8>,
    pub membership_generation: i64,
    pub lease_id: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct UnlinkOutcome {
    pub handoff: Option<HandoffInfo>,
}

// ---- status ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OverallState {
    Healthy,
    Attention,
    Degraded,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProductState {
    UpToDate,
    Syncing,
    Waiting,
    NeedsAttention,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AttentionSeverity {
    Info,
    Warning,
    Critical,
}

/// What an attention item is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
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
    Ambiguous,
    OwnershipLost,
    VolumeChanged,
    VolumeUnconfirmed,
    ProviderNotReady,
    ProviderStuck,
    KeptEdits,
    ProviderOrphanDomain,
    UpdateRequired,
    Unrecognized,
}

/// One thing that needs the user's attention.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AttentionItem {
    pub category: AttentionCategory,
    pub severity: AttentionSeverity,
    /// A group id, volume path, device id or error category, by category.
    pub subject: String,
    /// The linked folder a folder-scoped item is about.
    pub folder_local_path: Option<String>,
    /// Stable id of the condition, for the app's string lookup.
    pub key: String,
    /// Stable identity of this condition: the same while the problem holds, never shown.
    pub identity: String,
}

/// One folder's state.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FolderStatus {
    pub local_path: String,
    pub group_id: String,
    pub name: String,
    pub on_demand: bool,
    pub paused: bool,
    pub state: ProductState,
    pub conflict_count: u64,
    pub hydrated_file_count: u64,
    pub placeholder_file_count: u64,
    pub degraded: bool,
    /// The other device the folder's newest recorded change came from, when known here.
    pub last_change_origin_device_id: Option<String>,
    /// Its name, when the account's device list could be read.
    pub last_change_origin_device_name: Option<String>,
}

/// The engine's status.
#[derive(Debug, Clone, uniffi::Record)]
pub struct StatusSummary {
    pub overall: OverallState,
    /// All folders together.
    pub product_state: ProductState,
    pub attention: Vec<AttentionItem>,
    pub folders: Vec<FolderStatus>,
    pub account: AccountStatus,
}

fn product_state(state: dto::ProductState) -> ProductState {
    match state {
        dto::ProductState::UpToDate => ProductState::UpToDate,
        dto::ProductState::Syncing => ProductState::Syncing,
        dto::ProductState::Waiting => ProductState::Waiting,
        dto::ProductState::NeedsAttention => ProductState::NeedsAttention,
        dto::ProductState::Paused => ProductState::Paused,
    }
}

fn category(category: dto::AttentionCategory) -> AttentionCategory {
    use dto::AttentionCategory as C;
    match category {
        C::Degraded => AttentionCategory::Degraded,
        C::DurabilityAtRisk => AttentionCategory::DurabilityAtRisk,
        C::DurabilityUnknown => AttentionCategory::DurabilityUnknown,
        C::FetchUnavailable => AttentionCategory::FetchUnavailable,
        C::FetchAvailabilityUnknown => AttentionCategory::FetchAvailabilityUnknown,
        C::Conflict => AttentionCategory::Conflict,
        C::Held => AttentionCategory::Held,
        C::StrandedDirectory => AttentionCategory::StrandedDirectory,
        C::LowDiskCritical => AttentionCategory::LowDiskCritical,
        C::LowDisk => AttentionCategory::LowDisk,
        C::PeerDisconnected => AttentionCategory::PeerDisconnected,
        C::RecentError => AttentionCategory::RecentError,
        C::UpdateFailed => AttentionCategory::UpdateFailed,
        C::Ambiguous => AttentionCategory::Ambiguous,
        C::OwnershipLost => AttentionCategory::OwnershipLost,
        C::VolumeChanged => AttentionCategory::VolumeChanged,
        C::VolumeUnconfirmed => AttentionCategory::VolumeUnconfirmed,
        C::ProviderNotReady => AttentionCategory::ProviderNotReady,
        C::ProviderStuck => AttentionCategory::ProviderStuck,
        C::KeptEdits => AttentionCategory::KeptEdits,
        C::ProviderOrphanDomain => AttentionCategory::ProviderOrphanDomain,
        C::UpdateRequired => AttentionCategory::UpdateRequired,
        C::Unrecognized => AttentionCategory::Unrecognized,
    }
}

impl From<dto::StatusSnapshot> for StatusSummary {
    fn from(snapshot: dto::StatusSnapshot) -> Self {
        Self {
            overall: match snapshot.overall {
                dto::OverallState::Healthy => OverallState::Healthy,
                dto::OverallState::Attention => OverallState::Attention,
                dto::OverallState::Degraded => OverallState::Degraded,
                dto::OverallState::Unknown => OverallState::Unknown,
            },
            product_state: product_state(snapshot.product.state),
            attention: snapshot
                .attention_reasons
                .into_iter()
                .map(|reason| AttentionItem {
                    category: category(reason.category),
                    severity: match reason.severity {
                        dto::AttentionSeverity::Info => AttentionSeverity::Info,
                        dto::AttentionSeverity::Warning => AttentionSeverity::Warning,
                        dto::AttentionSeverity::Critical => AttentionSeverity::Critical,
                    },
                    subject: reason.subject,
                    folder_local_path: reason.folder_local_path,
                    key: reason.key,
                    identity: reason.identity,
                })
                .collect(),
            folders: snapshot
                .folders
                .into_iter()
                .map(|folder| FolderStatus {
                    local_path: folder.local_path,
                    group_id: folder.group_id,
                    name: folder.name,
                    on_demand: matches!(folder.mode, dto::FolderMode::OnDemand),
                    paused: folder.paused,
                    state: product_state(folder.product.state),
                    conflict_count: folder.conflict_count,
                    hydrated_file_count: folder.hydrated_file_count,
                    placeholder_file_count: folder.placeholder_file_count,
                    degraded: folder.degraded,
                    last_change_origin_device_id: folder.last_change_origin_device_id,
                    last_change_origin_device_name: folder.last_change_origin_device_name,
                })
                .collect(),
            account: snapshot.account.into(),
        }
    }
}

/// How one connectivity check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DoctorStatus {
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DoctorCheck {
    pub name: String,
    pub status: DoctorStatus,
    /// What was found, and the fix when there is one.
    pub detail: String,
}

// ---- preserved items and space management ------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PreservedKind {
    /// A version of another device that the replacing state does not contain.
    RemoteOnly,
    BeyondClosureCutoff,
    /// An edit made during a rebootstrap's freeze to a path whose original was removed.
    LateEdit,
    /// Own changes of this device that were not replayed.
    OwnUnit,
}

/// Whether a preserved version's bytes are on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PreservedContent {
    Complete,
    Unavailable,
    RecordUnavailable,
    /// An own unit has no single version content.
    NotApplicable,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PreservedItem {
    pub kind: PreservedKind,
    pub group_id: String,
    /// The group is no longer linked on this device.
    pub group_removed: bool,
    pub item_id: String,
    pub path: String,
    pub paths: Vec<String>,
    pub content: PreservedContent,
    pub size: u64,
    pub blocks_held: u32,
    pub blocks_total: u32,
    pub recovery_id: String,
    pub originals_quarantined: bool,
}

impl From<host::PreservedItem> for PreservedItem {
    fn from(item: host::PreservedItem) -> Self {
        Self {
            kind: match item.kind {
                host::PreservedKind::RemoteOnly => PreservedKind::RemoteOnly,
                host::PreservedKind::BeyondClosureCutoff => PreservedKind::BeyondClosureCutoff,
                host::PreservedKind::LateEdit => PreservedKind::LateEdit,
                host::PreservedKind::OwnUnit => PreservedKind::OwnUnit,
            },
            group_id: item.group_id,
            group_removed: item.group_removed,
            item_id: item.item_id,
            path: item.path,
            paths: item.paths,
            content: match item.content.as_str() {
                "complete" => PreservedContent::Complete,
                "record_unavailable" => PreservedContent::RecordUnavailable,
                "" => PreservedContent::NotApplicable,
                // Unknown text is never taken for complete content.
                _ => PreservedContent::Unavailable,
            },
            size: item.size,
            blocks_held: item.blocks_held,
            blocks_total: item.blocks_total,
            recovery_id: item.recovery_id,
            originals_quarantined: item.originals_quarantined,
        }
    }
}

/// One preserved item of a group.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PreservedRef {
    pub group_id: String,
    pub item_id: String,
}

impl From<PreservedRef> for host::PreservedRef {
    fn from(item: PreservedRef) -> Self {
        Self { group_id: item.group_id, item_id: item.item_id }
    }
}

// ---- account ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SignInState {
    SignedOut,
    SignedIn,
    /// A credential store exists and cannot be used.
    CredentialStoreUnusable {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountStatus {
    pub sign_in: SignInState,
    pub client_id: Option<String>,
    pub this_device_id: Option<String>,
    pub device_registered: bool,
    /// A prefill for the device-name field.
    pub default_device_name: String,
    /// `None` when the engine did not say.
    pub has_linked_folders: Option<bool>,
    /// A start over was begun and is not finished: sign in if signed out, then call
    /// `start_over` again (it registers this device as a new one).
    pub start_over_pending: bool,
    /// The signed-in account's email; `None` when signed out, not read yet, or not given.
    pub email: Option<String>,
    /// `"google"` or `"apple"`: which provider the account signs in with; `None` when unknown.
    pub sign_in_provider: Option<String>,
    /// The name Apple delivered at the first sign-in; `None` otherwise.
    pub display_name: Option<String>,
}

impl From<dto::AccountStatus> for AccountStatus {
    fn from(status: dto::AccountStatus) -> Self {
        Self {
            sign_in: match status.sign_in {
                dto::SignInState::SignedOut => SignInState::SignedOut,
                dto::SignInState::SignedIn => SignInState::SignedIn,
                dto::SignInState::CredentialStoreUnusable { message } => {
                    SignInState::CredentialStoreUnusable { message }
                }
            },
            client_id: status.client_id,
            this_device_id: status.this_device_id,
            device_registered: status.device_registered,
            default_device_name: status.default_device_name,
            has_linked_folders: status.has_linked_folders,
            start_over_pending: status.start_over_pending,
            email: status.email,
            sign_in_provider: status.sign_in_provider,
            display_name: status.display_name,
        }
    }
}

/// Which page a sign-in step asks the person to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum BrowserPurpose {
    ApproveDevice,
    SignIn,
}

/// The origins a sign-in link may be opened on (https only), e.g. `https://auth.example.test:8443`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignInOrigins {
    /// `BrowserPurpose::ApproveDevice`: the coordination service.
    pub approve_device: Option<String>,
    /// `BrowserPurpose::SignIn` and the `ShowDeviceCode` verification page: the Authorization
    /// Server. It is not the `approve_device` host when the settings name a separate one.
    pub authorization: Option<String>,
}

/// One step of a sign-in. The last one is `SignedIn`, `Failed` or `Cancelled`.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum SignInEvent {
    Enrolling,
    OpenBrowser {
        url: String,
        purpose: BrowserPurpose,
    },
    WaitingForApproval {
        expires_in_ms: u64,
    },
    WaitingForAuthorization,
    /// The page to open on another screen and the code to enter there.
    ShowDeviceCode {
        verification_uri: String,
        user_code: String,
    },
    SignedIn {
        account: AccountStatus,
    },
    Failed {
        error: AccountError,
    },
    Cancelled,
}

impl From<dto::LoginEvent> for SignInEvent {
    fn from(event: dto::LoginEvent) -> Self {
        match event {
            dto::LoginEvent::Enrolling => Self::Enrolling,
            dto::LoginEvent::OpenBrowser { url, purpose } => Self::OpenBrowser {
                url,
                purpose: match purpose {
                    dto::BrowserPurpose::ApproveDevice => BrowserPurpose::ApproveDevice,
                    dto::BrowserPurpose::SignIn => BrowserPurpose::SignIn,
                },
            },
            dto::LoginEvent::WaitingForApproval { expires_in } => Self::WaitingForApproval {
                expires_in_ms: u64::try_from(expires_in.as_millis()).unwrap_or(u64::MAX),
            },
            dto::LoginEvent::WaitingForAuthorization => Self::WaitingForAuthorization,
            dto::LoginEvent::ShowDeviceCode { verification_uri, user_code } => {
                Self::ShowDeviceCode { verification_uri, user_code }
            }
            dto::LoginEvent::SignedIn { account } => Self::SignedIn { account: account.into() },
            dto::LoginEvent::Failed { error } => Self::Failed { error: error.into() },
            dto::LoginEvent::Cancelled => Self::Cancelled,
        }
    }
}

/// What cancelling the engine's current sign-in (without its id) came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SignInCancellation {
    /// The engine held no sign-in: nothing was running, nothing to do.
    NothingToCancel,
    /// This sign-in has stopped and will store nothing; it ends as `Cancelled`, or keeps the
    /// `Failed` it already ended with (its overall timeout). A repeated cancel answers the same.
    Stopped { id: u64 },
    /// This sign-in's flow had completed before the cancel, so its credential may be stored:
    /// read its last step with `poll_sign_in` (`SignedIn` or `Failed`).
    AlreadyFinished { id: u64 },
}

impl From<host::SignInCancellation> for SignInCancellation {
    fn from(cancellation: host::SignInCancellation) -> Self {
        match cancellation {
            host::SignInCancellation::NothingToCancel => Self::NothingToCancel,
            host::SignInCancellation::Stopped(id) => Self::Stopped { id: id.0 },
            host::SignInCancellation::AlreadyFinished(id) => Self::AlreadyFinished { id: id.0 },
        }
    }
}

/// One numbered step of a sign-in.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SignInStep {
    /// Pass it as `after` to get the step that follows.
    pub seq: u64,
    pub event: SignInEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SignOutKind {
    Revoked { grants_revoked: u32 },
    AlreadyRevoked,
    ConfirmedRevokedAfterRejection,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignOutOutcome {
    pub kind: SignOutKind,
    /// Set when the device key's copy in the OS credential store could not be removed.
    pub key_cleanup_warning: Option<String>,
}

impl From<dto::SignOutOutcome> for SignOutOutcome {
    fn from(outcome: dto::SignOutOutcome) -> Self {
        Self {
            kind: match outcome.kind {
                dto::SignOutKind::Revoked { grants_revoked } => {
                    SignOutKind::Revoked { grants_revoked }
                }
                dto::SignOutKind::AlreadyRevoked => SignOutKind::AlreadyRevoked,
                dto::SignOutKind::ConfirmedRevokedAfterRejection => {
                    SignOutKind::ConfirmedRevokedAfterRejection
                }
            },
            key_cleanup_warning: outcome.key_cleanup_warning,
        }
    }
}

/// How far `start_over` got.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum StartOverProgress {
    /// The old identity is retired and this installation is signed out. Sign in
    /// (`begin_sign_in`, `poll_sign_in`), then call `start_over` again.
    SignInRequired { retired_device_id: String },
    /// The device is registered as a new one and every linked folder was handled. Restart the
    /// engine (`suspend`, `resume`) so it opens the database as the new device. When
    /// `report.complete` is false, call `start_over` again after the restart.
    Finished { report: StartOverReport },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct StartOverReport {
    /// The device that was retired: its signing key and device record were moved to
    /// `retired-devices/<id>/` in the state directory, and the device stays on the account
    /// signed out (remove it from the account's device list if it is no longer wanted).
    pub retired_device_id: String,
    pub new_device_id: String,
    /// Folders joined again. Always empty on mobile: see `not_rejoined`.
    pub rejoined: Vec<String>,
    /// Every linked folder, on mobile: it stops syncing and is reported as needing the person
    /// (`not joined to its folder group`). Its files are kept. Today the only way back is an
    /// invite to the group (it creates a new provider folder) or unlinking it; there is no
    /// re-link of the existing folder yet. While every folder is marked, a replacement the
    /// service called unconfirmed cannot be confirmed (it needs the group complete here).
    pub not_rejoined: Vec<NotRejoined>,
    /// Nothing is left to retry. When false, call `start_over` again.
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NotRejoined {
    /// The folder's identity key (a locator for a provider folder).
    pub local_path: String,
    pub group_id: String,
    /// The engine's English sentence, for the log only: never shown. Word `reason`.
    pub message: String,
    pub reason: RejoinReason,
}

/// Why a linked folder was not joined to its group again after a start over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RejoinReason {
    /// A provider folder: it is joined again from the provider folder list.
    ProviderFolder,
    /// This host does not join a folder again by itself: accept an invite to its group again,
    /// or unlink the folder.
    HostCannotRejoin,
    /// This account does not own the folder group: accept a new invite to it.
    NotGroupOwner,
    /// Joining the group again failed; start over again retries it.
    JoinFailed,
}

impl From<dto::RejoinReason> for RejoinReason {
    fn from(reason: dto::RejoinReason) -> Self {
        match reason {
            dto::RejoinReason::ProviderFolder => Self::ProviderFolder,
            dto::RejoinReason::HostCannotRejoin => Self::HostCannotRejoin,
            dto::RejoinReason::NotGroupOwner => Self::NotGroupOwner,
            dto::RejoinReason::JoinFailed => Self::JoinFailed,
        }
    }
}

impl From<dto::StartOverProgress> for StartOverProgress {
    fn from(progress: dto::StartOverProgress) -> Self {
        match progress {
            dto::StartOverProgress::SignInRequired { retired_device_id } => {
                Self::SignInRequired { retired_device_id }
            }
            dto::StartOverProgress::Finished { report } => Self::Finished {
                report: StartOverReport {
                    retired_device_id: report.retired_device_id,
                    new_device_id: report.new_device_id,
                    rejoined: report.rejoined,
                    not_rejoined: report
                        .not_rejoined
                        .into_iter()
                        .map(|f| NotRejoined {
                            local_path: f.local_path,
                            group_id: f.group_id,
                            message: f.message,
                            reason: f.reason.into(),
                        })
                        .collect(),
                    complete: report.complete,
                },
            },
        }
    }
}

/// A group that deleting the account affects.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeletionImpactGroup {
    pub group_id: String,
    pub name: String,
    /// Devices of other accounts in a group this account owns; `None` for a foreign group.
    pub guest_devices: Option<u32>,
}

/// What deleting the account does to other people's access and data custody.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeletionImpact {
    /// Groups owned by someone else where this account's devices are the only full replicas.
    pub foreign_groups_at_risk: Vec<DeletionImpactGroup>,
    /// Groups this account owns that other accounts' devices belong to.
    pub owned_groups_with_guests: Vec<DeletionImpactGroup>,
}

impl From<dto::AccountDeletionImpact> for DeletionImpact {
    fn from(impact: dto::AccountDeletionImpact) -> Self {
        let groups = |groups: Vec<dto::AccountDeletionImpactGroup>| {
            groups
                .into_iter()
                .map(|g| DeletionImpactGroup {
                    group_id: g.group_id,
                    name: g.name,
                    guest_devices: g.guest_devices,
                })
                .collect()
        };
        Self {
            foreign_groups_at_risk: groups(impact.foreign_groups_at_risk),
            owned_groups_with_guests: groups(impact.owned_groups_with_guests),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DeletionState {
    Active,
    Requested,
    Grace,
    /// A state this build does not know.
    Other {
        raw: String,
    },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DeletionStatus {
    pub state: DeletionState,
    /// Seconds since the Unix epoch when the grace period ends.
    pub grace_expires_at_unix: Option<u64>,
    pub remaining_ms: Option<u64>,
}

impl From<dto::AccountDeletionStatus> for DeletionStatus {
    fn from(status: dto::AccountDeletionStatus) -> Self {
        Self {
            state: match status.state {
                dto::AccountDeletionState::Active => DeletionState::Active,
                dto::AccountDeletionState::Requested => DeletionState::Requested,
                dto::AccountDeletionState::Grace => DeletionState::Grace,
                dto::AccountDeletionState::Other { raw } => DeletionState::Other { raw },
            },
            grace_expires_at_unix: status
                .grace_expires_at
                .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
            remaining_ms: status
                .remaining
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        }
    }
}

// ---- the methods -----------------------------------------------------------------------

impl MobileHost {
    pub(crate) fn run(
        &self,
        command: host::Command,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<host::CommandOutput, CallFailure> {
        Ok(self.inner.execute(command, &options(cancel, deadline_ms))?)
    }

    fn transfer_call(
        &self,
        what: &'static str,
        command: host::AccountCommand,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<PrimaryTransfer, CallFailure> {
        match self.account(command, cancel, deadline_ms)? {
            host::CommandOutput::PrimaryTransfer(transfer) => Ok(transfer.into()),
            other => Err(unexpected(what, &other)),
        }
    }

    fn account(
        &self,
        command: host::AccountCommand,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<host::CommandOutput, CallFailure> {
        self.run(host::Command::Account(command), cancel, deadline_ms)
    }
}

/// Every command takes a cancel handle (one per call) and an optional deadline. A read-only
/// command is aborted when cancelled; a command that changes state keeps running and the
/// failure says so (`still_running`): read the state to find the outcome.
#[uniffi::export]
impl MobileHost {
    /// Creates a share and links a folder to it.
    ///
    /// # Errors
    /// `NoChangeSource` for an ordinary folder; `Refused` with the enrollment's typed code;
    /// the other [`CallFailure`] cases.
    pub fn create_share(
        &self,
        request: CreateShareRequest,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<ShareOutcome, CallFailure> {
        let command = host::Command::CreateShare(host::CreateShare {
            group_name: request.group_name,
            folder: request.folder.into(),
            on_demand: request.on_demand,
            acknowledge_risks: request.acknowledge_risks,
        });
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Shared(outcome) => Ok(outcome.into()),
            other => Err(unexpected("create_share", &other)),
        }
    }

    /// Joins a share of this account and links a folder to it.
    ///
    /// # Errors
    /// As `create_share`.
    pub fn join_group(
        &self,
        request: JoinGroupRequest,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<ShareOutcome, CallFailure> {
        let command = host::Command::JoinGroup(host::JoinGroup {
            group_id: request.group_id,
            group_name: request.group_name,
            folder: request.folder.into(),
            on_demand: request.on_demand,
            acknowledge_risks: request.acknowledge_risks,
        });
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Shared(outcome) => Ok(outcome.into()),
            other => Err(unexpected("join_group", &other)),
        }
    }

    /// Takes a device's access to a folder group away (the caller must be the group's owner or
    /// an owner-role member). Without `force` it is refused `Refused` with `ReplicaNotReady`,
    /// nothing changed, when the group would be left without another confirmed complete copy;
    /// `force` is a data-loss override that the person confirms, never a retry convenience.
    /// `forced_group_ids` of the answer names groups left unprotected.
    ///
    /// # Errors
    /// `Refused` (`ReplicaNotReady`, `CoordinationRejected`, `TermsConsentRequired`,
    /// `RecoveryPending`, ...) and `Account` with `NotSignedIn`; the other [`CallFailure`] cases.
    pub fn revoke_member(
        &self,
        group_id: String,
        device_id: String,
        force: bool,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<MembershipOutcome, CallFailure> {
        let command = host::Command::RevokeMember { group_id, device_id, force };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::MemberRevoked(outcome) => Ok(outcome.into()),
            other => Err(unexpected("revoke_member", &other)),
        }
    }

    /// The folder groups of this account that can be joined on this device. Read-only; join
    /// one with `join_group`.
    ///
    /// # Errors
    /// `Account` with `NotSignedIn`; the other [`CallFailure`] cases.
    pub fn list_joinable_groups(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<JoinableGroup>, CallFailure> {
        match self.account(host::AccountCommand::ListJoinableGroups, cancel, deadline_ms)? {
            host::CommandOutput::JoinableGroups(groups) => {
                Ok(groups.into_iter().map(Into::into).collect())
            }
            other => Err(unexpected("list_joinable_groups", &other)),
        }
    }

    /// The devices of one folder group: name, whether each keeps a full replica, whether it can
    /// write, online. For the destination picker: show only groups where some device has
    /// `full_replica` (camera uploads and uploads never target a group without one). Read-only;
    /// needs a sign-in.
    ///
    /// # Errors
    /// `Account` with `NotSignedIn`; the other [`CallFailure`] cases.
    pub fn list_group_devices(
        &self,
        group_id: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<GroupDevice>, CallFailure> {
        match self.account(
            host::AccountCommand::ListGroupDevices { group_id },
            cancel,
            deadline_ms,
        )? {
            host::CommandOutput::GroupDevices(devices) => {
                Ok(devices.into_iter().map(Into::into).collect())
            }
            other => Err(unexpected("list_group_devices", &other)),
        }
    }

    /// Offers the primary ownership of `group_id` (a folder this account owns) to the account
    /// that owns `target_device_id`, an active member device of it. The target must accept; an
    /// offer lasts seven days and a folder has at most one pending offer. Retries and restarts
    /// replay the same offer (the operation id is kept on disk). Needs the service and a sign-in.
    ///
    /// # Errors
    /// `Account` with a `PrimaryTransfer*` kind for the service's typed refusals, `NotSignedIn`,
    /// `Network`; the other [`CallFailure`] cases.
    pub fn offer_primary_transfer(
        &self,
        group_id: String,
        target_device_id: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<PrimaryTransfer, CallFailure> {
        self.transfer_call(
            "offer_primary_transfer",
            host::AccountCommand::OfferPrimaryTransfer { group_id, target_device_id },
            cancel,
            deadline_ms,
        )
    }

    /// Withdraws a pending offer this account made.
    ///
    /// # Errors
    /// As `offer_primary_transfer`.
    pub fn cancel_primary_transfer(
        &self,
        group_id: String,
        transfer_id: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<PrimaryTransfer, CallFailure> {
        self.transfer_call(
            "cancel_primary_transfer",
            host::AccountCommand::CancelPrimaryTransfer { group_id, transfer_id },
            cancel,
            deadline_ms,
        )
    }

    /// Turns down an offer made to this account.
    ///
    /// # Errors
    /// As `offer_primary_transfer`.
    pub fn decline_primary_transfer(
        &self,
        group_id: String,
        transfer_id: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<PrimaryTransfer, CallFailure> {
        self.transfer_call(
            "decline_primary_transfer",
            host::AccountCommand::DeclinePrimaryTransfer { group_id, transfer_id },
            cancel,
            deadline_ms,
        )
    }

    /// Accepts an offer made to this account (any of its devices may): the folder moves onto
    /// this account's quota and this account becomes its primary owner.
    ///
    /// # Errors
    /// As `offer_primary_transfer`.
    pub fn accept_primary_transfer(
        &self,
        group_id: String,
        transfer_id: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<PrimaryTransferAccepted, CallFailure> {
        match self.account(
            host::AccountCommand::AcceptPrimaryTransfer { group_id, transfer_id },
            cancel,
            deadline_ms,
        )? {
            host::CommandOutput::PrimaryTransferAccepted(accepted) => Ok(accepted.into()),
            other => Err(unexpected("accept_primary_transfer", &other)),
        }
    }

    /// The pending, unexpired ownership offers this account made or received. Read-only; needs
    /// a sign-in.
    ///
    /// # Errors
    /// `Account` with `NotSignedIn`; the other [`CallFailure`] cases.
    pub fn list_primary_transfers(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<PrimaryTransfer>, CallFailure> {
        match self.account(host::AccountCommand::ListPrimaryTransfers, cancel, deadline_ms)? {
            host::CommandOutput::PrimaryTransfers(transfers) => {
                Ok(transfers.into_iter().map(Into::into).collect())
            }
            other => Err(unexpected("list_primary_transfers", &other)),
        }
    }

    /// Recent file events across every linked folder, newest first: the Activity list.
    /// `limit` is clamped to 1..=500; `before_cursor` is the previous page's `next_cursor`
    /// (`None`: the newest). Read-only. Needs no sign-in: signed out, events carry device ids
    /// but no names.
    ///
    /// # Errors
    /// The [`CallFailure`] cases.
    pub fn list_activity(
        &self,
        limit: u32,
        before_cursor: Option<i64>,
        filter: Option<ActivityFilter>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<ActivityPage, CallFailure> {
        let command =
            host::Command::ListActivity { limit, before_cursor, filter: filter.map(Into::into) };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Activity(page) => Ok(page.into()),
            other => Err(unexpected("list_activity", &other)),
        }
    }

    /// Joins a share by invite.
    ///
    /// # Errors
    /// As `create_share`, with `Refused` codes `InviteExpired` and `InviteAlreadyUsed`.
    pub fn join_share(
        &self,
        request: JoinShareRequest,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<ShareOutcome, CallFailure> {
        let command = host::Command::JoinShare(host::JoinShare {
            invite_code: request.invite_code,
            folder: request.folder.into(),
            on_demand: request.on_demand,
            acknowledge_risks: request.acknowledge_risks,
        });
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Shared(outcome) => Ok(outcome.into()),
            other => Err(unexpected("join_share", &other)),
        }
    }

    /// Mints a one-use invite to a folder group. `role` is `viewer`, `editor` or `owner`; `None`
    /// and a `None` lifetime take the service's defaults.
    ///
    /// # Errors
    /// `Refused` with `TermsConsentRequired` when the terms must be accepted first, or
    /// `CoordinationRejected`; the other [`CallFailure`] cases.
    pub fn mint_invite(
        &self,
        group_id: String,
        role: Option<String>,
        ttl_secs: Option<u64>,
        requires_approval: bool,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<MintedInvite, CallFailure> {
        let command = host::Command::MintInvite { group_id, role, ttl_secs, requires_approval };
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Invite(invite) => Ok(invite.into()),
            other => Err(unexpected("mint_invite", &other)),
        }
    }

    /// Pauses a linked folder.
    ///
    /// # Errors
    /// `Refused` with `GroupMismatch` when the expected group no longer owns the link.
    pub fn pause_link(
        &self,
        request: PauseLinkRequest,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        let command = host::Command::PauseLink(host::PauseLink {
            link_key: request.link_key,
            duration: request.duration.into(),
            expected_group_id: request.expected_group_id,
        });
        self.done("pause_link", command, cancel, deadline_ms)
    }

    /// Resumes a linked folder.
    ///
    /// # Errors
    /// As `pause_link`.
    pub fn resume_link(
        &self,
        request: ResumeLinkRequest,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        let command = host::Command::ResumeLink(host::ResumeLink {
            link_key: request.link_key,
            expected_group_id: request.expected_group_id,
        });
        self.done("resume_link", command, cancel, deadline_ms)
    }

    /// Re-adopts the folder a start over marked as needing action into its group: it syncs
    /// again, keeping its files; on-demand while a replacement waits for confirmation, it is
    /// made a full replica. Call after the engine restarted following the start over.
    ///
    /// # Errors
    /// `ReadoptRefused` (`GroupUnknown`, `NotMarked`, `NotAProviderFolder`, `RestartRequired`),
    /// or `Refused` with the codes a join has (the group is gone or not accessible).
    pub fn readopt_marked_folder(
        &self,
        request: ReadoptRequest,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<ReadoptOutcome, CallFailure> {
        let command = host::Command::ReadoptMarkedFolder(host::ReadoptMarkedFolder {
            group_id: request.group_id,
        });
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Readopted(outcome) => Ok(ReadoptOutcome {
                group_id: outcome.group_id,
                link_key: outcome.link_key,
                provider_root_id: outcome.provider_root_id,
                promoted_to_eager: outcome.promoted_to_eager,
            }),
            other => Err(unexpected("readopt_marked_folder", &other)),
        }
    }

    /// Unlinks a folder after the custody checks.
    ///
    /// # Errors
    /// `Refused` with `NotProtected` unless forced, or `GroupMismatch`.
    pub fn unlink_folder(
        &self,
        request: UnlinkRequest,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<UnlinkOutcome, CallFailure> {
        let command = host::Command::Unlink(host::UnlinkFolder {
            link_key: request.link_key,
            force: request.force,
            expected_group_id: request.expected_group_id,
        });
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Unlinked(outcome) => Ok(UnlinkOutcome {
                handoff: outcome.handoff.map(|h| HandoffInfo {
                    target_device_id: h.target_device_id,
                    root_digest: h.root_digest.to_vec(),
                    membership_generation: h.membership_generation,
                    lease_id: h.lease_id,
                }),
            }),
            other => Err(unexpected("unlink_folder", &other)),
        }
    }

    /// The engine's status. Read-only.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn status(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<StatusSummary, CallFailure> {
        match self.run(host::Command::Status, cancel, deadline_ms)? {
            host::CommandOutput::Status(snapshot) => Ok((*snapshot).into()),
            other => Err(unexpected("status", &other)),
        }
    }

    /// The connectivity doctor's rows. Read-only.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn doctor(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<DoctorCheck>, CallFailure> {
        match self.run(host::Command::Doctor, cancel, deadline_ms)? {
            host::CommandOutput::Doctor(rows) => Ok(rows
                .into_iter()
                .map(|row| DoctorCheck {
                    name: row.name,
                    status: match row.status {
                        host::DoctorStatus::Ok => DoctorStatus::Ok,
                        host::DoctorStatus::Warn => DoctorStatus::Warn,
                        host::DoctorStatus::Error => DoctorStatus::Error,
                    },
                    detail: row.detail,
                })
                .collect()),
            other => Err(unexpected("doctor", &other)),
        }
    }

    /// What a rebootstrap set aside. Read-only.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn preserved_items(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<Vec<PreservedItem>, CallFailure> {
        match self.run(host::Command::ListPreserved, cancel, deadline_ms)? {
            host::CommandOutput::Preserved(items) => {
                Ok(items.into_iter().map(Into::into).collect())
            }
            other => Err(unexpected("preserved_items", &other)),
        }
    }

    /// Restores a preserved version as one ordinary new write; the item stays.
    ///
    /// # Errors
    /// `PreservedRefused` for the item's own refusals.
    pub fn restore_preserved(
        &self,
        item: PreservedRef,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        self.done(
            "restore_preserved",
            host::Command::RestorePreserved(item.into()),
            cancel,
            deadline_ms,
        )
    }

    /// Deletes a preserved item: the only operation that does.
    ///
    /// # Errors
    /// As `restore_preserved`.
    pub fn discard_preserved(
        &self,
        item: PreservedRef,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        self.done(
            "discard_preserved",
            host::Command::DiscardPreserved(item.into()),
            cancel,
            deadline_ms,
        )
    }

    /// Asks the engine to try a preserved item again; the item stays until it is restored or
    /// discarded.
    ///
    /// # Errors
    /// As `restore_preserved`.
    pub fn retry_preserved(
        &self,
        item: PreservedRef,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        self.done(
            "retry_preserved",
            host::Command::RetryPreserved(item.into()),
            cancel,
            deadline_ms,
        )
    }

    /// Whether automatic space management is on. Read-only; Off when never set.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn space_management(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<bool, CallFailure> {
        match self.run(host::Command::SpaceManagement, cancel, deadline_ms)? {
            host::CommandOutput::SpaceManagement(setting) => Ok(setting.enabled),
            other => Err(unexpected("space_management", &other)),
        }
    }

    /// Turns automatic space management on or off; returns the setting now stored.
    ///
    /// # Errors
    /// `Failed` when it cannot be saved.
    pub fn set_space_management(
        &self,
        enabled: bool,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<bool, CallFailure> {
        match self.run(host::Command::SetSpaceManagement { enabled }, cancel, deadline_ms)? {
            host::CommandOutput::SpaceManagement(setting) => Ok(setting.enabled),
            other => Err(unexpected("set_space_management", &other)),
        }
    }

    /// The metered-network policy. Read-only.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn network_policy(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<NetworkPolicy, CallFailure> {
        policy_call(self, "network_policy", host::Command::NetworkPolicy, cancel, deadline_ms)
    }

    /// Allows (`true`) or pauses (`false`, the default) sync on a metered connection; returns
    /// the policy now in force.
    ///
    /// # Errors
    /// `Failed` when it cannot be saved.
    pub fn set_sync_on_metered(
        &self,
        enabled: bool,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<NetworkPolicy, CallFailure> {
        policy_call(
            self,
            "set_sync_on_metered",
            host::Command::SetSyncOnMetered { enabled },
            cancel,
            deadline_ms,
        )
    }

    /// Tells the engine what the connection is. Call it when the engine starts and whenever the
    /// OS reports a change (iOS: the path is expensive or constrained, i.e. cellular; the engine
    /// does not guess). While the connection is metered and sync on metered is off, no peer is
    /// dialled or served.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn report_network_cost(
        &self,
        cost: NetworkCost,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<NetworkPolicy, CallFailure> {
        policy_call(
            self,
            "report_network_cost",
            host::Command::ReportNetworkCost { cost: cost.into() },
            cancel,
            deadline_ms,
        )
    }

    /// Sign-in, registration and linked-folder state. Read-only.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn account_status(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<AccountStatus, CallFailure> {
        match self.account(host::AccountCommand::Status, cancel, deadline_ms)? {
            host::CommandOutput::Account(status) => Ok((*status).into()),
            other => Err(unexpected("account_status", &other)),
        }
    }

    /// Starts a device-code sign-in and returns its id, ending the one before. Poll it with
    /// `poll_sign_in`; the engine's restart ends it.
    ///
    /// `reauthenticate`: the step-up of the signed-in installation, for an action refused with
    /// `ReauthenticationRequired` (it keeps this installation's identity and device; the caller
    /// repeats the refused action once the sign-in ends as `SignedIn`). Otherwise an ordinary
    /// sign-in.
    ///
    /// # Errors
    /// `Account` with `PermissionDenied` when an ordinary sign-in starts while signed in, and
    /// with `NotSignedIn` when a step-up starts while signed out.
    pub fn begin_sign_in(
        &self,
        reauthenticate: bool,
        overall_timeout_ms: Option<u64>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<u64, CallFailure> {
        let begin = host::BeginSignIn {
            overall_timeout: overall_timeout_ms.map(Duration::from_millis),
            reauthenticate,
        };
        match self.account(host::AccountCommand::BeginSignIn(begin), cancel, deadline_ms)? {
            host::CommandOutput::SignInBegun(id) => Ok(id.0),
            other => Err(unexpected("begin_sign_in", &other)),
        }
    }

    /// Starts a sign-in with a pairing code from the account's web page ("add this device with a
    /// code" / QR scan) and returns its id, ending the one before. No browser is involved. Poll
    /// it with `poll_sign_in`: the events are `Enrolling`, then `SignedIn`; a failure is the
    /// poll's `Failed` with the typed error (below).
    ///
    /// `pairing_code` is what the person typed (any case, hyphens optional) or what the QR
    /// scan read (the QR carries a link; it is accepted as it is). The code is a secret for
    /// ten minutes: never log it.
    ///
    /// # Errors
    /// `Account` with `InvalidInput` for text that cannot be a code (nothing is sent), and
    /// `PermissionDenied` while signed in. In the poll's failure: `PairingCodeInvalid` (make a
    /// new code on the web page), `Network` when the service cannot be reached or asks to wait
    /// (rate limit: try again later).
    pub fn begin_pairing_sign_in(
        &self,
        pairing_code: String,
        overall_timeout_ms: Option<u64>,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<u64, CallFailure> {
        let begin = host::BeginPairingSignIn {
            pairing_code,
            overall_timeout: overall_timeout_ms.map(Duration::from_millis),
        };
        match self.account(host::AccountCommand::BeginPairingSignIn(begin), cancel, deadline_ms)? {
            host::CommandOutput::SignInBegun(id) => Ok(id.0),
            other => Err(unexpected("begin_pairing_sign_in", &other)),
        }
    }

    /// The origins (scheme, host, port) a sign-in link may be opened on, per purpose: a link is
    /// opened only when its origin equals the one of its purpose and is https. A `None` origin
    /// means no link of that purpose is trusted. An unreadable credential store is a failure,
    /// not a fallback.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn sign_in_origins(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<SignInOrigins, CallFailure> {
        match self.account(host::AccountCommand::SignInOrigins, cancel, deadline_ms)? {
            host::CommandOutput::SignInOrigins(hosts) => Ok(SignInOrigins {
                approve_device: hosts.approve_device,
                authorization: hosts.authorization,
            }),
            other => Err(unexpected("sign_in_origins", &other)),
        }
    }

    /// Waits for the sign-in step after `after` (0 for the first). A repeated call with the
    /// same `after` returns the same step, so a timed-out or dropped call loses none.
    ///
    /// # Errors
    /// `DeadlineExceeded` when no step came in time (the sign-in goes on); `Account` with
    /// `InvalidInput` for an id that is not the current sign-in.
    pub fn poll_sign_in(
        &self,
        id: u64,
        after: u64,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<SignInStep, CallFailure> {
        let poll = host::PollSignIn { id: host::SignInId(id), after };
        match self.account(host::AccountCommand::PollSignIn(poll), cancel, deadline_ms)? {
            host::CommandOutput::SignInStep(step) => {
                Ok(SignInStep { seq: step.seq, event: step.event.into() })
            }
            other => Err(unexpected("poll_sign_in", &other)),
        }
    }

    /// Cancels the sign-in `id` if it is the current one (any other id is already ended).
    ///
    /// When this returns `Ok`, the sign-in's flow has stopped: a step of it that was running on
    /// another thread has finished and none starts again, so nothing of it is written to the
    /// credential store afterwards, for an ordinary sign-in and a step-up alike. A flow that had
    /// already finished keeps its own last step (read with `poll_sign_in`): `SignedIn` (its
    /// credential is stored) or `Failed`; use `cancel_current_sign_in` for the typed answer.
    /// Idempotent.
    ///
    /// An `Err` (`Cancelled` or `DeadlineExceeded` with `still_running`, or a failed call)
    /// confirms nothing: repeat the cancel.
    ///
    /// # Errors
    /// A [`CallFailure`].
    pub fn cancel_sign_in(
        &self,
        id: u64,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        let command =
            host::Command::Account(host::AccountCommand::CancelSignIn(host::SignInId(id)));
        self.done("cancel_sign_in", command, cancel, deadline_ms)
    }

    /// Cancels whatever sign-in this engine currently holds, without its id: for a host whose
    /// `begin_sign_in` call ran out of time (`DeadlineExceeded` with `still_running`) and so
    /// never learned the id. It gives the same guarantee as `cancel_sign_in` when it returns
    /// `Ok`: the flow has stopped and stores nothing afterwards. Safe when the engine holds none
    /// (`NothingToCancel`), and repeatable.
    ///
    /// It is ordered with `begin_sign_in` on the engine's one sign-in slot, so it cancels a begin
    /// that has started running even though its answer was lost. A begin that was submitted but
    /// has not started yet (the engine had not scheduled it) is not affected: repeat this call
    /// after the begin call's own result is known, or once the sign-in id is. The engine's
    /// restart also ends the sign-in.
    ///
    /// # Errors
    /// A [`CallFailure`]; a `still_running` failure confirms nothing, repeat the cancel.
    pub fn cancel_current_sign_in(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<SignInCancellation, CallFailure> {
        match self.account(host::AccountCommand::CancelCurrentSignIn, cancel, deadline_ms)? {
            host::CommandOutput::SignInCancellation(cancellation) => Ok(cancellation.into()),
            other => Err(unexpected("cancel_current_sign_in", &other)),
        }
    }

    /// Registers this device on the account, once signed in; returns its device id. Restart
    /// the engine (`suspend`, `resume`) afterwards so it runs as the registered device.
    ///
    /// # Errors
    /// `Account` with `NotSignedIn`.
    pub fn register_device(
        &self,
        name: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<String, CallFailure> {
        match self.account(host::AccountCommand::RegisterDevice { name }, cancel, deadline_ms)? {
            host::CommandOutput::DeviceRegistered(device) => Ok(device.device_id),
            other => Err(unexpected("register_device", &other)),
        }
    }

    /// Revokes this installation on the server, then removes its credential; the credential
    /// is kept whenever the revocation could not be confirmed.
    ///
    /// # Errors
    /// `Account` with `NotSignedIn`, or the failure that kept the credential.
    pub fn sign_out(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<SignOutOutcome, CallFailure> {
        match self.account(host::AccountCommand::SignOut, cancel, deadline_ms)? {
            host::CommandOutput::SignedOut(outcome) => Ok(outcome.into()),
            other => Err(unexpected("sign_out", &other)),
        }
    }

    /// Starts over as a new device: the way out of the status item with key
    /// `database_restored` (the replica database was restored or copied, or its installation
    /// witness is missing or unreadable, so this device may not author with its old identity).
    ///
    /// With no start over under way (`AccountStatus::start_over_pending` false), `confirmed`
    /// must be true: show the person first that this device becomes a new device, that its old
    /// device stays on the account signed out, and that its folders stop syncing until they are
    /// linked again. It is refused with nothing changed unless the engine reports
    /// `database_restored` right now. It signs this installation out and retires the device key
    /// and device record (kept under `retired-devices/`, never deleted), then returns
    /// `SignInRequired`. After the person signs in, call it again (`confirmed` is not asked
    /// again): it registers `device_name` as a new device, marks every linked folder as needing
    /// the person and returns `Finished`. Then restart the engine (`suspend`, `resume`); the
    /// engine opens the database as the new device and records the installation witness anew.
    /// Until that restart the engine starts no new start over: a call with none under way is
    /// refused, with nothing changed. No synced file is deleted or rewritten (the link rows are
    /// marked). Interrupted or incomplete runs continue from the state directory's journal when
    /// called again.
    ///
    /// # Errors
    /// `Account` with `Refused` (not confirmed, not restored, in progress), `StartOverRestartRequired`, `NotSignedIn`,
    /// `Network`, `PermissionDenied` or the failure of the step that stopped; run it again.
    pub fn start_over(
        &self,
        confirmed: bool,
        device_name: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<StartOverProgress, CallFailure> {
        match self.account(
            host::AccountCommand::StartOver { confirmed, device_name },
            cancel,
            deadline_ms,
        )? {
            host::CommandOutput::StartOver(progress) => Ok(progress.into()),
            other => Err(unexpected("start_over", &other)),
        }
    }

    /// Records that the person acknowledged that changes made after the backup may be missing,
    /// which lets the engine confirm a replacement the service called unconfirmed (status item
    /// `replacement_unconfirmed` with step `acknowledge`). Only from an explicit user action.
    /// `false`: no replacement was waiting. Idempotent.
    ///
    /// # Errors
    /// A [`CallFailure`]; nothing is acknowledged.
    pub fn acknowledge_possible_loss(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<bool, CallFailure> {
        match self.account(host::AccountCommand::AcknowledgePossibleLoss, cancel, deadline_ms)? {
            host::CommandOutput::PossibleLossAcknowledged(done) => Ok(done),
            other => Err(unexpected("acknowledge_possible_loss", &other)),
        }
    }

    /// What deleting the account would do to other people. Read-only.
    ///
    /// # Errors
    /// `Account` with `NotSignedIn`.
    pub fn account_deletion_impact(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<DeletionImpact, CallFailure> {
        match self.account(host::AccountCommand::DeletionImpact, cancel, deadline_ms)? {
            host::CommandOutput::DeletionImpact(impact) => Ok(impact.into()),
            other => Err(unexpected("account_deletion_impact", &other)),
        }
    }

    /// Asks for account deletion and returns the one-time confirmation token; nothing is
    /// deleted until it is confirmed.
    ///
    /// # Errors
    /// `Account` with `DurabilityBlocked` (and `can_force`) until `acknowledge_impact`.
    pub fn request_account_deletion(
        &self,
        acknowledge_impact: bool,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<String, CallFailure> {
        let command = host::AccountCommand::RequestDeletion { acknowledge_impact };
        match self.account(command, cancel, deadline_ms)? {
            host::CommandOutput::DeletionRequested(requested) => Ok(requested.confirmation_token),
            other => Err(unexpected("request_account_deletion", &other)),
        }
    }

    /// Confirms a requested deletion with its token, starting the grace period.
    ///
    /// # Errors
    /// An `Account` failure.
    pub fn confirm_account_deletion(
        &self,
        confirmation_token: String,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<DeletionStatus, CallFailure> {
        let command = host::AccountCommand::ConfirmDeletion { confirmation_token };
        self.deletion_status_of("confirm_account_deletion", command, cancel, deadline_ms)
    }

    /// Cancels a requested or confirmed deletion before the grace period ends.
    ///
    /// # Errors
    /// An `Account` failure.
    pub fn cancel_account_deletion(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<DeletionStatus, CallFailure> {
        self.deletion_status_of(
            "cancel_account_deletion",
            host::AccountCommand::CancelDeletion,
            cancel,
            deadline_ms,
        )
    }

    /// Where the account's deletion stands. Read-only.
    ///
    /// # Errors
    /// An `Account` failure.
    pub fn account_deletion_status(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<DeletionStatus, CallFailure> {
        self.deletion_status_of(
            "account_deletion_status",
            host::AccountCommand::DeletionStatus,
            cancel,
            deadline_ms,
        )
    }

    /// After the server finalized the deletion, removes this device's credential and key.
    /// Fails closed: while the account still exists nothing is removed.
    ///
    /// # Errors
    /// An `Account` failure.
    pub fn complete_account_deletion(
        &self,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<SignOutOutcome, CallFailure> {
        match self.account(host::AccountCommand::CompleteDeletion, cancel, deadline_ms)? {
            host::CommandOutput::SignedOut(outcome) => Ok(outcome.into()),
            other => Err(unexpected("complete_account_deletion", &other)),
        }
    }
}

impl MobileHost {
    /// A command that returns nothing.
    fn done(
        &self,
        name: &str,
        command: host::Command,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<(), CallFailure> {
        match self.run(command, cancel, deadline_ms)? {
            host::CommandOutput::Done => Ok(()),
            other => Err(unexpected(name, &other)),
        }
    }

    fn deletion_status_of(
        &self,
        name: &str,
        command: host::AccountCommand,
        cancel: &CancelHandle,
        deadline_ms: Option<u64>,
    ) -> Result<DeletionStatus, CallFailure> {
        match self.account(command, cancel, deadline_ms)? {
            host::CommandOutput::DeletionStatus(status) => Ok(status.into()),
            other => Err(unexpected(name, &other)),
        }
    }
}

// ---- invites and logging ---------------------------------------------------------------

/// Why an invite link or code was refused. A flat error: the foreign side gets each case with
/// the engine's wording as its message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum InviteError {
    #[error("{}", host::InviteLinkError::Empty)]
    Empty,
    #[error("{}", host::InviteLinkError::TooLong)]
    TooLong,
    #[error("{}", host::InviteLinkError::Malformed)]
    Malformed,
}

impl From<host::InviteLinkError> for InviteError {
    fn from(error: host::InviteLinkError) -> Self {
        match error {
            host::InviteLinkError::Empty => Self::Empty,
            host::InviteLinkError::TooLong => Self::TooLong,
            host::InviteLinkError::Malformed => Self::Malformed,
        }
    }
}

/// The invite code in a `yadorilink://invite/<code>` link or a bare code: the engine's own
/// parser, so the app and the engine cannot disagree about what an invite is. Synchronous and
/// free of I/O.
///
/// # Errors
/// [`InviteError`] for empty, oversized or malformed input.
#[uniffi::export]
pub fn parse_invite_input(input: String) -> Result<String, InviteError> {
    Ok(host::parse_invite_input(&input).map(str::to_owned)?)
}

/// How serious a log event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<host::LogLevel> for LogLevel {
    fn from(level: host::LogLevel) -> Self {
        match level {
            host::LogLevel::Trace => Self::Trace,
            host::LogLevel::Debug => Self::Debug,
            host::LogLevel::Info => Self::Info,
            host::LogLevel::Warn => Self::Warn,
            host::LogLevel::Error => Self::Error,
        }
    }
}

impl From<LogLevel> for host::LogLevel {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => Self::Trace,
            LogLevel::Debug => Self::Debug,
            LogLevel::Info => Self::Info,
            LogLevel::Warn => Self::Warn,
            LogLevel::Error => Self::Error,
        }
    }
}

/// Where the engine's log events go; the app implements it (for example forwarding to
/// `os_log`). Called from any thread, so it must not block.
#[uniffi::export(with_foreign)]
pub trait LogSink: Send + Sync {
    /// One event: its level, the module that emitted it, and its message with the event's
    /// fields appended as `key=value`.
    fn log(&self, level: LogLevel, target: String, message: String);
}

/// Why the log sink was not installed.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LogSinkFailure {
    /// This process already has a global log subscriber; only one can exist.
    #[error("a log subscriber is already installed in this process")]
    AlreadyInstalled,
}

/// Routes the engine's log events at `min_level` and above to `sink`, for the rest of the
/// process. Until a sink is installed events are dropped. Call it once, before starting the
/// engine.
///
/// # Errors
/// `AlreadyInstalled` when the process already has a global subscriber.
#[uniffi::export]
pub fn install_log_sink(sink: Arc<dyn LogSink>, min_level: LogLevel) -> Result<(), LogSinkFailure> {
    let forward: host::LogSink = Arc::new(move |level, target, message| {
        sink.log(level.into(), target.to_owned(), message.to_owned());
    });
    host::install_log_sink(forward, min_level.into())
        .map_err(|host::LogSinkError::AlreadyInstalled| LogSinkFailure::AlreadyInstalled)
}
