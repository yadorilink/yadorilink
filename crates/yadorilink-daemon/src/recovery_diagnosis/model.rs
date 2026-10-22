//! Typed output shapes for the evidence-identity
//! qualification (`crate::recovery_diagnosis::identity`). Nothing here
//! reads a database, calls the coordination plane, or decides a
//! recommendation -- that is the classifier's job, layered on top of these
//! types, not part of this module.

/// One field two identity-bearing values (a local journal row and its
/// related local/remote evidence) can disagree on. A closed enum, not a
/// free-form string: a mismatch report a caller (an operator, or the
/// diagnosis classifier) can match on exhaustively is worth far more than
/// a human-readable sentence that has to be re-parsed to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityField {
    Kind,
    GroupId,
    GroupName,
    DeviceId,
    /// The device a membership operation removes -- kept distinct from
    /// [`Self::DeviceId`] (an enrollment's own device identity) even
    /// though both ultimately name a device: the two mean different
    /// things in different domains, and collapsing them into one variant
    /// would make a wire slug ambiguous about which domain it came from.
    RemovedDeviceId,
    SourceDeviceId,
    TargetDeviceId,
    LocalPath,
    StorageMode,
    Action,
    CommitMode,
    LeaseId,
    GroupTuples,
    ResultGroupId,
}

impl IdentityField {
    /// Wire slug, centralized -- mirrors [`super::RecoveryReasonCode::as_str`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kind => "kind",
            Self::GroupId => "group_id",
            Self::GroupName => "group_name",
            Self::DeviceId => "device_id",
            Self::RemovedDeviceId => "removed_device_id",
            Self::SourceDeviceId => "source_device_id",
            Self::TargetDeviceId => "target_device_id",
            Self::LocalPath => "local_path",
            Self::StorageMode => "storage_mode",
            Self::Action => "action",
            Self::CommitMode => "commit_mode",
            Self::LeaseId => "lease_id",
            Self::GroupTuples => "group_tuples",
            Self::ResultGroupId => "result_group_id",
        }
    }
}

/// The qualification of one related-evidence observation (a link, or a
/// pending-enrollment marker) against the journal row it's read alongside.
/// Deliberately mirrors [`crate::recovery::LocalObservation`]'s
/// own shape (`ConfirmedAbsent`/`Invalid`/`Ambiguous` pass straight
/// through) plus the two outcomes only meaningful once a row IS present:
/// `Exact` (every identity field this evidence carries agrees with the
/// journal row) or `Mismatch` (at least one does not). `ConfirmedAbsent`
/// here is a plain observation, not a verdict -- whether absence is
/// EXPECTED for the journal row's own state is the classifier's call, not
/// this qualification's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservationQualification {
    ConfirmedAbsent,
    Exact,
    Mismatch { fields: Vec<IdentityField> },
    Invalid { detail: String },
    Ambiguous { detail: String },
}

/// Why a remote record's identity could not be evaluated at all, despite a
/// record being available to compare against (or not) -- kept separate
/// from [`RemoteIdentityQualification::Mismatch`], which means a
/// comparison WAS made and disagreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityQualificationReason {
    /// A `Create` row still `PreparePending` has no `group_id` to compare
    /// against `record.result_group_id` yet, and its local `group_name` is
    /// missing -- the one field its own state validation guarantees is
    /// present, so this should not normally happen against a
    /// strictly-decoded row.
    MissingLocalGroupName,
    /// A row past `PreparePending` has no local `group_id` to compare a
    /// remote `result_group_id` against.
    MissingLocalGroupId,
    /// The remote record's own `result_group_id` is absent even though the
    /// remote status implies one should exist by now.
    MissingRemoteResultGroupId,
    /// Reserved for a local role-loss `action` this build's wire mapping
    /// does not (yet) recognize. Every `RoleLossAction` variant maps today
    /// -- see `identity::role_loss_wire_action` -- so this is currently
    /// unreachable, kept for forward compatibility with a future action
    /// variant.
    UnsupportedLocalRoleLossAction,
}

impl IdentityQualificationReason {
    /// Wire slug, centralized -- mirrors [`super::RecoveryReasonCode::as_str`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingLocalGroupName => "missing_local_group_name",
            Self::MissingLocalGroupId => "missing_local_group_id",
            Self::MissingRemoteResultGroupId => "missing_remote_result_group_id",
            Self::UnsupportedLocalRoleLossAction => "unsupported_local_role_loss_action",
        }
    }
}

/// Why a remote identity comparison was never attempted at all -- the
/// remote lookup itself did not return a record to compare against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityNotEvaluatedReason {
    RecordNotFound,
    RemoteUnavailable,
}

impl IdentityNotEvaluatedReason {
    /// Wire slug, centralized -- mirrors [`super::RecoveryReasonCode::as_str`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecordNotFound => "record_not_found",
            Self::RemoteUnavailable => "remote_unavailable",
        }
    }
}

/// The qualification of a Worker-side remote record's identity against the
/// local journal row it was looked up for. `RecordNotFound`/`Unavailable`
/// remote evidence is NEVER converted into `Exact` or `Mismatch` -- both
/// collapse to `NotEvaluated`, preserving exactly why no comparison could
/// be made, since neither "no record" nor "couldn't ask" is itself
/// evidence of agreement OR disagreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteIdentityQualification {
    Exact,
    Mismatch {
        fields: Vec<IdentityField>,
    },
    /// A record exists, but a piece of information a full comparison needs
    /// is itself absent on one side or the other (see
    /// [`IdentityQualificationReason`]).
    NotComparable {
        reasons: Vec<IdentityQualificationReason>,
    },
    NotEvaluated {
        reason: IdentityNotEvaluatedReason,
    },
}

/// The complete B1 qualification for one enrollment operation's evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentEvidenceQualification {
    pub link: ObservationQualification,
    pub pending_marker: ObservationQualification,
    pub remote_identity: RemoteIdentityQualification,
}

/// The complete B1 qualification for one membership operation's evidence.
/// No link/marker fields -- a membership operation has no related local
/// row of its own the way enrollment/role-loss do (the `links` table is
/// consulted for role-loss, not membership).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEvidenceQualification {
    pub remote_identity: RemoteIdentityQualification,
}

/// The complete B1 qualification for one role-loss operation's evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleLossEvidenceQualification {
    pub link: ObservationQualification,
    pub remote_identity: RemoteIdentityQualification,
}
