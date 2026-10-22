//! Stable, closed reason codes a [`super::RecoveryDiagnosis`]
//! attaches to its own [`super::RecoveryRecommendation`] -- never a
//! free-form string. Wire slugs (for JSON output)
//! are centralized in [`RecoveryReasonCode::as_str`], so a rename here is a
//! one-place change rather than a hunt through every classifier arm that
//! constructs one.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryReasonCode {
    RecoveryBlocked,

    RemoteUnavailable,
    RemoteRecordNotFound,
    RemoteIdentityMismatch,
    RemoteIdentityNotComparable,
    RemoteResultIncomplete,
    RemoteResultConflict,

    LocalLinkMissing,
    LocalLinkUnexpected,
    LocalLinkIdentityMismatch,
    LocalLinkInvalid,
    LocalLinkAmbiguous,

    LocalMarkerMissing,
    LocalMarkerUnexpected,
    LocalMarkerIdentityMismatch,
    LocalMarkerInvalid,
    LocalMarkerAmbiguous,

    RemoteActiveBeforeLocalSetup,
    RemoteAuthorizationGone,
    RemoteCommittedLocalUnsettled,

    DurabilityScopeUnknown,
    DurabilityLatchMissing,

    LegacyRoleLossReceiptUncertain,
    RoleLossCompensationRequired,
    UnsupportedRoleLossAction,
}

impl RecoveryReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryBlocked => "recovery_blocked",
            Self::RemoteUnavailable => "remote_unavailable",
            Self::RemoteRecordNotFound => "remote_record_not_found",
            Self::RemoteIdentityMismatch => "remote_identity_mismatch",
            Self::RemoteIdentityNotComparable => "remote_identity_not_comparable",
            Self::RemoteResultIncomplete => "remote_result_incomplete",
            Self::RemoteResultConflict => "remote_result_conflict",
            Self::LocalLinkMissing => "local_link_missing",
            Self::LocalLinkUnexpected => "local_link_unexpected",
            Self::LocalLinkIdentityMismatch => "local_link_identity_mismatch",
            Self::LocalLinkInvalid => "local_link_invalid",
            Self::LocalLinkAmbiguous => "local_link_ambiguous",
            Self::LocalMarkerMissing => "local_marker_missing",
            Self::LocalMarkerUnexpected => "local_marker_unexpected",
            Self::LocalMarkerIdentityMismatch => "local_marker_identity_mismatch",
            Self::LocalMarkerInvalid => "local_marker_invalid",
            Self::LocalMarkerAmbiguous => "local_marker_ambiguous",
            Self::RemoteActiveBeforeLocalSetup => "remote_active_before_local_setup",
            Self::RemoteAuthorizationGone => "remote_authorization_gone",
            Self::RemoteCommittedLocalUnsettled => "remote_committed_local_unsettled",
            Self::DurabilityScopeUnknown => "durability_scope_unknown",
            Self::DurabilityLatchMissing => "durability_latch_missing",
            Self::LegacyRoleLossReceiptUncertain => "legacy_role_loss_receipt_uncertain",
            Self::RoleLossCompensationRequired => "role_loss_compensation_required",
            Self::UnsupportedRoleLossAction => "unsupported_role_loss_action",
        }
    }
}

/// Ensures `reason_codes` never depends on which internal check happened to
/// run first -- matches the same discipline `identity::sorted_dedup`
/// already applies to mismatch fields.
pub(super) fn sorted_dedup_reasons(
    mut reasons: Vec<RecoveryReasonCode>,
) -> Vec<RecoveryReasonCode> {
    reasons.sort();
    reasons.dedup();
    reasons
}
