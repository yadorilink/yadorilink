//! A pure classifier that combines a local recovery
//! journal row's own state with the evidence-identity
//! qualification into a [`RecoveryDiagnosis`] -- a
//! [`RecoveryRecommendation`] an operator, or an automatic
//! reconciler, can act on. No database, no HTTP client, no mutation: every
//! function here is a pure `local + remote -> diagnosis` mapping over
//! values already produced by earlier phases.
//!
//! The public entry points (`diagnose_enrollment`/`diagnose_membership`/
//! `diagnose_role_loss`) deliberately take only `local`/`remote` --
//! `qualification` is generated INSIDE, never accepted as a caller-supplied
//! parameter. A caller-supplied qualification could be built from a
//! DIFFERENT `local`/`remote` pair than the ones actually passed in,
//! producing a diagnosis that describes an evidence combination that never
//! existed.

use crate::recovery::{
    EnrollmentLocalEvidence, LocalObservation, MembershipLocalEvidence, RecoveryOperationKey,
    RoleLossLocalEvidence,
};
use yadorilink_replica_domain::recovery::RecoveryDomain;
use yadorilink_replica_domain::session_state::EnrollmentKind;
use yadorilink_replica_domain::session_state::{
    EnrollmentOperationState, MembershipDurabilityScope, MembershipOperationAction,
    MembershipOperationState, RoleLossAction, RoleLossOperationState,
};

use crate::coordination_client::{
    EnrollmentOperationRecord, EnrollmentRemoteStatus, MembershipOperationRecord,
    MembershipRemoteStatus, RemoteEvidenceErrorCategory, RoleLossOperationRecord,
};
use crate::recovery_evidence::RemoteEvidence;

use super::identity::{qualify_enrollment, qualify_membership, qualify_role_loss};
use super::model::{
    EnrollmentEvidenceQualification, MembershipEvidenceQualification, ObservationQualification,
    RemoteIdentityQualification, RoleLossEvidenceQualification,
};
use super::reason::{sorted_dedup_reasons, RecoveryReasonCode};

/// What existing automatic recovery, if any, should do next with this
/// operation. Every variant maps to exactly one
/// [`RecoveryRecommendation::automatic_recovery_safe`] answer -- see that
/// method's own doc comment for why it, not this construction site, is the
/// single source of truth for that bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecoveryRecommendation {
    WaitForAutomaticRecovery,
    WaitForRemoteEvidence,

    RetrySameRemoteRequest,
    RetryRemoteActivation,
    RetryRemoteCancellation,

    ContinueAutomaticCompensation,
    CompleteLocalSettlement,

    Conflict,
    ManualInvestigation,
}

impl RecoveryRecommendation {
    /// Wire slug for this recommendation, centralized so a rename here is a
    /// one-place change rather than a hunt through every conversion site --
    /// mirrors [`super::RecoveryReasonCode::as_str`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WaitForAutomaticRecovery => "wait_for_automatic_recovery",
            Self::WaitForRemoteEvidence => "wait_for_remote_evidence",
            Self::RetrySameRemoteRequest => "retry_same_remote_request",
            Self::RetryRemoteActivation => "retry_remote_activation",
            Self::RetryRemoteCancellation => "retry_remote_cancellation",
            Self::ContinueAutomaticCompensation => "continue_automatic_compensation",
            Self::CompleteLocalSettlement => "complete_local_settlement",
            Self::Conflict => "conflict",
            Self::ManualInvestigation => "manual_investigation",
        }
    }

    /// "Safe" here means only: the evidence gathered supports running the
    /// EXISTING automatic-recovery action this recommendation names. It is
    /// NOT a claim that the underlying data is currently safe/durable --
    /// `CompleteLocalSettlement` for a `DurabilityScopeUnknown` operation
    /// is exactly this: safe to let local settlement proceed, while the
    /// data's own durability remains genuinely unknown (see that reason
    /// code, attached alongside, not overridden by this bool).
    pub fn automatic_recovery_safe(self) -> bool {
        matches!(
            self,
            Self::WaitForAutomaticRecovery
                | Self::RetrySameRemoteRequest
                | Self::RetryRemoteActivation
                | Self::RetryRemoteCancellation
                | Self::ContinueAutomaticCompensation
                | Self::CompleteLocalSettlement
        )
    }
}

/// A recovery journal row's own domain-specific state, kept as its real
/// typed enum -- never stringified early. Display/wire formatting is
/// `super::ipc`'s concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryLocalState {
    Enrollment(EnrollmentOperationState),
    Membership(MembershipOperationState),
    RoleLoss(RoleLossOperationState),
}

/// What the remote lookup itself reported, normalized across domains but
/// still typed. `RoleLossCommitted` stands in for role-loss's own
/// existence-only receipt (there is no separate status field to carry --
/// see [`RoleLossOperationRecord`]'s own doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryRemoteState {
    Enrollment(EnrollmentRemoteStatus),
    Membership(MembershipRemoteStatus),
    RoleLossCommitted,
    RecordNotFound,
    Unavailable { category: RemoteEvidenceErrorCategory },
}

/// The B1 qualification this diagnosis was built from, wrapped by domain --
/// carried on [`RecoveryDiagnosis`] purely for the caller's own inspection/
/// display; the classifier itself never re-reads this field after
/// constructing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryEvidenceQualification {
    Enrollment(EnrollmentEvidenceQualification),
    Membership(MembershipEvidenceQualification),
    RoleLoss(RoleLossEvidenceQualification),
}

/// Immutable by construction: every field is private, `build_diagnosis` (the
/// only constructor, used exclusively by this module's own `classify_*`
/// functions) is the sole place a value is ever assembled, and there is no
/// public way to mutate one after the fact. This is deliberate, not an
/// oversight -- a `pub` struct literal or `pub` fields would let a caller
/// set `recommendation` and `automatic_recovery_safe` inconsistently, or
/// push a duplicate/unsorted entry onto `reason_codes`, silently breaking
/// the exact invariants this type exists to guarantee. `automatic_recovery_safe`
/// is not even stored -- it is derived fresh on every call to
/// [`Self::automatic_recovery_safe`], so it can never drift from
/// `recommendation` no matter how this type evolves later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryDiagnosis {
    key: RecoveryOperationKey,
    local_state: RecoveryLocalState,
    remote_state: RecoveryRemoteState,
    qualification: RecoveryEvidenceQualification,
    recommendation: RecoveryRecommendation,
    reason_codes: Vec<RecoveryReasonCode>,
}

impl RecoveryDiagnosis {
    pub fn key(&self) -> &RecoveryOperationKey {
        &self.key
    }

    pub fn local_state(&self) -> RecoveryLocalState {
        self.local_state
    }

    pub fn remote_state(&self) -> RecoveryRemoteState {
        self.remote_state
    }

    pub fn qualification(&self) -> &RecoveryEvidenceQualification {
        &self.qualification
    }

    pub fn recommendation(&self) -> RecoveryRecommendation {
        self.recommendation
    }

    pub fn reason_codes(&self) -> &[RecoveryReasonCode] {
        &self.reason_codes
    }

    /// Always `self.recommendation().automatic_recovery_safe()` -- derived
    /// on every call, never stored, so it cannot drift from
    /// `recommendation` even as this type's own internals change.
    pub fn automatic_recovery_safe(&self) -> bool {
        self.recommendation.automatic_recovery_safe()
    }
}

fn build_diagnosis(
    key: RecoveryOperationKey,
    local_state: RecoveryLocalState,
    remote_state: RecoveryRemoteState,
    qualification: RecoveryEvidenceQualification,
    recommendation: RecoveryRecommendation,
    reason_codes: Vec<RecoveryReasonCode>,
) -> RecoveryDiagnosis {
    RecoveryDiagnosis {
        key,
        local_state,
        remote_state,
        qualification,
        recommendation,
        reason_codes: sorted_dedup_reasons(reason_codes),
    }
}

fn is_invalid(q: &ObservationQualification) -> bool {
    matches!(q, ObservationQualification::Invalid { .. })
}
fn is_ambiguous(q: &ObservationQualification) -> bool {
    matches!(q, ObservationQualification::Ambiguous { .. })
}
fn is_mismatch(q: &ObservationQualification) -> bool {
    matches!(q, ObservationQualification::Mismatch { .. })
}
fn is_remote_mismatch(q: &RemoteIdentityQualification) -> bool {
    matches!(q, RemoteIdentityQualification::Mismatch { .. })
}
fn is_remote_not_comparable(q: &RemoteIdentityQualification) -> bool {
    matches!(q, RemoteIdentityQualification::NotComparable { .. })
}

// ============================== Enrollment ==============================

fn enrollment_remote_state(
    remote: &RemoteEvidence<EnrollmentOperationRecord>,
) -> RecoveryRemoteState {
    match remote {
        RemoteEvidence::Found(record) => RecoveryRemoteState::Enrollment(record.status),
        RemoteEvidence::RecordNotFound => RecoveryRemoteState::RecordNotFound,
        RemoteEvidence::Unavailable { category } => {
            RecoveryRemoteState::Unavailable { category: *category }
        }
    }
}

/// What local rows/observations this operation actually has, beyond what
/// B1's identity qualification alone carries -- specifically `orphaned`,
/// which identity qualification never inspects (orphaned-ness is not an
/// identity property) but the state matrix needs directly: an orphaned
/// link must never be treated as "still linked" when deciding whether a
/// `CancelPending` row may safely cancel, and a paused (but not orphaned)
/// link must still count as live -- pausing is a reversible sync gate, not
/// an unlink.
struct EnrollmentLocalShape {
    link_present: bool,
    live_link_present: bool,
    marker_present: bool,
}

fn enrollment_local_shape(local: &EnrollmentLocalEvidence) -> EnrollmentLocalShape {
    let (link_present, live_link_present) = match &local.link {
        LocalObservation::Found(link) => (true, !link.orphaned),
        _ => (false, false),
    };
    let marker_present = matches!(local.pending_marker, LocalObservation::Found(_));
    EnrollmentLocalShape { link_present, live_link_present, marker_present }
}

/// Independent of identity -- a remote record whose STATUS implies a
/// result should already exist, but doesn't, is internally inconsistent
/// regardless of whether it also happens to name the same request. See
/// this module's own doc comment on why this is checked once, ahead of
/// the state matrix, rather than duplicated in every state that might
/// otherwise trust `result_group_id`.
/// Checked regardless of the LOCAL row's own state or `kind` (Create/Join
/// share the same wire contract here): the remote record's internal
/// consistency is a property of that record alone, not of what this
/// device has confirmed yet.
///
/// ```text
/// Preparing  -- result_group_id must be None (Some is a live
///               contradiction: the plane hasn't resolved a group yet)
/// Prepared   -- result_group_id must be Some
/// Active     -- result_group_id must be Some
/// Cancelled  -- result_group_id may be EITHER -- the Worker's own
///               `settleOperation(..., status: "cancelled", resultJson:
///               null)` path (stale-preparing sweep, a cancel racing an
///               in-flight prepare) legitimately produces `None` here;
///               this is a normal terminal outcome, not a malformed one.
/// ```
fn enrollment_result_shape_issue(record: &EnrollmentOperationRecord) -> Option<RecoveryReasonCode> {
    match record.status {
        EnrollmentRemoteStatus::Preparing => {
            record.result_group_id.is_some().then_some(RecoveryReasonCode::RemoteResultConflict)
        }
        EnrollmentRemoteStatus::Prepared | EnrollmentRemoteStatus::Active => {
            record.result_group_id.is_none().then_some(RecoveryReasonCode::RemoteResultIncomplete)
        }
        EnrollmentRemoteStatus::Cancelled => None,
    }
}

fn classify_enrollment(
    local: &EnrollmentLocalEvidence,
    remote: &RemoteEvidence<EnrollmentOperationRecord>,
    qualification: EnrollmentEvidenceQualification,
) -> RecoveryDiagnosis {
    let key = RecoveryOperationKey {
        domain: RecoveryDomain::Enrollment,
        operation_id: local.operation.operation_id.clone(),
    };
    let local_state = RecoveryLocalState::Enrollment(local.operation.state);
    let remote_state = enrollment_remote_state(remote);
    let wrap = || RecoveryEvidenceQualification::Enrollment(qualification.clone());

    // 1. RecoveryBlocked always wins.
    if local.operation.state == EnrollmentOperationState::RecoveryBlocked {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::ManualInvestigation,
            vec![RecoveryReasonCode::RecoveryBlocked],
        );
    }

    // 2/3. Local Invalid / Ambiguous observations.
    let mut hard_reasons = Vec::new();
    if is_invalid(&qualification.link) {
        hard_reasons.push(RecoveryReasonCode::LocalLinkInvalid);
    }
    if is_invalid(&qualification.pending_marker) {
        hard_reasons.push(RecoveryReasonCode::LocalMarkerInvalid);
    }
    if is_ambiguous(&qualification.link) {
        hard_reasons.push(RecoveryReasonCode::LocalLinkAmbiguous);
    }
    if is_ambiguous(&qualification.pending_marker) {
        hard_reasons.push(RecoveryReasonCode::LocalMarkerAmbiguous);
    }
    if !hard_reasons.is_empty() {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::ManualInvestigation,
            hard_reasons,
        );
    }

    // 4. Local identity mismatch.
    let mut mismatch_reasons = Vec::new();
    if is_mismatch(&qualification.link) {
        mismatch_reasons.push(RecoveryReasonCode::LocalLinkIdentityMismatch);
    }
    if is_mismatch(&qualification.pending_marker) {
        mismatch_reasons.push(RecoveryReasonCode::LocalMarkerIdentityMismatch);
    }
    if !mismatch_reasons.is_empty() {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::Conflict,
            mismatch_reasons,
        );
    }

    // 5. Remote identity mismatch.
    if is_remote_mismatch(&qualification.remote_identity) {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::Conflict,
            vec![RecoveryReasonCode::RemoteIdentityMismatch],
        );
    }

    // 5.5. Remote result-shape consistency (independent of identity).
    if let RemoteEvidence::Found(record) = remote {
        if let Some(reason) = enrollment_result_shape_issue(record) {
            return build_diagnosis(
                key,
                local_state,
                remote_state,
                wrap(),
                RecoveryRecommendation::ManualInvestigation,
                vec![reason],
            );
        }
    }

    let not_comparable = is_remote_not_comparable(&qualification.remote_identity);
    let shape = enrollment_local_shape(local);

    // 6. Domain state matrix.
    let (recommendation, mut reasons) =
        classify_enrollment_state_matrix(local, remote, &shape, not_comparable);
    if not_comparable {
        // A trust-positive branch already downgraded itself to
        // `ManualInvestigation` when this mattered (see `trust`'s own doc
        // comment in `classify_enrollment_state_matrix`); anything else
        // reaching here with `not_comparable` still set took a branch that
        // doesn't need remote identity to be trustworthy at all (e.g. a
        // plain resend). The fact is still surfaced as a reason either way
        // -- an operator inspecting a `RetrySameRemoteRequest` diagnosis
        // should still know identity couldn't be confirmed, even though it
        // didn't change what action was recommended.
        reasons.push(RecoveryReasonCode::RemoteIdentityNotComparable);
    }
    reasons = sorted_dedup_reasons(reasons);
    build_diagnosis(key, local_state, remote_state, wrap(), recommendation, reasons)
}

fn classify_enrollment_state_matrix(
    local: &EnrollmentLocalEvidence,
    remote: &RemoteEvidence<EnrollmentOperationRecord>,
    shape: &EnrollmentLocalShape,
    not_comparable: bool,
) -> (RecoveryRecommendation, Vec<RecoveryReasonCode>) {
    use EnrollmentRemoteStatus as S;
    use RecoveryRecommendation as R;

    /// Downgrades a "trust remote's CURRENT reported status as the truth"
    /// recommendation (`CompleteLocalSettlement`/`RetryRemoteActivation`)
    /// to `ManualInvestigation` when identity could not be confirmed --
    /// see this module's own doc comment for why a plain resend
    /// (`RetrySameRemoteRequest`/`RetryRemoteCancellation`) does NOT need
    /// this: a resend doesn't read or trust remote's current state at
    /// all, it just re-sends the caller's own request under the same id.
    fn trust(
        not_comparable: bool,
        recommendation: RecoveryRecommendation,
    ) -> (RecoveryRecommendation, Vec<RecoveryReasonCode>) {
        if not_comparable {
            (
                RecoveryRecommendation::ManualInvestigation,
                vec![RecoveryReasonCode::RemoteIdentityNotComparable],
            )
        } else {
            (recommendation, vec![])
        }
    }

    match local.operation.state {
        EnrollmentOperationState::PreparePending => {
            if shape.link_present || shape.marker_present {
                let mut reasons = Vec::new();
                if shape.link_present {
                    reasons.push(RecoveryReasonCode::LocalLinkUnexpected);
                }
                if shape.marker_present {
                    reasons.push(RecoveryReasonCode::LocalMarkerUnexpected);
                }
                return (R::ManualInvestigation, reasons);
            }
            match remote {
                RemoteEvidence::RecordNotFound => {
                    (R::RetrySameRemoteRequest, vec![RecoveryReasonCode::RemoteRecordNotFound])
                }
                RemoteEvidence::Unavailable { .. } => {
                    (R::WaitForRemoteEvidence, vec![RecoveryReasonCode::RemoteUnavailable])
                }
                RemoteEvidence::Found(record) => match record.status {
                    S::Preparing | S::Prepared => (R::WaitForAutomaticRecovery, vec![]),
                    S::Active => {
                        (R::Conflict, vec![RecoveryReasonCode::RemoteActiveBeforeLocalSetup])
                    }
                    S::Cancelled => (R::Conflict, vec![RecoveryReasonCode::RemoteResultConflict]),
                },
            }
        }
        EnrollmentOperationState::Prepared => {
            if shape.link_present != shape.marker_present {
                let reason = if shape.link_present {
                    RecoveryReasonCode::LocalMarkerMissing
                } else {
                    RecoveryReasonCode::LocalLinkMissing
                };
                return (R::ManualInvestigation, vec![reason]);
            }
            if shape.link_present && shape.marker_present {
                // Exact local evidence alone does not mean automatic
                // recovery may proceed blindly -- remote reporting
                // `Active` here means activation already happened before
                // this row ever reached `LocalSetupPending`, the exact
                // phantom-full-replica race `LocalSetupPending` exists to
                // prevent (see `EnrollmentOperationState`'s own doc
                // comment). Must stay a `Conflict`, matching every other
                // branch in this state matrix that treats a remote
                // `Active` this early the same way.
                return match remote {
                    RemoteEvidence::Found(record) if record.status == S::Active => {
                        (R::Conflict, vec![RecoveryReasonCode::RemoteActiveBeforeLocalSetup])
                    }
                    _ => (R::WaitForAutomaticRecovery, vec![]),
                };
            }
            match remote {
                RemoteEvidence::RecordNotFound => match local.operation.kind {
                    EnrollmentKind::Create => {
                        (R::ManualInvestigation, vec![RecoveryReasonCode::RemoteRecordNotFound])
                    }
                    EnrollmentKind::Join => {
                        (R::RetrySameRemoteRequest, vec![RecoveryReasonCode::RemoteRecordNotFound])
                    }
                },
                RemoteEvidence::Unavailable { .. } => {
                    (R::WaitForRemoteEvidence, vec![RecoveryReasonCode::RemoteUnavailable])
                }
                RemoteEvidence::Found(record) => match record.status {
                    S::Preparing | S::Prepared => (R::WaitForAutomaticRecovery, vec![]),
                    S::Active => {
                        (R::Conflict, vec![RecoveryReasonCode::RemoteActiveBeforeLocalSetup])
                    }
                    S::Cancelled => trust(not_comparable, R::CompleteLocalSettlement),
                },
            }
        }
        EnrollmentOperationState::LocalSetupPending => {
            let one_only = shape.link_present != shape.marker_present;
            if one_only {
                let reason = if shape.link_present {
                    RecoveryReasonCode::LocalMarkerMissing
                } else {
                    RecoveryReasonCode::LocalLinkMissing
                };
                return (R::ManualInvestigation, vec![reason]);
            }
            match remote {
                RemoteEvidence::Found(record) if record.status == S::Active => {
                    (R::Conflict, vec![RecoveryReasonCode::RemoteActiveBeforeLocalSetup])
                }
                _ => (R::WaitForAutomaticRecovery, vec![]),
            }
        }
        EnrollmentOperationState::ActivationPending => {
            if shape.live_link_present && shape.marker_present {
                match remote {
                    RemoteEvidence::RecordNotFound => (
                        R::WaitForAutomaticRecovery,
                        vec![
                            RecoveryReasonCode::RemoteRecordNotFound,
                            RecoveryReasonCode::RemoteAuthorizationGone,
                        ],
                    ),
                    RemoteEvidence::Unavailable { .. } => {
                        (R::WaitForRemoteEvidence, vec![RecoveryReasonCode::RemoteUnavailable])
                    }
                    RemoteEvidence::Found(record) => match record.status {
                        S::Prepared => trust(not_comparable, R::RetryRemoteActivation),
                        S::Active => trust(not_comparable, R::CompleteLocalSettlement),
                        S::Preparing => (R::WaitForAutomaticRecovery, vec![]),
                        S::Cancelled => (
                            R::WaitForAutomaticRecovery,
                            vec![RecoveryReasonCode::RemoteAuthorizationGone],
                        ),
                    },
                }
            } else if shape.live_link_present && !shape.marker_present {
                match remote {
                    RemoteEvidence::Found(record) if record.status == S::Active => {
                        trust(not_comparable, R::CompleteLocalSettlement)
                    }
                    _ => (R::ManualInvestigation, vec![RecoveryReasonCode::LocalMarkerMissing]),
                }
            } else if !shape.link_present && !shape.marker_present {
                match remote {
                    RemoteEvidence::RecordNotFound => {
                        trust(not_comparable, R::CompleteLocalSettlement)
                    }
                    RemoteEvidence::Unavailable { .. } => {
                        (R::WaitForRemoteEvidence, vec![RecoveryReasonCode::RemoteUnavailable])
                    }
                    RemoteEvidence::Found(record) => match record.status {
                        S::Preparing | S::Prepared => (R::RetryRemoteCancellation, vec![]),
                        S::Cancelled => trust(not_comparable, R::CompleteLocalSettlement),
                        S::Active => (R::Conflict, vec![]),
                    },
                }
            } else {
                // marker present, link present but orphaned (not live).
                match remote {
                    RemoteEvidence::Found(record) if record.status == S::Active => {
                        (R::Conflict, vec![])
                    }
                    RemoteEvidence::Unavailable { .. } => {
                        (R::WaitForRemoteEvidence, vec![RecoveryReasonCode::RemoteUnavailable])
                    }
                    _ => (R::WaitForAutomaticRecovery, vec![]),
                }
            }
        }
        EnrollmentOperationState::CancelPending => {
            if shape.marker_present {
                return (R::ManualInvestigation, vec![RecoveryReasonCode::LocalMarkerUnexpected]);
            }
            if shape.live_link_present {
                return (R::Conflict, vec![RecoveryReasonCode::LocalLinkUnexpected]);
            }
            match remote {
                RemoteEvidence::RecordNotFound => {
                    (R::RetryRemoteCancellation, vec![RecoveryReasonCode::RemoteRecordNotFound])
                }
                RemoteEvidence::Unavailable { .. } => {
                    (R::WaitForRemoteEvidence, vec![RecoveryReasonCode::RemoteUnavailable])
                }
                RemoteEvidence::Found(record) => match record.status {
                    S::Preparing | S::Prepared => (R::RetryRemoteCancellation, vec![]),
                    S::Cancelled => trust(not_comparable, R::CompleteLocalSettlement),
                    S::Active => (R::Conflict, vec![]),
                },
            }
        }
        EnrollmentOperationState::RecoveryBlocked => {
            unreachable!("classify_enrollment already handled RecoveryBlocked")
        }
    }
}

pub fn diagnose_enrollment(
    local: &EnrollmentLocalEvidence,
    remote: &RemoteEvidence<EnrollmentOperationRecord>,
) -> RecoveryDiagnosis {
    let qualification = qualify_enrollment(local, remote);
    classify_enrollment(local, remote, qualification)
}

// ============================== Membership ==============================

fn membership_remote_state(
    remote: &RemoteEvidence<MembershipOperationRecord>,
) -> RecoveryRemoteState {
    match remote {
        RemoteEvidence::Found(record) => RecoveryRemoteState::Membership(record.status),
        RemoteEvidence::RecordNotFound => RecoveryRemoteState::RecordNotFound,
        RemoteEvidence::Unavailable { category } => {
            RecoveryRemoteState::Unavailable { category: *category }
        }
    }
}

/// Independent of identity -- see `enrollment_result_shape_issue`'s
/// identical reasoning. A `revoke` commit's own result payload may be
/// empty (the Worker doesn't record an affected-groups list for it), but
/// MUST exist; a `remove-device` commit's result must additionally carry
/// `affected_group_ids` (needed to latch durability); a rejected commit
/// must carry no result payload at all.
fn membership_result_shape_issue(
    action: MembershipOperationAction,
    record: &MembershipOperationRecord,
) -> Option<RecoveryReasonCode> {
    match record.status {
        MembershipRemoteStatus::Committed => match action {
            MembershipOperationAction::Revoke => {
                if record.result.is_none() {
                    Some(RecoveryReasonCode::RemoteResultIncomplete)
                } else {
                    None
                }
            }
            MembershipOperationAction::RemoveDevice => match &record.result {
                Some(result) if result.affected_group_ids.is_some() => None,
                _ => Some(RecoveryReasonCode::RemoteResultIncomplete),
            },
        },
        MembershipRemoteStatus::DefinitelyRejected => {
            if record.result.is_some() {
                Some(RecoveryReasonCode::RemoteResultConflict)
            } else {
                None
            }
        }
    }
}

fn membership_durability_overlay(
    local: &MembershipLocalEvidence,
    reasons: &mut Vec<RecoveryReasonCode>,
) {
    if local.operation.durability_scope == MembershipDurabilityScope::Unknown {
        reasons.push(RecoveryReasonCode::DurabilityScopeUnknown);
    } else {
        let missing = local
            .operation
            .latch_group_ids
            .iter()
            .any(|group_id| !local.present_durability_latches.contains(group_id));
        if missing {
            reasons.push(RecoveryReasonCode::DurabilityLatchMissing);
        }
    }
}

fn classify_membership(
    local: &MembershipLocalEvidence,
    remote: &RemoteEvidence<MembershipOperationRecord>,
    qualification: MembershipEvidenceQualification,
) -> RecoveryDiagnosis {
    let key = RecoveryOperationKey {
        domain: RecoveryDomain::Membership,
        operation_id: local.operation.operation_id.clone(),
    };
    let local_state = RecoveryLocalState::Membership(local.operation.state);
    let remote_state = membership_remote_state(remote);
    let wrap = || RecoveryEvidenceQualification::Membership(qualification.clone());

    if local.operation.state == MembershipOperationState::RecoveryBlocked {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::ManualInvestigation,
            vec![RecoveryReasonCode::RecoveryBlocked],
        );
    }

    if is_remote_mismatch(&qualification.remote_identity) {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::Conflict,
            vec![RecoveryReasonCode::RemoteIdentityMismatch],
        );
    }
    if is_remote_not_comparable(&qualification.remote_identity) {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::ManualInvestigation,
            vec![RecoveryReasonCode::RemoteIdentityNotComparable],
        );
    }

    if let RemoteEvidence::Found(record) = remote {
        if let Some(reason) = membership_result_shape_issue(local.operation.action, record) {
            return build_diagnosis(
                key,
                local_state,
                remote_state,
                wrap(),
                RecoveryRecommendation::ManualInvestigation,
                vec![reason],
            );
        }
    }

    let (recommendation, mut reasons) = classify_membership_state_matrix(local, remote);
    membership_durability_overlay(local, &mut reasons);
    build_diagnosis(
        key,
        local_state,
        remote_state,
        wrap(),
        recommendation,
        sorted_dedup_reasons(reasons),
    )
}

fn classify_membership_state_matrix(
    local: &MembershipLocalEvidence,
    remote: &RemoteEvidence<MembershipOperationRecord>,
) -> (RecoveryRecommendation, Vec<RecoveryReasonCode>) {
    use MembershipRemoteStatus as S;
    use RecoveryRecommendation as R;

    match local.operation.state {
        MembershipOperationState::Prepared | MembershipOperationState::Ambiguous => match remote {
            RemoteEvidence::RecordNotFound => {
                (R::RetrySameRemoteRequest, vec![RecoveryReasonCode::RemoteRecordNotFound])
            }
            RemoteEvidence::Unavailable { .. } => {
                (R::WaitForRemoteEvidence, vec![RecoveryReasonCode::RemoteUnavailable])
            }
            RemoteEvidence::Found(record) => match record.status {
                S::Committed => (
                    R::CompleteLocalSettlement,
                    vec![RecoveryReasonCode::RemoteCommittedLocalUnsettled],
                ),
                S::DefinitelyRejected => (R::CompleteLocalSettlement, vec![]),
            },
        },
        MembershipOperationState::LocalSettlementPending => {
            if local.operation.durability_scope == MembershipDurabilityScope::Known {
                match remote {
                    RemoteEvidence::RecordNotFound => (R::CompleteLocalSettlement, vec![]),
                    RemoteEvidence::Unavailable { .. } => (R::CompleteLocalSettlement, vec![]),
                    RemoteEvidence::Found(record) => match record.status {
                        S::Committed => (R::CompleteLocalSettlement, vec![]),
                        S::DefinitelyRejected => (R::Conflict, vec![]),
                    },
                }
            } else {
                match remote {
                    RemoteEvidence::RecordNotFound => {
                        (R::WaitForRemoteEvidence, vec![RecoveryReasonCode::RemoteRecordNotFound])
                    }
                    RemoteEvidence::Unavailable { .. } => {
                        (R::WaitForRemoteEvidence, vec![RecoveryReasonCode::RemoteUnavailable])
                    }
                    RemoteEvidence::Found(record) => match record.status {
                        S::DefinitelyRejected => (R::Conflict, vec![]),
                        S::Committed => {
                            let affected_present = record
                                .result
                                .as_ref()
                                .and_then(|r| r.affected_group_ids.as_ref())
                                .is_some();
                            if affected_present {
                                (R::CompleteLocalSettlement, vec![])
                            } else {
                                (
                                    R::ManualInvestigation,
                                    vec![RecoveryReasonCode::RemoteResultIncomplete],
                                )
                            }
                        }
                    },
                }
            }
        }
        MembershipOperationState::Completed => match remote {
            RemoteEvidence::RecordNotFound | RemoteEvidence::Unavailable { .. } => {
                (R::CompleteLocalSettlement, vec![])
            }
            RemoteEvidence::Found(record) => match record.status {
                S::Committed => (R::CompleteLocalSettlement, vec![]),
                S::DefinitelyRejected => (R::Conflict, vec![]),
            },
        },
        MembershipOperationState::DefinitelyRejected => match remote {
            RemoteEvidence::RecordNotFound | RemoteEvidence::Unavailable { .. } => {
                (R::CompleteLocalSettlement, vec![])
            }
            RemoteEvidence::Found(record) => match record.status {
                S::DefinitelyRejected => (R::CompleteLocalSettlement, vec![]),
                S::Committed => (R::Conflict, vec![]),
            },
        },
        MembershipOperationState::RecoveryBlocked => {
            unreachable!("classify_membership already handled RecoveryBlocked")
        }
    }
}

pub fn diagnose_membership(
    local: &MembershipLocalEvidence,
    remote: &RemoteEvidence<MembershipOperationRecord>,
) -> RecoveryDiagnosis {
    let qualification = qualify_membership(local, remote);
    classify_membership(local, remote, qualification)
}

// ============================== Role loss ================================

fn role_loss_remote_state(remote: &RemoteEvidence<RoleLossOperationRecord>) -> RecoveryRemoteState {
    match remote {
        RemoteEvidence::Found(_) => RecoveryRemoteState::RoleLossCommitted,
        RemoteEvidence::RecordNotFound => RecoveryRemoteState::RecordNotFound,
        RemoteEvidence::Unavailable { category } => {
            RecoveryRemoteState::Unavailable { category: *category }
        }
    }
}

fn classify_role_loss(
    local: &RoleLossLocalEvidence,
    remote: &RemoteEvidence<RoleLossOperationRecord>,
    qualification: RoleLossEvidenceQualification,
) -> RecoveryDiagnosis {
    let key = RecoveryOperationKey {
        domain: RecoveryDomain::RoleLoss,
        operation_id: local.operation.operation_id.clone(),
    };
    let local_state = RecoveryLocalState::RoleLoss(local.operation.state);
    let remote_state = role_loss_remote_state(remote);
    let wrap = || RecoveryEvidenceQualification::RoleLoss(qualification.clone());

    // The reserved, never-written-by-production `Revoke` action wins over
    // everything else -- this build's own compensation logic (asserting
    // eager) is specific to Demote/Unlink; acting on a Revoke row would be
    // acting on a shape this build doesn't actually know how to recover.
    if local.operation.action == RoleLossAction::Revoke {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::ManualInvestigation,
            vec![RecoveryReasonCode::UnsupportedRoleLossAction],
        );
    }

    if is_remote_mismatch(&qualification.remote_identity) {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::Conflict,
            vec![RecoveryReasonCode::RemoteIdentityMismatch],
        );
    }
    if is_remote_not_comparable(&qualification.remote_identity) {
        return build_diagnosis(
            key,
            local_state,
            remote_state,
            wrap(),
            RecoveryRecommendation::ManualInvestigation,
            vec![RecoveryReasonCode::RemoteIdentityNotComparable],
        );
    }

    if let RemoteEvidence::Found(record) = remote {
        if let Some(local_generation) = local.operation.worker_membership_generation {
            if record.membership_generation != local_generation {
                return build_diagnosis(
                    key,
                    local_state,
                    remote_state,
                    wrap(),
                    RecoveryRecommendation::Conflict,
                    vec![RecoveryReasonCode::RemoteResultConflict],
                );
            }
        }
    }

    let (recommendation, mut reasons) = classify_role_loss_state_matrix(local, remote);

    // Local link qualification is a REASON, never a compensation gate --
    // see this module's own doc comment for why role-loss deliberately
    // does not apply enrollment/membership's "local mismatch -> Conflict"
    // rule: the safe-direction Worker-side compensation (reassert eager)
    // does not read or depend on the local link row at all.
    match &qualification.link {
        ObservationQualification::ConfirmedAbsent => {
            reasons.push(RecoveryReasonCode::LocalLinkMissing)
        }
        ObservationQualification::Mismatch { .. } => {
            reasons.push(RecoveryReasonCode::LocalLinkIdentityMismatch)
        }
        ObservationQualification::Invalid { .. } => {
            reasons.push(RecoveryReasonCode::LocalLinkInvalid)
        }
        ObservationQualification::Ambiguous { .. } => {
            reasons.push(RecoveryReasonCode::LocalLinkAmbiguous)
        }
        ObservationQualification::Exact => {}
    }

    build_diagnosis(
        key,
        local_state,
        remote_state,
        wrap(),
        recommendation,
        sorted_dedup_reasons(reasons),
    )
}

fn classify_role_loss_state_matrix(
    local: &RoleLossLocalEvidence,
    remote: &RemoteEvidence<RoleLossOperationRecord>,
) -> (RecoveryRecommendation, Vec<RecoveryReasonCode>) {
    use RecoveryRecommendation as R;

    match local.operation.state {
        RoleLossOperationState::Prepared
        | RoleLossOperationState::WorkerCommitted
        | RoleLossOperationState::Compensating => match remote {
            RemoteEvidence::Found(_) => (R::ContinueAutomaticCompensation, vec![]),
            RemoteEvidence::RecordNotFound => (
                R::ContinueAutomaticCompensation,
                vec![
                    RecoveryReasonCode::RemoteRecordNotFound,
                    RecoveryReasonCode::LegacyRoleLossReceiptUncertain,
                    RecoveryReasonCode::RoleLossCompensationRequired,
                ],
            ),
            RemoteEvidence::Unavailable { .. } => (
                R::ContinueAutomaticCompensation,
                vec![
                    RecoveryReasonCode::RemoteUnavailable,
                    RecoveryReasonCode::RoleLossCompensationRequired,
                ],
            ),
        },
        RoleLossOperationState::LocalCommitted | RoleLossOperationState::Completed => {
            (R::CompleteLocalSettlement, vec![])
        }
    }
}

pub fn diagnose_role_loss(
    local: &RoleLossLocalEvidence,
    remote: &RemoteEvidence<RoleLossOperationRecord>,
) -> RecoveryDiagnosis {
    let qualification = qualify_role_loss(local, remote);
    classify_role_loss(local, remote, qualification)
}
