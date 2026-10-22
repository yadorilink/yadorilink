//! Assembling a single stable [`RecoveryDiagnosis`] for one
//! operation, combining the local recovery snapshot with the remote
//! evidence lookup and the diagnosis classifier.
//!
//! The whole point of this module is the ONE property none of those
//! layers could provide alone: the remote lookup takes real time (a real
//! HTTP round trip), and an automatic reconciler running concurrently on
//! another pooled connection can mutate the SAME operation's local
//! evidence while that lookup is in flight. Combining a "before" local
//! snapshot with remote evidence gathered against it, and a diagnosis
//! classified from both, is only trustworthy if the local evidence is
//! PROVEN not to have changed in between -- so this module always re-reads
//! a fresh local snapshot after the remote lookup returns and compares the
//! two full evidence values directly (never just their revision
//! fingerprints, which are a cheap log/display aid, not the correctness
//! check itself -- see [`crate::recovery::LocalRecoveryEvidence::revision`]'s
//! own doc comment). Any difference discards the diagnosis entirely rather
//! than combining stale local evidence with fresh remote evidence.
//!
//! Still strictly read-only and still only depends on
//! [`crate::recovery_evidence::RecoveryEvidenceSource`] for remote reads --
//! that trait carries no mutation method at all (see its own module doc),
//! so nothing in this file could call a coordination-plane mutation even
//! by accident. Exactly one remote lookup per call: no retry loop, no
//! unbounded wait on a reconciler that keeps moving the target.

use crate::recovery::{
    LocalRecoveryEvidence, RecoveryLocalSnapshot, RecoveryOperationKey, RecoveryOperationSummary,
    RecoverySnapshotRevision,
};
use crate::sync_error::SyncError;
use yadorilink_replica_domain::recovery::RecoveryDomain;

use crate::coordination_client::{
    EnrollmentOperationRecord, MembershipOperationRecord, RoleLossOperationRecord,
};
use crate::recovery_evidence::{RecoveryEvidenceSource, RemoteEvidence};
use crate::replica_coordinator::ReplicaCoordinator;

use super::{diagnose_enrollment, diagnose_membership, diagnose_role_loss, RecoveryDiagnosis};

/// What a re-read local snapshot looked like AFTER the remote lookup
/// returned, when it turned out to differ from the "before" snapshot --
/// carried on [`StableDiagnosisOutcome::LocalEvidenceChanged`] purely for
/// the caller's own logging/display, never re-used to build a diagnosis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SnapshotAfterLookup {
    Found { revision: RecoverySnapshotRevision },
    OperationNotFound,
    InvalidOperation { raw_state: Option<String>, detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StableDiagnosisOutcome {
    Diagnosed {
        /// The SAME "before" snapshot's own operation row, normalized --
        /// never re-read from a later, separate `inventory()`/snapshot
        /// call, so this can never describe a different point in time
        /// than `diagnosis` itself does.
        operation: Box<RecoveryOperationSummary>,
        diagnosis: RecoveryDiagnosis,
        local_revision: RecoverySnapshotRevision,
    },
    /// No journal row existed for this operation in the initial ("before")
    /// snapshot -- no remote lookup was attempted.
    OperationNotFound { key: RecoveryOperationKey },
    /// The journal row exists but could not be strictly decoded, observed
    /// BEFORE any remote lookup was attempted.
    InvalidOperation { key: RecoveryOperationKey, raw_state: Option<String>, detail: String },
    /// The local evidence this diagnosis would have been built from
    /// changed between the "before" snapshot (used to decide what to look
    /// up) and the "after" snapshot (re-read once the remote lookup
    /// returned) -- no diagnosis is produced; the caller should re-run.
    LocalEvidenceChanged {
        key: RecoveryOperationKey,
        before: RecoverySnapshotRevision,
        after: SnapshotAfterLookup,
    },
}

/// The remote evidence lookup actually performed, tagged by domain --
/// internal to this module only. [`diagnose_stable`] always looks up
/// EXACTLY the domain `key.domain` names (never guessed from the local
/// row's own shape), so this can never disagree with `before_evidence`'s
/// own domain unless something outside this module's own invariants broke.
enum DomainRemoteEvidence {
    Enrollment(RemoteEvidence<EnrollmentOperationRecord>),
    Membership(RemoteEvidence<MembershipOperationRecord>),
    RoleLoss(RemoteEvidence<RoleLossOperationRecord>),
}

async fn lookup_for_domain<S: RecoveryEvidenceSource>(
    evidence_source: &S,
    key: &RecoveryOperationKey,
) -> DomainRemoteEvidence {
    match key.domain {
        RecoveryDomain::Enrollment => {
            DomainRemoteEvidence::Enrollment(evidence_source.lookup_enrollment(key).await)
        }
        RecoveryDomain::Membership => {
            DomainRemoteEvidence::Membership(evidence_source.lookup_membership(key).await)
        }
        RecoveryDomain::RoleLoss => {
            DomainRemoteEvidence::RoleLoss(evidence_source.lookup_role_loss(key).await)
        }
    }
}

/// Assembles one stable [`RecoveryDiagnosis`] for `key`. See this module's
/// own doc comment for the full before/lookup/after/compare sequence and
/// why it is the only way to make combining local and remote evidence
/// trustworthy. `replica_coordinator` is only ever asked for two
/// independent, already-complete snapshots
/// (`ReplicaCoordinator::recovery_snapshot_reader`'s own
/// `recovery_local_snapshot`) -- no SQLite transaction is held across the
/// `.await` in between.
pub(crate) async fn diagnose_stable<S>(
    replica_coordinator: &ReplicaCoordinator,
    evidence_source: &S,
    key: &RecoveryOperationKey,
) -> Result<StableDiagnosisOutcome, SyncError>
where
    S: RecoveryEvidenceSource,
{
    let before_evidence =
        match replica_coordinator.recovery_snapshot_reader().recovery_local_snapshot(key)? {
            RecoveryLocalSnapshot::Found(evidence) => *evidence,
            RecoveryLocalSnapshot::OperationNotFound { key } => {
                return Ok(StableDiagnosisOutcome::OperationNotFound { key });
            }
            RecoveryLocalSnapshot::InvalidOperation { key, raw_state, detail } => {
                return Ok(StableDiagnosisOutcome::InvalidOperation { key, raw_state, detail });
            }
        };
    let before_revision = before_evidence.revision();
    let operation = before_evidence.summary();

    let remote = lookup_for_domain(evidence_source, key).await;

    let after_evidence =
        match replica_coordinator.recovery_snapshot_reader().recovery_local_snapshot(key)? {
            RecoveryLocalSnapshot::Found(evidence) => *evidence,
            RecoveryLocalSnapshot::OperationNotFound { .. } => {
                return Ok(StableDiagnosisOutcome::LocalEvidenceChanged {
                    key: key.clone(),
                    before: before_revision,
                    after: SnapshotAfterLookup::OperationNotFound,
                });
            }
            RecoveryLocalSnapshot::InvalidOperation { raw_state, detail, .. } => {
                return Ok(StableDiagnosisOutcome::LocalEvidenceChanged {
                    key: key.clone(),
                    before: before_revision,
                    after: SnapshotAfterLookup::InvalidOperation { raw_state, detail },
                });
            }
        };

    // The correctness check is this full-value comparison, not the
    // revisions -- see this module's own doc comment. `revision()` below
    // is computed only because `LocalEvidenceChanged` carries it for the
    // caller's own logging/display.
    if before_evidence != after_evidence {
        return Ok(StableDiagnosisOutcome::LocalEvidenceChanged {
            key: key.clone(),
            before: before_revision,
            after: SnapshotAfterLookup::Found { revision: after_evidence.revision() },
        });
    }

    let diagnosis = match (before_evidence, remote) {
        (LocalRecoveryEvidence::Enrollment(local), DomainRemoteEvidence::Enrollment(remote)) => {
            diagnose_enrollment(&local, &remote)
        }
        (LocalRecoveryEvidence::Membership(local), DomainRemoteEvidence::Membership(remote)) => {
            diagnose_membership(&local, &remote)
        }
        (LocalRecoveryEvidence::RoleLoss(local), DomainRemoteEvidence::RoleLoss(remote)) => {
            diagnose_role_loss(&local, &remote)
        }
        _ => {
            // `key.domain` alone selected both the local snapshot's domain
            // (via `recovery_local_snapshot`) and the remote lookup's
            // domain (via `lookup_for_domain`), so this is unreachable
            // through this module's own call path -- but a pure function
            // must never assume its own future callers stay that
            // disciplined. This is not a legitimate, expected outcome the
            // way `InvalidOperation`/`OperationNotFound` are (both describe
            // real states a journal row can actually be in) -- it means
            // this module's OWN domain-routing invariant broke, so it is a
            // genuine internal error, not a diagnosable operation state.
            return Err(SyncError::CorruptState(
                "recovery diagnosis: local and remote evidence named different domains".to_string(),
            ));
        }
    };

    Ok(StableDiagnosisOutcome::Diagnosed {
        operation: Box::new(operation),
        diagnosis,
        local_revision: before_revision,
    })
}

#[cfg(test)]
mod tests;
