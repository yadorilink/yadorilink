//! The facts the repair sweep places a row by.
//!
//! For each row the sweep acts on, the facts it has already read are gathered into
//! [`CrashFacts`]; `classify` places them and `verdict` (in `yadorilink-replica-domain`) names the
//! action the sweep then carries out. The intent's phase is read through the lane reads that
//! already fold in the proof relation (a landed write with no proof published since, a
//! flush-pending write whose proof still stands).

use yadorilink_replica_domain::crash_state::{
    CrashFacts, DiskObservation, IntentKind, IntentPhase, OpenIntent, ProofRelation, RootKind,
};
use yadorilink_replica_domain::session_state::MaterializationState;

use crate::materialization_execution::{
    MaterializationExecutionError, MaterializationExecutionPort, MaterializationIntentKind,
};

/// What the sweep saw at the path.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DiskSeen {
    Absent,
    /// The object the row describes.
    Spec,
    /// Something else is there.
    Present,
}

/// Builds the facts of one row from the sweep's own reads. The sweep ties a temp file to its row
/// through the intent's own pointer (`write_intent_tmp_path`), which is an input to the verdict,
/// not a fact about the row's phase.
#[allow(
    clippy::too_many_arguments,
    reason = "each argument is an observation the sweep already made for this row"
)]
pub(crate) fn observed_crash_facts(
    state: &dyn MaterializationExecutionPort,
    group_id: &str,
    path: &str,
    out_path: &std::path::Path,
    row: MaterializationState,
    intent_kind: Option<MaterializationIntentKind>,
    disk: DiskSeen,
    proof: ProofRelation,
) -> Result<CrashFacts, MaterializationExecutionError> {
    let intent = match intent_kind {
        None => None,
        Some(MaterializationIntentKind::Delete) => {
            Some(OpenIntent { kind: IntentKind::Delete, phase: IntentPhase::Prepared })
        }
        Some(MaterializationIntentKind::Materialize) => {
            let phase = if state.flush_pending_proof_identity(group_id, path)?.is_some() {
                IntentPhase::FlushPending
            } else if state.write_landed_unproven(group_id, path)? {
                IntentPhase::Landed
            } else {
                IntentPhase::Prepared
            };
            Some(OpenIntent { kind: IntentKind::Write, phase })
        }
    };
    let disk = match disk {
        DiskSeen::Absent => DiskObservation::Absent,
        DiskSeen::Spec => DiskObservation::Spec,
        DiskSeen::Present => {
            let torn = match state.flush_pending_proof_identity(group_id, path)? {
                Some(Some(proof)) => {
                    yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(out_path)
                        .is_ok_and(|observed| observed == proof)
                }
                _ => false,
            };
            if torn && intent_kind == Some(MaterializationIntentKind::Materialize) {
                DiskObservation::TornSpec
            } else if intent_kind == Some(MaterializationIntentKind::Materialize)
                && state.disk_is_untouched_pre_image(group_id, path, out_path)?
            {
                DiskObservation::PreImage
            } else {
                DiskObservation::Other
            }
        }
    };
    Ok(CrashFacts {
        root: RootKind::Plain,
        intent,
        row,
        proof,
        // Advisory: it only tells an idle row from one whose proof still owes an obligation (both
        // are left alone), so a failed read must not stop a recovery the row needs.
        obligation_open: state.has_unsettled_projection_obligation(group_id, path).unwrap_or(false),
        disk,
    })
}
