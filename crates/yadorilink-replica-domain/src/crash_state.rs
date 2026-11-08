//! The crash states of a write operation on a plain root, and the pure
//! function that places the persisted facts of one path into exactly one of
//! them.
//!
//! A write operation (materialize or delete) leaves durable facts at each step: an intent row
//! with its kind and phase, the materialization row, a proof under the mutation fence, a
//! projection obligation, and whatever the disk shows. [`classify`] maps those facts to a
//! [`CrashState`]; the states are the only situations recovery has to handle, and [`verdict`]
//! picks the one recovery action for each. A fact combination no state describes classifies to
//! [`CrashState::Unplaced`], which is reported rather than guessed at.

use crate::session_state::MaterializationState;

/// What an open intent is for. These are the persisted `kind` values.
///
/// Eviction, restore and the repair's own quarantine are not kinds of intent here: an eviction is
/// the `Evicting` row state with its own quarantine name, a restore has its own journal, and the
/// repair quarantine opens an ordinary write intent. None of them leaves an intent of its own
/// kind behind for this classifier to meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntentKind {
    /// Content is being written to the path.
    Write,
    /// The path is being removed.
    Delete,
}

impl IntentKind {
    pub const ALL: [Self; 2] = [Self::Write, Self::Delete];

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Delete => "delete",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_db_str() == value)
    }
}

/// How far an open intent got. These are the persisted `phase` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntentPhase {
    /// Intent and fence are durable; nothing else is recorded.
    Prepared,
    /// The new name is durable (set only after the directory sync, or after
    /// the batch barrier when names are deferred). No proof yet.
    Landed,
    /// The proof is published; the flush barrier still owes the bytes.
    FlushPending,
}

impl IntentPhase {
    pub const ALL: [Self; 3] = [Self::Prepared, Self::Landed, Self::FlushPending];

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Landed => "landed",
            Self::FlushPending => "flush_pending",
        }
    }

    pub fn from_db_str(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|phase| phase.as_db_str() == value)
    }
}

/// The open intent of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenIntent {
    pub kind: IntentKind,
    pub phase: IntentPhase,
}

/// Whether a proof of the row's version stands under the live fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofRelation {
    /// No proof, or one the fence has since invalidated.
    NotCurrent,
    Current,
}

/// What the disk shows at the path, relative to the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiskObservation {
    Absent,
    /// The object this device put there before the operation, untouched.
    PreImage,
    /// The object the row's version describes.
    Spec,
    /// The object the operation placed, with its data not stable.
    TornSpec,
    /// Anything else: bytes a user (or another process) put there.
    Other,
}

impl DiskObservation {
    pub const ALL: [Self; 5] =
        [Self::Absent, Self::PreImage, Self::Spec, Self::TornSpec, Self::Other];
}

/// The kind of root the path is under. Only a plain root has a
/// daemon-written visible name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootKind {
    Plain,
    Provider,
}

/// Everything recovery knows about one path before it touches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashFacts {
    pub root: RootKind,
    pub intent: Option<OpenIntent>,
    pub row: MaterializationState,
    pub proof: ProofRelation,
    pub obligation_open: bool,
    pub disk: DiskObservation,
}

/// The named crash states. See the write-operation design for each. The numbers are the design's
/// and are not renumbered: X2, X9, X10 and X12 are not states (nothing leaves them behind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrashState {
    /// No intent, nothing owed.
    X0Idle,
    X1Prepared,
    X3RenamedUnrecorded,
    X4LandedDurable,
    X5ProvenFlushPending,
    X6ProvenObligationOpen,
    X7Diverged,
    X8DeleteInFlight,
    /// A delete intent whose removal never ran: the file on disk is still the row's own.
    X8bDeleteNotRemoved,
    /// A write intent still open while a proof already stands under the live fence, with the
    /// disk either the version or gone. A prepare bumps the fence, so a proof that survived it
    /// means the write never began: the lane that opened the intent (recording a version without
    /// its content over an older object) left it behind, or a healing lane published a proof
    /// without clearing it. Nothing of this write is on disk, so the path is judged as if the
    /// intent were not there: the version stands, prove it; the name is gone, someone removed it.
    X13IntentOverStandingProof,
    /// A transient row, or a bumped fence, with no intent.
    X11TransientNoIntent,
    /// The facts fit no state: a bug in the recording or in the table.
    Unplaced,
}

/// What recovery does to a path. `Leave` writes nothing for it: a healthy
/// row, a hand-off to the local-change capture or to the operation that owns
/// the path, or a deferral to a later pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryAction {
    Leave,
    /// Publish the proof for an object that is already the version.
    Prove,
    /// Write the object again from local blocks, in place.
    Rebuild,
    /// Move the bytes at the path aside as a conflict copy first.
    Quarantine,
    /// The version's bytes are not here: the row goes back to a retriable
    /// state and the path is fetched again.
    Demote,
    /// Same as `Demote`, over an untouched pre-image that stays in place.
    StandDown,
    /// The durable name is gone: the user removed it; journal that. Also the answer for a delete
    /// whose removal already took the recorded object from the name, when something else is
    /// there now: the delete is done, and what is there is the person's, left as it is.
    RecordRemoval,
}

/// What recovery has observed beyond the facts that place the state: the inputs that decide
/// between the actions a state allows. Each is false until the sweep has looked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RepairInputs {
    /// Every block of the version is in the local store.
    pub blocks_here: bool,
    /// The intent names a temp file that reads back as exactly the version, so the write can be
    /// finished from it.
    pub finishable_temp: bool,
    /// The write placed the name durably and it is gone now: the user removed it.
    pub removed_by_user: bool,
}

/// The one action recovery takes at a path: a pure function of the state, the facts and the
/// inputs, so each state's policy is one row and a test can read it.
///
/// `Leave` means the path is handed on (to capture, to the lane that owns it, or to a later
/// pass). The sweep may also leave a path for reasons the verdict does not model (a row that
/// moved under it, a flush that failed); only an action it does take is compared.
pub fn verdict(state: CrashState, facts: &CrashFacts, inputs: RepairInputs) -> RecoveryAction {
    use CrashState::*;
    use DiskObservation as D;
    use RecoveryAction::*;
    // The bytes of the version are somewhere on this device to write from.
    // (A rebuild that is chosen and then fails falls back to demoting the row in the executor; that
    // is the executor's recovery from an error, not a row of this table.)
    let rebuild_or_demote =
        if inputs.finishable_temp || inputs.blocks_here { Rebuild } else { Demote };
    match state {
        // Nothing owed, or an operation that owns the path (a delete settles its own removal).
        X0Idle | X6ProvenObligationOpen | X8DeleteInFlight => Leave,
        Unplaced => Leave,
        // The file is the row's own and the removal never ran: re-prove it. Repair never unlinks.
        X8bDeleteNotRemoved => Prove,
        // The write never began; the disk decides as it would with no intent: the version
        // stands (prove it again, which clears the intent), or the name was removed.
        X13IntentOverStandingProof => {
            if facts.disk == D::Spec {
                Prove
            } else if inputs.removed_by_user {
                RecordRemoval
            } else {
                rebuild_or_demote
            }
        }
        // Bytes that are not the row's under a delete: the delete's removal already took the
        // recorded object from the name, so it is done. What is there now was put there by a person
        // after that; it is neither removed nor moved aside, and the normal capture path takes it
        // as a new local change.
        X7Diverged if facts.intent.is_some_and(|i| i.kind == IntentKind::Delete) => RecordRemoval,
        // Bytes that are not the row's under a write: moved aside as a conflict copy before
        // anything is written.
        X7Diverged => Quarantine,
        // No intent: only an object that already is the version is proven; anything else is
        // capture's or the lane's.
        X11TransientNoIntent => {
            if facts.disk == D::Spec {
                Prove
            } else {
                Leave
            }
        }
        // The previous version still stands. A temp or blocks to write from: write. Otherwise the
        // version has to be fetched and the previous version stays meanwhile.
        X1Prepared => {
            if inputs.finishable_temp || inputs.blocks_here {
                Rebuild
            } else {
                StandDown
            }
        }
        X3RenamedUnrecorded | X5ProvenFlushPending => {
            if facts.disk == D::Spec {
                Prove
            } else {
                rebuild_or_demote
            }
        }
        X4LandedDurable => {
            if facts.disk == D::Spec {
                Prove
            } else if inputs.removed_by_user {
                RecordRemoval
            } else {
                rebuild_or_demote
            }
        }
    }
}

/// Places `facts` in exactly one crash state.
pub fn classify(facts: &CrashFacts) -> CrashState {
    use CrashState::*;
    use DiskObservation as D;
    let state = match facts.intent {
        None => match (facts.row, facts.proof) {
            (MaterializationState::Hydrating | MaterializationState::Evicting, _)
            | (MaterializationState::Present, ProofRelation::NotCurrent) => X11TransientNoIntent,
            (_, ProofRelation::Current) if facts.obligation_open => X6ProvenObligationOpen,
            _ => X0Idle,
        },
        // Bytes that are not the row's under a delete intent are a divergence (an edit made
        // while the delete was in flight), not a delete to settle.
        Some(OpenIntent { kind: IntentKind::Delete, .. }) => match facts.disk {
            D::Other => X7Diverged,
            D::Spec => X8bDeleteNotRemoved,
            _ => X8DeleteInFlight,
        },
        Some(OpenIntent { kind: IntentKind::Write, phase }) => match (phase, facts.disk) {
            (_, D::Other) => X7Diverged,
            (_, D::PreImage) => X1Prepared,
            // A proof that lapsed (the row moved to another version, the fence moved) leaves the
            // write unrecorded whatever phase it had reached; a flush-pending write is the one
            // whose proof stood when its rename was left unflushed.
            (
                IntentPhase::Prepared | IntentPhase::FlushPending,
                D::Spec | D::TornSpec | D::Absent,
            ) if facts.proof == ProofRelation::NotCurrent => X3RenamedUnrecorded,
            (IntentPhase::Landed, D::Spec | D::Absent)
                if facts.proof == ProofRelation::NotCurrent =>
            {
                X4LandedDurable
            }
            (IntentPhase::FlushPending, D::Spec | D::TornSpec | D::Absent)
                if facts.proof == ProofRelation::Current =>
            {
                X5ProvenFlushPending
            }
            (IntentPhase::Prepared | IntentPhase::Landed, D::Spec | D::Absent)
                if facts.proof == ProofRelation::Current =>
            {
                X13IntentOverStandingProof
            }
            _ => Unplaced,
        },
    };
    // A provider root has no daemon-written visible name to be in the
    // rename-unrecorded, landed or flush-pending states.
    if facts.root == RootKind::Provider
        && matches!(
            state,
            X3RenamedUnrecorded
                | X4LandedDurable
                | X5ProvenFlushPending
                | X13IntentOverStandingProof
        )
    {
        return Unplaced;
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROWS: [MaterializationState; 4] = [
        MaterializationState::Remote,
        MaterializationState::Hydrating,
        MaterializationState::Present,
        MaterializationState::Evicting,
    ];
    const PROOFS: [ProofRelation; 2] = [ProofRelation::NotCurrent, ProofRelation::Current];

    /// The expected state, written out independently of `classify` as a
    /// table over the whole product of facts.
    fn expected(f: &CrashFacts) -> CrashState {
        use CrashState::*;
        use DiskObservation as D;
        use IntentPhase as P;
        let Some(intent) = f.intent else {
            let transient =
                matches!(f.row, MaterializationState::Hydrating | MaterializationState::Evicting)
                    || (f.row == MaterializationState::Present
                        && f.proof == ProofRelation::NotCurrent);
            return if transient {
                X11TransientNoIntent
            } else if f.proof == ProofRelation::Current && f.obligation_open {
                X6ProvenObligationOpen
            } else {
                X0Idle
            };
        };
        let plain = match intent.kind {
            IntentKind::Delete if f.disk == D::Other => X7Diverged,
            IntentKind::Delete if f.disk == D::Spec => X8bDeleteNotRemoved,
            IntentKind::Delete => X8DeleteInFlight,
            IntentKind::Write => {
                let current = f.proof == ProofRelation::Current;
                match (intent.phase, f.disk, current) {
                    (_, D::Other, _) => X7Diverged,
                    (_, D::PreImage, _) => X1Prepared,
                    (P::Prepared | P::FlushPending, _, false) => X3RenamedUnrecorded,
                    (P::Landed, D::Spec | D::Absent, false) => X4LandedDurable,
                    (P::FlushPending, D::Spec | D::TornSpec | D::Absent, true) => {
                        X5ProvenFlushPending
                    }
                    (P::Prepared | P::Landed, D::Spec | D::Absent, true) => {
                        X13IntentOverStandingProof
                    }
                    _ => Unplaced,
                }
            }
        };
        if f.root == RootKind::Provider
            && matches!(
                plain,
                X3RenamedUnrecorded
                    | X4LandedDurable
                    | X5ProvenFlushPending
                    | X13IntentOverStandingProof
            )
        {
            Unplaced
        } else {
            plain
        }
    }

    #[allow(clippy::excessive_nesting, reason = "a plain product over every fact value")]
    fn all_facts() -> Vec<CrashFacts> {
        let mut intents = vec![None];
        for kind in IntentKind::ALL {
            for phase in IntentPhase::ALL {
                intents.push(Some(OpenIntent { kind, phase }));
            }
        }
        let mut out = Vec::new();
        for root in [RootKind::Plain, RootKind::Provider] {
            for intent in &intents {
                for row in ROWS {
                    for proof in PROOFS {
                        for obligation_open in [false, true] {
                            for disk in DiskObservation::ALL {
                                out.push(CrashFacts {
                                    root,
                                    intent: *intent,
                                    row,
                                    proof,
                                    obligation_open,
                                    disk,
                                });
                            }
                        }
                    }
                }
            }
        }
        out
    }

    #[test]
    fn classifier_table_covers_the_whole_fact_product() {
        for facts in all_facts() {
            assert_eq!(classify(&facts), expected(&facts), "{facts:?}");
        }
    }

    #[test]
    fn named_states_are_each_reachable_on_a_plain_root() {
        use std::collections::HashSet;
        let seen: HashSet<CrashState> =
            all_facts().iter().filter(|f| f.root == RootKind::Plain).map(classify).collect();
        for state in [
            CrashState::X0Idle,
            CrashState::X1Prepared,
            CrashState::X3RenamedUnrecorded,
            CrashState::X4LandedDurable,
            CrashState::X5ProvenFlushPending,
            CrashState::X6ProvenObligationOpen,
            CrashState::X7Diverged,
            CrashState::X8DeleteInFlight,
            CrashState::X8bDeleteNotRemoved,
            CrashState::X11TransientNoIntent,
            CrashState::X13IntentOverStandingProof,
        ] {
            assert!(seen.contains(&state), "{state:?} is unreachable");
        }
    }

    fn inputs_product() -> Vec<RepairInputs> {
        let mut out = Vec::new();
        for blocks_here in [false, true] {
            for finishable_temp in [false, true] {
                for removed_by_user in [false, true] {
                    out.push(RepairInputs { blocks_here, finishable_temp, removed_by_user });
                }
            }
        }
        out
    }

    fn write_facts(phase: IntentPhase, disk: DiskObservation, proof: ProofRelation) -> CrashFacts {
        CrashFacts {
            root: RootKind::Plain,
            intent: Some(OpenIntent { kind: IntentKind::Write, phase }),
            row: MaterializationState::Present,
            proof,
            obligation_open: false,
            disk,
        }
    }

    fn verdict_of(facts: &CrashFacts, inputs: RepairInputs) -> RecoveryAction {
        verdict(classify(facts), facts, inputs)
    }

    /// Whatever the inputs, a verdict never writes where the state forbids it, proves only an
    /// object that is the version, and removes only a name that was durably placed.
    #[test]
    fn verdict_obeys_the_invariants_over_the_whole_product() {
        use CrashState::*;
        use RecoveryAction::*;
        for facts in all_facts() {
            let state = classify(&facts);
            for inputs in inputs_product() {
                let action = verdict(state, &facts, inputs);
                match state {
                    X0Idle | X6ProvenObligationOpen | X8DeleteInFlight | Unplaced => {
                        assert_eq!(action, Leave, "{state:?}")
                    }
                    _ => {}
                }
                if action == Prove {
                    assert!(
                        facts.disk == DiskObservation::Spec,
                        "{state:?} proves an object that is not the version: {facts:?}"
                    );
                }
                if action == RecordRemoval {
                    assert!(facts.disk != DiskObservation::Spec);
                    if state == X7Diverged {
                        assert!(
                            facts.intent.is_some_and(|i| i.kind == IntentKind::Delete),
                            "{facts:?}"
                        );
                    } else {
                        assert!(matches!(state, X4LandedDurable | X13IntentOverStandingProof));
                        assert!(inputs.removed_by_user, "{state:?}");
                    }
                }
                if matches!(action, Rebuild | Demote | StandDown) {
                    assert!(
                        matches!(state, X1Prepared | X3RenamedUnrecorded)
                            || matches!(
                                state,
                                X4LandedDurable | X5ProvenFlushPending | X13IntentOverStandingProof
                            ),
                        "{state:?} {action:?}"
                    );
                }
                if action == Rebuild {
                    assert!(inputs.blocks_here || inputs.finishable_temp, "{state:?}");
                }
                if action == StandDown {
                    assert!(!inputs.blocks_here && !inputs.finishable_temp, "{state:?}");
                }
                if action == Demote {
                    assert!(!inputs.blocks_here && !inputs.finishable_temp, "{state:?}");
                }
            }
        }
    }

    /// Repair never unlinks: under a delete intent it may re-prove a file that is still the
    /// row's own, nothing more; a name that is gone or unclear is the delete lane's to settle,
    /// and bytes that are not the row's are a divergence.
    #[test]
    fn a_delete_in_flight_proves_only_the_rows_own_file() {
        let facts = |disk| CrashFacts {
            root: RootKind::Plain,
            intent: Some(OpenIntent { kind: IntentKind::Delete, phase: IntentPhase::Prepared }),
            row: MaterializationState::Present,
            proof: ProofRelation::NotCurrent,
            obligation_open: false,
            disk,
        };
        let all = RepairInputs { blocks_here: true, finishable_temp: true, removed_by_user: true };
        assert_eq!(verdict_of(&facts(DiskObservation::Spec), all), RecoveryAction::Prove);
        for disk in [DiskObservation::Absent, DiskObservation::PreImage, DiskObservation::TornSpec]
        {
            assert_eq!(verdict_of(&facts(disk), all), RecoveryAction::Leave, "{disk:?}");
        }
        assert_eq!(verdict_of(&facts(DiskObservation::Other), all), RecoveryAction::RecordRemoval);
    }

    #[test]
    fn a_missing_name_is_a_removal_only_once_the_name_was_durably_placed() {
        let removed = RepairInputs { removed_by_user: true, ..RepairInputs::default() };
        let before =
            write_facts(IntentPhase::Prepared, DiskObservation::Absent, ProofRelation::NotCurrent);
        assert_eq!(classify(&before), CrashState::X3RenamedUnrecorded);
        assert_ne!(verdict_of(&before, removed), RecoveryAction::RecordRemoval);
        let landed =
            write_facts(IntentPhase::Landed, DiskObservation::Absent, ProofRelation::NotCurrent);
        assert_eq!(verdict_of(&landed, removed), RecoveryAction::RecordRemoval);
        assert_eq!(verdict_of(&landed, RepairInputs::default()), RecoveryAction::Demote);
    }

    /// A write interrupted over the previous version: a temp that reads back as the version, or
    /// the blocks, is written from; with neither the previous version stays and the new one is
    /// fetched.
    #[test]
    fn an_interrupted_write_over_the_previous_version_finishes_or_stands_down() {
        let facts = write_facts(
            IntentPhase::Prepared,
            DiskObservation::PreImage,
            ProofRelation::NotCurrent,
        );
        assert_eq!(classify(&facts), CrashState::X1Prepared);
        let temp = RepairInputs { finishable_temp: true, ..RepairInputs::default() };
        let blocks = RepairInputs { blocks_here: true, ..RepairInputs::default() };
        assert_eq!(verdict_of(&facts, temp), RecoveryAction::Rebuild);
        assert_eq!(verdict_of(&facts, blocks), RecoveryAction::Rebuild);
        assert_eq!(verdict_of(&facts, RepairInputs::default()), RecoveryAction::StandDown);
    }

    #[test]
    fn an_object_that_is_the_version_is_proved_in_every_write_state() {
        for (phase, proof) in [
            (IntentPhase::Prepared, ProofRelation::NotCurrent),
            (IntentPhase::Landed, ProofRelation::NotCurrent),
            // An intent left open under a proof that stands.
            (IntentPhase::Prepared, ProofRelation::Current),
            (IntentPhase::Landed, ProofRelation::Current),
            (IntentPhase::FlushPending, ProofRelation::Current),
        ] {
            let facts = write_facts(phase, DiskObservation::Spec, proof);
            for inputs in inputs_product() {
                assert_eq!(verdict_of(&facts, inputs), RecoveryAction::Prove, "{phase:?}");
            }
        }
    }

    /// A proof that survived the prepare's fence bump means the write never began; if the name is
    /// gone then and the name's directory stood when the pass began, someone removed it, whatever
    /// the inputs say about what could be rebuilt. If the directory did not stand, the name went
    /// with it and the path is written (or fetched) as for any lost name.
    #[test]
    fn an_intent_over_a_standing_proof_with_the_name_gone_is_a_removal_not_a_rebuild() {
        let removed = RepairInputs { removed_by_user: true, ..RepairInputs::default() };
        for phase in [IntentPhase::Prepared, IntentPhase::Landed] {
            let facts = write_facts(phase, DiskObservation::Absent, ProofRelation::Current);
            assert_eq!(classify(&facts), CrashState::X13IntentOverStandingProof, "{phase:?}");
            for inputs in inputs_product() {
                let inputs = RepairInputs { removed_by_user: true, ..inputs };
                assert_eq!(verdict_of(&facts, inputs), RecoveryAction::RecordRemoval, "{phase:?}");
            }
            let blocks = RepairInputs { blocks_here: true, ..RepairInputs::default() };
            assert_eq!(verdict_of(&facts, blocks), RecoveryAction::Rebuild, "{phase:?}");
            assert_eq!(verdict_of(&facts, RepairInputs::default()), RecoveryAction::Demote);
            let _ = removed;
        }
        let provider = CrashFacts {
            root: RootKind::Provider,
            ..write_facts(IntentPhase::Prepared, DiskObservation::Absent, ProofRelation::Current)
        };
        assert_eq!(classify(&provider), CrashState::Unplaced);
    }

    /// A flush-pending write whose proof has since lapsed (the row moved to another version) is
    /// an unrecorded write like any other: it is proved, written or demoted, never left.
    #[test]
    fn a_flush_pending_write_whose_proof_lapsed_is_an_unrecorded_write() {
        for disk in [DiskObservation::Spec, DiskObservation::TornSpec, DiskObservation::Absent] {
            let facts = write_facts(IntentPhase::FlushPending, disk, ProofRelation::NotCurrent);
            assert_eq!(classify(&facts), CrashState::X3RenamedUnrecorded, "{disk:?}");
            let expected = if disk == DiskObservation::Spec {
                RecoveryAction::Prove
            } else {
                RecoveryAction::Demote
            };
            assert_eq!(verdict_of(&facts, RepairInputs::default()), expected, "{disk:?}");
        }
        let over_the_old_version = write_facts(
            IntentPhase::FlushPending,
            DiskObservation::PreImage,
            ProofRelation::Current,
        );
        assert_eq!(classify(&over_the_old_version), CrashState::X1Prepared);
    }

    /// A delete whose removal already took the recorded object from the name is done, whatever a
    /// person has put there since: the verdict closes it over the recorded object and neither
    /// removes nor moves aside what is there. A write over the same bytes is another matter: the
    /// bytes are a conflict to move aside before the write.
    #[test]
    fn a_delete_over_a_persons_object_is_closed_and_a_write_over_it_quarantines() {
        let delete = CrashFacts {
            root: RootKind::Plain,
            intent: Some(OpenIntent { kind: IntentKind::Delete, phase: IntentPhase::Prepared }),
            row: MaterializationState::Present,
            proof: ProofRelation::NotCurrent,
            obligation_open: false,
            disk: DiskObservation::Other,
        };
        assert_eq!(classify(&delete), CrashState::X7Diverged);
        for inputs in inputs_product() {
            assert_eq!(verdict_of(&delete, inputs), RecoveryAction::RecordRemoval);
        }
        for phase in [IntentPhase::Prepared, IntentPhase::Landed] {
            let write = write_facts(phase, DiskObservation::Other, ProofRelation::NotCurrent);
            assert_eq!(classify(&write), CrashState::X7Diverged);
            for inputs in inputs_product() {
                assert_eq!(verdict_of(&write, inputs), RecoveryAction::Quarantine, "{phase:?}");
            }
        }
    }

    #[test]
    fn kind_and_phase_strings_round_trip() {
        for kind in IntentKind::ALL {
            assert_eq!(IntentKind::from_db_str(kind.as_db_str()), Some(kind));
        }
        for phase in IntentPhase::ALL {
            assert_eq!(IntentPhase::from_db_str(phase.as_db_str()), Some(phase));
        }
        assert_eq!(IntentKind::from_db_str("structural_mkdir"), None);
    }
}
