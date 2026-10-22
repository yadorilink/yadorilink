//! The author-side rule a change must satisfy against its author's own
//! pre-state, stated over the pre-state history.
//!
//! The pre-state heads are computed from the definition
//! ([`crate::semantics::heads_at`]), not from any incremental state.
//!

use std::collections::BTreeSet;

use crate::model::{conflict_path, Change, ChangeId, History, Path, Universe};
use crate::semantics::{heads_at, watermarks};

/// The first clause of the author-side rule a change fails.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StrictViolation {
    SeqNotNext { expected: u64, got: u64 },
    DuplicateTouchedPath { path: Path },
    DuplicateBasisMember { path: Path, member: ChangeId },
    BasisNotCurrentHead { path: Path, member: ChangeId },
    DuplicatePreservationTarget { target_path: Path },
    PreservationSourceNotInBasis { source_path: Path, source: ChangeId },
    PreservationTargetNotCanonical { target_path: Path },
    PreservationTargetNotLanded { target_path: Path },
    PreservationTargetHasBasis { target_path: Path },
    PreservationVersionMismatch { target_path: Path },
}

/// Checks `change` against the history `pre` its author knows: the
/// sequence number is next, touched paths are distinct, each basis is
/// duplicate-free and made of current heads. An author's own current heads
/// need not be in the basis: a write never supersedes a version its author
/// did not observe.
///
pub fn verify_strict(
    universe: &Universe,
    pre: &History,
    change: &Change,
) -> Result<(), StrictViolation> {
    let expected = watermarks(universe, pre).get(&change.author).copied().unwrap_or(0) + 1;
    if change.seq != expected {
        return Err(StrictViolation::SeqNotNext { expected, got: change.seq });
    }
    let mut touched = BTreeSet::new();
    for op in &change.ops {
        if !touched.insert(op.path.as_str()) {
            return Err(StrictViolation::DuplicateTouchedPath { path: op.path.clone() });
        }
    }
    for op in &change.ops {
        let heads = heads_at(universe, pre, &op.path);
        let mut members = BTreeSet::new();
        for &member in &op.basis {
            if !members.insert(member) {
                return Err(StrictViolation::DuplicateBasisMember {
                    path: op.path.clone(),
                    member,
                });
            }
            if !heads.contains(&member) {
                return Err(StrictViolation::BasisNotCurrentHead { path: op.path.clone(), member });
            }
        }
    }
    Ok(())
}

/// [`verify_strict`] plus, per preservation: targets are distinct, the
/// source is in the basis of its path, the target is the canonical conflict
/// path, the change lands content there with an empty basis, and the
/// landed and the signed version both equal the source's version.
///
pub fn verify_strict_safe(
    universe: &Universe,
    pre: &History,
    change: &Change,
) -> Result<(), StrictViolation> {
    verify_strict(universe, pre, change)?;
    let mut targets = BTreeSet::new();
    for pres in &change.preservations {
        let target_path = pres.target_path.clone();
        if !targets.insert(pres.target_path.as_str()) {
            return Err(StrictViolation::DuplicatePreservationTarget { target_path });
        }
        if !change.in_basis(&pres.source_path, pres.source) {
            return Err(StrictViolation::PreservationSourceNotInBasis {
                source_path: pres.source_path.clone(),
                source: pres.source,
            });
        }
        if pres.target_path != conflict_path(&pres.source_path, pres.source) {
            return Err(StrictViolation::PreservationTargetNotCanonical { target_path });
        }
        if !change.lands(&pres.target_path) {
            return Err(StrictViolation::PreservationTargetNotLanded { target_path });
        }
        if change.basis_at(&pres.target_path).next().is_some() {
            return Err(StrictViolation::PreservationTargetHasBasis { target_path });
        }
        let source_version =
            universe.get(pres.source).and_then(|s| s.version_at(&pres.source_path));
        let landed = change.version_at(&pres.target_path);
        if source_version.is_none() || landed != source_version || landed != Some(pres.version) {
            return Err(StrictViolation::PreservationVersionMismatch { target_path });
        }
    }
    Ok(())
}
