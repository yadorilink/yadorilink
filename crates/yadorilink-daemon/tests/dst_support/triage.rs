//! Automatic
//! artifact-vs-product triage of violations by relaxed-harness replay.
//!
//! Triage today is manual: a violation reaching a human starts from a blank
//! page. makes the harness re-run the same `Case` (same seed, same IR)
//! under a *relaxed* profile -- self-healing sweeps forced at every step,
//! settle budget multiplied, event coalescing off -- and classify: if the
//! violation disappears under relaxation it is `LikelyHarnessArtifact`,
//! with the specific relaxation knob that eliminated it named by bisection;
//! if it persists it is `LikelyProductBug`. The cost model changes from
//! "every failure gets a human" to "humans start from a verdict and a named
//! knob".
//!
//! Deliberately labeled *Likely*: relaxation can mask a real bug that only
//! manifests under tight timing, so `LikelyHarnessArtifact` findings are
//! still surfaced (grouped, non-blocking) rather than dropped, and a corpus
//! entry that later reproduces under an improved harness escalates to
//! `LikelyProductBug`.
//!
//! This module owns the *generic* triage machinery: the profile knob set,
//! the verdict types, and the replay/bisection runner. Replaying a `Case`
//! is inherently scenario-specific (each scenario interprets its `Case`
//! differently), so the runner takes a scenario-provided `replay` closure
//! -- the same seam a long-running soak supervisor reuses.
//!
//! `#![cfg(turmoil)]`-gated like every DST scenario file.

use serde::{Deserialize, Serialize};

use super::case_ir::Case;
use super::oracle::Violation;

/// How often the self-healing sweep runs during a run -- the standard
/// lifecycle hook (task group 3) runs it at quiescent points; the relaxed
/// profile forces it at every step to see whether a violation is a
/// sweep-repairable harness artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SweepFrequency {
    Quiescent,
    EveryStep,
}

/// The knob set that distinguishes the standard harness from the relaxed
/// one. A `Case` fully describes the workload; the profile
/// describes how forgivingly the harness runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessProfile {
    pub sweeps: SweepFrequency,
    /// The settle budget is multiplied by this before each `settle` call --
    /// the relaxed profile's extended convergence polling.
    pub settle_multiplier: u32,
    /// Whether watcher-event coalescing (`fs_events::coalesce`) is applied.
    /// Off under relaxation, so a coalescing-induced artifact reappears.
    pub coalescing: bool,
}

/// The ordinary run profile: sweeps at quiescent points (task group 3),
/// unmultiplied settle budget, realistic coalescing on.
pub const STANDARD: HarnessProfile =
    HarnessProfile { sweeps: SweepFrequency::Quiescent, settle_multiplier: 1, coalescing: true };

/// The relaxed replay profile: sweeps forced every step,
/// settle budget 4x, coalescing off.
pub const RELAXED: HarnessProfile =
    HarnessProfile { sweeps: SweepFrequency::EveryStep, settle_multiplier: 4, coalescing: false };

/// Which single relaxation knob, changed alone on top of the standard
/// profile, eliminated a violation -- the named cause a human starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriageKnob {
    Sweeps,
    SettleMultiplier,
    Coalescing,
}

impl HarnessProfile {
    /// The standard profile with exactly one knob relaxed to its RELAXED
    /// value -- the bisection probe that isolates which knob matters.
    fn standard_with_one_relaxed(knob: TriageKnob) -> Self {
        let mut p = STANDARD;
        match knob {
            TriageKnob::Sweeps => p.sweeps = RELAXED.sweeps,
            TriageKnob::SettleMultiplier => p.settle_multiplier = RELAXED.settle_multiplier,
            TriageKnob::Coalescing => p.coalescing = RELAXED.coalescing,
        }
        p
    }
}

/// The machine-produced verdict for one violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriageVerdict {
    /// Disappeared under relaxation. `knob` names the single relaxation that
    /// eliminated it when bisection could isolate one; `None` means no
    /// single knob alone eliminated it (an interaction of several) -- still
    /// an artifact, just not attributable to one knob within the replay
    /// budget.
    LikelyHarnessArtifact { knob: Option<TriageKnob> },
    /// Reproduced under relaxation -- a real product bug, reported as a
    /// failure with the seed and case attached.
    LikelyProductBug,
}

impl TriageVerdict {
    /// Whether this verdict warrants the full-fidelity treatment -- a bundle
    /// with the whole timeline and a shrink pass (harness artifacts don't
    /// merit the shrink cost or
    /// disk, they get the slim bundle instead). The shrinker gates on this
    /// (`shrinker::should_shrink`) and the sweep failure path selects
    /// full-vs-slim bundle on it.
    pub fn is_product_bug(&self) -> bool {
        matches!(self, TriageVerdict::LikelyProductBug)
    }
}

/// A violation paired with its triage verdict. Attaching the verdict via a
/// wrapper (rather than a field on the widely-constructed `Violation`
/// struct) keeps triage -- a post-hoc, whole-run step -- from having to
/// thread `triage: None` through every `check_*` oracle literal and every
/// scenario's own `Violation` construction.
#[derive(Debug, Clone)]
pub struct TriagedViolation {
    pub violation: Violation,
    pub verdict: TriageVerdict,
}

impl std::fmt::Display for TriagedViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.verdict {
            TriageVerdict::LikelyProductBug => write!(f, "[LikelyProductBug] {}", self.violation),
            TriageVerdict::LikelyHarnessArtifact { knob } => {
                write!(f, "[LikelyHarnessArtifact")?;
                if let Some(knob) = knob {
                    write!(f, " knob={knob:?}")?;
                }
                write!(f, "] {}", self.violation)
            }
        }
    }
}

/// True if `candidate` is "the same violation" as `original` for triage
/// purposes: same kind and same path. Content-ids/devices deliberately do
/// not participate -- a relaxed replay can legitimately shift which device
/// index a convergence disagreement is reported against while being the
/// same underlying finding.
fn same_signature(original: &Violation, candidate: &Violation) -> bool {
    original.kind == candidate.kind && original.path == candidate.path
}

fn reproduces(original: &Violation, replayed: &[Violation]) -> bool {
    replayed.iter().any(|v| same_signature(original, v))
}

/// Triages one violation by relaxed-harness replay.
///
/// `replay(case, profile)` re-runs `case` under `profile` and returns the
/// violations that run produced -- the scenario owns this closure. The
/// runner performs at most four replays: one under the fully-relaxed
/// profile, then (only if that eliminated the violation) up to three
/// single-knob bisection probes to name the eliminating knob.
pub fn triage_case(
    original: &Violation,
    case: &Case,
    replay: &mut impl FnMut(&Case, &HarnessProfile) -> Vec<Violation>,
) -> TriageVerdict {
    // 1. Fully relaxed replay: if it still reproduces, it is a real bug.
    if reproduces(original, &replay(case, &RELAXED)) {
        return TriageVerdict::LikelyProductBug;
    }

    // 2. Eliminated under relaxation -> an artifact. Bisect the three knobs
    //  (each relaxed alone on top of standard) to name the one that
    //  eliminates it; the first probe that no longer reproduces wins.
    for knob in [TriageKnob::Sweeps, TriageKnob::SettleMultiplier, TriageKnob::Coalescing] {
        let probe = HarnessProfile::standard_with_one_relaxed(knob);
        if !reproduces(original, &replay(case, &probe)) {
            return TriageVerdict::LikelyHarnessArtifact { knob: Some(knob) };
        }
    }

    // No single knob alone eliminated it -- an interaction of several.
    TriageVerdict::LikelyHarnessArtifact { knob: None }
}

#[cfg(test)]
mod tests {
    use super::super::case_ir::{ContentTable, FaultPlan, Topology};
    use super::super::oracle::ViolationKind;
    use super::*;

    fn a_case() -> Case {
        Case {
            seed: 1,
            topology: Topology { device_count: 2, links: Vec::new() },
            workload: Vec::new(),
            fault_schedule: Vec::new(),
            content_table: ContentTable::default(),
            fault_plan: FaultPlan::default(),
            history_steps: Vec::new(),
        }
    }

    fn a_violation(kind: ViolationKind) -> Violation {
        Violation {
            kind,
            path: Some("a.txt".to_string()),
            content_ids: Vec::new(),
            devices: Vec::new(),
            detail: "test".to_string(),
        }
    }

    #[test]
    fn persistent_under_relaxation_is_a_product_bug() {
        let original = a_violation(ViolationKind::NoLoss);
        let case = a_case();
        // Reproduces under every profile, including fully relaxed.
        let mut replay = |_: &Case, _: &HarnessProfile| vec![a_violation(ViolationKind::NoLoss)];
        assert_eq!(triage_case(&original, &case, &mut replay), TriageVerdict::LikelyProductBug);
    }

    #[test]
    fn eliminated_by_sweeps_is_an_artifact_named_sweeps() {
        let original = a_violation(ViolationKind::StructuralIndexDiskMismatch);
        let case = a_case();
        // Only reproduces while sweeps run at quiescent points (i.e.
        // forcing sweeps every step clears it) -- the interrupted-
        // materialize artifact class.
        let mut replay = |_: &Case, profile: &HarnessProfile| {
            if profile.sweeps == SweepFrequency::Quiescent {
                vec![a_violation(ViolationKind::StructuralIndexDiskMismatch)]
            } else {
                Vec::new()
            }
        };
        assert_eq!(
            triage_case(&original, &case, &mut replay),
            TriageVerdict::LikelyHarnessArtifact { knob: Some(TriageKnob::Sweeps) }
        );
    }

    #[test]
    fn eliminated_only_by_the_combination_names_no_single_knob() {
        let original = a_violation(ViolationKind::Convergence);
        let case = a_case();
        // Clears only under the *fully* relaxed profile; no single-knob
        // probe (each relaxed alone) clears it.
        let mut replay = |_: &Case, profile: &HarnessProfile| {
            if *profile == RELAXED {
                Vec::new()
            } else {
                vec![a_violation(ViolationKind::Convergence)]
            }
        };
        assert_eq!(
            triage_case(&original, &case, &mut replay),
            TriageVerdict::LikelyHarnessArtifact { knob: None }
        );
    }

    #[test]
    fn eliminated_by_extended_settle_is_named_settle_multiplier() {
        let original = a_violation(ViolationKind::SlowConvergence);
        let case = a_case();
        let mut replay = |_: &Case, profile: &HarnessProfile| {
            if profile.settle_multiplier > 1 {
                Vec::new()
            } else {
                vec![a_violation(ViolationKind::SlowConvergence)]
            }
        };
        assert_eq!(
            triage_case(&original, &case, &mut replay),
            TriageVerdict::LikelyHarnessArtifact { knob: Some(TriageKnob::SettleMultiplier) }
        );
    }
}
