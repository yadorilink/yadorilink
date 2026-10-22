//! The single failure-handling entry point
//! that ties the diagnostics pieces together on a scenario's failure branch.
//!
//! On this tree there is no one shared seed-sweep loop -- each `dst_*.rs`
//! scenario runs its own loop and (today) persists a bare `Case` itself. This
//! module is the scenario-agnostic "what to do when a run fails" that the
//! INTEGRATION.md seams asked for, expressed once so a scenario's failure
//! branch is a single [`record_failure`] call rather than re-deriving the
//! triage → signature → known-lookup → bundle → shrink → corpus chain by hand.
//!
//! What it wires:
//!  1. runs [`triage_failures`](super::corpus::triage_failures) over
//!  the run's violations to get a per-violation verdict;
//!  2. computes the stable [`signature`](super::signature::compute_signature)
//!  from the terminal violation and the (optional) first-divergence point;
//!  3. scans the corpus for that signature and returns the
//!  [`known_prefix`](super::corpus::known_prefix) (`KNOWN` / `KNOWN-DIVERGENT`);
//!  4. gates the [`shrinker`](super::shrinker) on the verdict
//!  ([`should_shrink`](super::shrinker::should_shrink)) with a real
//!  reproduce-check closure, storing `case_min`;
//!  5. emits a **full** [`FailureBundle`](super::bundle::FailureBundle) for a
//!  `LikelyProductBug` and a **slim** [`SlimBundle`](super::bundle::SlimBundle)
//!  for a `LikelyHarnessArtifact`;
//!  6. records the failing case + verdicts + signature + `case_min` back to the
//!  corpus so the next run's signature scan finds it.
//!
//! Two seams remain caller-fed by design and are documented, not hidden:
//!  - **first-divergence (seam 3).** [`FirstDivergence`] is an *input*: the
//!  [`DivergenceObserver`](super::divergence::DivergenceObserver) needs one
//!  `holds` sample per event boundary, which requires a per-boundary replay
//!  hook the scenarios do not expose yet. The observer is unit-tested
//!  standalone; here its output flows through to the signature and bundle
//!  when a caller supplies it, and localizes to `none` when it does not.
//!  - **coverage (seam 10).** Coverage is accumulated *across* a sweep, not per
//!  failure, so it stays in [`super::coverage`]; a sweep loop calls
//!  `record_case` per run and `emit` at the end.

use std::path::{Path, PathBuf};

use super::bundle::{
    self, BundleInputs, BundledViolation, FailureBundle, PathState, SlimBundle, TimelineEvent,
};
use super::case_ir::Case;
use super::corpus::{self, CorpusEntry};
use super::divergence::FirstDivergence;
use super::oracle::Violation;
use super::shrinker::{self, ReproOutcome, ShrinkConfig};
use super::signature;
use super::triage::{HarnessProfile, TriageVerdict};

/// Everything [`record_failure`] needs about a failing run that is not a
/// closure. The two closures (`replay`, `reproduce`) are passed separately so
/// the borrow checker lets a scenario capture its own mutable state in them.
pub struct FailureInputs<'a> {
    pub scenario: &'a str,
    /// The failing case, as the scenario would persist it.
    pub case: &'a Case,
    /// Every violation the run's oracles reported, in report order. The
    /// terminal violation (the one the signature localizes) is the first
    /// `LikelyProductBug`, or the first violation if none is a product bug.
    pub violations: &'a [Violation],
    /// The first-divergence point (seam 3), when a replay hook produced one.
    pub first_divergence: Option<FirstDivergence>,
    /// The full event timeline; [`bundle::assemble`] slices it to the size cap.
    pub full_timeline: Vec<TimelineEvent>,
    /// Per-affected-path per-device state for the bundle.
    pub path_states: Vec<PathState>,
    /// The scenario's corpus file (read for the known-lookup, appended to).
    pub corpus_path: &'a Path,
    /// Where bundles are written; defaults to [`bundle::failures_dir`] when
    /// `None`.
    pub failures_dir: Option<&'a Path>,
}

/// What a failure branch does with a [`record_failure`] result: lead the report
/// with `known_prefix` if the signature is already catalogued, otherwise treat
/// the (freshly recorded) case as a new finding.
#[derive(Debug, Clone)]
pub struct FailureReport {
    pub signature: String,
    /// Per-violation verdicts, in `violations` order.
    pub verdicts: Vec<TriageVerdict>,
    /// The dominant verdict: `LikelyProductBug` if any violation is one.
    pub terminal_verdict: TriageVerdict,
    /// `Some(KNOWN…/KNOWN-DIVERGENT…)` when the signature was already in the
    /// corpus *before this run recorded it*.
    pub known_prefix: Option<String>,
    /// The shrunk minimal case, when the verdict warranted shrinking.
    pub case_min: Option<Case>,
    /// The bundle written for this failure (full or slim).
    pub bundle_path: Option<PathBuf>,
}

/// Index of the terminal violation: the first `LikelyProductBug`, else 0.
fn terminal_index(verdicts: &[TriageVerdict]) -> usize {
    verdicts.iter().position(|v| v.is_product_bug()).unwrap_or(0)
}

/// The whole failure-branch pipeline. `replay` is the scenario's
/// `Case`-interpreter (as [`triage_failures`](super::corpus::triage_failures)
/// takes); `reproduce` re-runs a candidate case under the same seed/harness and
/// reports whether the terminal violation still fires (the shrinker's
/// reproduce-check).
pub fn record_failure(
    inputs: FailureInputs,
    replay: &mut impl FnMut(&Case, &HarnessProfile) -> Vec<Violation>,
    reproduce: &mut impl FnMut(&Case) -> ReproOutcome,
) -> FailureReport {
    let FailureInputs {
        scenario,
        case,
        violations,
        first_divergence,
        full_timeline,
        path_states,
        corpus_path,
        failures_dir,
    } = inputs;

    // 1. Triage every violation, then pick the terminal one.
    let triaged = corpus::triage_failures(violations, case, replay);
    let verdicts: Vec<TriageVerdict> = triaged.iter().map(|t| t.verdict).collect();
    let term = terminal_index(&verdicts);
    let terminal_verdict = verdicts.get(term).copied().unwrap_or(TriageVerdict::LikelyProductBug);

    // 2. Signature from the terminal violation's kind + path + first-divergence.
    let (kind_label, path) = match violations.get(term) {
        Some(v) => (bundle::violation_kind_label(v.kind), v.path.as_deref()),
        None => ("none", None),
    };
    let sig = signature::compute_signature(kind_label, path, first_divergence.as_ref());

    // 3. Shrink -- but only for a product bug (the design: artifacts don't merit
    //  the cost). The reproduce-check is the caller's real replay.
    let case_min = if shrinker::should_shrink(&terminal_verdict) {
        let result = shrinker::shrink(case.clone(), &mut *reproduce, ShrinkConfig::default());
        Some(result.case_min)
    } else {
        None
    };

    // 4. Known-failure lookup against the corpus *as it was before this run*.
    let existing = corpus::load_corpus(corpus_path);
    let known_prefix = corpus::known_prefix(&existing, &sig, case_min.as_ref().or(Some(case)));

    // 5. Emit a bundle -- full for a product bug, slim for an artifact.
    let dir_owned;
    let dir: &Path = match failures_dir {
        Some(d) => d,
        None => {
            dir_owned = bundle::failures_dir();
            &dir_owned
        }
    };
    let seed = case.seed;
    let bundle_path = if terminal_verdict.is_product_bug() {
        let bundled: Vec<BundledViolation> = triaged
            .iter()
            .map(|t| BundledViolation::from_violation(&t.violation, Some(t.verdict)))
            .collect();
        let bundle: FailureBundle = bundle::assemble(
            BundleInputs {
                scenario: scenario.to_string(),
                seed,
                signature: sig.clone(),
                case: case.clone(),
                case_min: case_min.clone(),
                violations: bundled,
                first_divergence: first_divergence.clone(),
                full_timeline,
                path_states,
                full_log_pointer: None,
            },
            bundle::BUNDLE_SIZE_CAP_BYTES,
        );
        bundle::emit(dir, &sig, seed, &bundle).ok()
    } else {
        let slim = SlimBundle::new(scenario, seed, sig.clone(), terminal_verdict);
        bundle::emit(dir, &sig, seed, &slim).ok()
    };

    // 6. Record the case + verdicts + signature + case_min for the next run's
    //  signature scan.
    let entry = CorpusEntry {
        verdicts: verdicts.clone(),
        signature: Some(sig.clone()),
        case_min: case_min.clone(),
        ..CorpusEntry::new(case.clone())
    };
    let _ = corpus::append_entry(corpus_path, &entry);

    FailureReport {
        signature: sig,
        verdicts,
        terminal_verdict,
        known_prefix,
        case_min,
        bundle_path,
    }
}

#[cfg(test)]
mod tests {
    use super::super::case_ir::{
        ContentTable, DeviceTimeline, FaultPlan, LinkTopology, Op, Topology,
    };
    use super::super::oracle::ViolationKind;
    use super::super::triage::SweepFrequency;
    use super::*;

    fn case_with_ops(seed: u64, ops: Vec<Op>) -> Case {
        Case {
            seed,
            topology: Topology {
                device_count: 2,
                links: vec![
                    LinkTopology { group_id: "g".into(), initial_online: true },
                    LinkTopology { group_id: "g".into(), initial_online: true },
                ],
            },
            workload: vec![DeviceTimeline {
                device_index: 0,
                ops: ops.into_iter().enumerate().map(|(i, op)| (i as u64, op)).collect(),
            }],
            fault_schedule: Vec::new(),
            content_table: ContentTable::default(),
            fault_plan: FaultPlan::default(),
            history_steps: Vec::new(),
        }
    }

    fn violation(kind: ViolationKind, path: &str) -> Violation {
        Violation {
            kind,
            path: Some(path.to_string()),
            content_ids: Vec::new(),
            devices: Vec::new(),
            detail: "injected".to_string(),
        }
    }

    /// This case "reproduces" iff device 0 still writes `poison.bin`.
    fn poison_reproduce(case: &Case) -> ReproOutcome {
        let has_poison = case.workload.iter().any(|tl| {
            tl.ops
                .iter()
                .any(|(_, op)| matches!(op, Op::Write { path, .. } if path == "poison.bin"))
        });
        if has_poison {
            ReproOutcome::Reproduced
        } else {
            ReproOutcome::NotReproduced
        }
    }

    #[test]
    fn product_bug_emits_full_bundle_shrinks_and_records_signature() {
        let dir = tempfile::tempdir().unwrap();
        let corpus_path = dir.path().join("corpus.jsonl");
        let failures = dir.path().join("failures");

        // A case padded with noise ops plus the one poison Write.
        let case = case_with_ops(
            0xBEEF,
            vec![
                Op::Write { path: "noise-01.txt".into(), content_id: 1 },
                Op::Write { path: "poison.bin".into(), content_id: 2 },
                Op::Delete { path: "noise-01.txt".into() },
            ],
        );
        // A Convergence violation that persists under every profile => product bug.
        let violations = vec![violation(ViolationKind::Convergence, "poison.bin")];
        let mut replay = |_: &Case, _: &HarnessProfile| {
            vec![violation(ViolationKind::Convergence, "poison.bin")]
        };
        let mut reproduce = poison_reproduce;

        let report = record_failure(
            FailureInputs {
                scenario: "dst_two_device_chaos",
                case: &case,
                violations: &violations,
                first_divergence: Some(FirstDivergence {
                    sim_time_nanos: 42,
                    event_index: 1,
                    oracle_kind: "Convergence".into(),
                }),
                full_timeline: Vec::new(),
                path_states: Vec::new(),
                corpus_path: &corpus_path,
                failures_dir: Some(&failures),
            },
            &mut replay,
            &mut reproduce,
        );

        assert_eq!(report.terminal_verdict, TriageVerdict::LikelyProductBug);
        assert!(report.known_prefix.is_none(), "first sight of this signature is not KNOWN");
        assert!(report.signature.starts_with("Convergence|"), "{}", report.signature);
        // The signature embeds the first-divergence oracle kind as its location.
        assert!(report.signature.ends_with("@Convergence"), "{}", report.signature);

        // Shrinking ran and peeled the case down to just the poison Write.
        let case_min = report.case_min.expect("a product bug is shrunk");
        let min_ops: usize = case_min.workload.iter().map(|tl| tl.ops.len()).sum();
        assert_eq!(min_ops, 1, "shrunk to the single reproducing op");

        // A full bundle landed on disk and re-reads as a FailureBundle.
        let path = report.bundle_path.expect("a bundle was written");
        let json = std::fs::read_to_string(&path).unwrap();
        let back: FailureBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.form, "full");
        assert_eq!(back.signature, report.signature);
        assert!(back.case_min.is_some());

        // The corpus now carries the signature, so a second identical failure is
        // reported as KNOWN.
        let report2 = record_failure(
            FailureInputs {
                scenario: "dst_two_device_chaos",
                case: &case,
                violations: &violations,
                first_divergence: Some(FirstDivergence {
                    sim_time_nanos: 42,
                    event_index: 1,
                    oracle_kind: "Convergence".into(),
                }),
                full_timeline: Vec::new(),
                path_states: Vec::new(),
                corpus_path: &corpus_path,
                failures_dir: Some(&failures),
            },
            &mut replay,
            &mut reproduce,
        );
        let known = report2.known_prefix.expect("second failure is KNOWN");
        assert!(known.starts_with("KNOWN"), "{known}");
        assert!(known.contains("LikelyProductBug"), "{known}");
    }

    #[test]
    fn harness_artifact_emits_slim_bundle_and_does_not_shrink() {
        let dir = tempfile::tempdir().unwrap();
        let corpus_path = dir.path().join("corpus.jsonl");
        let failures = dir.path().join("failures");

        let case = case_with_ops(7, vec![Op::Write { path: "poison.bin".into(), content_id: 1 }]);
        // A violation that clears the moment sweeps run every step => artifact.
        let violations = vec![violation(ViolationKind::StructuralIndexDiskMismatch, "a.txt")];
        let mut replay = |_: &Case, profile: &HarnessProfile| {
            if profile.sweeps == SweepFrequency::Quiescent {
                vec![violation(ViolationKind::StructuralIndexDiskMismatch, "a.txt")]
            } else {
                Vec::new()
            }
        };
        let mut reproduce = poison_reproduce;

        let report = record_failure(
            FailureInputs {
                scenario: "dst_watcher_debounce",
                case: &case,
                violations: &violations,
                first_divergence: None,
                full_timeline: Vec::new(),
                path_states: Vec::new(),
                corpus_path: &corpus_path,
                failures_dir: Some(&failures),
            },
            &mut replay,
            &mut reproduce,
        );

        assert!(matches!(report.terminal_verdict, TriageVerdict::LikelyHarnessArtifact { .. }));
        assert!(report.case_min.is_none(), "artifacts are not shrunk");
        // Missing first-divergence localizes to `none`.
        assert!(report.signature.ends_with("@none"), "{}", report.signature);

        let path = report.bundle_path.expect("a slim bundle was written");
        let json = std::fs::read_to_string(&path).unwrap();
        let back: SlimBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.form, "slim");
        assert_eq!(back.signature, report.signature);
    }
}
