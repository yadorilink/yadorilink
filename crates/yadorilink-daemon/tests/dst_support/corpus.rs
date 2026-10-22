//! The shared, scenario-agnostic corpus-with-triage facility.
//!
//! Two layers live here, reconciled into one module:
//!
//!  1. **Triage persistence.** Each scenario already persists a failing `Case` to its own
//!  `tests/dst_corpus/<name>_cases.jsonl` and replays it on the next run.
//!  This layer adds triage onto both ends of that loop *generically*, so no
//!  scenario re-implements it -- the runner stays at the `dst_support` level
//!  and each scenario supplies only its own `replay` closure (the same seam
//!  `triage_case` already takes) and its own corpus path:
//!  - on failure at a seed-sweep entry point: [`triage_failures`] runs the
//!  group-6 [`triage_case`] runner over the run's violations and returns
//!  the per-violation verdicts, and [`record_triaged_case`] appends the
//!  `Case` *and* its verdicts as one JSONL [`CorpusEntry`] line.
//!  - on replay: [`load_corpus`] reads entries back -- tolerating legacy
//!  bare-`Case` lines (no verdict field) so an already-recorded corpus
//!  keeps loading -- and [`replay_and_escalate`] re-triages a recorded
//!  `LikelyHarnessArtifact` entry: if the violation still reproduces
//!  under the current harness it escalates to `LikelyProductBug`
//!  (an artifact that later reproduces under an improved
//!  harness is a real bug), so the corpus is a ratchet, not a silent
//!  amnesty list.
//!
//!  2. **Failure-signature memory** — the failure
//!  *signature memory* layered on top of the same JSONL entry. Each entry
//!  gains the optional `signature`, `note`, and `case_min` fields (every new
//!  field is `#[serde(default)]` and skipped when empty, so an older entry
//!  carrying only `case`+`verdicts` still deserializes) plus a
//!  `#[serde(flatten)]` catch-all so a future field is preserved verbatim
//!  across a load→store cycle rather than dropped. On a new failure the
//!  harness scans the corpus for a matching signature via [`known_prefix`]
//!  and, if found, leads the report with `KNOWN: … — <verdict> — <note>` --
//!  the single lookup that stops an agent re-investigating a duplicate. When
//!  the new shrunk case differs materially from the stored `case_min`, the
//!  prefix is flagged `KNOWN-DIVERGENT`.
//!
//! Deliberately generic: replaying a `Case` is scenario-specific, so every
//! entry point here takes the scenario's `replay(&Case, &HarnessProfile) ->
//! Vec<Violation>` closure rather than knowing any scenario's internals.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::case_ir::{Case, Op};
use super::oracle::Violation;
use super::triage::{triage_case, HarnessProfile, TriageVerdict, TriagedViolation, STANDARD};

/// One corpus line: the failing `Case`, the triage verdicts it was recorded
/// with, and the agent-diagnostics signature memory.
///
/// `verdicts` is `#[serde(default)]` and the loader falls back to parsing a
/// bare `Case`, so a corpus written before (bare `Case` lines, no
/// verdict field) still loads -- as an entry with no recorded verdicts. The
/// fields (`signature`/`note`/`case_min`) are all optional-and-skipped, so a
/// `{case, verdicts}`-only line loads unchanged, and `extra` preserves any
/// field this version does not model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub case: Case,
    #[serde(default)]
    pub verdicts: Vec<TriageVerdict>,
    /// Stable failure signature,
    /// computed by [`super::signature::compute_signature`] on the failure path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The one-line investigation note recorded on resolution -- the primary
    /// record of what a failure turned out to be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The shrunk minimal case ([`super::shrinker`]), when shrinking
    /// ran for this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_min: Option<Case>,
    /// Any field this version does not know about (e.g. a future field): kept so
    /// a load→store cycle never silently drops it.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl CorpusEntry {
    /// A bare entry for `case` with no verdicts or diagnostics yet.
    pub fn new(case: Case) -> Self {
        Self {
            case,
            verdicts: Vec::new(),
            signature: None,
            note: None,
            case_min: None,
            extra: BTreeMap::new(),
        }
    }
}

/// The outcome of replaying one recorded corpus entry under the current
/// harness (see [`replay_and_escalate`]).
#[derive(Debug, Clone)]
pub struct ReplayOutcome {
    /// The violations the replay produced, each re-triaged under the current
    /// harness. Empty = the entry no longer reproduces at all (a prior
    /// artifact the current harness now fully absorbs, or a since-fixed bug).
    pub triaged: Vec<TriagedViolation>,
    /// True iff the entry was recorded as (only) `LikelyHarnessArtifact` but a
    /// replayed violation now triages to `LikelyProductBug` -- the
    /// escalation case. A caller treats this as a real, gating failure.
    pub escalated: bool,
}

/// Triage every violation a failing run produced, in order, returning each
/// paired with its verdict. `replay` is the scenario's `Case`-interpreter (the
/// same closure [`triage_case`] takes). A seed-sweep entry point calls this
/// once when a run fails, then hands the verdicts to [`record_triaged_case`].
pub fn triage_failures(
    violations: &[Violation],
    case: &Case,
    replay: &mut impl FnMut(&Case, &HarnessProfile) -> Vec<Violation>,
) -> Vec<TriagedViolation> {
    let mut out = Vec::with_capacity(violations.len());
    for v in violations {
        let verdict = triage_case(v, case, replay);
        out.push(TriagedViolation { violation: v.clone(), verdict });
    }
    out
}

/// Append one failing `case` plus its triage `verdicts` to `corpus_path` as a
/// single JSONL [`CorpusEntry`] line. Best-effort -- a persist failure must
/// not panic an already-failing run -- mirroring each scenario's existing
/// bare-`Case` `record_failing_case`, just carrying the verdict too.
pub fn record_triaged_case(corpus_path: &Path, case: &Case, verdicts: &[TriageVerdict]) {
    let mut entry = CorpusEntry::new(case.clone());
    entry.verdicts = verdicts.to_vec();
    let _ = append_entry(corpus_path, &entry);
}

/// Append an arbitrary [`CorpusEntry`] (carrying signature/case_min/note as the
/// diagnostics path populates them) to `corpus_path`, creating it. Best-effort,
/// like [`record_triaged_case`]: a persist failure of an already-failing run is
/// swallowed rather than panicking.
pub fn append_entry(path: &Path, entry: &CorpusEntry) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let line = serde_json::to_string(entry).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    writeln!(f, "{line}").map_err(|e| e.to_string())
}

/// Serialize entries back to JSONL (one compact line each) -- used by the
/// Signature backfill which loads, fills signatures, and rewrites.
pub fn to_jsonl(entries: &[CorpusEntry]) -> Result<String, String> {
    let mut out = String::new();
    for e in entries {
        out.push_str(&serde_json::to_string(e).map_err(|err| err.to_string())?);
        out.push('\n');
    }
    Ok(out)
}

/// Parse one corpus line into a [`CorpusEntry`], skipping blanks and `#`
/// comments. Tries the `{case, verdicts,...}` shape first, then falls back to
/// a legacy bare `Case` (recorded with no verdicts) so a pre-6.4 corpus keeps
/// loading.
pub fn parse_corpus_line(line: &str) -> Option<CorpusEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    if let Ok(entry) = serde_json::from_str::<CorpusEntry>(line) {
        return Some(entry);
    }
    serde_json::from_str::<Case>(line).ok().map(CorpusEntry::new)
}

/// Load every entry from `corpus_path`. Missing file -> empty (a first run
/// has no corpus yet). Unparseable lines are skipped, matching the scenarios'
/// existing `filter_map(...ok)` loaders.
pub fn load_corpus(corpus_path: &Path) -> Vec<CorpusEntry> {
    let Ok(contents) = std::fs::read_to_string(corpus_path) else { return Vec::new() };
    contents.lines().filter_map(parse_corpus_line).collect()
}

/// Replay a recorded corpus `entry` under the current harness and re-triage
/// it (the escalation case). The entry replays under [`STANDARD`]; each
/// resulting violation is triaged afresh via [`triage_case`]. If the entry
/// had been recorded as (only) `LikelyHarnessArtifact` and any replayed
/// violation now triages to `LikelyProductBug`, [`ReplayOutcome::escalated`]
/// is set -- the harness has tightened enough that a former artifact is now a
/// reproduced bug.
pub fn replay_and_escalate(
    entry: &CorpusEntry,
    replay: &mut impl FnMut(&Case, &HarnessProfile) -> Vec<Violation>,
) -> ReplayOutcome {
    let current = replay(&entry.case, &STANDARD);
    let mut triaged = Vec::with_capacity(current.len());
    for v in &current {
        let verdict = triage_case(v, &entry.case, replay);
        triaged.push(TriagedViolation { violation: v.clone(), verdict });
    }
    let recorded_all_artifacts = !entry.verdicts.is_empty()
        && entry.verdicts.iter().all(|v| matches!(v, TriageVerdict::LikelyHarnessArtifact { .. }));
    let now_product_bug = triaged.iter().any(|t| t.verdict == TriageVerdict::LikelyProductBug);
    ReplayOutcome { triaged, escalated: recorded_all_artifacts && now_product_bug }
}

// --- Signature memory / known-failure lookup ---

/// The first corpus entry whose signature matches.
pub fn find_by_signature<'a>(
    entries: &'a [CorpusEntry],
    signature: &str,
) -> Option<&'a CorpusEntry> {
    entries.iter().find(|e| e.signature.as_deref() == Some(signature))
}

/// A coarse, order-independent fingerprint of a case, used to decide whether a
/// new shrunk case "differs materially" from a stored `case_min`: device count,
/// total op count, and the set of paths touched. Deliberately coarse -- a byte
/// diff would flag every seed as divergent; this flags a genuinely different
/// shape.
#[derive(Debug, PartialEq, Eq)]
pub struct CaseFingerprint {
    pub device_count: usize,
    pub op_count: usize,
    pub paths: BTreeSet<String>,
}

pub fn case_fingerprint(case: &Case) -> CaseFingerprint {
    let mut paths = BTreeSet::new();
    let mut op_count = 0;
    for timeline in &case.workload {
        for (_, op) in &timeline.ops {
            op_count += 1;
            for p in op_paths(op) {
                paths.insert(p);
            }
        }
    }
    CaseFingerprint { device_count: case.topology.device_count, op_count, paths }
}

fn op_paths(op: &Op) -> Vec<String> {
    match op {
        Op::Write { path, .. }
        | Op::Edit { path, .. }
        | Op::Delete { path }
        | Op::Mkdir { path }
        | Op::Rmdir { path }
        | Op::RmTree { path }
        | Op::Chmod { path, .. } => vec![path.clone()],
        Op::Rename { from, to } | Op::Move { from, to } | Op::RenameTree { from, to } => {
            vec![from.clone(), to.clone()]
        }
        Op::ConflictingConcurrent { paths } => paths.clone(),
    }
}

/// A short human label for an entry's recorded verdicts, for the KNOWN report
/// line. The corpus stores per-violation `verdicts`; the report
/// summarizes them: any product bug dominates, else it's a harness artifact,
/// else the entry was recorded without a verdict.
fn verdict_label(verdicts: &[TriageVerdict]) -> &'static str {
    if verdicts.is_empty() {
        "unverdicted"
    } else if verdicts.iter().any(|v| v.is_product_bug()) {
        "LikelyProductBug"
    } else {
        "LikelyHarnessArtifact"
    }
}

/// The known-failure report prefix for a new failure with `signature`, or
/// `None` if the signature is unknown. When `shrunk_case` is given and the
/// matched entry has a `case_min` with a materially different fingerprint, the
/// prefix is `KNOWN-DIVERGENT` instead of `KNOWN`.
pub fn known_prefix(
    corpus: &[CorpusEntry],
    signature: &str,
    shrunk_case: Option<&Case>,
) -> Option<String> {
    let entry = find_by_signature(corpus, signature)?;
    let verdict = verdict_label(&entry.verdicts);
    let note = entry.note.as_deref().unwrap_or("(no note)");

    let divergent = match (shrunk_case, &entry.case_min) {
        (Some(new), Some(stored)) => case_fingerprint(new) != case_fingerprint(stored),
        _ => false,
    };
    let tag = if divergent { "KNOWN-DIVERGENT" } else { "KNOWN" };
    Some(format!("{tag}: {signature} — {verdict} — {note}"))
}

/// True when the caller wants a fast, targeted run with no corpus replay --
/// either the dedicated `DST_SKIP_CORPUS_REPLAY` flag, or an explicit
/// `DST_BASE_SEED`. The latter matches the convention the retired two-device and
/// generated-sweep scenarios already established before this function
/// existed: a caller pinning down one specific seed (the documented
/// `DST_BASE_SEED=<seed> DST_VARIATIONS=1` reproduction recipe) has already
/// opted into "just this seed", and paying to replay an ever-growing
/// regression corpus underneath that request both wastes most of the run's
/// wall-clock cost and can muddy a targeted result with an unrelated corpus
/// failure.
///
/// Corpus replay stays ON by default: an untargeted run (what CI performs,
/// and what a bare `cargo test --test <scenario>` does) still exercises the
/// full corpus every time, preserving the regression-corpus guarantee.
/// This predicate only ever narrows what an *already*-targeted run does; it
/// can never turn on corpus replay for a run that would otherwise have
/// skipped it, and it can never turn it off for a plain, untargeted run.
///
/// `DST_SKIP_CORPUS_REPLAY` exists specifically for a driver (such as a
/// targeted-repeat runner) that wants a fast repeated single-seed measurement
/// without also having to set `DST_BASE_SEED`/`DST_VARIATIONS` itself, and
/// without silently depending on those two env vars continuing to imply
/// "skip corpus" as an accident of scenario-specific wiring rather than a
/// documented contract.
pub fn should_skip_replay() -> bool {
    std::env::var("DST_SKIP_CORPUS_REPLAY").is_ok() || std::env::var("DST_BASE_SEED").is_ok()
}

#[cfg(test)]
mod tests {
    use super::super::case_ir::{ContentTable, DeviceTimeline, FaultPlan, LinkTopology, Topology};
    use super::super::oracle::ViolationKind;
    use super::super::triage::{TriageKnob, RELAXED};
    use super::*;

    fn a_case() -> Case {
        Case {
            seed: 7,
            topology: Topology { device_count: 2, links: Vec::new() },
            workload: Vec::new(),
            fault_schedule: Vec::new(),
            content_table: ContentTable::default(),
            fault_plan: FaultPlan::default(),
            history_steps: Vec::new(),
        }
    }

    /// A case with `device_count` devices and a single device-0 op timeline, for
    /// the fingerprint/divergence tests.
    fn case_with(device_count: usize, ops: Vec<Op>) -> Case {
        Case {
            seed: 1,
            topology: Topology {
                device_count,
                links: (0..device_count)
                    .map(|_| LinkTopology { group_id: "g".into(), initial_online: true })
                    .collect(),
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

    fn a_violation(kind: ViolationKind, path: &str) -> Violation {
        Violation {
            kind,
            path: Some(path.to_string()),
            content_ids: Vec::new(),
            devices: Vec::new(),
            detail: "test".to_string(),
        }
    }

    #[test]
    fn triage_failures_labels_each_violation_independently() {
        let case = a_case();
        // `bug.txt` reproduces under every profile; `artifact.txt` clears the
        // moment sweeps run every step.
        let bug = a_violation(ViolationKind::NoLoss, "bug.txt");
        let artifact = a_violation(ViolationKind::StructuralIndexDiskMismatch, "artifact.txt");
        let mut replay = |_: &Case, profile: &HarnessProfile| {
            let mut out = vec![a_violation(ViolationKind::NoLoss, "bug.txt")];
            if profile.sweeps == super::super::triage::SweepFrequency::Quiescent {
                out.push(a_violation(ViolationKind::StructuralIndexDiskMismatch, "artifact.txt"));
            }
            out
        };
        let triaged = triage_failures(&[bug, artifact], &case, &mut replay);
        assert_eq!(triaged[0].verdict, TriageVerdict::LikelyProductBug);
        assert_eq!(
            triaged[1].verdict,
            TriageVerdict::LikelyHarnessArtifact { knob: Some(TriageKnob::Sweeps) }
        );
    }

    #[test]
    fn record_and_load_roundtrips_case_and_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/cases.jsonl");
        let case = a_case();
        let verdicts = vec![
            TriageVerdict::LikelyProductBug,
            TriageVerdict::LikelyHarnessArtifact { knob: None },
        ];
        record_triaged_case(&path, &case, &verdicts);
        let loaded = load_corpus(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].case.seed, case.seed);
        assert_eq!(loaded[0].verdicts, verdicts);
    }

    #[test]
    fn load_tolerates_legacy_bare_case_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.jsonl");
        // A corpus written before: one bare `Case` per line, no
        // wrapper and no verdict field.
        let bare = serde_json::to_string(&a_case()).unwrap();
        std::fs::write(&path, format!("# a comment\n{bare}\n\n")).unwrap();
        let loaded = load_corpus(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].case.seed, a_case().seed);
        assert!(loaded[0].verdicts.is_empty(), "legacy line loads with no recorded verdicts");
    }

    #[test]
    fn recorded_artifact_that_reproduces_under_relaxation_escalates() {
        // Recorded as an artifact, but on replay it now reproduces under every
        // profile (including fully relaxed) -- a since-tightened harness turns
        // it into a reproduced product bug.
        let entry = CorpusEntry {
            verdicts: vec![TriageVerdict::LikelyHarnessArtifact { knob: Some(TriageKnob::Sweeps) }],
            ..CorpusEntry::new(a_case())
        };
        let mut replay =
            |_: &Case, _: &HarnessProfile| vec![a_violation(ViolationKind::NoLoss, "x.txt")];
        let outcome = replay_and_escalate(&entry, &mut replay);
        assert!(outcome.escalated, "an artifact reproducing under relaxation must escalate");
        assert_eq!(outcome.triaged[0].verdict, TriageVerdict::LikelyProductBug);
    }

    #[test]
    fn recorded_artifact_still_clearing_under_relaxation_does_not_escalate() {
        let entry = CorpusEntry {
            verdicts: vec![TriageVerdict::LikelyHarnessArtifact { knob: None }],
            ..CorpusEntry::new(a_case())
        };
        // Reproduces under standard but still clears under full relaxation:
        // remains an artifact, no escalation.
        let mut replay = |_: &Case, profile: &HarnessProfile| {
            if *profile == RELAXED {
                Vec::new()
            } else {
                vec![a_violation(ViolationKind::Convergence, "y.txt")]
            }
        };
        let outcome = replay_and_escalate(&entry, &mut replay);
        assert!(!outcome.escalated);
        assert!(matches!(outcome.triaged[0].verdict, TriageVerdict::LikelyHarnessArtifact { .. }));
    }

    #[test]
    fn recorded_artifact_that_no_longer_reproduces_is_absorbed_not_escalated() {
        let entry = CorpusEntry {
            verdicts: vec![TriageVerdict::LikelyHarnessArtifact { knob: Some(TriageKnob::Sweeps) }],
            ..CorpusEntry::new(a_case())
        };
        let mut replay = |_: &Case, _: &HarnessProfile| Vec::new();
        let outcome = replay_and_escalate(&entry, &mut replay);
        assert!(!outcome.escalated);
        assert!(outcome.triaged.is_empty(), "a fully-absorbed entry yields no violations");
    }

    // --- signature-memory tests ---

    #[test]
    fn diagnostics_fields_survive_a_load_store_cycle() {
        let mut e =
            CorpusEntry::new(case_with(2, vec![Op::Write { path: "a.txt".into(), content_id: 1 }]));
        e.verdicts = vec![TriageVerdict::LikelyProductBug];
        e.signature = Some("Convergence|a.txt@Convergence".into());
        e.note = Some("real VV fast-forward bug; fixed in conflict.rs".into());
        e.case_min = Some(case_with(2, vec![Op::Write { path: "a.txt".into(), content_id: 1 }]));
        let line = serde_json::to_string(&e).unwrap();
        let back: CorpusEntry = serde_json::from_str(&line).unwrap();
        assert_eq!(back.signature.as_deref(), Some("Convergence|a.txt@Convergence"));
        assert_eq!(back.verdicts, vec![TriageVerdict::LikelyProductBug]);
        assert!(back.case_min.is_some());
    }

    #[test]
    fn unknown_fields_survive_a_load_store_cycle() {
        // A future field this version doesn't model, alongside a real entry.
        let bare = serde_json::to_string(&a_case()).unwrap();
        let line = format!("{{\"case\":{bare},\"future_field\":{{\"a\":1}}}}");
        let entries = vec![parse_corpus_line(&line).unwrap()];
        let round = to_jsonl(&entries).unwrap();
        assert!(round.contains("future_field"), "flatten must preserve unknown fields: {round}");
    }

    #[test]
    fn known_prefix_reports_match_and_flags_divergence() {
        let mut stored = CorpusEntry::new(a_case());
        stored.signature = Some("Convergence|dst-N.bin@Convergence".into());
        stored.verdicts = vec![TriageVerdict::LikelyProductBug];
        stored.note = Some("known race".into());
        stored.case_min =
            Some(case_with(2, vec![Op::Write { path: "dst-01.bin".into(), content_id: 1 }]));
        let corpus = vec![stored];

        // Unknown signature: no prefix.
        assert!(known_prefix(&corpus, "Corruption|x@Corruption", None).is_none());

        // Known, no shrunk case to compare: plain KNOWN.
        let p = known_prefix(&corpus, "Convergence|dst-N.bin@Convergence", None).unwrap();
        assert!(p.starts_with("KNOWN:"), "{p}");
        assert!(p.contains("LikelyProductBug"));
        assert!(p.contains("known race"));

        // Known but the new shrunk case has a different shape (3 ops vs 1):
        // KNOWN-DIVERGENT.
        let bigger = case_with(
            2,
            vec![
                Op::Write { path: "dst-01.bin".into(), content_id: 1 },
                Op::Write { path: "dst-02.bin".into(), content_id: 2 },
                Op::Delete { path: "dst-01.bin".into() },
            ],
        );
        let p = known_prefix(&corpus, "Convergence|dst-N.bin@Convergence", Some(&bigger)).unwrap();
        assert!(p.starts_with("KNOWN-DIVERGENT:"), "{p}");

        // Known and the shrunk case matches the stored fingerprint: plain KNOWN.
        let same = case_with(2, vec![Op::Write { path: "dst-01.bin".into(), content_id: 1 }]);
        let p = known_prefix(&corpus, "Convergence|dst-N.bin@Convergence", Some(&same)).unwrap();
        assert!(p.starts_with("KNOWN:"), "{p}");
    }
}
