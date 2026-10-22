//! The bounded, schema-versioned failure bundle.
//!
//! Every DST violation produces one self-contained JSON file under
//! `target/dst-failures/<signature>-<seed>.json` that is sufficient to begin
//! diagnosis without opening scenario source or full logs: seed + full Case IR,
//! the violations with their triage verdicts, the first-observable divergence
//! point, an event-timeline *slice* centered on that point, and per-affected-
//! path state (index row + on-disk content hash per device). A hard ~64 KiB cap
//! keeps one bundle ≈ one comfortable `Read`; when the assembled bundle would
//! exceed it, the timeline slice shrinks (K halves) until it fits and the drop
//! is recorded in `truncated`, with a pointer to the full on-disk log.
//!
//! Triage verdicts are the `triage` placeholder (see `triage.rs`).

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use yadorilink_replica_domain::file::FileRecord;

use super::case_ir::Case;
use super::divergence::FirstDivergence;
use super::oracle::{Violation, ViolationKind};
use super::triage::TriageVerdict;

pub const BUNDLE_SCHEMA_VERSION: u32 = 2;

/// Hard size cap for a full bundle (the design: "one bundle ≈ one comfortable
/// Read"). The timeline slice shrinks until the serialized bundle fits.
pub const BUNDLE_SIZE_CAP_BYTES: usize = 64 * 1024;

/// Default half-window: the assembler starts by keeping this many events on
/// each side of the divergence point, then halves on cap pressure.
pub const DEFAULT_TIMELINE_HALF_WINDOW: usize = 64;

/// Stable string label for a `ViolationKind` (which is not itself `Serialize`).
/// Kept exhaustive so a new oracle kind forces an update here at compile time.
pub fn violation_kind_label(kind: ViolationKind) -> &'static str {
    match kind {
        ViolationKind::Convergence => "Convergence",
        ViolationKind::NoLoss => "NoLoss",
        ViolationKind::Corruption => "Corruption",
        ViolationKind::ConflictCopyAccounting => "ConflictCopyAccounting",
        ViolationKind::StructuralIndexDiskMismatch => "StructuralIndexDiskMismatch",
        ViolationKind::StructuralOrphanIndexRow => "StructuralOrphanIndexRow",
        ViolationKind::ConvergedToWrongWinner => "ConvergedToWrongWinner",
        ViolationKind::StructuralMaterializationMismatch => "StructuralMaterializationMismatch",
        ViolationKind::SameVersionIdentityMismatch => "SameVersionIdentityMismatch",
        ViolationKind::SlowConvergence => "SlowConvergence",
        ViolationKind::RepairedBySweep => "RepairedBySweep",
        ViolationKind::Namespace(kind) => kind.label(),
    }
}

/// A violation, flattened into a serializable form with its triage verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledViolation {
    pub kind: String,
    pub path: Option<String>,
    pub content_ids: Vec<u64>,
    pub devices: Vec<usize>,
    pub detail: String,
    /// The violation's triage verdict; `None` when no triage runner produced
    /// one.
    pub triage: Option<TriageVerdict>,
}

impl BundledViolation {
    pub fn from_violation(v: &Violation, triage: Option<TriageVerdict>) -> Self {
        Self {
            kind: violation_kind_label(v.kind).to_string(),
            path: v.path.clone(),
            content_ids: v.content_ids.clone(),
            devices: v.devices.clone(),
            detail: v.detail.clone(),
            triage,
        }
    }
}

/// One event in the run's timeline, as rendered into the bundle's slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub event_index: usize,
    pub sim_time_nanos: u64,
    pub device: Option<usize>,
    pub summary: String,
}

/// A concise index-row summary for one device's view of a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexRowSummary {
    pub deleted: bool,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub block_count: usize,
}

impl IndexRowSummary {
    pub fn from_record(record: &FileRecord) -> Self {
        Self {
            deleted: record.deleted,
            size: record.size,
            mtime_unix_nanos: record.mtime_unix_nanos,
            block_count: record.blocks.len(),
        }
    }
}

/// One device's state for an affected path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePathState {
    pub device: usize,
    /// `None` if the path has no index row on this device.
    pub index_row: Option<IndexRowSummary>,
    /// SHA-256 of the on-disk file content, or `None` if absent on disk.
    pub content_hash: Option<String>,
}

/// Per-affected-path state across every device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathState {
    pub path: String,
    pub per_device: Vec<DevicePathState>,
}

/// Record of what the size cap forced out of the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Truncation {
    pub reason: String,
    pub original_event_count: usize,
    pub kept_event_count: usize,
    pub dropped_event_count: usize,
    pub final_half_window: usize,
}

/// The full failure bundle (the design).
///
/// Not `PartialEq`/`Eq`: it embeds `Case`, which is not comparable (its
/// `ContentTable` is a `HashMap`); tests compare bundles by their serialized
/// JSON instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureBundle {
    pub schema_version: u32,
    /// Always `"full"` for this struct; lets a reader distinguish it from a
    /// `SlimBundle` at the top level.
    pub form: String,
    pub scenario: String,
    pub seed: u64,
    pub signature: String,
    pub case: Case,
    /// The shrunk minimal case (see `shrinker`), when shrinking ran. Stored
    /// alongside the original so a session picks up the minimal form directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_min: Option<Case>,
    pub violations: Vec<BundledViolation>,
    pub first_divergence: Option<FirstDivergence>,
    pub timeline: Vec<TimelineEvent>,
    pub path_states: Vec<PathState>,
    pub truncated: Option<Truncation>,
    /// Pointer to the full on-disk event log (the escape hatch when the cap
    /// dropped the one event that mattered). `None` if no full log was kept.
    pub full_log_pointer: Option<String>,
}

/// The slim bundle emitted for `LikelyHarnessArtifact` verdicts (
/// design open-question "lean: slim"): verdict + knob only, so artifacts do not
/// compete for attention or disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlimBundle {
    pub schema_version: u32,
    pub form: String,
    pub scenario: String,
    pub seed: u64,
    pub signature: String,
    pub triage: TriageVerdict,
}

impl SlimBundle {
    pub fn new(
        scenario: impl Into<String>,
        seed: u64,
        signature: impl Into<String>,
        triage: TriageVerdict,
    ) -> Self {
        Self {
            schema_version: BUNDLE_SCHEMA_VERSION,
            form: "slim".to_string(),
            scenario: scenario.into(),
            seed,
            signature: signature.into(),
            triage,
        }
    }
}

/// Inputs to [`assemble`] that are independent of the size cap.
pub struct BundleInputs {
    pub scenario: String,
    pub seed: u64,
    pub signature: String,
    pub case: Case,
    /// The shrunk minimal case, or `None` if shrinking did not run.
    pub case_min: Option<Case>,
    pub violations: Vec<BundledViolation>,
    pub first_divergence: Option<FirstDivergence>,
    /// The complete event timeline; [`assemble`] slices it to fit the cap.
    pub full_timeline: Vec<TimelineEvent>,
    pub path_states: Vec<PathState>,
    pub full_log_pointer: Option<String>,
}

/// Assemble a full bundle, shrinking the timeline slice until the serialized
/// JSON fits `cap_bytes`. The slice is centered on the first-divergence event
/// (or the timeline midpoint if divergence is unknown). Records a `Truncation`
/// whenever any event is dropped.
pub fn assemble(inputs: BundleInputs, cap_bytes: usize) -> FailureBundle {
    let total = inputs.full_timeline.len();
    let center = inputs
        .first_divergence
        .as_ref()
        .map(|d| d.event_index.min(total.saturating_sub(1)))
        .unwrap_or(total / 2);

    let mut half_window = DEFAULT_TIMELINE_HALF_WINDOW;
    // Shrink until it fits or the window collapses to nothing.
    loop {
        let (slice, dropped) = slice_around(&inputs.full_timeline, center, half_window);
        let truncated = (dropped > 0).then(|| Truncation {
            reason: format!(
                "timeline slice capped at half-window {half_window} to fit {cap_bytes} bytes"
            ),
            original_event_count: total,
            kept_event_count: slice.len(),
            dropped_event_count: dropped,
            final_half_window: half_window,
        });
        let bundle = FailureBundle {
            schema_version: BUNDLE_SCHEMA_VERSION,
            form: "full".to_string(),
            scenario: inputs.scenario.clone(),
            seed: inputs.seed,
            signature: inputs.signature.clone(),
            case: inputs.case.clone(),
            case_min: inputs.case_min.clone(),
            violations: inputs.violations.clone(),
            first_divergence: inputs.first_divergence.clone(),
            timeline: slice,
            path_states: inputs.path_states.clone(),
            truncated,
            full_log_pointer: inputs.full_log_pointer.clone(),
        };

        let size = serialized_len(&bundle);
        if size <= cap_bytes || half_window == 0 {
            // Fits, or we've dropped the whole timeline and still can't fit
            // (case/path-states alone exceed the cap) — emit anyway with the
            // truncation recorded; the cap tunes the default, it never deletes
            // the evidence (the full log pointer remains).
            return bundle;
        }
        half_window /= 2;
    }
}

/// Events within `[center-half, center+half]`, and how many were dropped.
fn slice_around(
    events: &[TimelineEvent],
    center: usize,
    half: usize,
) -> (Vec<TimelineEvent>, usize) {
    if events.is_empty() {
        return (Vec::new(), 0);
    }
    let lo = center.saturating_sub(half);
    let hi = (center + half + 1).min(events.len());
    let slice = events[lo..hi].to_vec();
    let dropped = events.len() - slice.len();
    (slice, dropped)
}

fn serialized_len(value: &impl Serialize) -> usize {
    serde_json::to_vec(value).map(|v| v.len()).unwrap_or(usize::MAX)
}

/// The default failure-bundle directory:
/// `<workspace>/target/dst-failures`, overridable with `DST_FAILURES_DIR`
/// (used by the emit tests).
pub fn failures_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("DST_FAILURES_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/dst-failures")
}

/// `<signature>-<seed>.json`, with any path-hostile characters in the signature
/// replaced so the filename is always valid.
pub fn bundle_filename(signature: &str, seed: u64) -> String {
    let safe: String = signature
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    format!("{safe}-{seed:016x}.json")
}

/// Write a bundle (full or slim) to `dir/<signature>-<seed>.json`, creating the
/// directory. Returns the path written.
pub fn emit(
    dir: &Path,
    signature: &str,
    seed: u64,
    bundle: &impl Serialize,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(bundle_filename(signature, seed));
    let json = serde_json::to_vec_pretty(bundle).map_err(std::io::Error::other)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::super::case_ir::{
        ContentTable, DeviceTimeline, FaultPlan, LinkTopology, Op, Topology,
    };
    use super::*;

    fn sample_case() -> Case {
        let mut content_table = ContentTable::default();
        content_table.insert(1, b"payload".to_vec());
        Case {
            seed: 7,
            topology: Topology {
                device_count: 2,
                links: vec![
                    LinkTopology { group_id: "g".into(), initial_online: true },
                    LinkTopology { group_id: "g".into(), initial_online: true },
                ],
            },
            workload: vec![DeviceTimeline {
                device_index: 0,
                ops: vec![(0, Op::Write { path: "a.txt".into(), content_id: 1 })],
            }],
            fault_schedule: Vec::new(),
            content_table,
            fault_plan: FaultPlan::default(),
            history_steps: Vec::new(),
        }
    }

    fn timeline(n: usize) -> Vec<TimelineEvent> {
        (0..n)
            .map(|i| TimelineEvent {
                event_index: i,
                sim_time_nanos: (i as u64) * 1000,
                device: Some(i % 2),
                summary: format!("event {i}: wrote dst-{:02}.bin under seed", i % 6),
            })
            .collect()
    }

    fn inputs(full_timeline: Vec<TimelineEvent>, first: Option<FirstDivergence>) -> BundleInputs {
        BundleInputs {
            scenario: "dst_two_device_chaos".into(),
            seed: 0xABCD,
            signature: "Convergence.dev_N.file_N@sim".into(),
            case: sample_case(),
            case_min: None,
            violations: vec![BundledViolation {
                kind: "Convergence".into(),
                path: Some("a.txt".into()),
                content_ids: vec![1],
                devices: vec![0, 1],
                detail: "devices disagree on a.txt".into(),
                triage: Some(TriageVerdict::LikelyProductBug),
            }],
            first_divergence: first,
            full_timeline,
            path_states: vec![PathState {
                path: "a.txt".into(),
                per_device: vec![
                    DevicePathState {
                        device: 0,
                        index_row: Some(IndexRowSummary {
                            deleted: false,
                            size: 7,
                            mtime_unix_nanos: 123,
                            block_count: 1,
                        }),
                        content_hash: Some("abcd".into()),
                    },
                    DevicePathState { device: 1, index_row: None, content_hash: None },
                ],
            }],
            full_log_pointer: Some("target/dst-logs/seed-abcd.log".into()),
        }
    }

    #[test]
    fn full_bundle_round_trips_through_json() {
        let first = Some(FirstDivergence {
            sim_time_nanos: 5000,
            event_index: 5,
            oracle_kind: "Convergence".into(),
        });
        let bundle = assemble(inputs(timeline(12), first), BUNDLE_SIZE_CAP_BYTES);
        let json = serde_json::to_string(&bundle).unwrap();
        let back: FailureBundle = serde_json::from_str(&json).unwrap();
        // Compare by re-serialization (FailureBundle isn't PartialEq).
        assert_eq!(json, serde_json::to_string(&back).unwrap());
        assert_eq!(back.schema_version, BUNDLE_SCHEMA_VERSION);
        assert_eq!(back.form, "full");
        // Small timeline: nothing dropped.
        assert!(back.truncated.is_none());
        assert_eq!(back.timeline.len(), 12);
    }

    #[test]
    fn cap_is_enforced_with_visible_truncation_centered_on_divergence() {
        // A timeline far larger than the cap can hold.
        let first = Some(FirstDivergence {
            sim_time_nanos: 4_000_000,
            event_index: 4000,
            oracle_kind: "Convergence".into(),
        });
        let bundle = assemble(inputs(timeline(8000), first), BUNDLE_SIZE_CAP_BYTES);

        assert!(
            serialized_len(&bundle) <= BUNDLE_SIZE_CAP_BYTES,
            "bundle exceeded cap: {} bytes",
            serialized_len(&bundle)
        );
        let trunc = bundle.truncated.expect("large timeline must be truncated");
        assert_eq!(trunc.original_event_count, 8000);
        assert!(trunc.dropped_event_count > 0);
        assert_eq!(trunc.kept_event_count, bundle.timeline.len());
        // The kept slice straddles the divergence point.
        let first_idx = bundle.timeline.first().unwrap().event_index;
        let last_idx = bundle.timeline.last().unwrap().event_index;
        assert!(
            first_idx <= 4000 && 4000 <= last_idx,
            "slice {first_idx}..={last_idx} misses 4000"
        );
        // The escape hatch survives truncation.
        assert!(bundle.full_log_pointer.is_some());
    }

    #[test]
    fn slim_bundle_round_trips() {
        let slim = SlimBundle::new(
            "dst_two_device_chaos",
            0xABCD,
            "StructuralIndexDiskMismatch.dev_N.file_N@sim",
            TriageVerdict::LikelyHarnessArtifact { knob: None },
        );
        let json = serde_json::to_string(&slim).unwrap();
        let back: SlimBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(slim, back);
        assert_eq!(back.form, "slim");
    }

    #[test]
    fn emit_writes_and_reloads_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = assemble(inputs(timeline(6), None), BUNDLE_SIZE_CAP_BYTES);
        let path = emit(dir.path(), &bundle.signature, bundle.seed, &bundle).unwrap();
        assert!(path.exists());
        assert!(path.file_name().unwrap().to_string_lossy().ends_with(".json"));

        let reloaded: FailureBundle =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_string(&reloaded).unwrap(),
            serde_json::to_string(&bundle).unwrap()
        );
    }

    #[test]
    fn filename_sanitizes_signature() {
        let name = bundle_filename("Convergence.dev_N/file_N@sim", 0xABCD);
        assert!(!name.contains('/'));
        assert!(!name.contains('@'));
        assert!(name.ends_with(".json"));
    }
}
