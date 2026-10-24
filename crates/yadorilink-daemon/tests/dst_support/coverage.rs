//! Sweep coverage-gap accounting.
//!
//! After a sweep, an agent's detection question is "what op-kind × fault-kind ×
//! topology combination has *no* coverage?" — answered here from data, not by
//! reading every scenario source. A `CoverageAccumulator` folds each run's
//! `Case` into frequency counts over the Case IR dimensions (op kind, fault
//! kind, topology, and pairwise op×fault), and `CoverageReport` adds the
//! explicit `never_exercised` list derived from a declared validity model
//! (the design: the gap list is signal, not noise, because validity is declared
//! next to the generator).
//!
//! This is accounting, not feedback-directed generation (a Non-Goal): it counts
//! what ran, it does not steer what runs next.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::case_ir::{Case, DiskFault, Fault, NetFault, Op};

/// Stable label for an op kind (the variant name; path/content operands are
/// coverage-irrelevant).
pub fn op_kind_label(op: &Op) -> &'static str {
    match op {
        Op::Write { .. } => "Write",
        Op::Edit { .. } => "Edit",
        Op::Delete { .. } => "Delete",
        Op::Rename { .. } => "Rename",
        Op::Move { .. } => "Move",
        Op::Mkdir { .. } => "Mkdir",
        Op::Rmdir { .. } => "Rmdir",
        Op::RmTree { .. } => "RmTree",
        Op::RenameTree { .. } => "RenameTree",
        Op::Chmod { .. } => "Chmod",
        Op::ConflictingConcurrent { .. } => "ConflictingConcurrent",
    }
}

/// The op axis of the validity model: exactly the kinds the fault-carrying
/// generators (`generate_case`, `generate_pairwise`) draw from.
///
/// The whole-tree kinds (`RmTree`, `RenameTree`) are counted in
/// `op_kinds` when a case carries them, but are not on this axis: their
/// only generator, `generate_directory_case`, is fault-free, so every
/// op×fault pair they would add could never be exercised and would only
/// pad `never_exercised`. Put them here when a faulted generator emits
/// them.
pub const OP_KINDS: &[&str] = &[
    "Write",
    "Edit",
    "Delete",
    "Rename",
    "Move",
    "Mkdir",
    "Rmdir",
    "Chmod",
    "ConflictingConcurrent",
];

/// Stable label for a fault kind, granular to the sub-variant where the design
/// fault model distinguishes them (Net.*/Disk.*).
pub fn fault_kind_label(fault: &Fault) -> String {
    match fault {
        Fault::Net(n) => format!("Net.{}", net_label(n)),
        Fault::Disk(d) => format!("Disk.{}", disk_label(d)),
        Fault::Crash { .. } => "Crash".to_string(),
        Fault::Restart { .. } => "Restart".to_string(),
        Fault::ClockSkew { .. } => "ClockSkew".to_string(),
        Fault::ClockJump { .. } => "ClockJump".to_string(),
    }
}

fn net_label(n: &NetFault) -> &'static str {
    match n {
        NetFault::Drop => "Drop",
        NetFault::Delay { .. } => "Delay",
        NetFault::Reorder => "Reorder",
        NetFault::Duplicate => "Duplicate",
        NetFault::Partition { .. } => "Partition",
        NetFault::Heal { .. } => "Heal",
        NetFault::PartitionOneWay { .. } => "PartitionOneWay",
        NetFault::HealOneWay { .. } => "HealOneWay",
        NetFault::DuplicateDatagrams { .. } => "DuplicateDatagrams",
        NetFault::StopDuplicating { .. } => "StopDuplicating",
        NetFault::HoldInbound { .. } => "HoldInbound",
        NetFault::StopHolding { .. } => "StopHolding",
    }
}

fn disk_label(d: &DiskFault) -> &'static str {
    match d {
        DiskFault::Enospc => "Enospc",
        DiskFault::Eio => "Eio",
        DiskFault::TornWrite => "TornWrite",
        DiskFault::FsyncFail => "FsyncFail",
        DiskFault::SlowIo { .. } => "SlowIo",
        DiskFault::SqliteBusy => "SqliteBusy",
        DiskFault::SqliteLocked => "SqliteLocked",
    }
}

/// Every fault kind in the Case IR vocabulary — the fault axis of the validity
/// model.
pub const FAULT_KINDS: &[&str] = &[
    "Net.Drop",
    "Net.Delay",
    "Net.Reorder",
    "Net.Duplicate",
    "Net.Partition",
    "Net.Heal",
    "Disk.Enospc",
    "Disk.Eio",
    "Disk.TornWrite",
    "Disk.FsyncFail",
    "Disk.SlowIo",
    "Disk.SqliteBusy",
    "Disk.SqliteLocked",
    "Crash",
    "Restart",
    "ClockSkew",
    "ClockJump",
];

/// Op×fault pairs that are NOT meaningful and so are excluded from the validity
/// model (the design: declared next to the generator so the gap list is signal).
///
/// Currently empty: on this branch `fault_schedule` is always empty (fault
/// injectors arrive with the harness-artifact hardening work), so there is
/// no exercised fault data to justify pruning any pair yet. As real fault
/// coverage lands, add genuinely-meaningless pairs here with a one-line reason
/// so `never_exercised` stays actionable rather than noisy.
pub const EXCLUDED_OP_FAULT_PAIRS: &[(&str, &str)] = &[];

/// The declared set of meaningful op×fault pairs: the full vocabulary cross
/// product minus [`EXCLUDED_OP_FAULT_PAIRS`].
pub fn valid_op_fault_pairs() -> BTreeSet<(String, String)> {
    let excluded: BTreeSet<(&str, &str)> = EXCLUDED_OP_FAULT_PAIRS.iter().copied().collect();
    let mut set = BTreeSet::new();
    for &op in OP_KINDS {
        for &fault in FAULT_KINDS {
            if !excluded.contains(&(op, fault)) {
                set.insert((op.to_string(), fault.to_string()));
            }
        }
    }
    set
}

/// Frequency accounting over Case IR dimensions, accumulated across a sweep.
#[derive(Debug, Default, Clone)]
pub struct CoverageAccumulator {
    case_count: u64,
    op_kinds: BTreeMap<String, u64>,
    fault_kinds: BTreeMap<String, u64>,
    topologies: BTreeMap<String, u64>,
    /// Number of cases exercising each `(op_kind, fault_kind)` pair.
    op_fault_pairs: BTreeMap<(String, String), u64>,
}

impl CoverageAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one run's `Case` into the counts. Op-kind and fault-kind counts are
    /// per-occurrence; the pairwise count is per-case (a pair is credited once
    /// per case that contains both kinds), so it reads as "how many cases
    /// exercised this combination".
    pub fn record_case(&mut self, case: &Case) {
        self.case_count += 1;
        *self.topologies.entry(topology_label(case)).or_default() += 1;

        let mut case_ops: BTreeSet<String> = BTreeSet::new();
        for timeline in &case.workload {
            for (_, op) in &timeline.ops {
                let label = op_kind_label(op).to_string();
                *self.op_kinds.entry(label.clone()).or_default() += 1;
                case_ops.insert(label);
            }
        }

        let mut case_faults: BTreeSet<String> = BTreeSet::new();
        for (_, fault) in &case.fault_schedule {
            let label = fault_kind_label(fault);
            *self.fault_kinds.entry(label.clone()).or_default() += 1;
            case_faults.insert(label);
        }

        for op in &case_ops {
            for fault in &case_faults {
                *self.op_fault_pairs.entry((op.clone(), fault.clone())).or_default() += 1;
            }
        }
    }

    /// The `(op, fault)` pairs at least one case exercised.
    pub fn exercised_pairs(&self) -> BTreeSet<(String, String)> {
        self.op_fault_pairs.keys().cloned().collect()
    }

    /// Finalize into a serializable report: the accumulated counts plus the
    /// `never_exercised` gap list (valid pairs no case covered).
    pub fn into_report(self, sweep_id: impl Into<String>) -> CoverageReport {
        let exercised = self.exercised_pairs();
        let never_exercised: Vec<OpFaultPair> = valid_op_fault_pairs()
            .into_iter()
            .filter(|p| !exercised.contains(p))
            .map(|(op, fault)| OpFaultPair { op, fault })
            .collect();
        CoverageReport {
            schema_version: COVERAGE_SCHEMA_VERSION,
            sweep_id: sweep_id.into(),
            case_count: self.case_count,
            op_kinds: self.op_kinds,
            fault_kinds: self.fault_kinds,
            topologies: self.topologies,
            op_fault_pairs: self
                .op_fault_pairs
                .into_iter()
                .map(|((op, fault), count)| (format!("{op}×{fault}"), count))
                .collect(),
            never_exercised,
        }
    }
}

/// `"{device_count}-device"` topology label. Coarse on purpose — device count
/// is the coverage-relevant axis; finer link structure is not yet varied.
pub fn topology_label(case: &Case) -> String {
    format!("{}-device", case.topology.device_count)
}

pub const COVERAGE_SCHEMA_VERSION: u32 = 1;

/// A never-exercised op×fault combination, expressed in Case IR terms so an
/// agent can turn it directly into the next detection target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OpFaultPair {
    pub op: String,
    pub fault: String,
}

/// Machine-readable per-sweep coverage report (`target/dst-coverage/sweep-<id>.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub schema_version: u32,
    pub sweep_id: String,
    pub case_count: u64,
    pub op_kinds: BTreeMap<String, u64>,
    pub fault_kinds: BTreeMap<String, u64>,
    pub topologies: BTreeMap<String, u64>,
    pub op_fault_pairs: BTreeMap<String, u64>,
    pub never_exercised: Vec<OpFaultPair>,
}

/// Default coverage directory: `<workspace>/target/dst-coverage`, overridable
/// with `DST_COVERAGE_DIR`.
pub fn coverage_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("DST_COVERAGE_DIR") {
        return std::path::PathBuf::from(dir);
    }
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/dst-coverage")
}

/// Write a coverage report to `dir/sweep-<id>.json`, creating the directory.
pub fn emit(dir: &std::path::Path, report: &CoverageReport) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("sweep-{}.json", report.sweep_id));
    let json = serde_json::to_vec_pretty(report).map_err(std::io::Error::other)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::super::case_ir::{
        ContentTable, DeviceTimeline, FaultPlan, LinkTopology, NetFault, Op, SimNanos, Topology,
    };
    use super::*;

    fn case_with(device_count: usize, ops: Vec<Op>, faults: Vec<(SimNanos, Fault)>) -> Case {
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
            fault_schedule: faults,
            content_table: ContentTable::default(),
            fault_plan: FaultPlan::default(),
            history_steps: Vec::new(),
        }
    }

    #[test]
    fn accumulates_op_fault_and_topology_counts() {
        let mut acc = CoverageAccumulator::new();
        acc.record_case(&case_with(
            2,
            vec![
                Op::Write { path: "a".into(), content_id: 1 },
                Op::Write { path: "b".into(), content_id: 2 },
                Op::Delete { path: "a".into() },
            ],
            vec![(SimNanos::ZERO, Fault::Net(NetFault::Drop))],
        ));
        acc.record_case(&case_with(3, vec![Op::Write { path: "c".into(), content_id: 3 }], vec![]));

        assert_eq!(acc.case_count, 2);
        assert_eq!(acc.op_kinds["Write"], 3);
        assert_eq!(acc.op_kinds["Delete"], 1);
        assert_eq!(acc.fault_kinds["Net.Drop"], 1);
        assert_eq!(acc.topologies["2-device"], 1);
        assert_eq!(acc.topologies["3-device"], 1);
        // Pairwise: case 1 has {Write,Delete} × {Net.Drop} = 2 pairs, once each.
        assert_eq!(acc.op_fault_pairs[&("Write".into(), "Net.Drop".into())], 1);
        assert_eq!(acc.op_fault_pairs[&("Delete".into(), "Net.Drop".into())], 1);
    }

    #[test]
    fn never_exercised_lists_valid_pairs_no_case_covered() {
        let mut acc = CoverageAccumulator::new();
        acc.record_case(&case_with(
            2,
            vec![Op::Write { path: "a".into(), content_id: 1 }],
            vec![(SimNanos::ZERO, Fault::Net(NetFault::Drop))],
        ));
        let report = acc.into_report("test-1");

        // The exercised pair is absent from never_exercised.
        assert!(!report
            .never_exercised
            .contains(&OpFaultPair { op: "Write".into(), fault: "Net.Drop".into() }));
        // A valid-but-unseen pair is present.
        assert!(report
            .never_exercised
            .contains(&OpFaultPair { op: "Rename".into(), fault: "Disk.Eio".into() }));
        // Sanity: total valid pairs = exercised + never_exercised.
        assert_eq!(report.never_exercised.len() + 1, valid_op_fault_pairs().len());
    }

    /// A kind on the op axis that no faulted generator emits makes
    /// `|FAULT_KINDS|` permanent entries in every sweep's `never_exercised`.
    #[test]
    fn op_axis_is_the_faulted_generators_alphabet() {
        let generated: Vec<String> =
            super::super::generator::OP_KINDS.iter().map(|k| format!("{k:?}")).collect();
        assert_eq!(OP_KINDS, generated.iter().map(String::as_str).collect::<Vec<_>>());
    }

    #[test]
    fn report_emits_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let mut acc = CoverageAccumulator::new();
        acc.record_case(&case_with(2, vec![Op::Write { path: "a".into(), content_id: 1 }], vec![]));
        let report = acc.into_report("sweep-xyz");
        let path = emit(dir.path(), &report).unwrap();
        assert!(path.to_string_lossy().ends_with("sweep-sweep-xyz.json"));
        let back: CoverageReport =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back, report);
    }
}
