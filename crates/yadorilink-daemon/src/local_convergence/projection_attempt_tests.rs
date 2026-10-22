#![cfg(test)]

use super::types::{ProjectionAttempt, SettlementEvidence};

/// Placeholder evidence for tests exercising `settled`/`retry` KEY-SET
/// semantics, which `path_fully_resolved`/`is_settled`/`merge` are
/// documented to preserve regardless of evidence content — the exact
/// variant is irrelevant to what these tests assert.
fn placeholder_evidence() -> SettlementEvidence {
    SettlementEvidence::ExactAbsent { mutation_generation: 1 }
}

/// Regression test: the Convergence Engine (`yadorilink-daemon`'s
/// `process_group`) must not retire a job as soon as its own seed path
/// is `settled` while a conflict copy derived from that path is still
/// in `retry` -- that would silently drop the still-outstanding
/// obligation.
/// `path_fully_resolved` must return `false` in exactly this case, even
/// though `is_settled` alone would say `true`.
#[test]
fn path_fully_resolved_is_false_when_its_derived_conflict_copy_still_needs_retry() {
    let copy_path = yadorilink_replica_domain::conflict::conflict_copy_path(
        "shared.bin",
        0,
        "device-2",
        &[0x3c, 0x58, 0xcc, 0xc5],
    );
    let attempt = ProjectionAttempt {
        settled: std::collections::BTreeMap::from([(
            "shared.bin".to_string(),
            placeholder_evidence(),
        )]),
        retry: std::collections::BTreeSet::from([copy_path]),
        ..Default::default()
    };
    assert!(attempt.is_settled("shared.bin"), "sanity: the seed path itself did settle");
    assert!(
        !attempt.path_fully_resolved("shared.bin"),
        "a settled seed path must not read as fully resolved while its own \
         derived conflict copy is still outstanding in retry"
    );
}

/// The positive case: once neither the seed path nor any conflict copy
/// derived from it remains in `retry`, `path_fully_resolved` agrees with
/// `is_settled`.
#[test]
fn path_fully_resolved_is_true_when_settled_with_no_outstanding_conflict_copy() {
    let attempt = ProjectionAttempt {
        settled: std::collections::BTreeMap::from([(
            "shared.bin".to_string(),
            placeholder_evidence(),
        )]),
        retry: std::collections::BTreeSet::new(),
        ..Default::default()
    };
    assert!(attempt.path_fully_resolved("shared.bin"));
}

/// A `retry` entry that is NOT a conflict copy of `path` (an unrelated
/// path happening to also need retry this attempt) must not affect
/// `path`'s own resolution.
#[test]
fn path_fully_resolved_ignores_an_unrelated_retry_path() {
    let attempt = ProjectionAttempt {
        settled: std::collections::BTreeMap::from([(
            "shared.bin".to_string(),
            placeholder_evidence(),
        )]),
        retry: std::collections::BTreeSet::from(["unrelated.txt".to_string()]),
        ..Default::default()
    };
    assert!(attempt.path_fully_resolved("shared.bin"));
}
