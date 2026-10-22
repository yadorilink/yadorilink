//! An *independent reference model* for the two-device chaos scenario's
//! converged end state.
//!
//! Why this exists (the gap it closes): `oracle.rs`'s `GlobalOracle` is an
//! *invariant checker* — it observes the real run and asserts predicates
//! (convergence, no-loss, no-corruption, conflict-copy accounting,
//! structural). Every one of those predicates is structurally blind to a
//! *consistent-but-wrong converged winner*: if every device agrees on a
//! value that some device genuinely wrote, but which is NOT the value the
//! conflict rules say should win, `check_convergence` (all devices agree),
//! `check_no_loss` (both racing writes survive somewhere), and
//! `check_no_corruption` (every byte on disk was written by someone) all
//! pass. Nothing re-derives, from the input timeline alone, *which* content
//! should be the live/canonical winner and *which* should be a conflict
//! copy.
//!
//! This module is that missing reference model. It takes the *input*
//! timeline (per-device ordered ops, with their input mtimes and causal
//! round) — never the version vectors the implementation produced — and
//! predicts, per path, the expected converged state: the winning content
//! id at the canonical path plus the multiset of conflict-copy contents.
//! `check_reference_model` then compares that prediction to the real
//! converged on-disk snapshot.
//!
//! ## Independence
//!
//! The winner rule here is re-derived from `conflict.rs`'s *specification*,
//! not by calling `resolve_and_apply_conflict`/`a_is_loser`/
//! `resolve_conflict_names` (which would defeat the point — a bug in the
//! production rule would be copied verbatim into its own oracle). The spec,
//! restated:
//!
//! - A genuine concurrent conflict on a path is resolved by *last-writer-
//!   wins on clamped mtime*: the copy with the later effective mtime wins
//!   the canonical name; the older one is demoted. Effective mtime clamps a
//!   claimed value to at most `now + MAX_FUTURE_MTIME_SKEW_NANOS` before
//!   comparison.
//! - Ties (equal effective mtime) break on device id: the *larger* device
//!   id wins the canonical name (`a_is_loser` returns true — i.e. `a` is the
//!   loser — when `eff_a == eff_b && device_a < device_b`).
//! - Between two concurrent *writes*, that LWW decision picks the winner
//!   directly and *deterministically*: the later-mtime write keeps the
//!   canonical name, the older is preserved under a `(conflicted copy...)`
//!   name. The chaos driver always stamps the second racer's mtime strictly
//!   later, so the winner is a fixed function of the input timeline — this
//!   is the case the model checks.
//! - A concurrent *write-vs-delete* race has **two legitimate converged
//!   outcomes** and is therefore NOT deterministically predictable from the
//!   input timeline alone. Verified against the live scenario across seeds
//!   with the identical race construction (a pending write vs a
//!   concurrently-dispatched delete):
//!     * sometimes the delete is adopted first (as a causally-later
//!       tombstone over the shared base) and then superseded by the
//!       still-pending write resurfacing → the *write wins* the canonical
//!       path, delete dropped, no conflict copy (e.g. seed 3298840596,
//!       chaos-c.bin);
//!     * sometimes the two genuinely reach `resolve_and_apply_conflict` as
//!       `Concurrent` and mtime-LWW makes the later-mtime *delete win* the
//!       canonical path, with the losing write preserved as a conflict copy
//!       (e.g. seed 800000, chaos-a.bin).
//!   Both are consistent, converged, and *data-preserving* (the write's
//!   content survives either as the live file or as a conflict copy), so
//!   neither is "the wrong winner" — the choice depends on simulated
//!   scheduling, not on anything the input timeline determines. The model
//!   therefore **abstains** on any path whose timeline contains a concurrent
//!   write-vs-delete race: it makes no live/conflict-copy prediction for
//!   that path at all. Data-preservation for those paths is still covered by
//!   the existing no-loss / convergence / conflict-copy-accounting oracles;
//!   only the *specific-winner* assertion is skipped, since there is no
//!   single correct winner to assert.
//!
//! ## Conflict-copy identity normalization
//!
//! A conflict copy's real filename embeds a timestamp, device id, and an
//! 8-hex content-hash fragment, none of which this model can (or should)
//! predict. Prediction and checking therefore compare conflict copies by
//! *content* only (is-conflict-copy + which bytes), exactly as the task
//! requires — a conflict copy is identified by "a `(conflicted copy...)`
//! sibling of this path holding these bytes", nothing finer.
//!
//! ## Causality reconstruction (no VVs)
//!
//! The two-device chaos driver advances a monotonic per-run round counter;
//! each round touches one path either *solo* (one op) or as a *race* (two
//! concurrent ops on the same path in the same round). Two ops sharing a
//! `(path, round)` are exactly the driver's genuine-concurrent race pair;
//! anything else is causally ordered by round. That is the entire causal
//! signal this model needs, and it is derived from op *structure*, never
//! from the implementation's observed version vectors.

#![cfg(turmoil)]
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;

use super::case_ir::ContentTable;
use super::content_hash;
use super::oracle::{Violation, ViolationKind};

/// Skew bound, re-declared here (not imported from `conflict.rs`) to keep
/// this model independent of the production constant it is checking. Same
/// documented value: one day in nanoseconds.
pub const MAX_FUTURE_MTIME_SKEW_NANOS: i64 = 24 * 60 * 60 * 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefKind {
    Write { content_id: u64 },
    Delete,
}

/// One input op in the reference timeline. Deliberately a flat,
/// self-contained shape (device id string + causal round + input mtime),
/// so the unit tests can hand-build timelines with no dependency on the
/// sync engine or the driver's internals.
#[derive(Debug, Clone)]
pub struct RefOp {
    pub path: String,
    pub device_id: String,
    /// Monotonic causal generation. Ops sharing a `(path, round)` are
    /// genuinely concurrent (a race); across rounds, a higher round is
    /// strictly causally later.
    pub round: u64,
    pub kind: RefKind,
    /// The input mtime this op stamped (unix nanos) — the raw LWW input,
    /// before any `now`-relative clamping.
    pub mtime_nanos: i64,
}

/// The predicted converged state of a single path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPrediction {
    /// Content id expected at the live/canonical path, or `None` if the
    /// path is expected to be deleted/absent.
    pub live: Option<u64>,
    /// Multiset of content ids expected to survive as `(conflicted
    /// copy...)` siblings of this path. Sorted for stable comparison.
    pub conflict_copies: Vec<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Prediction {
    pub paths: HashMap<String, PathPrediction>,
}

/// Re-derived, independent copy of `conflict.rs`'s `a_is_loser` spec: is
/// `(mtime_a, device_a)` the loser (older effective mtime; ties broken by
/// the *smaller* device id losing) against `(mtime_b, device_b)`?
fn is_loser(mtime_a: i64, device_a: &str, mtime_b: i64, device_b: &str, now_nanos: i64) -> bool {
    let ceiling = now_nanos.saturating_add(MAX_FUTURE_MTIME_SKEW_NANOS);
    let eff_a = mtime_a.min(ceiling);
    let eff_b = mtime_b.min(ceiling);
    eff_a < eff_b || (eff_a == eff_b && device_a < device_b)
}

/// Predicts the converged end state per path from the input timeline.
///
/// `now_nanos` is the wall-clock "now" the LWW clamp is relative to; pass a
/// far-future value (the driver uses `i64::MAX`) when no adversarial mtime
/// is in play, so clamping is a no-op — the unit tests pass a concrete
/// value to exercise the clamp.
pub fn predict(ops: &[RefOp], now_nanos: i64) -> Prediction {
    // Group ops by path, then by round (ascending). A round with >1 op on
    // a path is a genuine-concurrent race; a round with exactly one is a
    // causally-ordered solo op superseding everything before it.
    let mut by_path: HashMap<String, BTreeMap<u64, Vec<RefOp>>> = HashMap::new();
    for op in ops {
        by_path.entry(op.path.clone()).or_default().entry(op.round).or_default().push(op.clone());
    }

    let mut paths = HashMap::new();
    for (path, rounds) in by_path {
        // Abstain on any path with a concurrent write-vs-delete race: that
        // race has two legitimate converged outcomes (write wins / delete
        // wins), so there is no single winner to assert (see module doc).
        // A "mixed" race group is one round with >=1 write AND >=1 delete.
        let has_write_delete_race = rounds.values().any(|group| {
            group.len() > 1
                && group.iter().any(|o| matches!(o.kind, RefKind::Write { .. }))
                && group.iter().any(|o| matches!(o.kind, RefKind::Delete))
        });
        if has_write_delete_race {
            continue; // unpredictable path -- no prediction emitted
        }

        // `live` = the current canonical content (None = deleted/absent).
        // `conflict_copies` accumulate: a `(conflicted copy...)` sibling is
        // its own distinct file, so a later solo/race round to the *base*
        // path never removes an earlier round's conflict copy — it persists
        // to the converged end state.
        let mut live: Option<u64> = None;
        let mut conflict_copies: Vec<u64> = Vec::new();

        for (_round, group) in rounds {
            if group.len() == 1 {
                // Solo op: causally supersedes everything prior on this
                // path. Sets the live content; leaves existing conflict
                // copies untouched (separate files).
                match &group[0].kind {
                    RefKind::Write { content_id } => live = Some(*content_id),
                    RefKind::Delete => live = None,
                }
            } else {
                // Concurrent race group. Mixed write-vs-delete races were
                // already abstained above, so this is an all-write race (or,
                // in principle, an all-delete one). Among concurrent writes
                // the winner is the one with the greatest effective mtime
                // (ties → larger device id), by the LWW spec `is_loser`
                // encodes; every other write is preserved as a conflict copy.
                // Structured as a linear "is anyone a strict winner over me?"
                // fold so it generalizes past the 2-way case the driver produces.
                let write_idxs: Vec<usize> = (0..group.len())
                    .filter(|&i| matches!(group[i].kind, RefKind::Write { .. }))
                    .collect();
                if write_idxs.is_empty() {
                    // An all-delete race (not produced by the driver, which
                    // always makes the pending `x` side a write): the path is
                    // deleted, no conflict copies.
                    live = None;
                } else {
                    let winner_idx = *write_idxs
                        .iter()
                        .max_by(|&&i, &&j| {
                            if is_loser(
                                group[j].mtime_nanos,
                                &group[j].device_id,
                                group[i].mtime_nanos,
                                &group[i].device_id,
                                now_nanos,
                            ) {
                                std::cmp::Ordering::Greater
                            } else {
                                std::cmp::Ordering::Less
                            }
                        })
                        .expect("non-empty writes");
                    for &idx in &write_idxs {
                        if let RefKind::Write { content_id } = &group[idx].kind {
                            if idx == winner_idx {
                                live = Some(*content_id);
                            } else {
                                conflict_copies.push(*content_id);
                            }
                        }
                    }
                }
            }
        }

        conflict_copies.sort_unstable();
        paths.insert(path, PathPrediction { live, conflict_copies });
    }

    Prediction { paths }
}

/// Flat (top-level) filename split into `(stem, ext)` — the driver's candidate
/// paths and their conflict copies are all flat, no directories.
fn split_stem_ext(name: &str) -> (&str, Option<&str>) {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (name, None),
    }
}

/// True if flat filename `candidate` is a `(conflicted copy...)` sibling of
/// base path `base`. Independent filename-shape parsing (not a call into
/// `conflict.rs`), matching the documented naming convention `<stem>
/// (conflicted copy, ...).<ext>`.
fn is_conflict_copy_of(candidate: &str, base: &str) -> bool {
    let (cand_stem, cand_ext) = split_stem_ext(candidate);
    let (base_stem, base_ext) = split_stem_ext(base);
    let marker = " (conflicted copy, ";
    let Some(idx) = cand_stem.find(marker) else { return false };
    cand_ext == base_ext && &cand_stem[..idx] == base_stem
}

/// Builds a flat `name -> content-hash` snapshot of a device root — the
/// same shape `oracle.rs`'s `flat_hash_snapshot` produces, reimplemented
/// here so this module stays self-contained.
fn flat_snapshot(root: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir(root) else { return out };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Ok(bytes) = std::fs::read(entry.path()) {
            out.insert(name, content_hash(&bytes));
        }
    }
    out
}

/// Compares the reference-model `prediction` against the real converged
/// on-disk state, emitting a `ConvergedToWrongWinner` violation for every
/// path whose live winner or conflict-copy multiset the implementation got
/// wrong.
///
/// `devices` are assumed to have already converged (the caller runs this
/// only at a quiescent point, after `check_convergence` passes); the real
/// state is read from the first device, since by convergence every device
/// agrees. Comparison is by content hash, so conflict-copy filenames'
/// timestamp/device/hash fragments are ignored — a conflict copy is
/// identified purely by "a `(conflicted copy...)` sibling holding these
/// bytes".
pub fn check_reference_model(
    prediction: &Prediction,
    content_table: &ContentTable,
    devices: &[(&Path, &ReplicaCoordinator)],
) -> Vec<Violation> {
    let Some((root0, _)) = devices.first() else { return Vec::new() };
    let snapshot = flat_snapshot(root0);
    check_reference_model_against_snapshot(prediction, content_table, &snapshot)
}

/// The pure core of `check_reference_model`: compares a prediction against
/// an already-materialized `name -> content-hash` snapshot. Split out so
/// the unit tests can drive it with a hand-built snapshot, no filesystem.
pub fn check_reference_model_against_snapshot(
    prediction: &Prediction,
    content_table: &ContentTable,
    snapshot: &HashMap<String, String>,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let hash_of = |id: u64| -> Option<String> { content_table.get(id).map(|b| content_hash(b)) };

    for (path, pred) in &prediction.paths {
        // --- Live/canonical winner ---
        let real_live = snapshot.get(path).cloned();
        let expected_live = pred.live.and_then(hash_of);
        if real_live != expected_live {
            violations.push(Violation {
                kind: ViolationKind::ConvergedToWrongWinner,
                path: Some(path.clone()),
                content_ids: pred.live.into_iter().collect(),
                devices: Vec::new(),
                detail: format!(
                    "live/canonical winner mismatch: reference model predicts {}, \
                     converged disk has {}",
                    describe(&expected_live, pred.live),
                    describe_hash(&real_live),
                ),
            });
        }

        // --- Conflict-copy multiset (by content, names normalized away) ---
        let mut real_ccs: Vec<String> = snapshot
            .iter()
            .filter(|(name, _)| is_conflict_copy_of(name, path))
            .map(|(_, hash)| hash.clone())
            .collect();
        real_ccs.sort();

        let mut expected_ccs: Vec<String> =
            pred.conflict_copies.iter().filter_map(|id| hash_of(*id)).collect();
        expected_ccs.sort();

        if real_ccs != expected_ccs {
            violations.push(Violation {
                kind: ViolationKind::ConvergedToWrongWinner,
                path: Some(path.clone()),
                content_ids: pred.conflict_copies.clone(),
                devices: Vec::new(),
                detail: format!(
                    "conflict-copy set mismatch: reference model predicts {} conflict \
                     copy/copies (hashes {:?}), converged disk has {} (hashes {:?})",
                    expected_ccs.len(),
                    short(&expected_ccs),
                    real_ccs.len(),
                    short(&real_ccs),
                ),
            });
        }
    }

    violations
}

fn describe(hash: &Option<String>, id: Option<u64>) -> String {
    match (hash, id) {
        (Some(h), Some(id)) => format!("content_id {id} (hash {})", &h[..h.len().min(8)]),
        (None, None) => "no live file (deleted)".to_string(),
        (Some(h), None) => format!("hash {}", &h[..h.len().min(8)]),
        (None, Some(id)) => format!("content_id {id} (missing from content table)"),
    }
}

fn describe_hash(hash: &Option<String>) -> String {
    match hash {
        Some(h) => format!("hash {}", &h[..h.len().min(8)]),
        None => "no live file".to_string(),
    }
}

fn short(hashes: &[String]) -> Vec<String> {
    hashes.iter().map(|h| h[..h.len().min(8)].to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(path: &str, dev: &str, round: u64, content_id: u64, mtime: i64) -> RefOp {
        RefOp {
            path: path.to_string(),
            device_id: dev.to_string(),
            round,
            kind: RefKind::Write { content_id },
            mtime_nanos: mtime,
        }
    }
    fn d(path: &str, dev: &str, round: u64, mtime: i64) -> RefOp {
        RefOp {
            path: path.to_string(),
            device_id: dev.to_string(),
            round,
            kind: RefKind::Delete,
            mtime_nanos: mtime,
        }
    }

    const NOW: i64 = i64::MAX; // no clamping in these cases

    fn pred_of(path: &str, ops: &[RefOp]) -> PathPrediction {
        predict(ops, NOW).paths.get(path).cloned().unwrap()
    }

    // ---- predict(): the model verified in isolation ----

    #[test]
    fn solo_write_is_the_live_winner_no_conflict_copies() {
        let p = pred_of("f.bin", &[w("f.bin", "device-a", 0, 7, 1000)]);
        assert_eq!(p, PathPrediction { live: Some(7), conflict_copies: vec![] });
    }

    #[test]
    fn later_solo_write_supersedes_earlier() {
        let ops = [w("f.bin", "device-a", 0, 1, 1000), w("f.bin", "device-b", 1, 2, 2000)];
        assert_eq!(
            pred_of("f.bin", &ops),
            PathPrediction { live: Some(2), conflict_copies: vec![] }
        );
    }

    #[test]
    fn solo_delete_leaves_no_live_file() {
        let ops = [w("f.bin", "device-a", 0, 1, 1000), d("f.bin", "device-a", 1, 2000)];
        assert_eq!(pred_of("f.bin", &ops), PathPrediction { live: None, conflict_copies: vec![] });
    }

    #[test]
    fn race_write_write_later_mtime_wins_older_becomes_conflict_copy() {
        // device-a mtime 1000 (older) vs device-b mtime 2000 (newer) in the
        // same round -> b wins the canonical name, a is the conflict copy.
        let ops = [w("f.bin", "device-a", 0, 10, 1000), w("f.bin", "device-b", 0, 20, 2000)];
        assert_eq!(
            pred_of("f.bin", &ops),
            PathPrediction { live: Some(20), conflict_copies: vec![10] }
        );
    }

    #[test]
    fn race_write_write_mtime_tie_breaks_to_larger_device_id() {
        // Equal mtimes -> larger device id ("device-b") wins; "device-a"
        // loses and becomes the conflict copy.
        let ops = [w("f.bin", "device-a", 0, 10, 5000), w("f.bin", "device-b", 0, 20, 5000)];
        assert_eq!(
            pred_of("f.bin", &ops),
            PathPrediction { live: Some(20), conflict_copies: vec![10] }
        );
    }

    #[test]
    fn write_vs_delete_race_path_is_abstained_not_predicted() {
        // A concurrent write-vs-delete race has two legitimate converged
        // outcomes (write wins / delete wins -- both data-preserving,
        // observed across seeds 3298840596 and 800000), so the model makes
        // NO prediction for the path at all. Neither mtime order changes
        // this: abstention holds regardless of which side is newer.
        let newer_delete = [w("f.bin", "device-a", 0, 10, 1000), d("f.bin", "device-b", 0, 2000)];
        assert!(predict(&newer_delete, NOW).paths.get("f.bin").is_none());
        let newer_write = [w("f.bin", "device-a", 0, 10, 2000), d("f.bin", "device-b", 0, 1000)];
        assert!(predict(&newer_write, NOW).paths.get("f.bin").is_none());
    }

    #[test]
    fn a_single_write_delete_race_abstains_the_whole_path_even_across_later_rounds() {
        // Regression for the seed-800000 shape: once a path has *any*
        // write-vs-delete race, its converged conflict-copy set is
        // permanently unpredictable (the losing write may or may not have
        // become a conflict copy), so the model abstains on the whole path
        // even though later rounds are themselves deterministic.
        let ops = [
            w("f.bin", "device-b", 0, 5, 1000),
            d("f.bin", "device-a", 0, 2000),
            d("f.bin", "device-a", 1, 3000),
        ];
        assert!(predict(&ops, NOW).paths.get("f.bin").is_none());
    }

    #[test]
    fn a_write_write_race_on_a_path_with_no_delete_race_is_still_predicted() {
        // Abstention is scoped per path: a path whose only race is
        // write-write stays fully predicted even if *other* paths in the run
        // have write-delete races.
        let ops = [
            w("a.bin", "device-a", 0, 10, 1000),
            w("a.bin", "device-b", 0, 20, 2000),
            w("b.bin", "device-a", 0, 30, 1000),
            d("b.bin", "device-b", 0, 2000),
        ];
        let pred = predict(&ops, NOW);
        assert_eq!(
            pred.paths.get("a.bin").cloned().unwrap(),
            PathPrediction { live: Some(20), conflict_copies: vec![10] }
        );
        assert!(pred.paths.get("b.bin").is_none(), "b.bin has a write-delete race -> abstained");
    }

    #[test]
    fn conflict_copy_from_an_earlier_race_persists_under_a_later_solo_write() {
        // Round 0 race -> live=20, conflict copy 10. Round 1 solo write
        // (content 30) overwrites the canonical path but must NOT remove the
        // earlier round's conflict-copy file.
        let ops = [
            w("f.bin", "device-a", 0, 10, 1000),
            w("f.bin", "device-b", 0, 20, 2000),
            w("f.bin", "device-a", 1, 30, 3000),
        ];
        assert_eq!(
            pred_of("f.bin", &ops),
            PathPrediction { live: Some(30), conflict_copies: vec![10] }
        );
    }

    #[test]
    fn conflict_copies_accumulate_across_two_races() {
        let ops = [
            w("f.bin", "device-a", 0, 10, 1000),
            w("f.bin", "device-b", 0, 20, 2000),
            w("f.bin", "device-a", 1, 30, 3000),
            w("f.bin", "device-b", 1, 40, 4000),
        ];
        // Round 0: live=20, cc=[10]. Round 1: live=40, cc=[10,30].
        assert_eq!(
            pred_of("f.bin", &ops),
            PathPrediction { live: Some(40), conflict_copies: vec![10, 30] }
        );
    }

    #[test]
    fn clamp_bounds_an_extreme_future_mtime_so_it_cannot_win_outright() {
        // An absurd future mtime (i64::MAX) claimed by device-a, against
        // device-b's mtime clamped-tied at the ceiling. With now small, both
        // clamp to `now + skew`, so the winner degrades to the device-id
        // tie-break: device-b (larger id) wins, device-a is the conflict
        // copy -- the extreme claim does NOT win outright.
        let now = 1_700_000_000i64 * 1_000_000_000;
        let ceiling = now + MAX_FUTURE_MTIME_SKEW_NANOS;
        let ops = [
            RefOp {
                path: "f.bin".into(),
                device_id: "device-a".into(),
                round: 0,
                kind: RefKind::Write { content_id: 10 },
                mtime_nanos: i64::MAX,
            },
            RefOp {
                path: "f.bin".into(),
                device_id: "device-b".into(),
                round: 0,
                kind: RefKind::Write { content_id: 20 },
                mtime_nanos: ceiling,
            },
        ];
        let p = predict(&ops, now).paths.get("f.bin").cloned().unwrap();
        assert_eq!(p, PathPrediction { live: Some(20), conflict_copies: vec![10] });
    }

    #[test]
    fn independent_paths_do_not_interact() {
        let ops = [w("a.bin", "device-a", 0, 1, 1000), w("b.bin", "device-b", 0, 2, 1000)];
        let pred = predict(&ops, NOW);
        assert_eq!(pred.paths.get("a.bin").unwrap().live, Some(1));
        assert_eq!(pred.paths.get("b.bin").unwrap().live, Some(2));
    }

    // ---- check_reference_model_against_snapshot(): the checker itself ----

    fn table(pairs: &[(u64, &str)]) -> ContentTable {
        let mut t = ContentTable::default();
        for (id, bytes) in pairs {
            t.insert(*id, bytes.as_bytes().to_vec());
        }
        t
    }

    fn snap(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(n, b)| (n.to_string(), content_hash(b.as_bytes()))).collect()
    }

    #[test]
    fn check_passes_when_disk_matches_prediction() {
        let t = table(&[(20, "winner"), (10, "loser")]);
        let pred = predict(
            &[w("f.bin", "device-a", 0, 10, 1000), w("f.bin", "device-b", 0, 20, 2000)],
            NOW,
        );
        let s = snap(&[
            ("f.bin", "winner"),
            ("f (conflicted copy, 2026-07-08-120000, device-a, 6c455bc2).bin", "loser"),
        ]);
        let v = check_reference_model_against_snapshot(&pred, &t, &s);
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn check_fires_when_the_wrong_content_won_the_canonical_name() {
        // Disk converged everyone onto "loser" as the live file (a
        // consistent-but-wrong winner) -- exactly what the existing oracles
        // are blind to.
        let t = table(&[(20, "winner"), (10, "loser")]);
        let pred = predict(
            &[w("f.bin", "device-a", 0, 10, 1000), w("f.bin", "device-b", 0, 20, 2000)],
            NOW,
        );
        let s = snap(&[
            ("f.bin", "loser"),
            ("f (conflicted copy, 2026-07-08-120000, device-b, 11223344).bin", "winner"),
        ]);
        let v = check_reference_model_against_snapshot(&pred, &t, &s);
        assert!(!v.is_empty());
        assert!(v.iter().all(|x| x.kind == ViolationKind::ConvergedToWrongWinner));
        assert!(v.iter().any(|x| x.detail.contains("live/canonical winner mismatch")));
    }

    #[test]
    fn check_fires_when_a_conflict_copy_is_missing() {
        let t = table(&[(20, "winner"), (10, "loser")]);
        let pred = predict(
            &[w("f.bin", "device-a", 0, 10, 1000), w("f.bin", "device-b", 0, 20, 2000)],
            NOW,
        );
        // Live winner correct, but the losing write's conflict copy vanished.
        let s = snap(&[("f.bin", "winner")]);
        let v = check_reference_model_against_snapshot(&pred, &t, &s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, ViolationKind::ConvergedToWrongWinner);
        assert!(v[0].detail.contains("conflict-copy set mismatch"));
    }

    #[test]
    fn check_passes_for_a_deleted_path_with_a_surviving_conflict_copy() {
        // A write-write race (winner=20 live, loser=10 conflict copy) then a
        // later solo delete of the canonical path: the live file is gone but
        // the earlier round's conflict copy persists as its own file.
        let t = table(&[(20, "winner"), (10, "losing-write")]);
        let pred = predict(
            &[
                w("f.bin", "device-a", 0, 10, 1000),
                w("f.bin", "device-b", 0, 20, 2000),
                d("f.bin", "device-a", 1, 3000),
            ],
            NOW,
        );
        assert_eq!(pred.paths.get("f.bin").unwrap().live, None);
        let s = snap(&[(
            "f (conflicted copy, 2026-07-08-120000, device-a, 6c455bc2).bin",
            "losing-write",
        )]);
        let v = check_reference_model_against_snapshot(&pred, &t, &s);
        assert!(v.is_empty(), "{v:?}");
    }
}
