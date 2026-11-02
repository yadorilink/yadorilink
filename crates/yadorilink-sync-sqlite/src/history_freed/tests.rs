use super::*;

fn m(seq: i64, admitted: Option<i64>) -> Member {
    Member { seq, admitted }
}

fn set(seqs: &[i64]) -> HashSet<i64> {
    seqs.iter().copied().collect()
}

#[test]
fn a_run_in_time_order_spans_from_its_oldest_to_the_successor() {
    // versions 1..=6 admitted at 10, 20, ..., 60; 2, 3 and 4 dropped; 5 follows.
    let rows: Vec<Member> = (1..=6).map(|s| m(s, Some(s * 10))).collect();
    let r = runs(&rows, &set(&[2, 3, 4]));
    assert_eq!(
        r,
        vec![Run { from_unix_nanos: Some(20), to_unix_nanos: Some(50), from_seq: 2, to_seq: 5 }]
    );
}

#[test]
fn a_kept_version_between_dropped_ones_splits_the_event_into_two_runs() {
    // 3 is protected: 1, 2 and 4, 5 are dropped around it.
    let rows: Vec<Member> = (1..=7).map(|s| m(s, Some(s * 10))).collect();
    let r = runs(&rows, &set(&[1, 2, 4, 5]));
    assert_eq!(
        r,
        vec![
            Run { from_unix_nanos: Some(40), to_unix_nanos: Some(60), from_seq: 4, to_seq: 6 },
            Run { from_unix_nanos: Some(10), to_unix_nanos: Some(30), from_seq: 1, to_seq: 3 },
        ]
    );
}

#[test]
fn a_clock_that_ran_backwards_widens_the_span() {
    // A@10 (seq 1), B@30 (2), C@20 (3), D@40 (4); B dropped. By time the order is D, B, C, A, so
    // B's successor in time is D and its older neighbour C: the span must still cover T=35 and the
    // times of its neighbours.
    let rows = vec![m(1, Some(10)), m(2, Some(30)), m(3, Some(20)), m(4, Some(40))];
    let r = runs(&rows, &set(&[2]));
    assert_eq!(r.len(), 1);
    let run = &r[0];
    assert!(run.from_unix_nanos.unwrap() <= 20, "{run:?}");
    assert!(run.to_unix_nanos.unwrap() >= 40, "{run:?}");
    assert!(run.from_seq <= 1 && run.to_seq >= 5 - 1, "{run:?}");
    let span = FreedSpan {
        reason: FreedReason::Expired,
        from_unix_nanos: run.from_unix_nanos,
        to_unix_nanos: run.to_unix_nanos,
        from_seq: run.from_seq,
        to_seq: run.to_seq,
        recorded_unix: 0,
    };
    assert!(span.covers_time(35), "T=35 selects nothing else");
    assert!(span.covers_time(30));
}

#[test]
fn a_missing_admission_time_leaves_that_side_unbounded() {
    // The oldest version has no admission time and is dropped: unbounded below.
    let rows = vec![m(1, None), m(2, Some(20)), m(3, Some(30))];
    let r = runs(&rows, &set(&[1]));
    assert_eq!(
        r,
        vec![Run { from_unix_nanos: None, to_unix_nanos: Some(20), from_seq: 1, to_seq: 2 }]
    );
    let span = FreedSpan {
        reason: FreedReason::Expired,
        from_unix_nanos: None,
        to_unix_nanos: Some(20),
        from_seq: 1,
        to_seq: 2,
        recorded_unix: 0,
    };
    assert!(span.covers_time(i64::MIN + 1));
    assert!(!span.covers_time(20));
}

#[test]
fn a_tie_in_admission_time_is_ordered_by_sequence_like_the_planner() {
    // 2 and 3 share an admission time; 2 is dropped. The planner lists 3 before 2, so 3 is 2's
    // successor and the span is empty in time ([20, 20)): nothing a time query can land on.
    let rows = vec![m(1, Some(10)), m(2, Some(20)), m(3, Some(20)), m(4, Some(40))];
    let r = runs(&rows, &set(&[2]));
    assert_eq!(r.len(), 1);
    let span = FreedSpan {
        reason: FreedReason::Expired,
        from_unix_nanos: r[0].from_unix_nanos,
        to_unix_nanos: r[0].to_unix_nanos,
        from_seq: r[0].from_seq,
        to_seq: r[0].to_seq,
        recorded_unix: 0,
    };
    assert!(!span.covers_time(20), "the planner picks 3 at T=20, which is kept");
    assert!(span.covers_seq(2) && !span.covers_seq(3));
}

// --- through the index: the expiry writes the record, the planner and the restore read it ---------

use crate::file_index::expire_superseded_and_trashed_versions_in_tx;
use crate::rewind_plan::compute_rewind_plan;
use yadorilink_replica_domain::rewind::{RewindPathAction, RewindUnavailableReason};

const DAY: i64 = 86_400 * 1_000_000_000;

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init_for_tests(&c).unwrap();
    yadorilink_sqlite_runtime::init_schema(&c).unwrap();
    c
}

fn seed(c: &Connection, path: &str, seq: i64, state: &str, size: i64, admitted: Option<i64>) {
    c.execute(
        "INSERT INTO files (group_id, path, version_seq, state, deleted, size, mtime_unix_nanos, \
                            blocks_json, admitted_at_unix_nanos) VALUES ('g', ?1, ?2, ?3, 0, ?4, 0, '[]', ?5)",
        rusqlite::params![path, seq, state, size, admitted],
    )
    .unwrap();
}

/// Versions 1..=13 superseded, admitted on days 1..=13, and version 14 current on day 14.
fn long_history(c: &Connection, path: &str) {
    for seq in 1..=13 {
        seed(c, path, seq, "superseded", seq * 10, Some(seq * DAY));
    }
    seed(c, path, 14, "current", 140, Some(14 * DAY));
}

fn expire(c: &Connection, now_days: i64, pinned: &[(&str, i64)]) -> usize {
    let pinned: HashSet<(String, i64)> = pinned.iter().map(|(p, s)| (p.to_string(), *s)).collect();
    expire_superseded_and_trashed_versions_in_tx(c, "g", now_days * DAY, &pinned).unwrap()
}

type Row = (String, Option<i64>, Option<i64>, i64, i64, String);

fn rows(c: &Connection) -> Vec<Row> {
    let mut stmt = c
        .prepare(
            "SELECT path, from_unix_nanos, to_unix_nanos, from_seq, to_seq, reason \
             FROM history_freed ORDER BY event_id",
        )
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn action(c: &Connection, path: &str, at: i64) -> RewindPathAction {
    let plan = compute_rewind_plan(c, "g", at, &|_| false).unwrap();
    plan.entries.iter().find(|e| e.path == path).unwrap().action.clone()
}

#[test]
fn the_expiry_records_the_run_it_removes_and_the_planner_refuses_to_guess_inside_it() {
    let c = conn();
    long_history(&c, "p.txt");
    assert_eq!(expire(&c, 100, &[]), 3, "versions 1 to 3 are beyond both bounds");

    assert_eq!(
        rows(&c),
        vec![("p.txt".into(), Some(DAY), Some(4 * DAY), 1, 4, "Expired".to_string())],
        "one row for the one run, bounded by the successor's admission"
    );
    // Inside the run: no other version is offered in its place.
    assert_eq!(
        action(&c, "p.txt", 2 * DAY + DAY / 2),
        RewindPathAction::Unavailable { reason: RewindUnavailableReason::NotKeptExpired }
    );
    // At the successor's admission and after it the answer is the ordinary one.
    assert!(matches!(
        action(&c, "p.txt", 4 * DAY),
        RewindPathAction::Replace { to_version_seq: 4, .. }
    ));
    assert!(matches!(
        action(&c, "p.txt", 5 * DAY + 1),
        RewindPathAction::Replace { to_version_seq: 5, .. }
    ));
}

#[test]
fn a_protected_version_between_dropped_ones_leaves_a_gap_on_each_side_and_is_itself_restorable() {
    let c = conn();
    long_history(&c, "p.txt");
    // Version 2 is protected by a lease: 1 and 3 go, 2 stays.
    assert_eq!(expire(&c, 100, &[("p.txt", 2)]), 2);

    let r = rows(&c);
    assert_eq!(r.len(), 2, "two runs, two rows: {r:?}");
    assert!(r.contains(&("p.txt".into(), Some(3 * DAY), Some(4 * DAY), 3, 4, "Expired".into())));
    assert!(r.contains(&("p.txt".into(), Some(DAY), Some(2 * DAY), 1, 2, "Expired".into())));
    // The protected version answers its own time; the gaps do not fall through to it.
    assert!(matches!(
        action(&c, "p.txt", 2 * DAY + DAY / 2),
        RewindPathAction::Replace { to_version_seq: 2, .. }
    ));
    assert_eq!(
        action(&c, "p.txt", 3 * DAY + DAY / 2),
        RewindPathAction::Unavailable { reason: RewindUnavailableReason::NotKeptExpired }
    );
}

#[test]
fn events_are_never_merged_when_written() {
    let c = conn();
    long_history(&c, "p.txt");
    expire(&c, 100, &[("p.txt", 2)]);
    // The lease ends; the next expiry removes version 2.
    assert_eq!(expire(&c, 101, &[]), 1);
    let r = rows(&c);
    assert_eq!(r.len(), 3, "three events, three rows: {r:?}");
    // Version 3 was already gone, so version 2's successor is now version 4.
    assert_eq!(r[2], ("p.txt".into(), Some(2 * DAY), Some(4 * DAY), 2, 4, "Expired".into()));
}

#[test]
fn a_restore_by_number_learns_why_a_version_is_gone_and_a_number_never_used_is_not_found() {
    let c = conn();
    long_history(&c, "p.txt");
    expire(&c, 100, &[]);

    let covering = span_covering_seq(&c, "g", "p.txt", 2).unwrap().expect("version 2 was dropped");
    assert_eq!(covering.reason, FreedReason::Expired);
    assert_eq!(covering.reason.words(), "the retention period ended");
    assert!(span_covering_seq(&c, "g", "p.txt", 4).unwrap().is_none(), "version 4 is kept");
    assert!(span_covering_seq(&c, "g", "p.txt", 99).unwrap().is_none(), "never existed here");
    assert!(span_covering_seq(&c, "g", "other.txt", 2).unwrap().is_none(), "another path");
}

#[test]
fn a_path_without_dropped_versions_is_planned_as_before() {
    let c = conn();
    seed(&c, "q.txt", 1, "superseded", 10, Some(10 * DAY));
    seed(&c, "q.txt", 2, "current", 20, Some(20 * DAY));
    assert_eq!(expire(&c, 100, &[]), 0);
    assert!(rows(&c).is_empty());
    assert!(matches!(
        action(&c, "q.txt", 15 * DAY),
        RewindPathAction::Replace { to_version_seq: 1, .. }
    ));
    // Before the path existed: the ordinary answer.
    assert_eq!(action(&c, "q.txt", 5 * DAY), RewindPathAction::Delete);
}

#[test]
fn a_clock_that_ran_backwards_is_still_covered_in_the_plan() {
    // A@10 (1), B@30 (2), C@20 (3), D@40 (4, current); B was dropped.
    let c = conn();
    seed(&c, "p.txt", 1, "superseded", 10, Some(10));
    seed(&c, "p.txt", 3, "superseded", 30, Some(20));
    seed(&c, "p.txt", 4, "current", 40, Some(40));
    let all = [m(1, Some(10)), m(2, Some(30)), m(3, Some(20)), m(4, Some(40))];
    record(&c, "g", "p.txt", &all, &set(&[2]), FreedReason::Expired, 5).unwrap();
    // T=35 would select C (admitted at 20) without the record.
    assert_eq!(
        action(&c, "p.txt", 35),
        RewindPathAction::Unavailable { reason: RewindUnavailableReason::NotKeptExpired }
    );
    assert!(matches!(action(&c, "p.txt", 40), RewindPathAction::Unchanged));
}

#[test]
fn only_rows_of_vanished_paths_are_pruned_and_never_a_row_for_its_age() {
    let c = conn();
    long_history(&c, "p.txt");
    // A gap record of a path that still has versions, recorded long ago: it keeps answering.
    c.execute(
        "INSERT INTO history_freed (group_id, path, from_unix_nanos, to_unix_nanos, from_seq, to_seq, \
                                    reason, recorded_unix) VALUES ('g', 'p.txt', 1, 2, 1, 2, 'Expired', 1)",
        [],
    )
    .unwrap();
    // A row of a path with no version left whose span ended long ago.
    c.execute(
        "INSERT INTO history_freed (group_id, path, from_unix_nanos, to_unix_nanos, from_seq, to_seq, \
                                    reason, recorded_unix) VALUES ('g', 'gone.txt', 1, ?1, 1, 2, 'Expired', ?2)",
        rusqlite::params![DAY, 99 * 86_400],
    )
    .unwrap();
    expire(&c, 4000, &[]);
    let r = rows(&c);
    assert!(r.iter().all(|row| row.0 == "p.txt"), "the vanished path's row is pruned: {r:?}");
    assert!(
        r.iter().any(|row| row.3 == 1 && row.4 == 2),
        "the old row of a live path is kept: {r:?}"
    );
}
