//! Ending a rebootstrap removes its journal and everything that belongs to it as one atomic
//! step: an error part-way leaves every row in place.

use crate::native_rebootstrap::{finish_rebootstrap, rebootstrap_status, set_journal_for_test};

use super::*;

const RID: &str = "recovery-under-test";

fn seeded() -> Connection {
    let c = conn();
    set_journal_for_test(&c, &group(), "replaying", RID);
    c.execute(
        "INSERT INTO native_rebootstrap_delta (group_id, ordinal, old_delta_hash, outcome) \
         VALUES (?1, 0, x'00', 'authored')",
        [GROUP],
    )
    .unwrap();
    c.execute(
        "INSERT INTO native_rebootstrap_recovery_item \
         (group_id, item_key, kind, size, content_hash, status) \
         VALUES (?1, 'k', 'file', 1, x'00', 'saved')",
        [GROUP],
    )
    .unwrap();
    for (path, status) in [("a", "done"), ("b", "retained")] {
        c.execute(
            "INSERT INTO native_rebootstrap_quarantine (group_id, recovery_id, path, status) \
             VALUES (?1, ?2, ?3, ?4)",
            (GROUP, RID, path, status),
        )
        .unwrap();
    }
    c
}

fn count(c: &Connection, table: &str) -> i64 {
    c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap()
}

#[test]
fn finish_removes_everything_but_retained_originals_and_is_idempotent() {
    let c = seeded();
    assert!(finish_rebootstrap(&c, &group(), RID).unwrap());
    assert_eq!(count(&c, "native_rebootstrap_journal"), 0);
    assert_eq!(count(&c, "native_rebootstrap_delta"), 0);
    assert_eq!(count(&c, "native_rebootstrap_recovery_item"), 0);
    assert_eq!(count(&c, "native_rebootstrap_quarantine"), 1, "the retained row stays");
    assert!(!finish_rebootstrap(&c, &group(), RID).unwrap(), "a second finish finds nothing");
    assert_eq!(count(&c, "native_rebootstrap_quarantine"), 1);
}

#[test]
fn a_failure_after_the_first_delete_removes_nothing() {
    let c = seeded();
    c.execute_batch(
        "CREATE TRIGGER fail_quarantine BEFORE DELETE ON native_rebootstrap_quarantine \
         BEGIN SELECT RAISE(ABORT, 'injected'); END;",
    )
    .unwrap();
    assert!(finish_rebootstrap(&c, &group(), RID).is_err());
    assert!(rebootstrap_status(&c, &group()).unwrap().is_some(), "the journal survives");
    assert_eq!(count(&c, "native_rebootstrap_journal"), 1);
    assert_eq!(count(&c, "native_rebootstrap_delta"), 1);
    assert_eq!(count(&c, "native_rebootstrap_recovery_item"), 1);
    assert_eq!(count(&c, "native_rebootstrap_quarantine"), 2);

    // Once the fault is gone the same call completes.
    c.execute_batch("DROP TRIGGER fail_quarantine").unwrap();
    assert!(finish_rebootstrap(&c, &group(), RID).unwrap());
    assert_eq!(count(&c, "native_rebootstrap_journal"), 0);
}

#[test]
fn finish_nests_inside_a_callers_transaction() {
    let c = seeded();
    c.execute_batch("BEGIN").unwrap();
    assert!(finish_rebootstrap(&c, &group(), RID).unwrap());
    c.execute_batch("ROLLBACK").unwrap();
    assert_eq!(count(&c, "native_rebootstrap_journal"), 1, "the caller's rollback wins");
}
