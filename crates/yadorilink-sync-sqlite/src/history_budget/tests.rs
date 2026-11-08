use std::collections::HashSet;

use yadorilink_replica_domain::file::{BlockInfo, FileRecord};

use super::*;
use crate::file_index::upsert_file_in_tx;
use crate::retention::Retention;

const GROUP: &str = "g";

fn record(path: &str, tags: &[u8]) -> FileRecord {
    FileRecord {
        path: path.into(),
        size: 4 * tags.len() as u64,
        mtime_unix_nanos: i64::from(tags[0]),
        blocks: tags
            .iter()
            .enumerate()
            .map(|(i, t)| BlockInfo { hash: vec![*t; 32], offset: 4 * i as u64, size: 4 })
            .collect(),
        deleted: false,
    }
}

fn write(db: &std::sync::Arc<yadorilink_sqlite_runtime::SyncDatabase>, path: &str, tags: &[u8]) {
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        upsert_file_in_tx(tx, GROUP, &record(path, tags), "dev", Retention::OwnEdit)
    })
    .unwrap();
}

fn kept(
    db: &std::sync::Arc<yadorilink_sqlite_runtime::SyncDatabase>,
    path: &str,
) -> Vec<(i64, String)> {
    db.read::<_, SyncSqliteError>(|c| {
        let mut s = c.prepare(
            "SELECT version_seq, state FROM files WHERE group_id = ?1 AND path = ?2 \
             AND state <> 'current' ORDER BY version_seq",
        )?;
        let rows = s
            .query_map([GROUP, path], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .unwrap()
}

fn trim(db: &std::sync::Arc<yadorilink_sqlite_runtime::SyncDatabase>, budget: u64) -> usize {
    crate::file_index::FileIndexRepository::new(db.clone())
        .trim_history_over_budget(budget, 1_000)
        .unwrap()
}

#[test]
fn over_budget_the_oldest_versions_go_first_and_each_is_recorded() {
    let db = crate::replica_tables::open_for_tests();
    for tag in 1..=5 {
        write(&db, "a", &[tag]);
    }
    // Four replaced versions of 4 bytes each, one current.
    assert_eq!(kept(&db, "a").len(), 4);
    assert_eq!(trim(&db, 8), 2);
    let left = kept(&db, "a");
    assert_eq!(left.len(), 2);
    let spans = db
        .read::<_, SyncSqliteError>(|c| crate::history_freed::spans_by_path(c, GROUP))
        .unwrap()
        .remove("a")
        .unwrap_or_default();
    assert!(spans.iter().all(|s| s.reason == FreedReason::OverBudget));
    assert!(!spans.is_empty());
}

#[test]
fn within_budget_nothing_changes() {
    let db = crate::replica_tables::open_for_tests();
    for tag in 1..=5 {
        write(&db, "a", &[tag]);
    }
    assert_eq!(trim(&db, 16), 0);
    assert_eq!(kept(&db, "a").len(), 4);
}

#[test]
fn a_block_the_current_version_shares_costs_history_nothing() {
    let db = crate::replica_tables::open_for_tests();
    // The replaced version's block 1 is the current version's too; its block 2 is its own.
    write(&db, "a", &[1, 2]);
    write(&db, "a", &[1]);
    assert_eq!(trim(&db, 4), 0, "only block 2 (4 bytes) is history's own");
    assert_eq!(trim(&db, 3), 1);
}

#[test]
fn a_block_two_kept_versions_share_counts_once() {
    let candidates = |anchor: i64, seq: i64| Candidate {
        group_id: GROUP.into(),
        path: "a".into(),
        version_seq: seq,
        anchor,
        blocks: vec![("s".into(), 10)],
    };
    // Both name one 10-byte block: 10 bytes of history, within a budget of 10.
    let drops = choose_drops(vec![candidates(1, 1), candidates(2, 2)], &HashSet::new(), 10);
    assert!(drops.is_empty());
    // Over budget, the oldest holder goes, then the next until it fits.
    let drops = choose_drops(vec![candidates(1, 1), candidates(2, 2)], &HashSet::new(), 5);
    assert_eq!(drops.len(), 2);
}

#[test]
fn a_version_a_lease_pins_is_never_dropped_and_does_not_count() {
    let db = crate::replica_tables::open_for_tests();
    for tag in 1..=3 {
        write(&db, "a", &[tag]);
    }
    let seqs: Vec<i64> = kept(&db, "a").into_iter().map(|(s, _)| s).collect();
    let pinned = serde_json::to_string(&vec![("a".to_owned(), seqs[0])]).unwrap();
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute(
            "INSERT INTO handoff_leases (lease_id, group_id, root_digest, pinned_versions_json, \
             state, created_at_unix, expires_at_unix) VALUES ('l', ?1, zeroblob(32), ?2, 'confirmed', 0, 9999999)",
            rusqlite::params![GROUP, pinned],
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(trim(&db, 0), 1);
    assert_eq!(kept(&db, "a").into_iter().map(|(s, _)| s).collect::<Vec<_>>(), vec![seqs[0]]);
}

/// The expiry sweep reads the lease pins inside its own transaction, so a lease recorded before
/// the sweep protects its versions with no pin set passed in.
#[test]
fn the_expiry_sweep_keeps_a_version_a_lease_pins() {
    let db = crate::replica_tables::open_for_tests();
    let day = 86_400 * 1_000_000_000i64;
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        for seq in 1..=13 {
            tx.execute(
                "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
                 mtime_unix_nanos, blocks_json, admitted_at_unix_nanos) \
                 VALUES (?1, 'a', ?2, 'superseded', 0, 1, 0, '[]', ?3)",
                rusqlite::params![GROUP, seq, seq * day],
            )?;
        }
        tx.execute(
            "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
             mtime_unix_nanos, blocks_json, admitted_at_unix_nanos) \
             VALUES (?1, 'a', 14, 'current', 0, 1, 0, '[]', ?2)",
            rusqlite::params![GROUP, 14 * day],
        )?;
        tx.execute(
            "INSERT INTO handoff_leases (lease_id, group_id, root_digest, pinned_versions_json, \
             state, created_at_unix, expires_at_unix) \
             VALUES ('l', ?1, zeroblob(32), '[[\"a\",1]]', 'confirmed', 0, 9999999999)",
            rusqlite::params![GROUP],
        )?;
        Ok(())
    })
    .unwrap();
    let repo = crate::file_index::FileIndexRepository::new(db.clone());
    let expired = repo.expire_superseded_and_trashed_versions(GROUP, 1000 * day).unwrap();
    assert!(expired > 0, "the unpinned old versions expire");
    let left: Vec<i64> = kept(&db, "a").into_iter().map(|(s, _)| s).collect();
    assert!(left.contains(&1), "the leased version stays: {left:?}");
    assert!(!left.contains(&2), "an unpinned old version expired: {left:?}");
}

#[test]
fn kept_history_bytes_counts_only_what_history_alone_holds() {
    let db = crate::replica_tables::open_for_tests();
    // Three versions of one path with distinct blocks: two are kept (4 bytes each), one is current.
    for tag in 1..=3 {
        write(&db, "a", &[tag]);
    }
    let repo = crate::file_index::FileIndexRepository::new(db.clone());
    assert_eq!(repo.kept_history_bytes(0).unwrap(), 8);
    // A lease pin takes a version out of the count, like the trim.
    let seqs: Vec<i64> = kept(&db, "a").into_iter().map(|(s, _)| s).collect();
    let pinned = serde_json::to_string(&vec![("a".to_owned(), seqs[0])]).unwrap();
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute(
            "INSERT INTO handoff_leases (lease_id, group_id, root_digest, pinned_versions_json, \
             state, created_at_unix, expires_at_unix) VALUES ('l', ?1, zeroblob(32), ?2, 'confirmed', 0, 9999999)",
            rusqlite::params![GROUP, pinned],
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(repo.kept_history_bytes(0).unwrap(), 4);
}
