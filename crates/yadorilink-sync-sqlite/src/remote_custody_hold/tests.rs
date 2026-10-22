#![cfg(test)]

use super::*;

fn open_file_db(dir: &tempfile::TempDir) -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open(dir.path().join("index.db"), |conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open file-backed db"),
    )
}

fn key(peer: &str) -> HoldKey {
    HoldKey {
        group_id: "g".into(),
        path: "a.bin".into(),
        version_hash: [7; 32],
        peer_id: peer.into(),
    }
}

/// A requested row is on disk before anything else happens to it, and it
/// survives the database being closed and reopened (a crash).
#[test]
fn a_requested_row_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
        repo.record_requested(&key("p1"), 4, [1; 16]).unwrap();
    }
    let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
    let rows = repo.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, key("p1"));
    assert_eq!(rows[0].state, HoldState::Requested);
    assert_eq!(rows[0].membership_generation, 4);
    assert!(!repo.is_granted(&key("p1")).unwrap());
}

/// Requested -> granted; the grant is durable and is per peer.
#[test]
fn granting_is_per_peer_and_durable() {
    let dir = tempfile::tempdir().unwrap();
    {
        let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
        repo.record_requested(&key("p1"), 1, [1; 16]).unwrap();
        repo.record_requested(&key("p2"), 1, [1; 16]).unwrap();
        repo.mark_granted(&key("p1")).unwrap();
    }
    let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
    assert!(repo.is_granted(&key("p1")).unwrap());
    assert!(!repo.is_granted(&key("p2")).unwrap());
    assert_eq!(repo.list().unwrap().len(), 2);
}

/// A stamp must never be issued for a hold that is not recorded.
#[test]
fn granting_a_hold_that_is_not_recorded_fails() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
    assert!(repo.mark_granted(&key("p1")).is_err());
    assert!(repo.list().unwrap().is_empty());
}

/// A repeated acquire for a hold that is already granted does not take the
/// grant back.
#[test]
fn recording_again_keeps_a_granted_row_granted() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
    repo.record_requested(&key("p1"), 1, [1; 16]).unwrap();
    repo.mark_granted(&key("p1")).unwrap();
    repo.record_requested(&key("p1"), 2, [1; 16]).unwrap();
    assert!(repo.is_granted(&key("p1")).unwrap());
    assert_eq!(repo.list().unwrap().len(), 1);
}

/// Delete removes exactly one (version, peer) row.
#[test]
fn delete_removes_only_that_row() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
    repo.record_requested(&key("p1"), 1, [1; 16]).unwrap();
    repo.record_requested(&key("p2"), 1, [1; 16]).unwrap();
    let mut other_version = key("p1");
    other_version.version_hash = [8; 32];
    repo.record_requested(&other_version, 1, [1; 16]).unwrap();
    repo.delete(&key("p1")).unwrap();
    repo.delete(&key("p1")).unwrap();
    let left: Vec<_> = repo.list().unwrap().into_iter().map(|r| r.key).collect();
    assert_eq!(left.len(), 2);
    assert!(left.contains(&key("p2")) && left.contains(&other_version));
}

/// The reconciler re-reads a row under the path lock; `get` is that read.
#[test]
fn get_returns_the_current_row_or_none() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
    assert!(repo.get(&key("p1")).unwrap().is_none());
    repo.record_requested(&key("p1"), 1, [1; 16]).unwrap();
    assert_eq!(repo.get(&key("p1")).unwrap().unwrap().state, HoldState::Requested);
    repo.mark_granted(&key("p1")).unwrap();
    assert_eq!(repo.get(&key("p1")).unwrap().unwrap().state, HoldState::Granted);
}

/// The attempt token is stored with the row and survives a restart; a repeated
/// acquire for the same hold keeps the first attempt's token, so the release
/// that eventually ends it names the attempt that may have reached the peer.
#[test]
fn the_attempt_token_is_stored_and_kept_by_a_repeated_acquire() {
    let dir = tempfile::tempdir().unwrap();
    {
        let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
        assert_eq!(repo.record_requested(&key("p1"), 1, [1; 16]).unwrap(), [1; 16]);
        assert_eq!(
            repo.record_requested(&key("p1"), 2, [2; 16]).unwrap(),
            [1; 16],
            "the stored attempt wins"
        );
    }
    let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
    assert_eq!(repo.get(&key("p1")).unwrap().unwrap().attempt_token, [1; 16]);
    repo.delete(&key("p1")).unwrap();
    assert_eq!(
        repo.record_requested(&key("p1"), 3, [3; 16]).unwrap(),
        [3; 16],
        "a released hold starts a new attempt"
    );
}

/// A reconciler pass reads every hold once and each hold once more under its
/// path lock. That is about 2H decoded rows, not H + H^2: the second read is a
/// keyed lookup. Counted in decoded rows, so the assertion does not depend on
/// how fast the machine is.
#[test]
fn a_pass_over_many_holds_decodes_a_linear_number_of_rows() {
    const HOLDS: usize = 20_000;
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
    repo.database
        .write::<_, SyncSqliteError>(|conn| {
            let tx = conn.unchecked_transaction()?;
            {
                let mut insert = tx.prepare(
                    "INSERT INTO remote_custody_hold \
                     (group_id, path, version_hash, peer_id, state, membership_generation, \
                      attempt_token) VALUES ('g', ?1, ?2, 'p1', 'granted', 1, ?3)",
                )?;
                for n in 0..HOLDS {
                    insert.execute(rusqlite::params![
                        format!("dir/{n}.bin"),
                        &[7u8; 32][..],
                        &[1u8; 16][..]
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .unwrap();

    reset_decoded_rows();
    let listed = repo.list().unwrap();
    assert_eq!(listed.len(), HOLDS);
    for hold in &listed {
        assert_eq!(repo.get(&hold.key).unwrap().as_ref(), Some(hold));
    }
    assert!(
        decoded_rows() <= 2 * HOLDS,
        "decoded {} rows for {HOLDS} holds; a pass must be linear",
        decoded_rows()
    );
}

/// A lookup of a hold that is not there, or that differs from a stored one in
/// any part of its key, finds nothing.
#[test]
fn a_keyed_lookup_matches_the_whole_key() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyHoldRepository::new(open_file_db(&dir));
    repo.record_requested(&key("p1"), 1, [1; 16]).unwrap();
    assert!(repo.get(&key("p1")).unwrap().is_some());
    assert!(repo.get(&key("p2")).unwrap().is_none());
    let mut other = key("p1");
    other.version_hash = [8; 32];
    assert!(repo.get(&other).unwrap().is_none());
    other = key("p1");
    other.path = "b.bin".into();
    assert!(repo.get(&other).unwrap().is_none());
    other = key("p1");
    other.group_id = "h".into();
    assert!(repo.get(&other).unwrap().is_none());
}
