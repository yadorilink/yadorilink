#![cfg(test)]

use super::*;

const GROUP: &str = "g";

fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            crate::materialized_generation::init_materialized_generation_schema(conn).map_err(
                |e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()),
            )?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

fn seed_hydrating_row(db: &SyncDatabase, path: &str) {
    seed_hydrating_row_as(db, path, "file", "[{\"hash\":[1],\"offset\":0,\"size\":1}]", false);
}

fn seed_hydrating_row_as(
    db: &SyncDatabase,
    path: &str,
    record_kind: &str,
    blocks_json: &str,
    deleted: bool,
) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
             deleted, record_kind, materialization_state) \
             VALUES (?1, ?2, 0, 0, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                GROUP,
                path,
                blocks_json,
                deleted as i64,
                record_kind,
                MaterializationState::Hydrating.as_db_str()
            ],
        )?;
        Ok(())
    })
    .unwrap();
}

fn state_of(db: &SyncDatabase, path: &str) -> MaterializationState {
    db.write::<_, SyncSqliteError>(|conn| {
        let value: String = conn.query_row(
            "SELECT materialization_state FROM files \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            rusqlite::params![GROUP, path],
            |r| r.get(0),
        )?;
        Ok(MaterializationState::from_db_str(&value))
    })
    .unwrap()
}

#[test]
fn a_hydrating_row_with_no_intent_is_reset_and_one_with_an_intent_is_left_for_repair() {
    let db = open_full_test_db();
    let permit = RootCommitPermit::for_tests();
    seed_hydrating_row(&db, "abandoned-fetch.txt");
    seed_hydrating_row(&db, "interrupted-batch.txt");

    crate::MaterializationIntentRepository::new(db.clone())
        .begin_materialization_intent(GROUP, "interrupted-batch.txt", &[7u8; 32], &permit)
        .unwrap();

    let reset =
        MaterializationStateRepository::new(db.clone()).reset_stale_transients(&[], &[]).unwrap().0;

    assert_eq!(reset, 1, "only the row with nothing in flight may be reset");
    assert_eq!(
        state_of(&db, "abandoned-fetch.txt"),
        MaterializationState::Remote,
        "an abandoned fetch wrote nothing; Placeholder is what is true about it"
    );
    assert_eq!(
        state_of(&db, "interrupted-batch.txt"),
        MaterializationState::Hydrating,
        "a row whose journal says a write for it was in flight belongs to startup repair, \
         which can still tell its bytes apart from an offline edit"
    );
}

/// The carve-out is only correct while it matches what repair actually
/// walks. Repair skips a tombstone and an empty file outright -- so preserving those here hands them to a pass that will
/// never look at them, and nothing else will either: the next restart
/// runs this same reset, which skips them again. Wedged for good,
/// rather than merely until reboot.
///
/// An empty file is the reachable one. The eager batch carries a
/// zero-byte version like any other, including for a non-empty file
/// being replaced by an empty one.
#[test]
fn a_hydrating_row_repair_would_skip_is_reset_even_though_it_holds_an_intent() {
    let db = open_full_test_db();
    let permit = RootCommitPermit::for_tests();
    let intents = crate::MaterializationIntentRepository::new(db.clone());

    seed_hydrating_row_as(&db, "empty.txt", "file", "[]", false);
    seed_hydrating_row_as(&db, "tombstoned.txt", "file", "[]", true);
    // The one repair does walk, as a control.
    seed_hydrating_row(&db, "real.txt");
    for path in ["empty.txt", "tombstoned.txt", "real.txt"] {
        intents.begin_materialization_intent(GROUP, path, &[7u8; 32], &permit).unwrap();
    }

    let reset =
        MaterializationStateRepository::new(db.clone()).reset_stale_transients(&[], &[]).unwrap().0;

    assert_eq!(reset, 2, "every row repair declines must be freed here");
    for path in ["empty.txt", "tombstoned.txt"] {
        assert_eq!(
            state_of(&db, path),
            MaterializationState::Remote,
            "{path}: repair skips this shape, so leaving it transient wedges it forever"
        );
    }
    assert_eq!(
        state_of(&db, "real.txt"),
        MaterializationState::Hydrating,
        "the row repair does walk still belongs to repair"
    );
}

/// Symlink and directory rows carry no blocks and repair walks them
/// anyway, each on its own arm -- so the empty-block rule must not sweep
/// them up. A directory demoted here would be listed to a placeholder
/// host as a file-shaped `Remote`.
#[test]
fn a_hydrating_symlink_or_directory_with_an_intent_is_left_for_repair() {
    let db = open_full_test_db();
    let permit = RootCommitPermit::for_tests();
    let intents = crate::MaterializationIntentRepository::new(db.clone());
    seed_hydrating_row_as(&db, "link", "symlink", "[]", false);
    seed_hydrating_row_as(&db, "a-directory", "directory", "[]", false);
    for path in ["link", "a-directory"] {
        intents.begin_materialization_intent(GROUP, path, &[7u8; 32], &permit).unwrap();
    }

    let reset =
        MaterializationStateRepository::new(db.clone()).reset_stale_transients(&[], &[]).unwrap().0;

    assert_eq!(reset, 0);
    assert_eq!(state_of(&db, "link"), MaterializationState::Hydrating);
    assert_eq!(state_of(&db, "a-directory"), MaterializationState::Hydrating);
}

/// A present-file proof for `path`, published under fence value
/// `published_under`, with the path's live fence at `fence`.
fn seed_file_proof(db: &SyncDatabase, path: &str, published_under: i64, fence: i64) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO path_materialized_generations (group_id, path, generation_id, \
             reflected_heads, resolved_path_state_hash, object_kind, version_hash, \
             encoding_version, updated_at_unix_nanos, published_under_mutation_generation) \
             VALUES (?1, ?2, 'gen', X'', X'00', 'regular_file', X'01', 1, 0, ?3)",
            rusqlite::params![GROUP, path, published_under],
        )?;
        conn.execute(
            "INSERT INTO path_actual_mutation_fences (group_id, path, mutation_generation, \
             last_mutation_kind, last_mutation_at) VALUES (?1, ?2, ?3, 'test', 0)",
            rusqlite::params![GROUP, path, fence],
        )?;
        Ok(())
    })
    .unwrap();
}

/// A `Hydrating` row with no intent over a proof that still stands
/// against its fence was entered from `Present` and crashed before its
/// own fence bump -- nothing has touched disk since the proof, so it goes
/// back to `Present`, where hydrate will not reconstruct over an
/// unjournalled edit and startup repair re-proves or quarantines it.
///
/// The guard is the fence: a proof the fence has moved past (an eviction,
/// or an attempt that crashed after its own bump) says nothing about
/// disk, and that row still resets to `Remote`. An intent keeps a
/// row with the carve-out whatever its proof says.
#[test]
fn a_hydrating_row_over_a_standing_proof_goes_back_to_present() {
    let db = open_full_test_db();
    let permit = RootCommitPermit::for_tests();
    seed_hydrating_row(&db, "crashed-from-hydrated.txt");
    seed_file_proof(&db, "crashed-from-hydrated.txt", 3, 3);
    seed_hydrating_row(&db, "fence-moved.txt");
    seed_file_proof(&db, "fence-moved.txt", 3, 4);
    seed_hydrating_row(&db, "with-intent.txt");
    seed_file_proof(&db, "with-intent.txt", 3, 3);
    crate::MaterializationIntentRepository::new(db.clone())
        .begin_materialization_intent(GROUP, "with-intent.txt", &[7u8; 32], &permit)
        .unwrap();

    let reset =
        MaterializationStateRepository::new(db.clone()).reset_stale_transients(&[], &[]).unwrap().0;

    assert_eq!(reset, 2, "both rows without an intent leave Hydrating");
    assert_eq!(
        state_of(&db, "crashed-from-hydrated.txt"),
        MaterializationState::Present,
        "a standing proof means no write happened since it; the row's local-edit protection \
         must survive the restart"
    );
    assert_eq!(
        state_of(&db, "fence-moved.txt"),
        MaterializationState::Remote,
        "a proof the fence has moved past vouches for nothing on disk"
    );
    assert_eq!(
        state_of(&db, "with-intent.txt"),
        MaterializationState::Hydrating,
        "a row with an intent stays with startup repair"
    );
}
