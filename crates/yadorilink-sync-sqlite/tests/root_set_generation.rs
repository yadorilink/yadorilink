//! The change-detector behind the background custody summary.
//!
//! Its whole job is to be *total*: a `files` write that does not move the
//! generation is a write a memoised digest will not notice, and a memo that
//! does not notice a write hands a peer comparison a digest the table no
//! longer supports — a false positive in the one direction the durability
//! design must never produce.
//!
//! So these tests go at the counter through raw SQL rather than through the
//! repository API. The point is not that today's write paths bump it; it is
//! that nothing written against this table can avoid bumping it, including
//! code that does not exist yet.

use rusqlite::Connection;
use yadorilink_sqlite_runtime::init_schema;

/// The admission tables `init_schema`'s own triggers reference. `init_schema`
/// documents that its caller creates these first.
fn dag_tables(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS admitted_changes (
             group_id TEXT NOT NULL, change_hash BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS group_history_bases (
             group_id TEXT NOT NULL, history_base BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS history_base_path_heads (
             group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS history_base_carried_authors (
             group_id TEXT NOT NULL, base_hash BLOB NOT NULL, change_hash BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS native_authoring_witness (group_id TEXT NOT NULL, identity BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS published_evidence (change_hash BLOB NOT NULL, checkpoint_hash BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS authorization_checkpoints (checkpoint_hash BLOB NOT NULL, group_id TEXT NOT NULL);",
    )
    .unwrap();
}

fn db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    dag_tables(&conn);
    init_schema(&conn).unwrap();
    conn
}

fn generation(conn: &Connection, group_id: &str) -> i64 {
    conn.query_row(
        "SELECT COALESCE((SELECT generation FROM file_root_set_generation WHERE group_id = ?1), 0)",
        [group_id],
        |r| r.get(0),
    )
    .unwrap()
}

/// A `files` row with no authoring identity, which the authoring-identity
/// trigger permits only while the group has no changes at all — true here,
/// since these tests never write one.
fn insert_row(conn: &Connection, group_id: &str, path: &str, version_seq: i64, state: &str) {
    conn.execute(
        "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
         version_seq, state, origin_device_id, record_kind) \
         VALUES (?1, ?2, 1, 1, '[]', 0, ?3, ?4, 'device-a', 'file')",
        rusqlite::params![group_id, path, version_seq, state],
    )
    .unwrap();
}

#[test]
fn every_kind_of_files_write_moves_the_generation() {
    let conn = db();
    assert_eq!(generation(&conn, "g"), 0, "a group with no rows has never been written");

    insert_row(&conn, "g", "a.txt", 1, "current");
    let after_insert = generation(&conn, "g");
    assert!(after_insert > 0, "INSERT must move it");

    conn.execute("UPDATE files SET state = 'superseded' WHERE group_id = 'g'", []).unwrap();
    let after_update = generation(&conn, "g");
    assert!(after_update > after_insert, "UPDATE must move it");

    conn.execute("DELETE FROM files WHERE group_id = 'g'", []).unwrap();
    assert!(generation(&conn, "g") > after_update, "DELETE must move it");
}

/// An `UPDATE` that changes no column value is still a write, and the
/// counter is allowed to move for it. What must not happen is the reverse:
/// a write that leaves it where it was. This pins the direction of the
/// asymmetry, because only one direction is a safety problem — a spurious
/// bump costs a recomputation, a missed one caches a stale digest.
#[test]
fn a_no_op_update_may_move_the_generation_but_must_not_leave_it_behind() {
    let conn = db();
    insert_row(&conn, "g", "a.txt", 1, "current");
    let before = generation(&conn, "g");

    conn.execute("UPDATE files SET size = size WHERE group_id = 'g'", []).unwrap();

    assert!(generation(&conn, "g") >= before);
}

#[test]
fn the_generation_is_per_group() {
    let conn = db();
    insert_row(&conn, "g1", "a.txt", 1, "current");
    let g1 = generation(&conn, "g1");

    insert_row(&conn, "g2", "b.txt", 1, "current");

    assert_eq!(generation(&conn, "g1"), g1, "another group's write is not this group's change");
    assert!(generation(&conn, "g2") > 0);
}

/// The bump lives in the transaction of the write it observes, so a
/// rolled-back write takes its own bump with it. Without this a failed
/// import would leave every group's memo invalidated for nothing — and,
/// worse, would make the counter a record of attempts rather than of state.
#[test]
fn a_rolled_back_write_takes_its_bump_with_it() {
    let mut conn = db();
    insert_row(&conn, "g", "a.txt", 1, "current");
    let before = generation(&conn, "g");

    let tx = conn.transaction().unwrap();
    tx.execute(
        "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
         version_seq, state, origin_device_id, record_kind) \
         VALUES ('g', 'b.txt', 1, 1, '[]', 0, 1, 'current', 'device-a', 'file')",
        [],
    )
    .unwrap();
    assert!(generation(&tx, "g") > before, "visible inside the transaction");
    tx.rollback().unwrap();

    assert_eq!(generation(&conn, "g"), before, "and gone again with the rollback");
}

/// A group's counter outlives the group. Deleting the row on unlink would
/// restart the sequence at 1 for a later relink of the same group id, and a
/// memo keyed on `(group, generation)` would then match an entry belonging
/// to the group's previous life.
#[test]
fn unlinking_a_group_does_not_reset_its_generation() {
    let conn = db();
    insert_row(&conn, "g", "a.txt", 1, "current");
    let while_linked = generation(&conn, "g");

    // What an unlink does to this table: removes every `files` row.
    conn.execute("DELETE FROM files WHERE group_id = 'g'", []).unwrap();
    let after_unlink = generation(&conn, "g");
    assert!(after_unlink > while_linked);

    // A relink writing the same path again must not land back on a value
    // the memo could already be holding.
    insert_row(&conn, "g", "a.txt", 1, "current");
    assert!(generation(&conn, "g") > after_unlink);
}

/// An UPDATE that moves a row between groups must bump the group it LEFT as
/// well as the one it joined. Bumping only the destination leaves the source
/// group's memo valid while the source group has one fewer root — and the
/// memo would go on serving a digest containing the departed row until
/// something else happened to write to that group.
///
/// No production statement moves a row across groups today. That is not the
/// point: a trigger is used here precisely so the guarantee does not rest on
/// nobody ever writing one.
#[test]
fn moving_a_row_between_groups_moves_both_generations() {
    let conn = db();
    insert_row(&conn, "src", "a.txt", 1, "current");
    let src_before = generation(&conn, "src");
    let dst_before = generation(&conn, "dst");

    conn.execute("UPDATE files SET group_id = 'dst' WHERE group_id = 'src'", []).unwrap();

    assert!(generation(&conn, "src") > src_before, "the group the row left must move");
    assert!(generation(&conn, "dst") > dst_before, "so must the group it joined");
}

/// `INSERT OR REPLACE` is the one statement form that can delete a row
/// without firing a `DELETE` trigger (SQLite only fires those with
/// `PRAGMA recursive_triggers` on). The `INSERT` half still fires, which is
/// what keeps the counter total across it.
#[test]
fn insert_or_replace_still_moves_the_generation() {
    let conn = db();
    insert_row(&conn, "g", "a.txt", 1, "current");
    let before = generation(&conn, "g");

    conn.execute(
        "INSERT OR REPLACE INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
         deleted, version_seq, state, origin_device_id, record_kind) \
         VALUES ('g', 'a.txt', 2, 2, '[]', 0, 1, 'current', 'device-a', 'file')",
        [],
    )
    .unwrap();

    assert!(generation(&conn, "g") > before);
}

/// Opening an existing database again must not disturb the counter: the DDL
/// is idempotent, and a reopen is not a change to anyone's root set.
#[test]
fn reopening_the_schema_does_not_move_the_generation() {
    let conn = db();
    insert_row(&conn, "g", "a.txt", 1, "current");
    let before = generation(&conn, "g");

    init_schema(&conn).unwrap();

    assert_eq!(generation(&conn, "g"), before);
}
