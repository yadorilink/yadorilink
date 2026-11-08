use rusqlite::Connection;

use super::*;

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::native_store::init_native_tables(&c).unwrap();
    init_tables(&c).unwrap();
    c
}

fn next() -> u64 {
    request_ticket()
}

fn author_seq(conn: &Connection, group: &str, author: &str, incarnation: u8, seq: i64) {
    conn.execute(
        "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![group, author, [incarnation].as_slice(), seq],
    )
    .unwrap();
}

#[test]
fn everything_is_pending_until_a_peer_names_it() {
    let conn = conn();
    author_seq(&conn, "g", "me", 1, 5);
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 5);
    record_peer_progress(&conn, "g", "peer", 3, next()).unwrap();
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 2);
    record_peer_progress(&conn, "g", "peer", 5, next()).unwrap();
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 0);
}

#[test]
fn only_this_devices_own_authors_and_group_count() {
    let conn = conn();
    author_seq(&conn, "g", "me", 1, 4);
    author_seq(&conn, "g", "me", 2, 3);
    author_seq(&conn, "g", "other", 1, 100);
    author_seq(&conn, "h", "me", 1, 50);
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 7);
    assert_eq!(pending_own_deltas(&conn, "h", "me").unwrap(), 50);
}

#[test]
fn the_best_peer_decides_and_the_latest_request_replaces_a_peers_figure() {
    let conn = conn();
    author_seq(&conn, "g", "me", 1, 10);
    record_peer_progress(&conn, "g", "a", 4, next()).unwrap();
    record_peer_progress(&conn, "g", "b", 9, next()).unwrap();
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 1);
    // A peer that lost its copy and now names less is counted from what it names.
    record_peer_progress(&conn, "g", "b", 2, next()).unwrap();
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 6);
}

#[test]
fn a_write_the_database_runs_again_after_a_failed_attempt_still_stores_its_figure() {
    let mut conn = conn();
    author_seq(&conn, "g", "me", 1, 6);
    let ticket = next();
    // The first attempt records its ticket and then fails (a transient lock, a failed commit): its
    // transaction is rolled back, nothing is stored.
    {
        let tx = conn.transaction().unwrap();
        record_peer_progress(&tx, "g", "peer", 4, ticket).unwrap();
        tx.rollback().unwrap();
    }
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 6, "nothing was stored yet");
    // The database runs the same closure again with the same ticket: it must write this time.
    record_peer_progress(&conn, "g", "peer", 4, ticket).unwrap();
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 2);
    // A request older than the one recorded is still dropped, and a newer one still replaces it.
    record_peer_progress(&conn, "g", "peer", 1, ticket - 1).unwrap();
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 2);
    record_peer_progress(&conn, "g", "peer", 6, next()).unwrap();
    assert_eq!(pending_own_deltas(&conn, "g", "me").unwrap(), 0);
}

#[test]
fn an_older_request_written_late_does_not_replace_a_newer_figure() {
    let conn = conn();
    author_seq(&conn, "o", "me", 1, 10);
    let older = request_ticket();
    let newer = request_ticket();
    record_peer_progress(&conn, "o", "p", 8, newer).unwrap();
    record_peer_progress(&conn, "o", "p", 3, older).unwrap();
    assert_eq!(pending_own_deltas(&conn, "o", "me").unwrap(), 2);
}

#[test]
fn a_request_received_before_an_install_is_dropped_after_it() {
    let conn = conn();
    author_seq(&conn, "i", "me", 1, 10);
    let before = request_ticket();
    note_install("i");
    let after = request_ticket();
    record_peer_progress(&conn, "i", "p", 9, before).unwrap();
    assert_eq!(pending_own_deltas(&conn, "i", "me").unwrap(), 10, "the stale figure was restored");
    record_peer_progress(&conn, "i", "p", 4, after).unwrap();
    assert_eq!(pending_own_deltas(&conn, "i", "me").unwrap(), 6);
}
