//! How much of this device's own authored history each peer is known to have.
//!
//! A peer asks for what it lacks by naming everything it already has (the
//! `since` of a frontier-diff request). The entries of that list that name this
//! device's own authors say how far the peer has caught up with what this
//! device wrote. Their sum is stored per `(group, peer)` and only ever moves
//! forward. `pending_own_deltas` compares the best such figure with this
//! device's own total: the number of changes made here that no peer has told
//! us it holds.
//!
//! The figure counts deltas (changes), not files: one file edited three times is
//! three changes. It is a lower bound on what peers hold: a delta served in
//! answer to a request is only counted once the peer's next request names it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;

/// The order requests arrived in. A progress write runs off the answering thread, so two
/// requests of one peer can reach the writer in either order, and a write queued before a
/// checkpoint install can run after it. Each request takes a ticket when it is received; a write
/// is dropped when a newer request of the same peer was already recorded (the same request run again, which the database does after a transient lock error, is not newer than itself and writes), or when an install of
/// the group took its ticket after the request's. The tickets live in memory only: a queued write
/// does not outlive the process.
static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct Recorded {
    /// The newest ticket recorded per (group, peer).
    latest: HashMap<(String, String), u64>,
    /// The ticket of the latest install per group: older requests describe the replaced state.
    installed: HashMap<String, u64>,
}

static RECORDED: Mutex<Option<Recorded>> = Mutex::new(None);

fn with_recorded<T>(f: impl FnOnce(&mut Recorded) -> T) -> T {
    let mut guard = RECORDED.lock().unwrap_or_else(|p| p.into_inner());
    f(guard.get_or_insert_with(Recorded::default))
}

/// A ticket for a request that was just received.
pub fn request_ticket() -> u64 {
    NEXT_TICKET.fetch_add(1, Ordering::Relaxed)
}

/// Called inside the transaction that replaces `group_id`'s native state: the figures peers named
/// before it no longer describe this replica.
pub(crate) fn note_install(group_id: &str) {
    let ticket = request_ticket();
    with_recorded(|recorded| {
        recorded.installed.insert(group_id.to_string(), ticket);
    });
}

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS peer_own_progress (
            group_id        TEXT NOT NULL,
            peer_device     TEXT NOT NULL,
            -- Sum, over this device's own authors, of the sequence the peer named.
            acked_own_seq   INTEGER NOT NULL,
            PRIMARY KEY (group_id, peer_device)
        ) WITHOUT ROWID;",
    )?;
    Ok(())
}

/// Records that `peer_device` named `acked_own_seq` (the sum over this device's own authors of
/// the sequences in its request) for `group_id`, in the request that took `ticket`. The latest
/// request is the truth: a peer that lost its copy and names less is counted from what it names
/// now. A request that is not the latest, or that predates an install of the group, is ignored.
///
/// Call it inside the writer's transaction: the writer gate is what orders it against an install.
pub fn record_peer_progress(
    conn: &Connection,
    group_id: &str,
    peer_device: &str,
    acked_own_seq: u64,
    ticket: u64,
) -> Result<(), SyncSqliteError> {
    let current = with_recorded(|recorded| {
        let installed = recorded.installed.get(group_id).copied().unwrap_or(0);
        let key = (group_id.to_string(), peer_device.to_string());
        let newest = recorded.latest.get(&key).copied().unwrap_or(0);
        // `>=` on the request's own ticket: the database runs this closure again after a transient
        // lock error (also after a failed commit), and by then the first run has already recorded the
        // ticket. A strict `>` took that second run for a stale request and skipped the write, so the
        // figure was never stored. Two different requests never share a ticket.
        let current = ticket > installed && ticket >= newest;
        if current {
            recorded.latest.insert(key, ticket);
        }
        current
    });
    if !current {
        return Ok(());
    }
    conn.prepare_cached(
        "INSERT INTO peer_own_progress (group_id, peer_device, acked_own_seq) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT (group_id, peer_device) DO UPDATE SET \
             acked_own_seq = excluded.acked_own_seq",
    )?
    .execute(rusqlite::params![
        group_id,
        peer_device,
        acked_own_seq.min(i64::MAX as u64) as i64
    ])?;
    Ok(())
}

/// How many changes authored by `local_device` in `group_id` no peer is known to hold. Two
/// indexed reads: the sum of this device's own sequences and the best peer figure.
pub fn pending_own_deltas(
    conn: &Connection,
    group_id: &str,
    local_device: &str,
) -> Result<u64, SyncSqliteError> {
    let own: i64 = conn
        .prepare_cached(
            "SELECT COALESCE(SUM(seq), 0) FROM native_author_context \
             WHERE group_id = ?1 AND author = ?2",
        )?
        .query_row(rusqlite::params![group_id, local_device], |r| r.get(0))?;
    let best: Option<i64> = conn
        .prepare_cached("SELECT MAX(acked_own_seq) FROM peer_own_progress WHERE group_id = ?1")?
        .query_row([group_id], |r| r.get(0))
        .optional()?
        .flatten();
    Ok(own.saturating_sub(best.unwrap_or(0)).max(0) as u64)
}

#[cfg(test)]
mod tests;
