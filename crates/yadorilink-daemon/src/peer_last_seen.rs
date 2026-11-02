//! When each peer was last connected to this device, kept across restarts.
//!
//! A peer that is away is availability, never a problem, so what a person needs is how long it
//! has been away. The time is the moment a session with the peer came up or went down; a peer
//! connected now is reported as now by the reader, not from here. A session that lasts days and
//! ends in a crash leaves the time of its start (the stored value is never later than the truth).
//!
//! Display data only. The map lives in memory and every change is queued to one writer thread
//! that stores the newest value per peer in the `peer_last_seen` table, so a connection event
//! never waits for the database. A failed write is retried with the next batch; one still
//! pending when the owner is dropped after the database was closed is lost, which only means the
//! time is older (or a removed device's time stays) after a restart.
//! A revoked or removed device is forgotten, and a close that arrives after that does not bring
//! it back.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use yadorilink_sync_sqlite::SyncSqliteError;

type Database = yadorilink_sqlite_runtime::SyncDatabase;

/// How long a change waits for others before it is written.
const WRITE_DELAY: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Book {
    seen: BTreeMap<String, i64>,
    /// Devices forgotten since their last session came up: a late close does not re-add them.
    forgotten: BTreeSet<String>,
}

/// What the writer has yet to store: the newest value per device (`None` deletes it). Updated
/// under the book's lock, so the order the database sees is the order memory saw, and its size is
/// bounded by the number of devices.
#[derive(Default)]
struct Pending {
    changes: BTreeMap<String, Option<i64>>,
    closed: bool,
}

#[derive(Default)]
struct Shared {
    pending: Mutex<Pending>,
    wake: Condvar,
}

#[derive(Default)]
pub(crate) struct PeerLastSeen {
    book: Mutex<Book>,
    shared: Arc<Shared>,
    writer: Mutex<Option<std::thread::JoinHandle<()>>>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl PeerLastSeen {
    /// Kept in memory only (tests, and hosts with no database).
    pub(crate) fn in_memory() -> Self {
        Self::default()
    }

    /// Loads what the database holds and stores every later change from one writer thread.
    pub(crate) fn open(database: Arc<Database>) -> Self {
        Self::open_with_delay(database, WRITE_DELAY)
    }

    fn open_with_delay(database: Arc<Database>, delay: Duration) -> Self {
        // The writer holds the database weakly and only while it writes; dropping this value
        // waits for a write in progress, so the file is never held past the daemon.
        let weak = Arc::downgrade(&database);
        let seen: BTreeMap<String, i64> = database
            .read::<_, SyncSqliteError>(|conn| {
                let mut statement =
                    conn.prepare("SELECT device_id, last_connected_unix FROM peer_last_seen")?;
                let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
                rows.collect::<Result<_, _>>().map_err(Into::into)
            })
            .unwrap_or_default();
        let shared = Arc::new(Shared::default());
        let for_writer = shared.clone();
        let writer = std::thread::Builder::new()
            .name("peer-last-seen".into())
            .spawn(move || write_until_closed(&for_writer, &weak, delay))
            .ok();
        Self {
            book: Mutex::new(Book { seen, forgotten: BTreeSet::new() }),
            shared,
            writer: Mutex::new(writer),
        }
    }

    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Queues `change` for the writer. Called with the book's lock held.
    fn queue(&self, device_id: &str, change: Option<i64>) {
        let mut pending = self.shared.pending.lock().unwrap_or_else(|p| p.into_inner());
        pending.changes.insert(device_id.to_owned(), change);
        self.shared.wake.notify_one();
    }

    /// A session with `device_id` came up just now.
    pub(crate) fn session_up(&self, device_id: &str) {
        self.set(device_id, now_unix(), true);
    }

    /// A session with `device_id` went down just now.
    pub(crate) fn session_down(&self, device_id: &str) {
        self.set(device_id, now_unix(), false);
    }

    fn set(&self, device_id: &str, at: i64, up: bool) {
        let mut book = self.book();
        if up {
            book.forgotten.remove(device_id);
        } else if book.forgotten.contains(device_id) {
            return;
        }
        book.seen.insert(device_id.to_owned(), at);
        self.queue(device_id, Some(at));
    }

    /// The device was revoked or removed: its time is dropped and stays dropped until a session
    /// with it comes up again.
    pub(crate) fn forget(&self, device_id: &str) {
        let mut book = self.book();
        book.seen.remove(device_id);
        book.forgotten.insert(device_id.to_owned());
        self.queue(device_id, None);
    }

    /// The last time a session with `device_id` was up; 0 when this device never connected to it.
    pub(crate) fn get(&self, device_id: &str) -> i64 {
        self.book().seen.get(device_id).copied().unwrap_or(0)
    }
}

impl Drop for PeerLastSeen {
    fn drop(&mut self) {
        {
            let mut pending = self.shared.pending.lock().unwrap_or_else(|p| p.into_inner());
            pending.closed = true;
            self.shared.wake.notify_all();
        }
        let handle = self.writer.get_mut().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

/// Stores the newest value per device, at most once per `delay`, in one transaction; stores what
/// is left and returns once the owner is dropped.
fn write_until_closed(shared: &Shared, database: &std::sync::Weak<Database>, delay: Duration) {
    loop {
        let batch = {
            let mut pending = shared.pending.lock().unwrap_or_else(|p| p.into_inner());
            while pending.changes.is_empty() && !pending.closed {
                pending = shared.wake.wait(pending).unwrap_or_else(|p| p.into_inner());
            }
            if pending.changes.is_empty() {
                return;
            }
            // Changes arriving in the next moments (a flapping link) are written together.
            if !pending.closed {
                pending = shared
                    .wake
                    .wait_timeout_while(pending, delay, |p| !p.closed)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
            }
            std::mem::take(&mut pending.changes)
        };
        let Some(database) = database.upgrade() else { return };
        let stored = database.write::<_, SyncSqliteError>(|conn| {
            let tx = conn.transaction()?;
            for (device, at) in &batch {
                match at {
                    Some(at) => tx.execute(
                        "INSERT INTO peer_last_seen (device_id, last_connected_unix) \
                         VALUES (?1, ?2) ON CONFLICT(device_id) DO UPDATE SET \
                         last_connected_unix = excluded.last_connected_unix",
                        rusqlite::params![device, at],
                    )?,
                    None => tx.execute(
                        "DELETE FROM peer_last_seen WHERE device_id = ?1",
                        rusqlite::params![device],
                    )?,
                };
            }
            tx.commit()?;
            Ok(())
        });
        if let Err(error) = stored {
            tracing::debug!(%error, "could not store when peers were last seen");
            // Kept for the next round (a newer change for the same device wins); not retried
            // once the owner is dropped.
            let mut pending = shared.pending.lock().unwrap_or_else(|p| p.into_inner());
            for (device, change) in batch {
                pending.changes.entry(device).or_insert(change);
            }
            if pending.closed {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forgotten_device_stays_forgotten_until_a_session_comes_up() {
        let seen = PeerLastSeen::in_memory();
        seen.set("d1", 1_000, true);
        assert_eq!(seen.get("d1"), 1_000);
        seen.forget("d1");
        assert_eq!(seen.get("d1"), 0);
        seen.set("d1", 2_000, false);
        assert_eq!(seen.get("d1"), 0, "a late close does not bring it back");
        seen.set("d1", 3_000, true);
        assert_eq!(seen.get("d1"), 3_000);
        assert_eq!(seen.get("d2"), 0, "never connected reads as zero");
    }

    #[test]
    fn the_time_is_stored_in_the_database_and_a_forgotten_device_is_deleted() {
        use crate::replica_coordinator::ReplicaCoordinator;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.sqlite3");
        let delay = std::time::Duration::from_millis(20);
        {
            let coordinator = ReplicaCoordinator::open(&path).unwrap();
            let seen = PeerLastSeen::open_with_delay(coordinator.database(), delay);
            seen.set("kept", 1_000, true);
            seen.set("gone", 2_000, true);
            std::thread::sleep(std::time::Duration::from_millis(300));
            seen.forget("gone");
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        let coordinator = ReplicaCoordinator::open(&path).unwrap();
        let again = PeerLastSeen::open_with_delay(coordinator.database(), delay);
        assert_eq!(again.get("kept"), 1_000);
        assert_eq!(again.get("gone"), 0);
    }

    /// Dropping the owner stores what is pending at once (it does not wait out the delay) and
    /// waits for the writer, so a reopen of the same file never races it.
    #[test]
    fn dropping_stores_what_is_pending_and_waits_for_the_writer() {
        use crate::replica_coordinator::ReplicaCoordinator;
        // Repeated, because the unjoined writer only loses the race some of the time.
        for round in 1..=25_i64 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sync.sqlite3");
            {
                let coordinator = ReplicaCoordinator::open(&path).unwrap();
                let seen = PeerLastSeen::open_with_delay(
                    coordinator.database(),
                    std::time::Duration::from_secs(3600),
                );
                seen.set("d1", 7_000 + round, true);
            }
            let coordinator = ReplicaCoordinator::open(&path).unwrap();
            let again = PeerLastSeen::open(coordinator.database());
            assert_eq!(again.get("d1"), 7_000 + round, "round {round}");
        }
    }
}
