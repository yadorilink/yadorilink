//! Track Send's own, wholly separate local store: two small tables in
//! their own database file (never `yadorilink-sync-sqlite`'s index
//! database, never opened by anything in this file but this crate), built
//! on `yadorilink-sqlite-runtime::SyncDatabase` -- the generic pooled-
//! connection/WAL/writer-gate/retry runtime the sync engine also builds
//! on, supplying only its OWN schema-bootstrap closure below. No native-state
//! table (`native_heads`, `native_author_context`, ...) is created, read, or
//! referenced anywhere in this file.
//!
//! Chunk-level resume progress is deliberately NOT a table here: it is the
//! local `SegmentBlockStore`'s own on-disk content, checked via
//! `BlockContentStore::present_blocks`. What this store durably owns is
//! session-level state -- which transfers exist, for/from which device,
//! and (for an inbound transfer) which directory it is materializing
//! into once that decision has been made -- exactly the state a crash
//! between deciding and finishing needs to survive.

use std::path::Path;

use prost::Message;
use rusqlite::{params, OptionalExtension};
use yadorilink_ipc_proto::send::SendManifest;
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::{Result, SendError};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS send_outbound_transfers (
    transfer_id TEXT PRIMARY KEY,
    target_device_id TEXT NOT NULL,
    -- Captured once, at offer time, from the device directory's
    -- resolution of `target_device_id` -- never re-resolved later.
    -- Authorizing a pull compares the connection's authenticated peer key
    -- directly against this column, so a device's key changing (a
    -- re-enrollment) after an offer was made can never let a DIFFERENT
    -- key satisfy an old offer.
    target_signing_key BLOB NOT NULL,
    source_path TEXT NOT NULL,
    manifest_encoded BLOB NOT NULL,
    status TEXT NOT NULL,
    created_at_unix_nanos INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS send_outbound_transfers_by_source_target
    ON send_outbound_transfers(source_path, target_device_id);

-- Why a transfer, either direction, stopped, as a short closed code (`failure` below), for the
-- list the person sees. One row per transfer; it goes when the transfer retries or is pruned.
CREATE TABLE IF NOT EXISTS send_transfer_failures (
    transfer_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS send_inbound_transfers (
    transfer_id TEXT PRIMARY KEY,
    sender_device_id TEXT NOT NULL,
    manifest_encoded BLOB NOT NULL,
    status TEXT NOT NULL,
    destination_dir TEXT,
    offered_at_unix_nanos INTEGER NOT NULL
);
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundStatus {
    Offered,
    Acked,
    /// The receiver explicitly declined this offer
    /// (`SendManifestAck{accepted:false}`). Terminal: a rejected offer is
    /// never retried under the same transfer id -- `find_outbound_by_
    /// source_and_target` skips rows in this state, so `offer_send`
    /// re-running against the same (source, target) after a rejection
    /// always mints a fresh transfer id rather than reusing and mutating
    /// this row -- and -- critically --
    /// [`SendService::handle_pull`](crate::session::SendService::handle_pull)
    /// requires `Acked` before serving any chunk, so a transfer parked here
    /// can never be pulled. Distinct from `Offered` (still awaiting the
    /// receiver's ack) so a rejected offer can eventually be reaped or
    /// reported as declined rather than looking like it is still pending.
    Rejected,
    /// The sender stopped it. Terminal until the person retries it: nothing is served for it, and
    /// the receiver is told so when it comes to pull.
    Canceled,
    /// The receiver reported that it wrote every file (`TransferDone`). Terminal, but it keeps
    /// serving: a receiver that lost what it wrote may pull again.
    Completed,
}

impl OutboundStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutboundStatus::Offered => "offered",
            OutboundStatus::Acked => "acked",
            OutboundStatus::Rejected => "rejected",
            OutboundStatus::Canceled => "canceled",
            OutboundStatus::Completed => "completed",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "acked" => OutboundStatus::Acked,
            "rejected" => OutboundStatus::Rejected,
            "canceled" => OutboundStatus::Canceled,
            "completed" => OutboundStatus::Completed,
            _ => OutboundStatus::Offered,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundStatus {
    Pending,
    InProgress,
    Completed,
    /// The receive stopped without finishing (an error, or the daemon
    /// stopping mid-receive). Resumable by `receive` or retry.
    Failed,
    /// The user abandoned it. Only a retry resumes it.
    Canceled,
}

impl InboundStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            InboundStatus::Pending => "pending",
            InboundStatus::InProgress => "in_progress",
            InboundStatus::Completed => "completed",
            InboundStatus::Failed => "failed",
            InboundStatus::Canceled => "canceled",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "in_progress" => InboundStatus::InProgress,
            "completed" => InboundStatus::Completed,
            "failed" => InboundStatus::Failed,
            "canceled" => InboundStatus::Canceled,
            _ => InboundStatus::Pending,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboundTransfer {
    pub transfer_id: String,
    pub target_device_id: String,
    pub target_signing_key: [u8; 32],
    pub source_path: String,
    pub manifest: SendManifest,
    pub status: OutboundStatus,
    pub created_at_unix_nanos: i64,
}

#[derive(Debug, Clone)]
pub struct InboundTransfer {
    pub transfer_id: String,
    pub sender_device_id: String,
    pub manifest: SendManifest,
    pub status: InboundStatus,
    pub destination_dir: Option<String>,
    pub offered_at_unix_nanos: i64,
}

pub struct SendStore {
    db: SyncDatabase,
}

impl SendStore {
    /// Opens (creating if needed) this device's Track Send database at
    /// `path` -- WAL mode, `synchronous = FULL`, and the writer-gate
    /// `yadorilink-sqlite-runtime` already provides, running only the
    /// schema above. Never call `yadorilink_sqlite_runtime::init_schema`
    /// here -- that is the sync engine's own DDL, for a different
    /// database file entirely.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = SyncDatabase::open(path, |conn| {
            conn.execute_batch(SCHEMA)?;
            Ok(())
        })
        .map_err(SendError::Database)?;
        Ok(Self { db })
    }

    /// Durably records a new outbound offer before anything is dialed --
    /// the "record intent before the first mutating action" step for
    /// `send`: once this returns `Ok`, a crash before any byte reaches the
    /// network still leaves a resumable, re-drivable offer behind (see
    /// `find_outbound_by_source_and_target`).
    #[allow(clippy::too_many_arguments)]
    pub fn insert_outbound_offered(
        &self,
        transfer_id: &str,
        target_device_id: &str,
        target_signing_key: &[u8; 32],
        source_path: &str,
        manifest: &SendManifest,
        created_at_unix_nanos: i64,
    ) -> Result<()> {
        let encoded = manifest.encode_to_vec();
        self.db.write(|conn| -> Result<()> {
            conn.execute(
                "INSERT INTO send_outbound_transfers
                    (transfer_id, target_device_id, target_signing_key, source_path, manifest_encoded, status, created_at_unix_nanos)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    transfer_id,
                    target_device_id,
                    target_signing_key.as_slice(),
                    source_path,
                    encoded,
                    OutboundStatus::Offered.as_str(),
                    created_at_unix_nanos,
                ],
            )?;
            Ok(())
        })
    }

    /// An existing outbound offer for the exact same (source path, target
    /// device) pair, if one is already on record -- `send`'s idempotency
    /// check: re-running the same `send` command after a crash or a
    /// failed dial re-drives THIS transfer id rather than minting a new
    /// one and re-chunking the source a second time.
    ///
    /// Only a transfer still going (offered, or accepted and waiting to be pulled) is handed
    /// back. A declined, canceled or completed one is over: a re-send mints a genuinely new
    /// transfer id instead of reusing and mutating it, and the finished row is left in place for
    /// the history (a canceled or declined one is revived only by an explicit retry).
    pub fn find_outbound_by_source_and_target(
        &self,
        source_path: &str,
        target_device_id: &str,
    ) -> Result<Option<OutboundTransfer>> {
        self.db.read(|conn| -> Result<Option<OutboundTransfer>> {
            Ok(conn
                .query_row(
                    "SELECT transfer_id, target_device_id, target_signing_key, source_path, manifest_encoded, status, created_at_unix_nanos
                 FROM send_outbound_transfers
                 WHERE source_path = ?1 AND target_device_id = ?2
                   AND status IN ('offered', 'acked')
                 ORDER BY created_at_unix_nanos DESC LIMIT 1",
                    params![source_path, target_device_id],
                    row_to_outbound,
                )
                .optional()?)
        })
    }

    pub fn get_outbound(&self, transfer_id: &str) -> Result<Option<OutboundTransfer>> {
        self.db.read(|conn| -> Result<Option<OutboundTransfer>> {
            Ok(conn
                .query_row(
                    "SELECT transfer_id, target_device_id, target_signing_key, source_path, manifest_encoded, status, created_at_unix_nanos
                 FROM send_outbound_transfers WHERE transfer_id = ?1",
                    params![transfer_id],
                    row_to_outbound,
                )
                .optional()?)
        })
    }

    /// Whether any offer to the device holding `target_signing_key` has been
    /// accepted -- the receiver of an accepted offer may dial back to pull
    /// it at any later time. A canceled offer counts, so that receiver is admitted far enough to
    /// be told the sender canceled it, rather than failing as unreachable.
    pub fn has_acked_outbound_for(&self, target_signing_key: &[u8; 32]) -> Result<bool> {
        self.db.read(|conn| -> Result<bool> {
            Ok(conn
                .query_row(
                    "SELECT 1 FROM send_outbound_transfers
                 WHERE target_signing_key = ?1 AND status IN ('acked', 'completed', 'canceled') LIMIT 1",
                    params![&target_signing_key[..]],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
    }

    /// Records the receiver's acceptance. False when the transfer was no longer offered, for
    /// instance because it was canceled while the offer was in flight: a canceled transfer stays
    /// canceled.
    pub fn mark_outbound_acked(&self, transfer_id: &str) -> Result<bool> {
        self.transition_outbound(transfer_id, &["offered"], OutboundStatus::Acked)
    }

    /// Marks a declined offer terminal -- called once `offer_send` has
    /// observed `SendManifestAck{accepted:false}`. Leaves the offered
    /// chunks in the block store (nothing here reaps them) but moves the
    /// row itself to `Rejected`, which is what
    /// [`SendService::handle_pull`](crate::session::SendService::handle_pull)
    /// checks before serving any chunk pull for this transfer id.
    pub fn mark_outbound_rejected(&self, transfer_id: &str) -> Result<bool> {
        self.transition_outbound(transfer_id, &["offered", "acked"], OutboundStatus::Rejected)
    }

    /// Stops an offered or accepted outbound transfer. False (and no change) when it was already
    /// canceled, declined or completed, which is what makes cancel idempotent and never undoes a
    /// completed transfer.
    pub fn cancel_outbound(&self, transfer_id: &str) -> Result<bool> {
        self.transition_outbound(transfer_id, &["offered", "acked"], OutboundStatus::Canceled)
    }

    /// Makes a canceled, declined or never-answered outbound transfer offered again, forgetting
    /// why it stopped. The explicit retry is the only caller.
    ///
    /// Only from `observed`, the status the retry saw when it started: a cancel that landed while
    /// the retry waited for its authorization is newer than the retry and is not undone.
    pub fn reopen_outbound(&self, transfer_id: &str, observed: &OutboundStatus) -> Result<bool> {
        let reopened =
            self.transition_outbound(transfer_id, &[observed.as_str()], OutboundStatus::Offered)?;
        if reopened {
            self.clear_failure(transfer_id)?;
        }
        Ok(reopened)
    }

    /// The status of an outbound transfer, without decoding its manifest.
    pub fn outbound_status(&self, transfer_id: &str) -> Result<Option<OutboundStatus>> {
        self.db.read(|conn| -> Result<Option<OutboundStatus>> {
            Ok(conn
                .query_row(
                    "SELECT status FROM send_outbound_transfers WHERE transfer_id = ?1",
                    params![transfer_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|status| OutboundStatus::parse(&status)))
        })
    }

    /// Moves an offered or accepted transfer to completed. The receiver can finish and say so
    /// before the sender has recorded its acceptance, so an offer still being answered counts.
    /// False when it was canceled or declined.
    pub fn mark_outbound_completed(&self, transfer_id: &str) -> Result<bool> {
        self.transition_outbound(transfer_id, &["offered", "acked"], OutboundStatus::Completed)
    }

    fn transition_outbound(
        &self,
        transfer_id: &str,
        from: &[&str],
        to: OutboundStatus,
    ) -> Result<bool> {
        let from_list = from.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", ");
        Ok(self.db.write(|conn| -> Result<usize> {
            Ok(conn.execute(
                &format!(
                    "UPDATE send_outbound_transfers SET status = ?1
                     WHERE transfer_id = ?2 AND status IN ({from_list})"
                ),
                params![to.as_str(), transfer_id],
            )?)
        })? > 0)
    }

    /// Every outbound transfer still going, plus the `finished_limit` most recently started
    /// finished ones (declined, canceled or completed), oldest first. Older finished rows stay
    /// until pruned, addressable by id, but are not listed.
    pub fn list_outbound_recent(&self, finished_limit: usize) -> Result<Vec<OutboundTransfer>> {
        self.db.read(|conn| -> Result<Vec<OutboundTransfer>> {
            let mut stmt = conn.prepare(
                "SELECT transfer_id, target_device_id, target_signing_key, source_path, manifest_encoded, status, created_at_unix_nanos
                 FROM send_outbound_transfers
                 WHERE status IN ('offered', 'acked')
                    OR transfer_id IN (
                        SELECT transfer_id FROM send_outbound_transfers
                        WHERE status NOT IN ('offered', 'acked')
                        ORDER BY created_at_unix_nanos DESC, transfer_id DESC LIMIT ?1)
                 ORDER BY created_at_unix_nanos ASC, transfer_id ASC",
            )?;
            let rows = stmt.query_map(params![finished_limit as i64], row_to_outbound)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    /// Why `transfer_id` stopped, when it was recorded.
    pub fn failure(&self, transfer_id: &str) -> Result<Option<String>> {
        self.db.read(|conn| -> Result<Option<String>> {
            Ok(conn
                .query_row(
                    "SELECT reason FROM send_transfer_failures WHERE transfer_id = ?1",
                    params![transfer_id],
                    |row| row.get(0),
                )
                .optional()?)
        })
    }

    /// Records why `transfer_id` stopped, replacing an earlier reason.
    pub fn record_failure(&self, transfer_id: &str, reason: &str) -> Result<()> {
        self.db.write(|conn| -> Result<()> {
            conn.execute(
                "INSERT INTO send_transfer_failures (transfer_id, reason) VALUES (?1, ?2)
                 ON CONFLICT(transfer_id) DO UPDATE SET reason = excluded.reason",
                params![transfer_id, reason],
            )?;
            Ok(())
        })
    }

    /// Records how a serve ended for `transfer_id` -- `Some(reason)` it stopped, `None` a whole
    /// file was served (an earlier note no longer holds) -- only while the transfer is still
    /// accepted, decided in the same statement as the write so a cancel or completion landing
    /// meanwhile keeps what it has.
    pub fn note_serve_outcome(&self, transfer_id: &str, reason: Option<&str>) -> Result<()> {
        self.db.write(|conn| -> Result<()> {
            match reason {
                Some(reason) => conn.execute(
                    "INSERT INTO send_transfer_failures (transfer_id, reason)
                     SELECT transfer_id, ?2 FROM send_outbound_transfers
                     WHERE transfer_id = ?1 AND status = 'acked'
                     ON CONFLICT(transfer_id) DO UPDATE SET reason = excluded.reason",
                    params![transfer_id, reason],
                )?,
                None => conn.execute(
                    "DELETE FROM send_transfer_failures WHERE transfer_id = ?1
                     AND EXISTS (SELECT 1 FROM send_outbound_transfers
                                 WHERE transfer_id = ?1 AND status = 'acked')",
                    params![transfer_id],
                )?,
            };
            Ok(())
        })
    }

    pub fn clear_failure(&self, transfer_id: &str) -> Result<()> {
        self.db.write(|conn| -> Result<()> {
            conn.execute(
                "DELETE FROM send_transfer_failures WHERE transfer_id = ?1",
                params![transfer_id],
            )?;
            Ok(())
        })
    }

    /// Keeps the history bounded: of the finished transfers (outbound declined, canceled or
    /// completed; inbound completed or canceled) only the `keep` most recent of each direction
    /// stay; the rest are deleted with their notes. Never touches a transfer still going, an
    /// inbound one that failed (it can resume), received files or sent sources. A pruned
    /// completed outbound transfer can no longer be pulled again.
    ///
    /// `spare` (empty for none) is the transfer that just finished: it stays this once, so a
    /// transfer older than the bound that is canceled still shows as canceled and can be retried,
    /// instead of vanishing the moment it stops. It is pruned by the next call that ranks it old.
    pub fn prune_finished(&self, keep: usize, spare: &str) -> Result<()> {
        self.db.write(|conn| -> Result<()> {
            let keep = keep as i64;
            let outbound_old = "SELECT transfer_id FROM send_outbound_transfers
                 WHERE status IN ('rejected', 'canceled', 'completed')
                 ORDER BY created_at_unix_nanos DESC, transfer_id DESC LIMIT -1 OFFSET ?1";
            let inbound_old = "SELECT transfer_id FROM send_inbound_transfers
                 WHERE status IN ('completed', 'canceled')
                 ORDER BY offered_at_unix_nanos DESC, transfer_id DESC LIMIT -1 OFFSET ?1";
            for (table, old) in
                [("send_outbound_transfers", outbound_old), ("send_inbound_transfers", inbound_old)]
            {
                conn.execute(
                    &format!(
                        "DELETE FROM send_transfer_failures
                         WHERE transfer_id IN ({old}) AND transfer_id != ?2"
                    ),
                    params![keep, spare],
                )?;
                conn.execute(
                    &format!(
                        "DELETE FROM {table} WHERE transfer_id IN ({old}) AND transfer_id != ?2"
                    ),
                    params![keep, spare],
                )?;
            }
            Ok(())
        })
    }

    /// The hex hash of every chunk a transfer still on record can need from the block store:
    /// every sent transfer (a completed one keeps serving until pruned, a canceled or declined
    /// one can be retried without its content being stored again) and every received one but a
    /// completed one, whose files are written (pending, in progress, failed and canceled ones
    /// resume from the blocks already pulled). A manifest that cannot be decoded fails the whole
    /// call: an incomplete set must never reach a deletion decision.
    pub fn live_chunk_hashes(&self) -> Result<std::collections::HashSet<String>> {
        self.db.read(|conn| -> Result<std::collections::HashSet<String>> {
            let mut live = std::collections::HashSet::new();
            for sql in [
                "SELECT manifest_encoded FROM send_outbound_transfers",
                "SELECT manifest_encoded FROM send_inbound_transfers WHERE status != 'completed'",
            ] {
                let mut stmt = conn.prepare(sql)?;
                let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
                for encoded in rows {
                    let manifest = SendManifest::decode(encoded?.as_slice())
                        .map_err(|e| SendError::Protocol(format!("stored manifest: {e}")))?;
                    for file in &manifest.files {
                        live.extend(file.chunk_hashes.iter().map(hex::encode));
                    }
                }
            }
            Ok(live)
        })
    }

    #[cfg(test)]
    pub(crate) fn delete_outbound_for_tests(&self, transfer_id: &str) {
        self.db
            .write(|conn| -> Result<()> {
                conn.execute(
                    "DELETE FROM send_outbound_transfers WHERE transfer_id = ?1",
                    params![transfer_id],
                )?;
                Ok(())
            })
            .unwrap();
    }

    /// Durably records a freshly-offered inbound transfer -- called BEFORE
    /// the manifest's sender is acknowledged, so `accepted = true` on the
    /// wire is never sent for an offer this device has not actually
    /// retained. Idempotent: a duplicate offer for a `transfer_id` already
    /// on record (a sender retry after its own ack never arrived) is a
    /// no-op, reported via the returned `bool`.
    pub fn insert_inbound_if_new(
        &self,
        transfer_id: &str,
        sender_device_id: &str,
        manifest: &SendManifest,
        offered_at_unix_nanos: i64,
    ) -> Result<bool> {
        let encoded = manifest.encode_to_vec();
        let rows = self.db.write(|conn| -> Result<usize> {
            Ok(conn.execute(
                "INSERT OR IGNORE INTO send_inbound_transfers
                    (transfer_id, sender_device_id, manifest_encoded, status, destination_dir, offered_at_unix_nanos)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                params![
                    transfer_id,
                    sender_device_id,
                    encoded,
                    InboundStatus::Pending.as_str(),
                    offered_at_unix_nanos,
                ],
            )?)
        })?;
        Ok(rows > 0)
    }

    pub fn get_inbound(&self, transfer_id: &str) -> Result<Option<InboundTransfer>> {
        self.db.read(|conn| -> Result<Option<InboundTransfer>> {
            Ok(conn
                .query_row(
                    "SELECT transfer_id, sender_device_id, manifest_encoded, status, destination_dir, offered_at_unix_nanos
                 FROM send_inbound_transfers WHERE transfer_id = ?1",
                    params![transfer_id],
                    row_to_inbound,
                )
                .optional()?)
        })
    }

    /// Every unfinished inbound transfer, plus the `finished_limit` most
    /// recently offered finished ones (completed, failed or canceled), oldest
    /// first. This is the bounded history: older finished rows stay in the
    /// store, addressable by id, but are not listed.
    pub fn list_inbound_recent(&self, finished_limit: usize) -> Result<Vec<InboundTransfer>> {
        self.db.read(|conn| -> Result<Vec<InboundTransfer>> {
            let mut stmt = conn.prepare(
                "SELECT transfer_id, sender_device_id, manifest_encoded, status, destination_dir, offered_at_unix_nanos
                 FROM send_inbound_transfers
                 WHERE status IN ('pending', 'in_progress')
                    OR transfer_id IN (
                        SELECT transfer_id FROM send_inbound_transfers
                        WHERE status NOT IN ('pending', 'in_progress')
                        ORDER BY offered_at_unix_nanos DESC, transfer_id DESC LIMIT ?1)
                 ORDER BY offered_at_unix_nanos ASC, transfer_id ASC",
            )?;
            let rows = stmt.query_map(params![finished_limit as i64], row_to_inbound)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    /// Startup recovery: a receive runs only inside the daemon that started
    /// it, so any `in_progress` row found when the store is opened has
    /// nothing driving it. Marks them failed (resumable) and returns how
    /// many there were.
    pub fn interrupt_in_progress_inbound(&self) -> Result<usize> {
        self.transition_inbound_where_status_in(
            None,
            &[InboundStatus::InProgress],
            InboundStatus::Failed,
        )
    }

    /// Marks an unfinished transfer canceled. False (and no change) when it
    /// was already canceled or has completed, which is what makes cancel
    /// idempotent.
    pub fn cancel_inbound(&self, transfer_id: &str) -> Result<bool> {
        Ok(self.transition_inbound_where_status_in(
            Some(transfer_id),
            &[InboundStatus::Pending, InboundStatus::InProgress, InboundStatus::Failed],
            InboundStatus::Canceled,
        )? > 0)
    }

    /// Records that a running receive stopped with an error. Only an
    /// `in_progress` row changes: a transfer canceled underneath the receive
    /// stays canceled.
    pub fn fail_inbound(&self, transfer_id: &str) -> Result<bool> {
        Ok(self.transition_inbound_where_status_in(
            Some(transfer_id),
            &[InboundStatus::InProgress],
            InboundStatus::Failed,
        )? > 0)
    }

    /// A failed transfer starts receiving again. A canceled one is never
    /// resumed here, so a cancel that lands while a receive is starting
    /// cannot be undone by it.
    pub fn resume_inbound(&self, transfer_id: &str) -> Result<bool> {
        Ok(self.transition_inbound_where_status_in(
            Some(transfer_id),
            &[InboundStatus::Failed],
            InboundStatus::InProgress,
        )? > 0)
    }

    /// Makes a canceled transfer resumable again (failed). The explicit
    /// retry is the only caller.
    pub fn uncancel_inbound(&self, transfer_id: &str) -> Result<bool> {
        Ok(self.transition_inbound_where_status_in(
            Some(transfer_id),
            &[InboundStatus::Canceled],
            InboundStatus::Failed,
        )? > 0)
    }

    fn transition_inbound_where_status_in(
        &self,
        transfer_id: Option<&str>,
        from: &[InboundStatus],
        to: InboundStatus,
    ) -> Result<usize> {
        let from_list =
            from.iter().map(|s| format!("'{}'", s.as_str())).collect::<Vec<_>>().join(", ");
        self.db.write(|conn| -> Result<usize> {
            let sql = format!(
                "UPDATE send_inbound_transfers SET status = ?1
                 WHERE status IN ({from_list}) AND (?2 IS NULL OR transfer_id = ?2)"
            );
            Ok(conn.execute(&sql, params![to.as_str(), transfer_id])?)
        })
    }

    /// The "acquire authority, durably before the first mutating action"
    /// step for `receive`: if this transfer has no destination directory
    /// on record yet, atomically claims `requested_dir` as its destination
    /// and moves it to `in_progress`. If a destination is ALREADY on
    /// record (this is a resume, or a second `receive` call), the
    /// requested directory is ignored and the recorded one is returned --
    /// a transfer materializes into exactly one place for its whole
    /// lifetime, decided once, durably, before any chunk is pulled.
    pub fn claim_inbound_destination(
        &self,
        transfer_id: &str,
        requested_dir: &str,
    ) -> Result<String> {
        self.db.write_immediate(|tx| -> Result<String> {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT destination_dir FROM send_inbound_transfers WHERE transfer_id = ?1",
                    params![transfer_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten();
            if let Some(dir) = existing {
                return Ok(dir);
            }
            tx.execute(
                "UPDATE send_inbound_transfers
                 SET destination_dir = ?1, status = ?2
                 WHERE transfer_id = ?3",
                params![requested_dir, InboundStatus::InProgress.as_str(), transfer_id],
            )?;
            Ok(requested_dir.to_string())
        })
    }

    pub fn mark_inbound_completed(&self, transfer_id: &str) -> Result<()> {
        self.db.write(|conn| -> Result<()> {
            conn.execute(
                "UPDATE send_inbound_transfers SET status = ?1 WHERE transfer_id = ?2",
                params![InboundStatus::Completed.as_str(), transfer_id],
            )?;
            Ok(())
        })
    }
}

fn row_to_outbound(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboundTransfer> {
    let key_bytes: Vec<u8> = row.get(2)?;
    let target_signing_key: [u8; 32] = key_bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Blob,
            format!("signing key column has {} bytes, expected 32", bytes.len()).into(),
        )
    })?;
    let encoded: Vec<u8> = row.get(4)?;
    let manifest = SendManifest::decode(encoded.as_slice()).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Blob, Box::new(e))
    })?;
    let status: String = row.get(5)?;
    Ok(OutboundTransfer {
        transfer_id: row.get(0)?,
        target_device_id: row.get(1)?,
        target_signing_key,
        source_path: row.get(3)?,
        manifest,
        status: OutboundStatus::parse(&status),
        created_at_unix_nanos: row.get(6)?,
    })
}

fn row_to_inbound(row: &rusqlite::Row<'_>) -> rusqlite::Result<InboundTransfer> {
    let encoded: Vec<u8> = row.get(2)?;
    let manifest = SendManifest::decode(encoded.as_slice()).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Blob, Box::new(e))
    })?;
    let status: String = row.get(3)?;
    Ok(InboundTransfer {
        transfer_id: row.get(0)?,
        sender_device_id: row.get(1)?,
        manifest,
        status: InboundStatus::parse(&status),
        destination_dir: row.get(4)?,
        offered_at_unix_nanos: row.get(5)?,
    })
}

#[cfg(test)]
mod tests;
