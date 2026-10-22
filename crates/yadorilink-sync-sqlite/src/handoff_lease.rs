//! `HandoffLeaseRepository` owns the `handoff_leases` table -- the local
//! record of a version set this device has pinned against retention expiry
//! while a full-replica handoff is in progress. This module keeps the
//! SQL-backed half: schema-shaped row CRUD, the atomic
//! re-enumerate-and-pin transaction, and the persisted `HandoffLease`/
//! `HandoffLeaseState`/`PinnedVersion` value types.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::SyncSqliteError;
use crate::file_index::enumerate_group_durability_roots_on_conn;
use yadorilink_sqlite_runtime::SyncDatabase;

pub use yadorilink_replica_engine::handoff_lease::HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS;

pub type PinnedVersion = (String, i64);

/// A local, target-side handoff-lease pin -- the record that a
/// full-replica-handoff TARGET has pinned an exact version set against
/// retention expiry while its own coordination-service-confirmed handoff is
/// in progress.
///
/// Lifecycle: a target requests a lease from the coordination service after its
/// own local readiness check succeeds (`Provisional`); the source's
/// role-loss commit endpoint confirms it (`Confirmed`) atomically with
/// committing the role loss coordination-side; on any failure of that
/// commit — or if nothing ever reaches it — the lease is `Released` (an
/// explicit failure) or `Expired` (a coordination service TTL sweep, the
/// backstop for a target or source that crashes mid-handoff). Both
/// terminal-failure states stop the lease from pinning anything; retention
/// resumes normally for whatever it named. This type is only the local,
/// target-side half of the protocol: the coordination service's own
/// `handoff_leases` table is the authoritative, race-safe home for the
/// lease's actual state transitions (issued, confirmed, released, expired)
/// — this local copy exists purely so this device's own retention sweep has
/// something to consult without a network round trip on every pass.
#[derive(Debug, Clone, PartialEq)]
pub struct HandoffLease {
    pub lease_id: String,
    pub group_id: String,
    /// The durability-root-set digest this lease was requested against.
    pub root_digest: [u8; 32],
    pub state: HandoffLeaseState,
    /// The exact `(path, version_seq)` rows pinned against retention expiry.
    pub pinned_versions: Vec<PinnedVersion>,
    pub created_at_unix: i64,
    pub expires_at_unix: i64,
}

/// Which state a [`HandoffLease`] is in — see its doc comment for the full
/// lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffLeaseState {
    /// Issued, not yet confirmed by the source's role-loss commit. Actively
    /// pins its versions.
    Provisional,
    /// The source's role-loss commit confirmed this lease coordination-side
    /// — the handoff completed. Actively pins its versions (until it is
    /// separately cleared/expires; a confirmed lease is not automatically
    /// released the instant it confirms, since the caller may still want a
    /// short grace window — see the design note).
    Confirmed,
    /// Explicitly released — the role-loss commit failed, or the local
    /// caller gave up. No longer pins anything.
    Released,
    /// Never confirmed within its TTL; swept by the coordination service's TTL
    /// sweep. No longer pins anything.
    Expired,
}

impl HandoffLeaseState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            HandoffLeaseState::Provisional => "provisional",
            HandoffLeaseState::Confirmed => "confirmed",
            HandoffLeaseState::Released => "released",
            HandoffLeaseState::Expired => "expired",
        }
    }

    /// Strict: an unrecognized state is corruption. Coercing it to
    /// `Provisional` would reopen a lease the writer may have already
    /// confirmed, released or expired.
    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "provisional" => Ok(HandoffLeaseState::Provisional),
            "confirmed" => Ok(HandoffLeaseState::Confirmed),
            "released" => Ok(HandoffLeaseState::Released),
            "expired" => Ok(HandoffLeaseState::Expired),
            other => Err(format!("unknown handoff-lease state: {other}")),
        }
    }
}

pub struct HandoffLeaseRepository {
    database: Arc<SyncDatabase>,
}

impl HandoffLeaseRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Records a target-local pin for `group_id`'s durability-root version
    /// set, the LOCAL half of the lease-request round trip described on
    /// [`HandoffLease`]. `pinned_versions` is normally the exact result of
    /// [`crate::file_index::FileIndexRepository::enumerate_group_durability_root_versions`]
    /// captured alongside the digest the lease was requested against.
    /// Replaces any existing row with the same `lease_id` (idempotent retry
    /// of a request whose response was lost).
    pub fn record_handoff_lease(
        &self,
        group_id: &str,
        lease_id: &str,
        root_digest: [u8; 32],
        pinned_versions: &[PinnedVersion],
        created_at_unix: i64,
        expires_at_unix: i64,
    ) -> Result<(), SyncSqliteError> {
        let pinned_json = serde_json::to_string(pinned_versions)?;
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO handoff_leases \
                    (lease_id, group_id, root_digest, state, pinned_versions_json, \
                     created_at_unix, expires_at_unix) \
                 VALUES (?1, ?2, ?3, 'provisional', ?4, ?5, ?6) \
                 ON CONFLICT(lease_id) DO UPDATE SET \
                    group_id = excluded.group_id, root_digest = excluded.root_digest, \
                    state = 'provisional', pinned_versions_json = excluded.pinned_versions_json, \
                    created_at_unix = excluded.created_at_unix, \
                    expires_at_unix = excluded.expires_at_unix",
                rusqlite::params![
                    lease_id,
                    group_id,
                    &root_digest[..],
                    &pinned_json,
                    created_at_unix,
                    expires_at_unix
                ],
            )?;
            Ok(())
        })
    }

    /// Atomically re-enumerates `group_id`'s durability-root version rows
    /// (the identical `WHERE` clause
    /// [`crate::file_index::FileIndexRepository::enumerate_group_durability_root_versions`]
    /// uses) AND records the handoff-lease pin for exactly that set, in ONE
    /// write transaction — closing the window [`Self::record_handoff_lease`]
    /// alone leaves between a separately-captured enumeration and the pin
    /// write, during which this device's own retention sweep
    /// (`expire_superseded_and_trashed_versions`) could evict a row that was
    /// just enumerated but not yet pinned. Because the re-enumeration and
    /// the `INSERT`/`UPDATE` of `handoff_leases` below run on the same
    /// `IMMEDIATE` transaction, no retention sweep (itself a separate write
    /// transaction) can observe or delete a row in between — it either runs
    /// fully before this call's snapshot or fully after this call's commit.
    ///
    /// `ttl_seconds` is a DURATION, not a deadline — this device (the
    /// handoff target) always derives its own LOCAL pin deadline via
    /// [`yadorilink_replica_engine::handoff_lease::compute_pin_deadline`],
    /// stored as `handoff_leases.expires_at_unix` and later compared only
    /// against this SAME device's own `now_unix` (see
    /// [`Self::leased_version_keys_for_group`]). It never accepts or stores
    /// the coordination Worker's own absolute expiry -- see that function's
    /// own doc comment for the full clock-skew rationale.
    ///
    /// Returns the digest of exactly the set this call pinned — the same
    /// digest routine
    /// [`crate::file_index::FileIndexRepository::enumerate_group_durability_roots`]
    /// uses, computed from a `DurabilityRoots` read on this same
    /// transaction/connection — alongside the pinned `(path, version_seq)`
    /// rows themselves.
    ///
    /// Always writes in `'provisional'` state, matching
    /// [`Self::record_handoff_lease`]; replaces any existing row with the
    /// same `lease_id` (idempotent retry of a request whose response was
    /// lost), also matching it.
    pub fn record_handoff_lease_atomic(
        &self,
        group_id: &str,
        lease_id: &str,
        created_at_unix: i64,
        ttl_seconds: i64,
    ) -> Result<([u8; 32], Vec<PinnedVersion>), SyncSqliteError> {
        // Fails closed, writing no pin row, before this transaction is even
        // opened -- see `compute_pin_deadline`'s own doc comment for why a
        // non-positive TTL must never produce a pin.
        let expires_at_unix = yadorilink_replica_engine::handoff_lease::compute_pin_deadline(
            created_at_unix,
            ttl_seconds,
        )?;
        // IMMEDIATE takes SQLite's write lock at BEGIN, so the
        // re-enumeration and the pin INSERT below observe one snapshot
        // that no concurrent write transaction (in particular a
        // retention sweep) can mutate until this transaction commits.
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let current = enumerate_group_durability_roots_on_conn(tx, group_id)?;
            // Same category/ordering as `enumerate_group_durability_root_
            // versions`, run on the same `tx` so it sees the identical
            // snapshot `current` was just computed from.
            let pinned_versions: Vec<PinnedVersion> = {
                let mut stmt = tx.prepare(
                    "SELECT path, version_seq FROM files \
                     WHERE group_id = ?1 AND deleted = 0 AND record_kind = 'file' \
                       AND state IN ('current', 'superseded', 'trashed') \
                     ORDER BY path, version_seq",
                )?;
                let rows = stmt
                    .query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
                rows.collect::<Result<_, _>>()?
            };
            let pinned_json = serde_json::to_string(&pinned_versions)?;
            tx.execute(
                "INSERT INTO handoff_leases \
                    (lease_id, group_id, root_digest, state, pinned_versions_json, \
                     created_at_unix, expires_at_unix) \
                 VALUES (?1, ?2, ?3, 'provisional', ?4, ?5, ?6) \
                 ON CONFLICT(lease_id) DO UPDATE SET \
                    group_id = excluded.group_id, root_digest = excluded.root_digest, \
                    state = 'provisional', pinned_versions_json = excluded.pinned_versions_json, \
                    created_at_unix = excluded.created_at_unix, \
                    expires_at_unix = excluded.expires_at_unix",
                rusqlite::params![
                    lease_id,
                    group_id,
                    &current.digest[..],
                    pinned_json,
                    created_at_unix,
                    expires_at_unix
                ],
            )?;
            Ok((current.digest, pinned_versions))
        })
    }

    /// Flips a locally-recorded lease's state — `'confirmed'` once the
    /// source's role-loss commit has confirmed it coordination-side,
    /// `'released'`/`'expired'` once it no longer protects anything. A no-op
    /// (`Ok(false)`) if `lease_id` is not recorded locally (e.g. this device
    /// restarted and lost its marker — the lease still terminates on the
    /// the coordination service side via its own TTL sweep either way, so a
    /// missing local row is not itself a correctness problem, only a
    /// slightly earlier resumption of normal retention for whatever it would
    /// have pinned).
    pub fn set_handoff_lease_state(
        &self,
        lease_id: &str,
        new_state: HandoffLeaseState,
    ) -> Result<bool, SyncSqliteError> {
        let changed = self.database.write::<_, SyncSqliteError>(|conn| {
            Ok(conn.execute(
                "UPDATE handoff_leases SET state = ?1 WHERE lease_id = ?2",
                rusqlite::params![new_state.as_db_str(), lease_id],
            )?)
        })?;
        Ok(changed > 0)
    }

    /// Every handoff lease this device currently has recorded for
    /// `group_id`, regardless of state — a diagnostic/test read, not
    /// consulted directly by retention (see
    /// [`Self::leased_version_keys_for_group`] for the enforcement path).
    pub fn list_handoff_leases_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<HandoffLease>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT lease_id, group_id, root_digest, state, pinned_versions_json, \
                        created_at_unix, expires_at_unix \
                 FROM handoff_leases WHERE group_id = ?1 ORDER BY created_at_unix",
            )?;
            let rows = stmt.query_map([group_id], row_to_handoff_lease)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The `(path, version_seq)` set currently pinned against retention
    /// expiry for `group_id`: every row named by a lease that is still
    /// actively protecting it right now — `'provisional'` or `'confirmed'`,
    /// and not yet past its own `expires_at_unix` as of `now_unix_seconds`. A
    /// lease past its expiry is treated as not pinning anything even if its
    /// `state` column hasn't yet been flipped to `'expired'` by a sweep (the
    /// time check is authoritative; the state column is bookkeeping for
    /// visibility, not the enforcement mechanism itself) — this is what lets
    /// `expire_superseded_and_trashed_versions` stay correct even if the
    /// coordination-service/local TTL sweeps haven't run yet.
    ///
    /// `now_unix_seconds` (not nanos, unlike most timestamps elsewhere in
    /// this crate): `handoff_leases.expires_at_unix` holds a target-local
    /// unix-*seconds* deadline (this device's own clock at pin time + the
    /// grant's TTL duration + a fixed safety margin — see
    /// [`Self::record_handoff_lease_atomic`]), so the comparison here is
    /// against this same device's own clock, in seconds; callers must
    /// convert their nanos clock before calling this.
    pub fn leased_version_keys_for_group(
        &self,
        group_id: &str,
        now_unix_seconds: i64,
    ) -> Result<HashSet<PinnedVersion>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT pinned_versions_json FROM handoff_leases \
                 WHERE group_id = ?1 AND state IN ('provisional', 'confirmed') \
                   AND expires_at_unix > ?2",
            )?;
            let mut pinned = HashSet::new();
            let rows = stmt.query_map(rusqlite::params![group_id, now_unix_seconds], |r| {
                r.get::<_, String>(0)
            })?;
            for row in rows {
                let json = row?;
                let versions: Vec<PinnedVersion> = serde_json::from_str(&json)?;
                pinned.extend(versions);
            }
            Ok(pinned)
        })
    }
}

fn handoff_lease_decode_error(column_index: usize, detail: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column_index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, detail.into())),
    )
}

pub fn row_to_handoff_lease(r: &rusqlite::Row<'_>) -> rusqlite::Result<HandoffLease> {
    // Every writer stores a 32-byte digest and `serde_json::to_string` of
    // the pinned set. A short digest or unparseable JSON is corruption: an
    // all-zero root would compare equal to nothing and an empty pinned set
    // would silently unpin every version this lease is holding.
    let root_digest_vec: Vec<u8> = r.get(2)?;
    let root_digest: [u8; 32] = root_digest_vec.as_slice().try_into().map_err(|_| {
        handoff_lease_decode_error(
            2,
            format!("root digest is {} bytes, not 32", root_digest_vec.len()),
        )
    })?;
    let pinned_json: String = r.get(4)?;
    let pinned_versions: Vec<PinnedVersion> = serde_json::from_str(&pinned_json).map_err(|e| {
        handoff_lease_decode_error(4, format!("pinned versions are not valid JSON: {e}"))
    })?;
    Ok(HandoffLease {
        lease_id: r.get(0)?,
        group_id: r.get(1)?,
        root_digest,
        state: HandoffLeaseState::try_from_db_str(&r.get::<_, String>(3)?)
            .map_err(|e| handoff_lease_decode_error(3, e))?,
        pinned_versions,
        created_at_unix: r.get(5)?,
        expires_at_unix: r.get(6)?,
    })
}
