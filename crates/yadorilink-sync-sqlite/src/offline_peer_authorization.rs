//! `OfflinePeerAuthorizationRepository` owns the
//! `offline_peer_authorization` / `offline_peer_authorization_group` tables
//! -- this device's last-known-good record of what a live netmap last
//! authorized each of its peers for.
//!
//! What this is: a cache of a decision the coordination plane already made
//! and this device already verified, kept so a restart taken while that
//! plane is unreachable can go on syncing with peers on the same local
//! network instead of forgetting every peer it has.
//!
//! What this is NOT: an authority. Nothing here grants anything. Every row
//! is written by a live netmap application, replaced by the next one, and
//! deleted when that netmap withdraws the peer -- so the worst a stale row
//! can do is keep repeating an authorization the plane last confirmed,
//! which is exactly the contract, and it can never widen one. Detecting a
//! revocation that happens at the plane while this device is offline is not
//! in scope here and nothing in this module claims it.

use std::sync::Arc;

use crate::error::SyncSqliteError;
use yadorilink_sqlite_runtime::SyncDatabase;

/// One peer's persisted last-known-good authorization.
///
/// `signing_key` is the peer's pinned Ed25519 key, which is also its
/// endpoint id -- the identity a local-network announcement has to prove.
/// `writer_groups` is what it may write; `full_replica_groups` is the
/// subset of those it syncs as a full replica (always a subset: the live
/// state intersects them before this is written, and a reader that finds
/// otherwise should treat the extra entries as unauthorized).
///
/// `membership_generation` and `captured_at_unix` are the version and time
/// of the netmap application this row mirrors -- what a reader needs to say
/// how old the authorization it is running offline on is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePeerAuthorization {
    pub device_id: String,
    pub signing_key: [u8; 32],
    pub writer_groups: Vec<String>,
    pub full_replica_groups: Vec<String>,
    pub membership_generation: u64,
    pub captured_at_unix: i64,
}

/// The two version counters that belong to the snapshot as a whole rather
/// than to any one peer row.
///
/// `membership_generation` is the device's own authorization version at
/// the moment of the write; `snapshot_generation` is the coordination
/// plane's netmap snapshot version the write came from (0 when no netmap
/// has ever written these rows).
///
/// Both are monotonic on disk: a write takes the maximum of what it
/// carries and what is already stored, so neither can retreat. That is the
/// point of keeping them here rather than deriving them from the surviving
/// peer rows -- the row carrying the highest generation is exactly the one
/// a withdrawal deletes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OfflineSnapshotVersions {
    pub membership_generation: u64,
    pub snapshot_generation: u64,
}

pub struct OfflinePeerAuthorizationRepository {
    database: Arc<SyncDatabase>,
}

impl OfflinePeerAuthorizationRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Every persisted peer authorization, for a daemon rebuilding its
    /// in-memory peer authority at startup.
    ///
    /// Fails closed as a whole: a row whose stored signing key is not 32
    /// bytes is corrupt state, and the error it raises leaves the caller
    /// with no restored authorization rather than a partial set whose gaps
    /// nobody can see. Authorizing nobody is a working daemon that waits
    /// for a netmap; authorizing an unexamined subset is not.
    pub fn all_peer_authorizations(
        &self,
    ) -> Result<Vec<OfflinePeerAuthorization>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut peers: Vec<OfflinePeerAuthorization> = {
                let mut statement = conn.prepare(
                    "SELECT device_id, signing_key, membership_generation, captured_at_unix \
                     FROM offline_peer_authorization ORDER BY device_id",
                )?;
                // Row shape: `(device_id, signing_key, membership_generation,
                // captured_at_unix)`.
                type PeerRow = (String, Vec<u8>, i64, i64);
                let rows = statement
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
                let mut peers = Vec::new();
                for row in rows {
                    let (device_id, key_blob, generation, captured_at_unix): PeerRow = row?;
                    let signing_key: [u8; 32] = key_blob.as_slice().try_into().map_err(|_| {
                        SyncSqliteError::CorruptState(format!(
                            "stored offline authorization signing key for {device_id} is not \
                                 32 bytes"
                        ))
                    })?;
                    peers.push(OfflinePeerAuthorization {
                        device_id,
                        signing_key,
                        writer_groups: Vec::new(),
                        full_replica_groups: Vec::new(),
                        membership_generation: generation as u64,
                        captured_at_unix,
                    });
                }
                peers
            };

            let mut statement = conn.prepare(
                "SELECT device_id, group_id, is_full_replica \
                 FROM offline_peer_authorization_group ORDER BY device_id, group_id",
            )?;
            let rows = statement.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })?;
            for row in rows {
                let (device_id, group_id, is_full_replica) = row?;
                // A group edge whose parent row is gone authorizes nothing:
                // the pinned key is what an announcement is matched against,
                // and without it there is no peer to authorize.
                let Some(peer) = peers.iter_mut().find(|peer| peer.device_id == device_id) else {
                    continue;
                };
                peer.writer_groups.push(group_id.clone());
                if is_full_replica != 0 {
                    peer.full_replica_groups.push(group_id);
                }
            }
            Ok(peers)
        })
    }

    /// Writes (creating or replacing) one peer's last-known-good
    /// authorization, group edges included, as one transaction -- so a
    /// restart can never read a peer's key paired with the group set of an
    /// earlier netmap.
    ///
    /// The caller is a live netmap application mirroring what it has just
    /// applied in memory; this method makes no authorization decision of
    /// its own and validates nothing beyond the row shape.
    pub fn store_peer_authorization(
        &self,
        peer: &OfflinePeerAuthorization,
        versions: OfflineSnapshotVersions,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            advance_snapshot_versions(tx, versions)?;
            tx.execute(
                "INSERT OR REPLACE INTO offline_peer_authorization \
                 (device_id, signing_key, membership_generation, captured_at_unix) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    peer.device_id,
                    &peer.signing_key[..],
                    peer.membership_generation as i64,
                    peer.captured_at_unix,
                ],
            )?;
            // Replaced wholesale, never patched: a demotion has to be able
            // to remove a writer edge, and leaving one behind would outlive
            // the netmap that withdrew it.
            tx.execute(
                "DELETE FROM offline_peer_authorization_group WHERE device_id = ?1",
                [&peer.device_id],
            )?;
            for group_id in &peer.writer_groups {
                tx.execute(
                    "INSERT OR REPLACE INTO offline_peer_authorization_group \
                     (device_id, group_id, is_full_replica) VALUES (?1, ?2, ?3)",
                    rusqlite::params![
                        peer.device_id,
                        group_id,
                        i64::from(peer.full_replica_groups.iter().any(|g| g == group_id)),
                    ],
                )?;
            }
            Ok(())
        })
    }

    /// Withdraws one peer entirely -- what a live netmap that no longer
    /// lists the device leaves behind, so a later restart does not
    /// resurrect an authorization that netmap revoked.
    pub fn forget_peer_authorization(
        &self,
        device_id: &str,
        versions: OfflineSnapshotVersions,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            advance_snapshot_versions(tx, versions)?;
            tx.execute(
                "DELETE FROM offline_peer_authorization_group WHERE device_id = ?1",
                [device_id],
            )?;
            tx.execute("DELETE FROM offline_peer_authorization WHERE device_id = ?1", [device_id])?;
            Ok(())
        })
    }

    /// Drops the whole snapshot. For the events after which this device has
    /// no authorization to remember at all -- signing out, or being
    /// unregistered as a device -- where keeping a last-known-good record
    /// of peers would outlive the account relationship that produced it.
    /// The peer rows go; the version counters stay and advance. They name
    /// no device and record no relationship -- they are two integers whose
    /// only job is to never retreat, and resetting them would hand a later
    /// run a generation an earlier one had already used.
    pub fn forget_all_peer_authorizations(
        &self,
        versions: OfflineSnapshotVersions,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            advance_snapshot_versions(tx, versions)?;
            tx.execute("DELETE FROM offline_peer_authorization_group", [])?;
            tx.execute("DELETE FROM offline_peer_authorization", [])?;
            Ok(())
        })
    }

    /// The snapshot-wide version counters, or all-zero when nothing has
    /// ever been written.
    pub fn snapshot_versions(&self) -> Result<OfflineSnapshotVersions, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let stored = conn
                .query_row(
                    "SELECT membership_generation, snapshot_generation \
                     FROM offline_authorization_snapshot WHERE id = 1",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .map(|(membership, snapshot)| OfflineSnapshotVersions {
                    membership_generation: membership as u64,
                    snapshot_generation: snapshot as u64,
                });
            match stored {
                Ok(versions) => Ok(versions),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(OfflineSnapshotVersions::default()),
                Err(error) => Err(error.into()),
            }
        })
    }
}

/// Raises the stored counters to `versions`, never lowering either one.
///
/// `MAX` rather than assignment because these are watermarks: two writes
/// that reach disk out of the order their callers made them must still
/// leave the higher value behind, and a caller that legitimately carries a
/// lower number (a peer row written from an older in-memory read) must not
/// be able to rewind the snapshot's version.
fn advance_snapshot_versions(
    tx: &rusqlite::Transaction<'_>,
    versions: OfflineSnapshotVersions,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "INSERT INTO offline_authorization_snapshot \
         (id, membership_generation, snapshot_generation) VALUES (1, ?1, ?2) \
         ON CONFLICT(id) DO UPDATE SET \
         membership_generation = MAX(membership_generation, excluded.membership_generation), \
         snapshot_generation = MAX(snapshot_generation, excluded.snapshot_generation)",
        rusqlite::params![
            versions.membership_generation as i64,
            versions.snapshot_generation as i64,
        ],
    )?;
    Ok(())
}
