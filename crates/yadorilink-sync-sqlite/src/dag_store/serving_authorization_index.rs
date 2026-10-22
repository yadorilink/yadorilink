//! The block-service authorization boundary: `file_versions` (content-
//! addressed version bytes, scoped per group), `change_file_versions` (which
//! admitted change justifies a group holding a given version -- this is what
//! [`group_file_version_references_block`] actually consults to decide
//! whether to serve a physical block), and `group_block_provenance` (which
//! groups this device actually obtained verified block bytes through). Treat
//! `change_file_versions` as a security boundary, not a cache: an extra,
//! unjustified relation here can manufacture block-serving rights that the
//! group's signed history never granted, which is exactly what
//! [`prune_unjustified_change_file_versions`] guards against.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::VersionHash;

/// Whether a content-addressed file version is present.
pub fn has_file_version(
    conn: &Connection,
    group_id: &str,
    hash: &VersionHash,
) -> Result<bool, SyncSqliteError> {
    let present: Option<i64> = conn
        .prepare_cached("SELECT 1 FROM file_versions WHERE group_id = ?1 AND version_hash = ?2")?
        .query_row(rusqlite::params![group_id, &hash.0[..]], |r| r.get(0))
        .optional()?;
    Ok(present.is_some())
}

/// The file version stored under `hash`, decoded from its canonical bytes, or
/// `None`. The decoded version's hash is recomputed and checked against the
/// key, so a lookup only ever returns a version whose bytes actually hash to
/// the requested address — a corrupt row is a clean error, never silently
/// mismatched content.
pub fn get_file_version(
    conn: &Connection,
    group_id: &str,
    hash: &VersionHash,
) -> Result<Option<FileVersion>, SyncSqliteError> {
    let encoded: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT encoded FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
        )?
        .query_row(rusqlite::params![group_id, &hash.0[..]], |r| r.get(0))
        .optional()?;
    match encoded {
        Some(bytes) => {
            let version = FileVersion::from_canonical_encoding(&bytes)
                .map_err(|_| SyncSqliteError::NotFound("stored file version is corrupt".into()))?;
            if version.version_hash != *hash {
                return Err(SyncSqliteError::NotFound(
                    "stored file version hash does not match its key".into(),
                ));
            }
            Ok(Some(version))
        }
        None => Ok(None),
    }
}

/// Records that this device obtained verified block bytes through `group_id`.
/// Callers must only invoke this after a local chunk-store write or after a
/// fetched response has passed hash/size verification and been persisted.
pub fn record_group_block_provenance(
    conn: &Connection,
    group_id: &str,
    block_hashes: &[Vec<u8>],
) -> Result<(), SyncSqliteError> {
    let mut stmt = conn.prepare(
        "INSERT OR IGNORE INTO group_block_provenance (group_id, block_hash) VALUES (?1, ?2)",
    )?;
    for block_hash in block_hashes {
        stmt.execute(rusqlite::params![group_id, block_hash])?;
    }
    Ok(())
}

/// Whether verified bytes for `block_hash` were actually obtained through
/// `group_id`, independently of any peer-supplied metadata references.
pub fn group_has_block_provenance(
    conn: &Connection,
    group_id: &str,
    block_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM group_block_provenance WHERE group_id = ?1 AND block_hash = ?2)",
        rusqlite::params![group_id, block_hash],
        |row| row.get(0),
    )?)
}

/// Records the blocks the just-stored `versions` name in `file_version_blocks`, a few rows per
/// statement. Only called for versions that were newly inserted, in the same transaction.
fn index_version_blocks(
    conn: &Connection,
    group_id: &str,
    versions: &[&FileVersion],
) -> Result<(), SyncSqliteError> {
    // Three parameters per row, under SQLite's default limit.
    const ROWS_PER_INSERT: usize = 300;
    let mut rows = versions.iter().flat_map(|version| {
        version.blocks.iter().map(move |block| (&block.hash.0[..], &version.version_hash.0[..]))
    });
    loop {
        let chunk: Vec<(&[u8], &[u8])> = rows.by_ref().take(ROWS_PER_INSERT).collect();
        if chunk.is_empty() {
            return Ok(());
        }
        let marks = vec!["(?,?,?)"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "INSERT OR IGNORE INTO file_version_blocks (group_id, block_hash, version_hash) \
             VALUES {marks}"
        ))?;
        let params = chunk.iter().flat_map(|(block, version)| {
            [
                rusqlite::types::Value::from(group_id.to_owned()),
                rusqlite::types::Value::from(block.to_vec()),
                rusqlite::types::Value::from(version.to_vec()),
            ]
        });
        stmt.execute(rusqlite::params_from_iter(params))?;
    }
}

/// Persists a file version, keyed by its content hash. Idempotent — re-putting
/// an identical version is a no-op and returns `false`. The version's hash is
/// re-derived from its bytes and must match its `version_hash` field before
/// anything is written, so a version can never be stored under a hash that does
/// not describe its content (whether it came from local emission or a peer's
/// wire encoding). Runs on the supplied connection, so passing an open
/// transaction stores the version atomically with the change that references
/// it.
pub fn put_file_version(
    conn: &Connection,
    group_id: &str,
    version: &FileVersion,
) -> Result<bool, SyncSqliteError> {
    // A version that fails verification is malformed input, not a missing
    // row: its hash does not describe its bytes, or its structure is
    // invalid (e.g. block sizes that do not add up to the declared size).
    // Reported as `InvalidInput` carrying the real cause, so neither a log
    // reader nor a caller that treats `NotFound` as "not resolvable yet"
    // mistakes it for a lookup miss.
    version.verify_hash().map_err(|error| {
        SyncSqliteError::InvalidInput(format!(
            "file version {} is invalid: {error}",
            hex::encode(version.version_hash.0)
        ))
    })?;
    let changed = conn
        .prepare_cached(
            "INSERT OR IGNORE INTO file_versions (version_hash, group_id, encoded) \
             VALUES (?1, ?2, ?3)",
        )?
        .execute(rusqlite::params![
            &version.version_hash.0[..],
            group_id,
            version.canonical_encoding()
        ])?;
    if changed > 0 {
        index_version_blocks(conn, group_id, &[version])?;
        crate::native_desired_state::arm_projection_for_arrived_version(
            conn,
            group_id,
            &version.version_hash,
        )?;
    }
    Ok(changed > 0)
}

/// [`put_file_version`] for the versions of one bulk capture group: every version is verified,
/// the ones not yet stored are inserted in a few statements, and only those re-arm the paths
/// whose heads name them -- a version already stored, or repeated within `versions`, arms
/// nothing, as with [`put_file_version`] one version at a time. Returns how many were new.
pub fn put_file_versions_batch(
    conn: &Connection,
    group_id: &str,
    versions: &[&FileVersion],
) -> Result<usize, SyncSqliteError> {
    // The most rows one insert binds: three parameters each, under SQLite's default limit.
    const ROWS_PER_INSERT: usize = 300;
    for version in versions {
        version.verify_hash().map_err(|error| {
            SyncSqliteError::InvalidInput(format!(
                "file version {} is invalid: {error}",
                hex::encode(version.version_hash.0)
            ))
        })?;
    }
    let mut seen = std::collections::HashSet::new();
    let distinct: Vec<&FileVersion> =
        versions.iter().copied().filter(|v| seen.insert(v.version_hash.0)).collect();
    let mut stored = std::collections::HashSet::new();
    for chunk in distinct.chunks(crate::store::PATHS_PER_QUERY) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT version_hash FROM file_versions WHERE group_id = ?1 AND version_hash IN ({marks})"
        ))?;
        let params = std::iter::once(rusqlite::types::Value::from(group_id.to_owned()))
            .chain(chunk.iter().map(|v| rusqlite::types::Value::from(v.version_hash.0.to_vec())));
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            stored.insert(row.get::<_, Vec<u8>>(0)?);
        }
    }
    let fresh: Vec<&FileVersion> =
        distinct.into_iter().filter(|v| !stored.contains(&v.version_hash.0[..])).collect();
    for chunk in fresh.chunks(ROWS_PER_INSERT) {
        let marks = vec!["(?,?,?)"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "INSERT OR IGNORE INTO file_versions (version_hash, group_id, encoded) VALUES {marks}"
        ))?;
        let params = chunk.iter().flat_map(|v| {
            [
                rusqlite::types::Value::from(v.version_hash.0.to_vec()),
                rusqlite::types::Value::from(group_id.to_owned()),
                rusqlite::types::Value::from(v.canonical_encoding()),
            ]
        });
        stmt.execute(rusqlite::params_from_iter(params))?;
    }
    index_version_blocks(conn, group_id, &fresh)?;
    let arrived: Vec<VersionHash> = fresh.iter().map(|v| v.version_hash).collect();
    crate::native_desired_state::arm_projection_for_arrived_versions(conn, group_id, &arrived)?;
    Ok(arrived.len())
}
