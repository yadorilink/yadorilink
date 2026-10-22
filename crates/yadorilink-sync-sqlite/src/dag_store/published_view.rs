//! What native publication evidence vouches for, read for the paths that make
//! content externally observable (block-serving authorization).
//!
//! A row or a head counts only while a native witness, or the admitted
//! delta behind it, still carries retained authorization evidence
//! (`native_delta_authorization`). Nothing here verifies a signature; the
//! evidence was verified when it was attached.

use rusqlite::Connection;

use crate::error::SyncSqliteError;

/// Whether a block is referenced by a version whose content is justified by
/// publication evidence -- the block-serving authorization boundary. A native
/// row's content counts while its native witness stands and the evidence of
/// the delta behind it is retained; a live native head's content counts as
/// soon as it is admitted, whether or not this replica has projected it.
pub fn published_group_file_version_references_block(
    conn: &Connection,
    group_id: &str,
    block_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    // `file_version_blocks` answers which versions of the group name the block by index;
    // publication is read live from the evidence tables, so it cannot go stale. The version row
    // must still exist (as in the scan this replaced), so an index row alone never authorizes.
    // A stored version's bytes were verified against its hash at insert and never change, so
    // the lookup does not decode them again.
    //
    // Cost: one probe set per stored version that names the block, so it grows with how many
    // versions share it, not with the group's size. Measured (release, informal) with one block
    // shared by every version: a hit costs about 2 us at any count; a miss, which needs that many
    // stored versions that are all unpublished, about 0.4 ms at 1k, 4 ms at 10k and 20 ms at 50k.
    // A block no stored version names, or one a published version names, stays a point lookup.
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS( \
               SELECT 1 FROM file_version_blocks b \
               WHERE b.group_id = ?1 AND b.block_hash = ?2 \
                 AND EXISTS(SELECT 1 FROM file_versions fv \
                            WHERE fv.group_id = b.group_id AND fv.version_hash = b.version_hash) \
                 AND ( \
                 EXISTS( \
                   SELECT 1 FROM native_authoring_witness w \
                   JOIN native_delta_authorization a ON a.delta_hash = substr(w.identity, 1, 32) \
                   WHERE w.group_id = b.group_id AND w.version = b.version_hash) \
                 OR EXISTS( \
                   SELECT 1 FROM native_heads h \
                   JOIN native_delta_authorization a ON a.delta_hash = h.provenance \
                   WHERE h.group_id = b.group_id AND h.version = b.version_hash)))",
        )?
        .query_row(rusqlite::params![group_id, block_hash], |row| row.get(0))?)
}

/// The scan this lookup replaced: decodes every published version of the group until one names
/// the block. The equivalence tests hold the lookup to it.
#[cfg(test)]
pub(crate) fn published_group_file_version_references_block_by_scan(
    conn: &Connection,
    group_id: &str,
    block_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    if versions_reference_block(
        conn,
        "SELECT DISTINCT fv.encoded \
         FROM native_authoring_witness w \
         JOIN native_delta_authorization a ON a.delta_hash = substr(w.identity, 1, 32) \
         JOIN file_versions fv ON fv.group_id = w.group_id AND fv.version_hash = w.version \
         WHERE w.group_id = ?1",
        group_id,
        block_hash,
    )? {
        return Ok(true);
    }
    versions_reference_block(
        conn,
        "SELECT DISTINCT fv.encoded \
         FROM native_heads h \
         JOIN native_delta_authorization a ON a.delta_hash = h.provenance \
         JOIN file_versions fv ON fv.group_id = h.group_id AND fv.version_hash = h.version \
         WHERE h.group_id = ?1",
        group_id,
        block_hash,
    )
}

#[cfg(test)]
fn versions_reference_block(
    conn: &Connection,
    query: &str,
    group_id: &str,
    block_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    let mut stmt = conn.prepare(query)?;
    let mut rows = stmt.query([group_id])?;
    while let Some(row) = rows.next()? {
        let encoded: Vec<u8> = row.get(0)?;
        let version =
            yadorilink_replica_domain::file::FileVersion::from_canonical_encoding(&encoded)
                .map_err(|_| {
                    SyncSqliteError::CorruptState("stored file version is corrupt".into())
                })?;
        if version.blocks.iter().any(|block| block.hash.0.as_slice() == block_hash) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
#[path = "published_view_tests.rs"]
mod tests;
