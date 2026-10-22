//! The blocks the live native heads still name.
//!
//! A head's version can be absent from every `files` row (a conflicting head
//! whose projection has not been written yet, a head superseded locally but
//! still live on a peer). Its blocks stay reachable for the physical block
//! GC for as long as the head is live, so nothing a head promises is reclaimed
//! out from under it.

use std::collections::HashSet;

use rusqlite::Connection;
use yadorilink_replica_domain::ids::VersionHash;

use crate::error::SyncSqliteError;

/// Every block hash named by a retained version of a live native head, across
/// every group. A head whose version this replica never fetched contributes
/// nothing: there is no body to read blocks from.
pub fn native_head_retained_block_hashes_all_groups(
    conn: &Connection,
) -> Result<HashSet<String>, SyncSqliteError> {
    native_head_retained_block_hashes_except(conn, &[])
}

/// [`native_head_retained_block_hashes_all_groups`] without the heads at exactly one of `except`
/// (group, path, version): the versions a caller is itself deciding about, whose own heads must
/// not keep them alive. A head at another path, in another group, or at another version still counts.
pub fn native_head_retained_block_hashes_except(
    conn: &Connection,
    except: &[(&str, &str, &VersionHash)],
) -> Result<HashSet<String>, SyncSqliteError> {
    let mut stmt = conn.prepare("SELECT DISTINCT group_id, path, version FROM native_heads")?;
    let heads = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut live = HashSet::new();
    for (group_id, path, version) in heads {
        let Ok(hash) = <[u8; 32]>::try_from(version.as_slice()) else {
            return Err(SyncSqliteError::CorruptState(format!(
                "a native head of group {group_id} names a version that is not 32 bytes"
            )));
        };
        if except.iter().any(|(g, p, v)| *g == group_id && *p == path && v.0 == hash) {
            continue;
        }
        if let Some(version) = super::serving_authorization_index::get_file_version(
            conn,
            &group_id,
            &VersionHash(hash),
        )? {
            live.extend(version.blocks.iter().map(|block| hex::encode(&block.hash.0)));
        }
    }
    Ok(live)
}
