//! The two roots a `Summary` carries.
//!
//! The namespace root is stored and patched with every head write ([`crate::native_namespace`]), so
//! reading it costs one row however large the group is. The author-state root is over the authors,
//! not the paths, and is computed from its rows.

use rusqlite::Connection;

use yadorilink_replica_domain::ids::FolderGroupId;

use crate::error::SyncSqliteError;
use crate::native_replication::SummaryRoots;
use crate::native_store;

/// The roots computed from the rows by rebuilding the whole namespace trie in memory: the reference
/// the stored trie is checked against in tests, and what a caller that has no stored trie (a bundle
/// being verified) computes.
pub fn compute_summary_roots(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<SummaryRoots, SyncSqliteError> {
    let state = native_store::load_state(conn, group_id)?;
    Ok(SummaryRoots {
        namespace_root: native_store::namespace_root(&state)?.0,
        author_state_root: native_store::author_state_root(conn, group_id)?.0,
    })
}

/// The group's roots: the stored namespace root (patched with every head write, see
/// [`crate::native_namespace`]) and the author-state root, which is over the authors, not the paths.
pub(crate) fn summary_roots(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<SummaryRoots, SyncSqliteError> {
    // One snapshot for both roots. A savepoint, because a caller may already hold a transaction.
    conn.execute_batch("SAVEPOINT native_summary_roots")?;
    let result = (|| {
        Ok(SummaryRoots {
            namespace_root: crate::native_namespace::namespace_root(conn, group_id)?.0,
            author_state_root: native_store::author_state_root(conn, group_id)?.0,
        })
    })();
    conn.execute_batch("RELEASE native_summary_roots")?;
    result
}
