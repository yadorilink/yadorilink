//! Persistence for file versions, block provenance and the projection and
//! materialization tables, stored in the same SQLite database as the file
//! index.
//!
//! Every function here takes a plain `&Connection`. A `rusqlite::Transaction`
//! dereferences to `Connection`, so passing `&tx` runs the operation inside
//! that transaction -- this is what lets a local mutation author its delta
//! and mutate the file index atomically, in one commit. Reads take the same
//! `&Connection` so callers can query either standalone or inside a write
//! transaction.
//!
//! The submodules each own one structure:
//! - [`serving_authorization_index`] — `file_versions` and
//!   `group_block_provenance`.
//! - [`native_head_blocks`] — the blocks the live native heads still name.
//! - [`published_view`] — what native publication evidence vouches for.
//!
//! What stays here: the DDL of the tables above ([`init_dag_tables`]).

mod native_head_blocks;
pub mod published_view;
mod serving_authorization_index;

pub use native_head_blocks::{
    native_head_retained_block_hashes_all_groups, native_head_retained_block_hashes_except,
};
pub use serving_authorization_index::{
    get_file_version, group_has_block_provenance, has_file_version, put_file_version,
    put_file_versions_batch, record_group_block_provenance,
};

use rusqlite::Connection;

use crate::error::SyncSqliteError;

pub use yadorilink_replica_domain::admission::{LocalAuthorKey, PathRefusal};

/// The file-version and block-provenance tables.
pub(crate) const DAG_VERSION_TABLES: &str = r#"
        CREATE TABLE IF NOT EXISTS file_versions (
            version_hash BLOB NOT NULL,
            group_id     TEXT NOT NULL,
            encoded      BLOB NOT NULL,
            PRIMARY KEY (group_id, version_hash)
        );
        CREATE INDEX IF NOT EXISTS file_versions_by_group ON file_versions(group_id);

        -- The blocks each stored version names, written in the same statement
        -- batch that stores the version (versions are immutable, so the rows
        -- never change). Block-serving authorization asks which versions of a
        -- group name a block; this answers by index instead of by decoding
        -- every version. It carries no authorization of its own: whether a
        -- version counts as published is read live from the publication tables.
        CREATE TABLE IF NOT EXISTS file_version_blocks (
            group_id     TEXT NOT NULL,
            block_hash   BLOB NOT NULL,
            version_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, block_hash, version_hash)
        ) WITHOUT ROWID;

        -- Physical blocks remain globally content-addressed and deduplicated,
        -- while this table records the groups through which this device has
        -- actually obtained the verified bytes.  FileVersion metadata alone
        -- must never create one of these rows.
        CREATE TABLE IF NOT EXISTS group_block_provenance (
            group_id   TEXT NOT NULL,
            block_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, block_hash)
        );

"#;

/// Creates the file-version and block-provenance tables and the tables the
/// projection, materialization and local capture keep beside them.
pub(crate) fn init_dag_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.set_prepared_statement_cache_capacity(yadorilink_sqlite_runtime::STATEMENT_CACHE_CAPACITY);
    conn.execute_batch(DAG_VERSION_TABLES)?;
    crate::projection_obligations::init_projection_obligations_schema(conn)?;
    crate::materialized_generation::init_materialized_generation_schema(conn)?;
    crate::local_capture_provenance::init_local_capture_provenance_schema(conn)?;
    crate::structural_origin::init_structural_origin_schema(conn)?;
    Ok(())
}

pub(crate) fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}
