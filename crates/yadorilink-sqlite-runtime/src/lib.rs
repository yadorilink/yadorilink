//! Shared SQLite runtime: connection pool, in-process writer
//! serialization, and schema bootstrap for every SQLite-backed storage
//! crate in this workspace.

mod creation_marker;
mod database;
pub mod diag_hist;
mod error;
mod job_fence;
mod link_registry;
mod pool;
mod schema;

// Permanent writer-gate observability -- see `database::writer_gate_stats`'s own
// header comment.
pub use creation_marker::{
    creation_marker_path, record_database_created, refuse_lost_database, LostDatabaseError,
};
pub use database::writer_gate_stats;
pub use database::{
    current_thread_in_write_transaction, record_writer_generation_in_transaction,
    record_writer_generation_on, OpenOptions, SyncDatabase,
};
pub use error::{DatabaseError, SqlOperationError};
pub use job_fence::{FenceWait, JobCompletion, JobFence, JobScope, FENCE_WARN_INTERVAL};
#[cfg(any(test, feature = "test-support"))]
pub use link_registry::write_registry_for_test;
pub use link_registry::{read_link_registry, RegisteredLink};
pub use pool::{ConnectionPool, BUSY_TIMEOUT, STATEMENT_CACHE_CAPACITY};
pub use schema::{
    authoring_evidence_missing, check_replica_schema_generation, check_schema_version_supported,
    files_authoring_triggers, init_schema, note_child_set_change, note_item_replaced,
    note_retention_changed, reconcile_provider_liveness, table_exists, SCHEMA_VERSION,
};
