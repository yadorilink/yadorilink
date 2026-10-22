//! `OfflineGroupPolicyLogRepository` owns the `offline_group_policy_log`
//! table -- the raw signed policy log the coordination plane last sent for
//! each group, kept so a daemon restarted while that plane is unreachable
//! can re-verify it and go on admitting changes.
//!
//! What this is: signed bytes. Every record in a stored log carries the
//! group authority's Ed25519 signature over its own canonical preimage, and
//! the reader verifies the whole chain against the service key this device
//! has pinned before any of it is believed -- the same verification a live
//! netmap frame goes through, over the same bytes. Storage therefore grants
//! nothing: a row that was tampered with fails verification, and a row that
//! is an older chain than this device has already adopted fails the
//! persisted rollback watermark (`group_policy_watermark`).
//!
//! What this is NOT: an authority, and not a second opinion about policy. A
//! live netmap replaces what is here wholesale on the way past, and a group
//! whose snapshot fails verification has its row deleted rather than left
//! for a later restart to fall back on.

use std::sync::Arc;

use crate::error::SyncSqliteError;
use yadorilink_sqlite_runtime::SyncDatabase;

/// One group's stored signed policy log.
///
/// `log` is opaque here on purpose: this repository stores and returns the
/// encoded chain without interpreting it, because the only component
/// entitled to an opinion about its contents is the verifier that checks its
/// signatures. `captured_at_unix` is when the netmap frame it came from was
/// applied -- what a reader needs to say how old the policy it is running
/// offline on is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineGroupPolicyLog {
    pub group_id: String,
    pub log: String,
    pub captured_at_unix: i64,
}

pub struct OfflineGroupPolicyLogRepository {
    database: Arc<SyncDatabase>,
}

impl OfflineGroupPolicyLogRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Every stored policy log, for a daemon rebuilding its verified policy
    /// state at startup.
    pub fn all_group_policy_logs(&self) -> Result<Vec<OfflineGroupPolicyLog>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut statement = conn.prepare(
                "SELECT group_id, log, captured_at_unix FROM offline_group_policy_log \
                 ORDER BY group_id",
            )?;
            let rows = statement.query_map([], |r| {
                Ok(OfflineGroupPolicyLog {
                    group_id: r.get(0)?,
                    log: r.get(1)?,
                    captured_at_unix: r.get(2)?,
                })
            })?;
            let mut logs = Vec::new();
            for row in rows {
                logs.push(row?);
            }
            Ok(logs)
        })
    }

    /// Stores (replacing) one group's signed policy log. The caller is a
    /// live netmap application that has just verified this exact chain.
    pub fn store_group_policy_log(
        &self,
        group_id: &str,
        log: &str,
        captured_at_unix: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT OR REPLACE INTO offline_group_policy_log \
                 (group_id, log, captured_at_unix) VALUES (?1, ?2, ?3)",
                rusqlite::params![group_id, log, captured_at_unix],
            )?;
            Ok(())
        })
    }

    /// Drops one group's stored log -- what a snapshot that failed
    /// verification or the rollback watermark leaves behind, so a restart
    /// does not fall back on a chain this device has stopped trusting.
    pub fn forget_group_policy_log(&self, group_id: &str) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM offline_group_policy_log WHERE group_id = ?1", [group_id])?;
            Ok(())
        })
    }

    /// Drops every stored log. For signing out or being unregistered, where
    /// nothing about this device's groups should outlive the account
    /// relationship that produced it.
    pub fn forget_all_group_policy_logs(&self) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM offline_group_policy_log", [])?;
            Ok(())
        })
    }
}
