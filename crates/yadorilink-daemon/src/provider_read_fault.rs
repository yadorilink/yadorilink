//! Test support: makes one repository read fail, and later succeed again.
//!
//! A column the read selects is renamed, so the statement no longer prepares (a read error, not an
//! empty answer) while the data stays intact; renaming it back is the recovery.

use std::sync::Arc;

use yadorilink_replica_domain::session_state::ProviderKind;
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::replica_coordinator::ReplicaCoordinator;

pub(crate) const GROUP: &str = "group-a";

/// A coordinator with one declared provider root; returns it with the root id.
pub(crate) fn declared_root() -> (Arc<ReplicaCoordinator>, String) {
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/provider/p", GROUP).unwrap();
    let root = coordinator
        .provider_repository()
        .declare_root(GROUP, ProviderKind::MacFileProvider, "P")
        .unwrap();
    (coordinator, root)
}

fn rename(coordinator: &ReplicaCoordinator, table: &str, from: &str, to: &str) {
    // The schema change needs every statement on the table finished, and the driver under test is
    // reading it concurrently: a table lock held by one of its reads is a reason to try again, not
    // to fail the test (it failed on a slower host).
    let mut last = None;
    for _ in 0..100 {
        let renamed = coordinator.database().write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute_batch(&format!("ALTER TABLE {table} RENAME COLUMN {from} TO {to}"))?;
            Ok(())
        });
        match renamed {
            Ok(()) => return,
            Err(error) => last = Some(error),
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("could not rename {table}.{from}: {:?}", last.unwrap());
}

/// Reads of `table.column` fail until the returned guard's `restore` runs.
pub(crate) struct Fault<'a> {
    coordinator: &'a ReplicaCoordinator,
    table: &'static str,
    column: &'static str,
}

impl<'a> Fault<'a> {
    pub(crate) fn inject(
        coordinator: &'a ReplicaCoordinator,
        table: &'static str,
        column: &'static str,
    ) -> Self {
        rename(coordinator, table, column, "broken_for_test");
        Self { coordinator, table, column }
    }

    pub(crate) fn restore(self) {
        rename(self.coordinator, self.table, "broken_for_test", self.column);
    }
}
