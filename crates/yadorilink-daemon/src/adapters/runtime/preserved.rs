//! `DaemonState`-backed [`PreservedPort`].

use std::sync::Arc;

use crate::application::ports::common::BoxFuture;
use crate::application::ports::preserved::PreservedPort;
use crate::daemon_state::DaemonState;
use crate::preserved_items::{self, PreservedError, PreservedItem, PreservedSummary, RetainedItem};
use yadorilink_sync_sqlite::native_rebootstrap_retained::RetainedOutcome;

pub(crate) struct DaemonPreservedAdapter {
    state: Arc<DaemonState>,
}

impl DaemonPreservedAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl PreservedPort for DaemonPreservedAdapter {
    fn list(&self) -> BoxFuture<'_, Result<Vec<PreservedItem>, PreservedError>> {
        Box::pin(async move { preserved_items::list(&self.state).await })
    }

    fn restore(
        &self,
        group_id: String,
        item_id: String,
    ) -> BoxFuture<'_, Result<(), PreservedError>> {
        Box::pin(async move { preserved_items::restore(&self.state, &group_id, &item_id).await })
    }

    fn retry(
        &self,
        group_id: String,
        item_id: String,
    ) -> BoxFuture<'_, Result<(), PreservedError>> {
        Box::pin(async move { preserved_items::retry(&self.state, &group_id, &item_id).await })
    }

    fn discard(
        &self,
        group_id: String,
        item_id: String,
    ) -> BoxFuture<'_, Result<(), PreservedError>> {
        Box::pin(async move { preserved_items::discard(&self.state, &group_id, &item_id).await })
    }

    fn list_retained(&self) -> BoxFuture<'_, Result<Vec<RetainedItem>, PreservedError>> {
        Box::pin(async move { preserved_items::list_retained(&self.state).await })
    }

    fn release_retained(
        &self,
        group_id: String,
    ) -> BoxFuture<'_, Result<Vec<(String, RetainedOutcome)>, PreservedError>> {
        Box::pin(async move { preserved_items::release_retained(&self.state, &group_id).await })
    }

    fn summary(&self) -> PreservedSummary {
        preserved_items::summary(&self.state)
    }

    fn undecided_uploads(&self) -> (u64, u64) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        self.state
            .replica_coordinator
            .provider_repository()
            .undecided_uploads(now_ms)
            .unwrap_or((0, 0))
    }

    fn rebootstrapping_groups(&self) -> Vec<String> {
        preserved_items::rebootstrapping_groups(&self.state)
    }
}
