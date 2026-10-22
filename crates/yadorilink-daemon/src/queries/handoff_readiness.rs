//! `CheckFullReplicaHandoffReady`/`CheckFullReplicaHandoffReadyExcluding`'s
//! read model -- strictly read-only pre-checks (see
//! `full_replica_handoff_not_ready_excluding`'s original doc comment: the
//! authoritative, fail-closed re-check happens again inside
//! `SetStorageMode`/`RemoveDeviceCommand`'s own commit path; this is only
//! ever a UI-facing hint).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::sync_error::SyncError;

pub(crate) type BoxFutureAlias<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub(crate) trait HandoffReadinessPort: Send + Sync {
    fn ready<'a>(&'a self, group_id: &'a str) -> BoxFutureAlias<'a, bool>;

    /// The subset of `group_id` (or, when `group_id` is empty, every
    /// group this daemon has a local link for) that is NOT yet
    /// handoff-ready once `excluded_device_id` is excluded from counting
    /// as the confirming replica -- see the original doc comment on this
    /// exact semantics ("partial view, not a distributed proof").
    fn not_ready_excluding<'a>(
        &'a self,
        group_id: &'a str,
        excluded_device_id: &'a str,
    ) -> BoxFutureAlias<'a, Result<Vec<String>, SyncError>>;
}

pub(crate) struct HandoffReadinessQueryService {
    port: Arc<dyn HandoffReadinessPort>,
}

impl HandoffReadinessQueryService {
    pub(crate) fn new(port: Arc<dyn HandoffReadinessPort>) -> Self {
        Self { port }
    }

    pub(crate) async fn ready(&self, group_id: &str) -> bool {
        self.port.ready(group_id).await
    }

    pub(crate) async fn not_ready_excluding(
        &self,
        group_id: &str,
        excluded_device_id: &str,
    ) -> Result<Vec<String>, SyncError> {
        self.port.not_ready_excluding(group_id, excluded_device_id).await
    }
}
