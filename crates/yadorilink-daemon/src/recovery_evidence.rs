//! Read-only remote-evidence lookups the daemon uses to
//! diagnose a stuck local recovery-journal operation against the
//! coordination plane's own durable state.
//!
//! This module is strictly read-only, structurally: [`RecoveryEvidenceSource`]
//! carries no mutation method at all. A diagnosis engine (`crate::recovery_diagnosis`)
//! built only against this trait cannot retry, cancel, or otherwise change
//! coordination-plane state no matter what it concludes -- write-side
//! resolution needs a separate capability entirely, not an
//! extension of this one.

use crate::coordination_client::{
    self, EnrollmentOperationRecord, MembershipOperationLookup, MembershipOperationRecord,
    RemoteEvidenceErrorCategory, RemoteQueryError, RoleLossOperationRecord,
};
use crate::recovery::RecoveryOperationKey;

/// The outcome of a single remote-evidence lookup.
///
/// `RecordNotFound` means ONLY that no durable operation record was
/// returned for this operation id at lookup time (a genuine HTTP 404). It
/// does NOT prove that:
/// - the request was definitely rejected;
/// - no historical mutation occurred (a role-loss commit made before
///   `role_loss_operation_receipts` existed leaves no receipt at all, and
///   even after that table exists, an enrollment/membership row whose own
///   endpoint never distinguishes "genuinely rejected" from "never
///   attempted" -- see each Worker route's own doc comment -- looks
///   identical here too);
/// - deleting the local journal, or otherwise treating this operation as
///   resolved, is safe.
///
/// Domain-specific diagnosis (`crate::recovery_diagnosis`) decides whether the same
/// request should be retried or whether additional evidence is required --
/// this type only reports what the lookup itself observed, nothing more.
///
/// The three-way split (as opposed to a plain `Option`) is what makes that
/// downstream diagnosis possible at all: a caller MUST be able to tell "the
/// coordination plane returned nothing for this id" (`RecordNotFound`)
/// apart from "the coordination plane could not be asked right now"
/// (`Unavailable`) -- collapsing the two, as an early draft of the
/// `role_loss_operation_receipts` write path itself briefly did in reverse
/// (treating a post-hoc state re-check as proof of success -- see that
/// fix's own doc comment in the coordination service), is
/// exactly the class of bug this type exists to make impossible to write
/// by accident: nothing in this enum can be constructed by silently
/// downgrading `Unavailable` into `RecordNotFound`.
#[derive(Debug, Clone)]
pub enum RemoteEvidence<T> {
    Found(T),
    RecordNotFound,
    Unavailable { category: RemoteEvidenceErrorCategory },
}

fn from_lookup<T>(result: Result<Option<T>, RemoteQueryError>) -> RemoteEvidence<T> {
    match result {
        Ok(Some(value)) => RemoteEvidence::Found(value),
        Ok(None) => RemoteEvidence::RecordNotFound,
        Err(error) => RemoteEvidence::Unavailable { category: error.category },
    }
}

/// Read-only remote-evidence source for recovery diagnosis. See this
/// module's own doc comment for why it carries no mutation method.
pub trait RecoveryEvidenceSource {
    fn lookup_enrollment(
        &self,
        key: &RecoveryOperationKey,
    ) -> impl std::future::Future<Output = RemoteEvidence<EnrollmentOperationRecord>> + Send;

    fn lookup_membership(
        &self,
        key: &RecoveryOperationKey,
    ) -> impl std::future::Future<Output = RemoteEvidence<MembershipOperationRecord>> + Send;

    fn lookup_role_loss(
        &self,
        key: &RecoveryOperationKey,
    ) -> impl std::future::Future<Output = RemoteEvidence<RoleLossOperationRecord>> + Send;
}

/// The real [`RecoveryEvidenceSource`], backed by HTTP calls to the
/// coordination plane via `crate::coordination_client`. Holds its own
/// `reqwest::Client` (rather than each lookup building one internally) so
/// a test can inject a short-timeout client via
/// [`Self::with_timeout`] and exercise a genuine, real `Timeout`
/// classification end to end.
pub struct WorkerEvidenceSource<'a> {
    pub addr: &'a str,
    pub auth: &'a yadorilink_fapi_client::CoordinationAuth,
    client: reqwest::Client,
}

impl<'a> WorkerEvidenceSource<'a> {
    pub fn new(addr: &'a str, auth: &'a yadorilink_fapi_client::CoordinationAuth) -> Self {
        Self::with_timeout(addr, auth, coordination_client::EVIDENCE_LOOKUP_TIMEOUT)
    }

    pub fn with_timeout(
        addr: &'a str,
        auth: &'a yadorilink_fapi_client::CoordinationAuth,
        timeout: std::time::Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("building the recovery-evidence HTTP client");
        WorkerEvidenceSource { addr, auth, client }
    }
}

impl RecoveryEvidenceSource for WorkerEvidenceSource<'_> {
    async fn lookup_enrollment(
        &self,
        key: &RecoveryOperationKey,
    ) -> RemoteEvidence<EnrollmentOperationRecord> {
        from_lookup(
            coordination_client::query_enrollment_operation(
                &self.client,
                self.addr,
                self.auth,
                &key.operation_id,
            )
            .await,
        )
    }

    async fn lookup_membership(
        &self,
        key: &RecoveryOperationKey,
    ) -> RemoteEvidence<MembershipOperationRecord> {
        match coordination_client::query_membership_operation_categorized(
            &self.client,
            self.addr,
            self.auth,
            &key.operation_id,
        )
        .await
        {
            Ok(MembershipOperationLookup::Found(record)) => RemoteEvidence::Found(*record),
            Ok(MembershipOperationLookup::NotFound) => RemoteEvidence::RecordNotFound,
            Err(error) => RemoteEvidence::Unavailable { category: error.category },
        }
    }

    async fn lookup_role_loss(
        &self,
        key: &RecoveryOperationKey,
    ) -> RemoteEvidence<RoleLossOperationRecord> {
        from_lookup(
            coordination_client::query_role_loss_operation(
                &self.client,
                self.addr,
                self.auth,
                &key.operation_id,
            )
            .await,
        )
    }
}

#[cfg(test)]
mod tests;
