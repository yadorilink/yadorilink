//! `RecoveryJob` -- the one owner of every crash-recovery journal sweep
//! this daemon runs: this device's own role loss (demote/unlink),
//! unknown-scope and ambiguous membership operations, and interrupted
//! create/join enrollments. `async`, unlike `RetentionExpiryJob`: each
//! sweep makes coordination-plane HTTP calls.
//!
//! Holds the application services that own each recovery workflow, never
//! the daemon state itself: what a sweep does lives in
//! `ReplicaRoleService`, `ReplicaMembershipService` and
//! `EnrollmentRecoveryService`, the same instances a control-socket
//! command reaches, so a crash-recovery pass and a live command cannot
//! diverge. `maintenance_coordinator` owns WHEN the membership sweeps run
//! and `app.rs` owns WHEN the enrollment sweep runs (it needs the
//! coordination-plane config recorded first).

use std::sync::Arc;

use crate::application::{
    ApplicationServices, EnrollmentRecoveryService, ReplicaMembershipService, ReplicaRoleService,
};

pub(crate) struct RecoveryJob {
    replica_role: Arc<ReplicaRoleService>,
    membership: Arc<ReplicaMembershipService>,
    enrollment_recovery: Arc<EnrollmentRecoveryService>,
}

impl RecoveryJob {
    pub(crate) fn new(application: &ApplicationServices) -> Self {
        Self {
            replica_role: application.replica_role.clone(),
            membership: application.membership.clone(),
            enrollment_recovery: application.enrollment_recovery.clone(),
        }
    }

    /// One pass over every membership-related recovery journal: role loss
    /// first, then unknown-scope device removals, then ambiguous
    /// ticket-bound revoke/remove commits.
    pub(crate) async fn run_membership_recovery_once(&self) {
        self.replica_role.reconcile_role_loss().await;
        self.membership.reconcile_unknown_scope().await;
        self.membership.reconcile_ambiguous().await;
    }

    /// One pass over the create/join enrollment journal and its
    /// unconfirmed-activation markers.
    pub(crate) async fn run_enrollment_recovery_once(&self) {
        self.enrollment_recovery.reconcile_once().await;
    }
}
