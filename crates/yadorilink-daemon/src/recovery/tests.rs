#![cfg(test)]

use super::*;
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::session_state::{
    EnrollmentKind, MembershipCommitMode, MembershipDurabilityScope, MembershipOperationAction,
    RoleLossAction, RoleLossOperationParams,
};

pub(crate) fn insert_valid_enrollment_op(state: &ReplicaCoordinator, operation_id: &str) {
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: operation_id.to_string(),
            kind: EnrollmentKind::Create,
            group_id: Some("group-1".to_string()),
            group_name: None,
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::ActivationPending,
            last_error: None,
            attempts: 2,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();
}

pub(crate) fn insert_valid_membership_op(state: &ReplicaCoordinator, operation_id: &str) {
    state
        .membership_operation_repository()
        .try_insert_membership_operation(
            operation_id,
            MembershipOperationAction::Revoke,
            MembershipCommitMode::PlainRevoke,
            "device-b",
            &["group-1".to_string()],
            &[],
            &[],
            MembershipOperationState::Prepared,
            MembershipDurabilityScope::Known,
            &[],
            None,
            1,
        )
        .unwrap();
}

pub(crate) fn insert_valid_role_loss_op(state: &ReplicaCoordinator, operation_id: &str) {
    state
        .role_loss_operation_repository()
        .insert_role_loss_operation(
            operation_id,
            "group-1",
            RoleLossOperationParams {
                source_device_id: "device-c",
                target_device_id: "device-d",
                lease_id: "lease-fixture",
                action: RoleLossAction::Demote,
                local_path: Some("/home/alice/Photos"),
                now_unix: 1,
            },
        )
        .unwrap();
}

#[test]
fn recovery_inventory_lists_enrollment_membership_and_role_loss_together() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-enroll");
    insert_valid_membership_op(&state, "op-membership");
    insert_valid_role_loss_op(&state, "op-role-loss");

    let inv = crate::recovery::inventory(&state).unwrap();

    assert!(inv.invalid.is_empty());
    assert_eq!(inv.valid.len(), 3);
    let domains: std::collections::HashSet<_> = inv.valid.iter().map(|op| op.domain).collect();
    assert!(domains.contains(&crate::recovery::RecoveryDomain::Enrollment));
    assert!(domains.contains(&crate::recovery::RecoveryDomain::Membership));
    assert!(domains.contains(&crate::recovery::RecoveryDomain::RoleLoss));
}

#[test]
fn recovery_inventory_shows_recovery_blocked_rows_that_the_open_scan_excludes() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-blocked".to_string(),
            kind: EnrollmentKind::Create,
            group_id: None,
            group_name: Some("photos".to_string()),
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::RecoveryBlocked,
            last_error: Some("identity mismatch".to_string()),
            attempts: 1,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();

    // The ordinary reconciliation scan must still exclude it...
    let open_scan = state.enrollment_repository().scan_open_enrollment_operations().unwrap();
    assert!(open_scan.valid.is_empty(), "reconciliation must never see a blocked row");

    // ...but the inventory must show it, with Blocked severity.
    let inv = crate::recovery::inventory(&state).unwrap();
    assert_eq!(inv.valid.len(), 1);
    assert_eq!(inv.valid[0].operation_id, "op-blocked");
    assert_eq!(inv.valid[0].severity, crate::recovery::RecoverySeverity::Blocked);
}

#[test]
fn recovery_inventory_isolates_an_unknown_state_string_into_invalid() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-1");
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "INSERT INTO enrollment_operations \
                (operation_id, kind, group_id, group_name, device_id, local_path, \
                 storage_mode, state, last_error, attempts, created_at_unix, updated_at_unix) \
             VALUES ('op-malformed', 'create', 'group-1', NULL, 'device-a', '/tmp/broken', \
                'eager', 'from-the-future', NULL, 0, 1, 1)",
            [],
        )
        .unwrap();

    let inv = crate::recovery::inventory(&state).unwrap();

    assert_eq!(inv.valid.len(), 1);
    assert_eq!(inv.valid[0].operation_id, "op-1");
    assert_eq!(inv.invalid.len(), 1);
    assert_eq!(inv.invalid[0].operation_id.as_deref(), Some("op-malformed"));
    assert_eq!(inv.invalid[0].domain, crate::recovery::RecoveryDomain::Enrollment);
    assert_eq!(
        inv.invalid[0].raw_state.as_deref(),
        Some("from-the-future"),
        "the exact persisted state must survive even when it fails to decode, so \
         `recovery show` can display it"
    );
}

/// A membership row with an unknown `state` string must be reported as
/// `invalid`, not silently dropped -- `scan_membership_operations_in_states`'s
/// `WHERE state IN (...)` allow-list would match none of its bound
/// placeholders and simply omit such a row from BOTH `valid` and
/// `invalid`, which is why the inventory uses `scan_all_membership_operations`
/// (no state filter) instead.
#[test]
fn recovery_inventory_isolates_an_unknown_membership_state_into_invalid() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-1");
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "INSERT INTO membership_operations \
                (operation_id, action, commit_mode, removed_device_id, group_ids, \
                 target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                 last_error, created_at_unix, updated_at_unix) \
             VALUES ('op-future-state', 'revoke', 'plain-revoke', 'device-b', '[\"group-1\"]', \
                '[]', '[]', 'from-the-future', 'known', '[]', NULL, 1, 1)",
            [],
        )
        .unwrap();

    let inv = crate::recovery::inventory(&state).unwrap();

    assert!(inv.valid.iter().any(|op| op.operation_id == "op-1"));
    assert_eq!(inv.invalid.len(), 1);
    assert_eq!(inv.invalid[0].operation_id.as_deref(), Some("op-future-state"));
    assert_eq!(inv.invalid[0].domain, crate::recovery::RecoveryDomain::Membership);
}

#[test]
fn recovery_inventory_isolates_a_malformed_json_array_into_invalid() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_role_loss_op(&state, "op-good");
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "INSERT INTO membership_operations \
                (operation_id, action, commit_mode, removed_device_id, group_ids, \
                 target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                 last_error, created_at_unix, updated_at_unix) \
             VALUES ('op-malformed-json', 'revoke', 'plain-revoke', 'device-b', \
                'not-a-json-array', '[]', '[]', 'prepared', 'known', '[]', NULL, 1, 1)",
            [],
        )
        .unwrap();

    let inv = crate::recovery::inventory(&state).unwrap();

    // The role-loss row (a different domain) is unaffected...
    assert!(inv.valid.iter().any(|op| op.operation_id == "op-good"));
    // ...and the malformed membership row is isolated, not silently dropped.
    assert_eq!(inv.invalid.len(), 1);
    assert_eq!(inv.invalid[0].operation_id.as_deref(), Some("op-malformed-json"));
    assert_eq!(inv.invalid[0].domain, crate::recovery::RecoveryDomain::Membership);
}

/// A row whose `operation_id` column is not TEXT at all (corruption, or
/// a manual repair gone wrong -- a BLOB here) must still be isolated
/// into `invalid` with `operation_id: None`, never abort the whole
/// inventory. `row.get::<_, String>(0)?` -- the naive read this replaced
/// -- would return early on such a row, failing the ENTIRE `inventory()`
/// call and hiding every other, perfectly healthy operation in every
/// domain behind it.
#[test]
fn recovery_inventory_isolates_a_non_text_operation_id_into_invalid() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-1");
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "INSERT INTO membership_operations \
                (operation_id, action, commit_mode, removed_device_id, group_ids, \
                 target_device_ids, lease_ids, state, durability_scope, latch_group_ids, \
                 last_error, created_at_unix, updated_at_unix) \
             VALUES (X'80FF', 'revoke', 'plain-revoke', 'device-b', '[]', '[]', '[]', \
                'prepared', 'known', '[]', NULL, 1, 1)",
            [],
        )
        .unwrap();

    let inv = crate::recovery::inventory(&state).unwrap();

    assert!(
        inv.valid.iter().any(|op| op.operation_id == "op-1"),
        "a sibling row in a different domain must still be reported"
    );
    assert_eq!(inv.invalid.len(), 1);
    assert_eq!(inv.invalid[0].operation_id, None);
    assert_eq!(inv.invalid[0].domain, crate::recovery::RecoveryDomain::Membership);
}

/// Negative `attempts` is corruption, not a legitimate value -- the wire
/// conversion (`recovery_summary_to_proto`) must never receive one to
/// silently clamp to zero; the row must be isolated as `invalid` before
/// it ever reaches that conversion.
#[test]
fn recovery_inventory_isolates_negative_attempts_into_invalid() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "INSERT INTO enrollment_operations \
                (operation_id, kind, group_id, group_name, device_id, local_path, \
                 storage_mode, state, last_error, attempts, created_at_unix, updated_at_unix) \
             VALUES ('op-negative-attempts', 'create', 'group-1', NULL, 'device-a', \
                '/tmp/broken', 'eager', 'activation_pending', NULL, -1, 1, 1)",
            [],
        )
        .unwrap();

    let inv = crate::recovery::inventory(&state).unwrap();

    assert_eq!(inv.valid.len(), 0);
    assert_eq!(inv.invalid.len(), 1);
    assert_eq!(inv.invalid[0].operation_id.as_deref(), Some("op-negative-attempts"));
    assert!(inv.invalid[0].detail.contains("negative"), "detail was: {}", inv.invalid[0].detail);
}

#[test]
fn recovery_inventory_does_not_convert_a_db_read_failure_into_an_empty_list() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-1");
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute("DROP TABLE role_loss_operations", [])
        .unwrap();

    let result = crate::recovery::inventory(&state);

    assert!(
        result.is_err(),
        "a genuine DB read failure must propagate as an error, never as an empty inventory"
    );
}

#[test]
fn recovery_inventory_is_read_only() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-enroll");
    insert_valid_membership_op(&state, "op-membership");
    insert_valid_role_loss_op(&state, "op-role-loss");

    let before_enrollment =
        state.enrollment_repository().scan_all_enrollment_operations().unwrap().valid;
    let before_membership =
        state.membership_operation_repository().scan_all_membership_operations().unwrap().valid;
    let before_role_loss =
        state.role_loss_operation_repository().scan_all_role_loss_operations().unwrap().valid;

    let _ = crate::recovery::inventory(&state).unwrap();

    let after_enrollment =
        state.enrollment_repository().scan_all_enrollment_operations().unwrap().valid;
    let after_membership =
        state.membership_operation_repository().scan_all_membership_operations().unwrap().valid;
    let after_role_loss =
        state.role_loss_operation_repository().scan_all_role_loss_operations().unwrap().valid;

    assert_eq!(before_enrollment, after_enrollment);
    assert_eq!(before_membership, after_membership);
    assert_eq!(before_role_loss, after_role_loss);
}
