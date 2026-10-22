#![cfg(test)]

use crate::recovery::tests::{
    insert_valid_enrollment_op, insert_valid_membership_op, insert_valid_role_loss_op,
};
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::session_state::{
    EnrollmentKind, EnrollmentOperation, EnrollmentOperationState, MembershipCommitMode,
    MembershipDurabilityScope, MembershipOperationAction, MembershipOperationState,
    PendingEnrollment, RoleLossAction, RoleLossOperationParams,
};

#[test]
fn recovery_local_snapshot_enrollment_found_with_exact_link_and_marker() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: Some("group-1".to_string()),
            group_name: None,
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::ActivationPending,
            last_error: None,
            attempts: 1,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();
    state
        .enrollment_repository()
        .add_link_with_pending_enrollment(
            "/home/alice/Photos",
            "group-1",
            &PendingEnrollment {
                operation_id: "op-1".to_string(),
                kind: EnrollmentKind::Create,
                group_id: "group-1".to_string(),
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
            },
        )
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) = snapshot else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
        panic!("expected Enrollment evidence");
    };
    assert_eq!(evidence.operation.operation_id, "op-1");
    assert!(matches!(evidence.link, crate::recovery::LocalObservation::Found(_)));
    assert!(matches!(evidence.pending_marker, crate::recovery::LocalObservation::Found(_)));
}

/// `LocalRecoveryEvidence::summary()` must produce exactly the same
/// `RecoveryOperationSummary` `recovery::inventory()` does for the SAME
/// underlying row -- both now call the identical per-domain helper, so
/// this pins that they can never independently drift.
#[test]
fn recovery_local_snapshot_summary_matches_inventory_summary_for_enrollment() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-1");

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let from_snapshot = evidence.summary();

    let inv = crate::recovery::inventory(&state).unwrap();
    let from_inventory =
        inv.valid.into_iter().find(|op| op.operation_id == "op-1").expect("row in inventory");

    assert_eq!(from_snapshot, from_inventory);
}

#[test]
fn recovery_local_snapshot_summary_matches_inventory_summary_for_membership() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_membership_op(&state, "op-1");

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Membership,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let from_snapshot = evidence.summary();

    let inv = crate::recovery::inventory(&state).unwrap();
    let from_inventory =
        inv.valid.into_iter().find(|op| op.operation_id == "op-1").expect("row in inventory");

    assert_eq!(from_snapshot, from_inventory);
}

#[test]
fn recovery_local_snapshot_summary_matches_inventory_summary_for_role_loss() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_role_loss_op(&state, "op-1");

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::RoleLoss,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let from_snapshot = evidence.summary();

    let inv = crate::recovery::inventory(&state).unwrap();
    let from_inventory =
        inv.valid.into_iter().find(|op| op.operation_id == "op-1").expect("row in inventory");

    assert_eq!(from_snapshot, from_inventory);
}

#[test]
fn recovery_local_snapshot_membership_reports_only_actually_present_latches() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .membership_operation_repository()
        .try_insert_membership_operation(
            "op-1",
            MembershipOperationAction::RemoveDevice,
            MembershipCommitMode::HandoffRemoveDevice,
            "device-b",
            &["g1".to_string(), "g2".to_string()],
            &["device-x".to_string(), "device-y".to_string()],
            &[Some("lease-1".to_string()), Some("lease-2".to_string())],
            MembershipOperationState::Prepared,
            MembershipDurabilityScope::Known,
            &["g2".to_string(), "g3".to_string()],
            None,
            1,
        )
        .unwrap();
    state.role_loss_operation_repository().latch_group_durability_unknown("g2").unwrap();
    state.role_loss_operation_repository().latch_group_durability_unknown("g3").unwrap();
    // g1 is a candidate (it's in operation.group_ids) but deliberately
    // left unlatched -- must NOT appear in present_durability_latches.

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Membership,
        operation_id: "op-1".to_string(),
    };
    let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) = snapshot else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::Membership(evidence) = *evidence else {
        panic!("expected Membership evidence");
    };
    assert_eq!(evidence.present_durability_latches, vec!["g2".to_string(), "g3".to_string()]);
}

#[test]
fn recovery_local_snapshot_role_loss_found_with_exact_link() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    state
        .role_loss_operation_repository()
        .insert_role_loss_operation(
            "op-1",
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

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::RoleLoss,
        operation_id: "op-1".to_string(),
    };
    let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) = snapshot else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::RoleLoss(evidence) = *evidence else {
        panic!("expected RoleLoss evidence");
    };
    assert!(matches!(evidence.link, crate::recovery::LocalObservation::Found(_)));
}

#[test]
fn recovery_local_snapshot_reports_operation_not_found() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "does-not-exist".to_string(),
    };
    let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
    assert!(matches!(snapshot, crate::recovery::RecoveryLocalSnapshot::OperationNotFound { .. }));
}

#[test]
fn recovery_local_snapshot_reports_invalid_operation_for_a_malformed_row() {
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
             VALUES ('op-malformed', 'create', 'group-1', NULL, 'device-a', '/tmp/broken', \
                'eager', 'from-the-future', NULL, 0, 1, 1)",
            [],
        )
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-malformed".to_string(),
    };
    let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
    let crate::recovery::RecoveryLocalSnapshot::InvalidOperation { raw_state, .. } = snapshot
    else {
        panic!("expected InvalidOperation, got {snapshot:?}");
    };
    assert_eq!(raw_state.as_deref(), Some("from-the-future"));
}

/// `EnrollmentOperation::storage_mode` on a Create row records the
/// CALLER's own requested local materialization mode
/// (`CreateAndLinkCommand::on_demand`, see
/// `EnrollmentService::create_and_link`) -- a completely different
/// concept from the remote creator edge's own always-"eager" wire
/// construction. A Create row legitimately requesting on-demand local
/// materialization must decode as `Found`, never `InvalidOperation`.
#[test]
fn recovery_local_snapshot_accepts_an_on_demand_create_row_as_valid() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: None,
            group_name: Some("photos".to_string()),
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "on-demand".to_string(),
            state: EnrollmentOperationState::PreparePending,
            last_error: None,
            attempts: 0,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let snapshot = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();
    assert!(
        matches!(snapshot, crate::recovery::RecoveryLocalSnapshot::Found(_)),
        "expected Found, got {snapshot:?}"
    );
}

#[test]
fn recovery_local_snapshot_propagates_a_genuine_db_read_failure() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute_batch("DROP TABLE enrollment_operations")
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let result = state.recovery_snapshot_reader().recovery_local_snapshot(&key);
    assert!(
        result.is_err(),
        "a genuine DB read failure must propagate as an error, never as an empty/absent result"
    );
}

#[test]
fn recovery_local_snapshot_resolves_by_domain_even_when_the_same_id_exists_in_all_three_tables() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-shared");
    insert_valid_membership_op(&state, "op-shared");
    insert_valid_role_loss_op(&state, "op-shared");

    let enrollment_key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-shared".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&enrollment_key).unwrap()
    else {
        panic!("expected Found for enrollment domain");
    };
    assert!(matches!(*evidence, crate::recovery::LocalRecoveryEvidence::Enrollment(_)));

    let membership_key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Membership,
        operation_id: "op-shared".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&membership_key).unwrap()
    else {
        panic!("expected Found for membership domain");
    };
    assert!(matches!(*evidence, crate::recovery::LocalRecoveryEvidence::Membership(_)));

    let role_loss_key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::RoleLoss,
        operation_id: "op-shared".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&role_loss_key).unwrap()
    else {
        panic!("expected Found for role-loss domain");
    };
    assert!(matches!(*evidence, crate::recovery::LocalRecoveryEvidence::RoleLoss(_)));
}

#[test]
fn recovery_local_snapshot_keeps_a_marker_whose_operation_id_matches_but_other_fields_dont() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: Some("group-1".to_string()),
            group_name: None,
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::ActivationPending,
            last_error: None,
            attempts: 1,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();
    // A marker under the SAME operation_id but naming a DIFFERENT
    // group/device/path -- the snapshot must not filter this out or treat it
    // specially; spotting the mismatch is the diagnosis layer's own
    // identity-qualification job, not this snapshot's.
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "INSERT INTO pending_enrollments \
                (operation_id, kind, group_id, device_id, local_path) \
             VALUES ('op-1', 'create', 'group-DIFFERENT', 'device-DIFFERENT', '/tmp/other')",
            [],
        )
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
        panic!("expected Enrollment evidence");
    };
    let crate::recovery::LocalObservation::Found(marker) = evidence.pending_marker else {
        panic!("expected the mismatched marker to still be Found, not filtered");
    };
    assert_eq!(marker.group_id, "group-DIFFERENT");
}

#[test]
fn recovery_local_snapshot_surfaces_a_link_whose_group_id_conflicts_with_the_operation() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    // A link genuinely exists at this operation's local_path, but under
    // a DIFFERENT group_id than the operation itself names -- this must
    // be surfaced as Found (with its own, conflicting group_id), never
    // filtered into ConfirmedAbsent. Hiding it would hide exactly the
    // identity conflict a diagnosis classifier most
    // needs to see.
    state.link_repository().add_link("/home/alice/Photos", "group-CONFLICTING").unwrap();
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: Some("group-1".to_string()),
            group_name: None,
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::ActivationPending,
            last_error: None,
            attempts: 1,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
        panic!("expected Enrollment evidence");
    };
    let crate::recovery::LocalObservation::Found(link) = evidence.link else {
        panic!("expected the conflicting link to still be Found, not filtered");
    };
    assert_eq!(link.group_id, "group-CONFLICTING");
}

#[test]
fn recovery_local_snapshot_role_loss_multiple_link_candidates_is_ambiguous() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    // A DB-level constraint refuses two LIVE links for the same
    // group_id (see `insert_link_row`'s own `AmbiguousLink` guard, now
    // also enforced at the SQLite layer), so real ambiguity here can
    // only arise from an orphaned row left behind at an old path
    // alongside a live link at a new one -- both still name group-1.
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "INSERT INTO links (local_path, group_id, orphaned) \
             VALUES ('/home/alice/Photos-old', 'group-1', 1)",
            [],
        )
        .unwrap();
    state.link_repository().add_link("/home/alice/Photos-new", "group-1").unwrap();
    state
        .role_loss_operation_repository()
        .insert_role_loss_operation(
            "op-1",
            "group-1",
            RoleLossOperationParams {
                source_device_id: "device-c",
                target_device_id: "device-d",
                lease_id: "lease-fixture",
                action: RoleLossAction::Demote,
                local_path: None,
                now_unix: 1,
            },
        )
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::RoleLoss,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::RoleLoss(evidence) = *evidence else {
        panic!("expected RoleLoss evidence");
    };
    assert!(matches!(evidence.link, crate::recovery::LocalObservation::Ambiguous { .. }));
}

#[test]
fn recovery_local_snapshot_reports_invalid_for_a_malformed_pending_marker() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: Some("group-1".to_string()),
            group_name: None,
            device_id: "device-a".to_string(),
            local_path: "/home/alice/Photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::ActivationPending,
            last_error: None,
            attempts: 1,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "INSERT INTO pending_enrollments \
                (operation_id, kind, group_id, device_id, local_path) \
             VALUES ('op-1', 'not-a-kind', 'group-1', 'device-a', '/home/alice/Photos')",
            [],
        )
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
        panic!("expected Enrollment evidence");
    };
    assert!(matches!(evidence.pending_marker, crate::recovery::LocalObservation::Invalid { .. }));
}

#[test]
fn recovery_local_snapshot_reports_confirmed_absent_when_no_link_or_marker_exists() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-1");

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
        panic!("expected Enrollment evidence");
    };
    assert!(matches!(evidence.link, crate::recovery::LocalObservation::ConfirmedAbsent));
    assert!(matches!(evidence.pending_marker, crate::recovery::LocalObservation::ConfirmedAbsent));
}

#[test]
fn recovery_local_snapshot_enrollment_surfaces_a_link_at_its_path_even_with_no_group_id_yet() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    // A Create row still PreparePending has no group_id yet, but its
    // own local_path might already be occupied by an EXISTING link
    // belonging to a different group entirely -- the snapshot must still
    // surface it, not silently skip the lookup because group_id is
    // still None.
    state.link_repository().add_link("/data/photos", "group-existing").unwrap();
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: None,
            group_name: Some("photos".to_string()),
            device_id: "device-a".to_string(),
            local_path: "/data/photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::PreparePending,
            last_error: None,
            attempts: 0,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
        panic!("expected Enrollment evidence");
    };
    let crate::recovery::LocalObservation::Found(link) = evidence.link else {
        panic!("expected the pre-existing link to still be Found, not skipped");
    };
    assert_eq!(link.group_id, "group-existing");
}

#[test]
fn recovery_local_snapshot_enrollment_confirmed_absent_when_group_id_is_none_and_no_link_exists() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .enrollment_repository()
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: "op-1".to_string(),
            kind: EnrollmentKind::Create,
            group_id: None,
            group_name: Some("photos".to_string()),
            device_id: "device-a".to_string(),
            local_path: "/data/photos".to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::PreparePending,
            last_error: None,
            attempts: 0,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
        panic!("expected Enrollment evidence");
    };
    assert!(matches!(evidence.link, crate::recovery::LocalObservation::ConfirmedAbsent));
}

#[test]
fn recovery_local_snapshot_reports_invalid_for_a_malformed_link_row() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-1");
    state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .execute(
            "INSERT INTO links (local_path, group_id, materialization_policy) \
             VALUES ('/home/alice/Photos', 'group-1', 'not-a-real-policy')",
            [],
        )
        .unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(evidence) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };
    let crate::recovery::LocalRecoveryEvidence::Enrollment(evidence) = *evidence else {
        panic!("expected Enrollment evidence");
    };
    assert!(matches!(evidence.link, crate::recovery::LocalObservation::Invalid { .. }));
}

#[test]
fn recovery_local_snapshot_enrollment_link_lookup_propagates_a_genuine_db_read_failure() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-1");
    state.database().pool_for_test().get().unwrap().execute_batch("DROP TABLE links").unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let result = state.recovery_snapshot_reader().recovery_local_snapshot(&key);
    assert!(
        result.is_err(),
        "a genuine `links` read failure must propagate as an error, never as Invalid or \
         ConfirmedAbsent"
    );
}

#[test]
fn recovery_local_snapshot_role_loss_group_link_lookup_propagates_a_genuine_db_read_failure() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state
        .role_loss_operation_repository()
        .insert_role_loss_operation(
            "op-1",
            "group-1",
            RoleLossOperationParams {
                source_device_id: "device-c",
                target_device_id: "device-d",
                lease_id: "lease-fixture",
                action: RoleLossAction::Demote,
                local_path: None,
                now_unix: 1,
            },
        )
        .unwrap();
    state.database().pool_for_test().get().unwrap().execute_batch("DROP TABLE links").unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::RoleLoss,
        operation_id: "op-1".to_string(),
    };
    let result = state.recovery_snapshot_reader().recovery_local_snapshot(&key);
    assert!(
        result.is_err(),
        "a genuine `links` read failure must propagate as an error, never as Invalid or \
         ConfirmedAbsent"
    );
}

#[test]
fn recovery_local_snapshot_is_read_only() {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_enrollment_op(&state, "op-1");
    state
        .enrollment_repository()
        .add_link_with_pending_enrollment(
            "/home/alice/Photos",
            "group-1",
            &PendingEnrollment {
                operation_id: "op-1".to_string(),
                kind: EnrollmentKind::Create,
                group_id: "group-1".to_string(),
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
            },
        )
        .unwrap();

    let before_op = state.enrollment_repository().get_enrollment_operation("op-1").unwrap();
    let before_links = state.link_repository().list_links().unwrap();
    let before_markers = state.enrollment_repository().list_pending_enrollments().unwrap();

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Enrollment,
        operation_id: "op-1".to_string(),
    };
    let _ = state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap();

    assert_eq!(before_op, state.enrollment_repository().get_enrollment_operation("op-1").unwrap());
    assert_eq!(before_links, state.link_repository().list_links().unwrap());
    assert_eq!(before_markers, state.enrollment_repository().list_pending_enrollments().unwrap());
}

/// Proves the exact SQLite property `recovery_local_snapshot` depends on:
/// once a `Deferred` transaction has executed its first read, later
/// reads in the SAME transaction see the database as of that first
/// read, even if another connection commits a write in between (WAL's
/// readers-never-blocked-by-writers guarantee). An implementation that
/// read the operation row and its related rows through separate pool
/// checkouts (losing this fixed snapshot) would not have this property.
#[test]
fn deferred_read_transaction_snapshot_is_isolated_from_a_concurrent_commit() {
    let dir = tempfile::tempdir().unwrap();
    let state = ReplicaCoordinator::open(dir.path().join("state.db")).unwrap();
    state.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();

    let mut conn_a = state.database().pool_for_test().get().unwrap();
    let tx_a = conn_a.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred).unwrap();
    let paused_before: i64 = tx_a
        .query_row("SELECT paused FROM links WHERE local_path = ?1", ["/home/alice/Photos"], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(paused_before, 0);

    // A DIFFERENT connection commits a write while tx_a is still open.
    let conn_b = state.database().pool_for_test().get().unwrap();
    conn_b
        .execute("UPDATE links SET paused = 1 WHERE local_path = ?1", ["/home/alice/Photos"])
        .unwrap();
    drop(conn_b);

    // tx_a must still observe the state as of its own first read.
    let paused_during: i64 = tx_a
        .query_row("SELECT paused FROM links WHERE local_path = ?1", ["/home/alice/Photos"], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        paused_during, 0,
        "a Deferred transaction must keep its snapshot fixed across a concurrent commit"
    );
    tx_a.commit().unwrap();

    // A FRESH transaction now sees the committed write.
    let paused_after: i64 = state
        .database()
        .pool_for_test()
        .get()
        .unwrap()
        .query_row("SELECT paused FROM links WHERE local_path = ?1", ["/home/alice/Photos"], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(paused_after, 1);
}

/// The operation row's own `state`/`updated_at_unix` can stay UNCHANGED
/// while related evidence (here: a durability latch) changes -- the
/// revision must still change, or the stable-diagnosis service's stale-snapshot
/// re-check would miss it and combine stale local evidence with fresh
/// remote evidence.
#[test]
fn recovery_local_snapshot_revision_changes_when_a_related_latch_changes_but_the_operation_row_does_not(
) {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    insert_valid_membership_op(&state, "op-1");

    let key = crate::recovery::RecoveryOperationKey {
        domain: crate::recovery::RecoveryDomain::Membership,
        operation_id: "op-1".to_string(),
    };
    let crate::recovery::RecoveryLocalSnapshot::Found(before) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };

    // Latches this group -- the operation row itself is untouched.
    state.role_loss_operation_repository().latch_group_durability_unknown("group-1").unwrap();

    let crate::recovery::RecoveryLocalSnapshot::Found(after) =
        state.recovery_snapshot_reader().recovery_local_snapshot(&key).unwrap()
    else {
        panic!("expected Found");
    };

    assert_eq!(
        before.revision().state,
        after.revision().state,
        "sanity: the operation row's own state must be unchanged by this test"
    );
    assert_ne!(
        before.revision(),
        after.revision(),
        "a related-evidence change (here: a new durability latch) must change the revision \
         even though the operation row's own state/updated_at_unix did not"
    );
}
