#![cfg(test)]

use super::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use yadorilink_replica_domain::recovery::RecoveryDomain;

/// The credential a lookup now carries. These tests drive the
/// pre-cutover plane's opaque token, which is the one shape a string can
/// still express.
fn test_auth() -> yadorilink_fapi_client::CoordinationAuth {
    yadorilink_fapi_client::test_support::offline_auth()
}

fn key(domain: RecoveryDomain, operation_id: &str) -> RecoveryOperationKey {
    RecoveryOperationKey { domain, operation_id: operation_id.to_string() }
}

/// A `RecoveryEvidenceSource` implementor, by construction, has no
/// method that could mutate anything -- there is no "mutation call
/// count" to even track for a fake built against this trait, since the
/// trait itself has no such method to fake. This isn't asserted at
/// runtime; it's a property of the trait's own shape, exercised here
/// simply by implementing it with a fake that could not add a mutation
/// method even if it wanted to influence a diagnosis result.
struct FakeEvidenceSource;
impl RecoveryEvidenceSource for FakeEvidenceSource {
    async fn lookup_enrollment(
        &self,
        _key: &RecoveryOperationKey,
    ) -> RemoteEvidence<EnrollmentOperationRecord> {
        RemoteEvidence::RecordNotFound
    }
    async fn lookup_membership(
        &self,
        _key: &RecoveryOperationKey,
    ) -> RemoteEvidence<MembershipOperationRecord> {
        RemoteEvidence::RecordNotFound
    }
    async fn lookup_role_loss(
        &self,
        _key: &RecoveryOperationKey,
    ) -> RemoteEvidence<RoleLossOperationRecord> {
        RemoteEvidence::RecordNotFound
    }
}

#[tokio::test]
async fn fake_evidence_source_compiles_with_only_the_three_read_methods() {
    let fake = FakeEvidenceSource;
    assert!(matches!(
        fake.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await,
        RemoteEvidence::RecordNotFound
    ));
}

#[tokio::test]
async fn enrollment_lookup_a_404_is_record_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(evidence, RemoteEvidence::RecordNotFound));
}

#[tokio::test]
async fn enrollment_lookup_a_5xx_is_unavailable_server_error_never_absent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::ServerError }
    ));
}

#[tokio::test]
async fn enrollment_lookup_a_401_is_unavailable_unauthorized_never_absent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unauthorized }
    ));
}

#[tokio::test]
async fn enrollment_lookup_a_403_is_also_unavailable_unauthorized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unauthorized }
    ));
}

#[tokio::test]
async fn enrollment_lookup_a_malformed_2xx_body_is_unavailable_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::MalformedResponse }
    ));
}

/// A well-formed but unrecognized `status` (e.g. a newer Worker deploy
/// this build predates) is `Unsupported`, NOT `MalformedResponse` --
/// the JSON itself parses fine; only the semantic value is unknown.
#[tokio::test]
async fn enrollment_lookup_an_unknown_status_is_unavailable_unsupported_not_malformed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "kind": "create",
            "status": "from-the-future",
            "requestFingerprint": "fp-1",
            "request": { "userId": "user-1", "groupName": "photos", "deviceId": "device-a" },
            "result": null,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
    ));
}

/// Same distinction for a well-formed but unrecognized role-loss
/// `action`.
#[tokio::test]
async fn role_loss_lookup_an_unknown_action_is_unavailable_unsupported_not_malformed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/role-loss-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "groupId": "group-1",
            "sourceDeviceId": "device-a",
            "targetDeviceId": "device-b",
            "leaseId": null,
            "action": "teleport",
            "membershipGeneration": 1,
            "committedAt": 1_700_000_000,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
    ));
}

#[tokio::test]
async fn enrollment_lookup_a_network_error_is_unavailable_network_never_absent() {
    // No mock mounted, no server listening at this address at all --
    // the connection itself must fail, not merely 404.
    let auth = test_auth();
    let source = WorkerEvidenceSource::new("http://127.0.0.1:1", &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Network }
    ));
}

#[tokio::test]
async fn enrollment_lookup_a_timeout_is_unavailable_timeout_never_absent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(3600)))
        .mount(&server)
        .await;
    // A short-timeout `WorkerEvidenceSource` stands in for `new()`'s own
    // 10s bound -- waiting the real 10s in a unit test is undesirable --
    // but this exercises the ACTUAL `lookup_enrollment` call end to end,
    // not just `categorize_transport_error` in isolation against a
    // hand-built `reqwest::Error`.
    let addr = server.uri();
    let auth = test_auth();
    let source =
        WorkerEvidenceSource::with_timeout(&addr, &auth, std::time::Duration::from_millis(50));

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Timeout }
    ));
}

#[tokio::test]
async fn enrollment_lookup_a_valid_create_record_is_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "kind": "create",
            "status": "active",
            "requestFingerprint": "fp-1",
            "request": { "userId": "user-1", "groupName": "photos", "deviceId": "device-a" },
            "result": { "groupId": "group-1", "state": "active" },
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    let RemoteEvidence::Found(record) = evidence else {
        panic!("expected Found, got {evidence:?}");
    };
    assert_eq!(record.status, coordination_client::EnrollmentRemoteStatus::Active);
    assert_eq!(record.request_fingerprint, "fp-1");
    assert_eq!(
        record.request,
        coordination_client::EnrollmentRemoteRequest::Create {
            group_name: "photos".to_string(),
            device_id: "device-a".to_string(),
            storage_mode: "eager".to_string(),
        }
    );
    assert_eq!(record.result_group_id.as_deref(), Some("group-1"));
}

#[tokio::test]
async fn enrollment_lookup_a_valid_join_record_reads_the_real_storage_mode() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-2",
            "kind": "join",
            "status": "prepared",
            "requestFingerprint": "fp-2",
            "request": {
                "userId": "user-1",
                "groupId": "group-1",
                "deviceId": "device-b",
                "storageMode": "on-demand",
            },
            "result": null,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-2")).await;
    let RemoteEvidence::Found(record) = evidence else {
        panic!("expected Found, got {evidence:?}");
    };
    assert_eq!(record.status, coordination_client::EnrollmentRemoteStatus::Prepared);
    assert_eq!(
        record.request,
        coordination_client::EnrollmentRemoteRequest::Join {
            group_id: "group-1".to_string(),
            device_id: "device-b".to_string(),
            storage_mode: "on-demand".to_string(),
        }
    );
    assert_eq!(record.result_group_id, None);
}

#[tokio::test]
async fn membership_lookup_a_404_is_record_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/membership-operations/op-1"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
    assert!(matches!(evidence, RemoteEvidence::RecordNotFound));
}

#[tokio::test]
async fn membership_lookup_a_5xx_is_unavailable_never_absent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/membership-operations/op-1"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::ServerError }
    ));
}

#[tokio::test]
async fn membership_lookup_a_committed_revoke_is_found_with_its_full_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/membership-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "status": "committed",
            "action": "revoke",
            "removedDeviceId": "device-a",
            "requestFingerprint": "fp-1",
            "request": {
                "userId": "user-1",
                "action": "revoke",
                "removedDeviceId": "device-a",
                "mode": "guarded",
                "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
            },
            "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
            "rejectionCode": null,
            "rejectionDetail": null,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
    let RemoteEvidence::Found(record) = evidence else {
        panic!("expected Found, got {evidence:?}");
    };
    assert_eq!(record.status, coordination_client::MembershipRemoteStatus::Committed);
    assert_eq!(record.request.groups.len(), 1);
    assert_eq!(record.request.groups[0].group_id, "group-1");
}

/// An approved removal that has not finished is reported as `removal-pending`:
/// neither a final outcome nor an unknown status. It stays unresolved
/// (`Unavailable`), in its own category, so the caller retries the same
/// operation id instead of reading it as rejected or as a newer Worker.
#[tokio::test]
async fn membership_lookup_a_removal_pending_status_is_unavailable_pending() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/membership-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "status": "removal-pending",
            "action": "remove-device",
            "removedDeviceId": "device-a",
            "requestFingerprint": "fp-1",
            "request": {
                "userId": "user-1",
                "action": "remove-device",
                "removedDeviceId": "device-a",
                "mode": "plain",
                "groups": [],
            },
            "result": null,
            "rejectionCode": null,
            "rejectionDetail": null,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Pending }
    ));
}

#[tokio::test]
async fn role_loss_lookup_a_404_is_record_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/role-loss-operations/op-1"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
    assert!(matches!(evidence, RemoteEvidence::RecordNotFound));
}

#[tokio::test]
async fn role_loss_lookup_a_5xx_is_unavailable_never_absent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/role-loss-operations/op-1"))
        .respond_with(ResponseTemplate::new(502))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::ServerError }
    ));
}

#[tokio::test]
async fn role_loss_lookup_a_valid_receipt_is_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/role-loss-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "groupId": "group-1",
            "sourceDeviceId": "device-a",
            "targetDeviceId": "device-b",
            "leaseId": "lease-1",
            "action": "demote",
            "membershipGeneration": 4,
            "committedAt": 1_700_000_000,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
    let RemoteEvidence::Found(record) = evidence else {
        panic!("expected Found, got {evidence:?}");
    };
    assert_eq!(record.group_id, "group-1");
    assert_eq!(record.source_device_id, "device-a");
    assert_eq!(record.target_device_id, "device-b");
    assert_eq!(record.lease_id.as_deref(), Some("lease-1"));
    assert_eq!(record.action, "demote");
    assert_eq!(record.membership_generation, 4);
    assert_eq!(record.committed_at_unix, 1_700_000_000);
}

/// A response body naming a different operation id than the one
/// requested breaks the endpoint's own contract -- this is
/// `MalformedResponse`, not a local-vs-remote identity question the
/// diagnosis engine handles.
#[tokio::test]
async fn enrollment_lookup_operation_id_mismatch_is_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-other",
            "kind": "create",
            "status": "active",
            "requestFingerprint": "fp-1",
            "request": { "userId": "user-1", "groupName": "photos", "deviceId": "device-a" },
            "result": { "groupId": "group-1", "state": "active" },
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::MalformedResponse }
    ));
}

#[tokio::test]
async fn membership_lookup_operation_id_mismatch_is_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/membership-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-other",
            "status": "committed",
            "action": "revoke",
            "removedDeviceId": "device-a",
            "requestFingerprint": "fp-1",
            "request": {
                "userId": "user-1",
                "action": "revoke",
                "removedDeviceId": "device-a",
                "mode": "guarded",
                "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
            },
            "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
            "rejectionCode": null,
            "rejectionDetail": null,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::MalformedResponse }
    ));
}

#[tokio::test]
async fn role_loss_lookup_operation_id_mismatch_is_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/role-loss-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-other",
            "groupId": "group-1",
            "sourceDeviceId": "device-a",
            "targetDeviceId": "device-b",
            "leaseId": "lease-1",
            "action": "demote",
            "membershipGeneration": 4,
            "committedAt": 1_700_000_000,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::MalformedResponse }
    ));
}

/// A receipt whose `membershipGeneration` is NULL is a shape this build
/// does not recognize -- generation 8's column is `NOT NULL`, so a NULL
/// value here can only mean a pre-generation-8 row or a malformed
/// deploy, never a legitimately absent generation. Must never be
/// silently treated as generation 0.
#[tokio::test]
async fn role_loss_lookup_a_null_generation_is_unsupported_never_a_fabricated_zero() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/role-loss-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "groupId": "group-1",
            "sourceDeviceId": "device-a",
            "targetDeviceId": "device-b",
            "leaseId": null,
            "action": "demote",
            "membershipGeneration": null,
            "committedAt": 1_700_000_000,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
    ));
}

/// A `join` response naming a storage mode outside the known wire set
/// (`"eager"`/`"on-demand"`) is `Unsupported`, not a shape violation.
#[tokio::test]
async fn enrollment_lookup_an_unknown_join_storage_mode_is_unsupported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/enrollment-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "kind": "join",
            "status": "prepared",
            "requestFingerprint": "fp-1",
            "request": {
                "userId": "user-1",
                "groupId": "group-1",
                "deviceId": "device-b",
                "storageMode": "quantum",
            },
            "result": null,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
    ));
}

/// An unrecognized `mode` value is `Unsupported`, checked independently
/// of `action`.
#[tokio::test]
async fn membership_lookup_an_unknown_mode_is_unsupported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/membership-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "status": "committed",
            "action": "revoke",
            "removedDeviceId": "device-a",
            "requestFingerprint": "fp-1",
            "request": {
                "userId": "user-1",
                "action": "revoke",
                "removedDeviceId": "device-a",
                "mode": "telepathic",
                "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
            },
            "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
            "rejectionCode": null,
            "rejectionDetail": null,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
    ));
}

/// The top-level `action` and `request.action` are independently
/// decoded fields naming the same request -- disagreement between them
/// is the response contradicting itself, `MalformedResponse`, not an
/// unrecognized value.
#[tokio::test]
async fn membership_lookup_action_mismatch_between_top_level_and_request_is_malformed_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/membership-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "status": "committed",
            "action": "revoke",
            "removedDeviceId": "device-a",
            "requestFingerprint": "fp-1",
            "request": {
                "userId": "user-1",
                "action": "remove-device",
                "removedDeviceId": "device-a",
                "mode": "guarded",
                "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
            },
            "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
            "rejectionCode": null,
            "rejectionDetail": null,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::MalformedResponse }
    ));
}

#[tokio::test]
async fn membership_lookup_removed_device_mismatch_between_top_level_and_request_is_malformed_response(
) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices/membership-operations/op-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "operationId": "op-1",
            "status": "committed",
            "action": "revoke",
            "removedDeviceId": "device-a",
            "requestFingerprint": "fp-1",
            "request": {
                "userId": "user-1",
                "action": "revoke",
                "removedDeviceId": "device-z",
                "mode": "guarded",
                "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
            },
            "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
            "rejectionCode": null,
            "rejectionDetail": null,
        })))
        .mount(&server)
        .await;
    let addr = server.uri();
    let auth = test_auth();
    let source = WorkerEvidenceSource::new(&addr, &auth);

    let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
    assert!(matches!(
        evidence,
        RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::MalformedResponse }
    ));
}
