#![cfg(test)]

use prost::Message;

use crate::daemonctl::daemon_control_request::Payload as ReqPayload;
use crate::daemonctl::{
    create_and_link_command_response, daemon_control_response, remove_device_command_response,
    CreateAndLinkCommandRequest, CreateAndLinkCommandResponse, DaemonControlRequest,
    DaemonControlResponse, EnrollmentCommandOutcome, MembershipHandoffResult,
    RemoveDeviceCommandRequest, RemoveDeviceCommandResponse, ReplicaMembershipCommandOutcome,
    StatusRequest,
};

/// A request built by a current CLI carries `protocol_version ==
/// CONTROL_PROTOCOL_VERSION` alongside its payload, and both round-trip
/// through encode/decode untouched by each other — the top-level version
/// field and the `oneof payload` are independent.
#[test]
fn current_daemon_control_request_round_trips_protocol_version_and_payload() {
    let req = DaemonControlRequest {
        payload: Some(ReqPayload::Status(StatusRequest {})),
        protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let decoded = DaemonControlRequest::decode(req.encode_to_vec().as_slice()).unwrap();

    assert_eq!(decoded.protocol_version, crate::daemonctl::CONTROL_PROTOCOL_VERSION);
    assert!(matches!(decoded.payload, Some(ReqPayload::Status(_))));
}

#[test]
fn high_level_membership_command_round_trips() {
    let request = DaemonControlRequest {
        payload: Some(ReqPayload::RemoveDeviceCommand(RemoveDeviceCommandRequest {
            device_id: "device-b".into(),
            force: true,
        })),
        protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let decoded = DaemonControlRequest::decode(request.encode_to_vec().as_slice()).unwrap();
    assert!(matches!(decoded.payload, Some(ReqPayload::RemoveDeviceCommand(_))));

    let response = DaemonControlResponse {
        payload: Some(daemon_control_response::Payload::RemoveDeviceCommand(
            RemoveDeviceCommandResponse {
                result: Some(remove_device_command_response::Result::Outcome(
                    ReplicaMembershipCommandOutcome {
                        handoffs: vec![MembershipHandoffResult {
                            group_id: "group-1".into(),
                            target_device_id: "device-c".into(),
                            lease_id: "lease-1".into(),
                            membership_generation: 2,
                        }],
                        forced_group_ids: Vec::new(),
                        unknown_scope_operation_id: String::new(),
                    },
                )),
            },
        )),
        daemon_protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let decoded = DaemonControlResponse::decode(response.encode_to_vec().as_slice()).unwrap();
    assert!(matches!(
        decoded.payload,
        Some(daemon_control_response::Payload::RemoveDeviceCommand(_))
    ));
}

#[test]
fn high_level_enrollment_command_round_trips() {
    let request = DaemonControlRequest {
        payload: Some(ReqPayload::CreateAndLinkCommand(CreateAndLinkCommandRequest {
            group_name: "documents".into(),
            local_path: "/tmp/documents".into(),
            on_demand: false,
            acknowledge_risks: true,
            provider_display_name: String::new(),
            request_token: String::new(),
            create_local_path_if_missing: false,
        })),
        protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let decoded = DaemonControlRequest::decode(request.encode_to_vec().as_slice()).unwrap();
    assert!(matches!(decoded.payload, Some(ReqPayload::CreateAndLinkCommand(_))));

    let response = DaemonControlResponse {
        payload: Some(daemon_control_response::Payload::CreateAndLinkCommand(
            CreateAndLinkCommandResponse {
                result: Some(create_and_link_command_response::Result::Outcome(
                    EnrollmentCommandOutcome {
                        operation_id: "operation-1".into(),
                        group_id: "group-1".into(),
                        local_path: "/tmp/documents".into(),
                        // Create has no approval step; only a
                        // cross-account invite acceptance ever sets it.
                        awaiting_approval: false,
                        already_linked: false,
                        provider_root_id: String::new(),
                    },
                )),
            },
        )),
        daemon_protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
    };
    let decoded = DaemonControlResponse::decode(response.encode_to_vec().as_slice()).unwrap();
    assert!(matches!(
        decoded.payload,
        Some(daemon_control_response::Payload::CreateAndLinkCommand(_))
    ));
}

/// The shell and control wires carry two independent facts per path; the one
/// derived word is built from them, and an absent state is never "current".
#[test]
fn local_state_words_come_from_the_two_facts() {
    use crate::daemonctl::{local_state_word, LocalState, LocalTransition};
    let state = |object, current, transition: LocalTransition| LocalState {
        local_object_present: object,
        current_content_present: current,
        transition: transition as i32,
    };
    assert_eq!(local_state_word(None), "unknown");
    assert_eq!(local_state_word(Some(&state(false, false, LocalTransition::None))), "remote");
    assert_eq!(local_state_word(Some(&state(true, false, LocalTransition::None))), "local-stale");
    assert_eq!(local_state_word(Some(&state(true, true, LocalTransition::None))), "local-current");
    assert_eq!(
        local_state_word(Some(&state(false, false, LocalTransition::Hydrating))),
        "hydrating"
    );
    assert_eq!(local_state_word(Some(&state(true, false, LocalTransition::Evicting))), "evicting");
}

/// The new shell message decodes back to the same two facts, and a message
/// without it decodes as unknown, not as "current".
#[test]
fn shell_status_response_round_trips_the_two_facts() {
    use crate::shellipc::{LocalState, LocalTransition, StatusResponse};
    let sent = StatusResponse {
        path: "/x".into(),
        local_state: Some(LocalState {
            local_object_present: true,
            current_content_present: false,
            transition: LocalTransition::None as i32,
        }),
        ..Default::default()
    };
    let got = StatusResponse::decode(sent.encode_to_vec().as_slice()).unwrap();
    let local = got.local_state.expect("local_state survives the wire");
    assert!(local.local_object_present);
    assert!(!local.current_content_present);
    let bare =
        StatusResponse::decode(StatusResponse::default().encode_to_vec().as_slice()).unwrap();
    assert!(bare.local_state.is_none());
}

/// `ProviderFolder.read_only` survives the wire, and a folder from an older daemon (field absent)
/// decodes as writable.
#[test]
fn provider_folder_read_only_round_trips_and_defaults_to_writable() {
    use crate::shellipc::ProviderFolder;
    let sent =
        ProviderFolder { display_name: "Docs".into(), read_only: true, ..Default::default() };
    assert!(ProviderFolder::decode(sent.encode_to_vec().as_slice()).unwrap().read_only);
    let old = ProviderFolder { display_name: "Docs".into(), ..Default::default() };
    assert!(!ProviderFolder::decode(old.encode_to_vec().as_slice()).unwrap().read_only);
}
