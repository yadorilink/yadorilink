#![cfg(test)]

use super::*;

#[test]
fn every_request_kind_round_trips() {
    let requests = [
        ServiceRequest::HandoffLease { group_id: "g".into() },
        ServiceRequest::HandoffTicket { group_id: "g".into() },
        ServiceRequest::HandoffLeaseRelease { group_id: "g".into(), lease_id: "lease-1".into() },
        ServiceRequest::HandoffTicketRelease {
            group_id: "g".into(),
            target_device_id: "device-b".into(),
            lease_id: "lease-1".into(),
        },
    ];
    for request in requests {
        assert_eq!(decode_request(&encode_request(&request)).unwrap(), request);
        // And every one is refused at every truncation, not just the
        // shortest: a partial field must never decode as a shorter one.
        let encoded = encode_request(&request);
        for cut in 0..encoded.len() {
            assert!(decode_request(&encoded[..cut]).is_err(), "{request:?} cut to {cut}");
        }
    }
}

#[test]
fn every_response_kind_round_trips() {
    let responses = [
        ServiceResponse::HandoffLease { grant: None },
        ServiceResponse::HandoffLease {
            grant: Some(LeaseGrant {
                lease_id: "lease-1".into(),
                root_digest: [7u8; 32],
                expires_at_unix: -1,
                ttl_seconds: 900,
            }),
        },
        ServiceResponse::HandoffTicket { grant: None },
        ServiceResponse::HandoffTicket {
            grant: Some(TicketGrant {
                lease_id: "lease-1".into(),
                expires_at_unix: i64::MAX,
                target_device_id: "device-b".into(),
            }),
        },
        ServiceResponse::Released,
        ServiceResponse::ReleaseNotConfirmed,
    ];
    for response in responses {
        assert_eq!(decode_response(&encode_response(&response)).unwrap(), response);
    }
}

/// Every request names the group it is scoped to, because that is what the
/// answering side authorizes against — per request, from live membership.
/// A kind that could not name its group would be a kind that could not be
/// authorized.
#[test]
fn every_request_kind_names_its_group() {
    let requests = [
        ServiceRequest::VersionPresent {
            group_id: "g".into(),
            file_path: "f".into(),
            version_hash: VersionHash([0u8; 32]),
            blocks: Vec::new(),
            for_handoff: false,
        },
        ServiceRequest::HandoffLease { group_id: "g".into() },
        ServiceRequest::HandoffTicket { group_id: "g".into() },
        ServiceRequest::HandoffLeaseRelease { group_id: "g".into(), lease_id: "l".into() },
        ServiceRequest::HandoffTicketRelease {
            group_id: "g".into(),
            target_device_id: "d".into(),
            lease_id: "l".into(),
        },
    ];
    for request in requests {
        assert_eq!(request.group_id(), "g");
    }
}
