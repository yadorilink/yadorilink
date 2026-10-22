#![cfg(test)]

use super::*;

fn a_request() -> ServiceRequest {
    ServiceRequest::VersionPresent {
        group_id: "g".into(),
        file_path: "dir/report.pdf".into(),
        version_hash: VersionHash([9u8; 32]),
        blocks: vec![
            VersionBlock { hash: BlockHash(vec![1u8; 32]), size: 4096 },
            VersionBlock { hash: BlockHash(vec![2u8; 32]), size: 17 },
        ],
        for_handoff: true,
    }
}

#[test]
fn a_request_round_trips() {
    assert_eq!(decode_request(&encode_request(&a_request())).unwrap(), a_request());
}

#[test]
fn a_response_round_trips() {
    for present in [true, false] {
        let response = ServiceResponse::VersionPresent { present };
        assert_eq!(decode_response(&encode_response(&response)).unwrap(), response);
    }
}

#[test]
fn custody_messages_round_trip_and_reject_every_truncation() {
    let requests = [
        ServiceRequest::CustodyAcquire {
            group_id: "g".into(),
            file_path: "dir/a.bin".into(),
            version_hash: VersionHash([4u8; 32]),
            blocks: vec![VersionBlock { hash: BlockHash(vec![3u8; 32]), size: 9 }],
            membership_generation: 77,
            attempt_token: [6u8; 16],
        },
        ServiceRequest::CustodyRelease {
            group_id: "g".into(),
            file_path: "dir/a.bin".into(),
            version_hash: VersionHash([4u8; 32]),
            attempt_token: [6u8; 16],
        },
        ServiceRequest::CustodyRehome {
            group_id: "g".into(),
            file_path: "dir/a.bin".into(),
            version_hash: VersionHash([4u8; 32]),
            attempt_token: [6u8; 16],
        },
    ];
    for request in requests {
        let encoded = encode_request(&request);
        assert_eq!(decode_request(&encoded).unwrap(), request);
        for cut in 0..encoded.len() {
            assert!(decode_request(&encoded[..cut]).is_err());
        }
    }
    for flag in [true, false] {
        for response in [
            ServiceResponse::CustodyAcquire { granted: flag },
            ServiceResponse::CustodyRelease { released: flag },
            ServiceResponse::CustodyRehome { moved: flag },
        ] {
            assert_eq!(decode_response(&encode_response(&response)).unwrap(), response);
        }
    }
}

#[test]
fn a_truncated_request_is_rejected_at_every_offset() {
    let encoded = encode_request(&a_request());
    for cut in 0..encoded.len() {
        assert!(
            decode_request(&encoded[..cut]).is_err(),
            "a request cut to {cut} bytes must not decode"
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut encoded = encode_request(&a_request());
    encoded.push(0);
    assert!(matches!(decode_request(&encoded), Err(ServiceRpcError::TrailingBytes(1))));
}

/// A hostile block count is refused against the bytes actually present,
/// so it never becomes an allocation.
#[test]
fn an_impossible_block_count_is_refused_before_allocating() {
    let mut encoded = vec![RPC_VERSION, KIND_VERSION_PRESENT];
    put_str(&mut encoded, "g");
    put_str(&mut encoded, "f");
    encoded.extend_from_slice(&[0u8; 32]);
    encoded.push(0);
    encoded.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        decode_request(&encoded),
        Err(ServiceRpcError::FieldTooLarge { field: "block count", .. })
    ));

    let mut plausible = encoded[..encoded.len() - 4].to_vec();
    plausible.extend_from_slice(&(MAX_BLOCKS as u32 - 1).to_be_bytes());
    assert!(matches!(decode_request(&plausible), Err(ServiceRpcError::Truncated { .. })));
}

#[test]
fn an_unknown_kind_is_refused_not_guessed() {
    assert!(matches!(
        decode_request(&[RPC_VERSION, 0xEE]),
        Err(ServiceRpcError::UnknownKind(0xEE))
    ));
}

/// Kind 6, a retired request/response, is gone. A peer that still sends it
/// is refused like any other unknown kind, in both directions, rather than
/// answered.
#[test]
fn the_retired_rebootstrap_kind_is_refused_both_ways() {
    let mut request = vec![RPC_VERSION, 6];
    put_str(&mut request, "g");
    request.extend_from_slice(&[0u8; 32]);
    assert!(matches!(decode_request(&request), Err(ServiceRpcError::UnknownKind(6))));
    assert!(matches!(decode_response(&[RPC_VERSION, 6, 0]), Err(ServiceRpcError::UnknownKind(6))));
}

/// Rolling-upgrade contract: a response from a peer on another RPC generation, or of a kind this
/// build does not know, is an error in both directions and never decodes into an answer (least of
/// all a granting one).
#[test]
fn a_response_of_another_generation_or_unknown_kind_never_decodes() {
    let mut granting = encode_response(&ServiceResponse::CustodyAcquire { granted: true });
    for version in [RPC_VERSION - 1, RPC_VERSION + 1] {
        granting[0] = version;
        assert!(matches!(
            decode_response(&granting),
            Err(ServiceRpcError::UnsupportedVersion(v)) if v == version
        ));
        let mut request = encode_request(&a_request());
        request[0] = version;
        assert!(matches!(
            decode_request(&request),
            Err(ServiceRpcError::UnsupportedVersion(v)) if v == version
        ));
    }
    assert!(matches!(
        decode_response(&[RPC_VERSION, 0xEE, 1]),
        Err(ServiceRpcError::UnknownKind(0xEE))
    ));
}
