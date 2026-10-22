use super::*;

#[test]
fn not_found_on_a_delta_range_request_is_a_truncation_without_a_checkpoint() {
    assert_eq!(truncation_from_delta_refusal(&RefusalReason::NotFound), Some(None));
}

#[test]
fn a_named_history_floor_is_a_truncation_with_its_checkpoint() {
    let reason = RefusalReason::HistoryTruncated { checkpoint_id: [3; 32], frontier_root: [4; 32] };
    let note = truncation_from_delta_refusal(&reason).expect("a truncation").expect("a summary");
    assert_eq!((note.checkpoint_id, note.frontier_root), ([3; 32], [4; 32]));
}

#[test]
fn other_refusals_of_a_delta_range_request_say_nothing_about_history() {
    for reason in [RefusalReason::Unauthorized, RefusalReason::Overloaded] {
        assert_eq!(truncation_from_delta_refusal(&reason), None, "{reason:?}");
    }
}

/// A peer that cannot seal its state refuses the request for it with `NotFound`; that is a
/// failed request, never a note that the peer's history was truncated.
#[test]
fn not_found_from_the_checkpoint_seal_path_is_a_refused_request_not_a_truncation() {
    let refusal = protocol5::encode_message(&Message::Refused {
        request_id: protocol5::RequestId([1; 16]),
        reason: RefusalReason::NotFound,
    })
    .unwrap();
    assert!(!recovery_request_accepted(&refusal));
    assert!(recovery_request_accepted(&[]));
}
