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

/// Two groups, each answered in 5 s (inside the 8 s a new connection gets per group): the sweep
/// takes 10 s and both answers count. A limit on the whole sweep read this as silence.
#[tokio::test(start_paused = true)]
async fn a_slow_multi_group_sweep_is_not_read_as_a_silent_peer() {
    let started = tokio::time::Instant::now();
    let groups = vec![FolderGroupId("g1".into()), FolderGroupId("g2".into())];
    let rounds = sweep(groups, |_| async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        GroupRound::InSync
    })
    .await;
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert_eq!(rounds.len(), 2);
    assert!(rounds.iter().all(|(_, round)| !round.connection_is_dead()));
}

/// A fault on this side (database, request construction) or a refusal is not the connection's
/// fault; only a peer that did not answer is.
#[test]
fn only_a_silent_peer_means_the_connection_is_dead() {
    assert!(GroupRound::NoAnswer.connection_is_dead());
    for round in [
        GroupRound::Failed,
        GroupRound::InSync,
        GroupRound::Divergent,
        GroupRound::Requested { newer: 1 },
        GroupRound::Refused(RefusalReason::Unauthorized),
    ] {
        assert!(!round.connection_is_dead(), "{round:?}");
    }
}
