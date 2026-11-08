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

/// A refused recovery ask comes back after a backoff that doubles with each refusal in a row: not
/// at once (every ask made the peer load its whole state with the writer gate held), and not after
/// the whole cooldown (what made the peer unable to seal can end in seconds).
#[test]
fn a_refused_recovery_ask_is_retried_after_a_doubling_backoff() {
    let state = RecoveryState::default();
    let group = FolderGroupId("g".into());
    let back_date = |seconds: u64| {
        let mut asked = state.asked.lock().unwrap();
        let at = asked.get_mut(&group.0).expect("asked");
        *at = at.checked_sub(Duration::from_secs(seconds)).unwrap();
    };
    for (round, wait) in [(1u32, 5u64), (2, 10), (3, 20), (4, 40), (5, 60), (6, 60)] {
        let id = state.begin(&group).unwrap_or_else(|| panic!("round {round}: may ask"));
        state.refused(id);
        assert!(state.begin(&group).is_none(), "round {round}: asked again at once");
        back_date(wait - 1);
        assert!(state.begin(&group).is_none(), "round {round}: asked before {wait} s");
        back_date(1);
        // The ask made here is the next round's.
        let again = state.begin(&group);
        assert!(again.is_some(), "round {round}: not asked after {wait} s");
        state.abandon(again.unwrap());
        // `abandon` (an ask that never got an answer) leaves the count; make the next round's
        // refusal follow from a clean `asked`.
        state.asked.lock().unwrap().remove(&group.0);
    }
}

mod peer_progress {
    use std::sync::Arc;

    use yadorilink_local_storage::SegmentBlockStore;
    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId};
    use yadorilink_replica_domain::protocol5::{self, FrontierEntry, Message};

    use crate::daemon_state::DaemonState;
    use crate::native_replication_runtime::env_for_peer;
    use crate::replica_coordinator::ReplicaCoordinator;

    const ME: &str = "device-a";

    /// The folder group and peer a test uses. Every test gets its own: the order in which requests
    /// of one peer are recorded is kept in process-wide state keyed by (group, peer), so two tests
    /// that share both names, running side by side, can make each other's later write look stale and
    /// get it dropped (the figure then stays where the other test left it, for ever).
    struct Ids {
        group: String,
        peer: String,
    }

    fn ids() -> Ids {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ids { group: format!("group-{n}"), peer: format!("device-b-{n}") }
    }

    fn state() -> Arc<DaemonState> {
        let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        DaemonState::new(ME.into(), sync_state, store)
    }

    fn entry(device: &str, incarnation: u8, seq: u64) -> FrontierEntry {
        FrontierEntry {
            author: AuthorId {
                device: DeviceId(device.into()),
                incarnation: IncarnationId([incarnation; 16]),
            },
            seq: AuthorSeq(seq),
            tip: None,
        }
    }

    fn request(ids: &Ids, since: Vec<FrontierEntry>) -> Vec<u8> {
        protocol5::encode_message(&Message::FrontierDiffRequest {
            request_id: protocol5::RequestId([7; 16]),
            group_id: FolderGroupId(ids.group.clone()),
            since,
        })
        .unwrap()
    }

    fn pending(state: &DaemonState, ids: &Ids) -> u64 {
        state
            .replica_coordinator
            .database()
            .read(|conn| {
                yadorilink_sync_sqlite::peer_progress::pending_own_deltas(conn, &ids.group, ME)
            })
            .unwrap()
    }

    /// The count once it reaches `want`: the figure is stored off the answering thread, on the
    /// blocking pool and behind the writer gate, so under load it can take well over a second.
    /// The wait ends as soon as the figure arrives; the bound only limits a failing run.
    async fn pending_settles_at(state: &DaemonState, ids: &Ids, want: u64) -> u64 {
        for _ in 0..3000 {
            if pending(state, ids) == want {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        pending(state, ids)
    }

    #[tokio::test]
    async fn a_frontier_request_records_how_much_of_my_history_the_peer_holds() {
        let state = state();
        let ids = ids();
        let mut env = env_for_peer(&state, &ids.peer);
        env.shares_group = Arc::new(|_| true);
        env.db
            .write(|conn| {
                conn.execute(
                    "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
                     VALUES (?1, ?2, ?3, 6)",
                    rusqlite::params![ids.group, ME, [1u8; 16].as_slice()],
                )?;
                Ok::<(), yadorilink_sync_sqlite::SyncSqliteError>(())
            })
            .unwrap();
        assert_eq!(pending(&state, &ids), 6);

        // The peer names 4 of my 6 changes and 90 of someone else's.
        env.answer(&request(&ids, vec![entry(ME, 1, 4), entry("device-c", 1, 90)])).unwrap();
        assert_eq!(pending_settles_at(&state, &ids, 2).await, 2);

        // Naming all of them clears the count.
        env.answer(&request(&ids, vec![entry(ME, 1, 6)])).unwrap();
        assert_eq!(pending_settles_at(&state, &ids, 0).await, 0);
    }

    #[tokio::test]
    async fn a_peer_cannot_inflate_its_progress_by_repeating_an_author_or_naming_huge_values() {
        let state = state();
        let ids = ids();
        let mut env = env_for_peer(&state, &ids.peer);
        env.shares_group = Arc::new(|_| true);
        env.db
            .write(|conn| {
                conn.execute(
                    "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
                     VALUES (?1, ?2, ?3, 10)",
                    rusqlite::params![ids.group, ME, [1u8; 16].as_slice()],
                )?;
                Ok::<(), yadorilink_sync_sqlite::SyncSqliteError>(())
            })
            .unwrap();
        // The same author twice counts once: 5 of 10, not 10.
        env.answer(&request(&ids, vec![entry(ME, 1, 5), entry(ME, 1, 5)])).unwrap();
        assert_eq!(pending_settles_at(&state, &ids, 5).await, 5);
        // Values near the top of u64 neither panic nor wrap into a negative figure.
        env.answer(&request(&ids, vec![entry(ME, 1, u64::MAX), entry(ME, 2, u64::MAX)])).unwrap();
        assert_eq!(pending_settles_at(&state, &ids, 0).await, 0);
    }

    #[tokio::test]
    async fn a_request_for_a_group_not_shared_with_the_peer_records_nothing() {
        let state = state();
        let ids = ids();
        let mut env = env_for_peer(&state, &ids.peer);
        env.shares_group = Arc::new(|_| false);
        env.db
            .write(|conn| {
                conn.execute(
                    "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
                     VALUES (?1, ?2, ?3, 6)",
                    rusqlite::params![ids.group, ME, [1u8; 16].as_slice()],
                )?;
                Ok::<(), yadorilink_sync_sqlite::SyncSqliteError>(())
            })
            .unwrap();
        env.answer(&request(&ids, vec![entry(ME, 1, 6)])).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(pending(&state, &ids), 6);
    }
}
