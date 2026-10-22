//! Exact-version materialization and hydration over a real peer session.
//!
//! These tests were `yadorilink-peer-session`'s until the executor they drive
//! moved into this crate. Their bodies are unchanged: what moved is ownership,
//! not behavior. The fixture they are built on lives in
//! `test_support::peer_session_fixture`, next to the `ReplicaCoordinator` it
//! is built on.

use yadorilink_daemon::test_support::peer_session_fixture::*;

/// The responder side of the exact-version-hash check, plus the local-path
/// guards that share its fixture shape. Named for a capability bit that no
/// longer exists: the check itself was never optional, and with the
/// negotiation gone it is simply what every responder does.
#[cfg(test)]
mod exact_version_hash_tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_ipc_proto::sync as proto;
    use yadorilink_local_storage::SegmentBlockStore;
    use yadorilink_peer_session::peer_session::PeerSyncSession;
    use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
    use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

    const GROUP: &str = "handoff-group";

    /// This module's own `SessionTransports` fixture -- a required
    /// `PeerSyncSession` constructor parameter now (A3/A4). Every session
    /// this module builds is `"device-b"` talking to `"device-a"`, and
    /// nothing here exercises a real peer response over these transports
    /// (they're either never opened at all, or the module's own
    /// scripted responders answer over their own lane) -- so a fresh,
    /// unshared pair per call is exactly as real as this module needs: a
    /// genuine substrate-backed port, not a stub, just not wired to a
    /// peer that answers anything either.
    async fn new_test_transports() -> yadorilink_peer_session::ports::SessionTransports {
        new_test_transports_with_peer().await.0
    }

    /// Like `new_test_transports`, but also hands back `"device-a"`'s own
    /// `TestPeerNode` -- for a test whose scripted responder plays that
    /// peer for real over the substrate's block lane (`accept_unclaimed_
    /// lane`, the lane counterpart of the raw-channel `accept_block_
    /// stream` these tests used before block requests moved off the
    /// control channel entirely), rather than never needing a peer to
    /// answer anything at all.
    async fn new_test_transports_with_peer() -> (
        yadorilink_peer_session::ports::SessionTransports,
        Arc<yadorilink_lane_ports::testing::TestPeerNode>,
    ) {
        let book = yadorilink_lane_ports::testing::TestAddressBook::new();
        let node_a =
            yadorilink_lane_ports::testing::TestPeerNode::start("device-b", book.clone()).await;
        let node_b = yadorilink_lane_ports::testing::TestPeerNode::start("device-a", book).await;
        let transports = node_a.transports_for("device-a");
        (
            yadorilink_peer_session::ports::SessionTransports {
                blocks: transports.clone(),
                service: transports.clone(),
            },
            node_b,
        )
    }

    /// Claims a sync root for the group, as linking the folder does. Tests that
    /// index a file and then run a scan or repair need this: an unmarked root
    /// whose indexed files are all absent is indistinguishable from an unmounted
    /// volume, and is refused.
    fn adopt_root(state: &ReplicaCoordinator, group: &str, root: &std::path::Path) {
        yadorilink_root_authority::root_identity::VerifiedRoot::open(root, group, state).unwrap();
    }

    async fn new_session(
        state: Arc<ReplicaCoordinator>,
        store: Arc<dyn yadorilink_local_storage::BlockContentStore>,
    ) -> Arc<crate::TestPeerRuntime> {
        let transports = new_test_transports().await;
        {
            let __state = state;
            let __store = store;
            let __roots = HashMap::new();
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        }
    }

    /// A session holding no sync root for a group must refuse to resolve a
    /// local path for it, not fall back to a relative one.
    ///
    /// `new_session` above builds exactly that shape: shared groups, empty
    /// `sync_roots`. With the old empty-path default, `local_file_path` returned
    /// a bare relative `"file.txt"`, so every write for the group landed under
    /// the process's working directory instead of the user's folder — and
    /// `verify_write_target` could not catch it, because its fast path asks
    /// whether the target's parent IS the root, and `""` is trivially the parent
    /// of `"file.txt"`. Both the path and its guard failed open together.
    #[tokio::test]
    async fn missing_sync_root_refuses_to_resolve_a_local_path() {
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().path()).unwrap());
        let session = new_session(state, store).await;

        let resolved = session.convergence.local_file_path(GROUP, "file.txt");
        assert!(
            resolved.is_err(),
            "a group with no sync root must not resolve to a path at all; got {resolved:?}"
        );

        // The write guard must refuse too, rather than waving through a
        // working-directory-relative target.
        let verified =
            session.convergence.verify_write_target(GROUP, std::path::Path::new("file.txt"));
        assert!(
            verified.is_err(),
            "the write-target guard must reject a target it cannot prove is under a known root"
        );
    }

    /// Regression lock on `holds_version_durably`'s behavior: a retained
    /// version whose block
    /// list happens to coincide with the query's (here, because only the
    /// mtime differs) must still be rejected when the queried `version_hash`
    /// does not equal that retained version's actual identity; the exact
    /// matching hash is still accepted; and an absent `version_hash` (a
    /// querier built before that field existed) still fails closed rather
    /// than falling back to a block-hash-only match.
    #[tokio::test]
    async fn holds_version_durably_requires_exact_hash_and_group_provenance() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // `holds_version_durably`'s first condition requires this device be
        // a full replica (Eager materialization policy, the default) of the
        // group.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        let content = b"same bytes, different metadata";
        let hash_hex = store.put(content).unwrap();
        let hash_bytes = hex::decode(hash_hex.as_str()).unwrap();

        let record = FileRecord {
            path: "a.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo {
                hash: hash_bytes.clone(),
                offset: 0,
                size: content.len() as u32,
            }],
            deleted: false,
        };
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let retained = state.sqlite().dag_list_versions(GROUP, "a.bin").unwrap();
        assert_eq!(retained.len(), 1, "the single upsert retains exactly one version");
        let actual_version_hash = retained[0].version_hash.0.to_vec();

        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root)]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store;
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // `DurableVersionQuery` directly -- what a decoded wire
        // `VersionPresent` service request converts into on the real path
        // (`answer_service_request`'s `ServiceRequest::VersionPresent` arm);
        // that wire type is protobuf-free now, so there is no
        // `proto::VersionPresentQuery` to build a starting point from any
        // more.
        let query_with = |version_hash: Vec<u8>| yadorilink_replica_engine::DurableVersionQuery {
            folder_group_id: GROUP.to_string(),
            file_path: "a.bin".to_string(),
            block_hashes: vec![hash_bytes.clone()],
            for_handoff: true,
            version_hash,
            block_sizes: vec![content.len() as u32],
        };

        let mismatched = query_with(vec![0xEEu8; 32]);
        assert!(
            !session.session.replica_engine.holds_version_durably(&mismatched).present,
            "block_hashes matching alone must not satisfy a for_handoff query whose \
             version_hash does not equal the retained version's actual identity"
        );

        let matching = query_with(actual_version_hash);
        assert!(
            !session.session.replica_engine.holds_version_durably(&matching).present,
            "global block presence without this group's provenance must not prove custody"
        );

        state
            .record_block_provenance(GROUP, std::slice::from_ref(&matching.block_hashes[0]))
            .unwrap();
        assert!(
            session.session.replica_engine.holds_version_durably(&matching).present,
            "the retained version's own exact version_hash alongside matching block_hashes/\
             block_sizes and group provenance must be confirmed present"
        );

        let absent_version_hash = query_with(Vec::new());
        assert!(
            !session.session.replica_engine.holds_version_durably(&absent_version_hash).present,
            "an absent version_hash (a querier that predates the field) must still fail closed, \
             not fall back to a block-hash-only match"
        );
    }

    /// Regression (data-loss): the LIVE peer-receive materialize path must
    /// itself journal a durable materialization intent, so a crash *after* it
    /// commits a brand-new `Present` row but *before* the temp-write-then-rename
    /// lands is recovered by reconstructing the file — never misclassified as an
    /// offline delete and tombstoned group-wide.
    ///
    /// This drives the REAL `PeerSyncSession::materialize` eager path for a
    /// brand-new received file and simulates the crash by forcing the
    /// post-upsert disk-headroom preflight to fail: an error injected AFTER the
    /// durable pre-write commit (intent, row, in-flight state, fence bump,
    /// one transaction) but BEFORE the temp file exists, which leaves exactly the
    /// on-disk/index state a real crash-before-rename leaves — a `Present` row,
    /// its blocks present locally, and no file on disk. Crucially it writes NO
    /// intent by hand; the whole point is that `materialize` must have written
    /// it. If the live path wrote no intent, this same state would be read as
    /// an offline delete and the fresh file tombstoned; the test passes only
    /// when the live path journals the intent.
    #[tokio::test]
    async fn live_materialize_crash_before_rename_is_reconstructed_not_deleted() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // Claim the root while the index is still empty, the way linking a
        // folder does. Without it the repair below sees indexed files with no
        // bytes in an unmarked root -- byte-for-byte an unmounted volume -- and
        // correctly refuses to touch it.
        adopt_root(&state, GROUP, &sync_root);

        // The received content is already in this device's block store (the
        // eager fetch completed before the simulated crash), so
        // `ensure_blocks_present` short-circuits with no peer round trip and the
        // reconstruct during repair needs no network.
        let content = b"a freshly received file the crash must not destroy".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();
        // `ensure_blocks_present` only short-circuits a block already in the
        // CAS store when this group also has recorded provenance for it (a
        // physical hit alone might belong to another group) -- production's
        // real fetch path always records this alongside the store write, so
        // seed it here too, or the eager materialize below goes looking for
        // this "missing" block over the (deliberately unreachable) peer
        // channel and blocks for the full 30s hydration timeout instead of
        // exercising the crash-before-rename path this test is about.
        state.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();

        let record = FileRecord {
            path: "doc.txt".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        // A live, started-up link is the only state a real daemon presents to a
        // peer session: `materialize` resolves its write target from the link
        // table on every call, and `wait_group_ready` defers a live link whose
        // startup never registered a gate.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // Force the post-upsert headroom preflight (which runs AFTER the
        // durable row commit and BEFORE the reconstruct-to-disk write) to
        // fail, standing in for a process kill in that exact window. An
        // impossible headroom reserve guarantees `check_disk_headroom` rejects.
        session.convergence.set_headroom_enforced_for_tests(true);
        session.convergence.set_headroom_override_bytes_for_tests(Some(u64::MAX));
        let fence_before = state.dag_snapshot_mutation_fence(GROUP, "doc.txt").unwrap();
        // The path is owed a projection, as an admitted change leaves it.
        state
            .sqlite()
            .dag_bump_projection_obligations_for_touched_paths(GROUP, &["doc.txt"], 0)
            .unwrap();
        let owed = state.sqlite().dag_lookup_projection_obligation(GROUP, "doc.txt").unwrap();

        // Drive the REAL eager materialize path. It must return the injected
        // disk-pressure error, having already committed the row.
        let out_path = sync_root.join("doc.txt");
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(result.is_err(), "the injected preflight failure must surface as an error");

        // The crash-before-rename state, produced entirely by the live path:
        // the row durably committed and marked as a materialization in
        // flight, blocks present, no file on disk — and a materialization
        // intent the live path wrote itself.
        //
        // In flight, NOT `Present`. The bytes do not exist yet, and the
        // row is what a reader would consult; the exact claim belongs to
        // the commit that can prove it, which this window never reaches.
        // What makes the crash recoverable is the intent below, not the
        // state -- which is exactly why the state does not have to lie.
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "doc.txt")
                .unwrap(),
            Some(yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE),
            "the durable row must record a materialization in flight before the crash window"
        );
        assert_ne!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "doc.txt")
                .unwrap(),
            Some(MaterializationState::Present),
            "and must not claim to hold content that was never written"
        );
        assert!(!out_path.exists(), "no file was written before the simulated crash");
        assert!(
            state
                .materialization_intent_repository()
                .has_materialization_intent(GROUP, "doc.txt")
                .unwrap(),
            "the LIVE materialize path must journal a durable intent before committing the \
             brand-new Hydrated row, so a crash in this window is recoverable"
        );
        // The fence the write's proof will CAS on is bumped in the same
        // commit as the intent and the row, so it is durable before the
        // first disk mutation: an edit or capture landing after that commit
        // moves it again and the stale write's proof loses its CAS.
        assert!(
            state.dag_snapshot_mutation_fence(GROUP, "doc.txt").unwrap() > fence_before,
            "the content write's fence bump must be durable before anything touches the disk"
        );

        // Repair (the production plain, no-emitter variant the daemon's startup/
        // periodic sweep runs) must RECONSTRUCT from the present blocks — never
        // classify this as an offline delete.
        let report = yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            state.as_ref(),
            store.as_ref(),
            &sync_root,
            GROUP,
            yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

        assert_eq!(
            report.reconstructed,
            vec!["doc.txt".to_string()],
            "a live-materialize crash-before-rename must be reconstructed"
        );
        assert!(
            report.offline_deleted.is_empty(),
            "the fresh file must NOT be misclassified as an offline deletion"
        );
        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            content,
            "the reconstructed file must have exactly the received bytes"
        );
        assert!(
            state
                .file_index_repository()
                .get_file(GROUP, "doc.txt")
                .unwrap()
                .is_some_and(|r| !r.deleted),
            "the index row must remain a live (not-deleted) record — no tombstone"
        );
        // Neither the crash nor repair closes what the path is owed: only
        // the commit that publishes a proof under a claim on it does, and
        // this attempt never got there. It stays open for the next claim.
        assert!(owed.is_some());
        assert_eq!(
            state.sqlite().dag_lookup_projection_obligation(GROUP, "doc.txt").unwrap(),
            owed,
            "the obligation must be exactly as it was before the write began"
        );
    }

    /// Regression: `materialize`'s bulk
    /// incoming-content path (the branch this module's own crash-recovery
    /// test above also drives) wraps `ensure_blocks_present` with `BULK_
    /// FETCH_RESPONSE_TIMEOUT`/`BULK_MATERIALIZE_TIMEOUT`, not the old
    /// `FETCH_RESPONSE_TIMEOUT` (5s) -- see those constants' own doc
    /// comments: under the earlier
    /// transport (a bespoke reliability layer over UDP), `FETCH_RESPONSE_TIMEOUT` was 5-13x
    /// SHORTER than that transport's own real worst-case single-frame
    /// recovery window, so this application layer routinely gave up on a
    /// fetch the transport layer was still actively, successfully
    /// retrying. The same class of problem exists under QUIC too --
    /// `BULK_FETCH_RESPONSE_TIMEOUT` is now derived from a 30s peer
    /// idle bound instead, the real
    /// worst case for "the peer stopped answering and nobody has noticed
    /// yet" under the current transport -- so this fix and its test stay
    /// warranted regardless of which transport originally motivated it.
    /// This drives a REAL peer connection (unlike every other test in this
    /// module) with a hand-scripted responder that deliberately delays its block
    /// response past the OLD 5s ceiling but well inside the NEW bulk
    /// one, and asserts two things the fix's own value is entirely about:
    /// (1) the fetch still succeeds -- the old 5s timeout would have
    /// reported `TimedOut` here and left a placeholder -- and (2) the
    /// responder saw exactly ONE block request for this hash, never a
    /// second one: `ensure_blocks_present`'s retry loop does not treat
    /// `FetchOutcome::TimedOut` as retriable (see its own doc comment on
    /// that arm), so a request that eventually succeeds within the bulk
    /// budget must never have been retried in the first place -- a
    /// regression that reintroduced the old short timeout would fail
    /// assertion (1); a regression that made this layer retry on ordinary
    /// slowness would fail assertion (2).
    #[tokio::test]
    async fn bulk_materialize_survives_a_reply_delay_past_the_old_fetch_timeout() {
        use prost::Message as _;

        // Comfortably past `FETCH_RESPONSE_TIMEOUT` (5s, the OLD ceiling
        // this fix replaced for this exact path) and comfortably under
        // the 30s peer idle bound plus
        // `BULK_FETCH_RESPONSE_TIMEOUT`'s own +10s margin on top of that
        // (40s total, `BULK_FETCH_RESPONSE_TIMEOUT`'s actual value) --
        // this value only needs to cross the OLD ceiling, not approach the
        // new one, to prove the fix; picked well clear of both bounds so
        // the assertion is unambiguous either way.
        const REPLY_DELAY: Duration = Duration::from_secs(8);

        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);

        // Deliberately NOT stored/provenance-recorded locally: this block
        // must actually cross the (slow) wire, exercising the real
        // `fetch_block_raw` timeout this test is about -- the crash-
        // recovery test above documents the opposite (already-present)
        // case's own reason for avoiding a live peer.
        let content = b"bulk-path content delayed past the old 5s ceiling".to_vec();
        let hash = crate::sha256_bytes(&content);
        let record = FileRecord {
            path: "slow-arrival.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash: hash.clone(), offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        let (transports, peer_node) = new_test_transports_with_peer().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // The scripted responder: waits for exactly one block request for
        // this hash, sleeps `REPLY_DELAY`, then answers `Found` -- and
        // keeps accepting afterward so an unwanted SECOND request (proof
        // of an unwanted retry) would also be captured, not silently
        // missed by the test ending too early. The bounded wait for a
        // further stream is what ends the loop: no more requests arriving
        // is the outcome this test wants, so it must be observable as the
        // task finishing rather than as a hang. Plays the peer over the
        // substrate's block lane (`accept_unclaimed_lane`) now, not the
        // raw control channel -- see `fetch_block_over_stream`'s own doc
        // comment for why the channel no longer carries block requests at
        // all.
        let responder_content = content.clone();
        let responder = tokio::spawn(async move {
            let content = responder_content;
            let mut requests_for_this_hash: u32 = 0;
            loop {
                let Ok(Some((_group, stream))) =
                    tokio::time::timeout(Duration::from_secs(5), peer_node.accept_unclaimed_lane())
                        .await
                else {
                    break; // no further traffic -- done observing
                };
                let mut stream = yadorilink_lane_ports::LaneBlockStream::new(stream);
                let Ok(header) = yadorilink_peer_session::ports::PeerBlockStream::recv_message(
                    &mut stream,
                    yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES,
                )
                .await
                else {
                    break;
                };
                let request = proto::BlockRequestHeader::decode(header.as_slice()).unwrap();
                if request.block_hash != hash {
                    continue;
                }
                requests_for_this_hash += 1;
                if requests_for_this_hash == 1 {
                    tokio::time::sleep(REPLY_DELAY).await;
                    crate::answer_block_request(
                        &mut stream,
                        &request,
                        crate::BlockAnswer::found(content.clone()),
                    )
                    .await;
                }
            }
            requests_for_this_hash
        });

        let out_path = sync_root.join("slow-arrival.bin");
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            session.convergence.materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            ),
        )
        .await
        .expect(
            "materialize must resolve within the bulk budget, not hang -- REPLY_DELAY (8s) is \
             far short of BULK_MATERIALIZE_TIMEOUT",
        )
        .unwrap();

        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::Settled(_)
            ),
            "expected a successful (Settled) materialize despite the delayed reply, got \
             {result:?}"
        );
        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            content,
            "the real content must have materialized once the delayed reply arrived"
        );
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "slow-arrival.bin")
                .unwrap(),
            Some(MaterializationState::Present),
            "a reply that arrives within the bulk budget must produce a normal Hydrated row, \
             not a placeholder -- the old 5s FETCH_RESPONSE_TIMEOUT would have timed out first \
             and left exactly a placeholder here instead"
        );

        let requests_seen = responder.await.unwrap();
        assert_eq!(
            requests_seen, 1,
            "exactly one block request must have been sent for this hash -- a response that \
             arrives within BULK_FETCH_RESPONSE_TIMEOUT must never trigger a duplicate fetch \
             (FetchOutcome::TimedOut, the only outcome that could have raced a slow-but-\
             eventually-successful reply, is deliberately not retried inside \
             ensure_blocks_present -- see that match arm's own doc comment)"
        );
    }

    /// A local write that lands while this device is fetching blocks must not
    /// be silently overwritten by the materialization already in flight for
    /// that path.
    ///
    /// The window is real and cannot be locked away: `path_lock` serializes
    /// only this device's own index-mediated writes, so a user's editor
    /// writing straight to the file races it freely. The only thing that can
    /// tell such a write apart from state that was always there is a
    /// comparison against what the path looked like *before* the blocks were
    /// requested -- which is why that observation is carried across the
    /// request rather than re-read on re-entry, where it would simply describe
    /// the racing write as the new baseline.
    ///
    /// Drives a real two-socket peer connection: the responder writes to the
    /// target path itself, at exactly the moment a real editor could, and only
    /// then answers the block request. The materialization must decline and
    /// leave the racing bytes untouched.
    #[tokio::test]
    async fn a_local_write_during_the_block_fetch_is_not_overwritten() {
        use prost::Message as _;

        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);

        // Not stored locally: this block has to cross the wire, because the
        // fetch is the window this test is about.
        let content = b"the peer's content, which must not win this race".to_vec();
        let hash = crate::sha256_bytes(&content);
        let record = FileRecord {
            path: "racing-edit.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash: hash.clone(), offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        let (transports, peer_node) = new_test_transports_with_peer().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let out_path = sync_root.join("racing-edit.bin");
        const LOCAL_BYTES: &[u8] = b"bytes a local editor wrote mid-fetch";

        let responder_content = content.clone();
        let racing_path = out_path.clone();
        let responder = tokio::spawn(async move {
            let (_group, stream) =
                tokio::time::timeout(Duration::from_secs(10), peer_node.accept_unclaimed_lane())
                    .await
                    .expect("the block request must arrive")
                    .expect("the endpoint must not have closed");
            let mut stream = yadorilink_lane_ports::LaneBlockStream::new(stream);
            let header = yadorilink_peer_session::ports::PeerBlockStream::recv_message(
                &mut stream,
                yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES,
            )
            .await
            .expect("the block stream ended before its request header");
            let request = proto::BlockRequestHeader::decode(header.as_slice())
                .expect("a block request header must decode");
            // The racing local write, placed exactly inside the fetch window:
            // the request is in flight and its answer has not been sent.
            std::fs::write(&racing_path, LOCAL_BYTES).unwrap();
            crate::answer_block_request(
                &mut stream,
                &request,
                crate::BlockAnswer::found(responder_content),
            )
            .await;
        });

        let result = tokio::time::timeout(
            Duration::from_secs(30),
            session.convergence.materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            ),
        )
        .await
        .expect("materialize must resolve, not hang")
        .unwrap();
        responder.await.unwrap();

        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired
            ),
            "a materialize whose target was written locally during the fetch must decline and \
             be retried, so the next resolution sees the two writes as concurrent; got {result:?}"
        );
        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            LOCAL_BYTES,
            "the racing local write must still be on disk -- overwriting it here destroys it \
             permanently, since it exists in no index and no block store"
        );
    }

    /// An eager record is charged to the per-group admission budget exactly
    /// once, even though its materialization is re-entered after the blocks
    /// arrive.
    ///
    /// The charge is a side effect, not a value that can be recomputed: the
    /// budget decides whether a record may fetch at all, so charging it again
    /// on re-entry both halves the session's real capacity and can fail a
    /// record whose blocks have already been fetched successfully, dropping it
    /// to a placeholder for the rest of the session.
    #[tokio::test]
    async fn an_eager_record_is_charged_to_the_admission_budget_once() {
        use prost::Message as _;

        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);

        let content = b"one block, charged once".to_vec();
        let hash = crate::sha256_bytes(&content);
        let record = FileRecord {
            path: "charged-once.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash: hash.clone(), offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        let (transports, peer_node) = new_test_transports_with_peer().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let responder_content = content.clone();
        let responder = tokio::spawn(async move {
            let (_group, stream) =
                tokio::time::timeout(Duration::from_secs(10), peer_node.accept_unclaimed_lane())
                    .await
                    .expect("the block request must arrive")
                    .expect("the endpoint must not have closed");
            let mut stream = yadorilink_lane_ports::LaneBlockStream::new(stream);
            let header = yadorilink_peer_session::ports::PeerBlockStream::recv_message(
                &mut stream,
                yadorilink_transport::MAX_BLOCK_STREAM_HEADER_BYTES,
            )
            .await
            .expect("the block stream ended before its request header");
            let request = proto::BlockRequestHeader::decode(header.as_slice())
                .expect("a block request header must decode");
            crate::answer_block_request(
                &mut stream,
                &request,
                crate::BlockAnswer::found(responder_content),
            )
            .await;
        });

        let result = tokio::time::timeout(
            Duration::from_secs(30),
            session.convergence.materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            ),
        )
        .await
        .expect("materialize must resolve, not hang")
        .unwrap();
        responder.await.unwrap();

        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::Settled(_)
            ),
            "the block was supplied, so this must settle; got {result:?}"
        );
        assert_eq!(
            session.convergence.eager_blocks_admitted(GROUP),
            record.blocks.len() as u64,
            "this record's blocks must be charged to the eager budget once, not once per pass \
             through the local core"
        );
    }

    /// A post-fetch failure inside `hydrate_file_with_timeout` (here: the
    /// pre-existing intermediate-directory-symlink escape guard,
    /// `verify_write_target`, refusing a root-escaping path) must not
    /// leave the row stuck at `Hydrating` forever -- every `?` between
    /// marking `Hydrating` and either `commit`ing or one of the two
    /// already-handled non-error exits used to have no rollback at all.
    /// Uses an already-locally-present block (seeded directly into the
    /// store with recorded provenance) so this test needs no live peer:
    /// `ensure_blocks_present` dedups on local presence + provenance
    /// before ever attempting a fetch.
    #[tokio::test]
    async fn hydrate_file_reverts_hydrating_state_on_a_post_fetch_failure() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let outside_dir = tempfile::tempdir().unwrap();

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "evil_link" inside the sync root points OUTSIDE it -- this
        // device's own local state, not anything peer-controlled.
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside_dir.path(), sync_root.join("evil_link")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(outside_dir.path(), sync_root.join("evil_link")).unwrap();

        let content = b"attacker-controlled content";
        let hash = hex::decode(
            yadorilink_local_storage::BlockContentStore::put(store.as_ref(), content).unwrap(),
        )
        .unwrap();
        state.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();

        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "evil_link/pwned.txt".into(),
                    size: content.len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "evil_link/pwned.txt",
                MaterializationState::Remote,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime_with_store(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let result = session
            .hydrate_file_with_timeout(
                GROUP,
                "evil_link/pwned.txt",
                std::time::Duration::from_secs(5),
            )
            .await;

        assert!(result.is_err(), "the symlink-escape write must be refused, not silently written");
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "evil_link/pwned.txt")
                .unwrap(),
            Some(MaterializationState::Remote),
            "a post-fetch failure must revert the row, not leave it stuck at Hydrating"
        );
        assert!(
            !outside_dir.path().join("pwned.txt").exists(),
            "the write must not have escaped the sync root through the symlink"
        );
    }

    /// `hydrate_file`/`hydrate_file_with_timeout` must serialize on
    /// `ReplicaCoordinator::path_lock` for the whole attempt -- the root fix for
    /// the class of races the authoring-bound identity checks above only
    /// mitigate (they stop the INDEX from lying about a superseded row,
    /// but `reconstruct_file`'s temp-then-rename write itself could still
    /// interleave with a concurrent, legitimate materialize's own rename
    /// for the same path without this). Proven here by holding the lock
    /// externally (as any other writer for this path would) and
    /// confirming a concurrent `hydrate_file` call genuinely blocks
    /// rather than proceeding.
    #[tokio::test]
    async fn hydrate_file_serializes_on_the_same_path_lock_every_other_writer_uses() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        let content = b"hydrated content";
        let hash = hex::decode(
            yadorilink_local_storage::BlockContentStore::put(store.as_ref(), content).unwrap(),
        )
        .unwrap();
        state.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "doc.txt".into(),
                    size: content.len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "doc.txt",
                MaterializationState::Remote,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime_with_store(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // Held externally, exactly as `rematerialize_one_record`/
        // `reconcile_group_paths` would while materializing this same
        // path.
        let path_lock = state.path_lock_registry().path_lock(GROUP, "doc.txt");
        let external_guard = path_lock.lock().await;

        let session_clone = session.clone();
        let hydrate_task =
            tokio::spawn(async move { session_clone.hydrate_file(GROUP, "doc.txt").await });

        // Bounded wait, not a race: while the external lock is held,
        // hydration must not have even reached `Hydrating` yet.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "doc.txt")
                .unwrap(),
            Some(MaterializationState::Remote),
            "hydrate_file must block on the held path_lock, not proceed concurrently with it"
        );

        drop(external_guard);
        let result = hydrate_task.await.unwrap();

        assert!(matches!(
            result,
            Ok(yadorilink_daemon::test_support::peer_session_fixture::HydrationOutcome::Hydrated)
        ));
        assert_eq!(std::fs::read(sync_root.join("doc.txt")).unwrap(), content);
    }

    /// `verify_write_target` must refuse a write when the sync root's
    /// identity marker no longer matches what this device adopted, even
    /// though nothing about lexical path containment changed -- the
    /// scenario a bare `canonicalize`/containment check cannot see: an
    /// external volume unmounted and replaced by something else at the
    /// same mountpoint path during a long block fetch, between
    /// `materialize`'s own one-time `VerifiedRoot::verify` at its start
    /// and the physical write at the end. Simulated here by removing the
    /// marker file after adoption -- from `verify_write_target`'s
    /// perspective this is indistinguishable from "the mountpoint now
    /// names something else": both leave a directory that canonicalizes
    /// and lexically contains `out_path` just fine, with no valid marker.
    #[tokio::test]
    async fn verify_write_target_refuses_a_root_whose_marker_no_longer_matches() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // Sanity: an ordinary top-level path passes while the marker is
        // still intact.
        let out_path = sync_root.join("doc.txt");
        session.convergence.verify_write_target(GROUP, &out_path).unwrap();

        // Simulate the mountpoint being unmounted and replaced: the
        // directory itself still canonicalizes and still lexically
        // contains `out_path`, but it no longer carries this group's
        // identity marker.
        std::fs::remove_file(
            sync_root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
        )
        .unwrap();

        let result = session.convergence.verify_write_target(GROUP, &out_path);
        assert!(
            result.is_err(),
            "a write target under a root whose marker no longer matches must be refused, not \
             just checked for lexical containment"
        );
    }

    /// A database written by an earlier receive path can hold a
    /// `version_seq = 0` scaffold row (`ensure_bootstrap_row_for_metadata`)
    /// for a path whose record was never projected, a tombstone's included.
    /// So when `materialize`'s hazard-hold branch runs, a row for the
    /// tombstone's OWN path can exist even though this device never
    /// genuinely indexed anything there. `get_file(...)
    /// .is_some()` alone cannot tell the two apart; this drives `materialize`
    /// directly (bypassing the full wire/DAG-negotiation path, which turned
    /// out not to reliably deliver a delete-only change for a path with no
    /// prior history anywhere in the DAG in a plain integration-test setup)
    /// to reproduce exactly that state.
    #[tokio::test]
    async fn hazardous_tombstone_for_a_bootstrap_only_scaffold_is_not_held() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&sync_root) {
            eprintln!("skipping: {} is case-sensitive here", sync_root.display());
            return;
        }

        // Adopt the (still-empty) root first, matching every other test in
        // this module -- `VerifiedRoot::open` refuses a folder that already
        // has un-adopted content on disk with no root marker.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "Photo.jpg" is live and materialized -- the sibling the tombstone
        // will collide with.
        std::fs::write(sync_root.join("Photo.jpg"), b"original photo bytes").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"original photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(
            state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().is_none(),
            "precondition: no prior row at all for the tombstone's own path"
        );

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let tombstone = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        // The scaffold a database still holds from before the receive path
        // stopped writing one: a metadata step that bootstrapped the path and
        // a restart before the record was projected.
        state
            .file_index_repository()
            .ensure_bootstrap_row_for_metadata(GROUP, "photo.jpg")
            .unwrap();
        assert!(
            state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().is_some(),
            "the bootstrap must have created a scaffold row -- this is the shape of the gap, \
             not the fix"
        );

        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&tombstone),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await
            .unwrap();

        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "photo.jpg")
                .unwrap()
                .is_none(),
            "a hazardous tombstone must not be held on a bootstrap-only scaffold -- there was \
             never any genuine content here to protect"
        );
        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired
            ),
            "nothing was actually recorded (no hold, no delete) -- a caller must not treat this \
             path as resolved for this attempt, or a sending peer that later disappears leaves \
             this deletion permanently unconverged"
        );
        assert_eq!(
            std::fs::read(sync_root.join("Photo.jpg")).unwrap(),
            b"original photo bytes",
            "the sibling must remain untouched"
        );
    }

    /// Holding a hazardous tombstone against a GENUINE live row must report
    /// `RetryRequired`, not `Settled`: `set_held` only stamps `held_reason`
    /// onto the still-live row -- it records neither the pending
    /// tombstone's authoring identity nor that a deletion is pending at
    /// all -- so nothing downstream can tell "durably resolved" from "live
    /// file that happens to carry a hold reason". `Settled` here would let
    /// this path's projection obligation close as though the deletion had
    /// actually happened, so nothing would ever re-examine it again even
    /// though nothing was deleted.
    #[tokio::test]
    async fn hazardous_tombstone_of_a_genuine_live_row_reports_retry_required() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&sync_root) {
            eprintln!("skipping: {} is case-sensitive here", sync_root.display());
            return;
        }

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "Photo.jpg" is live and materialized -- the sibling the tombstone
        // will collide with. On a case-insensitive filesystem "Photo.jpg"
        // and "photo.jpg" are the SAME on-disk entry, so "photo.jpg"'s own
        // genuine index row (below) is index-only, matching every other
        // test in this file that constructs this scenario.
        std::fs::write(sync_root.join("Photo.jpg"), b"original photo bytes").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"original photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // "photo.jpg" itself already has a GENUINE (version_seq > 0), live
        // (not deleted) row -- unlike the bootstrap-scaffold test above.
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "photo.jpg".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let tombstone = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&tombstone),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await
            .unwrap();

        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "photo.jpg")
                .unwrap()
                .is_some(),
            "the genuine live row must still be marked held"
        );
        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired
            ),
            "holding a genuine live row is not durable convergence -- the pending tombstone's \
             identity is nowhere recorded, so this must not be reported as settled"
        );

        let first_held_since = state
            .materialization_state_repository()
            .get_held_state(GROUP, "photo.jpg")
            .unwrap()
            .unwrap()
            .since_unix_nanos;
        // `RetryRequired` means the periodic materialization audit
        // re-drives this exact path every tick while the collision
        // persists -- re-materializing the identical tombstone must not
        // reset `held_since_unix_nanos` to "now" each time, or a path
        // held for hours would always read as held for a moment.
        std::thread::sleep(std::time::Duration::from_millis(5));
        session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&tombstone),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await
            .unwrap();
        let second_held_since = state
            .materialization_state_repository()
            .get_held_state(GROUP, "photo.jpg")
            .unwrap()
            .unwrap()
            .since_unix_nanos;
        assert_eq!(
            first_held_since, second_held_since,
            "held_since_unix_nanos must not advance on a re-drive with the same hold reason"
        );
    }

    /// A tombstone that already landed cleanly (row `deleted = true`,
    /// `clear_held` already ran) must not become held again just because a
    /// peer's periodic full-index resend redelivers it after a fresh
    /// collision appears. Holding it would leave a `held_reason` on an
    /// already-tombstoned row -- the "orphaned held entry" state
    /// `clear_held`'s own doc comment says this crate deliberately avoids.
    #[tokio::test]
    async fn hazardous_redelivery_of_an_already_landed_tombstone_is_not_held() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&sync_root) {
            eprintln!("skipping: {} is case-sensitive here", sync_root.display());
            return;
        }

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "photo.jpg" already landed as a clean tombstone -- no collision
        // existed when it was applied, so nothing is held.
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "photo.jpg".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: true,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(state
            .materialization_state_repository()
            .get_held_state(GROUP, "photo.jpg")
            .unwrap()
            .is_none());

        // "Photo.jpg" now becomes live -- a fresh collision the original
        // tombstone application never saw.
        std::fs::write(sync_root.join("Photo.jpg"), b"fresh photo bytes").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"fresh photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // The same tombstone, redelivered (a peer's periodic full-index
        // resend) after the fresh collision now exists.
        let redelivered_tombstone = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&redelivered_tombstone),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await
            .unwrap();

        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::Settled(_)
            ),
            "this deletion already converged (the row is already a genuine tombstone, not a \
             scaffold) -- reporting RetryRequired here would churn forever on a redundant resend"
        );
        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "photo.jpg")
                .unwrap()
                .is_none(),
            "redelivering an already-landed tombstone must not mark its own (already deleted) \
             row held"
        );
        assert!(
            state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().unwrap().deleted,
            "the row must remain a clean tombstone"
        );
    }

    /// `hazardous_redelivery_of_an_already_landed_tombstone_is_not_held`
    /// with the collision in an ancestor instead of the leaf.
    #[tokio::test]
    async fn hazardous_redelivery_of_a_tombstone_colliding_through_its_parent_is_not_held() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&sync_root) {
            eprintln!("skipping: {} is case-sensitive here", sync_root.display());
            return;
        }

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "Docs/photo.jpg" already landed as a clean tombstone -- no
        // collision existed when it was applied, so nothing is held.
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Docs/photo.jpg".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: true,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(state
            .materialization_state_repository()
            .get_held_state(GROUP, "Docs/photo.jpg")
            .unwrap()
            .is_none());

        // "docs/photo.jpg" now becomes live -- a fresh collision the
        // original tombstone application never saw, through the parent
        // directory: the leaf names are identical, so listing only the
        // leaf's parent (which resolves "Docs" to "docs") would find
        // "photo.jpg" and never observe the absence.
        std::fs::create_dir(sync_root.join("docs")).unwrap();
        std::fs::write(sync_root.join("docs/photo.jpg"), b"fresh photo bytes").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "docs/photo.jpg".into(),
                    size: b"fresh photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // The same tombstone, redelivered (a peer's periodic full-index
        // resend) after the fresh collision now exists.
        let redelivered_tombstone = FileRecord {
            path: "Docs/photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&redelivered_tombstone),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await
            .unwrap();

        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::Settled(_)
            ),
            "this deletion already converged (the row is already a genuine tombstone, not a \
             scaffold) -- reporting RetryRequired here would churn forever on a redundant resend"
        );
        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "Docs/photo.jpg")
                .unwrap()
                .is_none(),
            "redelivering an already-landed tombstone must not mark its own (already deleted) \
             row held"
        );
        assert!(
            state
                .file_index_repository()
                .get_file(GROUP, "Docs/photo.jpg")
                .unwrap()
                .unwrap()
                .deleted,
            "the row must remain a clean tombstone"
        );
    }

    /// The other side of `hazardous_redelivery_of_an_already_landed_
    /// tombstone_is_not_held`: an already-landed tombstone settles past its
    /// case-colliding live sibling only because the entry on disk is the
    /// sibling's, under the sibling's own name. When the entry's exact name
    /// is the tombstoned one, the absence was never observed and the
    /// redelivery must come back for another pass.
    #[tokio::test]
    async fn hazardous_redelivery_is_not_settled_while_an_entry_holds_exactly_its_name() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&sync_root) {
            eprintln!("skipping: {} is case-sensitive here", sync_root.display());
            return;
        }

        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();

        // "photo.jpg" already landed as a clean tombstone -- no collision
        // existed when it was applied, so nothing is held.
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "photo.jpg".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: true,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(state
            .materialization_state_repository()
            .get_held_state(GROUP, "photo.jpg")
            .unwrap()
            .is_none());

        // "Photo.jpg" now becomes live -- a fresh collision the original
        // tombstone application never saw.
        // ...but the one entry on disk carries exactly the tombstoned
        // name (the sibling was renamed onto it and not yet captured), so
        // this name is not observably absent.
        std::fs::write(sync_root.join("photo.jpg"), b"fresh photo bytes").unwrap();
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"fresh photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // The same tombstone, redelivered (a peer's periodic full-index
        // resend) after the fresh collision now exists.
        let redelivered_tombstone = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&redelivered_tombstone),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await
            .unwrap();

        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired
            ),
            "an entry named exactly 'photo.jpg' is on disk -- an absence that was not observed \
             must not be claimed, whatever the index row says"
        );
        assert_eq!(
            std::fs::read(sync_root.join("photo.jpg")).unwrap(),
            b"fresh photo bytes",
            "nothing may be deleted on the way"
        );
    }

    /// `materialize` must refuse a peer-advertised path naming a versioned
    /// reserved-namespace artefact, regardless of how the record got here
    /// (see the comment at the check site in `materialize` for why this is
    /// defense-in-depth rather than the only guard).
    #[tokio::test]
    async fn materialize_rejects_a_versioned_artefact_path() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let artefact_path = yadorilink_fs_platform::reserved_namespace::artefact_component_name(
            yadorilink_fs_platform::reserved_namespace::ArtefactKind::Stage,
            "deadbeef",
        )
        .unwrap();
        let record = FileRecord {
            path: artefact_path.clone(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &artefact_path),
            "expected a ReservedNamespaceCollision naming the artefact path, got {result:?}"
        );
        assert!(!sync_root.join(&artefact_path).exists());
    }

    /// THE remote-materialization hole this pins closed: a peer-driven
    /// `materialize` call naming this device's own sync-root lock file must
    /// be refused, driven through the real `materialize` entry point (not a
    /// bare predicate call). Without this, a change that skipped or
    /// predated admission's own `validate_no_reserved_paths` check would
    /// still reach disk here, replacing the on-disk lock file out from
    /// under this device's live OS lock — the exact "two processes both
    /// believe they own this root" state `sync_root_lock` exists to
    /// prevent.
    #[tokio::test]
    async fn materialize_rejects_the_sync_root_lock_path() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let lock_path =
            yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME.to_string();
        let record = FileRecord {
            path: lock_path.clone(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &lock_path),
            "expected a ReservedNamespaceCollision naming the sync-root lock path, got {result:?}"
        );
        assert!(!sync_root.join(&lock_path).exists());
    }

    /// `materialize`'s `PolicySkipped`
    /// outcome for a symlink used to leave `materialization_state` at its
    /// schema default of `Present`, even though nothing was ever written
    /// to disk. A `Present` row with no physical object and no
    /// materialization intent is exactly what the periodic repair sweep
    /// (`repair_interrupted_materializations`) reads as an offline
    /// deletion -- which it journals dirty, and the always-running
    /// dirty-journal redrive then turns into a real, signed, GROUP-WIDE
    /// PROPAGATING tombstone `Change`, deleting the path from every peer
    /// even though the skip was meant to be a benign, local-only policy
    /// decision. The concrete real-world trigger is a Windows peer without
    /// `windows_symlink_opt_in`; "no target recorded" reaches the exact
    /// same caller-side `PolicySkipped` match arm and is reachable on
    /// every platform, which is what this test exercises.
    #[tokio::test]
    async fn a_policy_skipped_symlink_is_demoted_to_placeholder_not_left_looking_hydrated() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let record = FileRecord {
            path: "mystery-link".to_string(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .file_index_repository()
            .set_record_kind(
                GROUP,
                "mystery-link",
                yadorilink_replica_domain::file::RecordKind::Symlink,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // Deliberately no `set_symlink_target` call -- this is the "no
        // target recorded" trigger for `PolicySkipped`, which reaches the
        // exact same caller-side match arm as the Windows-not-opted-in
        // trigger does.

        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::symlink_payload_for(&record, None),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            matches!(
                result,
                Ok(yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired)
            ),
            "expected a retriable PolicySkipped outcome, got {result:?}"
        );

        let materialization_state = state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "mystery-link")
            .unwrap();
        assert_eq!(
            materialization_state,
            Some(MaterializationState::Remote),
            "a policy-skipped symlink row must be demoted away from the schema-default Hydrated \
             state -- left at Hydrated, the periodic repair sweep would misread it as an \
             offline deletion and the dirty-journal redrive would turn that into a real, \
             propagating tombstone Change for a path this device never actually deleted"
        );
    }

    /// The transition-out-of-held window: a path that WAS hazard-held
    /// (`held_reason` set, protecting it from the offline-deletion
    /// tombstone loop on its own) is re-attempted once the hazard is
    /// gone. `materialize`'s symlink branch clears `held_reason` before
    /// calling `materialize_symlink_at` -- if that call then hits
    /// `PolicySkipped` (no target recorded, exercised here the same
    /// platform-independent way as the sibling test above), the row is
    /// left `Remote`, `held_reason` now NULL, and (nothing in this
    /// codebase re-arms a projection obligation once hazard settlement
    /// deleted it) no obligation either. Without a materialization intent
    /// protecting this exact window, that leaves ZERO of the tombstone
    /// loop's three vetoes (intent / obligation / `is_held`) covering a
    /// row that is genuinely still valid -- this device just could not
    /// materialize the symlink under this exact name, the same as any
    /// other policy skip.
    #[tokio::test]
    async fn a_symlink_whose_hold_clears_into_a_policy_skip_still_has_intent_protection() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let record = FileRecord {
            path: "was-held-link".to_string(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state.file_index_repository().upsert_file(GROUP, &record, &permit).unwrap();
        state
            .file_index_repository()
            .set_record_kind(
                GROUP,
                "was-held-link",
                yadorilink_replica_domain::file::RecordKind::Symlink,
                &permit,
            )
            .unwrap();
        // Deliberately no `set_symlink_target` call -- the same
        // platform-independent `PolicySkipped` trigger the sibling test
        // above uses.
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "was-held-link",
                MaterializationState::Remote,
                &permit,
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_held(GROUP, "was-held-link", "case_collision", 0)
            .unwrap();
        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "was-held-link")
                .unwrap()
                .is_some(),
            "sanity: the row must genuinely start held for this test to exercise the \
             transition-out-of-held window, not something else"
        );
        // "was-held-link" collides with nothing else in the group, so
        // `hazard_reason_for` genuinely reports no hazard for it -- this
        // is what drives `materialize`'s symlink branch to actually clear
        // the hold and retry, rather than re-holding it.

        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::symlink_payload_for(&record, None),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            matches!(
                result,
                Ok(yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired)
            ),
            "expected the hold to clear and the retry to hit the same retriable PolicySkipped \
             outcome as the sibling test, got {result:?}"
        );
        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "was-held-link")
                .unwrap()
                .is_none(),
            "sanity: the hold must genuinely have been cleared for this test to have exercised \
             the transition window, not left the row still protected by held_reason alone"
        );
        assert!(
            state
                .materialization_intent_repository()
                .has_materialization_intent(GROUP, "was-held-link")
                .unwrap(),
            "a materialization intent must protect this path through the held-to-policy-skip \
             transition -- without one, the row is left Placeholder, held_reason NULL, no \
             intent, and no projection obligation, which is indistinguishable from a genuine \
             offline deletion to the startup/live reconciliation scan's tombstone loop"
        );
    }

    /// The counterpart of the test above, in the opposite direction: this
    /// symlink was NEVER held, so `materialize`'s symlink branch must
    /// never open the transition-protecting intent guard for it at all.
    /// Every symlink materialize runs through this exact branch (not just
    /// a held-transition one), and on Windows-without-symlink-opt-in this
    /// same `PolicySkipped` outcome is the ordinary, permanent steady
    /// state for that path -- retried forever on capped backoff. Opening
    /// (and idempotently re-upserting) the extra intent unconditionally on
    /// every one of those retries would be a real, avoidable write with no
    /// protective benefit for a path that was never relying on
    /// `held_reason` in the first place.
    #[tokio::test]
    async fn an_unheld_symlink_never_opens_the_transition_intent_guard_on_a_policy_skip() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let record = FileRecord {
            path: "never-held-link".to_string(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        state.file_index_repository().upsert_file(GROUP, &record, &permit).unwrap();
        state
            .file_index_repository()
            .set_record_kind(
                GROUP,
                "never-held-link",
                yadorilink_replica_domain::file::RecordKind::Symlink,
                &permit,
            )
            .unwrap();
        // Deliberately no `set_symlink_target` call -- the same
        // platform-independent `PolicySkipped` trigger the sibling tests
        // above use. Deliberately no `set_held` call either -- this
        // path's whole point is that it was never held.
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "never-held-link",
                MaterializationState::Remote,
                &permit,
            )
            .unwrap();
        assert!(
            state
                .materialization_state_repository()
                .get_held_state(GROUP, "never-held-link")
                .unwrap()
                .is_none(),
            "sanity: this test's whole point is that the row was never held"
        );

        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::symlink_payload_for(&record, None),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            matches!(
                result,
                Ok(yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired)
            ),
            "expected the same retriable PolicySkipped outcome as the held sibling test, got \
             {result:?}"
        );
        assert!(
            !state
                .materialization_intent_repository()
                .has_materialization_intent(GROUP, "never-held-link")
                .unwrap(),
            "an unheld symlink must never have the transition-protecting intent guard opened \
             for it at all -- a dangling intent here would be pure waste on a permanent, \
             capped-backoff-retried steady state, not just a crash window"
        );
    }

    /// The tenth route in this same bug family, LIVE on Windows via the
    /// ordinary path -- not dormant like the rebootstrap-snapshot route.
    /// `create_or_defer_placeholder` writes nothing on Windows (real
    /// creation is deferred to `cfapi-host.exe`'s own poll), but this is
    /// the ordinary On-Demand receive path every Windows OnDemand-policy
    /// device takes for every normal incoming file -- and it used to
    /// settle `PolicyRemote` (completing this path's projection
    /// obligation) and clear the protecting intent unconditionally,
    /// exactly as if a real write had happened. That leaves a current,
    /// non-deleted row with nothing on disk under its own name and NONE
    /// of the tombstone loop's three vetoes -- reachable on the very
    /// first file any Windows OnDemand device ever receives, not a rare
    /// crash window. Uses `create_or_defer_placeholder`'s own test-only
    /// failure-injection seam (real Windows behavior is not exercisable
    /// on this host) to force the deferred outcome regardless of
    /// platform -- path-keyed, so this test's own distinct path cannot
    /// collide with any other concurrently-running test using the same
    /// seam for a different one.
    #[tokio::test]
    async fn a_deferred_windows_placeholder_never_settles_or_clears_its_intent() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        state
            .link_repository()
            .set_materialization_policy(
                &sync_root.to_string_lossy(),
                MaterializationPolicy::OnDemand,
            )
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let content = b"content this device never fetches -- OnDemand defers it";
        let hash = hex::decode(
            yadorilink_local_storage::BlockContentStore::put(store.as_ref(), content).unwrap(),
        )
        .unwrap();
        state.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();
        let record = FileRecord {
            path: "windows-ondemand-receive.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 0,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        let out_path = sync_root.join("windows-ondemand-receive.bin");
        yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
            &out_path, true,
        );
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::OnDemand,
                "device-a",
                None,
            )
            .await;
        yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
            &out_path, false,
        );

        assert!(
            matches!(
                result,
                Ok(yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired)
            ),
            "a deferred Windows placeholder must NOT settle as PolicyRemote -- nothing is \
             actually on disk yet to justify completing this path's projection obligation, got \
             {result:?}"
        );
        assert!(
            !sync_root.join("windows-ondemand-receive.bin").exists(),
            "sanity: create_or_defer_placeholder's test seam must genuinely have written \
             nothing, matching real Windows behavior"
        );
        assert!(
            state
                .materialization_intent_repository()
                .has_materialization_intent(GROUP, "windows-ondemand-receive.bin")
                .unwrap(),
            "a materialization intent must protect this path while its real placeholder \
             creation is deferred to cfapi-host.exe -- without one, the row is current, \
             non-deleted, nothing on disk under its own name, no intent, no obligation \
             (settlement would have completed it), no hold: exactly what the startup/live \
             reconciliation scan's tombstone loop reads as an offline deletion"
        );
    }

    #[tokio::test]
    async fn a_provider_object_is_not_deferred_for_a_path_where_an_object_already_stands() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        state
            .link_repository()
            .set_materialization_policy(
                &sync_root.to_string_lossy(),
                MaterializationPolicy::OnDemand,
            )
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let content = b"content this device never fetches -- OnDemand defers it";
        let hash = hex::decode(
            yadorilink_local_storage::BlockContentStore::put(store.as_ref(), content).unwrap(),
        )
        .unwrap();
        state.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();
        let record = FileRecord {
            path: "windows-ondemand-receive.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 0,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        let out_path = sync_root.join("windows-ondemand-receive.bin");
        // An object already stands here: the provider has nothing to create,
        // so there is nothing to defer to it.
        std::fs::write(&out_path, content).unwrap();
        yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
            &out_path, true,
        );
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::OnDemand,
                "device-a",
                None,
            )
            .await;
        yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
            &out_path, false,
        );

        assert!(
            matches!(
                result,
                Ok(yadorilink_daemon::local_convergence::types::MaterializeResult::Settled(_))
            ),
            "an object already stands, so a provider creation is not owed and the lane must \
             settle rather than retry forever, got {result:?}"
        );
        assert_eq!(std::fs::read(&out_path).unwrap(), content.as_slice());
    }

    /// The same deferred-Windows-placeholder danger as the sibling test
    /// above, at the eager/pinned "not every block present locally"
    /// branch instead of the OnDemand-receive one -- this branch already
    /// always returns `RetryRequired` (never settles), but it used to
    /// unconditionally clear the protecting intent right after the
    /// deferred write anyway, the same mistake as the OnDemand branch,
    /// just without the extra settlement half of the bug.
    #[tokio::test]
    async fn a_deferred_windows_placeholder_never_clears_its_intent_on_the_eager_not_all_present_branch(
    ) {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // A block this device does not have locally and cannot fetch: no
        // peer serves this session's block lane, so the eager fetch below
        // lands in the "not all present" branch.
        let missing_hash = vec![0x99u8; 32];
        let record = FileRecord {
            path: "windows-eager-not-all-present.bin".to_string(),
            size: 5,
            mtime_unix_nanos: 0,
            blocks: vec![BlockInfo { hash: missing_hash, offset: 0, size: 5 }],
            deleted: false,
        };

        let out_path = sync_root.join("windows-eager-not-all-present.bin");
        yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
            &out_path, true,
        );
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        yadorilink_local_storage::materialize_write::set_test_force_deferred_placeholder_for_path(
            &out_path, false,
        );

        assert!(
            matches!(
                result,
                Ok(yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired)
            ),
            "expected the ordinary retriable placeholder outcome for a not-fully-fetched \
             eager file, got {result:?}"
        );
        assert!(
            !sync_root.join("windows-eager-not-all-present.bin").exists(),
            "sanity: the deferred placeholder write must genuinely be absent"
        );
        assert!(
            state
                .materialization_intent_repository()
                .has_materialization_intent(GROUP, "windows-eager-not-all-present.bin")
                .unwrap(),
            "a materialization intent must protect this path while its real placeholder \
             creation is deferred to cfapi-host.exe, same reasoning as the OnDemand sibling \
             test"
        );
    }

    /// Windows drops trailing `.`/` ` in most Win32 path APIs, so a peer
    /// that spells the reserved name with a trailing dot or space types a
    /// path that is not literally the reserved name, but would land on
    /// disk — on a Windows device — as exactly the reserved name. Landing
    /// in the fail-closed direction is still a real defect: it lets any
    /// peer name (and thereby permanently block, via
    /// `ReservedNamespaceCollision`) an arbitrary path on someone else's
    /// device without ever spelling the exact reserved name on the wire.
    /// `materialize` must reject both forms regardless of which platform
    /// is running the check.
    #[tokio::test]
    async fn materialize_rejects_a_versioned_artefact_path_with_windows_trailing_normalization() {
        for suffix in [" ", "."] {
            let store_dir = tempfile::tempdir().unwrap();
            let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
                Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
            let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
            let root_dir = tempfile::tempdir().unwrap();
            let sync_root = root_dir.path().canonicalize().unwrap();
            state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
            adopt_root(&state, GROUP, &sync_root);
            let generation = state.startup_readiness().begin_group_startup(GROUP);
            state.startup_readiness().mark_group_ready(GROUP, generation);
            let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
            let transports = new_test_transports().await;
            let session = {
                let __state = state.clone();
                let __store = store.clone();
                let __roots = sync_roots;
                let __replica_engine =
                    yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
                        &__state,
                        __store.clone(),
                    );
                crate::permissive_runtime(
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    ),
                    "device-b",
                    __state,
                    __store,
                    __roots,
                )
            };

            let artefact_path = format!(
                "{}{suffix}",
                yadorilink_fs_platform::reserved_namespace::artefact_component_name(
                    yadorilink_fs_platform::reserved_namespace::ArtefactKind::Stage,
                    "deadbeef",
                )
                .unwrap()
            );
            let record = FileRecord {
                path: artefact_path.clone(),
                size: 0,
                mtime_unix_nanos: 1,
                blocks: Vec::new(),
                deleted: false,
            };
            let result = session
                .convergence
                .materialize(
                    &session.driver(),
                    GROUP,
                    &crate::payload_for(&record),
                    MaterializationPolicy::Eager,
                    "device-a",
                    None,
                )
                .await;
            assert!(
                matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &artefact_path),
                "suffix {suffix:?}: expected a ReservedNamespaceCollision, got {result:?}"
            );
        }
    }

    /// The converse of the artefact-rejection test above, and the fix for a
    /// real defect: a path merely containing the LEGACY `.yadorilink-tmp.`
    /// substring (e.g. a genuine user file named
    /// `report.yadorilink-tmp.old`) must still materialize normally.
    /// `materialize` keys its rejection on `path_has_artefact_component`,
    /// not the broader exclusion predicate `path_has_reserved_component` —
    /// the legacy marker is a substring match precisely because arbitrary
    /// user content can precede it, and
    /// recovery never deletes a file by its name. Pointing `materialize`'s check
    /// back at the exclusion predicate makes this test fail.
    #[tokio::test]
    async fn materialize_still_writes_a_legacy_marker_look_alike_user_file() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let content = b"my actual notes, not a temp file".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();
        state.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();
        let path = "report.yadorilink-tmp.old".to_string();
        let record = FileRecord {
            path: path.clone(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            result.is_ok(),
            "a legacy-marker look-alike user file must still materialize: {result:?}"
        );
        assert_eq!(std::fs::read(sync_root.join(&path)).unwrap(), content);
    }

    /// A trailing space makes this path non-portable (Windows silently
    /// drops it), independently of whether the path also happens to look
    /// like a legacy marker — the non-portability check must reject it
    /// before materialize ever reaches the legacy-marker/artefact
    /// classification at all. See
    /// `materialize_still_writes_a_legacy_marker_look_alike_user_file` for
    /// the sibling case (same look-alike name, no trailing space) that
    /// confirms the legacy-marker substring match alone must not block an
    /// ordinary user file, and
    /// `reserved_namespace::tests::wire_predicate_still_excludes_the_legacy_marker_with_a_trailing_space`
    /// for where the narrower "trailing-space stripping must not widen the
    /// artefact predicate" property this test used to pin now lives — it
    /// can no longer be exercised through this full materialize pipeline,
    /// since the non-portability check refuses the path before the
    /// artefact-vs-legacy classification is ever reached.
    #[tokio::test]
    async fn materialize_rejects_a_non_portable_path_even_when_it_also_looks_like_a_legacy_marker()
    {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let content = b"my actual notes, not a temp file".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();
        state.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();
        let path = "report.yadorilink-tmp.old ".to_string();
        let record = FileRecord {
            path: path.clone(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::NonPortablePath(ref p)) if p == &path),
            "a path with a trailing space must be rejected as non-portable, not materialized: \
             {result:?}"
        );
        assert!(!sync_root.join(&path).exists());
    }

    /// The actual data-loss shape this whole check exists to prevent,
    /// proven through the real `materialize` entry point rather than only
    /// against the predicate: two distinct logical paths that a Windows
    /// device's own path normalization would resolve onto ONE on-disk name
    /// (`"a"` and `"a "`, differing only in a trailing space) must never
    /// both be allowed to reach disk. This host cannot reproduce the
    /// actual on-disk aliasing (only a real Windows filesystem silently
    /// drops the trailing space), but it can — and must — prove the
    /// mechanism that prevents it on every host: the first, ordinary path
    /// materializes normally, and the second, would-be-colliding path is
    /// refused outright, leaving the first file's bytes on disk exactly as
    /// they were.
    ///
    /// Without the refusal, a Windows device receiving both changes would
    /// silently let the second overwrite the first with no conflict ever
    /// detected (they are different index paths, so no DAG conflict
    /// machinery ever compares them), while its own index kept believing
    /// both were independently, correctly `Present` — permanent,
    /// undetectable data loss. The sibling
    /// `materialize_rejects_a_non_portable_path_even_when_it_also_looks_like_a_legacy_marker`
    /// test only pins the predicate for a single path considered in
    /// isolation; this one pins the actual collision it exists to prevent.
    #[tokio::test]
    async fn materialize_refuses_a_colliding_trailing_space_variant_of_an_already_materialized_path(
    ) {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let original_content = b"the original file, must survive untouched".to_vec();
        let original_hash = hex::decode(store.put(&original_content).unwrap()).unwrap();
        state.record_block_provenance(GROUP, std::slice::from_ref(&original_hash)).unwrap();
        let original_path = "a".to_string();
        let original_record = FileRecord {
            path: original_path.clone(),
            size: original_content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo {
                hash: original_hash,
                offset: 0,
                size: original_content.len() as u32,
            }],
            deleted: false,
        };
        session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&original_record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read(sync_root.join(&original_path)).unwrap(), original_content);

        // A distinct logical path that a Windows device would resolve onto
        // the SAME on-disk name as `original_path` — different content, so
        // an undetected collision would silently destroy `original_content`.
        let colliding_content = b"a different peer's write, must never land here".to_vec();
        let colliding_hash = hex::decode(store.put(&colliding_content).unwrap()).unwrap();
        state.record_block_provenance(GROUP, std::slice::from_ref(&colliding_hash)).unwrap();
        let colliding_path = "a ".to_string();
        let colliding_record = FileRecord {
            path: colliding_path.clone(),
            size: colliding_content.len() as u64,
            mtime_unix_nanos: 2,
            blocks: vec![BlockInfo {
                hash: colliding_hash,
                offset: 0,
                size: colliding_content.len() as u32,
            }],
            deleted: false,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&colliding_record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            matches!(
                result,
                Err(yadorilink_peer_session::error::PeerSessionError::NonPortablePath(ref p)) if p == &colliding_path
            ),
            "the colliding trailing-space path must be refused, not materialized: {result:?}"
        );

        // The original file must be completely untouched — no collision,
        // no partial overwrite, no trace of the refused write.
        assert_eq!(
            std::fs::read(sync_root.join(&original_path)).unwrap(),
            original_content,
            "a refused colliding write must never disturb the original path's bytes"
        );
        assert!(!sync_root.join(&colliding_path).exists());
    }

    /// NTFS `filename::$DATA` addresses `filename`'s own default stream —
    /// the same on-disk object — so `materialize` must refuse an
    /// ADS-suffixed alias for a versioned artefact exactly like the
    /// un-suffixed name, or a peer could get such a record admitted and
    /// later write through the alias into the artefact's own bytes.
    #[tokio::test]
    async fn materialize_rejects_an_alternate_data_stream_alias_for_a_versioned_artefact() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let artefact_path = format!(
            "{}::$DATA",
            yadorilink_fs_platform::reserved_namespace::artefact_component_name(
                yadorilink_fs_platform::reserved_namespace::ArtefactKind::Stage,
                "deadbeef",
            )
            .unwrap()
        );
        let record = FileRecord {
            path: artefact_path.clone(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &artefact_path),
            "expected a ReservedNamespaceCollision naming the ADS-aliased path, got {result:?}"
        );
        assert!(!sync_root.join(&artefact_path).exists());
    }

    /// `change::validate_path` accepts both `/` and `\` as separators, so
    /// `materialize` must reject a backslash-delimited artefact component
    /// the same on every host — resolving `record.path` through the local
    /// `std::path::Path` type instead would make this check's outcome
    /// depend on which platform happens to be running it.
    #[tokio::test]
    async fn materialize_rejects_a_backslash_delimited_artefact_path_on_every_host() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        adopt_root(&state, GROUP, &sync_root);
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        let artefact_path = format!(
            "safe\\{}",
            yadorilink_fs_platform::reserved_namespace::artefact_component_name(
                yadorilink_fs_platform::reserved_namespace::ArtefactKind::Preimage,
                "cafef00d",
            )
            .unwrap()
        );
        let record = FileRecord {
            path: artefact_path.clone(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: false,
        };
        let result = session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await;
        assert!(
            matches!(result, Err(yadorilink_peer_session::error::PeerSessionError::ReservedNamespaceCollision(ref p)) if p == &artefact_path),
            "expected a ReservedNamespaceCollision naming the backslash-delimited path, got {result:?}"
        );
    }

    /// The converse guardrail on the same seam: a FULLY successful live
    /// materialize must CLEAR its intent (right after the durable rename, before
    /// the post-write exec-bit touch), so the intent can never linger under a
    /// `Present`+present file. If it lingered, a later genuine offline delete of
    /// that path would read `missing + intent present` and wrongly resurrect the
    /// file from its still-present blocks — the exact misclassification the
    /// journal exists to prevent, in the opposite direction. This drives the real
    /// `materialize` to success, asserts no intent remains, then deletes the file
    /// offline and asserts repair classifies it as a delete, not a reconstruct.
    #[tokio::test]
    async fn live_materialize_success_clears_intent_so_a_later_offline_delete_is_not_resurrected() {
        let store_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // Claim the root while the index is still empty, the way linking a
        // folder does. Without it the repair below sees indexed files with no
        // bytes in an unmarked root -- byte-for-byte an unmounted volume -- and
        // correctly refuses to touch it.
        adopt_root(&state, GROUP, &sync_root);

        let content = b"received, materialized cleanly, later deleted offline".to_vec();
        let hash = hex::decode(store.put(&content).unwrap()).unwrap();
        // See the sibling crash-before-rename test's identical seed for why:
        // without recorded group provenance, `ensure_blocks_present` treats
        // this block as missing for this group and the eager materialize
        // blocks on the unreachable peer channel for the full hydration
        // timeout instead of completing.
        state.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();

        let record = FileRecord {
            path: "doc.txt".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
            deleted: false,
        };

        // A live, started-up link is the only state a real daemon presents to a
        // peer session: `materialize` resolves its write target from the link
        // table on every call, and `wait_group_ready` defers a live link whose
        // startup never registered a gate.
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);
        let transports = new_test_transports().await;
        let session = {
            let __state = state.clone();
            let __store = store.clone();
            let __roots = sync_roots;
            crate::permissive_runtime(
                {
                    let __replica_engine = yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(&__state, __store.clone());
                    PeerSyncSession::over_substrate(
                        "device-b".to_string(),
                        "device-a".to_string(),
                        __state.clone()
                            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
                        __replica_engine,
                        __store.clone(),
                        vec![GROUP.to_string()],
                        transports,
                        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
                    )
                },
                "device-b",
                __state,
                __store,
                __roots,
            )
        };

        // No injected fault: the real eager materialize runs to completion.
        let out_path = sync_root.join("doc.txt");
        session
            .convergence
            .materialize(
                &session.driver(),
                GROUP,
                &crate::payload_for(&record),
                MaterializationPolicy::Eager,
                "device-a",
                None,
            )
            .await
            .expect("a clean materialize must succeed");
        assert_eq!(std::fs::read(&out_path).unwrap(), content, "the file must be materialized");
        assert_eq!(
            state
                .materialization_state_repository()
                .get_materialization_state(GROUP, "doc.txt")
                .unwrap(),
            Some(MaterializationState::Present)
        );
        // The crux: the success path cleared the intent after the durable rename.
        assert!(
            !state
                .materialization_intent_repository()
                .has_materialization_intent(GROUP, "doc.txt")
                .unwrap(),
            "a completed materialize must leave NO materialization intent"
        );

        // The user deletes the file while the daemon is stopped. The row is still
        // Hydrated, blocks still present, and — because the intent was cleared —
        // this is a genuine offline delete, not a crash.
        std::fs::remove_file(&out_path).unwrap();
        let report = yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            state.as_ref(),
            store.as_ref(),
            &sync_root,
            GROUP,
            yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

        assert!(
            report.reconstructed.is_empty(),
            "a cleanly-materialized-then-offline-deleted file must NOT be reconstructed"
        );
        assert_eq!(
            report.offline_deleted,
            vec!["doc.txt".to_string()],
            "the missing file with no intent must be classified as an offline deletion"
        );
        assert!(!out_path.exists(), "repair must not resurrect the offline-deleted file");
    }
}
