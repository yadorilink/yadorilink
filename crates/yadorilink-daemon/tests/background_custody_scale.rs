//! What a background cycle costs, measured rather than asserted about.
//!
//! The defect this design closes was a cost, not a correctness bug: the
//! background health check reused the action-time proof, so refreshing a
//! status indicator issued one round-trip and one whole-file re-read per
//! durability root, every ninety seconds. At eight thousand roots that is
//! eight thousand of each.
//!
//! So the thing to pin is the shape of the cost, not a wall-clock number. A
//! cycle's request count must not depend on how many roots a group has, and
//! must not depend on how many peers are connected multiplied by it.
//!
//! # Why the measuring tests hold a lock
//!
//! The counters `io_diag` and `custody_diag` keep are process-global — that
//! is what lets a benchmark read them from a running daemon without a seam
//! through every layer. Two tests measuring in the same process interleave
//! and both come out wrong, and the failure is not subtle: arming is global
//! too, so one test finishing disarms the counters under another that is
//! still running, and that one then measures a cycle as having asked
//! nothing.
//!
//! Which is exactly what happened here once a second measuring test was
//! added next to the first. So [`MEASURING`] makes the exclusion a fact
//! rather than a note: every test that reads a counter holds it for its
//! whole body. Nothing here may be written to run alongside anything else in
//! this file.
//!
//! # Why this one may run on a tmpfs and the write-path benchmark may not
//!
//! Everything asserted here is a COUNT: requests issued, block reads caused.
//! Counts do not depend on what filesystem the stores sit on, so the default
//! temporary directory is fine and the numbers mean the same thing anywhere.
//!
//! Its sibling `root_set_generation_write_cost` asserts a DURATION RATIO, and
//! that one refuses to run on a memory-backed filesystem, because the cost it
//! is about is a page write and a tmpfs has none. Keeping the distinction
//! explicit in both places is cheaper than rediscovering it.
//!
//! # The counters live on the peer that ANSWERS
//!
//! A custody query costs the responder a block read; the asker learns
//! nothing from its own question. Reading the asker's counters reports zero
//! for work that really happened, which looks exactly like a cycle that
//! verified nothing. Here both daemons are in one process, so one set of
//! counters covers both — but the assertions still say which side they are
//! about, because the day this becomes two processes that distinction is
//! the whole measurement.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{
    connect_two_daemons, ensure_device_signing_key, open_file_backed_replica_coordinator,
};
use yadorilink_daemon::background_custody::BackgroundCustodyOutcome;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::io_diag;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::custody_diag;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "scale-group";

/// Held for the whole body of every test that reads a global counter. See
/// this module's own header for what happens without it.
///
/// Poisoning is ignored deliberately: a panicking measurement has already
/// failed its own test, and refusing to run the others afterwards would turn
/// one failure into several and hide which was first.
static MEASURING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Enough roots that a per-root cost could not hide in noise, and few enough
/// that a debug build finishes. The whole-pass version would issue this many
/// round-trips and this many block reads per cycle; the point of the
/// assertions below is that the number they find is a small constant, not
/// that it is smaller than this.
const ROOTS: usize = 400;

struct Daemon {
    state: Arc<DaemonState>,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
    _root: tempfile::TempDir,
}

fn new_daemon(device_id: &str) -> Daemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.to_string(), Arc::new(sync_state), store);
    ensure_device_signing_key(&state);
    let root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), GROUP)
        .unwrap();
    Daemon { state, _store_dir: store_dir, _index_dir: index_dir, _root: root }
}

/// Puts `data` in `daemon`'s store, records its group provenance, indexes it
/// at `path`, and marks it materialized — everything a device needs to look
/// like one genuinely holding that file.
fn hold_file(daemon: &Daemon, path: &str, data: &[u8]) -> FileRecord {
    let hash_hex = daemon.state.block_store.put(data).unwrap();
    let hash = hex::decode(&hash_hex).unwrap();
    daemon
        .state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    let record = FileRecord {
        path: path.to_string(),
        size: data.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash, offset: 0, size: data.len() as u32 }],
        deleted: false,
    };
    let permit = RootCommitPermit::for_tests();
    daemon
        .state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(GROUP, &record, &permit)
        .unwrap();
    let on_disk = daemon._root.path().join(path);
    std::fs::write(&on_disk, data).unwrap();
    // `Present` alone says only that an object exists; the proof is what a
    // device's claim to hold the row's version stands on.
    yadorilink_daemon::test_support::seed_prior_cycle_proof(
        &daemon.state.replica_coordinator,
        GROUP,
        path,
        &on_disk,
        &permit,
    );
    record
}

fn custody_block_reads() -> u64 {
    io_diag::snapshot()
        .into_iter()
        .find(|s| s.name == "block_read_custody_evidence")
        .map(|s| s.calls)
        .unwrap_or(0)
}

/// A/B/G in one process, in order, with the counters reset between phases.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(
    clippy::await_holding_lock,
    reason = "the guard serializes this binary's measuring tests for their whole run; \
              holding it across awaits is the point"
)]
async fn a_background_cycle_costs_the_same_whatever_the_group_holds() {
    let _measuring = MEASURING.lock().unwrap_or_else(|p| p.into_inner());
    support::ensure_isolated_config_dir();
    io_diag::set_enabled(true);

    let a = new_daemon("device-a");
    let b = new_daemon("device-b");
    for i in 0..ROOTS {
        let content = format!("file {i}'s content, distinct enough to hash differently");
        let path = format!("f{i:05}.bin");
        hold_file(&a, &path, content.as_bytes());
        hold_file(&b, &path, content.as_bytes());
    }

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    a.state.authority.set_peer_group_full_replica("device-b", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ---- A: one background cycle, one group, one candidate peer ----
    io_diag::reset();
    let before = custody_diag::stats();
    let outcome = b.state.refresh_custody_confirmation(GROUP).await;
    let after = custody_diag::stats();
    let cycle_requests = after.requests - before.requests;
    let cycle_handoff_requests = after.requests_for_handoff - before.requests_for_handoff;
    let cycle_custody_reads = custody_block_reads();

    assert_eq!(outcome, BackgroundCustodyOutcome::Corroborated);
    assert_eq!(
        cycle_handoff_requests, 0,
        "a background cycle must issue no per-root handoff query at all -- {ROOTS} roots, \
         {cycle_handoff_requests} queries"
    );
    assert_eq!(
        cycle_requests, 0,
        "nor any other per-version custody query: the cycle asks one question about the group"
    );
    assert_eq!(
        cycle_custody_reads, 0,
        "and the peer answering it reads no block and re-hashes nothing -- this is the entire \
         difference between the health check and the proof"
    );

    // ---- B: the proof is intact, and still costs what it costs ----
    io_diag::reset();
    let before = custody_diag::stats();
    assert!(
        b.state.another_full_replica_is_ready(GROUP).await,
        "the action-time proof still confirms the same peer"
    );
    let after = custody_diag::stats();
    let proof_requests = after.requests_for_handoff - before.requests_for_handoff;
    let proof_reads = custody_block_reads();

    assert_eq!(
        proof_requests as usize, ROOTS,
        "the proof verifies every durability root, one query each -- if this number ever drops, \
         the proof has been weakened, not the monitor made cheaper"
    );
    assert_eq!(
        proof_reads as usize, ROOTS,
        "and every query makes the responder read that version's block back in full"
    );

    // ---- one candidate peer: one summary RPC, not {ROOTS} ----
    io_diag::reset();
    let before = custody_diag::stats();
    let outcome = b.state.refresh_custody_confirmation(GROUP).await;
    let after = custody_diag::stats();
    assert_eq!(outcome, BackgroundCustodyOutcome::Corroborated);
    assert_eq!(
        after.summary_requests - before.summary_requests,
        1,
        "one candidate peer costs one group-level RPC"
    );

    io_diag::set_enabled(false);
}

/// **G: the cycle's network cost is one RPC per candidate peer, and does not
/// multiply by the root count.**
///
/// The interesting number here is *not* zero. A background check that asked
/// nothing at all would have to explain where its freshness came from; this
/// one asks every candidate, every cycle, and the requirement is that the
/// count be `O(peers)` rather than `O(peers x roots)`.
///
/// So all three quantities are asserted together at 1, 4 and 8 peers: the
/// group-level RPCs (which must track the peer count), the per-root custody
/// queries (which must stay at zero), and the responder-side block reads
/// (likewise). Asserting only the zeros would pass just as happily against
/// an implementation that had stopped asking anyone.
///
/// `ROOTS_FOR_PEER_SCALING` is deliberately well above one: at 200 roots,
/// `P x R` is 200/800/1600 against a `P` of 1/4/8, so the two shapes cannot
/// be confused for each other by any amount of noise.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(
    clippy::await_holding_lock,
    reason = "the guard serializes this binary's measuring tests for their whole run; \
              holding it across awaits is the point"
)]
async fn the_cycle_costs_one_rpc_per_peer_and_none_per_root() {
    let _measuring = MEASURING.lock().unwrap_or_else(|p| p.into_inner());
    const ROOTS_FOR_PEER_SCALING: usize = 200;
    const PEER_COUNTS: [usize; 3] = [1, 4, 8];

    support::ensure_isolated_config_dir();
    io_diag::set_enabled(true);

    let files: Vec<(String, String)> = (0..ROOTS_FOR_PEER_SCALING)
        .map(|i| {
            (format!("g{i:05}.bin"), format!("file {i}'s content for the peer-scaling measurement"))
        })
        .collect();

    let asker = new_daemon("device-asker");
    for (path, content) in &files {
        hold_file(&asker, path, content.as_bytes());
    }

    // Every peer holds the same content as the asker, so each is a genuine
    // candidate and the cycle has to ask all of them before one answers.
    let mut peers = Vec::new();
    for p in 0..*PEER_COUNTS.last().expect("non-empty") {
        let id = format!("device-peer-{p}");
        let peer = new_daemon(&id);
        for (path, content) in &files {
            hold_file(&peer, path, content.as_bytes());
        }
        peers.push((id, peer));
    }

    let mut connected = 0usize;
    for &wanted in &PEER_COUNTS {
        while connected < wanted {
            let (id, peer) = &peers[connected];
            connect_two_daemons(
                &asker.state,
                "device-asker",
                &peer.state,
                id,
                &[GROUP.to_string()],
            )
            .await;
            asker.state.authority.set_peer_group_full_replica(id, GROUP, true);
            peer.state.authority.set_peer_group_full_replica("device-asker", GROUP, true);
            connected += 1;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            asker.state.custody_candidate_peer_count_for_tests(GROUP),
            wanted,
            "the premise: exactly {wanted} peers are worth asking"
        );

        io_diag::reset();
        let before = custody_diag::stats();
        let outcome = asker.state.refresh_custody_confirmation(GROUP).await;
        let after = custody_diag::stats();

        let summary_rpcs = after.summary_requests - before.summary_requests;
        let per_root = after.requests_for_handoff - before.requests_for_handoff;
        let reads = custody_block_reads();
        println!(
            "peers={wanted} roots={ROOTS_FOR_PEER_SCALING}: summary_rpcs={summary_rpcs} \
             per_root_rpcs={per_root} custody_block_reads={reads}"
        );

        assert_eq!(outcome, BackgroundCustodyOutcome::Corroborated);
        assert_eq!(
            summary_rpcs as usize, wanted,
            "the cycle asks each candidate once: expected {wanted} group-level RPCs, got \
             {summary_rpcs}. Zero would mean it stopped asking anyone, and would need a \
             different account of where its freshness comes from"
        );
        assert_eq!(
            per_root, 0,
            "and none per root -- the shape being excluded is {wanted} x \
             {ROOTS_FOR_PEER_SCALING}"
        );
        assert_eq!(reads, 0, "and no responder reads a block to answer");
    }

    io_diag::set_enabled(false);
}
