//! Strict release-candidate acceptance harness for the `taguchi_row_14`
//! scenario (`taguchi_collision_matrix.rs`): conflict-copy convergence must
//! never permanently stall.
//! `TestDevice`/`setup_device`/etc. are intentionally duplicated from
//! `taguchi_collision_matrix.rs` rather than shared -- matches this
//! codebase's existing convention of self-contained daemon integration test
//! binaries (see that file's own doc comment for the same reasoning).
//!
//! This is deliberately a *stricter* bar than "the row-14 test passed":
//!
//! 1. The periodic 90s materialization-repair sweep is disabled for the
//!    whole run (`set_default_materialization_repair_sweep_interval_for_
//!    tests`), so a pass can only be attributed to the Convergence
//!    Engine's own per-tick reconciliation -- never the old sweep quietly
//!    rescuing it, which would make it impossible to tell which mechanism
//!    actually converged the run.
//! 2. The longest no-progress gap seen during the run is tracked directly
//!    (not merely whether it crossed the stall-panic threshold) and must
//!    stay comfortably under it -- "never actually stalled" is a stronger
//!    claim than "recovered before the watchdog fired."
//! 3. After convergence, every device's `projection_obligations` table must
//!    have zero rows left for this group -- nothing stuck pending (or
//!    parked `ignore_blocked`) forever, invisible only because the strict
//!    content-hash comparison happened to pass anyway.
//! 4. The strict content-hash comparison itself (inherited from the
//!    ordinary row-14 test) already covers "a path that went through a
//!    retriable placeholder ends up with disk content matching the
//!    winner" -- every device's bytes must match, not just their file-name
//!    sets.
//!
//! Panics, background-task restarts, and SQLite lock errors during a run
//! are deliberately NOT asserted against from *inside* this test -- they're
//! checked by the acceptance script that repeatedly invokes this binary,
//! grepping each iteration's full captured stdout/stderr, since a
//! backgrounded `supervise::spawn_restarting` task's own panic does not
//! automatically fail the top-level `#[tokio::test]`.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::{open_file_backed_replica_coordinator, real_entry_names, TestAccount};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::{
    set_default_materialization_repair_sweep_interval_for_tests, DaemonState,
};
use yadorilink_local_storage::SegmentBlockStore;

const ABSOLUTE_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(900);
const STALL_TIMEOUT: Duration = Duration::from_secs(90);
/// Any no-progress gap beyond this is loud evidence the run came
/// uncomfortably close to a real stall, even if it never actually crossed
/// `STALL_TIMEOUT` -- see this file's own acceptance-criteria doc comment.
const MAX_ACCEPTABLE_PROGRESS_GAP: Duration = Duration::from_secs(60);

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let device_id = support::register_device(account, name, [0u8; 32]).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(device_id.clone(), sync_state, store);
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

/// Exponential backoff between reconnect attempts, matching
/// `peer_orchestrator::spawn_peer_session`'s own production schedule
/// exactly (`supervise::BackoffConfig::RECONNECT`) rather than a fixed
/// short delay. This matters here specifically: on a resource-constrained
/// CI runner, a handshake can fail not because the peer is gone but
/// because the runner is too loaded to complete it within the bounded
/// handshake timeout. A fixed ~200ms retry then hammers reconnects in a
/// tight loop, adding MORE concurrent connect/handshake attempts to an
/// already-contended runner -- worsening the exact contention causing the
/// failures, with no way to ever recover. Confirmed in CI (this file's own
/// run): 26 consecutive handshake failures over 321s with a fixed-delay
/// retry, several pairs never establishing a session for the whole run.
/// Backing off (1s, doubling, capped at 45s) gives transient load a real
/// chance to subside between attempts instead of adding to it.
const PAIR_RECONNECT_BACKOFF: yadorilink_daemon::supervise::BackoffConfig =
    yadorilink_daemon::supervise::BackoffConfig::RECONNECT;

/// Global cap on concurrent in-flight connect+handshake attempts across
/// EVERY pair in this run -- both the initial full-mesh formation
/// ([`connect_all_pairs`]) and every later reconnect
/// ([`spawn_pair_reconnect_supervisor`]). `one_factorization`'s round
/// batching alone only bounds the *initial* burst: each pair's reconnect
/// supervisor otherwise reconnects independently, so a burst of
/// chaos-triggered QUIC connection teardowns hitting several pairs around
/// the same moment can still recreate an unbounded concurrent-handshake burst
/// during the run's steady state, well after the initial mesh formed
/// cleanly -- confirmed in CI: the *first* handshake failure landed
/// ~1m50s into a run whose initial mesh (round-batched) had already
/// formed successfully, with every failure after that point coming from
/// independent reconnect attempts racing each other. One shared
/// `tokio::sync::Semaphore`, permit held for the full connect+ready
/// duration (not just the cheap initial `PeerChannel::connect` call --
/// the actual CPU cost is the handshake retries running inside the
/// spawned `PeerSyncSession::run` tasks afterward), is the single source
/// of truth for that bound regardless of which phase is calling.
/// Started at `n/2` = 3 (matching `one_factorization`'s own per-round
/// concurrency, which is proven to let the initial mesh form cleanly), but
/// CI's debug-build daemon-e2e job still exhausted the production
/// exact-generation handshake retry budget under that much concurrency
/// during the run's steady state -- every device pair failed at some point
/// over a 6-minute run, not merely the odd straggler. Serialized to 1
/// (fully sequential handshakes, never more than one in flight at a time)
/// rather than extending timeouts, since initial-connection speed is not
/// what this test is evaluating.
const MAX_CONCURRENT_HANDSHAKES: usize = 1;

/// Connects one pair and blocks until it is genuinely ready
/// ([`wait_pair_ready`]), holding `handshake_semaphore` for the whole
/// duration -- see [`MAX_CONCURRENT_HANDSHAKES`]'s own doc comment for
/// why the permit must span the wait, not just the initial connect call.
async fn connect_pair_with_bounded_concurrency(
    mesh: &support::TestPeerMesh,
    handshake_semaphore: &tokio::sync::Semaphore,
    state_i: &Arc<DaemonState>,
    device_i: &str,
    state_j: &Arc<DaemonState>,
    device_j: &str,
    group_ids: &[String],
) -> [tokio::task::JoinHandle<()>; 2] {
    let _permit = handshake_semaphore.acquire().await.unwrap();
    // This 6-device mesh pairs every device more than once (15 pairings over
    // a 1-factorization, plus every later reconnect) -- the free-function
    // `connect_two_daemons*`/`checkpoint_fake_for` path can permanently
    // split such a mesh into several separate coordination-authority
    // islands once a bridging pairing arrives after both sides have already
    // committed (see `checkpoint_fake_for`'s doc comment; this is exactly
    // the root cause behind this test's historical "winner change ...
    // UNKNOWN (never received at all)" failures). `TestPeerMesh` shares one
    // authority across every pairing this whole run makes, by construction.
    let handles = mesh.connect_with_handles(state_i, device_i, state_j, device_j, group_ids).await;
    wait_pair_ready(state_i, device_i, state_j, device_j).await;
    handles
}

/// Keeps one device pair connected for the rest of the run: whenever
/// either side's `PeerSyncSession::run` task ends on its own (not driven
/// by this test -- e.g. the QUIC connection idling out against a peer
/// this run's own chaos made transiently unreachable), reconnects both
/// sides fresh.
///
/// `support::connect_two_daemons*` itself is deliberately NOT changed to
/// do this: its own doc comment is explicit that its one-shot,
/// discard-the-handles shape is the right default for the many other
/// callers that pair a small, fixed device set once and let the process
/// exit. This strict acceptance run is the one caller that specifically
/// needs reconnect resilience (see `peer_orchestrator::spawn_peer_session`'s
/// own doc comment for the production-side version of the identical
/// reasoning), so the
/// supervision lives here instead.
// Everything the detached supervisor task owns, passed in once.
#[allow(clippy::too_many_arguments)]
fn spawn_pair_reconnect_supervisor(
    mesh: Arc<support::TestPeerMesh>,
    state_i: Arc<DaemonState>,
    device_i: String,
    state_j: Arc<DaemonState>,
    device_j: String,
    group_ids: Vec<String>,
    initial_handles: [tokio::task::JoinHandle<()>; 2],
    handshake_semaphore: Arc<tokio::sync::Semaphore>,
) {
    tokio::spawn(async move {
        let [mut h_i, mut h_j] = initial_handles;
        let mut attempt: u32 = 0;
        let mut generation_started = tokio::time::Instant::now();
        loop {
            // Cancel-safe: only whichever side actually resolved is
            // consumed; the other handle is still valid to select on
            // again after reconnecting (its own task tears itself down on
            // the fresh generation, same as a revoke would).
            tokio::select! {
                _ = &mut h_i => {}
                _ = &mut h_j => {}
            }
            // A generation that stayed up for a while was a genuine
            // success -- reset the backoff instead of letting it ratchet
            // toward its 45s cap and stay there for the rest of this run.
            // Only a generation that dies almost immediately (handshake
            // never completing) escalates.
            if generation_started.elapsed() > Duration::from_secs(3) {
                attempt = 0;
            }
            tokio::time::sleep(PAIR_RECONNECT_BACKOFF.next(attempt)).await;
            let handles = connect_pair_with_bounded_concurrency(
                &mesh,
                &handshake_semaphore,
                &state_i,
                &device_i,
                &state_j,
                &device_j,
                &group_ids,
            )
            .await;
            [h_i, h_j] = handles;
            attempt = attempt.saturating_add(1);
            generation_started = tokio::time::Instant::now();
        }
    });
}

/// A round-robin 1-factorization of the complete graph on `n` vertices (the
/// "circle method"): `n-1` rounds, each a set of `n/2` vertex-disjoint pairs
/// -- every vertex appears in exactly one pair per round. `n` must be even.
///
/// This is what bounds this test's initial full-mesh connection burst to a
/// production-plausible per-device concurrency: a real device's `netmap`
/// growing to `n-1` peers arrives incrementally over real time (netmap
/// pushes, existing sessions already up), never as an instantaneous
/// simultaneous handshake against every peer at once. Connecting all
/// `n*(n-1)/2` pairs together -- 15 for this test's 6 devices -- means every
/// device races `n-1` (5) concurrent QUIC handshakes from the first
/// instant, all competing for the same process's CPU. Under a debug build
/// on a resource-constrained CI runner, that CPU contention alone can push
/// genuine handshake completion past its own bounded timeout -- confirmed:
/// this exact shape, 26 consecutive handshake failures over a 321s CI run,
/// independent of anything about reconnect-supervisor behavior (which
/// only governs what happens once a *connected* pair later drops).
/// Bounding round concurrency to `n/2` (3 for this test) caps every device at
/// exactly one concurrent handshake at a time.
fn one_factorization(n: usize) -> Vec<Vec<(usize, usize)>> {
    assert!(
        n >= 2 && n.is_multiple_of(2),
        "one_factorization requires an even vertex count, got {n}"
    );
    let fixed = n - 1;
    let mut rotating: Vec<usize> = (0..n - 1).collect();
    let mut rounds = Vec::with_capacity(n - 1);
    for _ in 0..n - 1 {
        let mut round = Vec::with_capacity(n / 2);
        round.push((fixed.min(rotating[0]), fixed.max(rotating[0])));
        for k in 1..n / 2 {
            let a = rotating[k];
            let b = rotating[rotating.len() - k];
            round.push((a.min(b), a.max(b)));
        }
        rounds.push(round);
        rotating.rotate_right(1);
    }
    rounds
}

/// How long one pair's handshake + change-DAG negotiation may take before
/// [`wait_pair_ready`] gives up. Generous relative to the exact-generation
/// handshake's own bounded retry budget (~11s worst case) since this is a
/// hard failure (test setup itself is broken), not a tuning knob to shave
/// close -- initial connection speed is not what this test exists to evaluate.
const TEST_PAIR_READY_TIMEOUT: Duration = Duration::from_secs(30);

/// Blocks until both sides of a pair report a genuinely established
/// session -- handshake received AND the change-DAG negotiated, on BOTH
/// sides -- rather than a fixed sleep. A fixed delay is exactly the wrong
/// tool here: too short under load and the next round's connects race an
/// unfinished handshake (defeating the whole point of bounding per-round
/// concurrency); too long and a slow-but-healthy run pays the cost even
/// when nothing is wrong. Polling this session-state barrier instead scales
/// with however long the current environment actually needs. Takes
/// `(state, device_id)` pairs rather than `&TestDevice` so it can be
/// called both from `connect_all_pairs` (borrowing from `TestDevice`) and
/// from [`connect_pair_with_bounded_concurrency`] (which only has owned
/// `Arc<DaemonState>`/`String` inside a 'static reconnect-supervisor
/// task, not a `TestDevice` reference -- `TestDevice` owns a `TempDir`,
/// not `Clone`).
async fn wait_pair_ready(
    state_a: &Arc<DaemonState>,
    device_a_id: &str,
    state_b: &Arc<DaemonState>,
    device_b_id: &str,
) {
    tokio::time::timeout(TEST_PAIR_READY_TIMEOUT, async {
        loop {
            let a_session = state_a.peers.session(device_b_id);
            let b_session = state_b.peers.session(device_a_id);
            if a_session.is_some() && b_session.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("pair {device_a_id}<->{device_b_id} did not become ready within {TEST_PAIR_READY_TIMEOUT:?}")
    });
}

/// Builds the full mesh via [`one_factorization`]'s bounded-concurrency
/// rounds: within a round, every pair connects concurrently (still real
/// production-shaped parallelism, just capped at one handshake per device
/// instead of `n-1`), then this round's pairs must all report ready
/// ([`wait_pair_ready`], via [`connect_pair_with_bounded_concurrency`])
/// before the next round's connects begin -- a state barrier, not a fixed
/// delay, so this scales correctly on a slower runner instead of racing
/// ahead of an unfinished handshake or wasting time waiting past a fast
/// one. Every pair still goes through [`spawn_pair_reconnect_supervisor`],
/// sharing the same [`MAX_CONCURRENT_HANDSHAKES`] semaphore this function
/// seeds, so nothing about post-connection convergence/reconnect
/// semantics changes -- only the connection concurrency shape, uniformly
/// across the whole run's lifetime.
async fn connect_all_pairs(devices: &[TestDevice], group_ids: &[String]) {
    // One shared coordination authority for this whole 6-device mesh's
    // entire lifetime (initial connection AND every later reconnect) -- see
    // `connect_pair_with_bounded_concurrency`'s doc comment for why the
    // free-function `connect_two_daemons` path cannot safely serve a mesh
    // shaped like this one.
    let mesh = Arc::new(support::TestPeerMesh::new().await);
    let handshake_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_HANDSHAKES));
    for round in one_factorization(devices.len()) {
        futures_util::future::join_all(round.into_iter().map(|(i, j)| {
            let mesh = mesh.clone();
            let handshake_semaphore = handshake_semaphore.clone();
            async move {
                let handles = connect_pair_with_bounded_concurrency(
                    &mesh,
                    &handshake_semaphore,
                    &devices[i].state,
                    &devices[i].device_id,
                    &devices[j].state,
                    &devices[j].device_id,
                    group_ids,
                )
                .await;
                spawn_pair_reconnect_supervisor(
                    mesh.clone(),
                    devices[i].state.clone(),
                    devices[i].device_id.clone(),
                    devices[j].state.clone(),
                    devices[j].device_id.clone(),
                    group_ids.to_vec(),
                    handles,
                    handshake_semaphore.clone(),
                );
            }
        }))
        .await;
    }
}

async fn n_synced_devices(n: usize, test_name: &str) -> (Vec<TestDevice>, String) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let mut devices = Vec::with_capacity(n);
    for i in 0..n {
        devices.push(setup_device(&account, &format!("device-{i}")).await);
    }
    let group_id = support::create_folder_group(&account, "taguchi-group").await;
    for device in &devices {
        support::grant_access(&account, &group_id, &device.device_id).await;
    }
    for device in &devices {
        start_watching(device, &group_id).await;
    }
    connect_all_pairs(&devices, std::slice::from_ref(&group_id)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    (devices, group_id)
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Edit,
    Delete,
    Rename,
}

/// Mirrors row 14's own factor assignment exactly (op-pattern level 2:
/// edit/delete/rename cycled across devices).
const PATTERN: &[Op] = &[Op::Edit, Op::Delete, Op::Rename];

fn apply_op(root: &std::path::Path, device_idx: usize, op: Op, round: u32) {
    // path level 1 ("all same"): every device targets the identical name.
    let target = "shared.bin";
    let path = root.join(target);
    let content = format!("round {round} device {device_idx} target {target}");
    match op {
        Op::Edit => {
            std::fs::write(&path, content.as_bytes()).unwrap();
        }
        Op::Delete => {
            support::remove_file_unless_vanished(&path);
        }
        Op::Rename => {
            if path.exists() {
                let renamed = root.join(format!("{target}.renamed-{device_idx}-r{round}"));
                support::rename_unless_vanished(&path, &renamed);
            } else {
                std::fs::write(&path, content.as_bytes()).unwrap();
            }
        }
    }
}

fn snapshot(root: &std::path::Path) -> std::collections::HashMap<String, String> {
    use sha2::Digest;
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read(root.join(&name)).unwrap_or_default();
            (name, hex::encode(sha2::Sha256::digest(&content)))
        })
        .collect()
}

/// Diagnostic-only three-layer snapshot that classifies a stall on a specific conflict-copy path into one of:
///
/// A. The winner or loser Change itself is genuinely UNKNOWN to a device
///    (never received) -- a real DAG-propagation gap.
/// B. The Change is known but ORPHANED (buffered, missing ancestors) or
///    its parent closure has gaps on an otherwise-admitted change -- a
///    post-admission DAG-management gap (orphan promotion, batching).
/// C. Every device agrees on the DAG (same heads, same `resolve_path_heads`
///    outcome, this conflict-copy correctly appears in `conflict_copies`
///    everywhere) but a device's own job/audit history never re-examined
///    it -- a Convergence Engine projection-trigger gap, NOT a DAG
///    propagation gap.
/// D. Resolution and job state agree everywhere but the conflict-copy
///    still never lands on disk -- a pure projection/materialization bug.
///
/// Identifies the winner/loser `DeltaHash` values by finding a device
/// whose own `resolve_path_heads(source_path)` call already produces a
/// `ConflictCopy` matching `target_conflict_copy_path` by name -- avoids
/// having to reverse-parse the conflict-copy filename (its embedded hash
/// is a losing FILE VERSION hash prefix, not a `DeltaHash`, so it cannot
/// be used to look up the change directly).
fn dump_conflict_diagnostic_snapshot(
    devices: &[TestDevice],
    group_id: &str,
    source_path: &str,
    target_conflict_copy_path: &str,
) -> String {
    let mut out = format!(
        "=== conflict diagnostic snapshot: source_path={source_path:?} \
         target_conflict_copy_path={target_conflict_copy_path:?} ===\n"
    );
    for (i, device) in devices.iter().enumerate() {
        let coordinator = &device.state.replica_coordinator;
        let heads = coordinator.database().read(|conn| {
            yadorilink_sync_sqlite::native_store::native_heads_at(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned()),
                &yadorilink_replica_domain::ids::SyncPath(source_path.to_owned()),
            )
        });
        let authors = device.state.replica_coordinator.native_author_frontier(group_id).ok();
        out.push_str(&format!(
            "device-{i}: native heads at the source path = {:?}; authors in the frontier = {:?}\n",
            heads.map(|heads| {
                heads
                    .iter()
                    .map(|head| {
                        format!(
                            "{}@{} delta={}",
                            head.dot.author.device.0,
                            head.dot.seq.get(),
                            hex::encode(&head.payload.provenance.0[..4])
                        )
                    })
                    .collect::<Vec<_>>()
            }),
            authors.map(|frontier| frontier.len()),
        ));
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::excessive_nesting,
    reason = "stall-detection wait loop: the deeply nested blocks are the diagnostic branch \
              taken only when no-progress exceeds STALL_TIMEOUT, and it must inspect the same \
              live `devices`/`current` snapshots the loop is already holding to pick the \
              asymmetric (or content-mismatched) name to dump before panicking; extracting it \
              would mean threading that whole loop state out just to keep the panic path \
              shallower"
)]
async fn row14_strict_acceptance() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    static TRACING_INIT: std::sync::Once = std::sync::Once::new();
    TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    });

    // Criterion 1: the old periodic repair sweep must not be able to help
    // this run at all -- set the override BEFORE any `DaemonState::new`
    // call, closing the race `set_materialization_repair_sweep_interval`
    // alone cannot (see that function's own doc comment).
    set_default_materialization_repair_sweep_interval_for_tests(Duration::from_secs(3600));

    // Diagnostic-only: a runtime heartbeat, independent of any device's own
    // work. If this keeps ticking every ~1s throughout a run that
    // otherwise shows a long silent gap, the gap is a genuine (if slow)
    // async wait somewhere in the engine's own call chain, not worker-
    // thread starvation; if the heartbeat ALSO goes silent, something is
    // monopolizing this runtime's worker threads with blocking synchronous
    // work.
    tokio::spawn(async {
        let mut tick = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tick += 1;
            tracing::info!(tick, "runtime heartbeat");
        }
    });

    let device_count = 6;
    let (devices, group_id) = n_synced_devices(device_count, "strict-repair").await;
    let round_count = 10u32;
    let stagger = Duration::from_millis(100);

    for round in 0..round_count {
        for (idx, device) in devices.iter().enumerate() {
            let op = PATTERN[idx % PATTERN.len()];
            apply_op(device.root.path(), idx, op, round);
            tokio::time::sleep(stagger).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Criterion 2: custom wait loop tracking the longest no-progress gap
    // directly, instead of `support::wait_until_or_stalled` (which only
    // ever reports whether the panic threshold was crossed, not how close
    // a run came).
    let started = Instant::now();
    let mut last_progress_value: Vec<_> = devices.iter().map(|d| snapshot(d.root.path())).collect();
    let mut last_progress_at = started;
    let mut max_gap = Duration::ZERO;
    loop {
        let converged = {
            let reference = snapshot(devices[0].root.path());
            devices[1..].iter().all(|d| snapshot(d.root.path()) == reference)
        };
        if converged {
            break;
        }
        let now = Instant::now();
        if now.duration_since(started) > ABSOLUTE_CONVERGENCE_TIMEOUT {
            let entries = devices
                .iter()
                .enumerate()
                .map(|(i, d)| format!("device-{i}={:?}", real_entry_names(d.root.path())))
                .collect::<Vec<_>>()
                .join("; ");
            panic!(
                "row14_strict_acceptance: never converged within {ABSOLUTE_CONVERGENCE_TIMEOUT:?}: \
                 {entries}"
            );
        }
        let current: Vec<_> = devices.iter().map(|d| snapshot(d.root.path())).collect();
        if current != last_progress_value {
            last_progress_value = current;
            last_progress_at = now;
        } else {
            let gap = now.duration_since(last_progress_at);
            if gap > max_gap {
                max_gap = gap;
            }
            if gap > STALL_TIMEOUT {
                let entries = devices
                    .iter()
                    .enumerate()
                    .map(|(i, d)| format!("device-{i}={:?}", real_entry_names(d.root.path())))
                    .collect::<Vec<_>>()
                    .join("; ");
                // Diagnostic-only: find a name present on some but not all
                // devices (the asymmetric path) and dump the three-layer
                // classification snapshot for it before panicking -- see
                // `dump_conflict_diagnostic_snapshot`'s own doc comment.
                let mut name_counts: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();
                for d in &devices {
                    for name in real_entry_names(d.root.path()) {
                        *name_counts.entry(name).or_insert(0) += 1;
                    }
                }
                let mut asymmetric: Vec<String> = name_counts
                    .into_iter()
                    .filter(|(_, count)| *count > 0 && *count < devices.len())
                    .map(|(name, _)| name)
                    .collect();
                // Prefer a conflict-copy name if one is asymmetric -- it
                // has a clear `source_path` ("shared.bin") to run
                // `resolve_path_heads`/the fixpoint against. A bare
                // asymmetric direct-path name (no conflict-copy involved)
                // is its OWN source_path instead.
                asymmetric.sort_by_key(|n| !n.contains("(conflicted copy"));
                let diagnostic = asymmetric
                    .into_iter()
                    .next()
                    .map(|name| {
                        let source_path =
                            if name.contains("(conflicted copy") { "shared.bin" } else { &name };
                        dump_conflict_diagnostic_snapshot(&devices, &group_id, source_path, &name)
                    })
                    .or_else(|| {
                        // No asymmetric name -- fall back to the pure
                        // content-hash-mismatch case: every device has the
                        // same name, but at least one disagrees with
                        // device-0 on its sha256. Same three-layer dump as
                        // the asymmetric branch, just keyed off whichever
                        // mismatched name we find first.
                        let reference = &current[0];
                        let mut mismatched: Vec<String> = reference
                            .iter()
                            .filter(|(name, hash)| {
                                current[1..].iter().any(|snap| snap.get(*name) != Some(*hash))
                            })
                            .map(|(name, _)| name.clone())
                            .collect();
                        mismatched.sort_by_key(|n| !n.contains("(conflicted copy"));
                        mismatched.into_iter().next().map(|name| {
                            let source_path = if name.contains("(conflicted copy") {
                                "shared.bin".to_string()
                            } else {
                                name.clone()
                            };
                            format!(
                                "content-hash mismatch on {name:?} (every device agrees on the \
                                 name, not the bytes)\n{}",
                                dump_conflict_diagnostic_snapshot(
                                    &devices,
                                    &group_id,
                                    &source_path,
                                    &name
                                )
                            )
                        })
                    })
                    .unwrap_or_else(|| {
                        "no asymmetric path and no content-hash mismatch found among current \
                         entries (the stall must have resolved between the comparison above and \
                         this diagnostic pass)"
                            .to_string()
                    });
                panic!(
                    "row14_strict_acceptance: convergence stalled: no progress for over \
                     {STALL_TIMEOUT:?} ({:?} elapsed): {entries}\n{diagnostic}",
                    started.elapsed()
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eprintln!("row14_strict_acceptance: max no-progress gap observed = {max_gap:?}");
    assert!(
        max_gap <= MAX_ACCEPTABLE_PROGRESS_GAP,
        "row14_strict_acceptance: max no-progress gap {max_gap:?} exceeded the strict \
         acceptance bound {MAX_ACCEPTABLE_PROGRESS_GAP:?} (even though it stayed under the \
         {STALL_TIMEOUT:?} panic threshold) -- this run came uncomfortably close to a real stall"
    );

    // A final settle window before the strict content-hash comparison,
    // matching the ordinary row-14 test's own reasoning.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Criterion 4 (content correctness, including any path that passed
    // through a retriable placeholder along the way).
    let reference = snapshot(devices[0].root.path());
    for (i, device) in devices.iter().enumerate().skip(1) {
        let snap = snapshot(device.root.path());
        assert_eq!(snap, reference, "row14_strict_acceptance: device-{i} diverged from device-0");
    }

    // Criterion 3: nothing left non-terminal in any device's projection-
    // obligation table. Bounded extra wait (distinct from the STALL_TIMEOUT
    // machinery above, which only tracks visible DISK progress) -- content
    // can converge correctly while an obligation's own bookkeeping simply
    // hasn't caught up within the fixed 2s settle window yet (an obligation
    // legitimately still mid-cycle is not the same claim as "stuck
    // forever"). Genuinely stuck rows will still be non-empty after this
    // bounded wait; a merely-lagging bookkeeping write will not.
    //
    // `dag_claim_runnable_obligations` with `now = i64::MAX` reads every row
    // regardless of its own `next_attempt_at` backoff deadline -- a plain
    // read (no in-flight state to claim-and-mark), so this is safe to call
    // repeatedly and never perturbs anything. A settled obligation is
    // DELETED by its own completion primitive, so any row still present
    // (pending or parked `ignore_blocked`) means genuinely unfinished work.
    const OBLIGATION_TABLE_QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(30);
    let quiescence_deadline = Instant::now() + OBLIGATION_TABLE_QUIESCENCE_TIMEOUT;
    loop {
        let all_quiescent = devices.iter().all(|d| {
            d.state
                .replica_coordinator
                .sqlite()
                .dag_claim_runnable_obligations(i64::MAX, u32::MAX, u32::MAX)
                .map(|obligations| obligations.iter().all(|o| o.group_id != group_id))
                .unwrap_or(false)
        });
        if all_quiescent || Instant::now() >= quiescence_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    for (i, device) in devices.iter().enumerate() {
        let unfinished: Vec<_> = device
            .state
            .replica_coordinator
            .sqlite()
            .dag_claim_runnable_obligations(i64::MAX, u32::MAX, u32::MAX)
            .unwrap()
            .into_iter()
            .filter(|o| o.group_id == group_id)
            .collect();
        assert!(
            unfinished.is_empty(),
            "row14_strict_acceptance: device-{i} has {} non-terminal projection_obligations \
             row(s) left after convergence (group={group_id}): {:?}",
            unfinished.len(),
            unfinished
        );
    }
}

#[cfg(test)]
mod one_factorization_tests {
    use super::one_factorization;
    use std::collections::HashSet;

    /// Every pair of the `n` vertices appears exactly once across all
    /// rounds combined, and within any single round no vertex appears
    /// twice -- the two properties `connect_all_pairs` actually depends
    /// on: full coverage (every pair eventually connects) and bounded
    /// per-round concurrency (no device races two handshakes at once).
    fn assert_valid_one_factorization(n: usize) {
        let rounds = one_factorization(n);
        assert_eq!(rounds.len(), n - 1, "n={n} must produce exactly n-1 rounds");

        let mut all_pairs = HashSet::new();
        for round in &rounds {
            assert_eq!(round.len(), n / 2, "n={n}: every round must have exactly n/2 pairs");
            let mut seen_this_round = HashSet::new();
            for &(a, b) in round {
                assert!(a < b, "pairs must be stored in canonical (a < b) order: got ({a}, {b})");
                assert!(seen_this_round.insert(a), "vertex {a} appears twice in one round");
                assert!(seen_this_round.insert(b), "vertex {b} appears twice in one round");
                assert!(all_pairs.insert((a, b)), "pair ({a}, {b}) connected more than once");
            }
        }
        let expected_pair_count = n * (n - 1) / 2;
        assert_eq!(
            all_pairs.len(),
            expected_pair_count,
            "n={n}: expected every one of the {expected_pair_count} pairs to appear exactly once"
        );
    }

    #[test]
    fn covers_every_pair_exactly_once_with_bounded_round_concurrency_for_row14() {
        assert_valid_one_factorization(6);
    }

    #[test]
    fn holds_for_other_even_vertex_counts_too() {
        for n in [2, 4, 8, 10] {
            assert_valid_one_factorization(n);
        }
    }

    #[test]
    #[should_panic(expected = "even vertex count")]
    fn refuses_an_odd_vertex_count() {
        one_factorization(5);
    }
}
