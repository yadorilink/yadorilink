//! Deterministic regression: durability must not stay stuck in
//! `Protecting` when content has no obtainable holder.
//!
//! Root cause: a full-replica device's `Remote` row can legitimately
//! have NO obtainable holder among current membership -- its sole
//! provenance-verified holder left the group, and every other current
//! peer explicitly refuses the fetch (`FetchOutcome::Rejected`, "no
//! verified group provenance"), not merely times out. `materialization:
//! Partial` alone cannot distinguish "still trying, may yet succeed" from
//! "genuinely, permanently gone", so `classify` stayed at `Protecting`
//! forever. Fixed via a new `DurabilityFacts::known_unobtainable_
//! required_content` fact (backed by a durable `block_fetch_refusals`
//! table, written only on an EXPLICIT peer refusal, never a transient
//! miss) that routes to the EXISTING `AtRisk` variant -- no new
//! `GroupDurabilityStatus` variant, per explicit user instruction. The
//! conflict/content record itself is NEVER auto-retired: an unobtainable
//! record may be a user's only surviving edit, and silently deleting the
//! metadata would turn real data loss into apparent convergence.
//!
//! This test constructs the scenario directly rather than racing the
//! soak's own chaos for it: X (an OnDemand device) authors unique
//! content that fully propagates and hydrates on N (the full replica)
//! normally -- no timing games needed. N's copy is then put back into
//! the exact state a "never got a chance to fetch it" full replica would
//! be in: `hydration::evict` (the same real production operation
//! `topology_soak_lane.rs`'s own `op_evict` exercises) demotes the row
//! to `Remote`, then the underlying block bytes are deleted
//! directly from N's own block store. The direct deletion is necessary
//! and deliberate, not a shortcut: `gc::run_sweep` never reclaims a
//! still-CURRENT version's blocks (a full replica is supposed to keep
//! serving its current content forever, regardless of local
//! materialization state -- confirmed live, `blocks_deleted == 0` on
//! every attempt), so eviction alone leaves N able to trivially
//! "re-fetch" from its own already-present bytes with no peer involved
//! at all. X then genuinely leaves the group
//! (`FakeCoordination::remove_device`), and M/W (which never
//! independently held X's content -- they are OnDemand and never fetch
//! eagerly) are asked by N's own periodic materialization-repair sweep
//! and explicitly refuse.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::fake_coordination::FakeCoordination;
use support::register_with_fake;
use support::topology::{
    fully_connected, link_on_demand, new_node, spawn_orchestrator, stand_up_canonical_topology,
};
use yadorilink_daemon::durability_service::GroupDurabilityStatus;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "durability_unobtainable_content=debug,\
             yadorilink_daemon=debug,\
             yadorilink_peer_session=debug",
        ))
        .with_test_writer()
        .try_init();
}

/// Test-only sweep interval for both the materialization-repair job (M/W's
/// explicit refusals) and the custody-confirmation job (`ever_
/// confirmation_swept`) -- production defaults to 90s for each, which
/// would make this test's own bounded waits either impractically long or
/// racy (see this file's own history: waiting on production's 90s
/// interval intermittently raced X's departure against the confirmation
/// job's very first sweep). Set once, before any `DaemonState` in this
/// test is constructed, per `set_default_..._sweep_interval_for_tests`'s
/// own doc comment.
const TEST_SWEEP_INTERVAL: Duration = Duration::from_secs(3);

/// Generous relative to `TEST_SWEEP_INTERVAL`: needs at least one sweep
/// for M and W to both be asked and both explicitly refuse (every live
/// candidate is asked every sweep -- see `MaterializationRepairJob::
/// run_once`'s own doc comment for why stopping at the first `Ok(_)` was
/// itself a starvation bug, fixed alongside this one).
const CONVERGENCE_BOUND: Duration = Duration::from_secs(60);

// This scenario forces eviction with `set_test_on_demand_allowed`,
// which satisfies `hydration::evict`'s own pipeline-connected gate, but not
// `evict_to_placeholder`'s Windows-only requirement (materialization_eviction.rs)
// of a recorded CfAPI placeholder identity and a real cfapi-host dehydration --
// there is no fake for either here, so eviction fails closed with
// `EvictionRejected` before this scenario's actual property (known-unobtainable
// content converges to `AtRisk`) is ever exercised. That fail-closed behavior is
// the correct production answer on Windows and must not be weakened to pass
// this test; giving it a real CfAPI double is future work, not attempted here.
#[cfg_attr(
    windows,
    ignore = "needs a CfAPI placeholder-identity test double; see the comment above"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn unobtainable_content_converges_to_at_risk_not_stuck_protecting() {
    init_tracing();
    yadorilink_daemon::daemon_state::set_default_materialization_repair_sweep_interval_for_tests(
        TEST_SWEEP_INTERVAL,
    );
    yadorilink_daemon::daemon_state::set_default_custody_confirmation_sweep_interval_for_tests(
        TEST_SWEEP_INTERVAL,
    );
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "durability-unobtainable-group".to_string();
    let (n, m, w, mut handles) = stand_up_canonical_topology(&fake, &group_id).await;

    // A second full-replica candidate, matching `topology_soak_lane.rs`'s
    // own `op_device_join` reasoning exactly: without this, N is
    // structurally the ONLY full-replica peer, and `classify` returns
    // `AtRisk` from the EARLIER `!any_other_full_replica_peer_configured`
    // precedence step -- which would make this test pass even with the
    // fix's own new precedence step (`known_unobtainable_required_
    // content`) completely broken. Declaring W here keeps that earlier
    // step satisfied throughout, so only the new step can produce AtRisk.
    fake.set_full_replica(&w.device_id, &group_id, true);

    // X: the sole author of unique content, about to leave.
    let x = new_node("durability-x-author");
    link_on_demand(&x, &group_id);
    register_with_fake(&fake, &x.state, &x.device_id, &[&group_id]).await;
    let x_runtime = spawn_orchestrator(fake.addr(), &x);
    handles.insert(x.device_id.clone(), x_runtime);

    // X joins after the canonical topology's own barrier has already run, so
    // nobody knows where its reconciliation substrate answers and it knows
    // where nobody else's does. Re-including n/m/w is idempotent: `record`
    // overwrites each entry with the identical value.
    //
    // Without this, all three canonical nodes are stopped at
    // `SubstrateNode::connect` for X ("No addressing information available")
    // while X itself authors and settles its own content perfectly well --
    // so the test fails at "n never indexed x's unique content", long before
    // it can reach the unobtainability it exists to check.
    support::topology::advertise_substrate_endpoints(&[&n, &m, &w, &x]).await;

    // Wait for X to reach real DAG-negotiated sessions with all three
    // canonical nodes before writing -- a write before negotiation
    // completes can be sent nowhere yet.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !(fully_connected(&x.state, &n.device_id)
        && fully_connected(&x.state, &m.device_id)
        && fully_connected(&x.state, &w.device_id))
    {
        if Instant::now() >= deadline {
            panic!("x never reached full mesh connectivity with n/m/w within 60s");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let unique_path = "x-authored-unique-content.bin";
    std::fs::write(x.root.path().join(unique_path), b"content only x ever holds").unwrap();

    // Wait for the content to fully hydrate on N normally -- no timing
    // games, this is the ordinary Eager-fetch path succeeding while X is
    // still online and reachable.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let hydrated = n
            .state
            .replica_coordinator
            .file_index_repository()
            .list_files(&group_id)
            .ok()
            .and_then(|files| files.into_iter().find(|f| f.path == unique_path))
            .is_some();
        if hydrated {
            break;
        }
        if Instant::now() >= deadline {
            panic!("n never indexed x's unique content within 60s");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let out_path = n.root.path().join(unique_path);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !out_path.exists() {
        if Instant::now() >= deadline {
            panic!("n never materialized x's unique content to disk within 60s");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Wait for `DurabilityConfirmationJob` to complete at least one sweep
    // (`ever_confirmation_swept`) BEFORE evicting/removing X -- otherwise
    // this races X's departure against the sweep's own first cycle, and a
    // sweep that hasn't landed at all yet keeps `classify` at `Unknown`
    // regardless of `known_unobtainable_required_content`, an earlier
    // precedence step this fix's own new step never overrides (by
    // design -- "haven't checked yet" must never be reported as
    // known-insufficient). `ever_confirmation_swept` flips true after ANY
    // completed sweep attempt, success or not (this topology's W is only
    // a coordination-plane full-replica DECLARATION, not an actual
    // content holder, so `peer_confirmed_custody`/`Protected` can never
    // be reached here -- waiting for that status would hang forever, a
    // real bug this file's own history hit). A few sweep intervals'
    // worth of margin is simplest and sufficient; there is no production
    // introspection API for the raw fact itself.
    tokio::time::sleep(TEST_SWEEP_INTERVAL * 3).await;

    // X's orchestrator is shut down before N's content is evicted (belt
    // and suspenders alongside the GC sweep below): kills X's live
    // sessions first, so nothing can re-serve N's about-to-be-evicted
    // content from X specifically during the brief eviction/GC window.
    handles.take_and_shutdown(&x.device_id).await;

    // The exact block hashes this path's CURRENT version references --
    // captured before eviction, since eviction only changes
    // `materialization_state`, never the row's own `blocks` list.
    let block_hashes: Vec<String> = n
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(&group_id, unique_path)
        .expect("get_file must not error")
        .expect("x's record must still exist on n before eviction")
        .blocks
        .iter()
        .map(|b| hex::encode(&b.hash))
        .collect();
    assert!(!block_hashes.is_empty(), "x's content must reference at least one block");

    // Manually evict it on N -- the same real production operation
    // `topology_soak_lane.rs`'s `op_evict` exercises, bypassing the
    // custody gate entirely for a full-replica device (see this file's
    // own module doc comment). Demotes the row to `Remote`, but
    // does NOT by itself remove the underlying bytes from N's own block
    // store -- and `gc::run_sweep` never will either, for a file that's
    // still the group's CURRENT version: GC only reclaims blocks with NO
    // live DAG-retention reference, and a full replica is SUPPOSED to
    // keep serving its current content forever regardless of local
    // materialization state (confirmed live: `run_sweep_for_test`
    // consistently reclaimed zero blocks here, `blocks_deleted == 0`
    // every attempt -- correct production behavior, not a bug). Deleting
    // the blocks directly from N's OWN block store is the only way to
    // put N in the state a full replica that had genuinely never
    // fetched this content would be in, without waiting for a real
    // supersede-and-retire cycle this scenario doesn't call for.
    //
    // Pausing N's own materialization-repair sweep (which would
    // otherwise re-hydrate trivially from these very blocks moments
    // after eviction, on a DIFFERENT worker thread this task's own code
    // ordering cannot preempt) and retrying the evict+delete pair until
    // every block is confirmed gone closes the same race this file's own
    // history already hit once with the GC-based approach.
    n.state.set_materialization_repair_sweep_interval(Duration::from_secs(3600));
    n.state.set_test_on_demand_allowed(true);
    let mut fully_removed = false;
    for _ in 0..10 {
        {
            // Eviction unlinks the working-tree copy only where the OS proves no writer can
            // exist (the Linux write lease); elsewhere (macOS) it keeps the file by design, so
            // stand in for the exclusion there. Armed per call on this thread (thread-local).
            #[cfg(not(target_os = "linux"))]
            let _exclusion = yadorilink_filesystem_sync::materialization_eviction::assume_write_exclusion_for_test();
            yadorilink_daemon::hydration::evict(&n.state, &group_id, unique_path)
                .expect("evicting x's content on n (a complete copy) must not be custody-gated");
        }
        for hash in &block_hashes {
            let _ = n.state.block_store.delete(hash);
        }
        let still_present = n
            .state
            .block_store
            .present_blocks(&block_hashes)
            .expect("present_blocks must not error")
            .into_iter()
            .any(|present| present);
        if !still_present {
            fully_removed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(fully_removed, "never observed x's blocks fully removed from n's own block store");
    n.state.set_materialization_repair_sweep_interval(TEST_SWEEP_INTERVAL);

    fake.remove_device(&x.device_id);

    // M and W never independently held x's content (both OnDemand, never
    // fetch eagerly) -- N's own periodic materialization-repair sweep
    // will ask each of them in turn and both will explicitly refuse.
    let deadline = Instant::now() + CONVERGENCE_BOUND;
    #[allow(unused_assignments)]
    let mut last_status = n.state.group_durability_status(&group_id);
    loop {
        let status = n.state.group_durability_status(&group_id);
        last_status = status;
        if status == GroupDurabilityStatus::AtRisk {
            break;
        }
        assert_ne!(
            status,
            GroupDurabilityStatus::Protected,
            "durability must never silently converge to Protected while x's content remains \
             genuinely unobtainable -- that would misreport real data loss as success"
        );
        if Instant::now() >= deadline {
            panic!(
                "durability status never converged to AtRisk within {CONVERGENCE_BOUND:?} after \
                 x (the sole holder) left; last observed status: {last_status:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // The record itself must still exist -- never silently retired. An
    // unobtainable record may be the user's only surviving edit; deleting
    // the metadata would turn real data loss into apparent convergence
    // and erase the evidence the content ever existed.
    let still_present = n
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(&group_id, unique_path)
        .expect("get_file must not error")
        .map(|f| !f.deleted)
        .unwrap_or(false);
    assert!(
        still_present,
        "x's unique-content record must still be present (not deleted/retired) on n after \
         durability converges to AtRisk"
    );

    let _ = Arc::new(m);
    handles.shutdown();
}
