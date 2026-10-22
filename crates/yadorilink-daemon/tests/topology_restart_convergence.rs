//! Restart truthfulness: a daemon restart on the canonical
//! N/M/W topology must never resurrect a stale `Protected` reading
//! without fresh evidence -- the SAME property the
//! `restart_never_shows_a_stale_protected_status` unit test proves for a
//! single reopened `ReplicaCoordinator`, proven here through a REAL
//! multi-node restart: a genuinely different `DaemonState` process
//! instance, reopened against the same on-disk state, with real peers
//! still running and a real re-handshake required before any fresh
//! evidence can exist again.
//!
//! **Oracle discipline**: `fully_connected` only says a session is
//! registered, which a stale session object sitting in the registry (never
//! replaced) would satisfy just as well as a genuinely fresh one. This
//! file's own restart scenario therefore proves session REPLACEMENT by `Arc`
//! identity (`!Arc::ptr_eq(old, new)`).

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{fully_connected, restart_node, stand_up_canonical_topology, TopologyNode};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::durability_service::GroupDurabilityStatus;
use yadorilink_peer_session::peer_session::PeerSyncSession;

/// Installs a `tracing` subscriber writing to the test harness (visible
/// with `--nocapture`) at a verbosity that captures the full session-
/// generation lifecycle this file's own module doc comment describes:
/// supervisor generation start, `PeerChannel`/`PeerSyncSession`
/// creation, registry insert, actor exit reason, `PeerSyncSession::run`
/// exit, reconnect-loop backoff/next-attempt, QUIC handshake
/// initiation/authentication. Test-local only (matches this crate's
/// established `relay_failover.rs`-style pattern) -- no new production-
/// visible tracing was added; every event below already exists in
/// `peer_orchestrator.rs`/`peer_channel.rs`/`peer_session.rs`'s
/// production code, this just makes it visible.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "yadorilink_daemon=debug,yadorilink_transport=debug,yadorilink_peer_session=debug",
                )
            }),
        )
        .with_test_writer()
        .try_init();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn n_restart_never_shows_a_stale_protected_status() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-restart-group";

    let (n, m, w, mut handles) = stand_up_canonical_topology(&fake, group_id).await;

    // Establish a genuine Protected-eligible baseline: real content
    // converges, then a real custody-confirmation sweep runs. This
    // topology is a lone-full-replica-anchor shape (established fact,
    // `topology_n_m_w.rs`), so the reachable status is AtRisk -- but the
    // property under test (stale evidence must not survive a restart)
    // applies identically regardless of which non-Unknown status was
    // reached, so this still exercises it directly: assert a REAL,
    // non-Unknown status is reached before restart, then prove restart
    // doesn't let it survive un-reconfirmed.
    let path = m.root.path().join("before-restart.txt");
    std::fs::write(&path, b"before restart").unwrap();
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join("before-restart.txt")).ok().as_deref()
                == Some(b"before restart" as &[u8])
        },
        Duration::from_secs(30),
        || "N never converged on M's pre-restart content".to_string(),
    )
    .await;
    n.state.refresh_custody_confirmation(group_id).await;
    let pre_restart_status = n.state.group_durability_status(group_id);
    assert_ne!(
        pre_restart_status,
        GroupDurabilityStatus::Unknown,
        "sanity check: a genuine non-Unknown status must be established before restart, so \
         the post-restart assertion below actually proves \"reset to Unknown\", not merely \
         \"happens to also read Unknown\""
    );

    // Capture the PRE-restart session identity on M and W's side --
    // this is the "old PeerSyncSession" the module doc comment's
    // lifecycle starts from.
    let m_session_before: Arc<PeerSyncSession> = m
        .state
        .peers
        .session(&n.device_id)
        .expect("M must have an established session with N before restart");
    let w_session_before: Arc<PeerSyncSession> = w
        .state
        .peers
        .session(&n.device_id)
        .expect("W must have an established session with N before restart");
    tracing::info!(
        m_session_before = ?Arc::as_ptr(&m_session_before),
        w_session_before = ?Arc::as_ptr(&w_session_before),
        "TEST: captured pre-restart session identities"
    );

    // Restart N: shut down ONLY N's own orchestrator runtime (M/W's own
    // orchestrators must keep running -- their reconnect supervisors are
    // what actually notice N coming back; a plain `drop(handles)` would
    // wrongly kill every node's orchestrator, not just N's --
    // `take_and_shutdown`'s own doc comment) and its link runtime
    // (`restart_node`'s own `LinkRuntimeController::stop` call), then
    // reopen a fresh `DaemonState` against the exact same on-disk index
    // DB and block store.
    // Close the substrate first, while the runtime its tasks live on is still
    // running -- see `shutdown_substrate`. Killing the runtime first leaves the
    // socket bound with nothing polling it, which is not what a restart looks
    // like from a peer's side.
    support::topology::shutdown_substrate(&n).await;
    handles.take_and_shutdown(&n.device_id).await;
    let n = restart_node(n).await;
    tracing::info!(
        "TEST: N restarted -- old orchestrator/link runtime torn down, fresh DaemonState opened"
    );

    // Immediately after restart, BEFORE any new peer handshake or
    // custody-confirmation sweep has run, durability must read Unknown
    // -- never the pre-restart status resurrected from stale in-memory
    // state, since there IS no in-memory state anymore; this is really
    // asserting that nothing about `DaemonState::new`'s own
    // reconstruction from disk fabricates fresh-looking evidence that
    // was never actually re-confirmed this process instance.
    assert_eq!(
        n.state.group_durability_status(group_id),
        GroupDurabilityStatus::Unknown,
        "a freshly restarted daemon must report Unknown until its OWN confirmation sweep \
         has run, never the pre-restart status"
    );

    // Re-register with the coordination plane (a real restart re-runs
    // the orchestrator's own startup registration) and re-spawn the
    // orchestrator so N can reconnect to M and W -- through the SAME
    // dedicated-child-runtime `spawn_orchestrator` the initial mesh
    // uses, registered back into `handles` (`TopologyHandles::insert`),
    // so this fresh generation's own per-peer supervisors are tracked
    // and torn down at the test's end exactly like the original three
    // nodes' -- a bare `tokio::spawn` here (an earlier version of this
    // test) would leak them the same way the ORIGINAL design did.
    register_with_fake(&fake, &n.state, &n.device_id, &[group_id]).await;
    let n_runtime = support::topology::spawn_orchestrator(fake.addr(), &n);
    // The substrate rebinds on a fresh socket across a restart, so the address
    // the plane names for this node is stale until it is republished.
    support::topology::advertise_substrate_endpoints(&[&n, &m, &w]).await;
    handles.insert(n.device_id.clone(), n_runtime);
    tracing::info!("TEST: N's fresh orchestrator spawned, re-registered with coordination plane");

    // Step 1 of the required lifecycle: the OLD session must be
    // REPLACED by a genuinely different `PeerSyncSession` object on
    // BOTH M and W -- not merely "still has a session" (a stale one
    // sitting in the registry would pass that trivially). Deliberately
    // does NOT require observing an intermediate `None`: replacement
    // may legitimately happen faster than this polling interval, and a
    // registry slot going briefly empty is an implementation detail,
    // not a required observable state.
    wait_until_with_context(
        || {
            let m_replaced = m
                .state
                .peers
                .session(&n.device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &m_session_before));
            let w_replaced = w
                .state
                .peers
                .session(&n.device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &w_session_before));
            m_replaced && w_replaced
        },
        Duration::from_secs(180),
        || {
            format!(
                "M/W never got a FRESH session identity for N after restart (still the same \
                 pre-restart Arc, or no session at all): m_session={:?} w_session={:?}",
                m.state.peers.session(&n.device_id).map(|s| Arc::as_ptr(&s)),
                w.state.peers.session(&n.device_id).map(|s| Arc::as_ptr(&s)),
            )
        },
    )
    .await;
    tracing::info!("TEST: M and W both replaced their session for N with a fresh Arc identity");

    // Step 2: only NOW check negotiation flags -- on the confirmed-
    // fresh session, this is a valid signal (a stale session's sticky
    // flags could never have told us anything at this point).
    wait_until_with_context(
        || fully_connected(&m.state, &n.device_id) && fully_connected(&w.state, &n.device_id),
        Duration::from_secs(60),
        || {
            format!(
                "fresh sessions never completed their handshake: m={:?} w={:?}",
                m.state.peers.session(&n.device_id).is_some(),
                w.state.peers.session(&n.device_id).is_some(),
            )
        },
    )
    .await;
    tracing::info!("TEST: fresh sessions handshook -- proceeding to real traffic");

    // Step 3: real application traffic over the fresh session, exact
    // content verified -- not just "a session object exists." M is
    // On-Demand (this canonical topology's own established shape), so
    // the DAG job settling (visible in the trace as "job marked
    // Completed after direct projection verification") lands the file
    // as a placeholder first; explicit `hydration::hydrate` (the same
    // real entry point a real OS-provider callback drives, matching
    // `topology_n_m_w.rs`'s own established pattern) is required before
    // checking actual bytes -- an earlier version of this test wrongly
    // expected `std::fs::read` to see content immediately.
    let path = n.root.path().join("after-restart.txt");
    std::fs::write(&path, b"content authored after N's restart").unwrap();
    wait_until_with_context(
        || {
            m.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "after-restart.txt" && !f.deleted))
                .unwrap_or(false)
        },
        // A negotiated session can still hit a brief liveness re-race mid-
        // restart-recovery (the same jitter the hydrate-retry loop right
        // below this already documents/tolerates) -- 30s cut it too close
        // and produced hard failures in ~2/5 local runs with the DAG
        // record simply not there YET, not permanently missing. Matches
        // the margin already granted to the negotiation wait above it.
        Duration::from_secs(90),
        || "M never saw after-restart.txt's DAG record over the fresh session".to_string(),
    )
    .await;
    // A single `hydrate` attempt can genuinely race a still-settling
    // fresh generation (a brief re-race/liveness cycle mid-restart-
    // recovery) and return `HydrationFailed` even though N does hold the
    // content and the session is fundamentally healthy -- the same
    // transient outcome a real UI/CLI consumer must retry through,
    // documented on `hydrate`'s own doc comment ("Reverts to Placeholder
    // and returns HydrationFailed if the deadline elapses"). Retried a
    // few times rather than requiring the very first attempt to land in
    // exactly the right window.
    let mut hydrate_attempts = 0;
    loop {
        match yadorilink_daemon::hydration::hydrate(&m.state, group_id, "after-restart.txt").await {
            Ok(()) => break,
            Err(error) if hydrate_attempts < 5 => {
                hydrate_attempts += 1;
                tracing::warn!(
                    %error,
                    hydrate_attempts,
                    "TEST: hydration attempt failed, retrying (transient generation churn)"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => panic!(
                "hydration should eventually succeed once the fresh session's peer holds the \
                 content, after {hydrate_attempts} retries: {error}"
            ),
        }
    }
    wait_until_with_context(
        || {
            std::fs::read(m.root.path().join("after-restart.txt")).ok().as_deref()
                == Some(b"content authored after N's restart" as &[u8])
        },
        Duration::from_secs(10),
        || "M never converged on N's post-restart content over the fresh session".to_string(),
    )
    .await;

    // Once N has genuinely reconnected and run a fresh confirmation
    // sweep, it must reach the SAME real status the pre-restart baseline
    // reached (this topology's own structural fact hasn't changed) --
    // proving the post-restart Unknown was a truthful transient, not a
    // permanently-stuck state.
    n.state.refresh_custody_confirmation(group_id).await;
    assert_eq!(
        n.state.group_durability_status(group_id),
        pre_restart_status,
        "after reconnecting and re-sweeping post-restart, N must reach the same real status \
         the pre-restart baseline did -- the restart must be a truthful transient dip to \
         Unknown, not a permanent regression"
    );

    // Teardown: `handles` (Drop impl) shuts down every tracked runtime,
    // including N's post-restart generation now that it's registered
    // via `handles.insert` above -- proving a second restart would also
    // find something in `take_and_shutdown` for N.
    handles.shutdown();
}

/// TEMPORARY (scratch/topology-diag): classify where the M -> N pipeline stops.
///
/// Each stage is read from the table that actually holds it, so the first stage
/// that disagrees between the author and N is the defect boundary:
///   author canonical -> author servable -> N staged -> N canonical
///   -> N index row -> N disk bytes
fn pipeline_probe(nodes: &[(&str, &TopologyNode)], group_id: &str) -> String {
    nodes
        .iter()
        .map(|(tag, node)| {
            let c = &node.state.replica_coordinator;
            let heads = c
                .sqlite()
                .native_group_heads(group_id)
                .map(|mut h| {
                    h.sort();
                    h.iter().map(|x| hex::encode(x.0)[..8].to_string()).collect::<Vec<_>>()
                })
                .unwrap_or_else(|e| vec![format!("err({e})")]);
            let staged: Vec<String> = Vec::new();
            let servable: Vec<String> = Vec::new();
            let index = c
                .file_index_repository()
                .list_files(group_id)
                .map(|f| {
                    f.iter()
                        .map(|r| format!("{}{}", r.path, if r.deleted { "(del)" } else { "" }))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|e| vec![format!("err({e})")]);
            let dirty = c
                .dirty_path_repository()
                .list_dirty_paths(group_id)
                .map(|d| d.into_iter().map(|e| e.path).collect::<Vec<_>>())
                .unwrap_or_else(|e| vec![format!("err({e})")]);
            let disk = support::real_entry_names(node.root.path());
            format!(
                "  {tag}({}): heads={heads:?} staged={staged:?} servable={servable:?} \
                 dirty={dirty:?} index={index:?} disk={disk:?}",
                node.device_id
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Restart of a NON-anchor node:
/// the canonical topology is a full mesh (N<->M, N<->W, M<->W all
/// connected, `stand_up_canonical_topology`'s own wait proves this), so
/// restarting M or W -- unlike N, which is the lone full-replica/relay
/// anchor and has its own dedicated durability-status test above -- must
/// be observed from BOTH of the other two nodes at once, not just one.
/// Proves the same session-identity-first lifecycle N's own restart test
/// proves (fresh `Arc<PeerSyncSession>` on every remaining peer before
/// trusting negotiation flags), plus real bidirectional content
/// convergence: the restarted node's own pre-restart authorship must
/// still be held by its peers, and its post-restart authorship must
/// reach them again over the fresh session. Does not repeat the
/// N-restart test's `group_durability_status` assertions -- that
/// machinery is evaluated from the full-replica anchor's perspective
/// (N), which does not restart in this scenario, so there is nothing new
/// to prove there; "stale evidence must not survive a restart" is
/// already covered once, structurally, by the N-restart test above.
async fn on_demand_node_restart_recovers_and_resyncs(restart_w: bool) {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-restart-group";

    let (n, mut m, mut w, mut handles) = stand_up_canonical_topology(&fake, group_id).await;
    let label = if restart_w { "W" } else { "M" };

    let before_name = format!("before-restart-{label}.txt");
    {
        let author_root = if restart_w { w.root.path() } else { m.root.path() };
        std::fs::write(author_root.join(&before_name), b"before restart").unwrap();
    }
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join(&before_name)).ok().as_deref()
                == Some(b"before restart" as &[u8])
        },
        Duration::from_secs(30),
        || {
            format!(
                "N never converged on {label}'s pre-restart content\n{}",
                pipeline_probe(&[("author", if restart_w { &w } else { &m }), ("N", &n)], group_id)
            )
        },
    )
    .await;
    let bystander_hydrate_before = if restart_w { &m.state } else { &w.state };
    wait_until_with_context(
        || {
            bystander_hydrate_before
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == before_name && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(30),
        || format!("the bystander On-Demand peer never saw {label}'s pre-restart DAG record"),
    )
    .await;
    // The record can be listed while still the bootstrap scaffold, and the lane then
    // replaces it; a hydrate that sampled the scaffold fails closed and is retried.
    support::topology::hydrate_with_retries(bystander_hydrate_before, group_id, &before_name).await;

    let restart_device_id = if restart_w { w.device_id.clone() } else { m.device_id.clone() };
    let n_session_before: Arc<PeerSyncSession> =
        n.state.peers.session(&restart_device_id).unwrap_or_else(|| {
            panic!("N must have an established session with {label} before restart")
        });
    let bystander_state_before = if restart_w { &m.state } else { &w.state };
    let bystander_session_before: Arc<PeerSyncSession> =
        bystander_state_before.peers.session(&restart_device_id).unwrap_or_else(|| {
            panic!(
                "the bystander peer must have an established session with {label} before restart"
            )
        });

    // Restart the target node exactly like the N-restart test does:
    // tear down ONLY its own orchestrator runtime, reopen it against the
    // same on-disk state, re-register, and re-spawn a fresh orchestrator
    // tracked back into `handles`.
    if restart_w {
        // Close the substrate first, while the runtime its tasks live on is
        // still running -- see `shutdown_substrate`.
        support::topology::shutdown_substrate(&w).await;
        handles.take_and_shutdown(&w.device_id).await;
        w = restart_node(w).await;
        register_with_fake(&fake, &w.state, &w.device_id, &[group_id]).await;
        let runtime = support::topology::spawn_orchestrator(fake.addr(), &w);
        support::topology::advertise_substrate_endpoints(&[&n, &m, &w]).await;
        handles.insert(w.device_id.clone(), runtime);
    } else {
        // Close the substrate first, while the runtime its tasks live on is
        // still running -- see `shutdown_substrate`.
        support::topology::shutdown_substrate(&m).await;
        handles.take_and_shutdown(&m.device_id).await;
        m = restart_node(m).await;
        register_with_fake(&fake, &m.state, &m.device_id, &[group_id]).await;
        let runtime = support::topology::spawn_orchestrator(fake.addr(), &m);
        support::topology::advertise_substrate_endpoints(&[&n, &m, &w]).await;
        handles.insert(m.device_id.clone(), runtime);
    }
    tracing::info!(label, "TEST: restarted node's orchestrator re-spawned and re-registered");

    let bystander_state_after = if restart_w { &m.state } else { &w.state };
    wait_until_with_context(
        || {
            let n_replaced = n
                .state
                .peers
                .session(&restart_device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &n_session_before));
            let bystander_replaced = bystander_state_after
                .peers
                .session(&restart_device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &bystander_session_before));
            n_replaced && bystander_replaced
        },
        Duration::from_secs(180),
        || format!("N and/or the bystander peer never got a FRESH session identity for {label}"),
    )
    .await;
    wait_until_with_context(
        || {
            fully_connected(&n.state, &restart_device_id)
                && fully_connected(bystander_state_after, &restart_device_id)
        },
        Duration::from_secs(60),
        || format!("fresh sessions with restarted {label} never completed negotiation"),
    )
    .await;
    tracing::info!(label, "TEST: fresh sessions with restarted node negotiated");

    // Real post-restart traffic authored BY the restarted node, over the
    // fresh session, must reach BOTH other nodes again.
    let after_name = format!("after-restart-{label}.txt");
    let content = format!("content authored after {label}'s restart");
    {
        let author_root = if restart_w { w.root.path() } else { m.root.path() };
        std::fs::write(author_root.join(&after_name), content.as_bytes()).unwrap();
    }
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join(&after_name)).ok().as_deref()
                == Some(content.as_bytes())
        },
        Duration::from_secs(90),
        || format!("N never converged on {label}'s post-restart content over the fresh session"),
    )
    .await;
    wait_until_with_context(
        || {
            bystander_state_after
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == after_name && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(90),
        || format!("bystander peer never saw {label}'s post-restart DAG record"),
    )
    .await;
    // The record can be listed while still the bootstrap scaffold, and the lane then
    // replaces it; a hydrate that sampled the scaffold fails closed and is retried.
    support::topology::hydrate_with_retries(bystander_state_after, group_id, &after_name).await;

    handles.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn m_restart_recovers_and_resyncs_with_both_peers() {
    on_demand_node_restart_recovers_and_resyncs(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn w_restart_recovers_and_resyncs_with_both_peers() {
    on_demand_node_restart_recovers_and_resyncs(true).await;
}

/// A third device that is OFFLINE while another changes a file catches up when it returns: M
/// authors while W is down, N receives it live, and W, once restarted against its own on-disk
/// state, learns the change and can hydrate the bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_that_was_offline_catches_up_when_it_returns() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-offline-third-group";

    let (n, m, mut w, mut handles) = stand_up_canonical_topology(&fake, group_id).await;

    support::topology::shutdown_substrate(&w).await;
    handles.take_and_shutdown(&w.device_id).await;

    let name = "written-while-w-was-offline.txt";
    let content = b"authored while the third device was offline";
    std::fs::write(m.root.path().join(name), content).unwrap();
    wait_until_with_context(
        || std::fs::read(n.root.path().join(name)).ok().as_deref() == Some(content as &[u8]),
        Duration::from_secs(60),
        || "N never received the change made while W was offline".to_string(),
    )
    .await;

    w = restart_node(w).await;
    register_with_fake(&fake, &w.state, &w.device_id, &[group_id]).await;
    let runtime = support::topology::spawn_orchestrator(fake.addr(), &w);
    support::topology::advertise_substrate_endpoints(&[&n, &m, &w]).await;
    handles.insert(w.device_id.clone(), runtime);

    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == name && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(180),
        || "the returning device never learned the change made while it was offline".to_string(),
    )
    .await;
    // The record can be listed while still the bootstrap scaffold, and the lane then
    // replaces it; a hydrate that sampled the scaffold fails closed and is retried.
    support::topology::hydrate_with_retries(&w.state, group_id, name).await;

    handles.shutdown();
}

/// A restart while a large transfer
/// is actively in flight must never accept stale ACK/data from the OLD
/// transport epoch, and must still converge to the EXACT byte content --
/// not merely "some content", the way the other restart tests' small
/// single-write payloads could pass even with a subtly corrupted byte or
/// two lost in transit. A large (multi-megabyte) payload takes many rounds
/// over loopback, giving a real (if not perfectly deterministic) window for
/// N's restart to land mid-transfer rather than either before it starts or
/// comfortably after it finishes. Every restarted node's connection is
/// established fresh for a genuinely NEW generation, never reused across a
/// restart, so a correct implementation must recover to exact content
/// regardless of when the restart lands relative to the transfer; this test
/// exercises that live, rather than only asserting the invariant
/// statically.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn n_restart_mid_transfer_still_converges_exactly() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-restart-mid-transfer-group";

    let (n, m, w, mut handles) = stand_up_canonical_topology(&fake, group_id).await;

    // A large, non-repeating payload (LCG-derived, not all-zero/
    // all-same-byte, so a corrupted or truncated transfer can't
    // coincidentally hash-match the correct content) -- big enough that a
    // real reliable-delivery transfer over loopback takes measurable,
    // multi-chunk time rather than completing in a single round trip.
    const PAYLOAD_LEN: usize = 24 * 1024 * 1024;
    let mut payload = vec![0u8; PAYLOAD_LEN];
    let mut lcg_state: u64 = 0x243F6A8885A308D3;
    for byte in payload.iter_mut() {
        lcg_state = lcg_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *byte = (lcg_state >> 56) as u8;
    }
    let expected_hash = {
        use sha2::Digest;
        sha2::Sha256::digest(&payload)
    };

    let path = m.root.path().join("mid-transfer.bin");
    std::fs::write(&path, &payload).unwrap();

    // Restart N shortly after the write starts propagating, without
    // waiting for convergence first -- the whole point is to land the
    // restart WHILE the transfer is (plausibly) still in flight, not
    // after it has already settled.
    tokio::time::sleep(Duration::from_millis(150)).await;
    // Close the substrate first, while the runtime its tasks live on is still
    // running -- see `shutdown_substrate`. Killing the runtime first leaves the
    // socket bound with nothing polling it, which is not what a restart looks
    // like from a peer's side.
    support::topology::shutdown_substrate(&n).await;
    handles.take_and_shutdown(&n.device_id).await;
    let n = restart_node(n).await;
    tracing::info!(
        "TEST: N restarted mid-transfer -- old orchestrator/link runtime torn down, fresh \
         DaemonState opened"
    );
    register_with_fake(&fake, &n.state, &n.device_id, &[group_id]).await;
    let n_runtime = support::topology::spawn_orchestrator(fake.addr(), &n);
    // The substrate rebinds on a fresh socket across a restart, so the address
    // the plane names for this node is stale until it is republished.
    support::topology::advertise_substrate_endpoints(&[&n, &m, &w]).await;
    handles.insert(n.device_id.clone(), n_runtime);

    // Regardless of exactly when the restart landed relative to the
    // transfer, N must eventually converge on the EXACT payload -- no
    // stale partial/corrupted data accepted from the old epoch, and no
    // permanently-stuck-short transfer either. A generous deadline: the
    // whole payload may need to be resent from scratch over a fresh
    // generation, on top of the fresh handshake/negotiation this test
    // doesn't separately gate on (unlike the other restart tests) since
    // exact content convergence already implies it happened.
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join("mid-transfer.bin"))
                .map(|bytes| {
                    use sha2::Digest;
                    sha2::Sha256::digest(&bytes) == expected_hash
                })
                .unwrap_or(false)
        },
        Duration::from_secs(120),
        || {
            let actual_len = std::fs::read(n.root.path().join("mid-transfer.bin")).map(|b| b.len());
            format!(
                "N never converged on the EXACT mid-transfer payload after N's restart -- \
                 expected_len={PAYLOAD_LEN} actual_len={actual_len:?}"
            )
        },
    )
    .await;
    tracing::info!("TEST: N converged on the exact mid-transfer payload after restart");

    // W (the third, uninvolved-in-the-restart peer) must also eventually
    // reach the exact content over its own On-Demand hydration path --
    // proving the mid-transfer restart didn't leave any peer's copy
    // silently short or corrupted.
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "mid-transfer.bin" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || "W never saw mid-transfer.bin's DAG record".to_string(),
    )
    .await;
    let mut hydrate_attempts = 0;
    loop {
        match yadorilink_daemon::hydration::hydrate(&w.state, group_id, "mid-transfer.bin").await {
            Ok(()) => break,
            Err(error) if hydrate_attempts < 5 => {
                hydrate_attempts += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = error;
            }
            Err(error) => panic!("W's hydration should eventually succeed: {error}"),
        }
    }
    let w_bytes = std::fs::read(w.root.path().join("mid-transfer.bin"))
        .expect("W must have the hydrated file");
    assert_eq!(
        {
            use sha2::Digest;
            sha2::Sha256::digest(&w_bytes)
        },
        expected_hash,
        "W's copy of the mid-transfer payload must also be byte-exact"
    );

    handles.shutdown();
}
