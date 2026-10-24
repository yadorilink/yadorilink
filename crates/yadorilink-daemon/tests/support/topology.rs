//! Canonical 3-node topology -- N (Full Replica, "home NAS"
//! role conceptually), M and W (On-Demand, "Mac"/"Windows" roles
//! conceptually). Shared, reusable base for the multi-node acceptance
//! scenarios (moved here from `tests/topology_n_m_w.rs` once a second test
//! binary needed it too -- integration test FILES are separate crates
//! and cannot `use` each other directly, only shared `tests/support/`
//! modules).
//!
//! Real production code at every layer this exercises: real
//! `DaemonState`, real `peer_orchestrator`-driven `PeerChannel`/
//! QUIC-shaped sessions over loopback UDP, real DAG mutation propagation
//! via the real filesystem watcher (`std::fs::write` on a linked local
//! folder, not a raw DB upsert -- `monkey_chaos.rs`'s established
//! convention), real `MaterializationPolicy::OnDemand` storage mode
//! (`storage_mode_orchestration.rs`'s API), real custody-confirmation
//! sweep (`DaemonState::refresh_custody_confirmation`, the same method
//! `DurabilityConfirmationJob` calls periodically in production), real
//! `group_durability_status` derivation.
//!
//! **Not** OS-native (CfAPI/File Provider) acceptance -- this proves the
//! application/daemon/transport/storage integration above the
//! platform-native boundary, not Explorer/Finder lifecycle behavior.
//!
//! The peer-device relay mechanism this file's topology helpers once also
//! covered (a relay-anchor role, forced-relay routing, `RelayGrant`
//! wiring) was physically removed together with the rest of that
//! mechanism: the Iroh relay
//! carries the reconciliation/block/service substrate directly now, with
//! no per-peer relay session for a topology helper to force or wire a
//! grant source for.
//!
//! `#![allow(dead_code)]`: every integration test FILE under `tests/` is
//! its own separate compilation unit that includes the whole `support`
//! module tree via `mod support;`, regardless of which parts it actually
//! uses -- `-D warnings` clippy (this crate's CI gate) sees every item
//! here as dead code from the perspective of any sibling test binary
//! that doesn't happen to reference `topology`, exactly like
//! `fake_coordination.rs`'s existing per-method `#[allow(dead_code)]`
//! annotations already handle for the same reason, just applied at the
//! module level here since every item in this file is in the same boat.
#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::fake_coordination::FakeCoordination;
use super::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::MaterializationPolicy;

/// One node in the canonical N/M/W topology. `root` is the linked local
/// folder; kept public so scenario tests can `std::fs::write`/read
/// directly into it, exercising the real watcher/hydration path rather
/// than a bypass helper. `store_path`/`db_path` are real on-disk
/// locations (never in-memory) SPECIFICALLY so [`restart_node`] can
/// reopen the exact same persisted state a real daemon restart would --
/// `ReplicaCoordinator::open_in_memory()` (this file's own earlier,
/// restart-incapable version) loses everything the moment the
/// `DaemonState` is dropped, which would make any restart scenario
/// vacuous by construction.
pub struct TopologyNode {
    pub device_id: String,
    pub state: Arc<DaemonState>,
    pub root: tempfile::TempDir,
    /// Own the block-store and index-DB temp directories for this node's
    /// whole lifetime (across any number of `restart_node` calls) so they
    /// are cleaned up on drop -- an earlier version of this struct leaked
    /// both via `Box::leak` (needed then for a `&'static Path` this struct
    /// no longer holds), permanently littering the OS temp directory on
    /// every test run.
    store_dir: tempfile::TempDir,
    db_dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    /// This device's change-history signing identity -- kept here
    /// (rather than only living inside `DaemonState`, which never
    /// persists it: `DaemonState::device_signing_key` is a plain
    /// in-memory `Mutex<Option<SigningKey>>`) SPECIFICALLY so
    /// [`restart_node`] can re-apply the SAME key to the fresh
    /// `DaemonState`. A real device restart reloads its persistent
    /// identity key from `key_secret_store` (OS keyring); without this,
    /// a "restarted" node here would get a brand-new RANDOM signing key
    /// from `support::ensure_device_signing_key`'s own generate-if-unset
    /// fallback, and every change it retained/authored before the
    /// restart would then fail signature verification against its own
    /// (wrong) new identity -- a test-harness gap, not a production one,
    /// confirmed by tracing `yadorilink_daemon::change_auth`'s own
    /// "signature does not verify against the claimed device key" error
    /// in restart-convergence scenarios.
    signing_key: ed25519_dalek::SigningKey,
    /// Frees the node's state once the test lets go of the node: see [`ReleasesCycles`].
    _releases_cycles: ReleasesCycles,
}

/// Breaks the reference cycles a paired state forms with itself when it is dropped.
///
/// Registered sessions and the peer session driver reach back to their `DaemonState`, which
/// would otherwise keep it, both databases and every descriptor they hold alive for the rest of
/// the test binary; a binary whose tests each build several nodes then runs out of descriptors
/// at the default limit. Dropping a node releases them, as a daemon's exit would.
struct ReleasesCycles(Arc<DaemonState>);

impl Drop for ReleasesCycles {
    fn drop(&mut self) {
        // A hook that captured the group's states reaches back to this one too.
        self.0.set_rebootstrap_hook_for_test(None);
        self.0.release_reference_cycles_for_tests();
    }
}

impl TopologyNode {
    /// The root directory of this node's block store.
    pub fn store_root(&self) -> &std::path::Path {
        self.store_dir.path()
    }
}

pub fn new_node(device_id: &str) -> TopologyNode {
    // Suffixed with a per-process-unique counter: `ensure_isolated_config_
    // dir` gives each TEST BINARY (process) its own isolated pin-file
    // directory, but a test binary with more than one `#[tokio::test]`
    // function runs them CONCURRENTLY in that SAME process by default --
    // two such tests both calling `stand_up_canonical_topology` would
    // otherwise mint the exact same literal device ids
    // ("topology-n-nas"/etc.) with DIFFERENT randomly-generated keys, and
    // race each other writing the SAME shared `peer_keys.json`/`signing_
    // keys.json` pin files, corrupting whichever one loses the race with
    // a "key changed from pinned value; refusing connection" error --
    // confirmed as the actual cause of `m_restart_recovers_and_resyncs_
    // with_both_peers`/`w_restart_...`/`n_restart_...` all failing when
    // this file grew from one `#[tokio::test]` to three. No other file
    // using this module has more than one test function per binary
    // (each of those is its own separate process), so this was never
    // triggered until now; suffixing here (rather than serializing the
    // tests) keeps them running concurrently, matching this crate's
    // established convention elsewhere.
    static NODE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = NODE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let device_id = format!("{device_id}-{unique}");
    let device_id = device_id.as_str();
    let store_dir = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("index.db");
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(
        ReplicaCoordinator::open_with(&db_path, super::tuning_with_outside_witness()).unwrap(),
    );
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    let signing_key = yadorilink_transport::DeviceSigningKeyPair::generate().signing;
    state.set_device_signing_key(signing_key.clone());
    TopologyNode {
        device_id: device_id.to_string(),
        _releases_cycles: ReleasesCycles(state.clone()),
        state,
        root: tempfile::tempdir().unwrap(),
        signing_key,
        store_dir,
        db_dir,
        db_path,
    }
}

/// Simulates a real daemon restart for one topology node: stops the old
/// node's link runtime (watcher/debounce/executor/repair tasks --
/// `LinkRuntimeController::stop`, the SAME real teardown production/
/// `monkey_chaos.rs` use, awaited to genuine completion, not just
/// fire-and-abort), drops the old `DaemonState` (the caller's own
/// `TopologyHandles` must ALSO be torn down for the old node's
/// orchestrator -- see that struct's own doc comment for why a plain
/// `JoinHandle` abort used to leave the old node's per-peer supervisors,
/// and the `Arc<DaemonState>`/`ReplicaCoordinator` they hold, running
/// concurrently with the "restarted" node), and rebuilds a fresh
/// `DaemonState` against the EXACT SAME on-disk block store and index
/// DB, preserving device identity (id + transport keypair + signing key,
/// exactly like a real device restarting keeps its own key material) and
/// the same linked local folder. The caller is responsible for
/// re-registering with the coordination plane and re-spawning an
/// orchestrator for the returned node -- this function only performs the
/// state-reload half of a restart, matching how `DaemonState::new`
/// itself is the real production restart entry point (it reads
/// persisted latches/policy straight from the reopened
/// `ReplicaCoordinator`).
/// Close a node's substrate endpoint, the way a process exiting would.
///
/// MUST be awaited BEFORE the node's orchestrator runtime is shut down: the
/// endpoint's own tasks run on that runtime, so once it is gone nothing is
/// left to send the close and the socket is simply abandoned -- still bound,
/// nothing polling it. That is strictly weaker than production, where the
/// kernel closes the socket when the process exits, and it leaves every peer
/// holding a connection to an address that has silently stopped answering.
pub async fn shutdown_substrate(node: &TopologyNode) {
    node.state.stop_background_tasks_for_tests();
    if let Some(driver) = node.state.peer_session_driver() {
        driver.stack().shutdown().await;
    }
}

pub async fn restart_node(node: TopologyNode) -> TopologyNode {
    restart_node_inner(node, false).await
}

/// `refused_links_expected`: the database was restored in place, so the daemon refuses to start
/// the links (it cannot open its author identity). The refusal is checked, then left in place, as
/// production startup leaves it.
async fn restart_node_inner(node: TopologyNode, refused_links_expected: bool) -> TopologyNode {
    LinkRuntimeController::new(node.state.clone()).stop(&node.root.path().to_string_lossy()).await;
    let store = Arc::new(SegmentBlockStore::new(node.store_dir.path()).unwrap());
    // Bounded retry: the OLD generation's SQLite connection pool can still
    // be mid-close (a genuine, if narrow, race between `stop()` above
    // returning and its underlying `r2d2` pool actually releasing its file
    // lock) -- observed as a real, reproducible "database is locked" error
    // reopening the SAME db path here, worse under concurrent CPU load
    // when several tests each restart a node at once. Retrying a few times
    // with a short backoff closes that harness-only race without masking
    // a genuine, persistent failure (still panics with the real error if
    // it never clears).
    let mut open_attempts = 0;
    let sync_state = loop {
        match ReplicaCoordinator::open_with(&node.db_path, super::tuning_with_outside_witness()) {
            Ok(coordinator) => break Arc::new(coordinator),
            Err(error) if open_attempts < 10 => {
                open_attempts += 1;
                tracing::warn!(
                    %error,
                    open_attempts,
                    "restart_node: reopening the index DB failed, retrying (likely the old \
                     generation's connection pool still closing)"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => panic!("restart_node: could not reopen the index DB: {error}"),
        }
    };
    // `app.rs`'s startup settle of folder rewinds a gone process left
    // unfinished, decided from the journal row alone, before any link
    // starts.
    sync_state.rewind_run_repository().interrupt_unfinished_runs().unwrap();
    let state = DaemonState::new(node.device_id.clone(), sync_state, store);
    // Re-apply the SAME signing identity `signing_key`'s own doc comment
    // explains why: a real restart reloads this from persistent storage,
    // never generates a new one -- letting `support::ensure_device_
    // signing_key`'s generate-if-unset fallback fire here instead would
    // silently give this node a different identity than the one that
    // authored/retained its pre-restart change history.
    state.set_device_signing_key(node.signing_key.clone());
    // Resume watching every persisted link -- matching production's own
    // real startup sequence EXACTLY (`app.rs`'s own "Resume watching
    // every previously-linked folder" step: links survive a restart,
    // their watchers are simply restarted). Missing this was a real bug
    // in an earlier version of this function: a fresh `DaemonState` has
    // the link ROW in its reopened database, but no active
    // `LinkRuntimeController` watching the folder until something calls
    // `start` again -- so this device's OWN local writes after a
    // "restart" never even reached the DAG. `set_test_on_demand_allowed` is applied
    // unconditionally (harmless for an Eager link, required for
    // OnDemand) rather than duplicating `link_on_demand`'s own policy
    // branch here.
    let links = state.replica_coordinator.link_repository().list_links().unwrap();
    for link in links.iter().filter(|l| !l.orphaned) {
        state.set_test_on_demand_allowed(true);
        // Bounded retry, same shape and reason as the DB-reopen retry
        // above: `stop()`'s own bounded retry (`link_runtime_
        // controller.rs`'s fence-gap fix) can still exhaust its attempts
        // and fall back to abort-only teardown under load, which doesn't
        // release the root-lock sidecar file as promptly as a graceful
        // stop would -- observed live as a real, reproducible "sync root
        // ... is already in use by another YadoriLink process" panic
        // here under the soak's own rapid-repeated-restart chaos. Still
        // panics with the real error if it never clears.
        let mut start_attempts = 0;
        loop {
            match LinkRuntimeController::new(state.clone())
                .start(link.key().to_string(), link.group_id.clone())
            {
                Ok(()) => break,
                // The folder is away from its volume: the daemon leaves the
                // link waiting for it, as production startup does.
                Err(_) if state.links.is_awaiting_volume(link.key()) => break,
                Err(error) if refused_links_expected => {
                    assert!(
                        error.to_string().contains("must start over as a new device"),
                        "the restored database must be refused for being restored, not: {error}"
                    );
                    break;
                }
                Err(error) if start_attempts < 20 => {
                    start_attempts += 1;
                    tracing::warn!(
                        %error,
                        start_attempts,
                        "restart_node: restarting a link's watcher failed, retrying (likely the \
                         old generation's root-lock sidecar file still being released)"
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(error) => panic!("restart_node: could not restart link watcher: {error}"),
            }
        }
    }
    TopologyNode {
        device_id: node.device_id,
        _releases_cycles: ReleasesCycles(state.clone()),
        state,
        root: node.root,
        store_dir: node.store_dir,
        db_dir: node.db_dir,
        db_path: node.db_path,
        signing_key: node.signing_key,
    }
}

/// A node whose daemon is fully stopped: its link runtime is down and no connection to its
/// index database is open, so the database files can be copied or replaced the way a backup tool
/// would. The caller shuts the node's orchestrator and substrate down first (see
/// [`shutdown_substrate`] and [`TopologyHandles::take_and_shutdown`]).
pub struct StoppedNode {
    device_id: String,
    root: tempfile::TempDir,
    store_dir: tempfile::TempDir,
    db_dir: tempfile::TempDir,
    db_path: std::path::PathBuf,
    signing_key: ed25519_dalek::SigningKey,
}

pub async fn stop_node(node: TopologyNode) -> StoppedNode {
    LinkRuntimeController::new(node.state.clone()).stop(&node.root.path().to_string_lossy()).await;
    let TopologyNode {
        device_id,
        state,
        root,
        store_dir,
        db_dir,
        db_path,
        signing_key,
        _releases_cycles,
    } = node;
    state.stop_background_tasks_for_tests();
    drop(_releases_cycles);
    let weak = Arc::downgrade(&state);
    drop(state);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while weak.strong_count() > 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the stopped node's state still holds its database open"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    StoppedNode { device_id, root, store_dir, db_dir, db_path, signing_key }
}

fn is_database_file(path: &Path) -> bool {
    path.is_file() && path.file_name().unwrap().to_string_lossy().starts_with("index.db")
}

impl StoppedNode {
    /// Copies every file of the index database (the database, its WAL, the instance sidecar)
    /// into a new directory, as a backup tool would.
    pub fn database_image(&self) -> tempfile::TempDir {
        let image = tempfile::tempdir().unwrap();
        copy_database_files(self.db_dir.path(), image.path());
        image
    }

    /// Puts an older image of the database back. `other_machine == false` replaces the files in
    /// place (the machine the backup came from, whose installation witness remembers a newer
    /// state); `true` puts them at a new path, which has no witness (a different machine).
    pub fn restore_database_image(&mut self, image: &Path, other_machine: bool) {
        if other_machine {
            self.db_dir = tempfile::tempdir().unwrap();
            self.db_path = self.db_dir.path().join("index.db");
        } else {
            for entry in std::fs::read_dir(self.db_dir.path()).unwrap() {
                let path = entry.unwrap().path();
                if is_database_file(&path) {
                    std::fs::remove_file(path).unwrap();
                }
            }
        }
        copy_database_files(image, self.db_dir.path());
    }
}

fn copy_database_files(from: &Path, to: &Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        if is_database_file(&path) {
            std::fs::copy(&path, to.join(path.file_name().unwrap())).unwrap();
        }
    }
}

/// Starts a stopped node again over whatever its database files now hold.
pub async fn start_stopped_node(stopped: StoppedNode) -> TopologyNode {
    start_stopped_node_inner(stopped, false).await
}

/// [`start_stopped_node`] for a database restored in place: starting its links is refused.
pub async fn start_stopped_node_refusing_links(stopped: StoppedNode) -> TopologyNode {
    start_stopped_node_inner(stopped, true).await
}

async fn start_stopped_node_inner(
    stopped: StoppedNode,
    refused_links_expected: bool,
) -> TopologyNode {
    let StoppedNode { device_id, root, store_dir, db_dir, db_path, signing_key } = stopped;
    // `restart_node` takes a running node; this one only supplies the identity and paths it
    // reopens, and is dropped by it.
    let placeholder = DaemonState::new(
        device_id.clone(),
        Arc::new(ReplicaCoordinator::open_in_memory().unwrap()),
        Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap()),
    );
    restart_node_inner(
        TopologyNode {
            device_id,
            _releases_cycles: ReleasesCycles(placeholder.clone()),
            state: placeholder,
            root,
            store_dir,
            db_dir,
            db_path,
            signing_key,
        },
        refused_links_expected,
    )
    .await
}

pub fn link_eager(node: &TopologyNode, group_id: &str) {
    let local_path = node.root.path().to_string_lossy().to_string();
    node.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(node.state.clone()).start(local_path, group_id.to_string()).unwrap();
}

/// `LinkRuntimeController::start` fail-closes an `OnDemand` link unless
/// the root's on-demand capability reports a real platform-native
/// placeholder provider is wired up -- true only on real macOS/Windows
/// hardware in production. `set_test_on_demand_allowed` is the test-only escape
/// hatch this crate already wires a `test-support`-feature dev-dependency
/// for; it forces the gate open for THIS THREAD only, matching this
/// function's own synchronous, one-time-at-link-start call site (not
/// re-checked on every hydration operation), so it does not need to
/// cover the multi-threaded tokio runtime's worker threads.
pub fn link_on_demand(node: &TopologyNode, group_id: &str) {
    node.state.set_test_on_demand_allowed(true);
    let local_path = node.root.path().to_string_lossy().to_string();
    node.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    node.state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(&local_path, MaterializationPolicy::OnDemand)
        .unwrap();
    LinkRuntimeController::new(node.state.clone()).start(local_path, group_id.to_string()).unwrap();
}

/// Spawns `node`'s orchestrator on a DEDICATED child Tokio runtime,
/// returned so the caller's `TopologyHandles` can later kill it and
/// everything it transitively spawned in one shot.
///
/// `peer_orchestrator::run` itself spawns one DETACHED (bare
/// `tokio::spawn`, no `JoinHandle` retained anywhere) per-peer
/// reconnect-supervisor task per peer (`spawn_peer_session`) -- by design, matching production's own assumption
/// that these only ever stop via the whole PROCESS exiting, never a
/// supervising caller cancelling just this daemon's orchestrator layer
/// in isolation. Aborting only the top-level `run()` task (this
/// function's OWN earlier version) does NOT cascade to those detached
/// children: Tokio's `tokio::spawn` schedules an INDEPENDENT task, and
/// dropping/aborting a `JoinHandle` never aborts the task it was handed
/// out for unless that exact handle's `.abort()` is called. A restart
/// test that only aborted the top-level handle therefore left the "old"
/// node's per-peer supervisors (and everything they hold: `Arc<DaemonState>`
/// clones, the old `ReplicaCoordinator`/SQLite connection, old
/// `PeerChannel`/`PeerSyncSession` objects) running concurrently with the
/// "restarted" node's fresh ones.
///
/// A dedicated child runtime is the fix: every `tokio::spawn` call made
/// by code POLLED on that runtime (including `run()`'s own internal
/// spawns, and everything THEY spawn in turn) resolves to that SAME
/// runtime as its ambient context, since `tokio::spawn` always targets
/// "whichever runtime is currently driving this task" -- not the
/// runtime the calling code happened to be written in. `TopologyHandles`
/// dropping (or explicitly shutting down) that runtime therefore aborts
/// the whole tree at once, with zero production-code changes: this is a
/// pure test-harness technique, not a new production shutdown API (which
/// `peer_orchestrator` genuinely has none of today -- adding one is real,
/// separate scope beyond this restart-recovery fix).
/// Teaches every node where the others' reconciliation substrates answer.
///
/// This stands in for a hop these fixtures do not run, and the reason is
/// entirely on the test side -- production carries substrate addresses over
/// the coordination plane end to end. It breaks here twice:
///
/// 1. Nothing reports. `AddressDirectory::publish` reaches
///    `PeerConnectivityState::publish_substrate_endpoint`, which only writes the
///    `local_substrate_reachability` watch channel. Its one consumer is
///    `peer_connectivity_runtime::report_own_address`, spawned only by the
///    real `app.rs` startup. `spawn_orchestrator`
///    below mirrors `peer_orchestrator::run` and nothing else, so the watch
///    write has no reader and no endpoint report is ever POSTed.
/// 2. Nothing fans out. `FakeCoordination` stores a substrate report it does
///    receive, but its netmap frame carries `endpoints` only -- no
///    `substrateReachability` key. The daemon's own netmap decoder defaults
///    that field to `None`, so `project_substrate_reachability` takes its
///    compatibility branch and records relay URLs alone, leaving direct
///    addresses empty. No relay runs in these fixtures, so nothing dialable
///    results.
///
/// Teaching the fake to fan substrate reachability out -- the production
/// route, `endpoint report -> plane state -> netmap -> peer projection ->
/// address directory` -- would retire this helper fixture by fixture. That is
/// deliberately separate work: it changes fixture semantics for every
/// integration binary at once, so it belongs behind an opt-in capability
/// rather than mixed into a fix.
///
/// The address cannot simply ride `peer.endpoints`: that list is the legacy
/// peer-session transport's dial targets, the two transports listen on
/// different sockets with different ALPNs, and a dial landing on the wrong one
/// is refused for an unknown ALPN rather than retried.
///
/// Re-run after a restart: the substrate rebinds, so every address previously
/// known for it is stale from that moment. iroh republishes on its own, which
/// is why the daemon side needs no equivalent call.
pub async fn advertise_substrate_endpoints(nodes: &[&TopologyNode]) {
    // Shares `support`'s barrier rather than keeping a second copy. The copy
    // that used to live here had the same startup race: it waited for the
    // SOURCE to be serving but skipped any target that was not yet,
    // permanently dropping that direction.
    super::advertise_substrate_over(&TopologySubstrateDevices(nodes)).await;
    // ...and keep it current afterwards. A node's address is not final when
    // it first serves, and a restarted node's changes again shortly after
    // this barrier runs -- see `super::keep_substrate_advertised`.
    let states: Vec<&Arc<DaemonState>> = nodes.iter().map(|node| &node.state).collect();
    super::keep_substrate_advertised(&states);
}

/// Topology nodes as advertisement participants, naming the device in the
/// timeout assertion the way this module's own copy used to.
struct TopologySubstrateDevices<'a>(&'a [&'a TopologyNode]);

impl super::SubstrateDevices for TopologySubstrateDevices<'_> {
    fn device_count(&self) -> usize {
        self.0.len()
    }

    fn serving_address(&self, index: usize) -> Option<super::SubstrateAddress> {
        let driver = self.0[index].state.peer_session_driver()?;
        let address = driver.stack().local_address();
        let direct: Vec<std::net::SocketAddr> = address.direct_addrs().copied().collect();
        let relays: Vec<String> = address.relay_urls().map(ToString::to_string).collect();
        (!direct.is_empty() || !relays.is_empty()).then_some((address.peer(), direct, relays))
    }

    fn record(&self, target: usize, (peer, direct, relays): &super::SubstrateAddress) {
        self.0[target]
            .state
            .peer_session_driver()
            .expect("every node was proven to be serving in the phase above")
            .stack()
            .address_directory()
            .record(*peer, direct.clone(), relays.clone());
    }

    fn describe(&self, index: usize) -> String {
        self.0[index].device_id.clone()
    }
}

pub fn spawn_orchestrator(
    coordination_addr: String,
    node: &TopologyNode,
) -> tokio::runtime::Runtime {
    let device_id = node.device_id.clone();
    let log_device_id = device_id.clone();
    let state = node.state.clone();
    // Mirrors `app.rs`'s real startup path: production calls this once,
    // early, whenever both the address and token are available -- a test
    // node needs the exact same thing so `DaemonState::coordination_client_config`
    // is populated for anything that reads it directly rather than through
    // `OrchestratorConfig` (Track Send's `request_send_authorization`/
    // `consume_send_authorization`, and the role-loss-compensation path).
    // A no-op if already set, matching `OnceLock::set`'s own semantics, so
    // this is safe for every other existing test that never reads it.
    state.set_coordination_client_config(
        coordination_addr.clone(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        auth: yadorilink_fapi_client::test_support::offline_auth(),
        device_id,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("building a dedicated per-node orchestrator runtime must not fail in tests");
    runtime.spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    });
    runtime
}

/// A session exists between `state` and `peer_device_id` -- the peer is
/// authorized and reachable over the iroh substrate. Shared rather than
/// duplicated per test file with drift risk.
pub fn fully_connected(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    state.peers.has_session(peer_device_id)
}

/// Retries `hydrate` a bounded number of times with a fixed backoff.
/// `fully_connected` turning true is reachability, not a guarantee the
/// underlying `PeerSyncSession` is ready to serve a `fetch_block` call on
/// the very next poll -- a single immediate attempt right after a route/
/// reconnect wait can still race that by a few hundred milliseconds.
/// Panics (with the real error) once attempts are exhausted, since a
/// hydrate that should eventually succeed and still doesn't is a genuine
/// failure, not something to swallow.
pub async fn hydrate_with_retries(state: &Arc<DaemonState>, group_id: &str, path: &str) {
    let mut attempts = 0;
    loop {
        match yadorilink_daemon::hydration::hydrate(state, group_id, path).await {
            Ok(()) => return,
            Err(error) if attempts < 8 => {
                attempts += 1;
                tracing::warn!(%error, attempts, path, "hydration attempt failed, retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => panic!("hydration of {path} should eventually succeed: {error}"),
        }
    }
}

/// Stands up the canonical N(FullReplica)/M(OnDemand)/W(OnDemand) topology
/// sharing `group_id`, spawns real orchestrators for all three, and waits
/// for full mesh connectivity (N<->M, N<->W, M<->W) before returning. N is
/// registered as the group's full-replica writer with the coordination
/// plane (`fake.set_full_replica`).
pub async fn stand_up_canonical_topology(
    fake: &FakeCoordination,
    group_id: &str,
) -> (TopologyNode, TopologyNode, TopologyNode, TopologyHandles) {
    stand_up_canonical_topology_with_m_http_coordination(fake, group_id, None).await
}

/// [`stand_up_canonical_topology`], but with **M only** pointed at
/// `m_http_addr` for plain HTTP coordination instead of the netmap fake.
///
/// Two things force this shape, and both are easy to get wrong.
///
/// First, it has to happen before the orchestrators spawn.
/// `DaemonState::coordination_client_config` is a `OnceLock` whose `set`
/// return value is discarded, and [`spawn_orchestrator`] claims it — so a
/// test that stands the topology up first and calls
/// `set_coordination_client_config` afterwards is writing into an
/// already-claimed lock and its call does nothing, silently. Measured
/// directly: three sets to the fake's address succeeded, and every later set
/// to a test's own address was discarded.
///
/// Second, it has to be M and not every node. Redirecting a node's
/// coordination base URL takes `authorization-checkpoint` with it, and this
/// fake serves that route *statefully* — same policy-log verifier the daemon
/// runs, pinned policy epoch/seq/head, per-device issuance counter, signed
/// with the fake's own policy-service key. A device that authors content
/// needs it to work, so N keeps the fake; M, which only receives here, can
/// be pointed elsewhere to have its own outbound calls scripted and counted.
pub async fn stand_up_canonical_topology_with_m_http_coordination(
    fake: &FakeCoordination,
    group_id: &str,
    m_http_addr: Option<&str>,
) -> (TopologyNode, TopologyNode, TopologyNode, TopologyHandles) {
    let n = new_node("topology-n-nas");
    let m = new_node("topology-m-mac");
    let w = new_node("topology-w-windows");

    if let Some(addr) = m_http_addr {
        m.state.set_coordination_client_config(
            addr.to_string(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );
    }

    for node in [&n, &m, &w] {
        register_with_fake(fake, &node.state, &node.device_id, &[group_id]).await;
    }
    link_eager(&n, group_id);
    link_on_demand(&m, group_id);
    link_on_demand(&w, group_id);

    fake.set_full_replica(&n.device_id, group_id, true);

    let orchestrators: Vec<(String, tokio::runtime::Runtime)> = [&n, &m, &w]
        .map(|node| (node.device_id.clone(), spawn_orchestrator(fake.addr(), node)))
        .into_iter()
        .collect();

    // Before the mesh wait: every node's reconciliation substrate has to be
    // dialable, not just its peer-session transport. See
    // `advertise_substrate_endpoints`.
    advertise_substrate_endpoints(&[&n, &m, &w]).await;

    wait_until_with_context(
        || {
            fully_connected(&n.state, &m.device_id)
                && fully_connected(&n.state, &w.device_id)
                && fully_connected(&m.state, &w.device_id)
        },
        Duration::from_secs(60),
        || {
            format!(
                "canonical topology never reached full mesh: n<->m={} n<->w={} m<->w={}",
                fully_connected(&n.state, &m.device_id),
                fully_connected(&n.state, &w.device_id),
                fully_connected(&m.state, &w.device_id),
            )
        },
    )
    .await;

    (n, m, w, TopologyHandles { orchestrators })
}

/// Like [`stand_up_canonical_topology`], but M is ALSO a real, production
/// full replica (`link_eager` plus the matching coordination-plane
/// declaration -- the exact pairing N already gets there) instead of
/// On-Demand: N(FullReplica)/M(FullReplica)/W(OnDemand). The
/// "real `Protected`/`AvailableNow` through a confirmed remote holder"
/// scenario needs a SECOND real full replica -- `classify()`'s `Protected`
/// path deliberately requires an OTHER confirmed full-replica peer, never
/// a device's own local completeness alone, and `fetch_available_via_
/// confirmed_peer` needs a peer whose custody confirmation is real, not a
/// `FakeCoordination`-only declaration mismatched against that device's
/// actual local storage mode (the exact review finding this helper exists
/// to avoid repeating -- see `durability_unobtainable_content.rs`'s own
/// module doc for the same lesson learned there).
pub async fn stand_up_topology_two_full_replicas_one_on_demand(
    fake: &FakeCoordination,
    group_id: &str,
) -> (TopologyNode, TopologyNode, TopologyNode, TopologyHandles) {
    let n = new_node("topology-n-nas");
    let m = new_node("topology-m-second-complete-copy");
    let w = new_node("topology-w-windows");

    for node in [&n, &m, &w] {
        register_with_fake(fake, &node.state, &node.device_id, &[group_id]).await;
    }
    link_eager(&n, group_id);
    link_eager(&m, group_id);
    link_on_demand(&w, group_id);

    fake.set_full_replica(&n.device_id, group_id, true);
    fake.set_full_replica(&m.device_id, group_id, true);

    let orchestrators: Vec<(String, tokio::runtime::Runtime)> = [&n, &m, &w]
        .map(|node| (node.device_id.clone(), spawn_orchestrator(fake.addr(), node)))
        .into_iter()
        .collect();

    // Before the mesh wait: every node's reconciliation substrate has to be
    // dialable, not just its peer-session transport. `fully_connected` below
    // checks only the latter, so without this the mesh looks complete while
    // the plane that carries DAG changes has no route at all. This helper
    // was a near-copy of `stand_up_canonical_topology` that lost the line.
    advertise_substrate_endpoints(&[&n, &m, &w]).await;

    wait_until_with_context(
        || {
            fully_connected(&n.state, &m.device_id)
                && fully_connected(&n.state, &w.device_id)
                && fully_connected(&m.state, &w.device_id)
        },
        Duration::from_secs(60),
        || {
            format!(
                "two-complete-copy topology never reached full mesh: n<->m={} n<->w={} m<->w={}",
                fully_connected(&n.state, &m.device_id),
                fully_connected(&n.state, &w.device_id),
                fully_connected(&m.state, &w.device_id),
            )
        },
    )
    .await;

    (n, m, w, TopologyHandles { orchestrators })
}

/// A test's own mesh-wide background tasks -- each entry is the
/// dedicated child runtime [`spawn_orchestrator`] created for one node
/// (see that function's own doc comment for why a whole runtime, not
/// just a `JoinHandle`, is what's needed to actually kill everything a
/// node's orchestrator transitively spawns). Every scenario using this
/// topology must call [`Self::shutdown`] (or hold this until the test's
/// natural end, where `Drop` shuts down as a fallback) before returning:
/// a test binary can have more than one `#[tokio::test]`, all running
/// concurrently in the SAME process by default, so an un-torn-down mesh
/// from one test competes for CPU/UDP sockets with a sibling test's own
/// mesh -- the exact, previously-documented failure mode
/// `connect_two_daemons_with_handles`'s own doc comment describes for
/// `monkey_chaos.rs`'s per-iteration case.
pub struct TopologyHandles {
    orchestrators: Vec<(String, tokio::runtime::Runtime)>,
}

impl TopologyHandles {
    /// No orchestrators yet; for a test that stands nodes up one at a time.
    pub fn new() -> Self {
        Self { orchestrators: Vec::new() }
    }

    pub fn shutdown(mut self) {
        for (_, runtime) in self.orchestrators.drain(..) {
            shutdown_runtime(runtime);
        }
    }

    /// Removes and shuts down ONLY `device_id`'s own orchestrator
    /// runtime, leaving every other node's untouched -- required for a
    /// single-node restart scenario, where M/W must keep running (their
    /// own reconnect supervisors are what actually notice N coming back)
    /// while only N's old generation is torn down. A plain `drop(handles)`
    /// (this struct's own `Drop` impl) would incorrectly kill EVERY
    /// node's orchestrator at once -- exactly wrong for "restart just
    /// one node." Panics if `device_id` has no registered runtime --
    /// silently doing nothing here would mask exactly the class of bug
    /// this whole struct exists to prevent (a caller that assumed a
    /// node's old generation was torn down when it never was).
    ///
    /// Unlike `shutdown`/`Drop` (which use `shutdown_background` -- see
    /// that function's own doc comment for why they must not block), this
    /// method genuinely WAITS for the old generation's tasks to finish
    /// (bounded, via `shutdown_timeout`) before returning: a restart
    /// scenario's very next step reopens the SAME on-disk block store and
    /// index DB the old generation's still-running `spawn_blocking` store/
    /// compression work could still be touching (a real race if this
    /// method used the same non-blocking `shutdown_background` the other
    /// two do). The wait itself runs inside `spawn_blocking` -- off this
    /// async task's own worker thread -- specifically so blocking here
    /// cannot deadlock against this SAME test's outer Tokio runtime.
    pub async fn take_and_shutdown(&mut self, device_id: &str) {
        let index = self
            .orchestrators
            .iter()
            .position(|(id, _)| id == device_id)
            .unwrap_or_else(|| panic!("no registered orchestrator runtime for {device_id:?}"));
        let (_, runtime) = self.orchestrators.remove(index);
        const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);
        let device_id = device_id.to_string();
        tokio::task::spawn_blocking(move || {
            let start = std::time::Instant::now();
            runtime.shutdown_timeout(SHUTDOWN_DEADLINE);
            // `shutdown_timeout` does not report whether it hit the
            // deadline -- Tokio's own docs say unfinished work and its
            // threads are simply LEAKED and keep running if it does. A
            // caller here is about to reopen the exact on-disk store/DB
            // that leaked, still-running work (e.g. a peer session's
            // `spawn_blocking` store reads/writes) could still be
            // touching, so silently returning after a hit deadline would
            // reintroduce the exact race this method exists to close.
            // Measuring elapsed time against the same deadline (with a
            // small margin so ordinary scheduling jitter right at
            // completion can't false-positive) is the only signal
            // available; a genuine timeout leaves `elapsed` at
            // approximately the full deadline, while a real completion
            // returns as soon as tasks finish, almost always well under it.
            assert!(
                start.elapsed() < SHUTDOWN_DEADLINE - Duration::from_millis(500),
                "orchestrator runtime for {device_id:?} did not fully drain within its \
                 {SHUTDOWN_DEADLINE:?} shutdown deadline -- leaked tasks may still be touching \
                 the on-disk store/DB this test is about to reopen"
            );
        })
        .await
        .expect("orchestrator runtime teardown task panicked");
    }

    /// Registers `device_id`'s orchestrator runtime (e.g. the one
    /// [`spawn_orchestrator`] returns after [`restart_node`]) so it's
    /// tracked by this struct's own `Drop`/`shutdown`/`take_and_shutdown`
    /// exactly like the original three nodes' -- required for a SECOND
    /// restart cycle to have anything to tear down, and so the fresh
    /// generation's own per-peer supervisors don't outlive the test
    /// (the exact leak this struct's own doc comment describes) just
    /// because they were spawned after the initial
    /// `stand_up_canonical_topology` call.
    pub fn insert(&mut self, device_id: String, runtime: tokio::runtime::Runtime) {
        self.orchestrators.push((device_id, runtime));
    }
}

/// `shutdown_background` (not a plain `drop`, and not
/// `shutdown_timeout`): returns immediately without blocking this
/// thread, which matters here since this runs from INSIDE the test's
/// own async runtime -- a blocking wait for another runtime's worker
/// threads to fully drain would risk an executor-on-executor deadlock if
/// anything on that thread pool is (even transitively) waiting on this
/// one. The child runtime's worker threads still exit promptly on their
/// own once their tasks observe the shutdown signal at their next yield
/// point.
fn shutdown_runtime(runtime: tokio::runtime::Runtime) {
    runtime.shutdown_background();
}

impl Drop for TopologyHandles {
    fn drop(&mut self) {
        for (_, runtime) in self.orchestrators.drain(..) {
            shutdown_runtime(runtime);
        }
    }
}
