//! Linking a folder the way production links a folder.
//!
//! Every scenario here needs one thing before its devices can talk: the state a
//! real device is in once its folder has been linked and its first startup scan
//! has committed. `SyncState::add_link` alone is *not* that state, and the two
//! ways it falls short are both silent — they do not fail, they make the peer
//! receive nothing and the scenario pass while testing nothing.
//!
//! **The startup gate.** `wait_group_ready` defers a peer change for a group
//! that has a live link and no startup gate. That pairing is not an oversight in
//! the product: it means the link's startup never got off the ground, so the
//! folder was never scanned this boot, and applying a peer change could overwrite
//! local bytes that were never indexed — with no conflict copy, because the local
//! content never became a change the DAG could see. Production therefore arms the
//! gate in the same breath as it commits the link row (at boot, and on AddLink
//! via the watcher start). A harness that calls `add_link` and stops has built a
//! state production never produces: a live link that is owed a startup forever.
//! Every arriving change is deferred, the peer's index stays empty, and the only
//! symptom is a startup canary that never converges.
//!
//! **The root marker.** Linking a folder also mints the on-disk root-identity
//! marker; a bare `add_link` writes only the index row. An unmarked root whose
//! indexed files are all absent is byte-for-byte an unmounted volume, which the
//! root-identity check refuses.
//!
//! **The root-commit authority.** A `PeerSyncSession`'s own
//! `root_commit_authority_provider` dependency is a *third*, entirely separate
//! gap from the two above -- it is not something `add_link`/`ReplicaCoordinator`
//! has any bearing on at all. A live production link's `LinkRuntime` holds a
//! real `RootLease`, established by an actual `start_link_watch`; a bare
//! `ReplicaCoordinator`/`PeerSyncSession` harness runs neither, and
//! `yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()` defaults this field to a deny-by-default
//! provider like every other one-time capability, so `root_lease_for` fails
//! closed with "no live root-commit authority ... no established link, or no
//! provider injected" the moment anything (`materialize` chief among them)
//! needs to admit a `RootCommitPermit`-gated write. Confirmed live: this exact
//! gap silently turned every `materialize_dag_content_head` call in
//! `dst_dag_catchup_chaos.rs`'s DAG-catch-up scenario into a swallowed `Err`
//! (via `reconcile_group_paths`'s catch-all `tracing::warn!` + `retry`,
//! invisible under a harness with no tracing subscriber installed) — the
//! startup canary was admitted, resolved, and reported `Present`, yet never
//! once reached an actual disk write. [`TestRootCommitAuthorityProvider`]
//! below is this file's substitute (mirroring
//! `yadorilink-peer-session`'s own crate-internal
//! `AlwaysValidRootCommitAuthorityProvider`, not reachable from outside that
//! crate) -- every scenario building a `PeerSyncSessionDeps` needs
//! `root_commit_authority_provider: Arc::new(TestRootCommitAuthorityProvider)`
//! in its struct literal, not just `..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()`.
//! `link_and_start` cannot install this itself (it has no `PeerSyncSession` to
//! install it on) -- unlike the startup gate and root marker above, this one
//! is each scenario's own responsibility at session-construction time.
//!
//! Marking ready immediately is honest rather than a shortcut: these roots start
//! empty, so "the startup scan has committed its results" is vacuously true —
//! precisely the state the gate exists to certify. A scenario that wants to model
//! a *failed* or *in-flight* startup should drive `begin_group_startup` /
//! `mark_group_failed` itself and not use this.

use std::path::Path;
use std::sync::Arc;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_peer_session::peer_session::RootCommitAuthorityProvider;
use yadorilink_root_authority::root_commit::RootLease;
use yadorilink_root_authority::root_identity::VerifiedRoot;

/// A `PeerSyncSession`'s own `root_commit_authority_provider` dependency is
/// entirely separate from a `ReplicaCoordinator`'s
/// `install_test_root_commit_authority` (that one backs `DaemonState`'s own
/// `RootCommitAuthorityProvider` impl, which none of these bare
/// `ReplicaCoordinator`/`PeerSyncSession` scenarios construct at all).
/// `yadorilink_peer_session::peer_session::AlwaysValidRootCommitAuthorityProvider`
/// is this crate's private equivalent, reachable through
/// `PeerSyncSessionOneTimeDeps::test_permissive()` -- but that's the
/// crate-internal constructor path, not `yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()`
/// (which every scenario here actually builds sessions through), and
/// `standalone()` defaults this field to a deny-by-default provider like
/// every other one-time capability. Every scenario constructing a
/// `PeerSyncSessionDeps` needs this in its `change_authenticator: authenticator`
/// struct literal.
pub struct TestRootCommitAuthorityProvider;

impl RootCommitAuthorityProvider for TestRootCommitAuthorityProvider {
    fn root_lease_for(&self, _group_id: &str) -> Option<Arc<RootLease>> {
        Some(Arc::new(RootLease::for_tests()))
    }
}

/// Links `root` for `group_id` and brings it to the post-first-scan state:
/// claims the root and opens the group's startup gate. See this module's doc
/// comment for why `add_link` on its own leaves a device that can never
/// receive -- and, separately, why the caller's own `PeerSyncSessionDeps`
/// still needs `TestRootCommitAuthorityProvider` before it can materialize.
pub fn link_and_start(
    state: &ReplicaCoordinator,
    root: &Path,
    group_id: &str,
) -> Result<(), String> {
    state
        .link_repository()
        .add_link(&root.to_string_lossy(), group_id)
        .map_err(|e| e.to_string())?;
    adopt_root(state, root, group_id)?;
    open_startup_gate(state, group_id);
    Ok(())
}

/// Claims `root` as this device's folder for `group_id`, minting the marker, the
/// way linking a folder does. Split out for scenarios that need to link and
/// adopt at different points than [`link_and_start`] does.
pub fn adopt_root(state: &ReplicaCoordinator, root: &Path, group_id: &str) -> Result<(), String> {
    VerifiedRoot::open(root, group_id, state).map(|_| ()).map_err(|e| e.to_string())
}

/// Opens `group_id`'s startup gate, standing in for a completed startup scan.
/// Split out for scenarios that build their links by other means but still owe
/// the group a startup.
pub fn open_startup_gate(state: &ReplicaCoordinator, group_id: &str) {
    let generation = state.startup_readiness().begin_group_startup(group_id);
    state.startup_readiness().mark_group_ready(group_id, generation);
}
