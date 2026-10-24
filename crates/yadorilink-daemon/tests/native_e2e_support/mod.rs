//! Shared fixtures of the generation-11 daemon end-to-end tests.
//!
//! Devices are [`TopologyNode`]s: a file-backed replica database, a block
//! store and a linked folder, each restartable against the same on-disk
//! state with the same signing identity (`restart_node`). Devices pair over
//! the loopback reconciliation stack (`connect_two_daemons`) and are
//! partitioned by dropping that stack (`sever_reconciliation`). The oracle
//! is first the folder on disk, then the replica database read through the
//! production readers.
//!

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_replica_domain::author::{fixtures, AuthorId, IncarnationId};
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, canonical_signing_bytes, checkpoint_hash, fingerprint_signing_key,
    merkle_root, sign_checkpoint, AuthorizationCheckpoint,
};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, DeltaHash, DeviceId, FolderGroupId};
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::support;
pub use crate::support::topology::{link_eager, new_node, restart_node, TopologyNode};

/// How long a convergence wait may take before the test fails with the
/// devices' trees in the message.
pub const CONVERGE: Duration = Duration::from_secs(90);

// --- Devices and links ----------------------------------------------------------

/// A device linked to `group` with its folder watched.
pub fn device(name: &str, group: &str) -> TopologyNode {
    let node = new_node(name);
    link_eager(&node, group);
    node
}

/// Pairs `a` and `b` for `group` over the reconciliation stack. On the
/// first pairing of the group, both devices are granted writers by the
/// pairing's coordination plane and hold that signed policy, as a real
/// group's members do: a seal authorization the plane issues then verifies
/// on every peer (an empty bootstrap policy names no sealer).
pub async fn pair(a: &TopologyNode, b: &TopologyNode, group: &str) {
    support::connect_two_daemons(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        std::slice::from_ref(&group.to_string()),
    )
    .await;
    grant_writers(&[a, b], group);
    // Pairing installs the bootstrap policy before `grant_writers` installs
    // the plane's, so the flush inside `connect_two_daemons` cannot verify
    // a checkpoint, and a change captured before now (a restarted device's
    // startup scan, or an offline edit) would stay unpublished until the
    // next local write. Production flushes on reconnect once the verified
    // policy is in (`ws_netmap::spawn_flush_pending_checkpoints_on_
    // reconnect`); this is that flush.
    for node in [a, b] {
        node.state.flush_pending_checkpoint_for_group_for_test(group).await;
        node.state.flush_pending_native_checkpoint_for_group_for_test(group).await;
    }
}

/// Registers the fixture device `device` (its [`fixtures::signing_key`]) on
/// the nodes' coordination plane, grants it the writer role for `group`
/// and installs the resulting policy on every node: a fixture author whose
/// checkpoints ([`authorized_bundle`]) every peer verifies.
pub fn grant_fixture_writer(nodes: &[&TopologyNode], group: &str, device: &str) {
    let fake = support::checkpoint_fake_of(&nodes[0].state).expect("the nodes were paired");
    let key = fixtures::signing_key(&DeviceId(device.to_owned())).verifying_key().to_bytes();
    fake.register_device(device, key, "127.0.0.1:9".to_string(), &[group]);
    fake.grant_role(device, group, yadorilink_daemon::change_policy::WriterRole::Editor);
    let states: Vec<&Arc<DaemonState>> = nodes.iter().map(|node| &node.state).collect();
    install_plane_policy(&states, group);
}

/// Installs the group's current signed policy from the nodes' coordination
/// plane on every node.
fn install_plane_policy(states: &[&Arc<DaemonState>], group: &str) {
    use yadorilink_daemon::change_policy::verify_group_policy_log;
    let fake = support::checkpoint_fake_of(states[0]).expect("the nodes were paired");
    let service_key = fake
        .policy_signing_key()
        .expect("a pairing's plane signs policy")
        .verifying_key()
        .to_bytes();
    let log = fake.group_policy_log(group);
    for state in states {
        let policy = verify_group_policy_log(&service_key, &log).expect("the plane's log verifies");
        let mut policies = std::collections::HashMap::new();
        for link in state.replica_coordinator.link_repository().list_links().unwrap() {
            if let Some(existing) = state.authority.group_policy_state(&link.group_id) {
                policies.insert(link.group_id, existing);
            }
        }
        policies.insert(group.to_string(), policy);
        state.authority.replace_group_policy_states(policies);
    }
}

/// Grants every node in `nodes` the writer role for `group` on their shared
/// coordination plane, once, and installs the resulting signed policy on
/// each of them.
pub fn grant_writers(nodes: &[&TopologyNode], group: &str) {
    use yadorilink_daemon::change_policy::{verify_group_policy_log, WriterRole};
    let fake = support::checkpoint_fake_of(&nodes[0].state).expect("the nodes were paired");
    let service_key = fake
        .policy_signing_key()
        .expect("a pairing's plane signs policy")
        .verifying_key()
        .to_bytes();
    let before = fake.group_policy_log(group);
    let policy = verify_group_policy_log(&service_key, &before).expect("the plane's log verifies");
    for node in nodes {
        if !policy.current_writers().iter().any(|writer| writer.device_id == node.device_id) {
            fake.grant_role(&node.device_id, group, WriterRole::Editor);
        }
    }
    let states: Vec<&Arc<DaemonState>> = nodes.iter().map(|node| &node.state).collect();
    install_plane_policy(&states, group);
}

/// Demotes `device` to a viewer of `group` on the nodes' coordination plane and installs the
/// resulting signed policy on every node.
pub fn demote_to_viewer(nodes: &[&TopologyNode], group: &str, device: &str) {
    let fake = support::checkpoint_fake_of(&nodes[0].state).expect("the nodes were paired");
    fake.grant_role(device, group, yadorilink_daemon::change_policy::WriterRole::Viewer);
    let states: Vec<&Arc<DaemonState>> = nodes.iter().map(|node| &node.state).collect();
    install_plane_policy(&states, group);
}

/// [`demote_to_viewer`] for a caller that holds only the nodes' states, such as a hook that runs
/// while a daemon works.
pub fn demote_to_viewer_on(states: &[Arc<DaemonState>], group: &str, device: &str) {
    let fake = support::checkpoint_fake_of(&states[0]).expect("the nodes were paired");
    fake.grant_role(device, group, yadorilink_daemon::change_policy::WriterRole::Viewer);
    let refs: Vec<&Arc<DaemonState>> = states.iter().collect();
    install_plane_policy(&refs, group);
}

/// Partitions `a` from `b`: neither can reach the other until paired again.
pub async fn partition(a: &TopologyNode, b: &TopologyNode) {
    support::sever_reconciliation(&a.state, &b.state).await;
}

/// Restarts `node` against its own database, block store and folder, then
/// pairs it with every one of `peers` again.
pub async fn restart(node: TopologyNode, peers: &[&TopologyNode], group: &str) -> TopologyNode {
    support::topology::shutdown_substrate(&node).await;
    let node = restart_node(node).await;
    for peer in peers {
        pair(&node, peer, group).await;
    }
    node
}

// --- The folder on disk ---------------------------------------------------------

pub fn write(node: &TopologyNode, relative: &str, contents: &[u8]) {
    let path = node.root.path().join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

/// Removes a file. A directory goes through [`remove_dir`], which waits for the node's capture
/// to be quiescent first.
pub fn remove(node: &TopologyNode, relative: &str) {
    let path = node.root.path().join(relative);
    assert!(!path.is_dir(), "{relative} is a directory: use remove_dir");
    std::fs::remove_file(path).unwrap();
}

/// Renames a file. A directory goes through [`rename_dir`].
pub fn rename(node: &TopologyNode, from: &str, to: &str) {
    let from_path = node.root.path().join(from);
    assert!(!from_path.is_dir(), "{from} is a directory: use rename_dir");
    // quiescence-exempt: a file, which no open daemon capture can pin
    std::fs::rename(from_path, node.root.path().join(to)).unwrap();
}

/// Removes a directory tree once nothing of the node's own capture is pending or opening files
/// below it.
pub async fn remove_dir(node: &TopologyNode, group: &str, relative: &str) {
    support::quiescence::wait_quiescent(node.root.path(), &node.state, group).await;
    std::fs::remove_dir_all(node.root.path().join(relative)).unwrap();
}

/// Renames a directory once nothing of the node's own capture is pending or opening files below
/// it.
pub async fn rename_dir(node: &TopologyNode, group: &str, from: &str, to: &str) {
    support::quiescence::wait_quiescent(node.root.path(), &node.state, group).await;
    std::fs::rename(node.root.path().join(from), node.root.path().join(to)).unwrap();
}

/// Every real file under `root`, by relative path, with its contents; and
/// every real directory, as a path ending in `/` with no contents.
pub fn tree_of(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for name in support::real_entry_names(dir) {
            let path = dir.join(&name);
            let relative = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if path.is_dir() {
                out.insert(format!("{relative}/"), Vec::new());
                walk(root, &path, out);
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.insert(relative, bytes);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

pub fn tree(node: &TopologyNode) -> BTreeMap<String, Vec<u8>> {
    tree_of(node.root.path())
}

/// The names in `tree` that are conflict copies.
pub fn conflict_copies(tree: &BTreeMap<String, Vec<u8>>) -> Vec<String> {
    tree.keys().filter(|name| name.contains("(conflicted copy")).cloned().collect()
}

/// Waits until every device's folder holds the same tree and `accept`
/// holds for it.
pub async fn converge_where(
    nodes: &[&TopologyNode],
    what: &str,
    accept: impl Fn(&BTreeMap<String, Vec<u8>>) -> bool,
) -> BTreeMap<String, Vec<u8>> {
    support::wait_until_with_context(
        || {
            let first = tree(nodes[0]);
            accept(&first)
                && nodes[1..].iter().all(|node| tree(node) == first)
                && nodes.iter().all(|node| no_write_in_flight(node))
        },
        CONVERGE,
        || {
            let trees: Vec<String> = nodes
                .iter()
                .map(|node| {
                    format!(
                        "{}: {:?} [{}]",
                        node.device_id,
                        tree(node).keys().collect::<Vec<_>>(),
                        store_summary(node)
                    )
                })
                .collect();
            format!("{what}: {}", trees.join("; "))
        },
    )
    .await;
    tree(nodes[0])
}

/// Whether `node` has no materialization write still open. The bytes of a
/// peer's file are on disk before the write is committed, so a wait for the
/// tree alone returns while the daemon is still finishing the write; a test
/// that then edits the file races that commit (the edit lands between the
/// bytes and the proof, and is read as the daemon's own write). The state
/// commit, not the side effect, is what to wait for.
fn no_write_in_flight(node: &TopologyNode) -> bool {
    read(node, |conn| {
        let open: i64 =
            conn.query_row("SELECT COUNT(*) FROM materialization_intents", [], |row| row.get(0))?;
        Ok(open == 0)
    })
}

/// What a failed wait prints about one node's database: its native frontier and
/// live-head count (whether the devices agree on the state at all), the held
/// deltas and dirty paths still pending, and where the top level of its
/// projection differs from its own plan (names the plan places that the disk
/// lacks, and disk names the plan does not place). "The state differs" and "the
/// state agrees but the tree does not" are different bugs.
fn store_summary(node: &TopologyNode) -> String {
    let (state, group) = read(node, |conn| {
        let group: Option<String> = conn
            .query_row("SELECT group_id FROM native_author_frontier LIMIT 1", [], |row| row.get(0))
            .ok();
        let mut stmt = conn.prepare(
            "SELECT author, MAX(seq) FROM native_author_frontier GROUP BY author ORDER BY author",
        )?;
        let frontier = stmt
            .query_map([], |row| {
                Ok(format!("{}={}", row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut head_stmt = conn.prepare(
            "SELECT path || '@' || author || '#' || seq FROM native_heads ORDER BY path, author, seq",
        )?;
        let head_list = head_stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let heads = format!("{}{head_list:?}", head_list.len());
        let held: i64 =
            conn.query_row("SELECT COUNT(*) FROM native_delta_holds", [], |row| row.get(0))?;
        let dirty: i64 =
            conn.query_row("SELECT COUNT(*) FROM local_dirty_paths", [], |row| row.get(0))?;
        Ok((format!("frontier {frontier:?} heads {heads} held {held} dirty {dirty}"), group))
    });
    let Some(group) = group else { return state };
    let planned: std::collections::BTreeSet<String> = node
        .state
        .replica_coordinator
        .file_index_repository()
        .native_plan_level(&group, "")
        .map(|plan| plan.nodes.keys().map(|k| k.as_str().to_owned()).collect())
        .unwrap_or_default();
    let on_disk: std::collections::BTreeSet<String> =
        tree(node).keys().filter(|name| !name.contains('/')).cloned().collect();
    format!(
        "{state} planned_not_on_disk {:?} on_disk_not_planned {:?}",
        planned.difference(&on_disk).collect::<Vec<_>>(),
        on_disk.difference(&planned).collect::<Vec<_>>()
    )
}

/// Waits until every device's folder holds exactly `expected`.
pub async fn converge_to(nodes: &[&TopologyNode], expected: &[(&str, &[u8])], what: &str) {
    let expected: BTreeMap<String, Vec<u8>> =
        expected.iter().map(|(path, bytes)| (path.to_string(), bytes.to_vec())).collect();
    let files_only = |tree: &BTreeMap<String, Vec<u8>>| -> BTreeMap<String, Vec<u8>> {
        tree.iter()
            .filter(|(k, _)| !k.ends_with('/'))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    converge_where(nodes, what, |tree| files_only(tree) == expected).await;
}

// --- The replica database ---------------------------------------------------------

pub fn read<T>(node: &TopologyNode, f: impl FnMut(&Connection) -> Result<T, SyncSqliteError>) -> T {
    node.state.replica_coordinator.database().read(f).unwrap()
}

pub fn user_version(node: &TopologyNode) -> i32 {
    read(node, |conn| Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?))
}

/// Drops the signed body of every delta no live head rests on: the part of the
/// replication log a size/age policy would have collected. The hash log and
/// every delta a live head (or a row's witness) needs stay, so the node can
/// still seal its state but can no longer serve the history those deltas
/// carried.
pub fn collect_replication_log(node: &TopologyNode, group: &str) -> usize {
    node.state
        .replica_coordinator
        .database()
        .write(|conn| {
            let deleted = conn.execute(
                "DELETE FROM native_delta_bodies WHERE group_id = ?1 \
                 AND delta_hash NOT IN (SELECT provenance FROM native_heads WHERE group_id = ?1) \
                 AND delta_hash NOT IN (SELECT substr(native_authoring_identity, 1, 32) FROM files \
                                        WHERE group_id = ?1 AND state = 'current' \
                                          AND native_authoring_identity IS NOT NULL)",
                [group],
            )?;
            Ok::<_, SyncSqliteError>(deleted)
        })
        .unwrap()
}

/// Every path's present native heads, as (path, signed delta hashes).
pub fn heads(node: &TopologyNode, group: &str) -> BTreeMap<String, Vec<DeltaHash>> {
    let rows: Vec<(String, Vec<u8>)> = read(node, |conn| {
        let mut stmt =
            conn.prepare("SELECT path, provenance FROM native_heads WHERE group_id = ?1")?;
        let rows = stmt.query_map([group], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    });
    let mut out: BTreeMap<String, Vec<DeltaHash>> = BTreeMap::new();
    for (path, provenance) in rows {
        let hash: [u8; 32] = provenance.try_into().expect("a 32-byte provenance");
        out.entry(path).or_default().push(DeltaHash(hash));
    }
    for hashes in out.values_mut() {
        hashes.sort();
    }
    out
}

/// Everything two converged replicas agree on, read from the database:
/// every path's heads and the namespace root.
pub fn replica_state(
    node: &TopologyNode,
    group: &str,
) -> (BTreeMap<String, Vec<DeltaHash>>, String) {
    let root = read(node, |conn| {
        let group = yadorilink_replica_domain::ids::FolderGroupId(group.to_owned());
        let state = yadorilink_sync_sqlite::native_store::load_state(conn, &group)?;
        Ok(yadorilink_sync_sqlite::native_store::namespace_root(&state)
            .map(|root| format!("{root:?}"))
            .unwrap_or_default())
    });
    (heads(node, group), root)
}

/// Waits until every device's database state (heads, root) is the
/// same.
pub async fn converge_replicas(nodes: &[&TopologyNode], group: &str, what: &str) {
    support::wait_until_with_context(
        || {
            let first = replica_state(nodes[0], group);
            nodes[1..].iter().all(|node| replica_state(node, group) == first)
        },
        CONVERGE,
        || {
            let states: Vec<String> = nodes
                .iter()
                .map(|node| format!("{}: {:?}", node.device_id, replica_state(node, group)))
                .collect();
            format!("{what}: {}", states.join("; "))
        },
    )
    .await;
}

// --- The authority's own state ---------------------------------------------------------

/// The identities of the live heads at `path` in the native state, sorted:
/// `(dot, provenance)` pairs.
pub fn live_head_ids(node: &TopologyNode, group: &str, path: &str) -> Vec<String> {
    let mut ids: Vec<String> = read(node, |conn| {
        yadorilink_sync_sqlite::native_store::native_heads_at(
            conn,
            &FolderGroupId(group.to_owned()),
            &yadorilink_replica_domain::ids::SyncPath(path.to_owned()),
        )
    })
    .into_iter()
    .map(|head| {
        format!(
            "{}#{}@{}",
            head.dot.author.device.0,
            head.dot.seq.get(),
            head.payload.provenance.0.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    })
    .collect();
    ids.sort();
    ids
}

/// Waits until `node` holds a live head at `path` in the authority's own
/// state.
pub async fn has_live_head(node: &TopologyNode, group: &str, path: &str) {
    support::wait_until_with_context(
        || !live_head_ids(node, group, path).is_empty(),
        CONVERGE,
        || format!("{} never admitted a head at {path}", node.device_id),
    )
    .await;
}

/// The physical names the authority's plan for the group's top level shows,
/// each with the version it materializes, for a native run. Placements the
/// plan assigns on the way are why this needs a write connection.
pub fn native_plan_names(node: &TopologyNode, group: &str) -> BTreeMap<String, [u8; 32]> {
    use yadorilink_replica_domain::native_plan::NativePlannedNode;
    let plan = node
        .state
        .replica_coordinator
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::native_desired_state::native_plan_level(conn, group, "")
        })
        .unwrap();
    plan.nodes
        .into_iter()
        .filter_map(|(path, node)| match node {
            NativePlannedNode::Entry { head, .. } => {
                Some((path.as_str().to_owned(), head.version().0))
            }
            _ => None,
        })
        .collect()
}

/// Waits until every device holds the same authoritative state: DCF's base,
/// heads and root, or, for a native run, the same native summary roots.
pub async fn converge_state(nodes: &[&TopologyNode], group: &str, what: &str) {
    let roots = |node: &TopologyNode| {
        format!(
            "{:?}",
            read(node, |conn| yadorilink_sync_sqlite::native_replication::summary_roots(
                conn,
                &FolderGroupId(group.to_owned())
            ))
        )
    };
    support::wait_until_with_context(
        || {
            let first = roots(nodes[0]);
            nodes[1..].iter().all(|node| roots(node) == first)
        },
        CONVERGE,
        || {
            let states: Vec<String> =
                nodes.iter().map(|node| format!("{}: {}", node.device_id, roots(node))).collect();
            format!("{what}: native state: {}", states.join("; "))
        },
    )
    .await;
}

/// A removal a third author signed, delivered to one device by hand.
pub enum Removal {
    Native(yadorilink_replica_domain::signed_delta::NativeDelta),
}

impl Removal {
    /// Whether `node` holds the removal as admitted history.
    pub fn admitted_on(&self, node: &TopologyNode, group: &str) -> bool {
        match self {
            Removal::Native(delta) => read(node, |conn| {
                yadorilink_sync_sqlite::native_store::fetch_delta_body(
                    conn,
                    &FolderGroupId(group.to_owned()),
                    &delta.author,
                    delta.seq,
                )
            })
            .is_some(),
        }
    }
}

/// `remover`'s first delta in native terms: removes every live head `node`
/// holds at each of `paths`, signed with the fixture key, published under a
/// checkpoint the group's coordination plane issued, and admitted through
/// the production published-delta admission -- so `node` can serve it on to
/// its peers like any peer's delta. Nothing is projected until the
/// materialization wake the stack's receive would have given.
pub fn admit_native_removal(
    node: &TopologyNode,
    group: &str,
    remover: &str,
    paths: &[&str],
) -> yadorilink_replica_domain::signed_delta::NativeDelta {
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_replica_domain::signed_delta::{DeltaOp, HeadRef};
    let group_id = FolderGroupId(group.to_owned());
    let ops = paths
        .iter()
        .map(|path| {
            let heads = read(node, |conn| {
                yadorilink_sync_sqlite::native_store::native_heads_at(
                    conn,
                    &group_id,
                    &SyncPath((*path).to_owned()),
                )
            });
            assert!(!heads.is_empty(), "a native head to remove at {path}");
            DeltaOp {
                path: SyncPath((*path).to_owned()),
                removes: heads
                    .into_iter()
                    .map(|head| HeadRef { dot: head.dot, provenance: head.payload.provenance })
                    .collect(),
                put: None,
            }
        })
        .collect::<Vec<_>>();
    admit_native_ops(node, group, remover, ops)
}

/// `author`'s first delta with `ops`, signed with the fixture key, published
/// under a checkpoint the group's coordination plane issued, and admitted
/// through the production published-delta admission (see
/// [`admit_native_removal`]).
pub fn admit_native_ops(
    node: &TopologyNode,
    group: &str,
    author: &str,
    ops: Vec<yadorilink_replica_domain::signed_delta::DeltaOp>,
) -> yadorilink_replica_domain::signed_delta::NativeDelta {
    use yadorilink_replica_domain::ids::AuthorSeq;
    use yadorilink_replica_domain::signed_delta::NativeDelta;
    let author = fixture_author(author);
    let group_id = FolderGroupId(group.to_owned());
    let key = fixtures::signing_key(&author.device);
    let mut delta = NativeDelta {
        recursive_part: None,
        group_id: group_id.clone(),
        author: author.clone(),
        seq: AuthorSeq::FIRST,
        prev: None,
        ops,
        signature: [0; 64],
    };
    delta.sign(&key);

    let fake = support::checkpoint_fake_of(&node.state).expect("the node was paired");
    let authority = fake.policy_signing_key().expect("a pairing's plane signs policy");
    let log = fake.group_policy_log(group);
    let policy_head: [u8; 32] = log.policy_head.as_slice().try_into().expect("32-byte head");
    let leaves = [delta.delta_hash().0];
    let checkpoint = AuthorizationCheckpoint {
        group_id: group.to_owned(),
        device_id: author.device.as_str().to_owned(),
        signing_key_fingerprint: fingerprint_signing_key(&key.verifying_key()),
        merkle_root: merkle_root(&leaves),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: fingerprint_signing_key(&authority.verifying_key()),
        policy_epoch: log.current_epoch,
        policy_seq: log.current_seq,
        policy_head,
        issued_at_unix: 0,
    };
    let encoded = canonical_signing_bytes(&checkpoint);
    let signature = sign_checkpoint(&checkpoint, &authority);
    let hash = checkpoint_hash(&encoded, &signature);
    let proof = build_merkle_proof(&leaves, 0);
    let (fixture_author_id, fixture_key) = (author.clone(), key.verifying_key());
    let authority_key = authority.verifying_key();
    let authority_id = fingerprint_signing_key(&authority_key);
    let outcome = node
        .state
        .replica_coordinator
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::native_admission::admit_published_native_delta(
                conn,
                &group_id,
                &delta.to_wire_bytes(),
                &hash,
                &encoded,
                &signature,
                &key.verifying_key().to_bytes(),
                &proof,
                &|candidate: &AuthorId| (*candidate == fixture_author_id).then_some(fixture_key),
                |key_id: &[u8; 32], _head: &[u8; 32]| {
                    (*key_id == authority_id).then_some(authority_key)
                },
            )
        })
        .unwrap();
    assert!(
        matches!(
            outcome,
            yadorilink_sync_sqlite::native_admission::NativeAdmission::Admitted { .. }
        ),
        "{outcome:?}"
    );
    delta
}

/// Waits until `node` has captured every write on its disk: no dirty path
/// is left, and the index agrees with the folder -- every regular file
/// (conflict copies aside, which are projections) has a current row of its
/// size, and every current file row has its file. The dirty-path count
/// alone passes before the watcher has even reported a fresh write.
pub async fn captured(node: &TopologyNode, group: &str) {
    support::wait_until_with_context(
        || uncaptured(node, group).is_empty(),
        CONVERGE,
        || format!("{} never captured its writes: {:?}", node.device_id, uncaptured(node, group)),
    )
    .await;
}

/// What [`captured`] still waits for on `node`, one line per path.
fn uncaptured(node: &TopologyNode, group: &str) -> Vec<String> {
    let disk: BTreeMap<String, usize> = tree(node)
        .into_iter()
        .filter(|(path, _)| !path.ends_with('/') && !path.contains("(conflicted copy"))
        .map(|(path, bytes)| (path, bytes.len()))
        .collect();
    let (dirty, rows) = read(node, |conn| {
        let dirty: i64 = conn.query_row(
            "SELECT COUNT(*) FROM local_dirty_paths WHERE group_id = ?1",
            [group],
            |row| row.get(0),
        )?;
        let mut stmt = conn.prepare(
            "SELECT path, size FROM files WHERE group_id = ?1 AND state = 'current' \
               AND deleted = 0 AND record_kind = 'file'",
        )?;
        let rows = stmt
            .query_map([group], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok((dirty, rows))
    });
    let mut out = Vec::new();
    if dirty > 0 {
        out.push(format!("{dirty} dirty path(s)"));
    }
    for (path, len) in &disk {
        match rows.get(path) {
            Some(size) if *size == *len as i64 => {}
            other => out.push(format!("{path}: disk {len} bytes, row {other:?}")),
        }
    }
    for path in rows.keys() {
        if !path.contains("(conflicted copy") && !disk.contains_key(path) {
            out.push(format!("{path}: row without a file"));
        }
    }
    out
}

/// Waits until `node` holds a present head at `path`: its write there was
/// captured and admitted.
pub async fn has_head(node: &TopologyNode, group: &str, path: &str) {
    support::wait_until_with_context(
        || heads(node, group).contains_key(path),
        CONVERGE,
        || format!("{} never admitted a head at {path}", node.device_id),
    )
    .await;
}

// --- Remote input built by hand -----------------------------------------------------

/// The key the fixture authority signs checkpoints with.
pub fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&[0xA7; 32])
}

/// A fixture author on its own device.
pub fn fixture_author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.to_owned()), incarnation: IncarnationId([7; 16]) }
}

/// A real file version of `seed`.
pub fn fixture_version(seed: u8) -> FileVersion {
    FileVersion::new(
        vec![VersionBlock { hash: BlockHash(vec![seed; 32]), size: 16 }],
        16,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

pub fn shared(node: &TopologyNode) -> &Arc<DaemonState> {
    &node.state
}

/// A put of `version` at `path` by fixture author `author`, observing nothing
/// (a write that has seen none of the heads already at the path), delivered to
/// `node` alone. The version's content is stored on `node` first, as a peer's
/// delta batch would have carried it.
pub fn admit_native_put(
    node: &TopologyNode,
    group: &str,
    author: &str,
    path: &str,
    version: &FileVersion,
) -> yadorilink_replica_domain::signed_delta::NativeDelta {
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut};
    node.state
        .replica_coordinator
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::dag_store::put_file_version(conn, group, version)?;
            Ok::<_, SyncSqliteError>(())
        })
        .unwrap();
    admit_native_ops(
        node,
        group,
        author,
        vec![DeltaOp {
            path: yadorilink_replica_domain::ids::SyncPath(path.to_owned()),
            removes: Vec::new(),
            put: Some(DeltaPut { version: version.version_hash }),
        }],
    )
}

/// The device's native summary roots, as one comparable value: what a restart
/// or a no-op must leave unchanged.
pub fn native_state(node: &TopologyNode, group: &str) -> String {
    format!(
        "{:?}",
        read(node, |conn| yadorilink_sync_sqlite::native_replication::summary_roots(
            conn,
            &FolderGroupId(group.to_owned())
        ))
    )
}
