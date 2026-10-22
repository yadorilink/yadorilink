//! Native replication in real daemons: two devices, real sessions over
//! loopback, real (fake-plane) checkpoints. Nothing here feeds native from
//! DCF: a remote head reaches a device's `NativeState` only as a signed
//! delta over the native-replication ALPN.

mod native_e2e_support;
mod support;

use native_e2e_support::*;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_sqlite::{native_replication, native_store};

const GROUP: &str = "native-e2e-group";

fn setup() {
    support::ensure_isolated_config_dir();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

async fn two() -> (TopologyNode, TopologyNode) {
    let a = device("nat-a", GROUP);
    let b = device("nat-b", GROUP);
    pair(&a, &b, GROUP).await;
    (a, b)
}

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.to_string())
}

fn roots(node: &TopologyNode) -> native_replication::SummaryRoots {
    read(node, |conn| native_replication::summary_roots(conn, &group()))
}

fn native_head_count(node: &TopologyNode, path: &str) -> usize {
    read(node, |conn| {
        Ok(native_store::native_heads_at(
            conn,
            &group(),
            &yadorilink_replica_domain::ids::SyncPath(path.to_string()),
        )?
        .len())
    })
}

async fn native_converged(a: &TopologyNode, b: &TopologyNode, what: &str) {
    support::wait_until_with_context(
        || roots(a) == roots(b),
        std::time::Duration::from_secs(60),
        || format!("{what}: {:?} vs {:?}", roots(a), roots(b)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remote_write_reaches_the_peers_native_state() {
    setup();
    let (a, b) = two().await;
    assert!(
        a.state.native_replication_attached_for_test(&b.device_id)
            || b.state.native_replication_attached_for_test(&a.device_id)
    );

    write(&a, "note.txt", b"from a");
    captured(&a, GROUP).await;
    converge_to(&[&a, &b], &[("note.txt", b"from a")], "the file syncs").await;

    native_converged(&a, &b, "native state follows").await;
    assert_eq!(
        native_head_count(&b, "note.txt"),
        1,
        "b's native state holds a's head, received as a delta"
    );
}

/// Two concurrent writes of one path: the author of the losing head moves it
/// to its copy path, an ordinary entry on both devices, and the original path
/// keeps one head.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_are_forked_into_an_ordinary_copy_on_both_devices() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let (a, b) = two().await;
    write(&a, "c.txt", b"base");
    converge_to(&[&a, &b], &[("c.txt", b"base")], "base").await;
    partition(&a, &b).await;
    write(&a, "c.txt", b"from a");
    write(&b, "c.txt", b"from b");
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;
    let tree = converge_where(&[&a, &b], "a conflict copy appears", |tree| {
        conflict_copies(tree).len() == 1
    })
    .await;
    let copy = conflict_copies(&tree).remove(0);

    native_converged(&a, &b, "native state converges").await;
    for node in [&a, &b] {
        assert_eq!(native_head_count(node, "c.txt"), 1, "{}: the winner", node.device_id);
        assert_eq!(native_head_count(node, &copy), 1, "{}: the forked copy", node.device_id);
    }
}

/// Deleting a conflict copy removes its content's heads and the copy on every
/// device, whichever device wrote it: the copy is an ordinary entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_conflict_copy_removes_it_on_both_devices() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the deletion reaching the original",
    ) {
        return;
    }
    setup();
    let (a, b) = two().await;
    write(&a, "c.txt", b"base");
    converge_to(&[&a, &b], &[("c.txt", b"base")], "base").await;
    partition(&a, &b).await;
    write(&a, "c.txt", b"from a");
    write(&b, "c.txt", b"from b");
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;
    let tree = converge_where(&[&a, &b], "a conflict copy appears", |tree| {
        conflict_copies(tree).len() == 1
    })
    .await;
    let copy = conflict_copies(&tree).remove(0);
    let kept = tree["c.txt"].clone();
    remove(&b, &copy);
    converge_to(&[&a, &b], &[("c.txt", &kept)], "the copy is gone everywhere").await;
    native_converged(&a, &b, "native state converges").await;
    for node in [&a, &b] {
        assert_eq!(native_head_count(node, "c.txt"), 1, "{}: the winner stays", node.device_id);
        assert_eq!(
            native_head_count(node, &copy),
            0,
            "{}: the copy's head is gone",
            node.device_id
        );
    }
}

/// Unlinking drops only the link row. Linking the same folder again keeps the
/// replica's history, and what changed on disk meanwhile is authored as new
/// changes of this device that are concurrent with whatever the peer did that
/// this replica had not seen: a delete never removes a put it did not observe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relinking_after_unlink_authors_local_differences_as_concurrent_changes() {
    use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;

    setup();
    let (a, b) = two().await;
    write(&a, "x.txt", b"x0");
    write(&a, "z.txt", b"z0");
    converge_to(&[&a, &b], &[("x.txt", b"x0"), ("z.txt", b"z0")], "base").await;
    let a_versions_of_x =
        || a.state.replica_coordinator.sqlite().dag_list_versions(GROUP, "x.txt").unwrap();
    let versions_before = a_versions_of_x();
    assert!(!versions_before.is_empty());

    // Unlink A: the watcher stops and only the links row goes.
    let a_path = a.root.path().to_string_lossy().to_string();
    LinkRuntimeController::new(a.state.clone()).stop(&a_path).await;
    a.state.replica_coordinator.link_repository().remove_link(&a_path).unwrap();

    // While A is unlinked: A deletes x, edits z and creates w on disk; B, which
    // never saw any of that, edits x, adds y and edits z.
    remove(&a, "x.txt");
    write(&a, "z.txt", b"z-from-a");
    write(&a, "w.txt", b"w-from-a");
    write(&b, "x.txt", b"x1");
    write(&b, "y.txt", b"y-from-b");
    write(&b, "z.txt", b"z-from-b");
    captured(&b, GROUP).await;

    // Relink the same folder and reconnect.
    link_eager(&a, GROUP);
    pair(&a, &b, GROUP).await;

    // A platform without durable namespace changes cannot finish the conflict
    // on z (the winner replacing the loser's original), so there only the
    // safety properties are checked, after the creations have propagated and
    // the native state has converged.
    let resolves_conflicts = yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the conflict winner replacing the loser's original",
    );
    let tree = if resolves_conflicts {
        let tree = converge_where(&[&a, &b], "the unlinked-time changes merge", |tree| {
            tree.get("w.txt").is_some()
                && tree.get("y.txt").is_some()
                && conflict_copies(tree).len() == 1
        })
        .await;
        captured(&a, GROUP).await;
        native_converged(&a, &b, "native state converges").await;
        Some(tree)
    } else {
        support::wait_until_with_context(
            || tree(&a).contains_key("y.txt") && tree(&b).contains_key("w.txt"),
            std::time::Duration::from_secs(60),
            || format!("A: {:?}; B: {:?}", tree(&a).keys(), tree(&b).keys()),
        )
        .await;
        captured(&a, GROUP).await;
        native_converged(&a, &b, "native state converges").await;
        None
    };

    // B's unobserved new version of x survives A's delete, in B's folder and
    // as the one head A's delete left.
    assert_eq!(tree_of(b.root.path())["x.txt"], b"x1", "B's unobserved new version of x survives");
    assert_eq!(tree_of(a.root.path())["y.txt"], b"y-from-b", "B's new file arrives");
    assert_eq!(tree_of(b.root.path())["w.txt"], b"w-from-a", "A's new file syncs");
    assert_eq!(
        native_head_count(&a, "x.txt"),
        1,
        "A's delete removed only the head it had observed"
    );
    if let Some(tree) = tree {
        assert_eq!(tree["x.txt"], b"x1", "B's unobserved new version of x survives A's delete");
        let z_copy = conflict_copies(&tree).remove(0);
        let mut z_versions = [tree["z.txt"].clone(), tree[&z_copy].clone()];
        z_versions.sort();
        assert_eq!(
            z_versions,
            [b"z-from-a".to_vec(), b"z-from-b".to_vec()],
            "both concurrent edits of z are preserved"
        );
    }

    // A's history survived the unlink and relink: every version of x it
    // recorded before is still listed (its state moves on, its content hash
    // does not).
    let after: Vec<_> = a_versions_of_x().into_iter().map(|v| v.version_hash).collect();
    for kept in &versions_before {
        assert!(
            after.contains(&kept.version_hash),
            "a version of x recorded before the unlink is gone"
        );
    }
    assert!(after.len() > versions_before.len(), "the new versions are recorded beside the old");
}

/// A device whose folder is edited and pruned while its daemon is stopped
/// learns of those changes only at startup. Nothing may be lost: the deleted
/// file must disappear on the peer too, the edited bytes must survive on both
/// devices, and both must settle on one native state. An offline edit is an
/// ordinary edit: the peer receives it at the same path and no
/// conflicted copy appears on either device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edits_and_deletes_made_while_a_device_was_stopped_reach_its_peer_after_restart() {
    use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;

    setup();
    let (a, b) = two().await;
    write(&a, "report.txt", b"version one");
    write(&a, "gone.txt", b"to be deleted");
    converge_to(
        &[&a, &b],
        &[("report.txt", b"version one"), ("gone.txt", b"to be deleted")],
        "base",
    )
    .await;
    native_converged(&a, &b, "the base is shared").await;
    let roots_before = roots(&b);

    // Stop A's watcher, then change the folder behind its back.
    let a_path = a.root.path().to_string_lossy().to_string();
    LinkRuntimeController::new(a.state.clone()).stop(&a_path).await;
    let edited: &[u8] = b"version two, edited while the daemon was stopped";
    write(&a, "report.txt", edited);
    remove(&a, "gone.txt");

    let a = restart(a, &[&b], GROUP).await;
    let settled = converge_where(&[&a, &b], "the offline edit and delete reach the peer", |tree| {
        !tree.contains_key("gone.txt") && tree.get("report.txt").map(Vec::as_slice) == Some(edited)
    })
    .await;
    assert!(!settled.contains_key("gone.txt"), "the offline delete reaches the peer");
    for node in [&a, &b] {
        assert_eq!(
            tree(node).get("report.txt").map(Vec::as_slice),
            Some(edited),
            "{}: the peer receives the plain edit",
            node.device_id
        );
        assert!(
            conflict_copies(&tree(node)).is_empty(),
            "{}: an offline edit must not leave a conflicted copy: {:?}",
            node.device_id,
            conflict_copies(&tree(node))
        );
    }
    native_converged(&a, &b, "native state follows").await;
    assert_ne!(roots(&b), roots_before, "the peer's native state advanced past the base");
}

/// An offline edit that races a peer's edit of the same file is not special:
/// both sides keep their bytes through the ordinary conflict path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offline_edit_racing_a_peer_edit_keeps_both_versions_as_a_normal_conflict() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;

    setup();
    let (a, b) = two().await;
    write(&a, "doc.txt", b"base");
    converge_to(&[&a, &b], &[("doc.txt", b"base")], "base").await;
    native_converged(&a, &b, "the base is shared").await;

    let a_path = a.root.path().to_string_lossy().to_string();
    LinkRuntimeController::new(a.state.clone()).stop(&a_path).await;
    partition(&a, &b).await;
    let offline: &[u8] = b"edited on A while its daemon was stopped";
    let peer: &[u8] = b"edited on B meanwhile";
    write(&a, "doc.txt", offline);
    write(&b, "doc.txt", peer);
    captured(&b, GROUP).await;

    let a = restart(a, &[&b], GROUP).await;
    let tree = converge_where(&[&a, &b], "both versions survive on both devices", |tree| {
        conflict_copies(tree).len() == 1
            && tree.values().any(|c| c.as_slice() == offline)
            && tree.values().any(|c| c.as_slice() == peer)
    })
    .await;
    assert_eq!(conflict_copies(&tree).len(), 1, "exactly one conflicted copy: {tree:?}");
    native_converged(&a, &b, "native state follows").await;
}

/// Two devices that independently write the same bytes at different times hold
/// versions that differ only in mtime. There is nothing to choose between, so
/// both end with one file at the path, no conflicted copy, and a native state
/// that agrees; the file is not rewritten into a ping-pong of new versions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identical_content_written_concurrently_converges_without_a_conflict() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let (a, b) = two().await;
    write(&a, "same.txt", b"base");
    converge_to(&[&a, &b], &[("same.txt", b"base")], "base").await;
    partition(&a, &b).await;
    write(&a, "same.txt", b"identical edit");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    write(&b, "same.txt", b"identical edit");
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;

    converge_to(&[&a, &b], &[("same.txt", b"identical edit")], "one file, no copy").await;
    native_converged(&a, &b, "native state converges").await;
    // Give a spurious fork or rewrite time to show itself, then check again.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    for node in [&a, &b] {
        let tree = tree(node);
        assert!(conflict_copies(&tree).is_empty(), "{}: {tree:?}", node.device_id);
        assert_eq!(tree.len(), 1, "{}: {tree:?}", node.device_id);
    }
    native_converged(&a, &b, "native state is still converged").await;

    // Both devices' heads of the shared content are one version, so a later
    // edit supersedes both and a later delete leaves nothing behind.
    write(&b, "same.txt", b"edited after converging");
    captured(&b, GROUP).await;
    converge_to(&[&a, &b], &[("same.txt", b"edited after converging")], "the edit wins").await;
    native_converged(&a, &b, "native state follows the edit").await;
    for node in [&a, &b] {
        assert_eq!(native_head_count(node, "same.txt"), 1, "{}: one head", node.device_id);
    }
    remove(&a, "same.txt");
    converge_to(&[&a, &b], &[], "the delete reaches both").await;
    native_converged(&a, &b, "native state follows the delete").await;
    for node in [&a, &b] {
        assert_eq!(native_head_count(node, "same.txt"), 0, "{}: no head", node.device_id);
    }
}
