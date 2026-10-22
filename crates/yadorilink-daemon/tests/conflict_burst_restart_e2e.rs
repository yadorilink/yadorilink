//! Crash-recovery and conflict-preservation invariants of the large-tree acceptance run
//! (the maintainers' acceptance script), at a size that runs in every CI pass.
//!
//! Many paths are edited concurrently on two partitioned devices. The devices reconnect and one
//! of them is restarted while the conflicts are still being resolved (the delay is the only thing
//! that varies; the invariants do not depend on it). Afterwards, on both devices:
//! - nothing is lost: every path holds one of its two edits and one conflicted copy holds the other;
//! - there is exactly one conflicted copy per path (no duplicate or spurious copies);
//! - folders and native roots agree and nothing is dirty, held or half written;
//! - a further restart of both devices changes nothing (no copy appears after a restart).
//!
//! An in-process restart stops the link runtime, so this is not a `SIGKILL`; the process-kill
//! variant is the scale run's.

mod native_e2e_support;
mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use native_e2e_support::*;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_sqlite::native_replication;

const GROUP: &str = "conflict-burst-restart-group";
const PATHS: usize = 12;

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

fn roots(node: &TopologyNode) -> native_replication::SummaryRoots {
    read(node, |conn| native_replication::summary_roots(conn, &FolderGroupId(GROUP.to_owned())))
}

fn stuck(node: &TopologyNode) -> i64 {
    read(node, |conn| {
        let count = |sql: &str| conn.query_row(sql, [], |row| row.get::<_, i64>(0));
        Ok(count("SELECT COUNT(*) FROM local_dirty_paths")?
            + count("SELECT COUNT(*) FROM native_delta_holds")?
            + count("SELECT COUNT(*) FROM materialization_intents")?)
    })
}

fn stuck_detail(node: &TopologyNode) -> String {
    read(node, |conn| {
        let count = |sql: &str| conn.query_row(sql, [], |row| row.get::<_, i64>(0));
        Ok(format!(
            "dirty {} held {} open_writes {}",
            count("SELECT COUNT(*) FROM local_dirty_paths")?,
            count("SELECT COUNT(*) FROM native_delta_holds")?,
            count("SELECT COUNT(*) FROM materialization_intents")?
        ))
    })
}

fn path(i: usize) -> String {
    format!("dir{}/c{i:02}.txt", i % 4)
}

fn edit(side: &str, i: usize) -> Vec<u8> {
    format!("edit by {side} of path {i}").into_bytes()
}

/// The invariants that must hold once the conflicts are resolved.
fn assert_preserved(tree: &BTreeMap<String, Vec<u8>>, what: &str) {
    let files: BTreeMap<&String, &Vec<u8>> =
        tree.iter().filter(|(k, _)| !k.ends_with('/')).collect();
    let copies = conflict_copies(tree);
    assert_eq!(copies.len(), PATHS, "{what}: one conflicted copy per path: {copies:?}");
    assert_eq!(files.len(), 2 * PATHS, "{what}: only the originals and their copies: {files:?}");
    for i in 0..PATHS {
        let (a, b) = (edit("a", i), edit("b", i));
        let stem = format!("c{i:02}");
        let held: Vec<&Vec<u8>> = files
            .iter()
            .filter(|(name, _)| name.contains(&format!("/{stem}")))
            .map(|(_, bytes)| *bytes)
            .collect();
        assert_eq!(held.len(), 2, "{what}: path {i} and exactly one copy: {held:?}");
        assert!(
            held.contains(&&a) && held.contains(&&b),
            "{what}: path {i} lost an edit: {held:?}"
        );
    }
}

async fn run(delay: Duration, restart_a: bool) {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let a = device("cbr-a", GROUP);
    let b = device("cbr-b", GROUP);
    pair(&a, &b, GROUP).await;
    for i in 0..PATHS {
        write(&a, &path(i), b"base");
    }
    converge_where(&[&a, &b], "the base tree", |t| {
        t.iter().filter(|(k, v)| !k.ends_with('/') && v.as_slice() == b"base").count() == PATHS
    })
    .await;

    partition(&a, &b).await;
    for i in 0..PATHS {
        write(&a, &path(i), &edit("a", i));
        write(&b, &path(i), &edit("b", i));
    }
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;
    tokio::time::sleep(delay).await;

    let (a, b) = if restart_a {
        (restart(a, &[&b], GROUP).await, b)
    } else {
        let b = restart(b, &[&a], GROUP).await;
        (a, b)
    };

    let tree = converge_where(&[&a, &b], "every conflict is preserved once", |t| {
        conflict_copies(t).len() == PATHS
    })
    .await;
    assert_preserved(&tree, "after the restart");
    support::wait_until_with_context(
        || roots(&a) == roots(&b) && stuck(&a) + stuck(&b) == 0,
        Duration::from_secs(60),
        || format!("roots {:?} vs {:?}, stuck {} {}", roots(&a), roots(&b), stuck(&a), stuck(&b)),
    )
    .await;

    // Restarting both again must not add, remove or rewrite anything.
    let before = roots(&a);
    let a = restart(a, &[&b], GROUP).await;
    let b = restart(b, &[&a], GROUP).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = converge_where(&[&a, &b], "settled after both restart", |_| true).await;
    assert_eq!(after, tree, "a restart changed the settled tree");
    assert_preserved(&after, "after the second restart");
    assert_eq!(roots(&a), before, "a restart advanced the native state");
    assert_eq!(roots(&a), roots(&b));
    // The restart's own startup scan and repair pass finish shortly after the tree is stable.
    support::wait_until_with_context(
        || stuck(&a) + stuck(&b) == 0,
        Duration::from_secs(60),
        || format!("work still open after the restart: {} {}", stuck_detail(&a), stuck_detail(&b)),
    )
    .await;
    assert_eq!(converge_where(&[&a, &b], "still settled", |_| true).await, tree);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conflicts_survive_a_restart_before_any_delta_arrives() {
    run(Duration::ZERO, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conflicts_survive_a_restart_while_deltas_are_arriving() {
    run(Duration::from_millis(150), true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conflicts_survive_a_restart_of_the_other_device() {
    run(Duration::from_millis(60), false).await;
}
