//! Regression coverage for conflict-copy obligations that must survive
//! independently of the transient frontier a particular replica happens to
//! observe.
//!
//! The workload deliberately resembles Git usage rather than one isolated
//! write: two already-synced worktrees diverge from a common base, reconcile,
//! then one worktree performs a later merge/rebase-like edit, rename, delete,
//! or multi-file checkout. Two fresh replicas clone only after that later
//! descendant has collapsed the concurrent frontier. They therefore receive
//! the ancestry as catch-up history but must not depend on ever materializing
//! the old concurrent heads as the live frontier.
//!
//! These tests are intentionally full-stack and load-bearing: filesystem
//! watcher -> local DAG authoring -> encrypted loopback sessions -> catch-up
//! admission -> durable convergence jobs -> on-disk projection. Each scenario
//! attaches two late observers to opposite source peers concurrently so
//! delivery source, scheduling, and batch ordering cannot accidentally become
//! part of the correctness contract.

mod support;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use support::{
    open_file_backed_replica_coordinator, real_entry_names, wait_until_or_stalled,
    wait_until_with_context,
};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

type Snapshot = HashMap<String, String>;

const SETTLE_TIMEOUT: Duration = Duration::from_secs(90);
const STABILITY_WINDOW: Duration = Duration::from_millis(1_500);
// Late-observer catch-up (`assert_late_observers_match`) has more ground to
// cover than `settle_pair`'s direct convergence -- it replays the whole
// ancestry through a fresh full sync -- and shares `settle_pair`'s
// vulnerability to macOS hosted runners' slow/shared SQLite lock
// contention. A fixed 90s deadline made
// `multi_file_checkout_rewrite_preserves_every_loser_for_late_clones` flake
// under CI load even though it was still making progress. Same
// absolute-deadline-plus-stall-detector split `taguchi_collision_matrix.rs`
// uses: a generous ceiling for genuinely slow-but-healthy convergence, and a
// much tighter stall window that still fails fast on a real deadlock.
const LATE_OBSERVER_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(180);
const LATE_OBSERVER_STALL_TIMEOUT: Duration = Duration::from_secs(30);

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

fn setup_device(name: &str) -> TestDevice {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(name.to_string(), Arc::new(sync_state), store);
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id: name.to_string(),
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

async fn setup_four_devices(prefix: &str) -> (Vec<TestDevice>, String) {
    support::ensure_isolated_config_dir();
    // Captured per test and printed on failure; `RUST_LOG` widens it.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let group_id = format!("{prefix}-group");
    let devices = (0..4).map(|i| setup_device(&format!("{prefix}-device-{i}"))).collect::<Vec<_>>();
    for device in &devices {
        start_watching(device, &group_id);
    }

    // Only the two branch worktrees are connected initially. Devices 2 and 3
    // are fresh clones that must not see the transient concurrent frontier.
    let groups = vec![group_id.clone()];
    support::connect_two_daemons(
        &devices[0].state,
        &devices[0].device_id,
        &devices[1].state,
        &devices[1].device_id,
        &groups,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    (devices, group_id)
}

fn write_file(root: &Path, path: &str, content: &str) {
    let full = root.join(path);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(full, content.as_bytes()).unwrap();
}

fn snapshot(root: &Path) -> Snapshot {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read_to_string(root.join(&name)).unwrap_or_default();
            (name, content)
        })
        .collect()
}

fn snapshots_summary(devices: &[&TestDevice]) -> String {
    devices
        .iter()
        .enumerate()
        .map(|(i, device)| format!("observer-{i}={:?}", snapshot(device.root.path())))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy")
}

fn single_conflict(snapshot: &Snapshot) -> (String, String) {
    let conflicts = snapshot
        .iter()
        .filter(|(name, _)| is_conflict_copy(name))
        .map(|(name, content)| (name.clone(), content.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        conflicts.len(),
        1,
        "expected exactly one conflict copy, got {conflicts:?} from {snapshot:?}"
    );
    conflicts.into_iter().next().unwrap()
}

async fn settle_pair<F>(a: &TestDevice, b: &TestDevice, description: &str, accept: F) -> Snapshot
where
    F: Fn(&Snapshot) -> bool,
{
    let accept_ref = &accept;
    wait_until_with_context(
        || {
            let a_snapshot = snapshot(a.root.path());
            a_snapshot == snapshot(b.root.path()) && accept_ref(&a_snapshot)
        },
        SETTLE_TIMEOUT,
        || snapshots_summary(&[a, b]),
    )
    .await;

    // Do not accept a one-poll accidental equality while watcher events or DAG
    // batches are still queued. A late observer is connected only after the
    // source pair remains at the intended descendant state through this window.
    tokio::time::sleep(STABILITY_WINDOW).await;
    let reference = snapshot(a.root.path());
    assert_eq!(
        snapshot(b.root.path()),
        reference,
        "{description}: source peers diverged during the stability window"
    );
    assert!(
        accept(&reference),
        "{description}: accepted state changed during the stability window: {reference:?}"
    );
    reference
}

async fn seed_common_base(a: &TestDevice, b: &TestDevice, files: &[(&str, &str)]) {
    for (path, content) in files {
        write_file(a.root.path(), path, content);
    }
    let expected = files
        .iter()
        .map(|(path, content)| ((*path).to_string(), (*content).to_string()))
        .collect::<Snapshot>();
    settle_pair(a, b, "common base", |state| state == &expected).await;
}

async fn concurrent_worktree_writes(
    root_a: PathBuf,
    writes_a: Vec<(String, String)>,
    root_b: PathBuf,
    writes_b: Vec<(String, String)>,
) {
    let barrier = Arc::new(Barrier::new(3));
    let barrier_a = barrier.clone();
    let barrier_b = barrier.clone();
    let task_a = tokio::task::spawn_blocking(move || {
        barrier_a.wait();
        for (path, content) in writes_a {
            write_file(&root_a, &path, &content);
        }
    });
    let task_b = tokio::task::spawn_blocking(move || {
        barrier_b.wait();
        for (path, content) in writes_b {
            write_file(&root_b, &path, &content);
        }
    });
    barrier.wait();
    task_a.await.unwrap();
    task_b.await.unwrap();
}

fn pin_source_authors_on_late_observer(
    late: &TestDevice,
    source_a: &TestDevice,
    source_b: &TestDevice,
    group_id: &str,
) {
    // `connect_two_daemons` pins the directly-connected peer. A late clone,
    // however, receives ancestry containing changes authored by BOTH branch
    // devices from whichever peer it dials. Production learns all group-device
    // signing keys from the netmap, so mirror that here before catch-up; without
    // it, the test would reject the third-party-signed ancestor for a harness
    // reason and never reach the conflict-obligation behavior under test.
    let verifying_a = support::ensure_device_signing_key(&source_a.state);
    let verifying_b = support::ensure_device_signing_key(&source_b.state);
    late.state.record_peer_signing_key(&source_a.device_id, verifying_a);
    late.state.record_peer_signing_key(&source_b.device_id, verifying_b);
    late.state.set_peer_group_writer(&source_a.device_id, group_id, true);
    late.state.set_peer_group_writer(&source_b.device_id, group_id, true);
}

async fn connect_late_observers(
    source_a: &TestDevice,
    source_b: &TestDevice,
    late_a: &TestDevice,
    late_b: &TestDevice,
    group_id: &str,
) {
    pin_source_authors_on_late_observer(late_a, source_a, source_b, group_id);
    pin_source_authors_on_late_observer(late_b, source_a, source_b, group_id);

    let groups_a = vec![group_id.to_string()];
    let groups_b = groups_a.clone();
    let _ = tokio::join!(
        support::connect_two_daemons(
            &source_a.state,
            &source_a.device_id,
            &late_a.state,
            &late_a.device_id,
            &groups_a,
        ),
        support::connect_two_daemons(
            &source_b.state,
            &source_b.device_id,
            &late_b.state,
            &late_b.device_id,
            &groups_b,
        )
    );
}

/// Everything needed to tell, from one failure, whether two devices disagree
/// on the tree, the native heads, the recorded placements or a row's native
/// identity.
fn diagnostic_dump(expected: &Snapshot, devices: &[&TestDevice], group_id: &str) -> String {
    use yadorilink_replica_domain::ids::FolderGroupId;
    let group = FolderGroupId(group_id.to_string());
    let mut out = String::new();
    for device in devices {
        let tree = snapshot(device.root.path());
        out.push_str(&format!("=== {}\n", device.device_id));
        let held: Vec<String> = device
            .state
            .replica_coordinator
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT b.author || '#' || b.seq || CASE WHEN a.delta_hash IS NULL THEN ' unpublished' ELSE '' END \
                     FROM native_delta_bodies b LEFT JOIN native_delta_authorization a ON a.delta_hash = b.delta_hash \
                     WHERE b.group_id = ?1 ORDER BY b.author, b.seq",
                )?;
                let rows = stmt.query_map([group_id], |row| row.get::<_, String>(0))?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .unwrap();
        out.push_str(&format!("  deltas held: {held:?}\n"));
        let obligations: Vec<String> = device
            .state
            .replica_coordinator
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT path || ' ' || state || ' attempts=' || attempt_count || ' origin=' || origin FROM projection_obligations WHERE group_id = ?1",
                )?;
                let rows = stmt.query_map([group_id], |row| row.get::<_, String>(0))?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .unwrap();
        out.push_str(&format!("  obligations: {obligations:?}\n"));
        for (path, content) in expected {
            match tree.get(path) {
                None => out.push_str(&format!("  missing  {path} = {content:?}\n")),
                Some(actual) if actual != content => {
                    out.push_str(&format!("  differs  {path}: want {content:?} got {actual:?}\n"))
                }
                Some(_) => {}
            }
        }
        for (path, content) in &tree {
            if !expected.contains_key(path) {
                out.push_str(&format!("  extra    {path} = {content:?}\n"));
            }
        }
        let dump = device.state.replica_coordinator.database().read(
            |conn| -> Result<String, yadorilink_sync_sqlite::SyncSqliteError> {
                let mut text = String::new();
                let (heads, _) =
                    yadorilink_sync_sqlite::native_store::native_heads_at_level(conn, &group, "")?;
                for (path, path_heads) in &heads {
                    text.push_str(&format!("  heads {}:\n", path.as_str()));
                    for (dot, payload) in path_heads {
                        text.push_str(&format!(
                            "    {}/{}#{} v={} prov={}\n",
                            dot.author.device.0,
                            hex::encode(&dot.author.incarnation.0[..4]),
                            dot.seq.get(),
                            payload.version.to_hex(),
                            hex::encode(payload.provenance.0)
                        ));
                    }
                }
                let mut stmt = conn.prepare(
                    "SELECT path, deleted, hex(native_authoring_identity) FROM files \
                 WHERE group_id = ?1 AND state = 'current' ORDER BY path",
                )?;
                let rows = stmt.query_map([group_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                })?;
                for row in rows {
                    let (path, deleted, identity) = row?;
                    text.push_str(&format!(
                        "  row {path} deleted={deleted} native_id={identity:?}\n"
                    ));
                }
                Ok(text)
            },
        );
        out.push_str(&dump.unwrap_or_else(|error| format!("  dump failed: {error}\n")));
    }
    out
}

async fn assert_late_observers_match(
    expected: &Snapshot,
    source_a: &TestDevice,
    source_b: &TestDevice,
    late_a: &TestDevice,
    late_b: &TestDevice,
    group_id: &str,
) {
    let devices = [source_a, source_b, late_a, late_b];
    wait_until_or_stalled(
        || devices.iter().all(|device| snapshot(device.root.path()) == *expected),
        // Progress fingerprint: every device's own snapshot. Changes
        // whenever any device's on-disk state moves at all, not just when
        // they happen to already agree (which is what `cond` above checks,
        // and is `false` for the entire interior of a real catch-up).
        || devices.iter().map(|d| snapshot(d.root.path())).collect::<Vec<_>>(),
        LATE_OBSERVER_ABSOLUTE_TIMEOUT,
        LATE_OBSERVER_STALL_TIMEOUT,
        || {
            format!(
                "{}\n{}",
                snapshots_summary(&devices),
                diagnostic_dump(expected, &devices, group_id)
            )
        },
    )
    .await;
    tokio::time::sleep(STABILITY_WINDOW).await;
    for (i, device) in devices.iter().enumerate() {
        assert_eq!(
            snapshot(device.root.path()),
            *expected,
            "observer-{i} changed after reaching the expected catch-up state"
        );
    }
}

/// Equivalent to two branches editing one tracked file, followed by a merge
/// commit that rewrites the winning path. The merge's late clones must retain
/// the losing branch even though they first learn A, B, and the descendant C in
/// one catch-up and never need to project {A, B} as their live frontier.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn late_clone_after_merge_edit_preserves_the_pre_merge_loser() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    let (devices, group_id) = setup_four_devices("git-merge-edit").await;
    let (a, b, late_a, late_b) = (&devices[0], &devices[1], &devices[2], &devices[3]);
    seed_common_base(a, b, &[("tracked.txt", "base commit")]).await;

    concurrent_worktree_writes(
        a.root.path().to_path_buf(),
        vec![("tracked.txt".into(), "feature branch A".into())],
        b.root.path().to_path_buf(),
        vec![("tracked.txt".into(), "feature branch B".into())],
    )
    .await;

    let conflicted = settle_pair(a, b, "branch conflict", |state| {
        state.len() == 2 && state.contains_key("tracked.txt")
    })
    .await;
    let (_, conflict_content) = single_conflict(&conflicted);
    assert!(
        conflict_content == "feature branch A" || conflict_content == "feature branch B",
        "conflict copy did not preserve either branch: {conflicted:?}"
    );

    // The merge edit supersedes only the head it was written over (the
    // winner on disk); the pre-merge loser stays a live, concurrent head. Which
    // of two concurrent heads keeps the real name is decided by the content
    // version hash alone (`resolve_winner`), and that hash covers the file's
    // mtime, so it differs from run to run: the merge commit may hold
    // `tracked.txt` with the loser as the copy, or the other way round. Both are
    // correct. What must hold on every replica, in either arrangement, is that
    // exactly these two contents survive, one at the real name and one as
    // exactly one conflict copy.
    write_file(a.root.path(), "tracked.txt", "merge commit C");
    let expected = settle_pair(a, b, "post-merge descendant", |state| {
        let copies = state.iter().filter(|(name, _)| is_conflict_copy(name)).collect::<Vec<_>>();
        let mut survivors = vec![
            state.get("tracked.txt").map(String::as_str),
            copies.first().map(|(_, content)| content.as_str()),
        ];
        survivors.sort();
        let mut wanted = vec![Some(conflict_content.as_str()), Some("merge commit C")];
        wanted.sort();
        state.len() == 2 && copies.len() == 1 && survivors == wanted
    })
    .await;

    connect_late_observers(a, b, late_a, late_b, &group_id).await;
    assert_late_observers_match(&expected, a, b, late_a, late_b, &group_id).await;
}

/// Models a checkout/rebase that renames the resolved file and immediately
/// recreates the old path for a new generation. The old losing branch remains
/// an independent first-class file; a fresh clone must receive all three
/// objects rather than reconstructing only the latest source path.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn late_clone_after_rename_and_recreate_keeps_the_old_conflict_copy() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    let (devices, group_id) = setup_four_devices("git-rename-recreate").await;
    let (a, b, late_a, late_b) = (&devices[0], &devices[1], &devices[2], &devices[3]);
    seed_common_base(a, b, &[("module.rs", "base module")]).await;

    concurrent_worktree_writes(
        a.root.path().to_path_buf(),
        vec![("module.rs".into(), "branch A module".into())],
        b.root.path().to_path_buf(),
        vec![("module.rs".into(), "branch B module".into())],
    )
    .await;
    let conflicted = settle_pair(a, b, "module conflict", |state| state.len() == 2).await;
    let (_, conflict_content) = single_conflict(&conflicted);

    std::fs::rename(a.root.path().join("module.rs"), a.root.path().join("module-old.rs")).unwrap();
    write_file(a.root.path(), "module.rs", "new post-rebase generation");

    // The old loser stays a live head. Which of {loser, new generation} keeps
    // `module.rs` is decided by the version hash (it includes the mtime), and
    // the surviving copy may be renamed, so assert the pair, not the
    // assignment.
    let expected = settle_pair(a, b, "rename and recreate", |state| {
        let copies: Vec<&String> = state
            .iter()
            .filter(|(name, _)| name.starts_with("module (") && is_conflict_copy(name))
            .map(|(_, content)| content)
            .collect();
        let (Some(at_path), [at_copy]) = (state.get("module.rs"), copies.as_slice()) else {
            return false;
        };
        let new_generation = "new post-rebase generation";
        state.contains_key("module-old.rs")
            && ((at_path == &conflict_content && *at_copy == new_generation)
                || (at_path == new_generation && *at_copy == &conflict_content))
    })
    .await;

    connect_late_observers(a, b, late_a, late_b, &group_id).await;
    assert_late_observers_match(&expected, a, b, late_a, late_b, &group_id).await;
}

/// A user may deliberately delete a generated conflict copy before making a
/// later merge edit. Durable provenance must not turn into resurrection: the
/// historical loser is still known in the ancestry, but the descendant delete
/// on the derived path is authoritative for both existing and late replicas.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn deleted_conflict_copy_does_not_resurrect_on_a_late_clone() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    let (devices, group_id) = setup_four_devices("git-delete-conflict-copy").await;
    let (a, b, late_a, late_b) = (&devices[0], &devices[1], &devices[2], &devices[3]);
    seed_common_base(a, b, &[("notes.md", "base notes")]).await;

    concurrent_worktree_writes(
        a.root.path().to_path_buf(),
        vec![("notes.md".into(), "notes from branch A".into())],
        b.root.path().to_path_buf(),
        vec![("notes.md".into(), "notes from branch B".into())],
    )
    .await;
    let conflicted = settle_pair(a, b, "notes conflict", |state| state.len() == 2).await;
    let (conflict_name, conflict_content) = single_conflict(&conflicted);

    std::fs::remove_file(a.root.path().join(&conflict_name)).unwrap();
    settle_pair(a, b, "explicit conflict-copy deletion", |state| {
        !state.contains_key(&conflict_name) && !state.values().any(|v| v == &conflict_content)
    })
    .await;

    write_file(a.root.path(), "notes.md", "merge after deleting obsolete conflict copy");
    let expected = settle_pair(a, b, "post-deletion merge", |state| {
        state.get("notes.md").map(String::as_str)
            == Some("merge after deleting obsolete conflict copy")
            && !state.contains_key(&conflict_name)
            && !state.values().any(|v| v == &conflict_content)
    })
    .await;

    connect_late_observers(a, b, late_a, late_b, &group_id).await;
    assert_late_observers_match(&expected, a, b, late_a, late_b, &group_id).await;
    assert!(
        !expected.keys().any(|name| is_conflict_copy(name)),
        "the explicitly deleted conflict copy was resurrected: {expected:?}"
    );
}

/// A high-contention worktree transition: three files diverge concurrently,
/// then one side performs a rename, lockfile rewrite, delete/recreate, and new
/// file creation before two late clones catch up from opposite peers. This
/// catches implementations that derive only one obligation per Change, lose
/// obligations when operations are split across watcher batches, or depend on
/// peer/batch order for multi-path projection.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn multi_file_checkout_rewrite_preserves_every_loser_for_late_clones() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    let (devices, group_id) = setup_four_devices("git-multi-file-checkout").await;
    let (a, b, late_a, late_b) = (&devices[0], &devices[1], &devices[2], &devices[3]);
    seed_common_base(
        a,
        b,
        &[("src-lib.rs", "base source"), ("Cargo.lock", "base lock"), ("README.md", "base readme")],
    )
    .await;

    concurrent_worktree_writes(
        a.root.path().to_path_buf(),
        vec![
            ("src-lib.rs".into(), "source from branch A".into()),
            ("Cargo.lock".into(), "lock from branch A".into()),
            ("README.md".into(), "readme from branch A".into()),
        ],
        b.root.path().to_path_buf(),
        vec![
            ("src-lib.rs".into(), "source from branch B".into()),
            ("Cargo.lock".into(), "lock from branch B".into()),
            ("README.md".into(), "readme from branch B".into()),
        ],
    )
    .await;

    let conflicted = settle_pair(a, b, "three-path branch conflict", |state| {
        state.len() == 6
            && state.contains_key("src-lib.rs")
            && state.contains_key("Cargo.lock")
            && state.contains_key("README.md")
            && state.keys().filter(|name| is_conflict_copy(name)).count() == 3
    })
    .await;
    let preserved = conflicted
        .iter()
        .filter(|(name, _)| is_conflict_copy(name))
        .map(|(name, content)| (name.clone(), content.clone()))
        .collect::<Snapshot>();
    assert_eq!(preserved.len(), 3, "expected one loser per conflicted tracked file");

    // One tight worktree rewrite, deliberately issued without waiting between
    // operations, like a branch checkout/reset updating several tracked paths.
    std::fs::rename(a.root.path().join("src-lib.rs"), a.root.path().join("src-core.rs")).unwrap();
    write_file(a.root.path(), "Cargo.lock", "lock after rebase");
    std::fs::remove_file(a.root.path().join("README.md")).unwrap();
    write_file(a.root.path(), "README.md", "readme after squash");
    write_file(a.root.path(), "CHANGELOG.md", "release candidate");

    // The rename moves the version A showed at `src-lib.rs` and supersedes
    // only that head. The other head there, shown as its conflict copy, was
    // never in the rename's basis, so it stays a head of `src-lib.rs`. Alone,
    // it keeps its copy name under native authority (the rename's author saw
    // the copy and declares it kept, so a late clone that never saw the
    // contest agrees), and takes the name under DCF's older resolution. The
    // two other copies stay copies: the rewrite and the delete/recreate
    // superseded only the shown heads.
    let lib_shown = conflicted["src-lib.rs"].clone();
    let (lib_copy, lib_other) = preserved
        .iter()
        .find(|(name, _)| name.starts_with("src-lib ("))
        .map(|(name, content)| (name.clone(), content.clone()))
        .expect("a copy of the other src-lib.rs version");
    // The rewritten paths keep their losing version as a live head. Which of
    // {loser, rewrite} keeps the original name is decided by the version hash
    // (it includes the mtime), and the surviving conflict copy may be renamed.
    // So assert the pair, not the assignment: exactly one copy of the path
    // exists, and the path and that copy hold the loser and the rewrite, in
    // either order.
    let loser_of = |prefix: &str| {
        preserved
            .iter()
            .find(|(name, _)| name.starts_with(prefix))
            .map(|(_, content)| content.clone())
            .expect("a conflict copy for the rewritten path")
    };
    let lock_loser = loser_of("Cargo (");
    let readme_loser = loser_of("README (");
    let pair_is = |state: &Snapshot, path: &str, prefix: &str, loser: &str, rewrite: &str| {
        let copies: Vec<&String> = state
            .iter()
            .filter(|(name, _)| name.starts_with(prefix) && is_conflict_copy(name))
            .map(|(_, content)| content)
            .collect();
        let (Some(at_path), [at_copy]) = (state.get(path), copies.as_slice()) else {
            return false;
        };
        (at_path == loser && *at_copy == rewrite) || (at_path == rewrite && *at_copy == loser)
    };
    let expected = settle_pair(a, b, "multi-file checkout rewrite", |state| {
        state.get("src-core.rs") == Some(&lib_shown)
            && !state.contains_key("src-lib.rs")
            && state.get(&lib_copy) == Some(&lib_other)
            && pair_is(state, "Cargo.lock", "Cargo (", &lock_loser, "lock after rebase")
            && pair_is(state, "README.md", "README (", &readme_loser, "readme after squash")
            && state.get("CHANGELOG.md").map(String::as_str) == Some("release candidate")
    })
    .await;

    connect_late_observers(a, b, late_a, late_b, &group_id).await;
    assert_late_observers_match(&expected, a, b, late_a, late_b, &group_id).await;
}
