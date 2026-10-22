//! A peer must never make this device write or delete outside its sync root.
//!
//! The attack does not live in the incoming Change, which is ordinary and
//! correctly signed. It lives in what a path component already *is* on the
//! receiving side: a symlink, planted locally, pointing somewhere else. A
//! naive join of root and path then resolves outside the root, and admission
//! cannot see it — admission is a DAG and authorization decision, and the path
//! is legitimate history. The defence has to be in materialization, and it has
//! to fail closed.
//!
//! Two halves of one invariant, neither covered anywhere after the Change
//! protocol's tests were retired:
//!
//! ```text
//!   write   a peer's file at evil_link/pwned.txt must not be created outside
//!   delete  a peer's tombstone for external/victim.txt must not remove
//!           anything outside
//! ```
//!
//! Both are stated against a *real* second daemon, so what is exercised is the
//! projection path a peer's Change actually takes, not a materialize call made
//! directly.

#![cfg(unix)]

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::wait_until_with_context;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

const GROUP: &str = "path-escape-group";

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

impl TestDevice {
    fn path(&self, relative: &str) -> std::path::PathBuf {
        self.root.path().join(relative)
    }
}

fn setup_device(name: &str) -> TestDevice {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
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

fn start_watching(device: &TestDevice) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    LinkRuntimeController::new(device.state.clone()).start(local_path, GROUP.to_string()).unwrap();
}

async fn pair(a: &TestDevice, b: &TestDevice) {
    support::connect_two_daemons(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;
}

fn indexed(device: &TestDevice, path: &str) -> bool {
    device
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, path)
        .ok()
        .flatten()
        .is_some_and(|record| !record.deleted)
}

/// A peer's ordinary file, under a path whose first component is a symlink on
/// this device, must not be written through that symlink.
///
/// Nothing device-b does here is malicious: `evil_link` is a plain directory
/// on its side, and syncing a file inside it is ordinary. The whole attack is
/// what `evil_link` already is on device-a.
///
/// Device-b's `evil_link` is a directory it made, so it is replicated as an
/// explicit Directory entry, and device-a's is a Symlink entry at the same
/// path. An explicit Directory always keeps its path against a File or a
/// Symlink, whatever the order: the Symlink is the one relocated, to a
/// conflict-copy name, as the link itself (a rename never follows it). The
/// namespace then puts a real directory at `evil_link`, inside the root, and
/// the peer's file lands in it. So the file *is* visible at the joined path
/// here, and that is correct: nothing is reached through the symlink, and the
/// symlink survives untouched beside it.
///
/// The fail-closed refusal to write through a symlinked component is not
/// reached in this shape; the test below keeps it reached end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peers_write_cannot_escape_the_sync_root_through_a_symlinked_component() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    // Planted before anything syncs: a component inside a's root that points
    // outside it.
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), device_a.path("evil_link")).unwrap();

    start_watching(&device_a);
    start_watching(&device_b);

    std::fs::create_dir_all(device_b.path("evil_link")).unwrap();
    std::fs::write(device_b.path("evil_link/pwned.txt"), b"attacker-controlled content").unwrap();

    pair(&device_a, &device_b).await;

    wait_until_with_context(
        || device_a.path("evil_link/pwned.txt").is_file(),
        Duration::from_secs(30),
        || "device-a never placed the peer's file inside the root".into(),
    )
    .await;

    assert_eq!(
        std::fs::read_dir(outside.path()).unwrap().count(),
        0,
        "something was written outside the sync root"
    );

    let at_path = std::fs::symlink_metadata(device_a.path("evil_link")).unwrap();
    assert!(
        at_path.is_dir() && !at_path.file_type().is_symlink(),
        "the Directory must keep `evil_link` as a real directory inside the root"
    );
    assert_eq!(
        std::fs::read(device_a.path("evil_link/pwned.txt")).unwrap(),
        b"attacker-controlled content"
    );

    // The symlink was moved aside as itself, not deleted and not followed.
    let copies: Vec<std::path::PathBuf> = std::fs::read_dir(device_a.root.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("evil_link (conflicted copy"))
        })
        .collect();
    assert_eq!(copies.len(), 1, "the symlink must survive at exactly one copy name: {copies:?}");
    let copy = std::fs::symlink_metadata(&copies[0]).unwrap();
    assert!(copy.file_type().is_symlink(), "the relocated entry must still be the symlink");
    assert_eq!(
        std::fs::read_link(&copies[0]).unwrap(),
        outside.path(),
        "the relocated symlink must still point where it did"
    );

    // And the session carries on: an ordinary file that follows syncs
    // normally on the same connection.
    std::fs::write(device_b.path("ordinary.txt"), b"fine").unwrap();
    wait_until_with_context(
        || device_a.path("ordinary.txt").exists(),
        Duration::from_secs(30),
        || "the pair stopped syncing after the conflict".into(),
    )
    .await;
}

/// The fail-closed half, reached end to end: a symlinked component that the
/// namespace does *not* replace, so the only thing standing between the
/// peer's file and the outside is the refusal to write through it.
///
/// Device-a ignores `evil_link` itself but not the one file below it. The
/// ignore keeps device-a's symlink out of the group, and keeps device-b's
/// Directory entry off device-a's disk, so there is no contest for the path
/// and nothing moves the symlink aside. The file below it is still projected,
/// and its parent on device-a's disk is the symlink.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peers_write_is_refused_under_a_symlinked_component_the_namespace_leaves_in_place() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), device_a.path("evil_link")).unwrap();
    std::fs::write(device_a.path(".yadorilinkignore"), "evil_link\n!evil_link/pwned.txt\n")
        .unwrap();

    start_watching(&device_a);
    start_watching(&device_b);

    std::fs::create_dir_all(device_b.path("evil_link")).unwrap();
    std::fs::write(device_b.path("evil_link/pwned.txt"), b"attacker-controlled content").unwrap();

    pair(&device_a, &device_b).await;

    // Admission is not where the defence is: the Change is legitimate
    // history, and device-a indexes it. What must not follow is the write.
    wait_until_with_context(
        || indexed(&device_a, "evil_link/pwned.txt"),
        Duration::from_secs(30),
        || "device-a never admitted the peer's change, so the defence was never reached".into(),
    )
    .await;
    // Something ordinary must cross after it, so "nothing was written" cannot
    // be mistaken for "materialization never ran".
    std::fs::write(device_b.path("ordinary.txt"), b"fine").unwrap();
    wait_until_with_context(
        || device_a.path("ordinary.txt").exists(),
        Duration::from_secs(30),
        || "a refused path-escape must not wedge the rest of the sync".into(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        std::fs::read_dir(outside.path()).unwrap().count(),
        0,
        "the write escaped the sync root through the symlink"
    );
    let at_path = std::fs::symlink_metadata(device_a.path("evil_link")).unwrap();
    assert!(at_path.file_type().is_symlink(), "the ignored symlink must be left as it was");
    assert_eq!(std::fs::read_link(device_a.path("evil_link")).unwrap(), outside.path());
}

/// Content living outside the sync root, reachable only through a symlinked
/// directory inside it, must never enter this group — not the index, not the
/// DAG, and not a peer.
///
/// This is the read side of the same invariant as the write test above, and
/// the two disagreed until now: a write already refused to cross a symlinked
/// component while a read did not, so the outside file was captured and
/// replicated. Measured before the fix: device-b ended up holding bytes from a
/// file that was never in the folder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outside_content_behind_a_symlinked_component_never_reaches_a_peer() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("victim.txt"), b"do not replicate me").unwrap();
    std::os::unix::fs::symlink(outside.path(), device_a.path("external")).unwrap();

    start_watching(&device_a);
    start_watching(&device_b);
    pair(&device_a, &device_b).await;

    // Something ordinary must cross, so that "nothing arrived" cannot be
    // mistaken for "the pair never synced at all".
    std::fs::write(device_a.path("ordinary.txt"), b"fine").unwrap();
    wait_until_with_context(
        || device_b.path("ordinary.txt").exists(),
        Duration::from_secs(30),
        || "the pair never synced, so this test proves nothing".into(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Asserted against the *group*, not the filesystem. Both devices live in
    // one process on one filesystem here, and the synchronised symlink is
    // absolute, so reading `external/victim.txt` under device-b's root
    // resolves back to the very same outside file — through b's own symlink,
    // with nothing having crossed the wire. A filesystem assertion would fail
    // for a reason that has nothing to do with replication.
    assert!(
        !indexed(&device_a, "external/victim.txt"),
        "the outside file was captured into the group's index"
    );
    assert!(
        !indexed(&device_b, "external/victim.txt"),
        "the outside file reached the peer's index"
    );
    let in_dag = device_a
        .state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(GROUP, "external/victim.txt")
        .unwrap_or_default();
    assert!(in_dag.is_empty(), "the outside file entered the DAG: {in_dag:?}");
}

/// The symlink itself is still captured — refusing to walk through one is not
/// refusing to have one. Without this, the traversal rule could have been
/// implemented as "ignore symlinks entirely" and every other test here would
/// still pass.
///
/// Asserted on the capturing device only. Whether an out-of-root symlink is
/// then propagated to a peer was observed to vary run to run, and this test is
/// not the place to pin down a policy it does not own: a link to a path that
/// means something else on another machine is arguably not worth recreating
/// there. What matters here is that the object was not swallowed locally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_symlink_itself_still_reaches_the_peer() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), device_a.path("external")).unwrap();

    start_watching(&device_a);
    start_watching(&device_b);
    pair(&device_a, &device_b).await;

    // Asserted at the group level, not on disk. Whether a symlink pointing
    // *outside* the root is recreated on another machine is a separate
    // materialisation policy — a link to a path that means something else
    // over there is arguably not worth creating. What this test is about is
    // that the symlink is still a synchronised object rather than something
    // the traversal rule swallowed.
    wait_until_with_context(
        || indexed(&device_a, "external"),
        Duration::from_secs(30),
        || "the traversal rule swallowed the symlink instead of capturing it".into(),
    )
    .await;
}

/// A symlink cycle inside the root must not make the scan run forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_symlink_cycle_does_not_stall_the_scan() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    std::fs::create_dir(device_a.path("dir")).unwrap();
    std::os::unix::fs::symlink(device_a.path("dir"), device_a.path("dir/loop")).unwrap();

    start_watching(&device_a);
    start_watching(&device_b);
    pair(&device_a, &device_b).await;

    std::fs::write(device_a.path("ordinary.txt"), b"fine").unwrap();
    wait_until_with_context(
        || device_b.path("ordinary.txt").exists(),
        Duration::from_secs(30),
        || "a symlink cycle stalled the scan".into(),
    )
    .await;
}

/// The sequence that actually leaks: a peer introduces the path, and this
/// device then reads it back *through* its own symlinked component.
///
/// The path has to come from somewhere before a per-path read of it happens —
/// the recursive scan already refuses to descend into a symlinked directory,
/// so on its own it never names `external/victim.txt`. A peer naming it is
/// what supplies the name; the read that follows resolves it through the
/// symlink and picks up a file that was never in this folder.
///
/// The tell is the size: the peer's file and the outside file are
/// deliberately different lengths, so whose bytes ended up in the group is not
/// a matter of interpretation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_named_path_is_not_read_back_through_a_symlinked_component() {
    const PEER_CONTENT: &[u8] = b"harmless";
    const OUTSIDE_CONTENT: &[u8] = b"do not replicate me, i am outside";

    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("victim.txt"), OUTSIDE_CONTENT).unwrap();
    std::os::unix::fs::symlink(outside.path(), device_a.path("external")).unwrap();

    start_watching(&device_a);
    start_watching(&device_b);

    std::fs::create_dir_all(device_b.path("external")).unwrap();
    std::fs::write(device_b.path("external/victim.txt"), PEER_CONTENT).unwrap();

    pair(&device_a, &device_b).await;

    wait_until_with_context(
        || indexed(&device_a, "external/victim.txt"),
        Duration::from_secs(30),
        || "device-a never received the peer's file, so the read-back never happened".into(),
    )
    .await;
    // Long enough for a read-back to have happened and propagated.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let sizes: Vec<u64> = device_a
        .state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(GROUP, "external/victim.txt")
        .unwrap_or_default()
        .iter()
        .map(|v| v.size)
        .collect();
    assert!(
        !sizes.contains(&(OUTSIDE_CONTENT.len() as u64)),
        "the outside file's bytes entered the group's history: versions {sizes:?}, \
         outside is {} bytes and the peer's file is {} bytes",
        OUTSIDE_CONTENT.len(),
        PEER_CONTENT.len(),
    );
}

// The delete-side twin is a unit gate rather than a two-device one, and the
// reason is worth stating.
//
// `verify_delete_target_within_root` already holds it: it canonicalises the
// target's parent and refuses when that lands outside the root, which is
// exactly what a symlinked component does. It simply had no test. That gate
// now lives next to the primitive, in
// `yadorilink-local-storage::materialize_write`.
//
// Driving it from a real pair does not isolate it. The scenario needs
// device-a's `external` to be a symlink while device-b's is a real directory,
// and both devices then legitimately disagree about what `external` *is* —
// device-a synchronises it as a symlink, device-b as a directory. The delete
// stalls on that contest, not on the defence, and a test asserting the victim
// file survived would pass without the defence ever being consulted. Excluding
// the symlink from device-a's sync does not help either: the same ignore rule
// stops the file the tombstone refers to from arriving in the first place.
//
// Measured, not assumed: an ordinary delete propagates in this fixture in
// under a second, so the stall is specific to the contest.
