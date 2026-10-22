#![cfg(test)]

//! A received file's proof and its obligation's completion, driven by the
//! real obligation engine on a running link.
//!
//! The content write commits its proof, its `Present` stamp, its intent
//! clear and its obligation's completion in one transaction, after the bytes
//! are durable. These tests park the worker at exactly that seam -- the temp
//! file synced, renamed and its directory synced; nothing committed yet --
//! and land a competing mutation, or a crash, there:
//!
//! - a fence moved there (a capture, a local edit) publishes nothing and
//!   leaves the obligation open under the claim it had;
//! - a claim overtaken there (a newer admission or a re-arm of the same
//!   path's obligation) keeps the proof, which is still exactly true, and
//!   leaves the obligation open for a later claim to close without work;
//! - a crash there leaves the intent and the obligation open over bytes
//!   that are already right, which repair and the next pass finish
//!   without rewriting anything;
//! - a crash after the commit leaves nothing for either to do.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_sync_sqlite::projection_obligations::ProjectionObligation;

use super::receive_cost_tests::{content_of, fixture, Fixture, GROUP};
use crate::convergence::engine::{
    drive_obligations_once_for_test, drive_obligations_once_for_test_with_hooks,
    BeforeCompletionHook, ConvergenceEngine,
};
use crate::replica_coordinator::ReplicaCoordinator;

const ONE_BLOCK: usize = 4096;

fn multi_block() -> usize {
    2 * yadorilink_local_storage::chunker::DEFAULT_BLOCK_SIZE + 1000
}

async fn ready_fixture() -> (Fixture, Arc<ConvergenceEngine>) {
    let f = fixture(false).await;
    let engine = Arc::new(ConvergenceEngine::new(f.state.clone()));
    // Settles the group's one-time work first, so the parked attempt below
    // claims only the path under test.
    let warm = b"warm-up";
    let version = f.content_version(warm, 100);
    f.admit("warm.txt", &version);
    drive_until(&f, &engine, "the warm-up path closes", |f| obligation(f, "warm.txt").is_none())
        .await;
    f.state.replica_coordinator.test_observers.close_batch_sizes.lock().unwrap().clear();
    (f, engine)
}

/// The generation and incarnation a claim on `o` would carry.
fn claim_of(o: &ProjectionObligation) -> (i64, i64) {
    (o.invalidation_generation, o.obligation_incarnation)
}

fn obligation(f: &Fixture, name: &str) -> Option<ProjectionObligation> {
    f.state.replica_coordinator.sqlite().dag_lookup_projection_obligation(GROUP, name).unwrap()
}

/// The version the proof standing for `name` names, while it is usable
/// (published under the path's live fence).
fn proven_version(f: &Fixture, name: &str) -> Option<VersionHash> {
    f.state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation(
                conn, GROUP, name,
            )
        })
        .unwrap()
        .and_then(|basis| basis.version)
}

/// Whether any proof row exists for `name` at all, usable or not.
fn any_proof_row(f: &Fixture, name: &str) -> bool {
    f.state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM path_materialized_generations \
                 WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![GROUP, name],
                |r| r.get::<_, i64>(0),
            )? > 0)
        })
        .unwrap()
}

fn proof_names_current_row(f: &Fixture, name: &str) -> bool {
    f.state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::exact_materialized_commit::usable_proof_names_current_version(
                conn, GROUP, name,
            )
        })
        .unwrap()
}

/// Whether the basis the proof for `name` records is the path's frontier
/// now.
fn proof_basis_current(f: &Fixture, name: &str) -> bool {
    f.state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let basis =
                yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation(
                    conn, GROUP, name,
                )?
                .expect("a usable proof")
                .basis;
            yadorilink_sync_sqlite::materialization_basis::is_current(conn, GROUP, name, &basis)
        })
        .unwrap()
}

fn hydrated(f: &Fixture, name: &str) -> bool {
    f.state.replica_coordinator.get_materialization_state(GROUP, name).unwrap()
        == Some(MaterializationState::Present)
}

fn intent_open(f: &Fixture, name: &str) -> bool {
    f.state.replica_coordinator.has_materialization_intent(GROUP, name).unwrap()
}

#[cfg(unix)]
fn inode(f: &Fixture, name: &str) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(f.root.join(name)).unwrap().ino()
}

/// Drives the engine until `done` holds.
async fn drive_until(
    f: &Fixture,
    engine: &ConvergenceEngine,
    what: &str,
    done: impl Fn(&Fixture) -> bool,
) {
    for _ in 0..300 {
        tokio::time::timeout(
            Duration::from_secs(20),
            drive_obligations_once_for_test(engine, 128, 256),
        )
        .await
        .expect("one engine pass must not stall");
        if done(f) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{what}: never happened");
}

/// Admits `name` at `content` and drives one engine pass until it parks at
/// the completion seam. Returns the version, the claim the pass holds, the
/// hook and the parked pass.
async fn admit_and_park(
    f: &Fixture,
    engine: &Arc<ConvergenceEngine>,
    name: &str,
    content: &[u8],
) -> (FileVersion, ProjectionObligation, Arc<BeforeCompletionHook>, tokio::task::JoinHandle<bool>) {
    let version = f.content_version(content, 1000);
    f.admit(name, &version);
    let claimed = obligation(f, name).expect("the admission arms an obligation");
    let hook = BeforeCompletionHook::new();
    let (engine2, hook2) = (engine.clone(), hook.clone());
    let pass = tokio::spawn(async move {
        drive_obligations_once_for_test_with_hooks(&engine2, 128, 256, &hook2).await
    });
    tokio::time::timeout(Duration::from_secs(30), hook.wait_parked())
        .await
        .expect("the pass must park before it decides the obligation");
    (version, claimed, hook, pass)
}

/// The state the seam itself guarantees: the bytes are durably on disk
/// under their name (the temp file synced, renamed and its directory synced
/// before the seam is reached), and nothing about them is committed yet --
/// no proof, no `Present`, the intent still open, the obligation still
/// open under the claim the pass holds. This is also exactly what a crash
/// at the seam leaves.
fn assert_durable_on_disk_and_nothing_committed(
    f: &Fixture,
    name: &str,
    content: &[u8],
    claimed: &ProjectionObligation,
) {
    assert_eq!(f.read(name).as_deref(), Some(content), "the bytes are renamed into place");
    assert!(!any_proof_row(f, name), "no proof is published before the commit");
    assert!(!hydrated(f, name), "the row does not claim the bytes before the commit");
    assert!(intent_open(f, name), "the intent is open until the commit");
    assert_eq!(
        obligation(f, name).as_ref(),
        Some(claimed),
        "the obligation is open, under the claim, until the commit"
    );
}

/// RED for the folded commit: a fence moved between the rename and the
/// commit (a capture, a local write, any other mutator) publishes nothing
/// and closes nothing, and the next pass rewrites and closes it.
async fn a_fence_moved_at_the_seam_publishes_and_closes_nothing(len: usize) {
    let (f, engine) = ready_fixture().await;
    let name = "raced.bin";
    let content = content_of(len, 3);
    let (_, claimed, hook, pass) = admit_and_park(&f, &engine, name, &content).await;
    assert_durable_on_disk_and_nothing_committed(&f, name, &content, &claimed);

    f.state.replica_coordinator.dag_bump_mutation_fence(GROUP, name, "local_capture").unwrap();
    hook.resume();
    pass.await.unwrap();

    assert!(!any_proof_row(&f, name), "a lost fence publishes no proof at all");
    assert!(!hydrated(&f, name), "a lost fence stamps nothing");
    assert!(intent_open(&f, name), "a lost fence leaves the intent open");
    assert_eq!(
        obligation(&f, name).map(|o| claim_of(&o)),
        Some(claim_of(&claimed)),
        "a lost fence closes nothing: the obligation stays open under the same claim"
    );

    // Re-driven to an exact, closed state from where the lost commit left
    // it. Which version the path settles on is not this test's business --
    // a fence moved by a real capture may well make the bytes a local
    // version -- only that the claim the path ends with is proven.
    drive_until(&f, &engine, "the path is re-driven and closed", |f| obligation(f, name).is_none())
        .await;
    assert_eq!(f.read(name).as_deref(), Some(&content[..]));
    assert!(proof_names_current_row(&f, name), "the path ends proven for its row");
    assert!(hydrated(&f, name));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_empty_file_whose_fence_moves_at_the_seam_publishes_and_closes_nothing() {
    a_fence_moved_at_the_seam_publishes_and_closes_nothing(0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_one_block_file_whose_fence_moves_at_the_seam_publishes_and_closes_nothing() {
    a_fence_moved_at_the_seam_publishes_and_closes_nothing(ONE_BLOCK).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multi_block_file_whose_fence_moves_at_the_seam_publishes_and_closes_nothing() {
    a_fence_moved_at_the_seam_publishes_and_closes_nothing(multi_block()).await;
}

/// A local save at the seam: the edit is on disk and the fence moved, so
/// the peer's bytes are proven nowhere and the obligation is not closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_edit_at_the_seam_publishes_nothing_for_the_peers_bytes() {
    let (f, engine) = ready_fixture().await;
    let name = "edited.bin";
    let content = content_of(ONE_BLOCK, 5);
    let (version, _, hook, pass) = admit_and_park(&f, &engine, name, &content).await;

    std::fs::write(f.root.join(name), b"saved locally meanwhile").unwrap();
    f.state.replica_coordinator.dag_bump_mutation_fence(GROUP, name, "local_capture").unwrap();
    hook.resume();
    pass.await.unwrap();

    assert_ne!(
        proven_version(&f, name),
        Some(version.version_hash),
        "the peer's version is not proven over a local edit"
    );
    assert!(obligation(&f, name).is_some(), "the claim does not close the obligation");
    assert_eq!(f.read(name).as_deref(), Some(&b"saved locally meanwhile"[..]));
}

/// A claim overtaken at the seam -- the path's obligation re-armed, its
/// row and fence untouched. The proof is exactly true and is kept; the
/// obligation stays open at its newer generation, and the next pass closes
/// it with no physical work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_overtaken_at_the_seam_keeps_the_proof_and_leaves_the_obligation_open() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (f, engine) = ready_fixture().await;
    let name = "rearmed.bin";
    let content = content_of(ONE_BLOCK, 7);
    let (version, claimed, hook, pass) = admit_and_park(&f, &engine, name, &content).await;

    f.state
        .replica_coordinator
        .sqlite()
        .dag_bump_projection_obligations_for_touched_paths(GROUP, &[name], 1)
        .unwrap();
    hook.resume();
    pass.await.unwrap();

    assert_eq!(proven_version(&f, name), Some(version.version_hash), "the proof is kept");
    assert!(hydrated(&f, name), "the stamp is kept");
    assert!(!intent_open(&f, name), "the intent is cleared with the proof");
    let open = obligation(&f, name).expect("a stale claim closes nothing");
    assert_eq!(open.obligation_incarnation, claimed.obligation_incarnation);
    assert!(
        open.invalidation_generation > claimed.invalidation_generation,
        "the obligation is open at the generation that overtook the claim"
    );

    #[cfg(unix)]
    let before = inode(&f, name);
    drive_until(&f, &engine, "the overtaken obligation is closed", |f| {
        obligation(f, name).is_none()
    })
    .await;
    #[cfg(unix)]
    assert_eq!(inode(&f, name), before, "closed without rewriting the file");
    assert_eq!(f.read(name).as_deref(), Some(&content[..]));
    assert_eq!(proven_version(&f, name), Some(version.version_hash));
}

/// A newer admission of the SAME path at the seam. Admission moves the
/// path's obligation to a new generation but not its row, which still names
/// the version just written: the proof of those bytes is exactly true and
/// commits, and the claim -- overtaken by the admission -- closes nothing.
/// The obligation stays open for the newer version.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_path_admission_while_parked_is_independently_rejected_by_generation_cas() {
    let (f, engine) = ready_fixture().await;
    let name = "x2.txt";
    let first = content_of(ONE_BLOCK, 9);
    let (written, claimed, hook, pass) = admit_and_park(&f, &engine, name, &first).await;

    let second = content_of(ONE_BLOCK, 11);
    let newer = f.content_version(&second, 2000);
    let observing = crate::test_support::remote_admission_fixture::current_heads(
        &f.state.replica_coordinator,
        GROUP,
        name,
    );
    crate::test_support::remote_admission_fixture::admit_remote(
        &f.state.replica_coordinator,
        GROUP,
        "device-peer",
        vec![crate::test_support::remote_admission_fixture::put(
            name,
            newer.version_hash,
            observing,
        )],
        std::slice::from_ref(&newer),
    );
    hook.resume();
    pass.await.unwrap();

    let open = obligation(&f, name).expect("the stale attempt must not close the obligation");
    assert_ne!(
        open.invalidation_generation, claimed.invalidation_generation,
        "the refusal came from the claim, overtaken by the admission of the same path"
    );
    assert_eq!(
        proven_version(&f, name),
        Some(written.version_hash),
        "the proof names the bytes on disk, not the version the path now wants"
    );
    assert!(
        !proof_basis_current(&f, name),
        "the kept proof does not claim the newer, unwritten head as reflected"
    );
}

/// An admission touching only ANOTHER path at the seam moves the group's
/// heads but nothing about this path, so this path still closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unrelated_path_head_movement_must_not_discard_an_already_settled_attempt() {
    let (f, engine) = ready_fixture().await;
    let name = "x.txt";
    let content = content_of(ONE_BLOCK, 13);
    let (version, _, hook, pass) = admit_and_park(&f, &engine, name, &content).await;

    let unrelated = f.content_version(&content_of(ONE_BLOCK, 15), 3000);
    f.admit("y-unrelated.txt", &unrelated);
    hook.resume();
    pass.await.unwrap();

    assert!(
        obligation(&f, name).is_none(),
        "an unrelated path's admission must not keep this path's settled attempt from closing"
    );
    assert_eq!(proven_version(&f, name), Some(version.version_hash));
}

/// A crash at the seam: the bytes are durable and nothing is committed.
/// Startup repair finds bytes that already match the row and only finishes
/// the bookkeeping (proof, stamp, intent) -- it never closes an obligation
/// -- and the next pass closes the obligation with no physical work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_between_the_disk_publish_and_the_commit_is_finished_by_repair_and_the_next_pass() {
    let (f, engine) = ready_fixture().await;
    let name = "crashed.bin";
    let content = content_of(multi_block(), 17);
    let (version, claimed, _hook, pass) = admit_and_park(&f, &engine, name, &content).await;
    assert_durable_on_disk_and_nothing_committed(&f, name, &content, &claimed);

    // The crash: the worker never runs past the seam.
    pass.abort();
    let _ = pass.await;
    assert_durable_on_disk_and_nothing_committed(&f, name, &content, &claimed);

    let report = repair(&f);
    assert!(report.reconstructed.is_empty(), "the bytes already match: nothing to rebuild");
    assert!(report.offline_deleted.is_empty(), "an interrupted write is not an offline delete");
    assert!(report.quarantined_dirty.is_empty());
    assert!(!intent_open(&f, name), "repair finishes the interrupted write's intent");
    assert_eq!(proven_version(&f, name), Some(version.version_hash));
    assert!(hydrated(&f, name));
    assert_eq!(
        obligation(&f, name).as_ref(),
        Some(&claimed),
        "repair never closes an obligation: only a claim does"
    );

    #[cfg(unix)]
    let before = inode(&f, name);
    drive_until(&f, &engine, "the next pass closes it", |f| obligation(f, name).is_none()).await;
    #[cfg(unix)]
    assert_eq!(inode(&f, name), before, "closed without rewriting the file");
    assert_eq!(f.read(name).as_deref(), Some(&content[..]));
}

/// A crash after the commit: everything landed together, so repair finds
/// nothing and a later pass has nothing to claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_after_the_commit_leaves_nothing_to_repair_or_reproject() {
    let (f, engine) = ready_fixture().await;
    let name = "landed.bin";
    let content = content_of(ONE_BLOCK, 19);
    let version = f.content_version(&content, 1000);
    f.admit(name, &version);
    drive_until(&f, &engine, "the path closes", |f| obligation(f, name).is_none()).await;
    assert_eq!(proven_version(&f, name), Some(version.version_hash));
    assert!(hydrated(&f, name));
    assert!(!intent_open(&f, name));

    let report = repair(&f);
    assert!(report.reconstructed.is_empty());
    assert!(report.offline_deleted.is_empty());
    assert!(report.quarantined_dirty.is_empty());
    tokio::time::timeout(
        Duration::from_secs(20),
        drive_obligations_once_for_test(&engine, 128, 256),
    )
    .await
    .unwrap();
    assert!(obligation(&f, name).is_none());
    assert_eq!(proven_version(&f, name), Some(version.version_hash));
    assert_eq!(f.read(name).as_deref(), Some(&content[..]));
}

fn repair(
    f: &Fixture,
) -> yadorilink_filesystem_sync::materialization_repair::MaterializationRepairReport {
    let store = crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        f.state.block_store.clone(),
    );
    yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
        f.state.replica_coordinator.as_ref(),
        &store,
        &f.root,
        GROUP,
        yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap()
}

/// A file named like a conflict copy of another is an ordinary own-name entry
/// of the pass. When its write fails, the entry it looks like a copy of must
/// not close its obligation in the same pass: the claim is chosen after the
/// copy's outcome is known, however many writes the pass runs at once.
async fn a_name_that_looks_like_a_copy_keeps_its_original_owed(limit: usize) {
    let (f, engine) = ready_fixture().await;
    let source = "report.txt";
    let copy = "report (conflicted copy, device-b).txt";
    let (a, b) = (content_of(ONE_BLOCK, 31), content_of(ONE_BLOCK, 33));
    f.admit(source, &f.content_version(&a, 5000));
    f.admit(copy, &f.content_version(&b, 5100));
    let executor = f.state.peers.local_convergence("device-peer").unwrap();
    executor.receive_write_concurrency_override.store(limit, std::sync::atomic::Ordering::Relaxed);
    let (state, root) = (f.state.clone(), f.root.clone());
    let failed = Arc::new(std::sync::Mutex::new(None::<String>));
    let failed2 = failed.clone();
    // The first write of the attempt is the copy (it sorts first); a fence
    // moved under it makes that write fail and be retried.
    *executor.between_assemble_and_persist_hook.lock().unwrap() = Some(Box::new(move |out_path| {
        let rel = out_path.strip_prefix(&root).unwrap().to_string_lossy().into_owned();
        state.replica_coordinator.dag_bump_mutation_fence(GROUP, &rel, "local_capture").unwrap();
        *failed2.lock().unwrap() = Some(rel);
    }));

    tokio::time::timeout(
        Duration::from_secs(20),
        drive_obligations_once_for_test(&engine, 128, 256),
    )
    .await
    .unwrap();

    assert_eq!(
        failed.lock().unwrap().as_deref(),
        Some(copy),
        "the copy's write is the one that failed"
    );
    assert!(f.read(source).is_some(), "the source itself was written");
    assert!(
        obligation(&f, source).is_some(),
        "the source's obligation closed although its copy is unwritten (limit {limit})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_copy_named_entry_keeps_its_original_owed_serially() {
    a_name_that_looks_like_a_copy_keeps_its_original_owed(1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_copy_named_entry_keeps_its_original_owed_concurrently() {
    a_name_that_looks_like_a_copy_keeps_its_original_owed(8).await;
}

// ---------------------------------------------------------------------
// Several files of one window, closed in one batched transaction
// ---------------------------------------------------------------------

/// What a window of `count` files looks like before any of it is committed.
struct Window {
    names: Vec<String>,
    contents: Vec<Vec<u8>>,
    versions: Vec<FileVersion>,
    claims: Vec<ProjectionObligation>,
}

fn admit_window(f: &Fixture, prefix: &str, count: usize, len: usize) -> Window {
    let names: Vec<String> = (0..count).map(|i| format!("{prefix}{i}.bin")).collect();
    let contents: Vec<Vec<u8>> = (0..count).map(|i| content_of(len + i, (40 + i) as u8)).collect();
    // With the mode the written file has, so a watcher that looks at it while the
    // window waits finds nothing of its own to author.
    let versions: Vec<FileVersion> =
        contents.iter().map(|c| f.content_version_with_mode(c, 1000, Some(0o644))).collect();
    for (name, version) in names.iter().zip(&versions) {
        f.admit(name, version);
    }
    let claims =
        names.iter().map(|n| obligation(f, n).expect("the admission arms an obligation")).collect();
    Window { names, contents, versions, claims }
}

fn executor(f: &Fixture) -> Arc<crate::local_convergence::LocalConvergenceExecutor> {
    f.state.peers.local_convergence("device-peer").unwrap()
}

fn batch_sizes(f: &Fixture) -> Vec<usize> {
    f.state.replica_coordinator.test_observers.close_batch_sizes.lock().unwrap().clone()
}

fn long_deadline(f: &Fixture) {
    executor(f)
        .completion_max_latency_override_ms
        .store(20_000, std::sync::atomic::Ordering::Relaxed);
}

/// Parks one engine pass with every file of `window` renamed into place and
/// held before its completion, and returns the hook and the pass.
async fn park_window(
    engine: &Arc<ConvergenceEngine>,
    window: &Window,
) -> (Arc<BeforeCompletionHook>, tokio::task::JoinHandle<bool>) {
    let hook = BeforeCompletionHook::new();
    let (engine2, hook2) = (engine.clone(), hook.clone());
    let pass = tokio::spawn(async move {
        drive_obligations_once_for_test_with_hooks(&engine2, 128, 256, &hook2).await
    });
    // Wait for every file to be parked at the completion seam, not for a
    // guessed delay: bytes on disk say nothing about how far each future got.
    hook.wait_parked_count(window.names.len(), Duration::from_secs(30)).await;
    assert_eq!(hook.parked_count(), window.names.len(), "exactly one park per window file");
    (hook, pass)
}

/// Releases every parked file in turn, until the pass is over.
async fn release_all(hook: &BeforeCompletionHook, pass: tokio::task::JoinHandle<bool>) {
    let waited = std::time::Instant::now();
    while !pass.is_finished() {
        assert!(waited.elapsed() < Duration::from_secs(30), "the pass never finished");
        hook.resume();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    pass.await.unwrap();
}

fn assert_window_durable_and_nothing_committed(f: &Fixture, window: &Window) {
    for ((name, content), claimed) in window.names.iter().zip(&window.contents).zip(&window.claims)
    {
        assert_durable_on_disk_and_nothing_committed(f, name, content, claimed);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_of_claimed_files_closes_all_its_obligations_in_one_transaction() {
    let (f, engine) = ready_fixture().await;
    long_deadline(&f);
    let window = admit_window(&f, "w", 4, ONE_BLOCK);
    let (hook, pass) = park_window(&engine, &window).await;
    assert_window_durable_and_nothing_committed(&f, &window);
    release_all(&hook, pass).await;

    for (name, version) in window.names.iter().zip(&window.versions) {
        assert!(obligation(&f, name).is_none(), "{name}: the obligation closed with its proof");
        assert_eq!(proven_version(&f, name), Some(version.version_hash));
        assert!(hydrated(&f, name) && !intent_open(&f, name));
    }
    assert_eq!(batch_sizes(&f), vec![4], "four files, one close transaction");
}

/// One file's claim is overtaken while the window waits: its proof is kept and
/// its obligation stays open; the other files' obligations close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_overtaken_in_a_batch_leaves_only_that_obligation_open() {
    let (f, engine) = ready_fixture().await;
    long_deadline(&f);
    let window = admit_window(&f, "s", 3, ONE_BLOCK);
    let (hook, pass) = park_window(&engine, &window).await;
    f.state
        .replica_coordinator
        .sqlite()
        .dag_bump_projection_obligations_for_touched_paths(GROUP, &[window.names[1].as_str()], 1)
        .unwrap();
    release_all(&hook, pass).await;

    let stale = &window.names[1];
    assert_eq!(proven_version(&f, stale), Some(window.versions[1].version_hash));
    assert!(hydrated(&f, stale) && !intent_open(&f, stale), "the proof stands on its own");
    let open = obligation(&f, stale).expect("a stale claim closes nothing");
    assert!(open.invalidation_generation > window.claims[1].invalidation_generation);
    for i in [0, 2] {
        assert!(obligation(&f, &window.names[i]).is_none(), "{}", window.names[i]);
        assert!(hydrated(&f, &window.names[i]));
    }
    assert_eq!(batch_sizes(&f), vec![3]);

    drive_until(&f, &engine, "the overtaken obligation closes", |f| obligation(f, stale).is_none())
        .await;
}

/// One file's fence moves while the window waits: that file publishes and
/// closes nothing and keeps its intent and its claim; the others commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_moved_in_a_batch_refuses_only_that_file() {
    let (f, engine) = ready_fixture().await;
    long_deadline(&f);
    let window = admit_window(&f, "f", 3, ONE_BLOCK);
    let (hook, pass) = park_window(&engine, &window).await;
    let raced = &window.names[2];
    f.state.replica_coordinator.dag_bump_mutation_fence(GROUP, raced, "local_capture").unwrap();
    release_all(&hook, pass).await;

    assert!(!any_proof_row(&f, raced) && !hydrated(&f, raced) && intent_open(&f, raced));
    assert_eq!(obligation(&f, raced).map(|o| claim_of(&o)), Some(claim_of(&window.claims[2])));
    for i in [0, 1] {
        let name = &window.names[i];
        assert!(obligation(&f, name).is_none(), "{name}");
        assert!(hydrated(&f, name) && !intent_open(&f, name));
    }
    assert_eq!(batch_sizes(&f), vec![3]);

    drive_until(&f, &engine, "the refused file is re-driven", |f| obligation(f, raced).is_none())
        .await;
    assert!(proof_names_current_row(&f, raced));
}

fn head_count(f: &Fixture, name: &str) -> usize {
    f.state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::native_store::native_heads_at(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
                &yadorilink_replica_domain::ids::SyncPath(name.to_owned()),
            )
        })
        .unwrap()
        .len()
}

/// After any crash the end state is the same: every file Hydrated with an
/// exact proof, its intent and obligation closed, its bytes right, one head,
/// no conflict copy and no stray temp file.
fn assert_recovered(f: &Fixture, window: &Window) {
    for (name, content) in window.names.iter().zip(&window.contents) {
        assert_eq!(f.read(name).as_deref(), Some(&content[..]), "{name}");
        assert!(hydrated(f, name) && !intent_open(f, name), "{name}");
        assert!(proof_names_current_row(f, name), "{name}");
        assert!(obligation(f, name).is_none(), "{name}");
        assert_eq!(head_count(f, name), 1, "{name}: no second version authored");
    }
    let mut entries: Vec<String> = std::fs::read_dir(&f.root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    entries.sort();
    assert!(
        entries.iter().all(|n| !n.contains("conflict") && !n.contains(".yadorilink-tmp.")),
        "{entries:?}"
    );
}

/// Crash after the temp files are synced, before any rename: the stray temps
/// and in-flight rows are what a single file leaves, once per file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_after_the_temp_fsyncs_of_a_window_is_rebuilt_from_the_blocks() {
    let (f, engine) = ready_fixture().await;
    let window = admit_window(&f, "t", 3, multi_block());
    let probe = crate::local_convergence::OverlapProbe::new(
        crate::local_convergence::ProbeSeam::BeforeRename,
        1,
        60_000,
    );
    probe.hold_until_released();
    *executor(&f).overlap_probe.lock().unwrap() = Some(probe.clone());
    let pass = {
        let engine = engine.clone();
        tokio::spawn(async move { drive_obligations_once_for_test(&engine, 128, 256).await })
    };
    let waited = std::time::Instant::now();
    while probe.in_flight() < 3 {
        assert!(waited.elapsed() < Duration::from_secs(30), "{:?}", probe.events());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The crash: nothing ran past the temp file's sync.
    pass.abort();
    let _ = pass.await;
    *executor(&f).overlap_probe.lock().unwrap() = None;

    for (name, claimed) in window.names.iter().zip(&window.claims) {
        assert!(f.read(name).is_none(), "{name}: not renamed yet");
        assert!(!any_proof_row(&f, name) && !hydrated(&f, name) && intent_open(&f, name));
        assert_eq!(obligation(&f, name).as_ref(), Some(claimed));
    }
    let strays = f.state.replica_coordinator.remove_recorded_temp_files(GROUP, &f.root).unwrap();
    assert_eq!(strays.len(), 3, "one recorded temp per file: {strays:?}");

    let report = repair(&f);
    assert_eq!(report.reconstructed.len(), 3, "rebuilt from the blocks: {report:?}");
    assert!(report.offline_deleted.is_empty(), "an interrupted write is not an offline delete");
    drive_until(&f, &engine, "the window closes", |f| {
        window.names.iter().all(|n| obligation(f, n).is_none())
    })
    .await;
    assert_recovered(&f, &window);
}

/// Crash after the renames and directory syncs, before the batch commits,
/// with the database a real file that is reopened for recovery: the committed
/// state is what recovery sees, and it finishes every file without rewriting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_after_the_directory_syncs_before_the_batch_is_finished_by_repair() {
    let f = fixture(true).await;
    let engine = Arc::new(ConvergenceEngine::new(f.state.clone()));
    f.admit("warm.txt", &f.content_version(b"warm-up", 100));
    drive_until(&f, &engine, "the warm-up path closes", |f| obligation(f, "warm.txt").is_none())
        .await;
    f.state.replica_coordinator.test_observers.close_batch_sizes.lock().unwrap().clear();
    long_deadline(&f);
    let window = admit_window(&f, "c", 3, multi_block());
    let (_hook, pass) = park_window(&engine, &window).await;
    assert_window_durable_and_nothing_committed(&f, &window);

    pass.abort();
    let _ = pass.await;
    assert!(batch_sizes(&f).is_empty(), "nothing committed before the crash");

    // Restart: the database is opened again from its file.
    let mut reopened = ReplicaCoordinator::open(f.database_path().unwrap());
    for _ in 0..40 {
        if reopened.is_ok() {
            break;
        }
        // The aborted pass may still be finishing a statement on the old handle.
        tokio::time::sleep(Duration::from_millis(50)).await;
        reopened = ReplicaCoordinator::open(f.database_path().unwrap());
    }
    let reopened = reopened.unwrap();
    for name in &window.names {
        assert!(reopened.has_materialization_intent(GROUP, name).unwrap(), "{name}");
    }
    #[cfg(unix)]
    let inodes: Vec<u64> = window.names.iter().map(|n| inode(&f, n)).collect();
    let store = crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        f.state.block_store.clone(),
    );
    let report =
        yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            &reopened,
            &store,
            &f.root,
            GROUP,
            yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(report.reconstructed.is_empty(), "the bytes already match: {report:?}");
    assert!(report.offline_deleted.is_empty());
    assert!(report.quarantined_dirty.is_empty());
    for name in &window.names {
        assert!(!reopened.has_materialization_intent(GROUP, name).unwrap(), "{name}");
    }
    drive_until(&f, &engine, "the window closes", |f| {
        window.names.iter().all(|n| obligation(f, n).is_none())
    })
    .await;
    #[cfg(unix)]
    assert_eq!(
        window.names.iter().map(|n| inode(&f, n)).collect::<Vec<_>>(),
        inodes,
        "closed without rewriting any file"
    );
    assert_recovered(&f, &window);
}

/// Crash in the middle of the batch transaction: it is atomic, so none of the
/// files has any of its close, and recovery then finishes all of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_in_the_middle_of_the_batch_transaction_commits_none_of_it() {
    let (f, engine) = ready_fixture().await;
    long_deadline(&f);
    f.state
        .replica_coordinator
        .test_observers
        .close_batch_fails_before_commit
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let window = admit_window(&f, "m", 3, ONE_BLOCK);
    let (hook, pass) = park_window(&engine, &window).await;
    release_all(&hook, pass).await;

    assert!(!batch_sizes(&f).is_empty(), "the batch transaction ran");
    for ((name, content), claimed) in window.names.iter().zip(&window.contents).zip(&window.claims)
    {
        assert_eq!(f.read(name).as_deref(), Some(&content[..]), "{name}: the bytes are on disk");
        assert!(!any_proof_row(&f, name), "{name}: no proof of a rolled-back batch");
        assert!(!hydrated(&f, name) && intent_open(&f, name), "{name}");
        // The failed attempt is recorded against the obligation; nothing closed it.
        assert_eq!(obligation(&f, name).map(|o| claim_of(&o)), Some(claim_of(claimed)), "{name}");
    }

    f.state
        .replica_coordinator
        .test_observers
        .close_batch_fails_before_commit
        .store(false, std::sync::atomic::Ordering::SeqCst);
    // The restart's repair sweep. It `try_lock`s each path and leaves a path whose lock is held to
    // its next pass (it runs on a live cadence, not only at startup), and the fixture's own
    // watcher can hold one for a moment; a skipped path stays `Hydrating` with its intent open.
    // The window's obligation does not wait for that pass (the engine closes it regardless), so
    // the sweep is re-run until it has reached every path, as the cadence would.
    let swept = std::time::Instant::now();
    loop {
        repair(&f);
        if window.names.iter().all(|n| hydrated(&f, n) && !intent_open(&f, n)) {
            break;
        }
        assert!(
            swept.elapsed() < Duration::from_secs(30),
            "the repair sweep never reached every path"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drive_until(&f, &engine, "the window closes", |f| {
        window.names.iter().all(|n| obligation(f, n).is_none())
    })
    .await;
    assert_recovered(&f, &window);
}

// ---------------------------------------------------------------------
// Row helpers shared by the open and close recovery tests
// ---------------------------------------------------------------------

/// `(version_seq, unix_mode, size, state)` of every row of `name`.
fn rows_of(f: &Fixture, name: &str) -> Vec<(i64, i64, i64, String)> {
    f.state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT version_seq, unix_mode, size, state FROM files \
                 WHERE group_id = ?1 AND path = ?2 ORDER BY version_seq",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![GROUP, name], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
}

/// What recovery ends with, per file: its rows, bytes, proof, intent, obligation
/// and head count.
fn end_state(f: &Fixture, window: &Window) -> Vec<String> {
    window
        .names
        .iter()
        .map(|n| {
            format!(
                "{n} {:?} {:?} hydrated={} intent={} proof={} obligation={} heads={}",
                rows_of(f, n),
                f.read(n).map(|b| b.len()),
                hydrated(f, n),
                intent_open(f, n),
                proof_names_current_row(f, n),
                obligation(f, n).is_some(),
                head_count(f, n),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------
// The open of a window's writes, committed in one batched transaction
// ---------------------------------------------------------------------

const OPEN_BATCHED: u8 = 1;
const OPEN_PER_FILE: u8 = 2;

fn open_batches(f: &Fixture) -> Vec<usize> {
    f.state.replica_coordinator.test_observers.open_batch_sizes.lock().unwrap().clone()
}

/// The crash after the open of every file of a window has committed and
/// before any byte is at its name (each file's temp file is synced, nothing
/// is renamed). The state is read from a database reopened from its file,
/// startup repair rebuilds every file from its blocks, and the engine then
/// finishes the window. The per-file open reaches the same crash state and
/// the same end.
async fn a_crash_after_the_open_before_any_byte(mode: u8) -> (Vec<String>, Vec<String>) {
    let f = fixture(true).await;
    let engine = Arc::new(ConvergenceEngine::new(f.state.clone()));
    f.admit("warm.txt", &f.content_version(b"warm-up", 100));
    drive_until(&f, &engine, "the warm-up path closes", |f| obligation(f, "warm.txt").is_none())
        .await;
    // A window must not flush on its 20 ms latency bound while the three
    // files are still arriving, or the batch splits under load.
    long_deadline(&f);
    executor(&f).batch_open_override.store(mode, std::sync::atomic::Ordering::Relaxed);
    f.state.replica_coordinator.test_observers.open_batch_sizes.lock().unwrap().clear();
    let window = admit_window(&f, "o", 3, multi_block());
    let probe = crate::local_convergence::OverlapProbe::new(
        crate::local_convergence::ProbeSeam::BeforeRename,
        1,
        60_000,
    );
    probe.hold_until_released();
    *executor(&f).overlap_probe.lock().unwrap() = Some(probe.clone());
    let pass = {
        let engine = engine.clone();
        tokio::spawn(async move { drive_obligations_once_for_test(&engine, 128, 256).await })
    };
    let waited = std::time::Instant::now();
    while probe.in_flight() < 3 {
        assert!(waited.elapsed() < Duration::from_secs(30), "{:?}", probe.events());
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The crash: nothing ran past the temp files' sync.
    pass.abort();
    let _ = pass.await;
    *executor(&f).overlap_probe.lock().unwrap() = None;
    if mode == OPEN_BATCHED {
        assert_eq!(open_batches(&f), vec![3], "the three files opened together");
    } else {
        assert!(open_batches(&f).is_empty());
    }

    // Restart: what a fresh handle on the file sees.
    let mut reopened = ReplicaCoordinator::open(f.database_path().unwrap());
    for _ in 0..40 {
        if reopened.is_ok() {
            break;
        }
        // The aborted pass may still be finishing a statement on the old handle.
        tokio::time::sleep(Duration::from_millis(50)).await;
        reopened = ReplicaCoordinator::open(f.database_path().unwrap());
    }
    let reopened = reopened.unwrap();
    let mut crash_state = Vec::new();
    for name in &window.names {
        assert!(f.read(name).is_none(), "{name}: no byte at the name yet");
        assert!(reopened.has_materialization_intent(GROUP, name).unwrap(), "{name}");
        assert_eq!(
            reopened.get_materialization_state(GROUP, name).unwrap(),
            Some(yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE),
            "{name}"
        );
        assert!(obligation(&f, name).is_some(), "{name}: the obligation is still owed");
        crash_state.push(format!("{name} {:?}", rows_of(&f, name)));
    }
    let strays = reopened.remove_recorded_temp_files(GROUP, &f.root).unwrap();
    assert_eq!(strays.len(), 3, "one recorded temp per file: {strays:?}");
    let store = crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        f.state.block_store.clone(),
    );
    let report =
        yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            &reopened,
            &store,
            &f.root,
            GROUP,
            yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert_eq!(report.reconstructed.len(), 3, "rebuilt from the blocks: {report:?}");
    assert!(report.offline_deleted.is_empty(), "an interrupted open is not an offline delete");
    drive_until(&f, &engine, "the window closes", |f| {
        window.names.iter().all(|n| obligation(f, n).is_none())
    })
    .await;
    assert_recovered(&f, &window);
    (crash_state, end_state(&f, &window))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_after_the_batched_open_leaves_what_the_per_file_open_leaves() {
    let (per_file_crash, per_file_end) =
        a_crash_after_the_open_before_any_byte(OPEN_PER_FILE).await;
    let (batched_crash, batched_end) = a_crash_after_the_open_before_any_byte(OPEN_BATCHED).await;

    assert_eq!(batched_crash, per_file_crash);
    assert_eq!(batched_end, per_file_end);
}

/// Crash in the middle of the batched open transaction: it is atomic, so no
/// file has an intent, an in-flight state or bytes, and recovery then
/// finishes all of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_in_the_middle_of_the_open_batch_opens_none_of_it() {
    let (f, engine) = ready_fixture().await;
    executor(&f).batch_open_override.store(OPEN_BATCHED, std::sync::atomic::Ordering::Relaxed);
    f.state
        .replica_coordinator
        .test_observers
        .open_batch_fails_before_commit
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let window = admit_window(&f, "n", 3, ONE_BLOCK);
    tokio::time::timeout(
        Duration::from_secs(30),
        drive_obligations_once_for_test(&engine, 128, 256),
    )
    .await
    .expect("one engine pass must not stall");

    for name in &window.names {
        assert!(!intent_open(&f, name), "{name}: an intent of a rolled-back batch");
        assert_ne!(
            f.state.replica_coordinator.get_materialization_state(GROUP, name).unwrap(),
            Some(yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE),
            "{name}: an in-flight state of a rolled-back batch"
        );
        assert!(f.read(name).is_none(), "{name}: bytes before an open");
        assert!(obligation(&f, name).is_some(), "{name}: the obligation is still owed");
    }

    f.state
        .replica_coordinator
        .test_observers
        .open_batch_fails_before_commit
        .store(false, std::sync::atomic::Ordering::SeqCst);
    repair(&f);
    drive_until(&f, &engine, "the window closes", |f| {
        window.names.iter().all(|n| obligation(f, n).is_none())
    })
    .await;
    assert_recovered(&f, &window);
}
