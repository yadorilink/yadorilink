//! Deterministic two-device collision scenarios for a dimension the
//! broader collision-matrix coverage doesn't touch: the Unix
//! owner-executable bit and metadata-only (no content change) touches, as
//! distinct from ordinary content-edit conflicts. Same full-daemon-stack,
//! hand-picked-scenario convention as the rest of this suite.
//! `TestDevice`/`setup_device`/`start_watching`/`two_synced_devices` are
//! self-contained here rather than shared, matching this codebase's
//! existing convention of self-contained daemon integration test binaries.
//! The wire schema (`proto::FileInfo::unix_mode`) and the
//! materialization-side apply (`apply_unix_mode`,
//! `SyncState::get_unix_mode`/ `set_unix_mode`) exist and are exercised
//! end to end. The scenarios below assert against that wired behavior: a
//! brand-new executable file propagates its exec bit to peers (scenario
//! 4); an exec-bit-only chmod advances the version, so toggling it while a
//! peer concurrently edits content is a genuine two-version conflict that
//! surfaces a conflict copy (scenario 1); opposite exec-bit-only chmods
//! with identical content still converge to an agreed exec-bit state on
//! both devices, and the two-sided conflict is proved via explicit
//! pre-connect index reads and a post- convergence exec-bit-multiset
//! assertion, not just structural "a winner and a conflict copy exist"
//! (scenario 2); a no-op identical-bytes touch still never produces a
//! version-bumping record, so it cannot race a real edit (scenario 3); and
//! a genuinely shared-history exec-bit-only divergence -- both devices
//! starting from a real common ancestor, then diverging purely in metadata
//! while disconnected -- converges the same way, covering the shared-history
//! case scenario 2's create/create collision does not (scenario 5).

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use support::{
    open_file_backed_replica_coordinator, real_entry_names, wait_until, wait_until_with_context,
    TestAccount,
};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;
#[cfg(unix)]
use yadorilink_replica_domain::ids::DeltaHash;

/// This device's own indexed owner-exec bit for `path`, read directly from
/// its file index (not inferred from on-disk permissions, which a test may
/// have just set itself and which prove nothing about whether local capture
/// actually observed and recorded them). Used to assert what a device's own
/// DAG-backed state actually holds, independent of what the test wrote to
/// disk moments earlier.
#[cfg(unix)]
fn indexed_unix_mode(device: &TestDevice, group_id: &str, path: &str) -> bool {
    const OWNER_EXEC: u32 = 0o100;
    device
        .state
        .replica_coordinator
        .file_index_repository()
        .get_unix_mode(group_id, path)
        .unwrap_or_else(|error| {
            panic!("{}: failed to read indexed exec bit for {path}: {error}", device.device_id)
        })
        .is_some_and(|mode| mode & OWNER_EXEC != 0)
}

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // Uses file-backed WAL (production's concurrency model) instead of
    // open_in_memory's shared-cache backend — see
    // open_file_backed_replica_coordinator's doc comment. Held only to keep the
    // backing temp file alive for the test's duration.
    _index_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let device_id = support::register_device(account, name, [0u8; 32]).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(device_id.clone(), sync_state, store);
    // Give the device a change-signing key before its link watch starts, so the
    // change-DAG emitter is wired and local edits actually propagate.
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

/// Sets up two devices, both syncing a fresh folder group, and waits for
/// peer sessions to establish. Every scenario below starts from this.
async fn two_synced_devices(test_name: &str) -> (TestDevice, TestDevice, String) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "exec-bit-metadata-group").await;
    support::grant_access(&account, &group_id, &device_a.device_id).await;
    support::grant_access(&account, &group_id, &device_b.device_id).await;

    start_watching(&device_a, &group_id).await;
    start_watching(&device_b, &group_id).await;

    support::connect_two_daemons(
        &device_a.state,
        &device_a.device_id,
        &device_b.state,
        &device_b.device_id,
        std::slice::from_ref(&group_id),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    (device_a, device_b, group_id)
}

/// Like [`two_synced_devices`], but also returns the pairing's link so a
/// caller can later close it to genuinely and cleanly sever the pairing --
/// used by
/// `shared_history_unix_mode_only_divergence_converges_after_reconnect` to
/// construct a real disconnect/reconnect sequence on a file both devices
/// already share history on, rather than the create/create shape
/// [`two_unconnected_devices`] uses. See
/// `support::connect_two_daemons_with_link`'s doc comment for why closing
/// the link, not `JoinHandle::abort()`, is the correct disconnect primitive
/// here.
#[cfg(unix)]
async fn two_synced_devices_with_link(
    test_name: &str,
) -> (TestDevice, TestDevice, String, Arc<support::PairingLink>) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "exec-bit-metadata-group").await;
    support::grant_access(&account, &group_id, &device_a.device_id).await;
    support::grant_access(&account, &group_id, &device_b.device_id).await;

    start_watching(&device_a, &group_id).await;
    start_watching(&device_b, &group_id).await;

    let (_handles, link) = support::connect_two_daemons_with_link(
        &device_a.state,
        &device_a.device_id,
        &device_b.state,
        &device_b.device_id,
        std::slice::from_ref(&group_id),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    (device_a, device_b, group_id, link)
}

/// Sets up two devices watching a fresh shared folder group, exactly like
/// [`two_synced_devices`], but deliberately does NOT pair them yet — the
/// caller connects them explicitly (via `support::connect_two_daemons`)
/// once it is ready to. See
/// `concurrent_unix_mode_true_vs_false_no_content_change`'s doc comment for
/// why this matters: two devices that are already connected while each
/// makes an independent local write race the wire, and that race usually
/// resolves in favour of wire delivery beating the OTHER device's own local
/// debounce/capture; `yadorilink-local-capture`'s self-echo content-hash
/// suppression then treats the losing side's exec-bit-only difference as no
/// change. Simply not connecting the two devices until both already
/// hold their own independent, captured local `Change` sidesteps needing to
/// depend on winning that race at all -- no session exists yet, so there is
/// nothing for a local write to race against.
#[allow(dead_code)]
async fn two_unconnected_devices(test_name: &str) -> (TestDevice, TestDevice, String) {
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "exec-bit-metadata-group").await;
    support::grant_access(&account, &group_id, &device_a.device_id).await;
    support::grant_access(&account, &group_id, &device_b.device_id).await;

    // A linked group is intentionally fail-closed on local DAG emission
    // when its policy is absent -- normally installed as a side effect of
    // `connect_two_daemons`, which this helper deliberately doesn't call
    // yet (see this function's own doc comment). Install it explicitly so
    // each device's local writes below are captured immediately rather than
    // silently withheld.
    support::install_bootstrap_policy(&device_a.state, std::slice::from_ref(&group_id));
    support::install_bootstrap_policy(&device_b.state, std::slice::from_ref(&group_id));

    start_watching(&device_a, &group_id).await;
    start_watching(&device_b, &group_id).await;

    (device_a, device_b, group_id)
}

/// This device's own current change-DAG head set for `group_id` — the
/// direct, non-flaky way to observe "did this device's own local edit just
/// become a real, durable version-bump" without inferring it from on-disk
/// content/mtime. Two devices' heads differing (after both started from the
/// same head) is exactly what "genuinely distinct, independent DAG branch
/// tips" means at this crate's own boundary — see
/// `yadorilink_sync_sqlite::SqliteSyncStore::dag_group_heads`, the same
/// accessor `monkey_chaos.rs`/`retroactive_repair_seed_matrix.rs` already use
/// for per-device DAG-state debug context.
#[cfg(unix)]
fn dag_heads(device: &TestDevice, group_id: &str) -> Vec<DeltaHash> {
    support::native_group_head_set(&device.state, group_id)
}

/// A device's real (non-artifact) entries, keyed by name, valued by content —
/// plain content (not a hash) so a failure's assertion message is directly
/// readable. Used as the convergence signal for the exec-bit conflict scenario,
/// where a bare file-name-set match is satisfied before the conflict's content
/// actually propagates. Only exercised by the `#[cfg(unix)]` exec-bit conflict
/// scenario, so it is unused on non-unix builds.
#[allow(dead_code)]
fn snapshot(root: &std::path::Path) -> HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read_to_string(root.join(&name)).unwrap_or_default();
            (name, content)
        })
        .collect()
}

/// Reads back the real owner-exec bit a materialized file carries on
/// disk — the same bit `chunker::apply_unix_mode` sets/clears and
/// `types::unix_mode_from_metadata` would (if wired) capture.
/// Unix-only: intentionally not given a non-unix stub, since every call
/// site is itself behind a `#[cfg(unix)]` block.
#[cfg(unix)]
fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).map(|m| m.permissions().mode() & 0o100 != 0).unwrap_or(false)
}

/// Only exercised by the exec-bit conflict scenario below, which is itself
/// `#[cfg(unix)]`.
#[cfg(unix)]
fn is_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy")
}

/// Like [`snapshot`], but pairs each entry's content with its owner-exec
/// bit — used by `concurrent_unix_mode_true_vs_false_no_content_change`,
/// where equality must mean "both devices agree on every entry's bytes AND
/// exec bit," not merely on bytes.
#[cfg(unix)]
fn exec_snapshot(root: &std::path::Path) -> HashMap<String, (String, bool)> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let path = root.join(&name);
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            let exec = is_executable(&path);
            (name, (content, exec))
        })
        .collect()
}

// --- Scenario 1: concurrent exec-bit toggle vs. content edit --------------

/// Device A flips an already-synced file's exec bit to true (chmod only,
/// no content change) while device B concurrently edits the file's
/// content (content only, no permission change), with a small stagger for
/// deterministic ordering.
///
/// Per this file's header: A's exec-bit-only chmod is now captured by
/// `local_change.rs`'s record-building path and advances A's local index
/// version. So A's permission change and B's content edit are two
/// independent version-bumping changes to the same file — a genuine
/// concurrent conflict. B's edit is the later write, so it wins the
/// `shared.txt` name on both devices while A's losing side is preserved as
/// exactly one conflict copy. The exec bit is asserted as
/// agreement-between-devices rather than a fixed value, since both devices
/// materialize the same winning version — a divergence there would be a
/// real candidate bug this assertion is positioned to catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_unix_mode_toggle_true_vs_content_edit() {
    #[cfg(not(unix))]
    {
        eprintln!(
            "skipping concurrent_unix_mode_toggle_true_vs_content_edit: requires a POSIX owner-exec bit"
        );
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let (device_a, device_b, group_id) =
            two_synced_devices("exec-bit-toggle-vs-content-edit").await;
        let _ = group_id;

        std::fs::write(device_a.root.path().join("shared.txt"), b"base").unwrap();
        wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10))
            .await;

        // A: exec bit only, no content change.
        std::fs::set_permissions(
            device_a.root.path().join("shared.txt"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
                                                             // B: content only, no permission change.
        std::fs::write(device_b.root.path().join("shared.txt"), b"edited on B, exec bit untouched")
            .unwrap();

        // A's chmod and B's content edit both advance their own versions, so
        // this is a genuine concurrent conflict whose conflict-copy artifact
        // takes real synchronization to appear. Both directories already agree
        // on `["shared.txt"]` from the instant the two writes land -- well
        // before conflict resolution runs -- and even a two-entry name-set
        // match (original + conflict copy) can appear on both sides before the
        // conflict's *content* has actually propagated. Wait for a full
        // name->content snapshot match with more than one entry, so this can't
        // pass until both devices genuinely hold the same resolved bytes.
        wait_until_with_context(
            || {
                let a = snapshot(device_a.root.path());
                let b = snapshot(device_b.root.path());
                a.len() > 1 && a == b
            },
            Duration::from_secs(20),
            || {
                format!(
                    "device-a={:?} device-b={:?}",
                    real_entry_names(device_a.root.path()),
                    real_entry_names(device_b.root.path())
                )
            },
        )
        .await;

        let names = real_entry_names(device_a.root.path());
        assert!(names.contains(&"shared.txt".to_string()), "{names:?}");
        assert_eq!(
            names.iter().filter(|n| is_conflict_copy(n)).count(),
            1,
            "A's exec-bit-only chmod now advances A's version vector, so it and \
             B's concurrent content edit are a genuine conflict that must surface \
             exactly one conflict copy: {names:?}"
        );
        // DAG conflict resolution deliberately ignores wall-clock ordering and
        // chooses the canonical name by (lamport, change hash). Which content
        // owns `shared.txt` is therefore not an mtime contract; the durability
        // contract is that both replicas make the same choice and preserve
        // both the base+chmod version and B's edited bytes.
        let final_snapshot = snapshot(device_a.root.path());
        let mut contents: Vec<_> = final_snapshot.values().cloned().collect();
        contents.sort();
        assert_eq!(
            contents,
            vec!["base".to_string(), "edited on B, exec bit untouched".to_string()]
        );

        let exec_a = is_executable(&device_a.root.path().join("shared.txt"));
        let exec_b = is_executable(&device_b.root.path().join("shared.txt"));
        assert_eq!(
            exec_a, exec_b,
            "both devices must agree on shared.txt's final exec-bit state after \
             convergence (device-a={exec_a} device-b={exec_b})"
        );
    }
}

// --- Scenario 2: pure metadata conflict, opposite exec-bit values ----------

/// Both devices independently AUTHOR (never having synced this path with
/// each other) the SAME filename with byte-identical content but opposite
/// exec bits — a pure metadata conflict with no content divergence.
///
/// **Construction.** Starting both devices from the SAME synced boolean and
/// setting one to `true` and the other to `false` cannot generate two
/// genuinely concurrent, conflicting DAG branches — a boolean has only two
/// states, so whichever device's target already equalled the shared starting
/// value made no real change at all (no new local `Change`, no version
/// bump), leaving only ONE side with anything to converge.
///
/// This version sidesteps that entirely two ways at once:
///
/// 1. Each device's write is a brand-new local file CREATE (real content
///    bytes, a real exec bit, at creation time) rather than a chmod-only
///    edit to an already-synced file — the exact same create-time exec-bit
///    capture scenario 4 below already exercises and trusts.
/// 2. The two devices are deliberately NOT connected yet when they make
///    those writes ([`two_unconnected_devices`]) — connected only
///    afterward, once both already hold their own independently-captured
///    local `Change`.
///
/// Both are load-bearing: this test pins conflict resolution, not local
/// capture, so it must not depend on two capture paths in
/// `yadorilink-local-capture`:
///   - A chmod-only metadata edit to a path this device only knows about
///     because it *received* it from a peer (its size+mtime fast path does
///     not fire, because the receiving side's indexed `mtime` does not match
///     the materialized file's real on-disk mtime).
///   - The self-echo check (`existing.blocks == blocks => no-op`) compares
///     blocks, not the exec bit, so a local write whose content already
///     matches what's indexed -- e.g. two connected devices creating the
///     same path with the same content, one landing just after the other's
///     matching content arrived -- is treated as no change.
/// Connecting only after both independent
/// creates are already captured avoids depending on either path at all: with
/// no session yet, there is nothing for either device's local write to race
/// against, so [`dag_heads`] genuinely proves two distinct, independent DAG
/// branches exist before any wire delivery could have happened, not merely
/// a race won by chance.
///
/// The final exec-bit equality assertion is intentionally not softened to
/// "converges to something": an unnoticed permission divergence between
/// devices is the real regression this test exists to catch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_unix_mode_true_vs_false_no_content_change() {
    #[cfg(not(unix))]
    {
        eprintln!(
            "skipping concurrent_unix_mode_true_vs_false_no_content_change: requires a POSIX owner-exec bit"
        );
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let (device_a, device_b, group_id) =
            two_unconnected_devices("exec-bit-true-vs-false-no-content").await;

        let path_a = device_a.root.path().join("shared.txt");
        let path_b = device_b.root.path().join("shared.txt");

        // Two independent local CREATEs of the SAME path, byte-identical
        // content, opposite exec bits -- the devices are not yet connected
        // (see `two_unconnected_devices`), so each is genuinely this
        // device's own, uncontested root `Change`.
        std::fs::write(&path_a, b"base content, never edited").unwrap();
        std::fs::set_permissions(&path_a, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&path_b, b"base content, never edited").unwrap();
        std::fs::set_permissions(&path_b, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Proof of genuine two-sided concurrency, checked directly rather
        // than assumed from the setup: each device's own DAG head must
        // advance from empty (a real, captured local change), and the two
        // devices' heads must genuinely disagree -- independent branches,
        // not a race already resolved by the time this checks.
        wait_until_with_context(
            || !dag_heads(&device_a, &group_id).is_empty(),
            Duration::from_secs(10),
            || "device-a never captured its own local create into the DAG".to_string(),
        )
        .await;
        wait_until_with_context(
            || !dag_heads(&device_b, &group_id).is_empty(),
            Duration::from_secs(10),
            || "device-b never captured its own local create into the DAG".to_string(),
        )
        .await;
        let heads_a = dag_heads(&device_a, &group_id);
        let heads_b = dag_heads(&device_b, &group_id);
        assert_ne!(
            heads_a, heads_b,
            "device-a and device-b must have produced genuinely distinct, independent DAG \
             branch tips -- otherwise this is not a real concurrent conflict"
        );

        // Prove the actual claim this scenario's name makes -- not just that
        // *some* independent change was captured on each side, but that each
        // device's own file index genuinely holds the opposite exec-bit value
        // this test wrote. Read from the file index (`get_unix_mode`), not
        // disk permissions: disk permissions only prove the test wrote them a
        // moment ago, not that local capture actually observed and recorded
        // them into the DAG-backed index that conflict resolution will read.
        assert!(
            indexed_unix_mode(&device_a, &group_id, "shared.txt"),
            "device-a's own file index must show shared.txt as executable before the two \
             devices ever connect -- otherwise this isn't a genuine pre-connect exec-bit divergence"
        );
        assert!(
            !indexed_unix_mode(&device_b, &group_id, "shared.txt"),
            "device-b's own file index must show shared.txt as non-executable before the two \
             devices ever connect -- otherwise this isn't a genuine pre-connect exec-bit divergence"
        );

        // Only now connect the two devices, for the first time -- both
        // already hold their own independent, captured local `Change`, so
        // there was never anything for either device's write to race
        // against.
        support::connect_two_daemons(
            &device_a.state,
            &device_a.device_id,
            &device_b.state,
            &device_b.device_id,
            std::slice::from_ref(&group_id),
        )
        .await;

        // Two independent, un-ancestored creates of the same path -- even
        // with byte-identical content -- is the same DAG shape as an
        // ordinary create/create name collision (see
        // `windows_path_hazard_conflict.rs`'s own scenario 1): resolution
        // keeps ONE winner under `shared.txt` and preserves the other side
        // as exactly one conflict-copy artifact, rather than silently
        // picking a winning exec bit for a single merged entry. That is a
        // real, correct difference from a metadata-only edit to a file both
        // devices already shared history on (which this test would only be
        // able to construct by relying on the receiver-side chmod capture
        // gap documented above) -- what still matters, and is still worth
        // pinning down here, is that BOTH devices agree on which two
        // entries exist and on each entry's own exec bit: no silent,
        // unnoticed permission divergence on either side of the conflict.
        // Wait for full agreement (names, content, AND exec bit per entry)
        // rather than a fixed sleep.
        wait_until_with_context(
            || exec_snapshot(device_a.root.path()) == exec_snapshot(device_b.root.path()),
            Duration::from_secs(20),
            || {
                format!(
                    "device-a={:?} device-b={:?}",
                    exec_snapshot(device_a.root.path()),
                    exec_snapshot(device_b.root.path())
                )
            },
        )
        .await;

        let names = real_entry_names(device_a.root.path());
        assert_eq!(
            names.iter().filter(|n| is_conflict_copy(n)).count(),
            1,
            "two independent, byte-identical-content creates with different exec bits must still \
             resolve to exactly one winner plus one conflict copy, same as an ordinary \
             create/create collision: {names:?}"
        );
        assert!(names.contains(&"shared.txt".to_string()), "{names:?}");

        let snapshot_a = exec_snapshot(device_a.root.path());
        let snapshot_b = exec_snapshot(device_b.root.path());
        assert_eq!(
            snapshot_a, snapshot_b,
            "both devices must agree on every entry's content AND exec bit after convergence -- \
             not silently diverge on either with no error and no conflict artifact: \
             device-a={snapshot_a:?} device-b={snapshot_b:?}"
        );
        for (name, (content, _exec)) in &snapshot_a {
            assert_eq!(content, "base content, never edited", "{name}: {snapshot_a:?}");
        }

        // The specific claim this scenario exists to catch: neither side's
        // exec-bit value was lost or silently collapsed to a shared wrong
        // value. `snapshot_a == snapshot_b` above already proves agreement,
        // but agreement alone would also hold if a bug (e.g. `apply_unix_mode`
        // always clearing the bit) collapsed BOTH devices to the same wrong
        // value -- a failure mode that is reachable without this multiset
        // check. Assert the winner and
        // conflict-copy TOGETHER carry exactly one `true` and one `false`,
        // proving both original values genuinely survived resolution rather
        // than one being lost.
        let mut unix_modes: Vec<bool> = snapshot_a.values().map(|(_content, exec)| *exec).collect();
        unix_modes.sort();
        assert_eq!(
            unix_modes,
            vec![false, true],
            "the winner (shared.txt) and its conflict copy must together carry exactly one \
             true and one false exec bit -- neither original value may be lost or collapsed \
             to a shared wrong value: {snapshot_a:?}"
        );
    }
}

// --- Scenario 3: metadata-only touch racing a genuine content edit --------

/// Device A "touches" an already-synced file — rewrites the exact same
/// bytes, which bumps the real mtime with no actual content change —
/// concurrently with device B performing a genuine content edit.
///
/// Unlike the exec-bit scenarios above, this one needs no
/// platform-specific permission bit at all, so it runs unconditionally:
/// `build_record_for_created_or_modified`'s content-hash self-echo
/// suppression (comparing freshly-chunked blocks against what's already
/// indexed) means A's rewrite never produces a version-bumping
/// `FileRecord` regardless of the mtime bump, so it must not be able to
/// race against — let alone beat — B's real edit. The expected outcome is
/// unambiguous: B's edit simply wins, with no spurious conflict-copy
/// artifact generated against A's no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metadata_only_touch_race_with_real_content_edit() {
    let (device_a, device_b, group_id) = two_synced_devices("exec-bit-touch-vs-real-edit").await;
    let _ = group_id;

    std::fs::write(device_a.root.path().join("shared.txt"), b"original content").unwrap();
    wait_until(|| device_b.root.path().join("shared.txt").exists(), Duration::from_secs(10)).await;

    // A: rewrite byte-identical content -- bumps mtime, changes nothing
    // real. B: a genuine content edit, shortly after.
    std::fs::write(device_a.root.path().join("shared.txt"), b"original content").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    std::fs::write(device_b.root.path().join("shared.txt"), b"a genuine content edit from B")
        .unwrap();

    // A's byte-identical rewrite never produces a version-bumping record, so
    // only B's edit propagates -- but both directories trivially agree on
    // `["shared.txt"]` from the instant the writes land, before that edit
    // reaches A. Wait for A to actually receive B's new content rather than a
    // bare name match.
    wait_until_with_context(
        || {
            std::fs::read(device_a.root.path().join("shared.txt")).ok()
                == Some(b"a genuine content edit from B".to_vec())
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a entries={:?} content={:?}",
                real_entry_names(device_a.root.path()),
                std::fs::read(device_a.root.path().join("shared.txt")).ok()
            )
        },
    )
    .await;

    let names = real_entry_names(device_a.root.path());
    assert_eq!(
        names,
        vec!["shared.txt".to_string()],
        "a no-op touch (identical bytes rewritten) must never generate a conflict-copy artifact \
         against a concurrent real edit: {names:?}"
    );
    assert_eq!(
        std::fs::read(device_a.root.path().join("shared.txt")).unwrap(),
        b"a genuine content edit from B"
    );
    assert_eq!(
        std::fs::read(device_b.root.path().join("shared.txt")).unwrap(),
        b"a genuine content edit from B"
    );
}

// --- Scenario 4: baseline sanity -- new executable file propagation -------

/// Not a conflict: the simplest possible sanity case, establishing
/// whether this harness surfaces exec-bit propagation behavior at all
/// before the conflict scenarios above are trusted. Device A creates a
/// brand-new executable file (mode 0o755) with content; device B should
/// receive it with the SAME owner-exec bit set, not just the same
/// content.
///
/// Per this file's header, `unix_mode_from_metadata` is now wired into
/// `local_change.rs`'s record-building path, so device A's brand-new
/// executable file is captured with its owner-exec bit set and device B
/// should receive an executable copy, not just the same content. This
/// assertion is intentionally left as a direct, unsoftened equality check
/// rather than convergence-only: this scenario is the canary that exec-bit
/// propagation works at all, so a failure here is a real regression, not a
/// flaky or ambiguous test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unix_mode_set_on_brand_new_file_propagates_to_peer() {
    #[cfg(not(unix))]
    {
        eprintln!(
            "skipping unix_mode_set_on_brand_new_file_propagates_to_peer: requires a POSIX owner-exec bit"
        );
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let (device_a, device_b, group_id) = two_synced_devices("exec-bit-new-file-baseline").await;
        let _ = group_id;

        let path_a = device_a.root.path().join("script.sh");
        std::fs::write(&path_a, b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&path_a, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Waits for content AND the exec bit together, not just content:
        // materialization writes content via reconstruct_file's atomic
        // rename and then applies the exec bit as a separate, subsequent
        // apply_unix_mode call (see peer_session.rs) -- not one atomic step.
        // Polling for content alone would observe that always-present (if
        // usually sub-millisecond) window between the two and could assert
        // on the exec bit before it's actually applied, especially under
        // host load where the gap between the two syscalls widens.
        let script_b = device_b.root.path().join("script.sh");
        wait_until_with_context(
            || {
                std::fs::read(&script_b).ok() == Some(b"#!/bin/sh\necho hi\n".to_vec())
                    && is_executable(&script_b)
            },
            Duration::from_secs(10),
            || format!("device-b entries: {:?}", real_entry_names(device_b.root.path())),
        )
        .await;

        assert!(
            is_executable(&path_a),
            "sanity: device-a's own file must still be executable after its own chmod"
        );
        assert!(
            is_executable(&script_b),
            "device-b must receive the SAME owner-exec bit device-a set on a brand-new file, \
             not just the same content"
        );
    }
}

// --- Scenario 5: genuine shared-history exec-bit-only divergence ----------

/// The scenario the original SEC/convergence question was actually about,
/// closed here for the first time at this file's daemon-integration level.
///
/// Scenario 2 above is deliberately a create/create collision (two
/// independent DAG roots, never sharing history), which sidesteps rather
/// than answers the originally-intended question: a concurrent metadata-
/// only conflict on ONE file BOTH devices already share history on. This
/// scenario builds exactly that:
///
/// 1. Device A creates `shared.txt` (non-executable); device B receives it
///    over the wire -- a real, shared common-ancestor DAG version on both
///    devices, confirmed via [`dag_heads`] agreement before diverging.
/// 2. The pairing is genuinely severed (closing its link, via
///    [`two_synced_devices_with_link`] -- see its doc comment for why
///    not `JoinHandle::abort()`), so what follows cannot race delivery.
/// 3. Device A makes one real chmod (false -> true): one recorded DAG
///    version past the common ancestor.
/// 4. Device B makes two real, independently recorded chmods (false ->
///    true -> false): a genuine two-hop parallel branch past the SAME
///    common ancestor, confirmed via `indexed_unix_mode`/[`dag_heads`]
///    advancing between each step, not merely written to disk and assumed
///    captured.
/// 5. The two devices reconnect and must converge. Empirically confirmed
///    (this test's own repeated verification runs; see this arc's exit
///    report addendum) -- even though both branches' CONTENT is
///    byte-identical, this DAG conflict-resolution engine treats two
///    non-ancestor-related `FileVersion`s of the same path as a genuine
///    conflict, surfacing the SAME winner-plus-conflict-copy shape scenario
///    2 uses (reached via shared history here, not a create/create
///    collision), not a silent single-entry merge. That gives this scenario
///    the same multiset-style assertion scenario 2 uses: the winner and its
///    conflict copy must together carry exactly one `true` (device-a's
///    one-hop branch) and one `false` (device-b's two-hop branch) exec bit
///    -- not the fixed, deliberately winner-agnostic "both devices agree"
///    check alone, which a bug that collapses every materialized exec bit
///    to the same wrong value would still satisfy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end scenario read top to bottom: setup, divergence, reconnect, \
              then the multiset assertion described above"
)]
async fn shared_history_unix_mode_only_divergence_converges_after_reconnect() {
    #[cfg(not(unix))]
    {
        eprintln!(
            "skipping shared_history_unix_mode_only_divergence_converges_after_reconnect: \
             requires a POSIX owner-exec bit"
        );
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let (device_a, device_b, group_id, link) =
            two_synced_devices_with_link("exec-bit-shared-history-divergence").await;

        // Step 1: establish a real common ancestor -- device-a creates a
        // non-executable file, device-b receives it over the wire.
        let path_a = device_a.root.path().join("shared.txt");
        std::fs::write(&path_a, b"common content").unwrap();
        std::fs::set_permissions(&path_a, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path_b = device_b.root.path().join("shared.txt");
        wait_until_with_context(
            || std::fs::read(&path_b).ok() == Some(b"common content".to_vec()),
            Duration::from_secs(20),
            || format!("device-b entries: {:?}", real_entry_names(device_b.root.path())),
        )
        .await;
        wait_until_with_context(
            || {
                device_b
                    .state
                    .replica_coordinator
                    .file_index_repository()
                    .get_file(&group_id, "shared.txt")
                    .ok()
                    .flatten()
                    .is_some()
            },
            Duration::from_secs(20),
            || "device-b never indexed shared.txt at all before divergence".to_string(),
        )
        .await;
        assert!(
            !indexed_unix_mode(&device_a, &group_id, "shared.txt"),
            "device-a's own common-ancestor version must start non-executable"
        );
        assert!(
            !indexed_unix_mode(&device_b, &group_id, "shared.txt"),
            "device-b's own common-ancestor version must start non-executable"
        );

        let common_heads_a = dag_heads(&device_a, &group_id);
        let common_heads_b = dag_heads(&device_b, &group_id);
        assert_eq!(
            common_heads_a, common_heads_b,
            "both devices must agree on a single common DAG head before diverging -- \
             otherwise this isn't a genuine shared-history scenario"
        );

        // Step 2: genuinely sever the pairing before either device's
        // divergent edit, so the branches below are provably concurrent
        // rather than racing live wire delivery. Closing the link ends both
        // sides' sessions.
        link.close();
        // Changes converge over reconciliation, on its own connection, so
        // closing the link partitions only the block/service plane.
        // Without this the two devices keep converging right through the
        // "partition" and the divergence this test exists to create never
        // happens.
        support::sever_reconciliation(&device_a.state, &device_b.state).await;
        // A closed link still has to be observed by each session's task;
        // give them a moment to exit so no in-flight message from the moment
        // of the close is still being processed when the divergent edits
        // below start.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Step 3: device-a makes one real chmod (false -> true).
        std::fs::set_permissions(&path_a, std::fs::Permissions::from_mode(0o755)).unwrap();
        wait_until_with_context(
            || dag_heads(&device_a, &group_id) != common_heads_a,
            Duration::from_secs(20),
            || "device-a's chmod (false->true) was never captured into its own DAG".to_string(),
        )
        .await;
        assert!(
            indexed_unix_mode(&device_a, &group_id, "shared.txt"),
            "device-a's own file index must show shared.txt as executable after its chmod"
        );
        let heads_a_after = dag_heads(&device_a, &group_id);

        // Step 4: device-b makes two real, independently recorded chmods
        // (false -> true -> false), confirming each is captured before the
        // next is made.
        std::fs::set_permissions(&path_b, std::fs::Permissions::from_mode(0o755)).unwrap();
        wait_until_with_context(
            || dag_heads(&device_b, &group_id) != common_heads_b,
            Duration::from_secs(20),
            || {
                "device-b's first chmod (false->true) was never captured into its own DAG"
                    .to_string()
            },
        )
        .await;
        // Separates the four things that can be wrong here in one shot,
        // rather than asserting on the last of them and guessing backwards:
        // did the DAGs diverge as intended, do the two devices resolve the
        // path to the same version, and does each device's own index agree
        // with its own disk.
        let stage_dump = || {
            let idx = |d: &TestDevice| {
                d.state
                    .replica_coordinator
                    .file_index_repository()
                    .get_file(&group_id, "shared.txt")
                    .ok()
                    .flatten()
                    .map(|r| {
                        format!(
                            "present deleted={} mode={:?}",
                            r.deleted,
                            d.state
                                .replica_coordinator
                                .file_index_repository()
                                .get_unix_mode(&group_id, "shared.txt")
                                .ok()
                                .flatten()
                                .map(|m| format!("{m:o}"))
                        )
                    })
                    .unwrap_or_else(|| "<absent>".to_string())
            };
            let disk_mode = |d: &TestDevice| {
                std::fs::metadata(d.root.path().join("shared.txt"))
                    .map(|m| format!("{:o}", m.permissions().mode() & 0o777))
                    .unwrap_or_else(|e| format!("<{e}>"))
            };
            format!(
                "\n  common head        a={:?} b={:?}\
                 \n  heads now          a={:?} b={:?}\
                 \n  index              a=[{}] b=[{}]\
                 \n  disk mode          a={} b={}\
                 \n  entries            a={:?} b={:?}",
                common_heads_a.iter().map(|h| hex::encode(&h.0[..4])).collect::<Vec<_>>(),
                common_heads_b.iter().map(|h| hex::encode(&h.0[..4])).collect::<Vec<_>>(),
                dag_heads(&device_a, &group_id)
                    .iter()
                    .map(|h| hex::encode(&h.0[..4]))
                    .collect::<Vec<_>>(),
                dag_heads(&device_b, &group_id)
                    .iter()
                    .map(|h| hex::encode(&h.0[..4]))
                    .collect::<Vec<_>>(),
                idx(&device_a),
                idx(&device_b),
                disk_mode(&device_a),
                disk_mode(&device_b),
                real_entry_names(device_a.root.path()),
                real_entry_names(device_b.root.path()),
            )
        };
        // A head moving and the file index reflecting it are two separate
        // writes, so this waits rather than reading the instant the head
        // changed.
        wait_until_with_context(
            || indexed_unix_mode(&device_b, &group_id, "shared.txt"),
            Duration::from_secs(20),
            || {
                format!(
                    "device-b's own file index must show shared.txt as executable after its \
                     first chmod{}",
                    stage_dump()
                )
            },
        )
        .await;
        let heads_b_after_first = dag_heads(&device_b, &group_id);

        std::fs::set_permissions(&path_b, std::fs::Permissions::from_mode(0o644)).unwrap();
        wait_until_with_context(
            || dag_heads(&device_b, &group_id) != heads_b_after_first,
            Duration::from_secs(20),
            || {
                "device-b's second chmod (true->false) was never captured into its own DAG"
                    .to_string()
            },
        )
        .await;
        assert!(
            !indexed_unix_mode(&device_b, &group_id, "shared.txt"),
            "device-b's own file index must show shared.txt as non-executable after its second chmod"
        );
        let heads_b_after = dag_heads(&device_b, &group_id);

        // Proof of a genuine, non-trivial parallel divergence: device-a's
        // one-hop branch and device-b's two-hop branch are distinct DAG
        // tips, and neither collapsed back to the shared common ancestor.
        assert_ne!(heads_a_after, common_heads_a);
        assert_ne!(heads_b_after, common_heads_b);
        assert_ne!(
            heads_a_after, heads_b_after,
            "device-a's one-hop and device-b's two-hop branches must be genuinely distinct \
             DAG tips before reconnecting"
        );

        // Step 5: reconnect and wait for convergence.
        support::connect_two_daemons(
            &device_a.state,
            &device_a.device_id,
            &device_b.state,
            &device_b.device_id,
            std::slice::from_ref(&group_id),
        )
        .await;

        wait_until_with_context(
            || exec_snapshot(device_a.root.path()) == exec_snapshot(device_b.root.path()),
            Duration::from_secs(20),
            || {
                format!(
                    "device-a={:?} device-b={:?}",
                    exec_snapshot(device_a.root.path()),
                    exec_snapshot(device_b.root.path())
                )
            },
        )
        .await;

        // Even though both
        // branches' CONTENT is byte-identical, this DAG conflict-resolution
        // engine treats two non-ancestor-related `FileVersion`s of the same
        // path as a genuine conflict requiring a winner-plus-conflict-copy
        // pair, not a silent single-entry merge -- the same shape scenario 2
        // uses, just reached via shared history instead of a create/create
        // collision. Both devices must agree on this.
        let names_a = real_entry_names(device_a.root.path());
        // Which of the four stages this is, if it is any of them: did the
        // DAGs converge, did both sides keep two live content heads for the
        // path, and did the repair engine derive a conflict copy from them.
        let converged_dump = format!(
            "\n  heads              a={:?} b={:?}\
             \n  pre-merge tips     a={:?} b={:?}\
             \n  index mode         a={:?} b={:?}\
             \n  entries            a={:?} b={:?}",
            dag_heads(&device_a, &group_id)
                .iter()
                .map(|h| hex::encode(&h.0[..4]))
                .collect::<Vec<_>>(),
            dag_heads(&device_b, &group_id)
                .iter()
                .map(|h| hex::encode(&h.0[..4]))
                .collect::<Vec<_>>(),
            heads_a_after.iter().map(|h| hex::encode(&h.0[..4])).collect::<Vec<_>>(),
            heads_b_after.iter().map(|h| hex::encode(&h.0[..4])).collect::<Vec<_>>(),
            device_a
                .state
                .replica_coordinator
                .file_index_repository()
                .get_unix_mode(&group_id, "shared.txt")
                .ok()
                .flatten()
                .map(|m| format!("{m:o}")),
            device_b
                .state
                .replica_coordinator
                .file_index_repository()
                .get_unix_mode(&group_id, "shared.txt")
                .ok()
                .flatten()
                .map(|m| format!("{m:o}")),
            names_a,
            real_entry_names(device_b.root.path()),
        );
        assert_eq!(
            names_a.iter().filter(|n| is_conflict_copy(n)).count(),
            1,
            "a genuine metadata-only conflict on shared history must surface exactly one \
             conflict-copy artifact alongside the winner: {names_a:?}{converged_dump}"
        );
        assert!(names_a.contains(&"shared.txt".to_string()), "{names_a:?}");
        assert_eq!(names_a.len(), 2, "{names_a:?}");

        let snapshot_a = exec_snapshot(device_a.root.path());
        let snapshot_b = exec_snapshot(device_b.root.path());
        assert_eq!(
            snapshot_a, snapshot_b,
            "both devices must agree on every entry's content AND exec bit after convergence: \
             device-a={snapshot_a:?} device-b={snapshot_b:?}"
        );
        for (name, (content, _exec)) in &snapshot_a {
            assert_eq!(
                content, "common content",
                "{name}: {snapshot_a:?} (content must be \
                unaffected by this purely metadata conflict)"
            );
        }

        // The specific claim this scenario exists to catch, same as
        // scenario 2's multiset check: device-a's one-hop branch (true) and
        // device-b's two-hop branch (false) must BOTH survive resolution,
        // one as the winner and one as the conflict copy -- not collapse to
        // a single shared (possibly wrong) value. A bug that silently
        // forces every materialized exec bit to `false` would leave this
        // multiset `[false, false]`, not `[false, true]`.
        let mut unix_modes: Vec<bool> = snapshot_a.values().map(|(_content, exec)| *exec).collect();
        unix_modes.sort();
        assert_eq!(
            unix_modes,
            vec![false, true],
            "the winner (shared.txt) and its conflict copy must together carry exactly one \
             true (device-a's one-hop branch) and one false (device-b's two-hop branch) exec \
             bit -- neither original value may be lost or collapsed to a shared wrong value: \
             {snapshot_a:?}"
        );
    }
}
