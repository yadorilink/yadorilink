//! This file instead exercises what actually happens end-to-end when two
//! real devices race to create a hazardous name over the real
//! watcher/local-capture/peer-session/signing pipeline. **Current
//! understanding, read directly out of the source (this corrects an
//! earlier version of this file's header, which described the OPPOSITE of
//! scenarios 1-3's actual mechanism — the two must not be left
//! contradicting each other in one file):** - Scenarios 1-3 below
//! (`concurrent_create_of_a_windows_reserved_ basename`,
//! `concurrent_create_with_trailing_dot_or_space`,
//! `concurrent_create_with_illegal_windows_characters`) all trip
//! `yadorilink_fs_platform::reserved_namespace::path_has_non_
//! portable_wire_component`, invoked via `yadorilink_sync_sqlite::
//! dag_store::serving_authorization_index::validate_no_reserved_paths`.
//! Per that function's own doc comment, this check is **platform-independent** (never gated on
//! `cfg!(windows)`) and runs on **both** the receiving side
//! (`admit_change`) and the local-authoring side (`emit_local_change` and
//! its own callers). So a hazardous name is refused DAG admission the
//! moment each device tries to capture its OWN local write — before there
//! is ever a change to send to a peer, let alone materialize or hold. Each
//! device keeps only its own local content forever; neither ever learns
//! the other created the same (or a different) hazardous name at all. This
//! is a permanent, by-design refusal, not a timing gap, and it applies
//! identically on every platform — there is no "Windows device" vs.
//! "non-Windows device" distinction for this check at all, unlike scenario
//! 4 below. - `PeerSyncSession::hazard_reason_for` (host-gated on
//! `hazard::NamePolicy::local`, evaluated only inside `materialize`/
//! `hydrate_file` when a device is about to write a RECEIVED record to
//! disk) is a SEPARATE, materialize-time mechanism this file's scenarios
//! 1-3 do NOT exercise at all: `validate_no_reserved_paths` rejects these
//! hazardous names at DAG admission, before any of them could ever reach a
//! receiving device's `materialize` call. Since both simulated devices in
//! this file share one OS process, there is also no way, within one test
//! run, to have one simulated device be "the Windows one" for that
//! host-gated mechanism regardless — `cfg!(windows)` would branch per
//! test-run, not per device. - Scenario 4
//! (`long_path_near_windows_max_path_length`) is a genuinely different,
//! unrelated code path: Windows' `MAX_PATH` is an OS/Win32-API constraint
//! with nothing to do with `hazard.rs`'s or `reserved_ namespace`'s logic.
//! Both devices' creates ARE admitted and materialized normally here (a
//! real create/create conflict-copy scenario, same shape as
//! `collision_matrix.rs`'s scenario 1) — this scenario's own doc comment
//! covers its own ground truth separately.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{
    open_file_backed_replica_coordinator, real_entry_names, wait_until_with_context, TestAccount,
};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;

// --- Shared two-device harness (duplicated from collision_matrix.rs, matching
// this codebase's convention of self-contained daemon integration test
// binaries rather than sharing across `tests/*.rs`) ---------------------------

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
    // Give the device a change-signing key before its link watch starts (see
    // `start_watching`), so the change-DAG emitter is wired from the first edit
    // and local changes actually propagate — a key set afterward would leave
    // emission off and nothing would sync.
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

async fn two_synced_devices(test_name: &str) -> (TestDevice, TestDevice, String) {
    // Installs a process-global subscriber whose filter comes from
    // `RUST_LOG` -- this workspace enables tracing-subscriber's `env-filter`
    // feature, so with `RUST_LOG` unset nothing below ERROR is emitted
    // (measured: zero INFO/WARN/DEBUG lines). Not "inert": the subscriber is
    // still installed, and whichever test in this binary calls `try_init`
    // first wins for the whole process.
    //
    // Worth having because every
    // scenario here asserts on what did NOT arrive, so a failure surfaces
    // only as a 15s `wait_until` timeout with no indication of which stage
    // dropped it. The daemon already logs the answer -- local capture warns
    // with the exact path and refusal reason when a batched commit fails --
    // but with no subscriber installed in this binary that line goes
    // nowhere, turning a one-line diagnosis into a blind hunt.
    let _ = tracing_subscriber::fmt::try_init();
    let coordination_addr = support::start_coordination_server().await;
    let account =
        support::register_and_login(&coordination_addr, &format!("{test_name}@example.com")).await;

    let device_a = setup_device(&account, "device-a").await;
    let device_b = setup_device(&account, "device-b").await;
    let group_id = support::create_folder_group(&account, "windows-path-hazard-group").await;
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

fn is_conflict_copy(name: &str) -> bool {
    name.contains("conflicted copy")
}

/// Creates an ordinary, non-hazardous file on `writer` and waits for it to
/// propagate to `reader` -- proof that the watcher, local-capture, peer
/// session, and signing are all genuinely live for this pairing, not merely
/// that "nothing arrived" (which would be trivially true if the whole
/// pipeline were dead). Every scenario below that expects a hazardous name
/// to be permanently, silently refused calls this alongside its hazardous
/// write, so a failure to observe non-propagation is distinguishable from a
/// pipeline that simply never ran.
async fn prove_pipeline_is_live_with_a_sentinel_file(
    writer: &TestDevice,
    reader: &TestDevice,
    sentinel_name: &str,
) {
    let content = format!("sentinel content proving the pipeline is live: {sentinel_name}");
    std::fs::write(writer.root.path().join(sentinel_name), content.as_bytes()).unwrap();
    wait_until_with_context(
        || {
            std::fs::read(reader.root.path().join(sentinel_name)).ok().as_deref()
                == Some(content.as_bytes())
        },
        Duration::from_secs(15),
        || {
            format!(
                "sentinel file {sentinel_name:?} never propagated -- the watcher/local-capture/\
                 peer-session/signing pipeline itself may not be live, which would make any \
                 \"the hazardous name never arrived\" observation elsewhere in this test \
                 meaningless: reader entries={:?}",
                real_entry_names(reader.root.path())
            )
        },
    )
    .await;
}

/// Whether `device`'s own local file index/DAG ever admitted `path` for
/// `group_id` -- the direct, non-flaky way to check "this path never
/// entered the local index or DAG," rather than inferring it from an
/// absence on the OTHER device (which conflates "never admitted locally"
/// with "admitted locally but never delivered/received").
fn admitted_to_local_index(device: &TestDevice, group_id: &str, path: &str) -> bool {
    device
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(group_id, path)
        .unwrap()
        .is_some()
}

/// A directory's real (non-artifact) entries as a name→content map — plain
/// text content (not a hash) so a failure's assertion message stays directly
/// readable. Used for convergence waits so equality means both devices agree
/// on names *and* the bytes under each name, not merely on the name set — a
/// bare name-set-equality wait is satisfied the instant two devices happen to
/// list the same filenames, which can be true transiently before content has
/// actually propagated and been materialized under those names.
fn snapshot(dir: &std::path::Path) -> std::collections::HashMap<String, String> {
    real_entry_names(dir)
        .into_iter()
        .map(|name| {
            let content = std::fs::read_to_string(dir.join(&name)).unwrap_or_default();
            (name, content)
        })
        .collect()
}

/// A capability probe for a candidate filename this test wants to create on
/// the *current* host filesystem — some of the names below (a literal `:`,
/// trailing space/dot) are only guaranteed valid on POSIX filesystems, and
/// even there a given mount could reject or silently normalize them. Rather
/// than let `std::fs::write` panic the test for a reason that has nothing to
/// do with the sync engine, probe first in a scratch tempdir, and skip
/// (mirroring `collision_matrix.rs`'s `is_case_insensitive_filesystem`-gated
/// case-fold test) if this host can't literally represent the name.
fn host_supports_literal_filename(name: &str) -> bool {
    let probe_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let path = probe_dir.path().join(name);
    if std::fs::write(&path, b"probe").is_err() {
        return false;
    }
    // Confirm the name round-trips exactly rather than being silently
    // normalized (e.g. a trailing dot/space stripped at write time) by some
    // filesystem or OS layer unrelated to this crate's own hazard logic.
    let preserved = real_entry_names(probe_dir.path()).contains(&name.to_string());
    let _ = std::fs::remove_file(&path);
    preserved
}

// --- Scenario 1: concurrent create of a Windows-reserved device basename ----

/// Both devices concurrently create a file named `CON.txt` — a Windows-
/// reserved device basename.
///
/// **Corrected from this file's original premise** (see the module header's
/// "ground truth" list): that list only accounted for `hazard_reason_for`'s
/// MATERIALIZE-time, host-gated (`NamePolicy::local`) hold. There is a
/// SEPARATE, always-on, platform-INDEPENDENT check that runs first and
/// supersedes it for this exact hazard shape: `yadorilink_root_authority::
/// reserved_namespace::path_has_non_portable_wire_component` (via
/// `yadorilink_sync_sqlite::dag_store::serving_authorization_index::
/// validate_no_reserved_paths`) flags any path whose basename is a Windows
/// reserved device name (`is_windows_reserved_device_name` — `"CON"` among
/// them, matched on the stem before the first `.`, so `"CON.txt"`
/// qualifies), and — per `dag_store::emit_local_change`'s own doc
/// comment — this check runs on BOTH the
/// receiving side (`admit_change`) AND the local-authoring side
/// (`emit_local_change`), on every platform, not gated on `cfg!(windows)`
/// at all. So `CON.txt` is refused a DAG admission at the moment each
/// device tries to CAPTURE its own local write, before there is ever a
/// change to send to a peer, let alone materialize/hold. Confirmed by
/// direct observation on this (non-Windows) host: instrumented polling
/// showed each device keeps only its own local content forever, with
/// neither ever learning the other created the same name at all — not a
/// timing gap, a permanent, by-design refusal. Since the admission check
/// is host-independent by its own doc's explicit design goal ("every peer
/// in a group ... must reach the identical verdict for the identical wire
/// path"), the SAME refusal applies on a genuine Windows host too — the
/// `hazard_reason_for`/`held` mechanism this test originally exercised is
/// simply unreachable for this input on any platform, since the admission
/// check throws first. This still needs live re-verification on a real
/// Windows machine (nothing here runs one), but it is the correct
/// prediction from what the source actually does, not a guess -- same
/// caveat as `long_path_near_windows_max_path_length`'s own doc comment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_of_a_windows_reserved_basename() {
    let (device_a, device_b, group_id) =
        two_synced_devices("windows-hazard-reserved-basename").await;

    std::fs::write(device_a.root.path().join("CON.txt"), b"from A").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
    std::fs::write(device_b.root.path().join("CON.txt"), b"from B, different and longer").unwrap();

    // Proves the pipeline is genuinely alive (watcher/local-capture/peer-
    // session/signing all ran for real) before trusting the "CON.txt never
    // arrived" observation below -- otherwise that observation would be
    // trivially true even if nothing ran at all. Also doubles as the wait
    // itself: a same-content, cross-device round trip is strictly slower
    // than a single device's own local DAG-admission attempt, so once this
    // returns, CON.txt's own (much faster, purely local) admission attempt
    // has certainly already been made and refused, if it was ever going to
    // succeed at all.
    prove_pipeline_is_live_with_a_sentinel_file(
        &device_a,
        &device_b,
        "sentinel-reserved-basename-a-to-b.txt",
    )
    .await;
    prove_pipeline_is_live_with_a_sentinel_file(
        &device_b,
        &device_a,
        "sentinel-reserved-basename-b-to-a.txt",
    )
    .await;

    // Both devices keep their OWN local `CON.txt` -- never admitted to the
    // DAG, so never overwritten by a peer's version either. The name being
    // present on both sides is expected; what proves non-propagation is
    // that each side's CONTENT is still exactly, only, what that device
    // itself wrote (never the other device's bytes).
    let names_a = real_entry_names(device_a.root.path());
    let names_b = real_entry_names(device_b.root.path());
    assert!(names_a.contains(&"CON.txt".to_string()), "{names_a:?}");
    assert!(names_b.contains(&"CON.txt".to_string()), "{names_b:?}");
    assert_eq!(std::fs::read(device_a.root.path().join("CON.txt")).unwrap(), b"from A");
    assert_eq!(
        std::fs::read(device_b.root.path().join("CON.txt")).unwrap(),
        b"from B, different and longer"
    );

    // Not just "never appeared on the other device" (which the filesystem
    // assertions above already cover) -- directly confirm the hazardous
    // path never entered either device's own local file index/DAG at all
    // (the repository-level observation).
    assert!(
        !admitted_to_local_index(&device_a, &group_id, "CON.txt"),
        "CON.txt must never have been admitted to device-a's own local index/DAG"
    );
    assert!(
        !admitted_to_local_index(&device_b, &group_id, "CON.txt"),
        "CON.txt must never have been admitted to device-b's own local index/DAG"
    );
}

// --- Scenario 2: concurrent create of trailing-dot vs. trailing-space names -

/// One device creates `notes.txt.` (trailing dot), the other creates
/// `notes.txt ` (trailing space) — two hazardous name variants on Windows.
/// Since the two strings are literally different, `hazard::
/// case_fold_collision` (which only ever compares same-directory siblings
/// that fold to the same lowercase name) never even considers them related
/// to one another — this is not a collision at any layer except each name's
/// own individual Windows-invalid-name check.
///
/// **Corrected from this file's original premise**, same root cause and
/// same fix rationale as `concurrent_create_of_a_windows_reserved_
/// basename`'s own doc comment: `path_has_non_portable_wire_component`
/// treats a name a Windows peer's own trailing-dot/space normalization
/// would silently alter (`strip_windows_trailing_normalization(component)
/// != component`, true for both `"notes.txt."` and `"notes.txt "`) as
/// non-portable, checked at DAG admission on both the receiving AND the
/// local-authoring side, on every platform — so neither device's own write
/// is ever admitted to the DAG at all, on either platform. Each device
/// keeps only its own local file, forever; the two are never even offered
/// to each other, let alone held or hazard-checked on receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_with_trailing_dot_or_space() {
    if !host_supports_literal_filename("probe.txt.")
        || !host_supports_literal_filename("probe.txt ")
    {
        eprintln!(
            "skipping: this host filesystem can't literally represent a trailing-dot or \
             trailing-space filename"
        );
        return;
    }

    let (device_a, device_b, group_id) =
        two_synced_devices("windows-hazard-trailing-dot-space").await;

    std::fs::write(device_a.root.path().join("notes.txt."), b"trailing dot from A").unwrap();
    std::fs::write(device_b.root.path().join("notes.txt "), b"trailing space from B").unwrap();

    // Proves the pipeline is genuinely alive before trusting the
    // non-propagation observation below -- see scenario 1's doc comment for
    // why this matters and why it also serves as the wait itself.
    prove_pipeline_is_live_with_a_sentinel_file(
        &device_a,
        &device_b,
        "sentinel-trailing-dot-space-a-to-b.txt",
    )
    .await;
    prove_pipeline_is_live_with_a_sentinel_file(
        &device_b,
        &device_a,
        "sentinel-trailing-dot-space-b-to-a.txt",
    )
    .await;

    let a_names = real_entry_names(device_a.root.path());
    let b_names = real_entry_names(device_b.root.path());
    assert!(
        a_names.contains(&"notes.txt.".to_string()) && !b_names.contains(&"notes.txt.".to_string()),
        "device-a's own trailing-dot write must stay exactly as this device wrote it, and must \
         never reach device-b: device-a={a_names:?} device-b={b_names:?}"
    );
    assert!(
        b_names.contains(&"notes.txt ".to_string()) && !a_names.contains(&"notes.txt ".to_string()),
        "device-b's own trailing-space write must stay exactly as this device wrote it, and must \
         never reach device-a: device-a={a_names:?} device-b={b_names:?}"
    );
    assert_eq!(
        std::fs::read(device_a.root.path().join("notes.txt.")).unwrap(),
        b"trailing dot from A"
    );
    assert_eq!(
        std::fs::read(device_b.root.path().join("notes.txt ")).unwrap(),
        b"trailing space from B"
    );

    // Directly confirm neither hazardous path ever entered either device's
    // own local file index/DAG, not just "never appeared on the other
    // device."
    assert!(
        !admitted_to_local_index(&device_a, &group_id, "notes.txt."),
        "notes.txt. must never have been admitted to device-a's own local index/DAG"
    );
    assert!(
        !admitted_to_local_index(&device_b, &group_id, "notes.txt "),
        "notes.txt  (trailing space) must never have been admitted to device-b's own local \
         index/DAG"
    );
}

// --- Scenario 3: concurrent create with Windows-illegal characters ---------

/// Both devices create files whose names contain characters illegal on
/// Windows (`<>:"|?*`) at two distinct, non-colliding names. Same shape as
/// scenario 2 (two independent hazardous-elsewhere names, not a collision
/// with each other) but exercising `path_has_non_portable_wire_component`'s
/// forbidden-character/colon branch rather than its trailing-dot/space
/// branch — both are DAG-admission-time checks, per the module header; this
/// scenario does NOT exercise `windows_invalid_name_detail` (a
/// materialize-time branch this file's scenarios no longer reach for any
/// of these hazard shapes, corrected from an earlier version of this
/// comment).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_create_with_illegal_windows_characters() {
    let name_a = "report:v2.txt";
    let name_b = "report<final>.txt";
    if !host_supports_literal_filename(name_a) || !host_supports_literal_filename(name_b) {
        eprintln!(
            "skipping: this host filesystem can't literally represent a filename containing \
             one of Windows' forbidden characters"
        );
        return;
    }

    let (device_a, device_b, group_id) =
        two_synced_devices("windows-hazard-illegal-characters").await;

    std::fs::write(device_a.root.path().join(name_a), b"colon name from A").unwrap();
    std::fs::write(device_b.root.path().join(name_b), b"angle bracket name from B").unwrap();

    // Proves the pipeline is genuinely alive before trusting the
    // non-propagation observation below -- both `:` and `< >` are in
    // `wire_component_is_non_portable`'s `WINDOWS_RESERVED_FILENAME_CHARS`/
    // colon check, so neither device's own write is ever admitted to the
    // DAG at all, on either platform -- same root cause and fix rationale
    // as `concurrent_create_of_a_windows_reserved_basename`'s own doc
    // comment. See that scenario's doc comment for why the sentinel also
    // serves as the wait itself.
    prove_pipeline_is_live_with_a_sentinel_file(
        &device_a,
        &device_b,
        "sentinel-illegal-characters-a-to-b.txt",
    )
    .await;
    prove_pipeline_is_live_with_a_sentinel_file(
        &device_b,
        &device_a,
        "sentinel-illegal-characters-b-to-a.txt",
    )
    .await;

    let a_names = real_entry_names(device_a.root.path());
    let b_names = real_entry_names(device_b.root.path());
    assert!(
        a_names.contains(&name_a.to_string()) && !b_names.contains(&name_a.to_string()),
        "device-a's own illegal-character write must stay exactly as this device wrote it, and \
         must never reach device-b: device-a={a_names:?} device-b={b_names:?}"
    );
    assert!(
        b_names.contains(&name_b.to_string()) && !a_names.contains(&name_b.to_string()),
        "device-b's own illegal-character write must stay exactly as this device wrote it, and \
         must never reach device-a: device-a={a_names:?} device-b={b_names:?}"
    );
    assert_eq!(std::fs::read(device_a.root.path().join(name_a)).unwrap(), b"colon name from A");
    assert_eq!(
        std::fs::read(device_b.root.path().join(name_b)).unwrap(),
        b"angle bracket name from B"
    );

    // Directly confirm neither hazardous path ever entered either device's
    // own local file index/DAG, not just "never appeared on the other
    // device."
    assert!(
        !admitted_to_local_index(&device_a, &group_id, name_a),
        "{name_a:?} must never have been admitted to device-a's own local index/DAG"
    );
    assert!(
        !admitted_to_local_index(&device_b, &group_id, name_b),
        "{name_b:?} must never have been admitted to device-b's own local index/DAG"
    );
}

// --- Scenario 4: a full path near Windows' traditional MAX_PATH (260) ------

/// Builds a relative path (nested directories plus a filename) long enough
/// that the *full* path -- including the temp sync root -- comfortably
/// exceeds Windows' traditional 260-character `MAX_PATH` (without
/// `\\?\`-prefix long-path support). Both devices create it concurrently
/// with different content, same shape as `collision_matrix.rs` scenario 1,
/// checked directly at the deep path rather than via a root-level directory
/// listing (`real_entry_names` only lists one directory's immediate
/// entries).
///
/// This specifically needs re-verification on the real Windows test machine
/// from manual Windows VM testing: `MAX_PATH` is an OS/Win32-API-level
/// constraint that has nothing to do with this crate's own `hazard.rs`
/// logic, so nothing read while writing this file rules out a real failure
/// there (e.g. `CreateFileW` rejecting the path outright, or requiring the
/// `\\?\` long-path prefix this codebase's materialization writes don't
/// appear to add). On the current platform this is expected to simply work,
/// since Linux/macOS impose no such component-count-independent path-length
/// ceiling in the range this test builds.
const LONG_PATH_SEGMENT: &str =
    "a-fairly-long-directory-name-segment-used-only-to-pad-the-full-path";
const LONG_PATH_FILE: &str = "deep-file-near-the-windows-max-path-length-threshold.txt";

/// Two synced devices and the directory, past `MAX_PATH`, both create the file
/// under; `None` when this host rejects such a path during setup.
async fn long_path_devices(
    name: &str,
) -> Option<(TestDevice, TestDevice, std::path::PathBuf, std::path::PathBuf)> {
    const MIN_TOTAL_LEN: usize = 300; // comfortably over the 260 MAX_PATH threshold
    let rel_dir = deeply_nested_relative_dir(LONG_PATH_SEGMENT, MIN_TOTAL_LEN);
    let (device_a, device_b, _group_id) = two_synced_devices(name).await;
    let dir_a = device_a.root.path().join(&rel_dir);
    let dir_b = device_b.root.path().join(&rel_dir);
    let full_len_a = dir_a.join(LONG_PATH_FILE).to_string_lossy().len();
    assert!(full_len_a > 260, "test setup bug: path isn't actually long ({full_len_a} chars)");
    if std::fs::create_dir_all(&dir_a).is_err() || std::fs::create_dir_all(&dir_b).is_err() {
        eprintln!(
            "skipping: this host filesystem/path-length limit rejected a {full_len_a}-char path \
             during test setup, unrelated to the sync engine itself"
        );
        return None;
    }
    Some((device_a, device_b, dir_a, dir_b))
}

/// A file made alone under a path past `MAX_PATH` reaches the other device,
/// byte for byte: long-path support, on every platform and gate state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_under_a_path_past_max_path_length_reaches_the_other_device() {
    let Some((_device_a, _device_b, dir_a, dir_b)) = long_path_devices("windows-long-path").await
    else {
        return;
    };
    std::fs::write(dir_a.join(LONG_PATH_FILE), b"from A, deep path").unwrap();
    wait_until_with_context(
        || std::fs::read(dir_b.join(LONG_PATH_FILE)).ok().as_deref() == Some(b"from A, deep path"),
        Duration::from_secs(30),
        || format!("device-b deep dir={:?}", real_entry_names(&dir_b)),
    )
    .await;
    assert_eq!(real_entry_names(&dir_b), vec![LONG_PATH_FILE.to_string()]);
}

/// Both devices writing the same file under a path past `MAX_PATH` converge
/// on a winner and one conflict copy, with the same bytes on both: needs the
/// winner to replace the loser's original, which the closed Windows gate
/// withholds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_under_a_path_past_max_path_length_converge_on_a_winner_and_a_copy() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "conflict convergence requires durable namespace replacement",
    ) {
        return;
    }
    let Some((_device_a, _device_b, dir_a, dir_b)) =
        long_path_devices("windows-hazard-long-path").await
    else {
        return;
    };
    std::fs::write(dir_a.join(LONG_PATH_FILE), b"from A, deep path").unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await; // distinguishable mtime ordering
    std::fs::write(dir_b.join(LONG_PATH_FILE), b"from B, deep path, different and longer").unwrap();

    // Full name->content convergence at the deep directory: both devices must
    // agree on the bytes under every entry (including the conflict copy), not
    // merely on the name set.
    wait_until_with_context(
        || {
            let a = snapshot(&dir_a);
            let b = snapshot(&dir_b);
            a == b && a.keys().any(|n| is_conflict_copy(n))
        },
        Duration::from_secs(20),
        || {
            format!(
                "device-a deep dir={:?} device-b deep dir={:?}",
                real_entry_names(&dir_a),
                real_entry_names(&dir_b)
            )
        },
    )
    .await;

    let names = real_entry_names(&dir_a);
    assert!(names.contains(&LONG_PATH_FILE.to_string()), "{names:?}");
    assert_eq!(names.iter().filter(|n| is_conflict_copy(n)).count(), 1, "{names:?}");
}

/// Nests copies of `segment` under one another until the *relative* path
/// (not yet joined to any sync root) alone would push a `root.join(rel).
/// join(file)` well past `min_total_len` even for a short temp-root prefix
/// -- deliberately generous rather than computed against either device's
/// actual root length, so the same nesting applies identically to both
/// devices' sync roots regardless of their exact (similar, but not
/// guaranteed byte-identical) tempdir path lengths.
fn deeply_nested_relative_dir(segment: &str, min_total_len: usize) -> std::path::PathBuf {
    let mut rel = std::path::PathBuf::new();
    while rel.as_os_str().len() < min_total_len {
        rel.push(segment);
    }
    rel
}
