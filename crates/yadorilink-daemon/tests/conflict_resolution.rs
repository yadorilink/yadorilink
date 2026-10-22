//! Resolving a conflict copy through the daemon, end to end: real watcher
//! capture, the real control socket, real peers. The daemon decides and
//! performs Keep this / Keep both at the moment the request runs, so what a
//! list showed earlier can never make it destroy bytes nothing recorded.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::control_socket_client::{self, ControlSocketHandle};
use support::{open_file_backed_replica_coordinator, real_entry_names, wait_until_with_context};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::resolve_conflict_response::Result as Outcome;
use yadorilink_ipc_proto::daemonctl::{
    ApplicationErrorCode, ConflictResolution, ListConflictsRequest, ResolveConflictRequest,
};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::VersionState;

const COPY: &str = "plan (conflicted copy, 2026-01-01-000000, device-b).txt";

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    store_dir: tempfile::TempDir,
    index_dir: tempfile::TempDir,
}

fn open_state(
    device_id: &str,
    store_dir: &std::path::Path,
    index_db: &std::path::Path,
) -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(store_dir).unwrap());
    let coordinator =
        yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open(index_db).unwrap();
    let state = DaemonState::new(device_id.to_string(), Arc::new(coordinator), store);
    support::ensure_device_signing_key(&state);
    state
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
        store_dir,
        index_dir,
    }
}

fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    let links = device.state.replica_coordinator.link_repository();
    if !links.list_links().unwrap().iter().any(|link| link.group_id == group_id) {
        links.add_link(&local_path, group_id).unwrap();
    }
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

fn current(device: &TestDevice, group_id: &str, path: &str) -> Option<(i64, u64)> {
    device
        .state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group_id, path)
        .unwrap_or_default()
        .iter()
        .find(|v| v.state == VersionState::Current && !v.deleted)
        .map(|v| (v.version_seq, v.size))
}

async fn wait_captured(device: &TestDevice, group_id: &str, path: &str, size: u64) {
    wait_until_with_context(
        || current(device, group_id, path).is_some_and(|(_, s)| s == size),
        Duration::from_secs(30),
        || format!("{path} never captured at size {size}: {:?}", current(device, group_id, path)),
    )
    .await;
}

/// Waits until capture has recorded everything on disk at `path`: the current
/// version has the disk's size, mode and replicated xattrs, and the path is
/// no longer in the dirty journal. Content size alone says nothing about a
/// chmod/xattr change or a write made after it.
async fn wait_recorded(device: &TestDevice, group_id: &str, path: &str) {
    let recorded = || {
        let dirty = device
            .state
            .replica_coordinator
            .dirty_path_repository()
            .is_path_dirty(group_id, path)
            .unwrap_or(true);
        let Ok(file) = std::fs::File::open(device.root.path().join(path)) else { return false };
        let Ok(meta) = file.metadata() else { return false };
        let Some(version) = device
            .state
            .replica_coordinator
            .sqlite()
            .dag_list_versions(group_id, path)
            .unwrap_or_default()
            .into_iter()
            .find(|v| v.state == VersionState::Current && !v.deleted)
        else {
            return false;
        };
        !dirty
            && version.size == meta.len()
            && version.unix_mode == yadorilink_local_storage::unix_mode_from_metadata(&meta)
            && version.xattrs == yadorilink_local_storage::read_replicated_xattrs(&file)
    };
    wait_until_with_context(recorded, Duration::from_secs(30), || {
        format!("{path} never fully recorded: {:?}", current(device, group_id, path))
    })
    .await;
}

fn read(device: &TestDevice, path: &str) -> String {
    std::fs::read_to_string(device.root.path().join(path)).unwrap_or_default()
}

/// One device with `plan.txt` ("mine") and a conflict copy of it ("theirs!"),
/// both captured, and a control socket to drive it.
async fn device_with_conflict(group_id: &str) -> (TestDevice, ControlSocketHandle) {
    support::ensure_isolated_config_dir();
    let a = setup_device("device-a");
    support::install_bootstrap_policy(&a.state, &[group_id.to_string()]);
    start_watching(&a, group_id);
    std::fs::write(a.root.path().join("plan.txt"), "mine").unwrap();
    std::fs::write(a.root.path().join(COPY), "theirs!").unwrap();
    wait_captured(&a, group_id, "plan.txt", 4).await;
    wait_captured(&a, group_id, COPY, 7).await;
    let socket = control_socket_client::start(a.state.clone()).await;
    (a, socket)
}

async fn resolve(
    socket: &ControlSocketHandle,
    device: &TestDevice,
    copy: &str,
    resolution: ConflictResolution,
) -> Outcome {
    let resp = control_socket_client::send(
        socket,
        ReqPayload::ResolveConflict(ResolveConflictRequest {
            copy_path: device.root.path().join(copy).to_string_lossy().into_owned(),
            resolution: resolution as i32,
        }),
    )
    .await;
    let Some(RespPayload::ResolveConflict(resp)) = resp.payload else {
        panic!("wrong response variant: {resp:?}")
    };
    resp.result.expect("a result")
}

fn refusal_code(outcome: &Outcome) -> ApplicationErrorCode {
    match outcome {
        Outcome::Error(error) => ApplicationErrorCode::try_from(error.code).unwrap(),
        Outcome::KeptPath(path) => panic!("expected a refusal, got {path}"),
    }
}

/// The list is read before the action. An edit to the original made after
/// it, which capture has not taken, is in no version: Keep this refuses with
/// a typed reason and both files stay exactly as they are.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keep_this_refuses_while_the_original_has_an_unrecorded_edit() {
    let group_id = "conflict-unrecorded-original";
    let (a, socket) = device_with_conflict(group_id).await;
    let resp =
        control_socket_client::send(&socket, ReqPayload::ListConflicts(ListConflictsRequest {}))
            .await;
    let Some(RespPayload::ListConflicts(list)) = resp.payload else { panic!("{resp:?}") };
    assert!(
        list.files
            .iter()
            .any(|f| f.path == COPY && f.resolvable && f.origin_device_id == "device-a"),
        "{list:?}"
    );

    // Capture of the original is held, so the edit stays unrecorded however
    // long the request takes.
    a.state.replica_coordinator.paused_item_repository().pause(group_id, "plan.txt").unwrap();
    std::fs::write(a.root.path().join("plan.txt"), "edited after the listing").unwrap();

    let outcome = resolve(&socket, &a, COPY, ConflictResolution::KeepThis).await;

    assert_eq!(refusal_code(&outcome), ApplicationErrorCode::UnrecordedLocalChanges);
    assert_eq!(read(&a, "plan.txt"), "edited after the listing");
    assert_eq!(read(&a, COPY), "theirs!");
}

/// The copy's recorded content is what Keep this writes, so an edit to the
/// copy that capture has not taken would be removed with it: refused too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keep_this_refuses_while_the_copy_has_an_unrecorded_edit() {
    let group_id = "conflict-unrecorded-copy";
    let (a, socket) = device_with_conflict(group_id).await;
    a.state.replica_coordinator.paused_item_repository().pause(group_id, COPY).unwrap();
    std::fs::write(a.root.path().join(COPY), "copy edited after the listing").unwrap();

    let outcome = resolve(&socket, &a, COPY, ConflictResolution::KeepThis).await;

    assert_eq!(refusal_code(&outcome), ApplicationErrorCode::UnrecordedLocalChanges);
    assert_eq!(read(&a, "plan.txt"), "mine");
    assert_eq!(read(&a, COPY), "copy edited after the listing");
}

/// No file with a reserved (discard) name is on disk.
fn assert_no_reserved_names(device: &TestDevice) {
    let names = real_entry_names(device.root.path());
    assert!(
        names.iter().all(|name| !name.starts_with(".yadorilink-v1-discard")),
        "a reserved-name file exists: {names:?}"
    );
    let all: Vec<_> = std::fs::read_dir(device.root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(all.iter().all(|name| !name.contains("v1-discard")), "{all:?}");
}

async fn listed_copies(socket: &ControlSocketHandle) -> Vec<(String, bool)> {
    let resp =
        control_socket_client::send(socket, ReqPayload::ListConflicts(ListConflictsRequest {}))
            .await;
    let Some(RespPayload::ListConflicts(list)) = resp.payload else { panic!("{resp:?}") };
    list.files.iter().map(|f| (f.path.clone(), f.resolvable)).collect()
}

/// Keep this: the copy's content takes the original name, the copy stays
/// untouched under its own name, and the replaced version stays in the file's
/// history, restorable from this device alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keep_this_replaces_the_original_and_leaves_the_copy_alone() {
    let group_id = "conflict-keep-this";
    let (a, socket) = device_with_conflict(group_id).await;
    let (replaced_seq, _) = current(&a, group_id, "plan.txt").unwrap();
    wait_recorded(&a, group_id, "plan.txt").await;
    wait_recorded(&a, group_id, COPY).await;

    let outcome = resolve(&socket, &a, COPY, ConflictResolution::KeepThis).await;

    let Outcome::KeptPath(kept) = outcome else { panic!("{outcome:?}") };
    assert_eq!(std::path::Path::new(&kept), a.root.path().join("plan.txt"));
    assert_eq!(read(&a, "plan.txt"), "theirs!");
    assert_eq!(read(&a, COPY), "theirs!");
    assert_no_reserved_names(&a);
    // Restoring refuses while the write Keep this just made is uncaptured.
    wait_recorded(&a, group_id, "plan.txt").await;
    // Still recorded, and the list still reports it truthfully.
    assert!(current(&a, group_id, COPY).is_some_and(|(_, size)| size == 7));
    assert_eq!(listed_copies(&socket).await, vec![(COPY.to_string(), true)]);

    hydration::restore_to_version(&a.state, group_id, "plan.txt", replaced_seq).await.unwrap();
    assert_eq!(read(&a, "plan.txt"), "mine");
}

/// The retained copy keeps its permissions (and, where supported, its
/// extended attributes); repeating Keep this is safe and changes nothing
/// about the copy.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keep_this_retains_permissions_and_xattrs_and_can_be_repeated() {
    use std::os::unix::fs::PermissionsExt;
    let group_id = "conflict-keep-this-metadata";
    support::ensure_isolated_config_dir();
    let a = setup_device("device-a");
    support::install_bootstrap_policy(&a.state, &[group_id.to_string()]);
    start_watching(&a, group_id);
    std::fs::write(a.root.path().join("plan.txt"), "mine").unwrap();
    let copy_abs = a.root.path().join(COPY);
    std::fs::write(&copy_abs, "theirs!").unwrap();
    std::fs::set_permissions(&copy_abs, std::fs::Permissions::from_mode(0o640)).unwrap();
    #[cfg(target_os = "linux")]
    let (c_path, xattr_set) = {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(copy_abs.as_os_str().as_bytes()).unwrap();
        // SAFETY: NUL-terminated strings and a buffer valid for its length.
        let set = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                c"user.yadori_test".as_ptr(),
                b"v".as_ptr().cast(),
                1,
                0,
            ) == 0
        };
        (c_path, set)
    };
    wait_captured(&a, group_id, "plan.txt", 4).await;
    wait_captured(&a, group_id, COPY, 7).await;
    // The chmod/xattr change is captured as a version of its own.
    wait_recorded(&a, group_id, COPY).await;
    let socket = control_socket_client::start(a.state.clone()).await;

    for _ in 0..2 {
        // The second round also follows the plan.txt write of the first.
        wait_recorded(&a, group_id, "plan.txt").await;
        wait_recorded(&a, group_id, COPY).await;
        let outcome = resolve(&socket, &a, COPY, ConflictResolution::KeepThis).await;
        assert!(matches!(outcome, Outcome::KeptPath(_)), "{outcome:?}");
        assert_eq!(read(&a, "plan.txt"), "theirs!");
        assert_eq!(read(&a, COPY), "theirs!");
        let mode = std::fs::metadata(&copy_abs).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        #[cfg(target_os = "linux")]
        if xattr_set {
            let mut buf = [0u8; 8];
            // SAFETY: NUL-terminated strings and a buffer valid for its length.
            let n = unsafe {
                libc::getxattr(
                    c_path.as_ptr(),
                    c"user.yadori_test".as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            assert_eq!(&buf[..n.max(0) as usize], b"v");
        } else {
            eprintln!("skipping xattr check: this filesystem does not support user xattrs");
        }
        assert_no_reserved_names(&a);
        assert_eq!(listed_copies(&socket).await, vec![(COPY.to_string(), true)]);
    }
}

fn fence(device: &TestDevice, group_id: &str, path: &str) -> i64 {
    device.state.replica_coordinator.dag_snapshot_mutation_fence(group_id, path).unwrap()
}

/// Keep both retires any proof of what was at the copy's path before the copy is moved: the
/// path's mutation fence moves on. Keep this leaves the copy alone, so its fence stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resolving_invalidates_the_proof_of_the_copy_path() {
    for (group_id, resolution) in [("conflict-fence-keep-both", ConflictResolution::KeepBoth)] {
        let (a, socket) = device_with_conflict(group_id).await;
        let before = fence(&a, group_id, COPY);

        let outcome = resolve(&socket, &a, COPY, resolution).await;

        assert!(matches!(outcome, Outcome::KeptPath(_)), "{outcome:?}");
        assert!(
            fence(&a, group_id, COPY) > before,
            "the copy's mutation fence did not move on ({resolution:?})"
        );
    }
}

/// Keep this over a name that is a folder now is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keep_this_refuses_a_folder_at_the_original_name() {
    support::ensure_isolated_config_dir();
    let group_id = "conflict-folder-original";
    let a = setup_device("device-a");
    support::install_bootstrap_policy(&a.state, &[group_id.to_string()]);
    start_watching(&a, group_id);
    std::fs::create_dir(a.root.path().join("plan.txt")).unwrap();
    std::fs::write(a.root.path().join("plan.txt").join("inside"), "x").unwrap();
    std::fs::write(a.root.path().join(COPY), "theirs!").unwrap();
    wait_captured(&a, group_id, "plan.txt/inside", 1).await;
    wait_captured(&a, group_id, COPY, 7).await;
    let socket = control_socket_client::start(a.state.clone()).await;

    let outcome = resolve(&socket, &a, COPY, ConflictResolution::KeepThis).await;

    assert_eq!(refusal_code(&outcome), ApplicationErrorCode::ConflictNotResolvable);
    assert_eq!(read(&a, COPY), "theirs!");
    assert_eq!(read(&a, "plan.txt/inside"), "x");
}

/// Keep both never moves the copy over an existing name: one taken already,
/// or one created since the list was read, keeps its content and the copy
/// takes the next free name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keep_both_never_overwrites_an_existing_name() {
    let group_id = "conflict-keep-both";
    let (a, socket) = device_with_conflict(group_id).await;
    std::fs::write(a.root.path().join("plan (other version).txt"), "created in between").unwrap();

    let outcome = resolve(&socket, &a, COPY, ConflictResolution::KeepBoth).await;

    let Outcome::KeptPath(kept) = outcome else { panic!("{outcome:?}") };
    assert_eq!(std::path::Path::new(&kept), a.root.path().join("plan (other version 2).txt"));
    assert_eq!(read(&a, "plan (other version 2).txt"), "theirs!");
    assert_eq!(read(&a, "plan (other version).txt"), "created in between");
    assert_eq!(read(&a, "plan.txt"), "mine");
    assert!(!a.root.path().join(COPY).exists());
}

/// A path that is not a listed conflict copy is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_that_is_not_a_conflict_copy_is_refused() {
    let group_id = "conflict-not-a-copy";
    let (a, socket) = device_with_conflict(group_id).await;

    let outcome = resolve(&socket, &a, "plan.txt", ConflictResolution::KeepThis).await;

    assert_eq!(refusal_code(&outcome), ApplicationErrorCode::TargetNotFound);
    assert_eq!(read(&a, "plan.txt"), "mine");
}

/// Keep this on one device converges on a second one, and the result
/// survives that device's restart: the content stays, and the copy stays too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keep_this_converges_on_a_second_device_and_survives_its_restart() {
    support::ensure_isolated_config_dir();
    let group_id = "conflict-two-devices";
    let a = setup_device("device-a");
    let b = setup_device("device-b");
    start_watching(&a, group_id);
    start_watching(&b, group_id);
    let groups = [group_id.to_string()];
    support::connect_two_daemons(&a.state, &a.device_id, &b.state, &b.device_id, &groups).await;
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "B receiving A's resolution over its existing files",
    ) {
        return;
    }

    std::fs::write(a.root.path().join("plan.txt"), "mine").unwrap();
    std::fs::write(a.root.path().join(COPY), "theirs!").unwrap();
    wait_until_with_context(
        || read(&b, "plan.txt") == "mine" && read(&b, COPY) == "theirs!",
        Duration::from_secs(60),
        || format!("B never received both files: {:?}", real_entry_names(b.root.path())),
    )
    .await;

    let socket = control_socket_client::start(a.state.clone()).await;
    let outcome = resolve(&socket, &a, COPY, ConflictResolution::KeepThis).await;
    assert!(matches!(outcome, Outcome::KeptPath(_)), "{outcome:?}");

    // On disk and in the index: the original holds the kept content, and the
    // copy is still there, unchanged.
    let converged = |device: &TestDevice| {
        read(device, "plan.txt") == "theirs!"
            && read(device, COPY) == "theirs!"
            && current(device, group_id, COPY).is_some_and(|(_, size)| size == 7)
            && current(device, group_id, "plan.txt").is_some_and(|(_, size)| size == 7)
    };
    let state_of = |device: &TestDevice| {
        format!(
            "{}: {:?} copy={:?} plan={:?}",
            device.device_id,
            real_entry_names(device.root.path()),
            current(device, group_id, COPY),
            current(device, group_id, "plan.txt")
        )
    };
    wait_until_with_context(|| converged(&b), Duration::from_secs(60), || state_of(&b)).await;

    // Restart B: a fresh daemon over the same index, block store and folder.
    support::sever_reconciliation(&a.state, &b.state).await;
    LinkRuntimeController::new(b.state.clone()).stop(&b.root.path().to_string_lossy()).await;
    let TestDevice { device_id, state, root, store_dir, index_dir } = b;
    drop(state);
    let restarted = TestDevice {
        state: open_state(&device_id, store_dir.path(), &index_dir.path().join("index.db")),
        device_id,
        root,
        store_dir,
        index_dir,
    };
    start_watching(&restarted, group_id);
    support::connect_two_daemons(
        &a.state,
        &a.device_id,
        &restarted.state,
        &restarted.device_id,
        &groups,
    )
    .await;
    // The restarted device's startup scan and reconciliation have run once a
    // file written on A arrives; by then nothing may have changed either file.
    std::fs::write(a.root.path().join("after-restart.txt"), "later").unwrap();
    wait_until_with_context(
        || read(&restarted, "after-restart.txt") == "later",
        Duration::from_secs(60),
        || state_of(&restarted),
    )
    .await;
    assert!(converged(&restarted), "{}", state_of(&restarted));
    assert!(converged(&a), "{}", state_of(&a));
}

/// A folder above the copy that became a link out of the linked folder never
/// lets the daemon move or remove a file outside it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_folder_above_the_copy_linked_out_of_the_root_is_refused() {
    support::ensure_isolated_config_dir();
    let group_id = "conflict-linked-out";
    let a = setup_device("device-a");
    support::install_bootstrap_policy(&a.state, &[group_id.to_string()]);
    start_watching(&a, group_id);
    let sub_copy = format!("sub/{COPY}");
    std::fs::create_dir(a.root.path().join("sub")).unwrap();
    std::fs::write(a.root.path().join("sub/plan.txt"), "mine").unwrap();
    std::fs::write(a.root.path().join(&sub_copy), "theirs!").unwrap();
    wait_captured(&a, group_id, "sub/plan.txt", 4).await;
    wait_captured(&a, group_id, &sub_copy, 7).await;
    let socket = control_socket_client::start(a.state.clone()).await;

    a.state.replica_coordinator.paused_item_repository().pause(group_id, "sub").unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join(COPY), "outside the folder").unwrap();
    std::fs::rename(a.root.path().join("sub"), a.root.path().join("sub-moved")).unwrap();
    std::os::unix::fs::symlink(outside.path(), a.root.path().join("sub")).unwrap();

    for resolution in [ConflictResolution::KeepBoth, ConflictResolution::KeepThis] {
        // The path no longer resolves into the folder at all; the daemon's own
        // check behind it is pinned by its unit test.
        let outcome = resolve(&socket, &a, &sub_copy, resolution).await;
        assert!(matches!(outcome, Outcome::Error(_)), "{outcome:?}");
    }
    assert_eq!(std::fs::read_to_string(outside.path().join(COPY)).unwrap(), "outside the folder");
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
}
