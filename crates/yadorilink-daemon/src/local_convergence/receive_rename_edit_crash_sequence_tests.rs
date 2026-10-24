#![cfg(all(test, unix))]
//! The triple the pairwise sequences leave open: a rename and an edit by the
//! user while a receive is held, then a stop, then the restart.
//!
//! The write of a received file is held after it was renamed into place and
//! before its commit (`BeforeCommit`: the name exists, the proof does not). The
//! user then moves the file to another name, with or without editing it first
//! or after, the process stops there or the write runs on, and the next start
//! repairs, captures and receives again. This is the case where an edit could
//! follow a file to the wrong name, or be dropped by the repair.
//!
//! Fixed by construction, like `receive_edit_crash_sequence_tests`: the sequence is
//! the cell (user action, how the write ends, recovery order), enumerated in
//! full, so a failing cell names its own reproduction. The stop is credited
//! only if the write was seen at the step.
//!
//! The oracle is the disk and the index, and shares no code with the receive:
//!
//! * the bytes the user ended up with exist in the root (at the new name, or in
//!   a preserved copy), whatever the repair did, and a name the user deleted
//!   stays deleted;
//! * no temp file is left, and there is no copy explosion (a bounded number of
//!   files, a bounded number of conflict copies);
//! * the index and the disk agree: every live indexed file exists with the
//!   indexed bytes, and every file on disk is indexed, so nothing is owed;
//! * the state is stable: a second repair, scan and reconcile change nothing.
//!
//! "Acknowledged data" here is the received version (its blocks were fetched and
//! the intent was open) and the user's own bytes: neither may vanish unless the
//! user's own later operation replaced it. A user rename of the received file
//! is a delete of its name that the receive did not see, so the name may end
//! absent; what must not happen is the bytes ending nowhere.

use std::collections::BTreeMap;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::receive_window_concurrency_tests::{
    arm, driver, names, pin_concurrency, publish_new_files, reconcile,
};
use super::{OverlapProbe, ProbeSeam};

const MOVED: &str = "moved-by-user";

#[derive(Clone, Copy, Debug)]
enum Edit {
    InPlace,
    Append,
    AtomicReplace,
}

/// What the user does to the held file.
#[derive(Clone, Copy, Debug)]
enum Action {
    /// Moves it, unchanged.
    Rename,
    /// Moves it, then edits it under the new name.
    RenameThenEdit(Edit),
    /// Edits it under its name, then moves it.
    EditThenRename(Edit),
    /// Moves it, then deletes it under the new name. The delete is the user's
    /// and acknowledged: the moved name must not come back.
    RenameThenDelete,
    /// Moves it, then writes a fresh file at the old name (the rotate pattern).
    /// Both files are the user's; both must survive.
    RenameThenRecreate,
}

/// What the action leaves the user owning.
struct Outcome {
    /// Bytes the user's files hold; each must exist somewhere in the root.
    kept: Vec<Vec<u8>>,
    /// Names the user deleted; none may exist at the end.
    deleted: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
enum Stop {
    Crash,
    Release,
}

#[derive(Clone, Copy, Debug)]
enum Order {
    RepairThenCapture,
    CaptureThenRepair,
}

fn edit(h: &Harness, name: &str, received: &[u8], edit: Edit) -> Vec<u8> {
    use std::io::Write;
    match edit {
        Edit::InPlace => {
            let bytes = vec![b'U'; received.len()];
            std::fs::write(h.path(name), &bytes).unwrap();
            bytes
        }
        Edit::Append => {
            let mut file = std::fs::OpenOptions::new().append(true).open(h.path(name)).unwrap();
            file.write_all(b" and the user's own lines").unwrap();
            std::fs::read(h.path(name)).unwrap()
        }
        Edit::AtomicReplace => {
            let bytes = vec![b'R'; received.len()];
            let aside = h.path("user-editor.swp");
            std::fs::write(&aside, &bytes).unwrap();
            std::fs::rename(&aside, h.path(name)).unwrap();
            bytes
        }
    }
}

/// Performs the action and says what the user now owns.
fn act(h: &Harness, name: &str, received: &[u8], action: Action) -> Outcome {
    // A rename is a delete of the old name, whether or not the write had
    // committed: the received name must not come back.
    let keep = |bytes: Vec<u8>| Outcome { kept: vec![bytes], deleted: vec![name.to_string()] };
    match action {
        Action::Rename => {
            std::fs::rename(h.path(name), h.path(MOVED)).unwrap();
            keep(received.to_vec())
        }
        Action::RenameThenEdit(kind) => {
            std::fs::rename(h.path(name), h.path(MOVED)).unwrap();
            keep(edit(h, MOVED, received, kind))
        }
        Action::EditThenRename(kind) => {
            let bytes = edit(h, name, received, kind);
            std::fs::rename(h.path(name), h.path(MOVED)).unwrap();
            keep(bytes)
        }
        Action::RenameThenDelete => {
            std::fs::rename(h.path(name), h.path(MOVED)).unwrap();
            std::fs::remove_file(h.path(MOVED)).unwrap();
            Outcome { kept: vec![], deleted: vec![MOVED.to_string(), name.to_string()] }
        }
        Action::RenameThenRecreate => {
            std::fs::rename(h.path(name), h.path(MOVED)).unwrap();
            let fresh = vec![b'N'; received.len()];
            std::fs::write(h.path(name), &fresh).unwrap();
            Outcome { kept: vec![received.to_vec(), fresh], deleted: vec![] }
        }
    }
}

fn root_files(h: &Harness) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(h.path(""))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        // The root's own marker and lock are not data.
        .filter(|name| !name.starts_with(".yadorilink-root"))
        .map(|name| {
            let bytes = std::fs::read(h.path(&name)).unwrap();
            (name, bytes)
        })
        .collect()
}

fn repair(h: &Harness) {
    h.state.remove_recorded_temp_files(GROUP, &h.path("")).unwrap();
    yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
        h.state.as_ref(),
        &*h.convergence.store,
        &h.path(""),
        GROUP,
        yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
}

/// The live indexed files: path to the hex of its block hashes.
fn live_index(h: &Harness) -> BTreeMap<String, String> {
    h.state
        .file_index_repository()
        .list_files(GROUP)
        .unwrap()
        .into_iter()
        .filter(|row| !row.deleted)
        .map(|row| {
            let hashes: Vec<String> = row.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
            (row.path, hashes.join("+"))
        })
        .collect()
}

/// What the index must hold for these bytes on disk, computed by a store of
/// its own so the receive's block hashing is not asked to vouch for itself.
fn indexed_form(files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
    let scratch = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(scratch.path()).unwrap();
    files.iter().map(|(name, bytes)| (name.clone(), store.put(bytes).unwrap())).collect()
}

/// The files that are the user's or the receive's, without the peer's source
/// fixture, which always holds the received bytes and would satisfy any
/// preservation check on its own.
fn without_source(files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<&String, &Vec<u8>> {
    files.iter().filter(|(name, _)| !name.starts_with("zz-source-")).collect()
}

/// One start: repair, capture, scan, the journal's redrive, then receive and redrive
/// until quiet.
async fn start(h: &Harness, files: &[String], order: Order, name: &str) {
    match order {
        Order::RepairThenCapture => {
            repair(h);
            h.capture(name).await;
            h.capture(MOVED).await;
        }
        Order::CaptureThenRepair => {
            h.capture(name).await;
            h.capture(MOVED).await;
            repair(h);
        }
    }
    h.scan();
    // The daemon re-drives the dirty journal after the scan, inside the startup
    // barrier and before any peer apply runs.
    h.redrive().await;
    for _ in 0..3 {
        reconcile(h, files).await;
        h.redrive().await;
    }
}

async fn run_cell(action: Action, stop: Stop, order: Order) -> Result<String, String> {
    let h = Harness::new(false);
    pin_concurrency(&h, 2);
    let files = names("held-", 1);
    let name = files[0].clone();
    let received = publish_new_files(&h, &files).await.remove(&name).unwrap();

    let probe = OverlapProbe::new(ProbeSeam::BeforeCommit, 1, 30_000);
    probe.hold_until_released();
    arm(&h, &probe);
    let task = {
        let (convergence, files) = (h.convergence.clone(), files.clone());
        tokio::spawn(async move {
            convergence
                .reconcile_paths_directly(&driver(), GROUP, files.into_iter().collect())
                .await
        })
    };
    let waited = std::time::Instant::now();
    while probe.in_flight() < 1 {
        if waited.elapsed() > std::time::Duration::from_secs(30) {
            return Err(format!("the write never reached BeforeCommit: {:?}", probe.events()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    let user = act(&h, &name, &received, action);
    match stop {
        Stop::Crash => {
            task.abort();
            let _ = task.await;
        }
        Stop::Release => {
            probe.release();
            let _ = task.await;
        }
    }
    *h.convergence.overlap_probe.lock().unwrap() = None;
    if !probe.events().iter().any(|(path, entered)| path == &name && *entered) {
        return Err("the stop was not credited: the write never entered the step".into());
    }

    start(&h, &files, order, &name).await;

    let after = root_files(&h);
    let shape =
        || after.iter().map(|(n, b)| format!("{n}:{}", b.len())).collect::<Vec<_>>().join(" ");
    let own = without_source(&after);
    for bytes in &user.kept {
        if !own.values().any(|have| *have == bytes) {
            return Err(format!("the user's bytes ({} long) are gone: {}", bytes.len(), shape()));
        }
    }
    for gone in &user.deleted {
        if own.contains_key(gone) {
            return Err(format!("the user's delete of `{gone}` was undone: {}", shape()));
        }
    }
    let temps: Vec<_> = after.keys().filter(|n| n.contains(".yadorilink-tmp.")).collect();
    if !temps.is_empty() {
        return Err(format!("temp files left: {temps:?}"));
    }
    // The published source file (`zz-source-*`) is the peer's other file, always
    // there; the rest is the received name, the moved name and any copies.
    let copies = after.keys().filter(|n| n.contains("(conflicted copy")).count();
    if copies > 2 || after.len() > 5 {
        return Err(format!(
            "too many files ({} files, {copies} copies): {}",
            after.len(),
            shape()
        ));
    }
    let index = live_index(&h);
    let on_disk = indexed_form(&after);
    if index != on_disk {
        return Err(format!("the index {index:?} and the disk {on_disk:?} disagree"));
    }

    // Stable: another start changes nothing.
    start(&h, &files, order, &name).await;
    if root_files(&h) != after || live_index(&h) != index {
        return Err(format!("a second start changed the outcome: {}", shape()));
    }
    Ok(shape())
}

/// Every cell of the action x stop x order product keeps the user's bytes, the
/// index and the disk agree, nothing multiplies, and the outcome is stable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rename_and_an_edit_made_while_a_receive_is_held_survive_the_stop_and_the_restart() {
    let kinds = [Edit::InPlace, Edit::Append, Edit::AtomicReplace];
    let mut actions = vec![Action::Rename];
    actions.extend(kinds.into_iter().map(Action::RenameThenEdit));
    actions.extend(kinds.into_iter().map(Action::EditThenRename));
    actions.extend([Action::RenameThenDelete, Action::RenameThenRecreate]);
    let mut failures = Vec::new();
    let trace = std::env::var_os("YADORILINK_RENAME_EDIT_TRACE").is_some();
    for action in actions {
        for stop in [Stop::Crash, Stop::Release] {
            for order in [Order::RepairThenCapture, Order::CaptureThenRepair] {
                match run_cell(action, stop, order).await {
                    Ok(shape) if trace => eprintln!("{action:?} {stop:?} {order:?}: {shape}"),
                    Ok(_) => {}
                    Err(why) => failures.push(format!("{action:?} {stop:?} {order:?}: {why}")),
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
