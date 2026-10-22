#![cfg(all(test, unix))]
//! An ordered fault sequence on a receive: a file is held at a step of its write
//! (assembled in a temp file, or renamed into place without its commit), the
//! user edits the path while it is held, the process stops there, and the next
//! start repairs and receives again. The user's edit must survive on disk
//! whatever the step, the kind of edit, whether the write is dropped or runs on,
//! and the order in which the restart
//! captures the edit and repairs the interrupted write.
//!
//! Fixed by construction: the sequence is the cell (step, edit kind, how the write ends,
//! recovery order), enumerated in full, so a failing cell names its own reproduction.
//! The stop is credited only if the write was seen at the step
//! ([`OverlapProbe`]'s event log, written by the product's own seam).
//!
//! The oracle is the disk: the exact bytes the user wrote exist in the root
//! at the end (at the name, or in a conflict copy), no temp file is left, and a
//! second repair changes nothing.
//!
//! Not covered here: the unflushed window of a deferred-flush receive with a
//! power cut, which is `receive_deferred_flush_tests` and the persistence
//! model; the edit kinds here are the same three those tests use.

use std::collections::BTreeMap;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::receive_window_concurrency_tests::{
    arm, driver, names, pin_concurrency, publish_new_files, reconcile,
};
use super::{OverlapProbe, ProbeSeam};

#[derive(Clone, Copy, Debug)]
enum Edit {
    /// Overwrites the file in place with other bytes of the same length.
    InPlace,
    /// Appends to the file.
    Append,
    /// Writes the bytes aside and renames them over the name, as editors do.
    AtomicReplace,
}

/// How the held write ends.
#[derive(Clone, Copy, Debug)]
enum Stop {
    /// The process stops at the step (the write is dropped there).
    Crash,
    /// The hold is released and the write runs on past the user's edit, as
    /// when the user is quicker than the receive.
    Release,
}

#[derive(Clone, Copy, Debug)]
enum Order {
    RepairThenCapture,
    CaptureThenRepair,
}

fn apply(h: &Harness, name: &str, received: &[u8], edit: Edit) -> Vec<u8> {
    use std::io::Write;
    match edit {
        Edit::InPlace => {
            let bytes = vec![b'U'; received.len()];
            std::fs::write(h.path(name), &bytes).unwrap();
            bytes
        }
        Edit::Append => {
            let mut file =
                std::fs::OpenOptions::new().create(true).append(true).open(h.path(name)).unwrap();
            file.write_all(b" and the user's own lines").unwrap();
            // The file may not have existed (the step before the rename).
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

fn root_files(h: &Harness) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(h.path(""))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with("zz-source-"))
        .map(|name| {
            let bytes = std::fs::read(h.path(&name)).unwrap();
            (name, bytes)
        })
        .collect()
}

/// What a start does before it serves: removes the temp files the ledger
/// recorded (`link_runtime/factory.rs`), then repairs interrupted writes.
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

/// How a cell ends: `Err` names the broken invariant.
async fn run_cell(seam: ProbeSeam, edit: Edit, stop: Stop, order: Order) -> Result<(), String> {
    let h = Harness::new(false);
    pin_concurrency(&h, 2);
    let files = names("held-", 1);
    let name = files[0].clone();
    let received = publish_new_files(&h, &files).await.remove(&name).unwrap();

    // The write is held at the step.
    let probe = OverlapProbe::new(seam, 1, 30_000);
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
            return Err(format!("the write never reached {seam:?}: {:?}", probe.events()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    // The user edits while it is held; then the process stops.
    let user_bytes = apply(&h, &name, &received, edit);
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

    // The next start.
    match order {
        Order::RepairThenCapture => {
            repair(&h);
            h.capture(&name).await;
        }
        Order::CaptureThenRepair => {
            h.capture(&name).await;
            repair(&h);
        }
    }
    h.scan();
    for _ in 0..3 {
        reconcile(&h, &files).await;
        h.redrive().await;
    }

    let after = root_files(&h);
    if !after.values().any(|bytes| *bytes == user_bytes) {
        return Err(format!(
            "the user's bytes are gone: {:?}",
            after.iter().map(|(n, b)| (n.clone(), b.len())).collect::<Vec<_>>()
        ));
    }
    let temps: Vec<_> = after.keys().filter(|n| n.contains(".yadorilink-tmp.")).collect();
    if !temps.is_empty() {
        return Err(format!("temp files left: {temps:?}"));
    }
    repair(&h);
    if root_files(&h) != after {
        return Err("a second repair changed the root".into());
    }
    Ok(())
}

/// Every cell of the step x edit x order product keeps the user's bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_edit_made_while_a_receive_is_held_survives_the_stop_and_the_restart() {
    let (seams, edits) = (
        [ProbeSeam::BeforeRename, ProbeSeam::BeforeCommit],
        [Edit::InPlace, Edit::Append, Edit::AtomicReplace],
    );
    let (stops, orders) =
        ([Stop::Crash, Stop::Release], [Order::RepairThenCapture, Order::CaptureThenRepair]);
    let cells = seams.into_iter().flat_map(|seam| {
        edits.into_iter().flat_map(move |edit| {
            stops.into_iter().flat_map(move |stop| {
                orders.into_iter().map(move |order| (seam, edit, stop, order))
            })
        })
    });
    let mut failures = Vec::new();
    for (seam, edit, stop, order) in cells {
        if let Err(why) = run_cell(seam, edit, stop, order).await {
            failures.push(format!("{seam:?} {edit:?} {stop:?} {order:?}: {why}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
