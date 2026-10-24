//! The host's command calls: what the typed commands return, and how a call ends when it is
//! cancelled, runs out of time or loses its engine. Deterministic: each wait is released by
//! the test, not by the clock; a deadline test uses a command that never finishes on its own.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use yadorilink_embedded_host::{
    ordinary_folder_links_supported, CallError, CallOptions, CancelHandle, Command,
    CommandErrorKind, CommandOutput, EmbeddedHost, LinkFolder, RestoreVersion,
};

mod support;
use support::{area, serialized};

fn running_host() -> (EmbeddedHost, support::Area) {
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    (host, area)
}

/// Sets a flag when dropped: tells whether the command's future was dropped (aborted).
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn within(secs: u64) -> CallOptions {
    CallOptions { deadline: Some(Duration::from_secs(secs)), cancel: CancelHandle::new() }
}

#[test]
fn listing_folders_on_a_fresh_engine_finds_none() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let output = host.execute(Command::ListFolders, &within(30)).unwrap();
    assert_eq!(output, CommandOutput::Folders(Vec::new()));
    host.stop().unwrap();
}

#[test]
fn restoring_a_file_that_has_no_earlier_version_says_so() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let restore = RestoreVersion { group_id: "g".into(), path: "a.txt".into(), version_seq: None };
    let result = host.execute(Command::RestoreVersion(restore), &within(30));
    // The engine either reports there is nothing to restore, or refuses a group it does not
    // know; it never claims a restore happened.
    assert!(
        matches!(result, Ok(CommandOutput::Restored(false)) | Err(CallError::Failed(_))),
        "{result:?}"
    );
    host.stop().unwrap();
}

#[test]
fn a_link_that_the_engine_refuses_fails_with_its_message_and_changes_nothing() {
    let _serial = serialized();
    if !ordinary_folder_links_supported() {
        return; // covered by `an_ordinary_folder_is_not_linked_without_a_change_source`
    }
    let (host, _area) = running_host();
    let missing = LinkFolder {
        local_path: "/this/folder/does/not/exist".into(),
        group_id: "g".into(),
        on_demand: false,
        acknowledge_risks: false,
    };
    let result = host.execute(Command::LinkFolder(missing), &within(30));
    let Err(CallError::Failed(error)) = result else { panic!("expected a refusal: {result:?}") };
    assert!(!error.message().is_empty());
    assert_eq!(
        host.execute(Command::ListFolders, &within(30)).unwrap(),
        CommandOutput::Folders(Vec::new())
    );
    host.stop().unwrap();
}

/// A build with no OS watcher cannot capture an ordinary folder's edits, so it must not report
/// such a folder as linked: the refusal is typed and nothing is persisted.
#[test]
fn an_ordinary_folder_is_not_linked_without_a_change_source() {
    let _serial = serialized();
    if ordinary_folder_links_supported() {
        return; // this build has a watcher
    }
    let (host, _area) = running_host();
    let folder = tempfile::tempdir().unwrap();
    for acknowledge_risks in [false, true] {
        let link = LinkFolder {
            local_path: folder.path().to_str().unwrap().into(),
            group_id: "g".into(),
            on_demand: false,
            acknowledge_risks,
        };
        let result = host.execute(Command::LinkFolder(link), &within(30));
        let Err(CallError::Failed(error)) = result else {
            panic!("expected a refusal: {result:?}")
        };
        assert_eq!(error.kind(), CommandErrorKind::NoChangeSource);
        assert!(error.message().contains("provider folders"), "{}", error.message());
    }
    assert_eq!(
        host.execute(Command::ListFolders, &within(30)).unwrap(),
        CommandOutput::Folders(Vec::new()),
        "a refused link persisted nothing"
    );
    host.stop().unwrap();
}

#[test]
fn a_call_without_a_running_engine_is_refused() {
    let _serial = serialized();
    let area = area();
    let host = EmbeddedHost::new(area.config.clone());
    let result = host.execute(Command::ListFolders, &within(5));
    assert!(matches!(result, Err(CallError::Host(_))), "{result:?}");
}

#[test]
fn a_cancel_handle_belongs_to_one_call() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let options = within(30);
    host.execute(Command::ListFolders, &options).unwrap();
    assert_eq!(host.execute(Command::ListFolders, &options), Err(CallError::HandleUsed));
    host.stop().unwrap();
}

#[test]
fn a_handle_cancelled_before_the_call_stops_it_from_starting() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let started = Arc::new(AtomicBool::new(false));
    let options = within(30);
    options.cancel.cancel();
    let flag = started.clone();
    let result = host.execute_for_test(
        false,
        async move {
            flag.store(true, Ordering::SeqCst);
            Ok(CommandOutput::Linked)
        },
        &options,
    );
    assert_eq!(result, Err(CallError::Cancelled { still_running: false }));
    assert!(!started.load(Ordering::SeqCst));
    host.stop().unwrap();
}

#[test]
fn a_read_only_call_that_runs_out_of_time_is_aborted() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropFlag(dropped.clone());
    let options =
        CallOptions { deadline: Some(Duration::from_millis(100)), cancel: CancelHandle::new() };
    let result = host.execute_for_test(
        true,
        async move {
            let _guard = guard;
            std::future::pending::<()>().await;
            Ok(CommandOutput::Linked)
        },
        &options,
    );
    assert_eq!(result, Err(CallError::DeadlineExceeded { still_running: false }));
    host.stop().unwrap();
    assert!(dropped.load(Ordering::SeqCst), "the aborted command's future was dropped");
}

#[test]
fn a_state_changing_call_that_is_cancelled_keeps_running_to_its_end() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let (release, gate) = tokio::sync::oneshot::channel::<()>();
    let finished = Arc::new(AtomicBool::new(false));
    let flag = finished.clone();
    let options = within(30);
    let cancel = options.cancel.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        cancel.cancel();
    });
    let result = host.execute_for_test(
        false,
        async move {
            let _ = gate.await;
            flag.store(true, Ordering::SeqCst);
            Ok(CommandOutput::Linked)
        },
        &options,
    );
    canceller.join().unwrap();
    assert_eq!(result, Err(CallError::Cancelled { still_running: true }));
    assert!(!finished.load(Ordering::SeqCst), "the command was left running, not completed");

    release.send(()).unwrap();
    for _ in 0..200 {
        if finished.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(finished.load(Ordering::SeqCst), "the command ran to its end after the cancel");
    host.stop().unwrap();
}

#[test]
fn a_state_changing_call_that_runs_out_of_time_says_it_is_still_running() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let options =
        CallOptions { deadline: Some(Duration::from_millis(100)), cancel: CancelHandle::new() };
    let result = host.execute_for_test(
        false,
        async {
            std::future::pending::<()>().await;
            Ok(CommandOutput::Linked)
        },
        &options,
    );
    assert_eq!(result, Err(CallError::DeadlineExceeded { still_running: true }));
    host.stop().unwrap();
}

#[test]
fn a_call_whose_engine_stops_ends_with_engine_stopped() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let host = Arc::new(host);
    let waiting = host.clone();
    let call = std::thread::spawn(move || {
        waiting.execute_for_test(
            false,
            async {
                std::future::pending::<()>().await;
                Ok(CommandOutput::Linked)
            },
            &within(60),
        )
    });
    std::thread::sleep(Duration::from_millis(200));
    host.stop().unwrap();
    assert_eq!(call.join().unwrap(), Err(CallError::EngineStopped));
}

/// A host whose stop is held up: another thread owns the lifecycle lock for the whole teardown.
fn host_with_a_slow_stop(
) -> (Arc<EmbeddedHost>, std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>, support::Area) {
    let (host, area) = running_host();
    let host = Arc::new(host);
    let (release, stall) = std::sync::mpsc::channel::<()>();
    host.stall_stop_for_test(stall).unwrap();
    let stopping = host.clone();
    let stopper = std::thread::spawn(move || {
        let _ = stopping.stop();
    });
    // The stop has taken the lifecycle lock once the host no longer reports running.
    std::thread::sleep(Duration::from_millis(300));
    (host, release, stopper, area)
}

#[test]
fn a_short_deadline_is_honoured_while_another_thread_tears_the_host_down() {
    let _serial = serialized();
    let (host, release, stopper, _area) = host_with_a_slow_stop();
    let options =
        CallOptions { deadline: Some(Duration::from_millis(50)), cancel: CancelHandle::new() };
    let began = std::time::Instant::now();
    let result = host.execute(Command::ListFolders, &options);
    assert_eq!(result, Err(CallError::DeadlineExceeded { still_running: false }));
    assert!(began.elapsed() < Duration::from_secs(5), "the call waited out the teardown");
    release.send(()).unwrap();
    stopper.join().unwrap();
}

#[test]
fn a_pre_cancelled_call_returns_at_once_while_the_host_is_being_torn_down() {
    let _serial = serialized();
    let (host, release, stopper, _area) = host_with_a_slow_stop();
    let options = CallOptions { deadline: None, cancel: CancelHandle::new() };
    options.cancel.cancel();
    let began = std::time::Instant::now();
    let result = host.execute(Command::ListFolders, &options);
    assert_eq!(result, Err(CallError::Cancelled { still_running: false }));
    assert!(began.elapsed() < Duration::from_secs(5), "the call waited out the teardown");
    release.send(()).unwrap();
    stopper.join().unwrap();
}

#[test]
fn a_cancel_during_the_wait_for_the_lifecycle_lock_ends_the_call() {
    let _serial = serialized();
    let (host, release, stopper, _area) = host_with_a_slow_stop();
    let options = CallOptions { deadline: None, cancel: CancelHandle::new() };
    let cancel = options.cancel.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        cancel.cancel();
    });
    let result = host.execute(Command::ListFolders, &options);
    canceller.join().unwrap();
    assert_eq!(result, Err(CallError::Cancelled { still_running: false }));
    release.send(()).unwrap();
    stopper.join().unwrap();
}

/// A stop that begins while a call is between obtaining the engine's services and submitting its
/// work cannot finish under it: the stop waits for the lifecycle lock the submission holds, then
/// ends the work with the runtime. The services the work owned are released before the stop
/// reports success, so the data area is free and an immediate restart starts.
#[test]
fn a_stop_in_the_window_before_submission_cannot_leave_the_data_open() {
    let _serial = serialized();
    let (host, _area) = running_host();
    let host = Arc::new(host);
    let probe = host.release_probe().unwrap();
    let stopper: Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::default();
    let stopped_early = Arc::new(AtomicBool::new(false));

    let (hook_host, hook_stopper, early) = (host.clone(), stopper.clone(), stopped_early.clone());
    let result = host.execute_owning_for_test(
        false,
        move || {
            let thread = std::thread::spawn({
                let host = hook_host;
                move || host.stop().unwrap()
            });
            std::thread::sleep(Duration::from_millis(300));
            early.store(thread.is_finished(), Ordering::SeqCst);
            *hook_stopper.lock().unwrap() = Some(thread);
        },
        |commands| async move {
            // Owns the engine's services for as long as it lives, like a real command.
            let _commands = commands;
            std::future::pending::<()>().await;
            Ok(CommandOutput::Linked)
        },
        &CallOptions::default(),
    );

    assert!(!stopped_early.load(Ordering::SeqCst), "the stop finished inside the window");
    assert_eq!(result, Err(CallError::EngineStopped));
    stopper.lock().unwrap().take().unwrap().join().unwrap();
    assert!(support::released(&probe), "the call's services outlived the stop");
    host.start().expect("the data area is free right after the stop");
    host.stop().unwrap();
}
