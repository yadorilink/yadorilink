//! The Windows directory watcher: one `ReadDirectoryChangesW` handle on the
//! root, watching its whole subtree.
//!
//! `notify` 8's Windows backend is not used because it cannot tell us when
//! changes were lost. When more happens between two reads than the buffer
//! holds, the driver completes the read with zero bytes (or with
//! `ERROR_NOTIFY_ENUM_DIR`) and the contents of the buffer are no longer a
//! complete account; `notify` ignores that completion, so no event, no
//! error and no rescan follows. This watcher turns it into a
//! `Flag::Rescan` event, which the callback in `watcher.rs` records as an
//! overflow (a full index-vs-disk reconciliation).
//!
//! The events are the ones `notify`'s Windows backend produced, so the
//! callback is unchanged: `ADDED` is a create, `REMOVED` a remove,
//! `MODIFIED` a modify, and the two halves of a rename are
//! `Modify(Name(From))` and `Modify(Name(To))`, each on its own.
//!
//! The parsing and the policy (what a completion means) are plain
//! functions over bytes and results and run on every platform; only the
//! handle, the overlapped read and the thread are Windows-only.

use std::path::{Path, PathBuf};

use notify::event::{CreateKind, Flag, ModifyKind, RemoveKind, RenameMode};
use notify::{Event, EventKind};

const FILE_ACTION_ADDED: u32 = 1;
const FILE_ACTION_REMOVED: u32 = 2;
const FILE_ACTION_MODIFIED: u32 = 3;
const FILE_ACTION_RENAMED_OLD_NAME: u32 = 4;
const FILE_ACTION_RENAMED_NEW_NAME: u32 = 5;

/// `ERROR_NOTIFY_ENUM_DIR`: the driver lost changes; the directory must be
/// enumerated.
pub(crate) const ERROR_NOTIFY_ENUM_DIR: i32 = 1022;

/// What one completed read means.
#[derive(Debug)]
pub(crate) struct Translation {
    /// What to hand to the event handler, in order.
    pub results: Vec<notify::Result<Event>>,
    /// The watcher can not continue (the directory is gone, the handle was
    /// refused): the results end with an error and the thread ends.
    pub terminal: bool,
}

/// The event that says changes were lost and everything must be looked at.
pub(crate) fn rescan_event(root: &Path) -> Event {
    Event::new(EventKind::Other).add_path(root.to_path_buf()).set_flag(Flag::Rescan)
}

/// Whether a result from the watcher means changes may have been lost: a
/// rescan request, or an error (nothing says what the error cost).
pub(crate) fn result_means_changes_were_lost(result: &notify::Result<Event>) -> bool {
    match result {
        Ok(event) => event.need_rescan(),
        Err(_) => true,
    }
}

/// Reads the completion of one `ReadDirectoryChangesW`: `Ok(n)` is `n`
/// bytes in `buffer`, `Err(code)` the OS error. Zero bytes and
/// `ERROR_NOTIFY_ENUM_DIR` are an overflow; a buffer that does not parse is
/// treated as one too. Any other error ends the watcher.
pub(crate) fn translate_completion(
    root: &Path,
    outcome: Result<u32, i32>,
    buffer: &[u8],
    name_to_path: impl Fn(&[u16]) -> PathBuf,
) -> Translation {
    match outcome {
        Ok(0) | Err(ERROR_NOTIFY_ENUM_DIR) => {
            Translation { results: vec![Ok(rescan_event(root))], terminal: false }
        }
        Err(code) => Translation {
            results: vec![Err(notify::Error::generic(&format!(
                "ReadDirectoryChangesW failed with OS error {code}"
            )))],
            terminal: true,
        },
        Ok(returned) => {
            let Some(bytes) = buffer.get(..returned as usize) else {
                return Translation { results: vec![Ok(rescan_event(root))], terminal: false };
            };
            match parse_notifications(bytes) {
                Some(entries) => Translation {
                    results: entries
                        .into_iter()
                        .filter_map(|(action, name)| {
                            event_for(action, root.join(name_to_path(&name))).map(Ok)
                        })
                        .collect(),
                    terminal: false,
                },
                None => Translation { results: vec![Ok(rescan_event(root))], terminal: false },
            }
        }
    }
}

/// The `FILE_NOTIFY_INFORMATION` chain in `bytes`: `NextEntryOffset`,
/// `Action`, `FileNameLength` (bytes), then the UTF-16 name relative to the
/// watched directory. `None` when the chain is malformed (an entry that
/// runs past the data, or an offset that does not advance).
pub(crate) fn parse_notifications(bytes: &[u8]) -> Option<Vec<(u32, Vec<u16>)>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    loop {
        let header = bytes.get(offset..offset.checked_add(12)?)?;
        let next = u32::from_le_bytes(header[0..4].try_into().ok()?) as usize;
        let action = u32::from_le_bytes(header[4..8].try_into().ok()?);
        let length = u32::from_le_bytes(header[8..12].try_into().ok()?) as usize;
        let start = offset + 12;
        let name = bytes.get(start..start.checked_add(length)?)?;
        if name.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> =
            name.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
        entries.push((action, units));
        if next == 0 {
            return Some(entries);
        }
        offset = offset.checked_add(next)?;
    }
}

fn event_for(action: u32, path: PathBuf) -> Option<Event> {
    let kind = match action {
        FILE_ACTION_ADDED => EventKind::Create(CreateKind::Any),
        FILE_ACTION_REMOVED => EventKind::Remove(RemoveKind::Any),
        FILE_ACTION_MODIFIED => EventKind::Modify(ModifyKind::Any),
        FILE_ACTION_RENAMED_OLD_NAME => EventKind::Modify(ModifyKind::Name(RenameMode::From)),
        FILE_ACTION_RENAMED_NEW_NAME => EventKind::Modify(ModifyKind::Name(RenameMode::To)),
        _ => return None,
    };
    Some(Event::new(kind).add_path(path))
}

#[cfg(windows)]
pub(crate) use os::RootWatcher;

#[cfg(windows)]
pub(crate) mod os {
    use std::ffi::c_void;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::Arc;

    use notify::{Config, EventHandler, RecursiveMode, Watcher, WatcherKind};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
        FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION,
        FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
        FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    use super::{rescan_event, translate_completion, ERROR_NOTIFY_ENUM_DIR};

    /// The buffer one read fills. Larger than `notify`'s 16 KB: the whole
    /// tree reports through it.
    const BUFFER_BYTES: usize = 64 * 1024;
    /// How often a re-arm refused with an overflow is retried before the
    /// watcher gives up.
    const REARM_ATTEMPTS: usize = 8;

    fn wide_to_path(units: &[u16]) -> std::path::PathBuf {
        use std::os::windows::ffi::OsStringExt;
        std::path::PathBuf::from(std::ffi::OsString::from_wide(units))
    }

    /// The read the watcher has outstanding: the buffer the driver fills and
    /// the `OVERLAPPED` it completes through, at one address from the first
    /// arming to the end. Dropping it cancels a read still queued and waits
    /// for the driver to finish with the memory before the event is closed
    /// and the buffer freed.
    struct Armed {
        handle: isize,
        overlapped: Box<OVERLAPPED>,
        buffer: Vec<u8>,
        /// Whether a read is queued and not yet completed.
        pending: bool,
        /// Whether the read covers the subtree (the `bWatchSubtree` argument).
        subtree: i32,
        /// Test-only: the error code the next `arm` fails with, once.
        fault: Arc<AtomicI32>,
    }

    // SAFETY: the pointers inside `OVERLAPPED` (the event handle) are used
    // by one thread at a time: the caller of `watch` until it has armed,
    // the watcher thread after.
    unsafe impl Send for Armed {}

    impl Armed {
        /// Queues the next read; changes made from now on are held by the
        /// directory handle until it completes. `Err` is the OS error code.
        fn arm(&mut self) -> Result<(), i32> {
            let injected = self.fault.swap(0, Ordering::SeqCst);
            if injected != 0 {
                return Err(injected);
            }
            // SAFETY: the event is open; `buffer` and `overlapped` outlive
            // the read (`Drop` cancels it and waits for it first, and the
            // box is not moved).
            let queued = unsafe {
                ResetEvent(self.overlapped.hEvent);
                ReadDirectoryChangesW(
                    self.handle as HANDLE,
                    self.buffer.as_mut_ptr().cast::<c_void>(),
                    self.buffer.len() as u32,
                    self.subtree,
                    FILE_NOTIFY_CHANGE_FILE_NAME
                        | FILE_NOTIFY_CHANGE_DIR_NAME
                        | FILE_NOTIFY_CHANGE_ATTRIBUTES
                        | FILE_NOTIFY_CHANGE_SIZE
                        | FILE_NOTIFY_CHANGE_LAST_WRITE
                        | FILE_NOTIFY_CHANGE_CREATION
                        | FILE_NOTIFY_CHANGE_SECURITY,
                    std::ptr::null_mut(),
                    &mut *self.overlapped,
                    None,
                ) != 0
            };
            if queued {
                self.pending = true;
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
            }
        }

        /// Waits for the queued read to complete; `Err` is the OS error code.
        fn wait(&mut self) -> Result<u32, i32> {
            let mut returned = 0u32;
            // SAFETY: the handle is open for as long as this value lives;
            // `overlapped` is the one the read was queued with.
            let ok = unsafe {
                GetOverlappedResult(self.handle as HANDLE, &*self.overlapped, &mut returned, 1)
            };
            // Completed, with data or with an error: the driver is done
            // with the buffer.
            self.pending = false;
            if ok == 0 {
                Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
            } else {
                Ok(returned)
            }
        }
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            // SAFETY: the handle is still open (`RootWatcher` closes it only
            // after the worker has ended); after the cancelled read is
            // waited out nothing refers to the event, the buffer or the
            // `OVERLAPPED` any more.
            unsafe {
                if self.pending {
                    CancelIoEx(self.handle as HANDLE, &*self.overlapped);
                    let mut returned = 0u32;
                    GetOverlappedResult(self.handle as HANDLE, &*self.overlapped, &mut returned, 1);
                }
                CloseHandle(self.overlapped.hEvent);
            }
        }
    }

    /// Watches one root, once. Dropping it stops the thread and closes the
    /// handle.
    pub(crate) struct RootWatcher {
        handler: Option<Box<dyn EventHandler>>,
        buffer_bytes: usize,
        fault: Arc<AtomicI32>,
        running: Option<Running>,
    }

    struct Running {
        handle: isize,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl RootWatcher {
        /// Test-only: a watcher whose read buffer is `buffer_bytes`, and the
        /// cell through which the next re-arm can be made to fail.
        #[cfg(test)]
        pub(crate) fn with_buffer<F: EventHandler>(
            handler: F,
            buffer_bytes: usize,
        ) -> (Self, Arc<AtomicI32>) {
            let fault = Arc::new(AtomicI32::new(0));
            (
                Self {
                    handler: Some(Box::new(handler)),
                    buffer_bytes,
                    fault: fault.clone(),
                    running: None,
                },
                fault,
            )
        }
    }

    impl Watcher for RootWatcher {
        fn new<F: EventHandler>(handler: F, _config: Config) -> notify::Result<Self> {
            Ok(Self {
                handler: Some(Box::new(handler)),
                buffer_bytes: BUFFER_BYTES,
                fault: Arc::default(),
                running: None,
            })
        }

        /// Starts watching `root`; the first read is queued before this
        /// returns, so a change made right after it is not lost. A
        /// `RootWatcher` watches one directory, once.
        fn watch(&mut self, root: &Path, mode: RecursiveMode) -> notify::Result<()> {
            use std::os::windows::ffi::OsStrExt;
            let Some(mut handler) = self.handler.take() else {
                return Err(notify::Error::generic("the root is already watched"));
            };
            let subtree = i32::from(mode == RecursiveMode::Recursive);
            let name: Vec<u16> = yadorilink_fs_platform::long_path::for_win32(root)
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: `name` is NUL-terminated.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                    std::ptr::null_mut(),
                )
            };
            if handle as isize == -1 {
                return Err(notify::Error::io(std::io::Error::last_os_error()));
            }
            let handle = handle as isize;
            // A manual-reset event the driver sets when a read completes.
            // SAFETY: no arguments need to outlive the call.
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if event.is_null() {
                let error = std::io::Error::last_os_error();
                // SAFETY: the handle was just opened and nothing else holds it.
                unsafe { CloseHandle(handle as HANDLE) };
                return Err(notify::Error::io(error));
            }
            // SAFETY: an all-zero `OVERLAPPED` is the documented initial state.
            let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
            overlapped.hEvent = event;
            // From here `armed` owns the event, and cancels and waits out a
            // queued read when dropped.
            let mut armed = Armed {
                handle,
                overlapped,
                buffer: vec![0u8; self.buffer_bytes],
                pending: false,
                subtree,
                fault: self.fault.clone(),
            };
            if let Err(code) = armed.arm() {
                drop(armed);
                // SAFETY: nothing else holds the handle.
                unsafe { CloseHandle(handle as HANDLE) };
                return Err(notify::Error::io(std::io::Error::from_raw_os_error(code)));
            }
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            let base = root.to_path_buf();
            let spawned = std::thread::Builder::new()
                .name("yadorilink-fs-watch".into())
                .spawn(move || run(armed, &base, &stopping, &mut *handler));
            match spawned {
                Ok(thread) => {
                    self.running = Some(Running { handle, stop, thread: Some(thread) });
                    Ok(())
                }
                Err(error) => {
                    // The closure, and the `Armed` in it, is gone: its read
                    // was cancelled and waited out.
                    // SAFETY: nothing else holds the handle.
                    unsafe { CloseHandle(handle as HANDLE) };
                    Err(notify::Error::io(error))
                }
            }
        }

        fn unwatch(&mut self, _path: &Path) -> notify::Result<()> {
            self.running = None;
            Ok(())
        }

        fn configure(&mut self, _option: Config) -> notify::Result<bool> {
            Ok(false)
        }

        fn kind() -> WatcherKind {
            WatcherKind::ReadDirectoryChangesWatcher
        }
    }

    /// The watcher thread: wait for a read, translate it, queue the next
    /// read, hand the results on. The completed bytes are translated before
    /// the buffer is queued again, and the next read is queued before the
    /// handler runs, so its duration is not a blind window.
    fn run(mut armed: Armed, base: &Path, stopping: &AtomicBool, handler: &mut dyn EventHandler) {
        while !stopping.load(Ordering::SeqCst) {
            let outcome = armed.wait();
            if stopping.load(Ordering::SeqCst) {
                return;
            }
            let translation = translate_completion(base, outcome, &armed.buffer, wide_to_path);
            let mut rearmed = if translation.terminal { Ok(()) } else { armed.arm() };
            for result in translation.results {
                handler.handle_event(result);
            }
            if translation.terminal {
                return;
            }
            // A re-arm the driver refuses because it lost changes is itself
            // an overflow: the handler is told, and the read is queued
            // again. Any other refusal ends the watcher, loudly.
            for _ in 0..REARM_ATTEMPTS {
                match rearmed {
                    Ok(()) => break,
                    Err(ERROR_NOTIFY_ENUM_DIR) => {
                        handler.handle_event(Ok(rescan_event(base)));
                        rearmed = armed.arm();
                    }
                    Err(code) => {
                        handler.handle_event(Err(notify::Error::generic(&format!(
                            "ReadDirectoryChangesW could not be queued again: OS error {code}"
                        ))));
                        return;
                    }
                }
            }
            if rearmed.is_err() {
                handler.handle_event(Err(notify::Error::generic(
                    "ReadDirectoryChangesW kept overflowing while being queued again",
                )));
                return;
            }
        }
    }

    impl Drop for RootWatcher {
        fn drop(&mut self) {
            let Some(mut running) = self.running.take() else { return };
            running.stop.store(true, Ordering::SeqCst);
            // The worker may be just short of submitting its blocking read,
            // where a cancel finds nothing to cancel; cancelling again until
            // it has ended covers that window.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            let thread = running.thread.take();
            while thread.as_ref().is_some_and(|t| !t.is_finished())
                && std::time::Instant::now() < deadline
            {
                // SAFETY: `handle` is the open directory handle; cancelling
                // wakes a blocked read.
                unsafe { CancelIoEx(running.handle as HANDLE, std::ptr::null()) };
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            match thread {
                Some(thread) if thread.is_finished() => {
                    let _ = thread.join();
                    // SAFETY: the thread that used the handle has ended.
                    unsafe { CloseHandle(running.handle as HANDLE) };
                }
                // Still blocked after the deadline: the handle stays open
                // with it rather than being closed under a running read.
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(next: u32, action: u32, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&next.to_le_bytes());
        bytes.extend_from_slice(&action.to_le_bytes());
        bytes.extend_from_slice(&((units.len() * 2) as u32).to_le_bytes());
        for unit in units {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn to_path(units: &[u16]) -> PathBuf {
        PathBuf::from(String::from_utf16_lossy(units))
    }

    fn translate(outcome: Result<u32, i32>, buffer: &[u8]) -> Translation {
        translate_completion(Path::new("/r"), outcome, buffer, to_path)
    }

    fn is_rescan(result: &notify::Result<Event>) -> bool {
        matches!(result, Ok(event) if event.need_rescan())
    }

    #[test]
    fn a_zero_byte_completion_is_an_overflow_that_asks_for_a_rescan() {
        let translation = translate(Ok(0), &[0u8; 64]);
        assert!(!translation.terminal);
        assert_eq!(translation.results.len(), 1);
        assert!(is_rescan(&translation.results[0]));
        assert!(result_means_changes_were_lost(&translation.results[0]));
    }

    #[test]
    fn error_notify_enum_dir_is_an_overflow_that_asks_for_a_rescan() {
        let translation = translate(Err(ERROR_NOTIFY_ENUM_DIR), &[]);
        assert!(!translation.terminal);
        assert!(is_rescan(&translation.results[0]));
    }

    #[test]
    fn any_other_error_ends_the_watcher_with_an_error_that_counts_as_lost_changes() {
        let translation = translate(Err(5), &[]);
        assert!(translation.terminal);
        assert!(translation.results[0].is_err());
        assert!(result_means_changes_were_lost(&translation.results[0]));
    }

    #[test]
    fn a_malformed_chain_asks_for_a_rescan() {
        // A name that runs past the bytes returned.
        let mut bytes = entry(0, FILE_ACTION_ADDED, "abc");
        bytes.truncate(bytes.len() - 2);
        let n = bytes.len() as u32;
        let translation = translate(Ok(n), &bytes);
        assert!(is_rescan(&translation.results[0]));
        // More bytes claimed than the buffer holds.
        let translation = translate(Ok(100), &[0u8; 16]);
        assert!(is_rescan(&translation.results[0]));
    }

    #[test]
    fn a_normal_completion_gives_one_event_per_entry_with_notifys_kinds() {
        let mut first = entry(0, FILE_ACTION_RENAMED_OLD_NAME, "a.txt");
        while !first.len().is_multiple_of(4) {
            first.push(0);
        }
        let next = first.len() as u32;
        first[0..4].copy_from_slice(&next.to_le_bytes());
        let mut bytes = first;
        bytes.extend(entry(0, FILE_ACTION_RENAMED_NEW_NAME, "sub\\b.txt"));
        let n = bytes.len() as u32;

        let translation = translate(Ok(n), &bytes);
        assert!(!translation.terminal);
        let events: Vec<Event> = translation.results.into_iter().map(Result::unwrap).collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, EventKind::Modify(ModifyKind::Name(RenameMode::From)));
        assert_eq!(events[0].paths, vec![PathBuf::from("/r").join("a.txt")]);
        assert_eq!(events[1].kind, EventKind::Modify(ModifyKind::Name(RenameMode::To)));
        assert_eq!(events[1].paths, vec![PathBuf::from("/r").join("sub\\b.txt")]);
        assert!(events.iter().all(|event| !event.need_rescan()));
    }

    #[test]
    fn added_removed_and_modified_map_to_create_remove_and_modify() {
        for (action, kind) in [
            (FILE_ACTION_ADDED, EventKind::Create(CreateKind::Any)),
            (FILE_ACTION_REMOVED, EventKind::Remove(RemoveKind::Any)),
            (FILE_ACTION_MODIFIED, EventKind::Modify(ModifyKind::Any)),
        ] {
            let bytes = entry(0, action, "f");
            let translation = translate(Ok(bytes.len() as u32), &bytes);
            assert_eq!(translation.results.into_iter().next().unwrap().unwrap().kind, kind);
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use notify::{RecursiveMode, Watcher};
    use std::sync::mpsc::{channel, Receiver};
    use std::sync::Arc;
    use std::time::Duration;

    fn drain_for_rescan(rx: &Receiver<notify::Result<Event>>, within: Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        while std::time::Instant::now() < deadline {
            if let Ok(result) = rx.recv_timeout(Duration::from_millis(100)) {
                if result_means_changes_were_lost(&result) {
                    return true;
                }
            }
        }
        false
    }

    /// A burst of changes that does not fit the buffer reports a rescan
    /// (`notify` 8 reported nothing).
    #[test]
    fn a_burst_larger_than_the_buffer_reports_a_rescan() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (tx, rx) = channel();
        // The handler is blocked until the burst is made, so the driver's
        // buffer (256 bytes: a few entries) cannot keep up.
        let gate = Arc::new(std::sync::Barrier::new(2));
        let handler_gate = gate.clone();
        let first = std::sync::atomic::AtomicBool::new(true);
        let (mut watcher, _fault) = os::RootWatcher::with_buffer(
            move |result: notify::Result<Event>| {
                if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    handler_gate.wait();
                }
                let _ = tx.send(result);
            },
            256,
        );
        watcher.watch(&root, RecursiveMode::Recursive).unwrap();

        std::fs::write(root.join("first.txt"), b"x").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        for i in 0..400 {
            std::fs::write(root.join(format!("burst-with-a-long-file-name-{i}.txt")), b"x")
                .unwrap();
        }
        gate.wait();
        assert!(
            drain_for_rescan(&rx, Duration::from_secs(10)),
            "an overflowed buffer must be reported as lost changes"
        );
    }

    /// A refused re-arm that is not an overflow ends the watcher with an
    /// error the callback counts as lost changes.
    #[test]
    fn a_failed_rearm_is_reported_as_lost_changes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let (tx, rx) = channel();
        let (mut watcher, fault) = os::RootWatcher::with_buffer(
            move |result: notify::Result<Event>| {
                let _ = tx.send(result);
            },
            64 * 1024,
        );
        watcher.watch(&root, RecursiveMode::Recursive).unwrap();
        fault.store(5, std::sync::atomic::Ordering::SeqCst);
        std::fs::write(root.join("a.txt"), b"x").unwrap();
        assert!(drain_for_rescan(&rx, Duration::from_secs(10)));
    }

    /// An ordinary change below the root arrives as an event with its path.
    #[test]
    fn a_change_below_the_root_is_reported_with_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let (tx, rx) = channel();
        let mut watcher = os::RootWatcher::new(
            move |result: notify::Result<Event>| {
                let _ = tx.send(result);
            },
            notify::Config::default(),
        )
        .unwrap();
        watcher.watch(&root, RecursiveMode::Recursive).unwrap();
        let file = root.join("sub").join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut seen = false;
        while std::time::Instant::now() < deadline && !seen {
            if let Ok(Ok(event)) = rx.recv_timeout(Duration::from_millis(100)) {
                seen = event.paths.contains(&file);
            }
        }
        assert!(seen, "the create below the root was not reported");
    }
}
