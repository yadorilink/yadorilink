//! A recursive directory watcher, used purely as a SIGNAL source.
//!
//! `ReadDirectoryChangesW` says that something happened at a path (created, changed, renamed,
//! removed); it is not trusted to say what. Whoever receives the signal looks at the path and at
//! the provider state and decides. When the watcher cannot keep up (the buffer overflowed, the
//! driver returned nothing) it says so with [`Signal::Overflow`] and the receiver must look at
//! everything.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
    FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

pub use yadorilink_windows_provider_policy::host::Signal;

/// A running watcher. Dropping it stops the thread.
pub struct Watch {
    handle: isize,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

const BUFFER_BYTES: usize = 64 * 1024;
const ERROR_NOTIFY_ENUM_DIR: i32 = 1022;
/// How often a re-arm refused with an overflow is retried before the watcher gives up.
const REARM_ATTEMPTS: usize = 8;

/// The read the watcher has outstanding: the buffer the driver fills and the `OVERLAPPED` it
/// completes through, at one address from the first arming to the end. Dropping it cancels a
/// read still queued and waits for the driver to finish with the memory before the event is
/// closed and the buffer freed, on every way out of the worker (and of a failed spawn).
struct Armed {
    handle: isize,
    overlapped: Box<OVERLAPPED>,
    buffer: Vec<u8>,
    /// Whether a read is queued and not yet completed.
    pending: bool,
    /// Test-only: the error code the next `arm` fails with, once.
    fault: Arc<std::sync::atomic::AtomicI32>,
}

// SAFETY: the pointers inside `OVERLAPPED` (the event handle) are used by one thread at a time:
// the caller of `watch` until it has armed, the watcher thread after.
unsafe impl Send for Armed {}

impl Armed {
    /// Queues the next read; changes made from now on are held by the directory handle until it
    /// completes, so none falls between one read and the next. `Err` is the OS error code.
    fn arm(&mut self) -> Result<(), i32> {
        let injected = self.fault.swap(0, Ordering::SeqCst);
        if injected != 0 {
            return Err(injected);
        }
        // SAFETY: the event is open; `buffer` and `overlapped` outlive the read (`Drop` cancels
        // it and waits for it first, and the box is not moved).
        let queued = unsafe {
            ResetEvent(self.overlapped.hEvent);
            ReadDirectoryChangesW(
                self.handle as HANDLE,
                self.buffer.as_mut_ptr().cast::<c_void>(),
                self.buffer.len() as u32,
                1,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
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
        // SAFETY: the handle is open for as long as this value lives; `overlapped` is the one
        // the read was queued with.
        let ok = unsafe {
            GetOverlappedResult(self.handle as HANDLE, &*self.overlapped, &mut returned, 1)
        };
        // Completed, with data or with an error: the driver is done with the buffer.
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
        // SAFETY: the handle is still open (`Watch` closes it only after the worker has ended);
        // after the cancelled read is waited out nothing refers to the event, the buffer or the
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

/// Starts watching `root` and everything below it; `on_signal` is called from the watcher's own
/// thread and returns `false` to stop it. The first read is queued before this returns, so a
/// change made right after it is not lost.
pub fn watch(
    root: &Path,
    on_signal: impl Fn(Signal) -> bool + Send + 'static,
) -> std::io::Result<Watch> {
    start(root, on_signal, Arc::default())
}

fn start(
    root: &Path,
    on_signal: impl Fn(Signal) -> bool + Send + 'static,
    fault: Arc<std::sync::atomic::AtomicI32>,
) -> std::io::Result<Watch> {
    use std::os::windows::ffi::OsStrExt;
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
        return Err(std::io::Error::last_os_error());
    }
    let handle = handle as isize;
    // A manual-reset event the driver sets when a read completes.
    // SAFETY: no arguments need to outlive the call.
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: the handle was just opened and nothing else holds it.
        unsafe { CloseHandle(handle as HANDLE) };
        return Err(error);
    }
    // SAFETY: an all-zero `OVERLAPPED` is the documented initial state.
    let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
    overlapped.hEvent = event;
    // From here `armed` owns the event, and cancels and waits out a queued read when dropped.
    let mut armed =
        Armed { handle, overlapped, buffer: vec![0u8; BUFFER_BYTES], pending: false, fault };
    if let Err(code) = armed.arm() {
        drop(armed);
        // SAFETY: nothing else holds the handle.
        unsafe { CloseHandle(handle as HANDLE) };
        return Err(std::io::Error::from_raw_os_error(code));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let base = root.to_path_buf();
    let spawned =
        std::thread::Builder::new().name("yadorilink-dir-watch".into()).spawn(move || {
            let mut armed = armed;
            while !stopping.load(Ordering::SeqCst) {
                let result = armed.wait();
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let signal = match result {
                    Err(ERROR_NOTIFY_ENUM_DIR) | Ok(0) => Signal::Overflow,
                    // The directory went away or the handle was cancelled: nothing more to say.
                    Err(_) => break,
                    Ok(returned) => Signal::Paths(parse(&armed.buffer[..returned as usize], &base)),
                };
                // Queued again before the callback runs, so its duration is not a blind window.
                let mut rearmed = armed.arm();
                if !on_signal(signal) {
                    break;
                }
                // A re-arm the driver refuses because it lost changes is itself an overflow: the
                // receiver looks at everything, and the read is queued again.
                for _ in 0..REARM_ATTEMPTS {
                    match rearmed {
                        Ok(()) => break,
                        Err(ERROR_NOTIFY_ENUM_DIR) => {
                            if !on_signal(Signal::Overflow) {
                                return;
                            }
                            rearmed = armed.arm();
                        }
                        Err(_) => return,
                    }
                }
                if rearmed.is_err() {
                    return;
                }
            }
        });
    match spawned {
        Ok(thread) => Ok(Watch { handle, stop, thread: Some(thread) }),
        Err(error) => {
            // The closure, and the `Armed` in it, is gone: its read was cancelled and waited out.
            // SAFETY: nothing else holds the handle.
            unsafe { CloseHandle(handle as HANDLE) };
            Err(error)
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // The worker may be just short of submitting its blocking read, where a cancel finds
        // nothing to cancel; cancelling again until it has ended covers that window.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let thread = self.thread.take();
        while thread.as_ref().is_some_and(|t| !t.is_finished())
            && std::time::Instant::now() < deadline
        {
            // SAFETY: `handle` is the open directory handle; cancelling wakes a blocked read.
            unsafe { CancelIoEx(self.handle as HANDLE, std::ptr::null()) };
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        match thread {
            Some(thread) if thread.is_finished() => {
                let _ = thread.join();
                // SAFETY: the thread that used the handle has ended.
                unsafe { CloseHandle(self.handle as HANDLE) };
            }
            // Still blocked after the deadline: the handle stays open with it rather than being
            // closed under a running read.
            _ => {}
        }
    }
}

/// The paths in one `FILE_NOTIFY_INFORMATION` chain: `NextEntryOffset`, `Action`,
/// `FileNameLength` (bytes), then the UTF-16 name relative to the watched directory.
fn parse(buffer: &[u8], base: &Path) -> Vec<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut paths = Vec::new();
    let mut offset = 0usize;
    while let Some(header) = buffer.get(offset..offset + 12) {
        let next = u32::from_le_bytes(header[0..4].try_into().expect("4 bytes")) as usize;
        let length = u32::from_le_bytes(header[8..12].try_into().expect("4 bytes")) as usize;
        let Some(name) = buffer.get(offset + 12..offset + 12 + length) else { break };
        let units: Vec<u16> = (0..name.len() / 2)
            .map(|i| u16::from_le_bytes([name[2 * i], name[2 * i + 1]]))
            .collect();
        paths.push(base.join(std::ffi::OsString::from_wide(&units)));
        if next == 0 {
            break;
        }
        offset += next;
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("yl-watch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn collect(rx: &std::sync::mpsc::Receiver<Signal>, want: &Path) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if let Ok(Signal::Paths(paths)) = rx.recv_timeout(Duration::from_millis(200)) {
                if paths.iter().any(|p| p == want) {
                    return true;
                }
            }
        }
        false
    }

    /// Create, modify, rename and delete anywhere below the root are all signalled with the
    /// paths involved (both names of a rename).
    #[test]
    fn changes_below_the_root_are_signalled_with_their_paths() {
        let dir = temp("signals");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let (tx, rx) = channel();
        let _watch = watch(&dir, move |signal| tx.send(signal).is_ok()).unwrap();

        let file = dir.join("sub").join("a.txt");
        std::fs::write(&file, b"one").unwrap();
        assert!(collect(&rx, &file), "create was not signalled");
        std::fs::write(&file, b"two").unwrap();
        assert!(collect(&rx, &file), "modify was not signalled");
        let renamed = dir.join("b.txt");
        std::fs::rename(&file, &renamed).unwrap();
        assert!(collect(&rx, &renamed), "the new name of a rename was not signalled");
        std::fs::remove_file(&renamed).unwrap();
        assert!(collect(&rx, &renamed), "delete was not signalled");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A change made the moment `watch` returns is signalled: the watcher is armed before it
    /// hands control back, not some moments later on its own thread.
    #[test]
    fn a_change_made_as_soon_as_watch_returns_is_signalled() {
        let mut missed = 0;
        for round in 0..200 {
            let dir = temp(&format!("armed-{round}"));
            let (tx, rx) = channel();
            let _watch = watch(&dir, move |signal| tx.send(signal).is_ok()).unwrap();
            let file = dir.join("first.txt");
            std::fs::write(&file, b"x").unwrap();
            let seen = (0..10).any(|_| {
                matches!(rx.recv_timeout(Duration::from_millis(100)), Ok(Signal::Paths(p)) if p.contains(&file))
            });
            if !seen {
                missed += 1;
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
        assert_eq!(missed, 0, "{missed} of 200 first changes were never signalled");
    }

    /// A callback that asks to stop, followed at once by the drop of the watch: the worker's
    /// last queued read is cancelled and waited out before its memory goes, every time.
    #[test]
    fn stopping_from_the_callback_and_dropping_at_once_is_clean() {
        for round in 0..100 {
            let dir = temp(&format!("stopcb-{round}"));
            let (tx, rx) = channel();
            let watch = watch(&dir, move |signal| {
                let _ = tx.send(signal);
                false
            })
            .unwrap();
            std::fs::write(dir.join("x.txt"), b"x").unwrap();
            assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
            let started = std::time::Instant::now();
            drop(watch);
            assert!(started.elapsed() < Duration::from_secs(2), "drop waited out its deadline");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// A re-arm the driver refuses with an overflow is reported as one, and the watcher keeps
    /// signalling afterwards.
    #[test]
    fn a_refused_rearm_is_an_overflow_and_the_watch_goes_on() {
        let dir = temp("rearm");
        let (tx, rx) = channel();
        let fault = Arc::new(std::sync::atomic::AtomicI32::new(0));
        let _watch = start(&dir, move |signal| tx.send(signal).is_ok(), fault.clone()).unwrap();
        fault.store(ERROR_NOTIFY_ENUM_DIR, Ordering::SeqCst);
        std::fs::write(dir.join("one.txt"), b"1").unwrap();
        let mut overflowed = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !overflowed && std::time::Instant::now() < deadline {
            overflowed =
                matches!(rx.recv_timeout(Duration::from_millis(200)), Ok(Signal::Overflow));
        }
        assert!(overflowed, "the refused re-arm was not reported as an overflow");
        let two = dir.join("two.txt");
        std::fs::write(&two, b"2").unwrap();
        assert!(collect(&rx, &two), "the watch stopped after the overflow");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dropping_the_watcher_stops_it() {
        let dir = temp("drop");
        let (tx, rx) = channel();
        let watch = watch(&dir, move |signal| tx.send(signal).is_ok()).unwrap();
        drop(watch);
        std::fs::write(dir.join("late.txt"), b"x").unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_notification_chain_is_parsed_into_paths() {
        let entry = |name: &str, next: u32| {
            let units: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&next.to_le_bytes());
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&(units.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&units);
            bytes
        };
        let mut first = entry("a.txt", 0);
        while first.len() % 4 != 0 {
            first.push(0);
        }
        let next = first.len() as u32;
        first[0..4].copy_from_slice(&next.to_le_bytes());
        first.extend(entry("sub\\日本語.txt", 0));
        let paths = parse(&first, Path::new(r"C:\root"));
        assert_eq!(
            paths,
            vec![PathBuf::from(r"C:\root\a.txt"), PathBuf::from(r"C:\root\sub\日本語.txt")]
        );
    }
}
