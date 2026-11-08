//! A change of a placeholder's pin mark reaches the directory watcher, on a real sync root.
//!
//! The host learns that the person pinned or unpinned an item in the file manager from this signal,
//! so it has to arrive for the route the file manager takes (the attribute word set on the file) as
//! well as for the platform call the host itself uses. Each step waits for the event with a bound
//! that only limits a failing run.
//!
//! Skipped where a sync root cannot be registered (no Cloud Files API, no permission).
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use yadorilink_fs_platform::cloud_files::{self, PinMark};
use yadorilink_fs_platform::durable_dir::NoLedger;
use yadorilink_shell_ext::cfapi;
use yadorilink_shell_ext::dir_watch::{watch, Signal};
use yadorilink_shell_ext::provider_namespace::{pin, PinWish};

fn set_attributes(path: &Path, attributes: u32) {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: NUL-terminated and outlives the call.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::SetFileAttributesW(wide.as_ptr(), attributes)
    };
    assert_ne!(ok, 0, "SetFileAttributesW failed");
}

/// Waits until the watcher names `file`, or fails after the bound.
fn named(rx: &Receiver<Signal>, file: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(left) {
            Ok(Signal::Paths(paths)) if paths.iter().any(|p| p == file) => return,
            Ok(Signal::Overflow) => return, // the receiver looks at everything then
            Ok(_) => {}
            Err(_) => panic!("the watcher never named {} after a pin change", file.display()),
        }
    }
}

#[test]
fn a_pin_change_made_by_the_host_or_by_the_file_manager_is_signalled_with_the_path() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let root: PathBuf =
        std::env::temp_dir().join(format!("yl-pinwatch-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    if let Err(error) = cfapi::register_and_connect(&root) {
        eprintln!("skipped: cannot register a Cloud Files sync root here: {error}");
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    cfapi::create_item_placeholder(&NoLedger, &root, "a.bin", b"item-a", 4096, 0, false).unwrap();
    let file = root.join("a.bin");
    let (tx, rx) = mpsc::channel();
    let _watch = watch(&root, move |signal| {
        let _ = tx.send(signal);
        true
    })
    .unwrap();
    let mark = || cloud_files::pin_mark(cloud_files::attributes_of(&file).unwrap());
    let drain =
        |rx: &Receiver<Signal>| while rx.recv_timeout(Duration::from_millis(300)).is_ok() {};
    drain(&rx);

    // The host's own call.
    pin(&file, Some(b"item-a"), PinWish::Keep);
    assert_eq!(mark(), PinMark::Pinned);
    named(&rx, &file);
    drain(&rx);

    // The file manager's route: the attribute word on the file itself, each way round.
    let current = || cloud_files::attributes_of(&file).unwrap();
    set_attributes(&file, (current() | cloud_files::UNPINNED) & !cloud_files::PINNED);
    assert_eq!(mark(), PinMark::Unpinned);
    named(&rx, &file);
    drain(&rx);
    set_attributes(&file, (current() | cloud_files::PINNED) & !cloud_files::UNPINNED);
    assert_eq!(mark(), PinMark::Pinned);
    named(&rx, &file);
    drain(&rx);
    set_attributes(&file, current() & !(cloud_files::PINNED | cloud_files::UNPINNED));
    assert_eq!(mark(), PinMark::Unset);
    named(&rx, &file);

    drop(_watch);
    let _ = cfapi::unregister(&root);
    let _ = std::fs::remove_dir_all(&root);
}
