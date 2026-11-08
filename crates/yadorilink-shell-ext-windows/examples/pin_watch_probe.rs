//! Whether a change of a placeholder's pin mark raises a directory-change notification, on a real
//! Cloud Files sync root, and what else the same change raises.
//!
//! The host would learn that the person pinned or unpinned an item in Explorer from the directory
//! watcher; this checks that it can. For one dehydrated placeholder it sets and clears the marks
//! in turn, by the platform call the host itself uses (`CfSetPinState`) and by setting the attribute
//! word on the file (what Explorer's menu ends in), and prints every path the watcher reports within a second of each.
//!
//! Windows only:
//!
//! ```text
//! cargo run --example pin_watch_probe -- C:\path\to\a\new\empty\directory
//! ```

#[cfg(not(windows))]
fn main() {
    eprintln!("this probe needs Windows and the Cloud Files API");
}

#[cfg(windows)]
fn main() {
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;

    use yadorilink_fs_platform::cloud_files;
    use yadorilink_fs_platform::durable_dir::NoLedger;
    use yadorilink_shell_ext::cfapi;
    use yadorilink_shell_ext::dir_watch::{watch, Signal};
    use yadorilink_shell_ext::provider_namespace::{pin, PinWish};

    let Some(root) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage: pin_watch_probe <new empty directory>");
        return;
    };
    std::fs::create_dir_all(&root).expect("create the root");
    cfapi::register_and_connect(&root).expect("register the sync root");
    cfapi::create_item_placeholder(&NoLedger, &root, "a.bin", b"item-a", 4096, 0, false)
        .expect("create the placeholder");
    let file = root.join("a.bin");

    let (tx, rx) = mpsc::channel();
    let _watch = watch(&root, move |signal| {
        let _ = tx.send(signal);
        true
    })
    .expect("watch the root");
    std::thread::sleep(Duration::from_millis(500));
    while rx.try_recv().is_ok() {}

    let show = |what: &str| {
        let mut seen = Vec::new();
        while let Ok(signal) = rx.recv_timeout(Duration::from_secs(1)) {
            match signal {
                Signal::Paths(paths) => seen.extend(paths.iter().map(|p| p.display().to_string())),
                Signal::Overflow => seen.push("OVERFLOW".into()),
            }
        }
        let mark = cloud_files::attributes_of(&file).map_or_else(
            || "unreadable".into(),
            |a| format!("{a:#010x} {:?}", cloud_files::pin_mark(a)),
        );
        println!("{what}: attributes now {mark}; watcher reported {seen:?}");
    };

    println!("{:?}", pin(&file, Some(b"item-a"), PinWish::Keep));
    show("CfSetPinState keep");
    println!("{:?}", pin(&file, Some(b"item-a"), PinWish::OnlineOnly));
    show("CfSetPinState online only");
    println!("{:?}", pin(&file, Some(b"item-a"), PinWish::Clear));
    show("CfSetPinState clear");
    // What Explorer's menu ends in: the attribute word set on the file itself.
    let set_attributes = |what: &str, attributes: u32| {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = file.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: NUL-terminated and outlives the call.
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::SetFileAttributesW(wide.as_ptr(), attributes)
        };
        println!("SetFileAttributesW {what} ({attributes:#x}) -> {}", ok != 0);
    };
    let current = || cloud_files::attributes_of(&file).unwrap_or(0);
    set_attributes("pinned", (current() | cloud_files::PINNED) & !cloud_files::UNPINNED);
    show("SetFileAttributesW pinned");
    set_attributes("unpinned", (current() | cloud_files::UNPINNED) & !cloud_files::PINNED);
    show("SetFileAttributesW unpinned");
    set_attributes("neither", current() & !(cloud_files::PINNED | cloud_files::UNPINNED));
    show("SetFileAttributesW neither");
    let _ = cfapi::unregister(&root);
    let _ = std::fs::remove_dir_all(&root);
}
