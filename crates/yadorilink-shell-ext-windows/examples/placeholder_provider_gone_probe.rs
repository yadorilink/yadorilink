//! How a Cloud Files sync root behaves once its provider is gone, and what that means for the
//! checked publish.
//!
//! 1. How long after `CfDisconnectSyncRoot` creating a file in the root starts to fail, for an
//!    ordinary name and for a reserved probe name.
//! 2. What a bare `ReplaceFileW` does to a connected, dehydrated placeholder (no attribute
//!    restore after it), to tell the platform's doing from ours.
//! 3. What the daemon's checked publish does to an ordinary file that sits in the root when the
//!    provider is gone (a file the attributes do not mark as a placeholder).
//! 4. What asking "is this path under a registered sync root" costs, and what it answers.
//!
//! Windows only; needs a real Cloud Files sync root (a local NTFS volume):
//!
//! ```text
//! cargo run --example placeholder_provider_gone_probe -- C:\path\to\a\new\empty\directory
//! ```

#[cfg(not(windows))]
fn main() {
    eprintln!("this probe needs Windows and the Cloud Files API");
}

#[cfg(windows)]
fn main() {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use yadorilink_fs_platform::durable_dir::NoLedger;
    use yadorilink_local_storage::{
        persist_reconstructed_file_checked, Durability, NoTempLedger, TargetExpectation,
    };
    use yadorilink_shell_ext::cfapi;

    fn attributes(path: &Path) -> String {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => format!("0x{:08x} len={}", meta.file_attributes(), meta.len()),
            Err(error) => format!("unreadable: {error}"),
        }
    }
    fn listing(dir: &Path) -> String {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|e| {
                e.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        format!("{names:?}")
    }
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    let root: PathBuf = std::env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: placeholder_provider_gone_probe <a new empty directory on NTFS>");
        std::process::exit(2);
    });
    std::fs::create_dir_all(&root).expect("create the sync root directory");
    cfapi::register_and_connect(&root).expect("register and connect the sync root");
    println!("sync root {root:?} registered and connected");

    // Made while connected: a placeholder for the bare ReplaceFileW, an ordinary file for part 3.
    cfapi::create_item_placeholder(&NoLedger, &root, "bare.txt", b"item-bare", 4096, 0, false)
        .expect("placeholder");
    std::fs::write(root.join("bare.txt.staged"), b"the replacement bytes").unwrap();
    std::fs::write(root.join("plain.txt"), b"an ordinary file in the root").unwrap();
    std::fs::write(root.join("plain.txt.staged"), b"the replacement bytes").unwrap();
    println!("\n-- part 4 (connected): is the path under a registered sync root");
    let started = Instant::now();
    let mut answer = String::new();
    for _ in 0..1000 {
        answer = format!("{:?}", cfapi::registered_root_identity(&root.join("plain.txt")));
    }
    println!("   inside the root: {answer}; 1000 calls took {:?}", started.elapsed());
    let outside = std::env::temp_dir().join("yl-outside-the-root.txt");
    std::fs::write(&outside, b"x").unwrap();
    println!("   outside any root: {:?}", cfapi::registered_root_identity(&outside));
    let _ = std::fs::remove_file(&outside);

    println!("\n-- part 2 (connected): a bare ReplaceFileW over the dehydrated placeholder");
    let bare = root.join("bare.txt");
    println!("   before: {}", attributes(&bare));
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::ReplaceFileW(
            wide(&bare).as_ptr(),
            wide(&root.join("bare.txt.staged")).as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    println!("   ReplaceFileW returned {ok} ({})", std::io::Error::last_os_error());
    println!("   after:  {}", attributes(&bare));

    cfapi::disconnect(&root).expect("disconnect the provider");
    println!("\n-- part 1: creating a file in the root, every 5 ms after the disconnect");
    let begun = Instant::now();
    let (mut ordinary, mut reserved) = (None, None);
    let mut n = 0u32;
    while begun.elapsed() < Duration::from_secs(5) && (ordinary.is_none() || reserved.is_none()) {
        n += 1;
        if ordinary.is_none() {
            let p = root.join(format!("late-{n}.tmp"));
            if std::fs::OpenOptions::new().write(true).create_new(true).open(&p).is_err() {
                ordinary = Some(begun.elapsed());
            } else {
                let _ = std::fs::remove_file(&p);
            }
        }
        if reserved.is_none() {
            let p = root.join(format!(".yadorilink-v1-probe.late{n}-x"));
            if std::fs::OpenOptions::new().write(true).create_new(true).open(&p).is_err() {
                reserved = Some(begun.elapsed());
            } else {
                let _ = std::fs::remove_file(&p);
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    println!("   an ordinary name first failed after {ordinary:?}");
    println!("   a reserved probe name first failed after {reserved:?}");

    println!("\n-- part 3 (provider gone): the checked publish over an ordinary file in the root");
    let plain = root.join("plain.txt");
    let staged = root.join("plain.txt.staged");
    println!("   before: target {} staged {}", attributes(&plain), attributes(&staged));
    let expected = TargetExpectation::observe(&plain);
    match expected {
        Err(error) => println!("   observe fails: {error}"),
        Ok(expected) => {
            let result = persist_reconstructed_file_checked(
                &staged,
                &plain,
                &NoTempLedger,
                Durability::Full,
                None,
                expected,
            );
            println!("   RESULT: {result:?}");
        }
    }
    println!("   after:  target {} staged {}", attributes(&plain), attributes(&staged));
    println!("   dir: {}", listing(&root));
    let _ = cfapi::unregister(&root);
    println!("\nsync root unregistered");
}
