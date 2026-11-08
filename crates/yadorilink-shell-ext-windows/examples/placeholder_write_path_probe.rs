//! What the daemon's real write path does over a Cloud Files placeholder, and what can be seen
//! before the write about whether the provider is connected.
//!
//! For a dehydrated placeholder, with the provider connected and with it gone, this prints (1) the
//! queries that could tell the provider is gone, taken BEFORE any write; (2) whether a brand-new
//! file written into the sync root is usable; and (3) the outcome of
//! `yadorilink_local_storage::persist_reconstructed_file_checked`, the daemon's checked publish,
//! with the expectation it really uses (`TargetExpectation::observe` of the target).
//!
//! Windows only; needs a real Cloud Files sync root (a local NTFS volume):
//!
//! ```text
//! cargo run --example placeholder_write_path_probe -- C:\path\to\a\new\empty\directory
//! ```

#[cfg(not(windows))]
fn main() {
    eprintln!("this probe needs Windows and the Cloud Files API");
}

#[cfg(windows)]
fn main() {
    use std::os::windows::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
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
    fn short<T: std::fmt::Debug, E: std::fmt::Display>(r: Result<T, E>) -> String {
        match r {
            Ok(value) => format!("ok {value:?}"),
            Err(error) => format!("ERR {error}"),
        }
    }

    let root: PathBuf = std::env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: placeholder_write_path_probe <a new empty directory on NTFS>");
        std::process::exit(2);
    });
    std::fs::create_dir_all(&root).expect("create the sync root directory");
    cfapi::register_and_connect(&root).expect("register and connect the sync root");
    println!("sync root {root:?} registered and connected");

    for provider in ["connected", "disconnected"] {
        let name = format!("p-{provider}.txt");
        cfapi::create_item_placeholder(&NoLedger, &root, &name, b"probe-item", 4096, 0, false)
            .expect("create the placeholder");
        std::fs::write(root.join(format!("{name}.staged")), b"the replacement bytes")
            .expect("write the staged file");
    }
    for provider in ["connected", "disconnected"] {
        if provider == "disconnected" {
            cfapi::disconnect(&root).expect("disconnect the provider");
        }
        println!("\n=== provider {provider} ===");
        let name = format!("p-{provider}.txt");
        let (target, staged) = (root.join(&name), root.join(format!("{name}.staged")));

        println!("-- before any write");
        println!("   target attributes:      {}", attributes(&target));
        println!("   canonicalize(target):   {}", short(std::fs::canonicalize(&target)));
        println!("   canonicalize(root):     {}", short(std::fs::canonicalize(&root)));
        println!("   read_dir(root):         {}", listing(&root));
        println!("   registered_root_identity: {}", short(cfapi::registered_root_identity(&root)));
        println!("   cfapi::is_connected (this process): {}", cfapi::is_connected(&root));

        println!("-- candidate probes, on the pre-staged file and in the directory");
        let moved = root.join(format!("{name}.staged.moved"));
        println!(
            "   open staged for write (no create): {}",
            short(std::fs::OpenOptions::new().write(true).open(&staged).map(|_| ()))
        );
        println!("   rename staged away: {}", short(std::fs::rename(&staged, &moved)));
        println!("   rename it back:     {}", short(std::fs::rename(&moved, &staged)));
        let probe_file = root.join(format!("probe-{provider}.tmp"));
        println!(
            "   create_new probe file: {}",
            short(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&probe_file)
                    .map(|_| ())
            )
        );
        let _ = std::fs::remove_file(&probe_file);
        let probe_dir = root.join(format!("probe-{provider}.dir"));
        println!("   create_dir probe:      {}", short(std::fs::create_dir(&probe_dir)));
        let _ = std::fs::remove_dir(&probe_dir);
        println!("   staged after the probes: {}", attributes(&staged));

        let fresh = root.join(format!("fresh-{provider}.txt"));
        let wrote = std::fs::write(&fresh, b"a brand-new file");
        println!("-- a brand-new file in the sync root");
        println!("   write: {}", short(wrote));
        println!("   attributes: {}", attributes(&fresh));
        println!("   read back: {}", short(std::fs::read(&fresh).map(|b| b.len())));

        println!("-- the daemon's checked publish over the placeholder");
        let expected = TargetExpectation::observe(&target);
        println!(
            "   TargetExpectation::observe(target): {}",
            short(expected.as_ref().map(|_| "observed"))
        );
        let Ok(expected) = expected else { continue };
        let (sender, receiver) = mpsc::channel();
        let (t, s) = (target.clone(), staged.clone());
        std::thread::spawn(move || {
            let started = Instant::now();
            let result = persist_reconstructed_file_checked(
                &s,
                &t,
                &NoTempLedger,
                Durability::Full,
                None,
                expected,
            );
            let _ = sender.send((started.elapsed(), format!("{result:?}")));
        });
        match receiver.recv_timeout(Duration::from_secs(90)) {
            Err(_) => {
                println!("   RESULT: did not return within 90 s (hung)");
                std::process::exit(3);
            }
            Ok((elapsed, result)) => println!("   RESULT: {result} after {elapsed:?}"),
        }
        println!("   after: target {}", attributes(&target));
        println!("   after: staged {}", attributes(&staged));
        println!("   after: read target {}", short(std::fs::read(&target).map(|b| b.len())));
        println!("   after: dir {}", listing(&root));
    }
    let _ = cfapi::unregister(&root);
    println!("\nsync root unregistered");
}
