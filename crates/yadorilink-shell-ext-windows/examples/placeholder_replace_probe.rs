//! What the checked publish does to a Cloud Files placeholder at the target.
//!
//! `durable_dir::swap_in_if` replaces a target on Windows with `ReplaceFileW`, which moves the
//! replaced object to a backup name, verifies it, and removes it. Symlinks are kept away from
//! that primitive (it follows links); other reparse points are not, and a Cloud Files placeholder
//! is one. This program registers a sync root, creates an unhydrated placeholder, runs the swap
//! over it, and prints what happened, with the provider connected and again with it
//! disconnected, so the answer is on record instead of assumed.
//!
//! Windows only, and it needs a real Cloud Files sync root (a local NTFS volume):
//!
//! ```text
//! cargo run --example placeholder_replace_probe -- C:\path\to\a\new\empty\directory
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

    use yadorilink_fs_platform::durable_dir::{swap_in_if, NoLedger, SwapIn};
    use yadorilink_shell_ext::cfapi;

    fn attributes(path: &Path) -> String {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => format!("attributes=0x{:08x} len={}", meta.file_attributes(), meta.len()),
            Err(error) => format!("unreadable: {error}"),
        }
    }

    fn listing(dir: &Path) -> String {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        format!("{names:?}")
    }

    let root: PathBuf = std::env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(|| {
        eprintln!("usage: placeholder_replace_probe <a new empty directory on NTFS>");
        std::process::exit(2);
    });
    std::fs::create_dir_all(&root).expect("create the sync root directory");
    cfapi::register_and_connect(&root).expect("register and connect the sync root");
    println!("sync root {root:?} registered and connected");

    // Every placeholder is made while the provider is connected (marking one in sync needs the
    // connection); the offline cases then run with the provider gone.
    let cases = [
        ("connected", "swap"),
        ("connected", "rename"),
        ("disconnected", "swap"),
        ("disconnected", "rename"),
    ];
    for (provider, method) in cases {
        let name = format!("p-{provider}-{method}.txt");
        cfapi::create_item_placeholder(&NoLedger, &root, &name, b"probe-item", 4096, 0, false)
            .expect("create the placeholder");
        std::fs::write(root.join(format!("{name}.staged")), b"the replacement bytes")
            .expect("write the staged file");
    }
    let mut disconnected = false;
    for (provider, method) in cases {
        if provider == "disconnected" && !disconnected {
            cfapi::disconnect(&root).expect("disconnect the provider");
            disconnected = true;
        }
        println!("\n--- provider {provider}, replace by {method} ---");
        let name = format!("p-{provider}-{method}.txt");
        let (target, staged) = (root.join(&name), root.join(format!("{name}.staged")));
        println!("before:  target {}", attributes(&target));

        let (sender, receiver) = mpsc::channel();
        let (t, s, m) = (target.clone(), staged.clone(), method);
        std::thread::spawn(move || {
            let started = Instant::now();
            let captured = std::sync::Mutex::new(Vec::new());
            let outcome = if m == "swap" {
                // The expectation the real publish uses needs the captured object to be
                // readable (its stamp is observed with a stat): a stat that fails is "not the
                // expected object".
                let r = swap_in_if(&s, &t, &|backup: &Path| {
                    let seen = std::fs::symlink_metadata(backup);
                    captured.lock().unwrap().push(attributes(backup));
                    seen.is_ok_and(|meta| meta.len() == 4096)
                });
                match r {
                    Ok(SwapIn::Replaced) => "Replaced".to_string(),
                    Ok(SwapIn::Refused) => "Refused".to_string(),
                    Ok(SwapIn::Unsupported) => "Unsupported".to_string(),
                    Err(error) => format!("Err({error})"),
                }
            } else {
                match std::fs::rename(&s, &t) {
                    Ok(()) => "rename ok".to_string(),
                    Err(error) => format!("rename Err({error})"),
                }
            };
            let _ = sender.send((started.elapsed(), outcome, captured.into_inner().unwrap()));
        });
        match receiver.recv_timeout(Duration::from_secs(90)) {
            Err(_) => {
                println!("RESULT: did not return within 90 s (hung)");
                std::process::exit(3);
            }
            Ok((elapsed, outcome, captured)) => {
                println!("RESULT: {outcome} after {elapsed:?}");
                if !captured.is_empty() {
                    println!("        the captured object, as the check saw it: {captured:?}");
                }
            }
        }
        println!("after:   target {}", attributes(&target));
        println!("after:   staged {}", attributes(&staged));
        match std::fs::read(&target) {
            Ok(bytes) => println!("after:   target reads {} bytes", bytes.len()),
            Err(error) => println!("after:   target read fails: {error}"),
        }
        println!("after:   dir    {}", listing(&root));
    }
    let _ = cfapi::unregister(&root);
    println!("\nsync root unregistered");
}
