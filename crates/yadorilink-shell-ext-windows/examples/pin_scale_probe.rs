//! How long the host takes to pin a folder of many placeholders, on a real Cloud Files sync root.
//!
//! The daemon waits 30 seconds for the host's answer to a pin request, and the host answers from its
//! single event loop, so the time of `provider_namespace::pin` over a large folder decides whether a
//! pin of a big tree is reported as failed although it was applied. This measures, for a folder of N
//! dehydrated placeholder files: creating them, the recursive pin as online only, as clear, and as keep
//! (which also scans for remote content and starts the fetch), and a bare walk that reads the
//! attributes of every child.
//!
//! Windows only:
//!
//! ```text
//! cargo run --release --example pin_scale_probe -- C:\path\to\a\new\empty\directory 5000 2> fetch-errors.log
//! ```
//!
//! The fetch of a kept folder fails on every child here (nothing serves content on this root), which
//! is logged to stderr, hence the redirect.

#[cfg(not(windows))]
fn main() {
    eprintln!("this probe needs Windows and the Cloud Files API");
}

#[cfg(windows)]
fn main() {
    use std::path::PathBuf;
    use std::time::Instant;

    use yadorilink_fs_platform::cloud_files;
    use yadorilink_fs_platform::durable_dir::NoLedger;
    use yadorilink_shell_ext::cfapi;
    use yadorilink_shell_ext::provider_namespace::{pin, PinWish};

    let mut args = std::env::args().skip(1);
    let Some(root) = args.next().map(PathBuf::from) else {
        eprintln!("usage: pin_scale_probe <new empty directory> <children>");
        return;
    };
    let children: usize = args.next().and_then(|n| n.parse().ok()).unwrap_or(1000);
    std::fs::create_dir_all(&root).expect("create the root");
    cfapi::register_and_connect(&root).expect("register the sync root");

    cfapi::create_item_placeholder(&NoLedger, &root, "tree", b"tree-id", 0, 0, true)
        .expect("create the folder placeholder");
    let tree = root.join("tree");
    let started = Instant::now();
    for n in 0..children {
        let id = format!("child-{n}");
        cfapi::create_item_placeholder(
            &NoLedger,
            &tree,
            &format!("f{n}.bin"),
            id.as_bytes(),
            4096,
            0,
            false,
        )
        .expect("create a child placeholder");
    }
    println!("children={children}");
    println!("create_children_ms={}", started.elapsed().as_millis());

    let started = Instant::now();
    let remote = std::fs::read_dir(&tree)
        .expect("list the folder")
        .filter_map(Result::ok)
        .filter(|e| {
            cloud_files::attributes_of(&e.path()).is_some_and(cloud_files::content_is_remote)
        })
        .count();
    println!("walk_attributes_ms={} remote={remote}", started.elapsed().as_millis());

    for (name, wish) in
        [("online_only", PinWish::OnlineOnly), ("clear", PinWish::Clear), ("keep", PinWish::Keep)]
    {
        let started = Instant::now();
        let outcome = pin(&tree, Some(b"tree-id"), wish);
        println!("pin_{name}_ms={} outcome={outcome:?}", started.elapsed().as_millis());
    }
    // Let the fetch threads that failed finish logging before the root goes away.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let _ = cfapi::unregister(&root);
    let _ = std::fs::remove_dir_all(&root);
}
