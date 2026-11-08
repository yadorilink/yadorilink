//! The host applying the person's keep-on-this-device choice to a placeholder, on a real sync root.
//!
//! A keep sets the platform's PINNED mark (a folder: on everything beneath it), online only sets
//! UNPINNED, a clear sets neither, the result is read back through the mapping the daemon reads, and an item that is not
//! the one asked for is refused with nothing changed. The root has no provider serving content, so a
//! kept dehydrated file stays dehydrated: the answer is "downloading", not "done".
//!
//! Skipped where a sync root cannot be registered (no Cloud Files API, no permission).
#![cfg(windows)]

use std::path::{Path, PathBuf};

use yadorilink_fs_platform::cloud_files::{self, PinMark};
use yadorilink_fs_platform::durable_dir::NoLedger;
use yadorilink_shell_ext::cfapi;
use yadorilink_shell_ext::provider_namespace::{
    pin as pin_now, wait_for_background_fetches, PinOutcome, PinWish,
};

/// Applies a pin and waits for the fetch a keep starts: with no provider serving content the fetch
/// fails, and the platform's handling of a fetch that is still running must not be mixed with the
/// marks the next step reads (the background fetch has its own test in the provider namespace).
fn pin(path: &Path, item_id: Option<&[u8]>, wish: PinWish) -> PinOutcome {
    let outcome = pin_now(path, item_id, wish);
    wait_for_background_fetches();
    outcome
}

fn attributes(path: &Path) -> u32 {
    cloud_files::attributes_of(path).expect("stat")
}

/// A fresh empty directory on the system volume, registered as a sync root and connected.
struct SyncRoot(PathBuf);

impl SyncRoot {
    fn new() -> Option<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("yl-pin-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        match cfapi::register_and_connect(&dir) {
            Ok(()) => Some(Self(dir)),
            Err(error) => {
                eprintln!("skipped: cannot register a Cloud Files sync root here: {error}");
                let _ = std::fs::remove_dir_all(&dir);
                None
            }
        }
    }

    fn placeholder(&self, parent: &Path, name: &str, id: &[u8], directory: bool) -> PathBuf {
        cfapi::create_item_placeholder(&NoLedger, parent, name, id, 4096, 0, directory)
            .expect("create the placeholder");
        parent.join(name)
    }
}

impl Drop for SyncRoot {
    fn drop(&mut self) {
        let _ = cfapi::unregister(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_keep_pins_and_a_release_unpins_and_the_wrong_item_changes_nothing() {
    let Some(root) = SyncRoot::new() else { return };
    let file = root.placeholder(&root.0, "a.txt", b"item-a", false);
    let folder = root.placeholder(&root.0, "dir", b"item-dir", true);
    let child = root.placeholder(&folder, "b.txt", b"item-b", false);
    let sibling = root.placeholder(&folder, "c.txt", b"item-c", false);

    let before = attributes(&file);
    assert!(cloud_files::content_is_remote(before), "the placeholder is dehydrated: {before:#x}");
    assert_eq!(cloud_files::pin_mark(before), PinMark::Unset);

    // The wrong identity: refused, the marks untouched.
    let refused = pin(&file, Some(b"another-item"), PinWish::Keep);
    assert!(matches!(refused, PinOutcome::Error(_)), "{refused:?}");
    assert_eq!(attributes(&file), before, "a refused pin changed the item");

    // Keep: pinned, and (no provider serves content here) the content is still to come.
    let kept = pin(&file, Some(b"item-a"), PinWish::Keep);
    assert_eq!(kept, PinOutcome::Downloading, "{kept:?}");
    let after_keep = attributes(&file);
    assert_eq!(cloud_files::pin_mark(after_keep), PinMark::Pinned, "{after_keep:#x}");
    // Keeping again changes nothing.
    assert_eq!(pin(&file, Some(b"item-a"), PinWish::Keep), PinOutcome::Downloading);
    assert_eq!(attributes(&file), after_keep);

    // Online only: unpinned, nothing to fetch.
    assert_eq!(pin(&file, Some(b"item-a"), PinWish::OnlineOnly), PinOutcome::Done);
    assert_eq!(cloud_files::pin_mark(attributes(&file)), PinMark::Unpinned);
    // Clear (the default): neither mark, which is not the same as unpinned.
    assert_eq!(pin(&file, Some(b"item-a"), PinWish::Clear), PinOutcome::Done);
    assert_eq!(cloud_files::pin_mark(attributes(&file)), PinMark::Unset);

    // A folder: everything beneath it follows.
    assert_eq!(pin(&folder, Some(b"item-dir"), PinWish::Keep), PinOutcome::Downloading);
    assert_eq!(cloud_files::pin_mark(attributes(&folder)), PinMark::Pinned);
    assert_eq!(
        cloud_files::pin_mark(attributes(&child)),
        PinMark::Pinned,
        "the child of a kept folder is not kept: {:#x}",
        attributes(&child)
    );
    // An exception marked online only beneath the kept folder is not wanted on this PC. Keeping the
    // folder again (the daemon repeats its plan) while a sibling is still being fetched must not set the
    // folder's pin recursively again: that would pin the exception for a moment and let the fetch take it.
    assert_eq!(pin(&child, Some(b"item-b"), PinWish::OnlineOnly), PinOutcome::Done);
    assert_eq!(pin(&folder, Some(b"item-dir"), PinWish::Keep), PinOutcome::Downloading);
    assert_eq!(
        cloud_files::pin_mark(attributes(&child)),
        PinMark::Unpinned,
        "keeping an already kept folder pinned its online-only exception again"
    );
    assert_eq!(cloud_files::pin_mark(attributes(&sibling)), PinMark::Pinned);
    // Once nothing wanted is left to fetch beneath it, the answer is done.
    assert_eq!(pin(&sibling, Some(b"item-c"), PinWish::OnlineOnly), PinOutcome::Done);
    assert_eq!(pin(&folder, Some(b"item-dir"), PinWish::Keep), PinOutcome::Done);
    assert_eq!(cloud_files::pin_mark(attributes(&child)), PinMark::Unpinned);
    assert_eq!(pin(&folder, Some(b"item-dir"), PinWish::OnlineOnly), PinOutcome::Done);
    assert_eq!(cloud_files::pin_mark(attributes(&child)), PinMark::Unpinned);
    assert_eq!(pin(&folder, Some(b"item-dir"), PinWish::Clear), PinOutcome::Done);
    assert_eq!(cloud_files::pin_mark(attributes(&child)), PinMark::Unset);

    // The sync root itself (no item): it is a folder like any other.
    assert_eq!(pin(&root.0, None, PinWish::Keep), PinOutcome::Downloading);
    assert_eq!(cloud_files::pin_mark(attributes(&file)), PinMark::Pinned);
    assert_eq!(pin(&root.0, None, PinWish::OnlineOnly), PinOutcome::Done);
}
