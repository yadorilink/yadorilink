//! The checked publish over a Cloud Files placeholder, on a real sync root.
//!
//! A dehydrated placeholder at the target is replaced by the checked rename (not `ReplaceFileW`,
//! which would leave the placeholder's OFFLINE mark on the ordinary file that replaces it), and
//! while the provider of the sync root is not connected nothing is touched: the publish reports the
//! provider as unavailable and leaves the placeholder, the staged file and the directory exactly as
//! they were, where a swap would have left the names unreadable.
//!
//! Skipped where a sync root cannot be registered (no Cloud Files API, no permission).
#![cfg(windows)]

use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use yadorilink_fs_platform::durable_dir::{
    is_cloud_provider_unavailable, swap_in_if, NoLedger, SwapIn,
};
use yadorilink_local_storage::{
    persist_reconstructed_file_checked, Durability, NoTempLedger, StorageError, TargetExpectation,
};
use yadorilink_shell_ext::cfapi;

const OFFLINE: u32 = 0x1000;

fn attributes(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).expect("stat").file_attributes()
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list the sync root")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A fresh empty directory on the system volume, registered as a sync root and connected.
struct SyncRoot(PathBuf);

impl SyncRoot {
    fn new() -> Option<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir =
            std::env::temp_dir().join(format!("yl-placeholder-{}-{nanos}", std::process::id()));
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

    /// A dehydrated placeholder `name` and a staged replacement beside it.
    fn placeholder_and_staged(&self, name: &str) -> (PathBuf, PathBuf) {
        cfapi::create_item_placeholder(&NoLedger, &self.0, name, b"probe-item", 4096, 0, false)
            .expect("create the placeholder");
        let staged = self.0.join(format!("{name}.staged"));
        std::fs::write(&staged, b"the replacement bytes").expect("write the staged file");
        (self.0.join(name), staged)
    }
}

impl Drop for SyncRoot {
    fn drop(&mut self) {
        let _ = cfapi::unregister(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One test, two phases in order: the platform has been seen to answer a swap as if the provider
/// were still there when a second sync root was connected in the same process at the same time, so
/// the phases do not run in parallel.
#[test]
fn a_connected_placeholder_is_replaced_by_the_checked_rename() {
    let Some(root) = SyncRoot::new() else { return };

    // Connected: a dehydrated placeholder.
    let (target, staged) = root.placeholder_and_staged("connected.txt");
    let before = attributes(&target);
    assert_ne!(before & OFFLINE, 0, "the placeholder is dehydrated: {before:#x}");
    // The exchange is not used for it.
    assert_eq!(swap_in_if(&staged, &target, &|_| true).unwrap(), SwapIn::Unsupported);
    assert_eq!(attributes(&target), before, "the placeholder was touched");
    assert!(staged.exists());
    // The daemon's own publish replaces it, with the expectation it really uses.
    let expected = TargetExpectation::observe(&target).unwrap();
    persist_reconstructed_file_checked(
        &staged,
        &target,
        &NoTempLedger,
        Durability::Full,
        None,
        expected,
    )
    .unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"the replacement bytes");
    assert_eq!(attributes(&target) & OFFLINE, 0, "the OFFLINE mark leaked onto the new file");
    assert!(!staged.exists());
}

/// The root is a provider root (population ALWAYS_FULL, as every root the product registers is):
/// the platform answers a create in it without a provider, so the provider's absence is read
/// from the root's provider status.
#[test]
fn a_placeholder_is_left_alone_while_its_provider_is_gone() {
    let Some(root) = SyncRoot::new() else { return };
    // The provider gone: a placeholder and an ordinary file, both made while it was there. The
    // ordinary file shows nothing in its attributes, the root is what makes it unsafe to swap.
    let plain = root.0.join("plain.txt");
    let plain_staged = root.0.join("plain.txt.staged");
    std::fs::write(&plain, b"an ordinary file in the root").unwrap();
    std::fs::write(&plain_staged, b"the replacement bytes").unwrap();
    let (target, staged) = root.placeholder_and_staged("offline.txt");
    cfapi::disconnect(&root.0).expect("disconnect the provider");
    // (The platform hides some attribute bits of a placeholder once its provider is gone, so what
    // is compared is what it reports now.)
    let (before, listing) = (attributes(&target), names(&root.0));

    let error = swap_in_if(&staged, &target, &|_| true).expect_err("the provider is not there");
    assert!(is_cloud_provider_unavailable(&error), "{error:?}");
    assert_eq!(attributes(&target), before, "the placeholder was touched");
    assert_eq!(names(&root.0), listing, "the directory changed (a backup or a probe was left)");

    let expected = TargetExpectation::observe(&target).unwrap();
    let published = persist_reconstructed_file_checked(
        &staged,
        &target,
        &NoTempLedger,
        Durability::Full,
        None,
        expected,
    );
    let Err(StorageError::Io(error)) = published else {
        panic!("the publish did not report the provider as unavailable: {published:?}");
    };
    assert!(is_cloud_provider_unavailable(&error), "{error:?}");
    assert_eq!(attributes(&target), before, "the placeholder was touched");
    // (The failed publish may discard its temp: the staged file is not asserted on.)
    // The ordinary file in the root is refused the same way, and left as it was.
    let (plain_before, listing) = (attributes(&plain), names(&root.0));
    let error =
        swap_in_if(&plain_staged, &plain, &|_| true).expect_err("the provider is not there");
    assert!(is_cloud_provider_unavailable(&error), "{error:?}");
    assert_eq!(attributes(&plain), plain_before, "the ordinary file was touched");
    assert_eq!(names(&root.0), listing, "the directory changed");
    assert!(
        !names(&root.0).iter().any(|name| name.contains("backup")),
        "a backup of the placeholder was left: {:?}",
        names(&root.0)
    );
}

#[test]
fn the_provider_unavailable_family_is_recognised_and_other_errors_are_not() {
    use std::io::Error;
    assert!(is_cloud_provider_unavailable(&Error::from_raw_os_error(-2145452027)));
    assert!(is_cloud_provider_unavailable(&Error::from_raw_os_error(0x17B)));
    assert!(!is_cloud_provider_unavailable(&Error::from_raw_os_error(5)));
    assert!(!is_cloud_provider_unavailable(&Error::other("not an os error")));
}
