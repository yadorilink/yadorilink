#![cfg(test)]

//! The Windows ingest reader: a copy is read only when it is exactly what the request says it is.

use std::sync::Mutex;

use sha2::{Digest, Sha256};
use yadorilink_local_storage::{
    BlockContentStore, ContentHash, LocallyHashedBlock, SegmentBlockStore, StorageError,
};

use super::*;

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// A block store that can run a hook when the first block arrives (while the file is open) or
/// fail like a full disk.
struct Store {
    inner: SegmentBlockStore,
    on_first_put: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    full: std::sync::atomic::AtomicBool,
}

impl Store {
    fn new() -> Self {
        Self {
            inner: SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap(),
            on_first_put: Mutex::new(None),
            full: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn touch(&self) -> Result<(), StorageError> {
        if self.full.load(std::sync::atomic::Ordering::SeqCst) {
            // ERROR_DISK_FULL
            return Err(StorageError::Io(std::io::Error::from_raw_os_error(112)));
        }
        if let Some(hook) = self.on_first_put.lock().unwrap().take() {
            hook();
        }
        Ok(())
    }
}

impl BlockContentStore for Store {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.touch()?;
        self.inner.put(data)
    }
    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        self.touch()?;
        self.inner.put_prepared(prepared)
    }
    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        self.touch()?;
        self.inner.put_prepared_batch(prepared)
    }
    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.inner.get(hash)
    }
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        self.inner.present_blocks(hashes)
    }
}

fn put_file(dir: &std::path::Path, name: &str, data: &[u8]) {
    std::fs::write(dir.join(name), data).unwrap();
}

#[test]
fn a_well_formed_copy_is_read_and_its_digest_checked() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new();
    let data: Vec<u8> = (0..300_000u32).map(|n| (n % 251) as u8).collect();
    put_file(dir.path(), "copy-1", &data);

    let read = ingest(dir.path(), "copy-1", data.len() as u64, &sha(&data), &store).unwrap();
    assert_eq!(read.size, data.len() as u64);
    let mut rebuilt = Vec::new();
    for block in &read.blocks {
        rebuilt.extend(store.get(&hex::encode(&block.hash)).unwrap());
    }
    assert_eq!(rebuilt, data, "the stored blocks are not the file");

    // An empty file has no blocks.
    put_file(dir.path(), "empty", b"");
    let read = ingest(dir.path(), "empty", 0, &sha(b""), &store).unwrap();
    assert!(read.blocks.is_empty());
}

#[test]
fn names_that_are_not_one_plain_windows_component_are_refused_before_any_open() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new();
    for bad in [
        "",
        ".hidden",
        "..",
        "../x",
        r"..\x",
        "a/b",
        r"a\b",
        r"C:\Windows\win.ini",
        "c:x",
        "a:stream",
        "a\0b",
        "trailing.",
        "CON",
        "con.txt",
        "Nul",
        "aux.tar.gz",
        "COM1",
        "lpt9.log",
        &"x".repeat(129),
    ] {
        let result = ingest(dir.path(), bad, 0, &sha(b""), &store);
        assert!(matches!(result, Err(IngestError::Rejected(_))), "{bad:?}: {result:?}");
    }
    // Names that only look like device names are fine.
    for good in ["0123abc.part-1_x", "console", "com10", "lpt", "a.b.c"] {
        assert!(valid_windows_name(good), "{good}");
    }
}

#[test]
fn a_reparse_point_a_hard_link_a_directory_and_a_wrong_size_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new();
    let data = b"some bytes";
    put_file(dir.path(), "real", data);

    // A symbolic link needs a privilege an ordinary user may lack; a directory junction does not.
    let link = dir.path().join("link");
    let linked = std::os::windows::fs::symlink_file(dir.path().join("real"), &link).is_ok();
    if linked {
        assert!(matches!(
            ingest(dir.path(), "link", data.len() as u64, &sha(data), &store),
            Err(IngestError::Rejected(_))
        ));
    }
    let junction = dir.path().join("junction");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(status.status.success(), "mklink /J failed: {status:?}");
    assert!(matches!(
        ingest(dir.path(), "junction", 0, &sha(b""), &store),
        Err(IngestError::Rejected(_))
    ));

    std::fs::hard_link(dir.path().join("real"), dir.path().join("second-name")).unwrap();
    assert!(matches!(
        ingest(dir.path(), "real", data.len() as u64, &sha(data), &store),
        Err(IngestError::Rejected(_))
    ));
    std::fs::remove_file(dir.path().join("second-name")).unwrap();

    std::fs::create_dir(dir.path().join("sub")).unwrap();
    assert!(matches!(
        ingest(dir.path(), "sub", 0, &sha(b""), &store),
        Err(IngestError::Rejected(_))
    ));

    assert!(matches!(
        ingest(dir.path(), "real", data.len() as u64 + 1, &sha(data), &store),
        Err(IngestError::Rejected(_))
    ));
    assert!(matches!(
        ingest(dir.path(), "real", data.len() as u64, &[0u8; 5], &store),
        Err(IngestError::Rejected(_))
    ));
}

/// The ingest directory itself being a reparse point (swapped for a junction) is refused, even
/// though the file inside the target would pass every other check.
#[test]
fn an_ingest_directory_that_is_a_junction_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    put_file(&real, "copy", b"abc");
    let junction = dir.path().join("ingest");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&real)
        .output()
        .unwrap();
    assert!(made.status.success(), "mklink /J failed: {made:?}");
    let result = ingest(&junction, "copy", 3, &sha(b"abc"), &store);
    assert!(matches!(result, Err(IngestError::Rejected(_))), "{result:?}");
}

#[test]
fn a_missing_copy_or_a_wrong_digest_asks_the_extension_to_copy_again() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new();
    assert!(matches!(
        ingest(dir.path(), "gone", 3, &sha(b"abc"), &store),
        Err(IngestError::Unstable(_))
    ));
    put_file(dir.path(), "c", b"abc");
    assert!(matches!(
        ingest(dir.path(), "c", 3, &sha(b"xyz"), &store),
        Err(IngestError::Unstable(_))
    ));
}

/// While the copy is being read nobody can write to it: a writer is refused by the sharing mode
/// instead of racing the reader.
#[test]
fn a_copy_cannot_be_written_while_it_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new();
    let data: Vec<u8> = vec![7; 2_000_000];
    put_file(dir.path(), "moving", &data);
    let path = dir.path().join("moving");
    let refused = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = refused.clone();
    *store.on_first_put.lock().unwrap() = Some(Box::new(move || {
        let attempt = std::fs::OpenOptions::new().append(true).open(&path);
        seen.store(attempt.is_err(), std::sync::atomic::Ordering::SeqCst);
        let delete = std::fs::remove_file(&path);
        assert!(delete.is_err(), "the copy was deleted while it was read");
    }));
    let result = ingest(dir.path(), "moving", data.len() as u64, &sha(&data), &store);
    assert!(result.is_ok(), "{result:?}");
    assert!(refused.load(std::sync::atomic::Ordering::SeqCst), "a writer was admitted");
}

/// The identity is read again after the bytes: a change that the sharing mode does not stop (the
/// write time, which needs only attribute access) is still caught. If the sharing mode stops that
/// too, the copy is simply read unchanged; the test says which of the two happened.
#[test]
fn a_copy_whose_identity_changes_while_it_is_read_is_rejected() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new();
    let data: Vec<u8> = vec![7; 2_000_000];
    put_file(dir.path(), "moving", &data);
    let path = dir.path().join("moving");
    let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = changed.clone();
    *store.on_first_put.lock().unwrap() = Some(Box::new(move || {
        // FILE_WRITE_ATTRIBUTES only: not a data write.
        if let Ok(file) = std::fs::OpenOptions::new().access_mode(0x100).share_mode(7).open(&path) {
            let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
            flag.store(file.set_modified(later).is_ok(), std::sync::atomic::Ordering::SeqCst);
        }
    }));
    let result = ingest(dir.path(), "moving", data.len() as u64, &sha(&data), &store);
    if changed.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(matches!(result, Err(IngestError::Unstable(_))), "{result:?}");
    } else {
        assert!(result.is_ok(), "{result:?}");
    }
}

#[test]
fn a_full_disk_while_storing_blocks_is_reported_as_low_disk() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new();
    put_file(dir.path(), "big", &vec![1u8; 100_000]);
    store.full.store(true, std::sync::atomic::Ordering::SeqCst);
    let result = ingest(dir.path(), "big", 100_000, &sha(&vec![1u8; 100_000]), &store);
    assert!(matches!(result, Err(IngestError::LowDisk(_))), "{result:?}");
}

/// The temp root's layout: every directory exists, belongs to the current user and has a DACL
/// that names only that user (nothing inherited, no Everyone/Users entry); a reparse point in
/// place of one refuses the root.
#[test]
fn the_handoff_layout_is_private_to_the_current_user_and_never_a_reparse_point() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("provider");
    crate::provider_handoff::HandoffRoot::open(&root).unwrap();
    for name in ["staging", "handoff", "ingest", "domains"] {
        let path = root.join(name);
        assert!(crate::windows_fs_security::directory_owned_by_current_user(&path).unwrap());
        let acl = std::process::Command::new("icacls").arg(&path).output().unwrap();
        let listing = String::from_utf8_lossy(&acl.stdout).to_string();
        let entries: Vec<&str> =
            listing.lines().map(|line| line.trim()).filter(|line| line.contains(":(")).collect();
        assert_eq!(entries.len(), 1, "{name}: expected one ACL entry, got {listing}");
        assert!(!listing.contains("(I)"), "{name}: inherited entries remain: {listing}");
        for broad in ["Everyone", "BUILTIN\\Users", "Authenticated Users"] {
            assert!(!listing.contains(broad), "{name}: {broad} has access: {listing}");
        }
    }
    // A looser DACL is tightened on the next start.
    let loose = std::process::Command::new("icacls")
        .arg(root.join("ingest"))
        .args(["/grant", "Everyone:(OI)(CI)R"])
        .output()
        .unwrap();
    assert!(loose.status.success(), "{loose:?}");
    crate::provider_handoff::HandoffRoot::open(&root).unwrap();
    let after = std::process::Command::new("icacls").arg(root.join("ingest")).output().unwrap();
    assert!(!String::from_utf8_lossy(&after.stdout).contains("Everyone"));
    // A junction where a directory belongs refuses the root.
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::remove_dir_all(root.join("handoff")).unwrap();
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(root.join("handoff"))
        .arg(&elsewhere)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    assert!(crate::provider_handoff::HandoffRoot::open(&root).is_err());
}

/// A JOURNALED upload is never removed by age; an unjournaled partial copy ages out after a day,
/// an unjournaled finished copy only after the long safety age, and before the journal is known
/// (at open) nothing finished is swept. Ages come from the copy's modification time here.
#[test]
fn the_ingest_sweep_never_removes_a_journaled_upload() {
    let dir = tempfile::tempdir().unwrap();
    let root = crate::provider_handoff::HandoffRoot::open(dir.path()).unwrap();
    let ingest_dir = root.ingest_dir().to_path_buf();
    put_file(&ingest_dir, "journaled", b"x");
    put_file(&ingest_dir, "unclaimed", b"x");
    put_file(&ingest_dir, ".half.partial", b"x");
    let keep: std::collections::HashSet<String> = ["journaled".to_owned()].into();
    let hours = |h: u64| std::time::SystemTime::now() + std::time::Duration::from_secs(h * 3600);
    root.sweep_ingest_at(Some(&keep), hours(2));
    assert!(ingest_dir.join("unclaimed").exists(), "a finished upload was swept after two hours");
    root.sweep_ingest_at(None, hours(30 * 24));
    assert!(
        ingest_dir.join("unclaimed").exists(),
        "finished copies are not swept before the journal is known"
    );
    assert!(!ingest_dir.join(".half.partial").exists(), "a partial copy never ages out");
    root.sweep_ingest_at(Some(&keep), hours(30 * 24));
    assert!(ingest_dir.join("journaled").exists(), "a journaled upload was aged out");
    assert!(!ingest_dir.join("unclaimed").exists());
}
