#![cfg(test)]

//! The ingest reader: a copy is read only when it is exactly what the request says it is.

use std::os::unix::fs::symlink;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use yadorilink_local_storage::{
    BlockContentStore, ContentHash, LocallyHashedBlock, SegmentBlockStore, StorageError,
};

use super::*;

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// A store that can interfere while the file is being read, or fail like a full disk.
struct Interfering {
    inner: SegmentBlockStore,
    on_first_put: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    full: AtomicBool,
}

impl Interfering {
    fn new() -> Self {
        Self {
            inner: SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap(),
            on_first_put: Mutex::new(None),
            full: AtomicBool::new(false),
        }
    }

    fn touch(&self) -> Result<(), StorageError> {
        if self.full.load(Ordering::SeqCst) {
            return Err(StorageError::Io(std::io::Error::from_raw_os_error(libc::ENOSPC)));
        }
        if let Some(hook) = self.on_first_put.lock().unwrap().take() {
            hook();
        }
        Ok(())
    }
}

impl BlockContentStore for Interfering {
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
    let store = Interfering::new();
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
fn names_that_are_not_one_plain_component_are_refused_before_any_open() {
    let dir = tempfile::tempdir().unwrap();
    let store = Interfering::new();
    for bad in ["", ".hidden", "..", "../x", "a/b", "/etc/passwd", "a\0b", &"x".repeat(129)] {
        let result = ingest(dir.path(), bad, 0, &sha(b""), &store);
        assert!(matches!(result, Err(IngestError::Rejected(_))), "{bad:?}: {result:?}");
    }
    assert!(valid_ingest_name("0123abc.part-1_x"));
}

#[test]
fn a_symlink_a_hard_link_a_directory_and_a_wrong_size_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Interfering::new();
    let data = b"some bytes";
    put_file(dir.path(), "real", data);

    symlink(dir.path().join("real"), dir.path().join("link")).unwrap();
    assert!(matches!(
        ingest(dir.path(), "link", data.len() as u64, &sha(data), &store),
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
    // Nothing was stored for any of those.
}

#[test]
fn a_missing_copy_or_a_wrong_digest_asks_the_extension_to_copy_again() {
    let dir = tempfile::tempdir().unwrap();
    let store = Interfering::new();
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

/// The file changes while it is being read: nothing is accepted.
#[test]
fn a_copy_that_changes_while_it_is_read_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Interfering::new();
    let data: Vec<u8> = vec![7; 2_000_000];
    put_file(dir.path(), "moving", &data);
    let path = dir.path().join("moving");
    *store.on_first_put.lock().unwrap() = Some(Box::new(move || {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"appended while being read").unwrap();
    }));
    let result = ingest(dir.path(), "moving", data.len() as u64, &sha(&data), &store);
    assert!(matches!(result, Err(IngestError::Unstable(_))), "{result:?}");
}

#[test]
fn a_full_disk_while_storing_blocks_is_reported_as_low_disk() {
    let dir = tempfile::tempdir().unwrap();
    let store = Interfering::new();
    put_file(dir.path(), "big", &vec![1u8; 100_000]);
    store.full.store(true, Ordering::SeqCst);
    let result = ingest(dir.path(), "big", 100_000, &sha(&vec![1u8; 100_000]), &store);
    assert!(matches!(result, Err(IngestError::LowDisk(_))), "{result:?}");
}

#[test]
fn the_ingest_sweep_removes_only_abandoned_files_by_age() {
    let dir = tempfile::tempdir().unwrap();
    let root = crate::provider_handoff::HandoffRoot::open(dir.path()).unwrap();
    let ingest_dir = root.ingest_dir().to_path_buf();
    put_file(&ingest_dir, "fresh", b"x");
    put_file(&ingest_dir, ".fresh.partial", b"x");
    root.sweep_ingest(None);
    // Nothing is deleted merely for existing, including across a "restart".
    let _again = crate::provider_handoff::HandoffRoot::open(dir.path()).unwrap();
    assert!(ingest_dir.join("fresh").exists());
    assert!(ingest_dir.join(".fresh.partial").exists());
}

/// (W2/Y1) A JOURNALED upload is never removed by age; an unjournaled partial copy ages out after a
/// day, an unjournaled finished copy only after the long safety age, and before the journal is known
/// (open) nothing finished is swept.
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

/// (step 6) The temp root's layout: every directory is created 0700, a looser mode is tightened, and
/// a symlink or a non-directory in place of one refuses the root.
#[cfg(unix)]
#[test]
fn the_handoff_layout_is_private_and_never_a_symlink() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("provider");
    crate::provider_handoff::HandoffRoot::open(&root).unwrap();
    for name in ["staging", "handoff", "ingest", "domains"] {
        let mode = std::fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{name}");
    }
    // A shared mode is tightened on the next start.
    std::fs::set_permissions(root.join("ingest"), std::fs::Permissions::from_mode(0o755)).unwrap();
    crate::provider_handoff::HandoffRoot::open(&root).unwrap();
    assert_eq!(std::fs::metadata(root.join("ingest")).unwrap().permissions().mode() & 0o777, 0o700);
    // A symlink where a directory belongs refuses the root.
    let elsewhere = dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::remove_dir_all(root.join("handoff")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, root.join("handoff")).unwrap();
    assert!(crate::provider_handoff::HandoffRoot::open(&root).is_err());
}
