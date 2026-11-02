#![cfg(unix)]

//! Staging a file into `ingest/`: moved or cloned without a second copy, copied only when it has
//! to be, flushed, with the digest the write names, and refused before reading when it cannot fit.

use std::cell::Cell;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::*;

const NO_LIMIT: &dyn Fn(u64) -> Result<(), IngestError> = &|_| Ok(());

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

struct Dirs {
    _root: tempfile::TempDir,
    ingest: std::path::PathBuf,
    source_dir: std::path::PathBuf,
}

/// The ingest directory and a directory for sources on the SAME volume.
fn dirs() -> Dirs {
    let root = tempfile::tempdir().unwrap();
    let ingest = root.path().join("ingest");
    let source_dir = root.path().join("picked");
    std::fs::create_dir(&ingest).unwrap();
    std::fs::create_dir(&source_dir).unwrap();
    Dirs { _root: root, ingest, source_dir }
}

fn write_source(dirs: &Dirs, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dirs.source_dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn a_move_renames_the_file_and_copies_nothing() {
    let dirs = dirs();
    let bytes = vec![7u8; 3 << 20];
    let path = write_source(&dirs, "video.mov", &bytes);
    let inode = std::fs::metadata(&path).unwrap().ino();
    let reserved = Cell::new(false);
    let reserve = |_: u64| {
        reserved.set(true);
        Ok(())
    };
    let staged = stage_upload(
        &dirs.ingest,
        "up-1",
        &StageSource::Path(path.clone()),
        StageMode::Move,
        &reserve,
    )
    .unwrap();
    assert_eq!(staged.how, StagedHow::Moved);
    assert_eq!((staged.size, staged.sha256), (bytes.len() as u64, sha(&bytes)));
    assert!(!path.exists(), "a move leaves nothing at the source");
    assert_eq!(entries(&dirs.ingest), ["up-1"]);
    let moved = std::fs::metadata(dirs.ingest.join("up-1")).unwrap();
    assert_eq!(moved.ino(), inode, "the very same file: no second copy was written");
    assert_eq!(moved.nlink(), 1);
    assert!(!reserved.get(), "a move needs no space and asks for none");
}

#[test]
fn a_clone_keeps_the_source_and_a_copy_is_the_fallback_where_the_volume_cannot_clone() {
    let dirs = dirs();
    let bytes = b"clone me please".to_vec();
    let path = write_source(&dirs, "scan.pdf", &bytes);
    let staged = stage_upload(
        &dirs.ingest,
        "up-2",
        &StageSource::Path(path.clone()),
        StageMode::Clone,
        NO_LIMIT,
    )
    .unwrap();
    assert!(matches!(staged.how, StagedHow::Cloned | StagedHow::Copied));
    assert_eq!(staged.sha256, sha(&bytes));
    assert_eq!(std::fs::read(&path).unwrap(), bytes, "the source stays");
    assert_eq!(std::fs::read(dirs.ingest.join("up-2")).unwrap(), bytes);
    assert_eq!(entries(&dirs.ingest), ["up-2"], "no partial copy is left behind");
}

#[test]
fn a_copy_checks_the_space_before_reading_and_a_refusal_leaves_nothing() {
    let dirs = dirs();
    let path = write_source(&dirs, "big.bin", &[1u8; 4096]);
    let asked = Cell::new(0u64);
    let refuse = |bytes: u64| {
        asked.set(bytes);
        Err(IngestError::LowDisk("no room".into()))
    };
    let error = stage_upload(
        &dirs.ingest,
        "up-3",
        &StageSource::Path(path.clone()),
        StageMode::Copy,
        &refuse,
    )
    .unwrap_err();
    assert!(matches!(error, IngestError::LowDisk(_)), "{error:?}");
    assert_eq!(asked.get(), 4096, "the whole file's size is what is asked for");
    assert!(entries(&dirs.ingest).is_empty(), "nothing was written");
    assert!(path.exists(), "the source is untouched");
}

#[test]
fn a_copy_streams_flushes_and_names_its_digest() {
    let dirs = dirs();
    let bytes: Vec<u8> = (0..(2u32 << 20)).map(|i| (i % 251) as u8).collect();
    let path = write_source(&dirs, "photo.heic", &bytes);
    let before = yadorilink_fs_platform::flush::counts();
    let staged = stage_upload(
        &dirs.ingest,
        "up-4",
        &StageSource::Path(path.clone()),
        StageMode::Copy,
        NO_LIMIT,
    )
    .unwrap();
    let flushed = yadorilink_fs_platform::flush::counts();
    assert_eq!(staged.how, StagedHow::Copied);
    assert_eq!(staged.sha256, sha(&bytes));
    assert!(flushed.file_flushes > before.file_flushes, "the staged file was flushed");
    assert!(flushed.directory_syncs > before.directory_syncs, "the directory was flushed");
    assert_eq!(std::fs::read(dirs.ingest.join("up-4")).unwrap(), bytes);
    assert!(path.exists());
}

#[test]
fn a_descriptor_is_duplicated_never_closed_and_the_file_stays() {
    use std::os::fd::AsRawFd;
    let dirs = dirs();
    let bytes = b"from a descriptor".to_vec();
    let path = write_source(&dirs, "fd.bin", &bytes);
    let file = std::fs::File::open(&path).unwrap();
    for (name, mode) in [("up-5", StageMode::Move), ("up-6", StageMode::Copy)] {
        let staged = stage_upload(
            &dirs.ingest,
            name,
            &StageSource::Descriptor(file.as_raw_fd()),
            mode,
            NO_LIMIT,
        )
        .unwrap();
        assert_ne!(staged.how, StagedHow::Moved, "a descriptor cannot be moved");
        assert_eq!(staged.sha256, sha(&bytes));
    }
    // The caller's descriptor is still open and usable.
    assert!(file.metadata().is_ok());
    assert!(path.exists());
    // Not a descriptor at all.
    let bad =
        stage_upload(&dirs.ingest, "up-7", &StageSource::Descriptor(-1), StageMode::Copy, NO_LIMIT);
    assert!(matches!(bad, Err(IngestError::Rejected(_))));
}

#[test]
fn only_regular_files_this_user_owns_are_staged() {
    let dirs = dirs();
    let path = write_source(&dirs, "real.bin", b"data");
    let link = dirs.source_dir.join("link.bin");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let through_link =
        stage_upload(&dirs.ingest, "up-8", &StageSource::Path(link), StageMode::Copy, NO_LIMIT);
    assert!(matches!(through_link, Err(IngestError::Rejected(_))), "{through_link:?}");
    let directory = stage_upload(
        &dirs.ingest,
        "up-9",
        &StageSource::Path(dirs.source_dir.clone()),
        StageMode::Copy,
        NO_LIMIT,
    );
    assert!(matches!(directory, Err(IngestError::Rejected(_))), "{directory:?}");
    let missing = stage_upload(
        &dirs.ingest,
        "up-10",
        &StageSource::Path(dirs.source_dir.join("gone.bin")),
        StageMode::Move,
        NO_LIMIT,
    );
    assert!(matches!(missing, Err(IngestError::Unstable(_))), "{missing:?}");
    assert!(entries(&dirs.ingest).is_empty());
}

#[test]
fn a_file_with_other_links_is_copied_not_moved_and_the_source_goes_afterwards() {
    let dirs = dirs();
    let bytes = b"linked twice".to_vec();
    let path = write_source(&dirs, "a.bin", &bytes);
    std::fs::hard_link(&path, dirs.source_dir.join("b.bin")).unwrap();
    let staged = stage_upload(
        &dirs.ingest,
        "up-11",
        &StageSource::Path(path.clone()),
        StageMode::Move,
        NO_LIMIT,
    )
    .unwrap();
    // The ingest read refuses a file with other links, so the engine made its own.
    assert_ne!(staged.how, StagedHow::Moved);
    assert_eq!(std::fs::metadata(dirs.ingest.join("up-11")).unwrap().nlink(), 1);
    assert!(!path.exists(), "a move ends with the source gone");
}

#[test]
fn only_names_this_module_issued_can_be_discarded() {
    let dirs = dirs();
    std::fs::write(dirs.ingest.join("up-1"), b"x").unwrap();
    std::fs::write(dirs.ingest.join("copy-1"), b"x").unwrap();
    discard_staged(&dirs.ingest, "up-1").unwrap();
    discard_staged(&dirs.ingest, "up-1").unwrap();
    assert_eq!(entries(&dirs.ingest), ["copy-1"]);
    for bad in ["copy-1", "../x", "up-/..", ".up-1", ""] {
        assert!(discard_staged(&dirs.ingest, bad).is_err(), "{bad}");
    }
    assert_eq!(entries(&dirs.ingest), ["copy-1"], "another name was not touched");
}

/// The staged file is exactly what the ingest read accepts: the digest and size the stage returned
/// verify, and the ingest of a moved file is the same read as for any copy.
#[test]
fn a_staged_file_passes_the_ingest_read() {
    let dirs = dirs();
    let bytes: Vec<u8> = (0..(5u32 << 20)).map(|i| (i.wrapping_mul(31) % 253) as u8).collect();
    let path = write_source(&dirs, "movie.mov", &bytes);
    let staged =
        stage_upload(&dirs.ingest, "up-12", &StageSource::Path(path), StageMode::Move, NO_LIMIT)
            .unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap();
    let ingested = crate::provider_ingest::ingest(
        &dirs.ingest,
        &staged.ingest_name,
        staged.size,
        &staged.sha256,
        &crate::adapters::block_store_ports::BlockStorePortsAdapter::new(std::sync::Arc::new(
            store,
        )),
    )
    .unwrap();
    assert_eq!(ingested.size, bytes.len() as u64);
}
