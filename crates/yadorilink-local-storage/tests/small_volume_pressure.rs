// apple-cfg-file: macos-only mounts a small disk image with hdiutil
//! A real, small volume driven below the default headroom and back: the block store refuses
//! the write before it creates anything, and accepts it again once space returns. macOS
//! only (the volume is a disk image); run with `--ignored`.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;

use yadorilink_local_storage::free_space::classify_volume;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore, StorageError};

const MIB: u64 = 1024 * 1024;

struct Image {
    mount: PathBuf,
    _dir: tempfile::TempDir,
}

impl Image {
    fn attach(size_mib: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("vol.dmg");
        let name = format!("ylsmall{}", std::process::id());
        let ok = Command::new("hdiutil")
            .args(["create", "-size", &format!("{size_mib}m"), "-fs", "APFS", "-volname", &name])
            .arg(&img)
            .status()
            .unwrap()
            .success();
        assert!(ok, "hdiutil create");
        let ok = Command::new("hdiutil").arg("attach").arg(&img).status().unwrap().success();
        assert!(ok, "hdiutil attach");
        Self { mount: PathBuf::from(format!("/Volumes/{name}")), _dir: dir }
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil").arg("detach").arg("-force").arg(&self.mount).status();
    }
}

fn free(path: &Path) -> u64 {
    classify_volume(path, None).unwrap().available_bytes
}

fn ballast(path: &Path, leave_free: u64) {
    let want = free(path).saturating_sub(leave_free) / MIB;
    let ok = Command::new("dd")
        .arg("if=/dev/zero")
        .arg(format!("of={}", path.join("ballast").display()))
        .args(["bs=1m", &format!("count={want}")])
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "dd");
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    out
}

#[test]
#[ignore = "needs hdiutil; creates a 2 GiB sparse disk image"]
fn a_full_small_volume_refuses_the_write_cleanly_and_recovers() {
    let image = Image::attach(2048);
    let store_root = image.mount.join("store");
    let store = SegmentBlockStore::new(&store_root).unwrap().with_volume_verdict(|_| true);
    store.set_headroom_enforced(true);
    let headroom = classify_volume(&image.mount, None).unwrap().headroom_bytes;
    // 2 GiB volume: 1% is below the floor, so the floor (256 MiB) is the headroom.
    assert_eq!(headroom, 256 * MIB);

    // Leave less than the headroom free.
    ballast(&image.mount, headroom / 2);
    let before = files_under(&store_root);

    let payload = vec![7u8; 64 * 1024];
    let err = store.put(&payload).unwrap_err();
    assert!(matches!(err, StorageError::DiskPressure { .. }), "got {err:?}");
    assert_eq!(files_under(&store_root), before, "a refused write leaves nothing behind");

    // Free the space: the same write is accepted without any other nudge.
    std::fs::remove_file(image.mount.join("ballast")).unwrap();
    let hash = store.put(&payload).unwrap();
    assert_eq!(store.get(&hash).unwrap(), payload);
}
