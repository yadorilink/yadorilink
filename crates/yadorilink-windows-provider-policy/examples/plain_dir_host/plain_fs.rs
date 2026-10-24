//! The plain-directory stand-in for the operating system's file-provider view.
//!
//! A real host (macOS File Provider, Windows Cloud Files) keeps per-file placeholder state in the
//! operating system. Here that state is a sidecar record keyed by the file's inode, which survives
//! a rename like a placeholder identity does:
//!
//! * a placeholder is a file of the item's size and time with mode 000 and no bytes on the disk
//!   (a read fails with a permission error, the stand-in for "the content is not here");
//! * a hydrated file is an ordinary readable file; it is "in sync" while its size and time are the
//!   ones recorded when it was hydrated or last accepted by the daemon, and "changed" otherwise.
//!
//! Nothing here is shipped: it exists so that On-Demand can be exercised end to end without a
//! signed provider host. The record is never pruned: a file system that reuses the inode of a
//! deleted file quickly could make an unrelated new file look like a placeholder, which the short
//! test runs this serves do not reach.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use yadorilink_windows_provider_policy::namespace_policy::{unix_nanos_to_ticks, PlaceholderInfo};
use yadorilink_windows_provider_policy::provider_authoring::{
    fresh_ingest_name, AdoptError, CopyError, IngestCopy, Local, LocalStat, Located,
};

/// A file's identity on this machine: device and inode (inode numbers repeat across file
/// systems, and the sync roots may live on different ones).
pub type FileKey = (u64, u64);

pub fn key_of(md: &std::fs::Metadata) -> FileKey {
    (md.dev(), md.ino())
}

pub fn file_id_of(md: &std::fs::Metadata) -> u128 {
    (u128::from(md.dev()) << 64) | u128::from(md.ino())
}

/// What the sidecar knows about one item's file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub item_id: Vec<u8>,
    pub is_dir: bool,
    pub hydrated: bool,
    pub size: u64,
    pub mtime_nanos: i64,
    /// The content version (hash) the placeholder stands for; empty for a folder, and for a file
    /// the user authored until the namespace walk records the version the daemon accepted.
    pub version: Vec<u8>,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect()
}

pub fn mtime_nanos(md: &std::fs::Metadata) -> i64 {
    md.mtime() * 1_000_000_000 + md.mtime_nsec()
}

/// The stand-in for a change-journal sequence number: it moves when the file is written to.
pub fn usn_of(md: &std::fs::Metadata) -> i64 {
    mtime_nanos(md).wrapping_add(md.len() as i64)
}

pub fn set_mtime(path: &Path, nanos: i64) -> std::io::Result<()> {
    let time = if nanos >= 0 {
        UNIX_EPOCH + Duration::from_nanos(nanos as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(nanos.unsigned_abs())
    };
    std::fs::File::options().write(true).open(path)?.set_modified(time)
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// The sidecar record and the file operations on top of it.
pub struct PlainFs {
    file: PathBuf,
    pub ingest_dir: PathBuf,
    tmp_dir: PathBuf,
    /// Serializes every change the host makes to a file and its record with the install of a
    /// fetched file, so the install judges the state it then replaces.
    guard: Mutex<()>,
    entries: Mutex<HashMap<FileKey, Entry>>,
}

impl PlainFs {
    /// `staging_dir` is where fetched bytes are put together before they take their name: it
    /// must be on the file system of the sync roots (a rename cannot cross file systems) and
    /// outside what the host watches and lists.
    pub fn open(
        state_dir: &Path,
        ingest_dir: PathBuf,
        staging_dir: PathBuf,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let tmp_dir = staging_dir;
        std::fs::create_dir_all(&tmp_dir)?;
        // What an earlier run left half made.
        for entry in std::fs::read_dir(&tmp_dir)?.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
        let file = state_dir.join("entries.txt");
        let mut entries = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(&file) {
            for line in text.lines() {
                if let Some((ino, entry)) = decode(line) {
                    entries.insert(ino, entry);
                }
            }
        }
        Ok(Self { file, ingest_dir, tmp_dir, guard: Mutex::new(()), entries: Mutex::new(entries) })
    }

    fn serialized(&self) -> std::sync::MutexGuard<'_, ()> {
        self.guard.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<FileKey, Entry>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn persist(&self, entries: &HashMap<FileKey, Entry>) {
        let mut lines: Vec<String> = entries.iter().map(|(ino, e)| encode(*ino, e)).collect();
        lines.sort();
        let tmp = self.file.with_extension("tmp");
        let written = std::fs::write(&tmp, lines.join("\n") + "\n")
            .and_then(|()| std::fs::rename(&tmp, &self.file));
        if let Err(e) = written {
            eprintln!("plain-dir-host: could not record the placeholder state: {e}");
        }
    }

    pub fn set(&self, key: FileKey, entry: Entry) {
        let mut entries = self.lock();
        entries.insert(key, entry);
        self.persist(&entries);
    }

    pub fn forget(&self, key: FileKey) {
        let mut entries = self.lock();
        if entries.remove(&key).is_some() {
            self.persist(&entries);
        }
    }

    pub fn entry_of(&self, md: &std::fs::Metadata) -> Option<Entry> {
        self.lock().get(&key_of(md)).filter(|e| e.is_dir == md.is_dir()).cloned()
    }

    /// What the placeholder at `path` looks like to the host's policy.
    pub fn placeholder_info(&self, path: &Path) -> Option<PlaceholderInfo> {
        let md = std::fs::symlink_metadata(path).ok()?;
        self.info_of(&md)
    }

    fn info_of(&self, md: &std::fs::Metadata) -> Option<PlaceholderInfo> {
        let entry = self.entry_of(md)?;
        let in_sync =
            entry.is_dir || (md.len() == entry.size && mtime_nanos(md) == entry.mtime_nanos);
        Some(PlaceholderInfo {
            item_id: Some(entry.item_id),
            in_sync,
            is_dir: entry.is_dir,
            size: md.len(),
            mtime_ticks: unix_nanos_to_ticks(mtime_nanos(md)),
            dehydrated: !entry.is_dir && !entry.hydrated,
        })
    }

    /// Creates the placeholder of an item at `path`.
    pub fn create_placeholder(
        &self,
        path: &Path,
        item_id: &[u8],
        size: u64,
        mtime: i64,
        version: &[u8],
        is_dir: bool,
    ) -> std::io::Result<()> {
        let _serialized = self.serialized();
        if is_dir {
            std::fs::create_dir(path)?;
        } else {
            let file = std::fs::File::options().write(true).create_new(true).open(path)?;
            file.set_len(size)?;
            drop(file);
            set_mtime(path, mtime)?;
            set_mode(path, 0o000)?;
        }
        let md = std::fs::symlink_metadata(path)?;
        self.set(
            key_of(&md),
            Entry {
                item_id: item_id.to_vec(),
                is_dir,
                hydrated: false,
                size: md.len(),
                mtime_nanos: mtime_nanos(&md),
                version: version.to_vec(),
            },
        );
        Ok(())
    }

    /// Brings the placeholder of a file to a new version: its bytes are dropped (the daemon
    /// evicted the old copy before it published the new version) and size and time follow.
    pub fn update_placeholder(
        &self,
        path: &Path,
        item_id: &[u8],
        size: u64,
        mtime: i64,
        version: &[u8],
    ) -> Result<(), String> {
        let _serialized = self.serialized();
        let md = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        let info = self.info_of(&md).ok_or("not a placeholder")?;
        if info.item_id.as_deref() != Some(item_id) {
            return Err("the name no longer holds this item's placeholder".into());
        }
        if !info.in_sync {
            return Err("changed by the user meanwhile".into());
        }
        self.drop_bytes(path, item_id, size, mtime, version).map_err(|e| e.to_string())
    }

    /// Replaces the file's bytes by a hole of `size`, mode 000, and records it as a placeholder.
    fn drop_bytes(
        &self,
        path: &Path,
        item_id: &[u8],
        size: u64,
        mtime: i64,
        version: &[u8],
    ) -> std::io::Result<()> {
        set_mode(path, 0o600)?;
        let file = std::fs::File::options().write(true).truncate(true).open(path)?;
        file.set_len(size)?;
        drop(file);
        set_mtime(path, mtime)?;
        set_mode(path, 0o000)?;
        let md = std::fs::symlink_metadata(path)?;
        self.set(
            key_of(&md),
            Entry {
                item_id: item_id.to_vec(),
                is_dir: false,
                hydrated: false,
                size: md.len(),
                mtime_nanos: mtime_nanos(&md),
                version: version.to_vec(),
            },
        );
        Ok(())
    }

    /// Records the content version the daemon shows for the file at `path`, once the file holds
    /// exactly those bytes (hydrated and unchanged since). A file the user authored is bound
    /// without a version, so this is what lets it be evicted and fetched back later.
    pub fn record_version(&self, path: &Path, item_id: &[u8], version: &[u8; 32]) {
        let _serialized = self.serialized();
        let Ok(md) = std::fs::symlink_metadata(path) else { return };
        let Some(mut entry) = self.entry_of(&md) else { return };
        let in_sync = md.len() == entry.size && mtime_nanos(&md) == entry.mtime_nanos;
        if entry.item_id != item_id
            || entry.is_dir
            || !entry.hydrated
            || !in_sync
            || entry.version == version
        {
            return;
        }
        entry.version = version.to_vec();
        self.set(key_of(&md), entry);
    }

    /// Drops the local content of a placeholder (the stand-in for a dehydrate).
    pub fn evict(
        &self,
        path: &Path,
        item_id: &[u8],
    ) -> Result<(), yadorilink_windows_provider_policy::namespace_policy::EvictOutcome> {
        use yadorilink_windows_provider_policy::namespace_policy::EvictOutcome;
        let _serialized = self.serialized();
        let md = std::fs::symlink_metadata(path).map_err(|_| EvictOutcome::NotMaterialized)?;
        let Some(info) = self.info_of(&md) else { return Err(EvictOutcome::NotMaterialized) };
        if info.item_id.as_deref() != Some(item_id) {
            return Err(EvictOutcome::Error(format!(
                "{} is not the placeholder of the requested item",
                path.display()
            )));
        }
        if info.dehydrated {
            return Err(EvictOutcome::NotMaterialized);
        }
        if !info.in_sync {
            return Err(EvictOutcome::Error(format!(
                "{} has changes that are not shared yet",
                path.display()
            )));
        }
        let entry = self.entry_of(&md).ok_or(EvictOutcome::NotMaterialized)?;
        if entry.version.len() != 32 {
            // A placeholder without a version could never be fetched again.
            return Err(EvictOutcome::Error(format!(
                "{} has no recorded content version yet",
                path.display()
            )));
        }
        self.drop_bytes(path, item_id, entry.size, entry.mtime_nanos, &entry.version)
            .map_err(|e| EvictOutcome::Error(e.to_string()))
    }

    /// The item and content version a dehydrated placeholder stands for, and its size.
    pub fn placeholder_target(&self, path: &Path) -> Option<(Vec<u8>, [u8; 32], u64)> {
        let md = std::fs::symlink_metadata(path).ok()?;
        let entry = self.entry_of(&md)?;
        let version: [u8; 32] = entry.version.as_slice().try_into().ok()?;
        (!entry.is_dir && !entry.hydrated).then_some((entry.item_id, version, entry.size))
    }

    /// Fills the placeholder at `path` with `bytes_from` and records it hydrated and in sync, but
    /// only while the name still holds the very placeholder (same file, same item, same version,
    /// untouched) the fetch was made for: the namespace can move on, and the user can change the
    /// name, while a large file is fetched and copied.
    pub fn hydrate_from(
        &self,
        path: &Path,
        item_id: &[u8],
        version: &[u8; 32],
        bytes_from: &Path,
    ) -> Result<u64, String> {
        let before = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        let expected = self.entry_of(&before).ok_or("not a placeholder")?;
        let still_target = |entry: &Entry| {
            entry.item_id == item_id && entry.version == version && !entry.hydrated && !entry.is_dir
        };
        if !still_target(&expected) {
            return Err("the placeholder is not the one that was fetched".into());
        }
        // The bytes are put together outside the sync root and take the name in one rename, so a
        // half-written file is never visible there (the OS takes a handoff the same way).
        let staged = self.tmp_dir.join(format!("hydrate-{}", fresh_ingest_name()));
        let copied = std::fs::copy(bytes_from, &staged).map_err(|e| e.to_string())?;
        if copied != expected.size {
            let _ = std::fs::remove_file(&staged);
            return Err(format!(
                "the fetched file holds {copied} bytes, the placeholder stands for {}",
                expected.size
            ));
        }
        let installed = (|| -> Result<(), String> {
            let _serialized = self.serialized();
            // Judged again, under the same lock every host-side change takes, right before the
            // name changes hands: nothing that happened during the copy is overwritten.
            let now = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            let current = self.entry_of(&now).ok_or("the name no longer holds a placeholder")?;
            if key_of(&now) != key_of(&before)
                || current != expected
                || now.len() != current.size
                || mtime_nanos(&now) != current.mtime_nanos
            {
                return Err(
                    "the placeholder changed while its content was fetched; not installed".into()
                );
            }
            set_mtime(&staged, current.mtime_nanos).map_err(|e| e.to_string())?;
            set_mode(&staged, 0o644).map_err(|e| e.to_string())?;
            let staged_md = std::fs::symlink_metadata(&staged).map_err(|e| e.to_string())?;
            // Recorded under the staged inode first: a rename keeps it, so the name never holds a
            // file the record does not know.
            self.set(
                key_of(&staged_md),
                Entry {
                    hydrated: true,
                    size: staged_md.len(),
                    mtime_nanos: mtime_nanos(&staged_md),
                    ..current
                },
            );
            if let Err(e) = std::fs::rename(&staged, path) {
                self.forget(key_of(&staged_md));
                return Err(e.to_string());
            }
            self.forget(key_of(&now));
            Ok(())
        })();
        if installed.is_err() {
            let _ = std::fs::remove_file(&staged);
        }
        installed.map(|()| copied)
    }
}

fn encode((dev, ino): FileKey, e: &Entry) -> String {
    format!(
        "{dev}:{ino}\t{}\t{}\t{}\t{}\t{}\t{}",
        hex(&e.item_id),
        if e.is_dir { "d" } else { "f" },
        u8::from(e.hydrated),
        e.size,
        e.mtime_nanos,
        hex(&e.version)
    )
}

fn decode(line: &str) -> Option<(FileKey, Entry)> {
    let mut parts = line.split('\t');
    let (dev, ino) = parts.next()?.split_once(':')?;
    let ino = (dev.parse().ok()?, ino.parse().ok()?);
    let item_id = unhex(parts.next()?)?;
    let is_dir = parts.next()? == "d";
    let hydrated = parts.next()? == "1";
    let size = parts.next()?.parse().ok()?;
    let mtime_nanos = parts.next()?.parse().ok()?;
    let version = unhex(parts.next().unwrap_or(""))?;
    Some((ino, Entry { item_id, is_dir, hydrated, size, mtime_nanos, version }))
}

impl Local for PlainFs {
    fn stat(&self, path: &Path) -> Option<LocalStat> {
        let md = std::fs::symlink_metadata(path).ok()?;
        let placeholder = self.info_of(&md);
        Some(LocalStat {
            is_dir: md.is_dir(),
            is_symlink: md.file_type().is_symlink(),
            size: md.len(),
            mtime_unix_nanos: mtime_nanos(&md),
            placeholder,
            file_id: Some(file_id_of(&md)),
        })
    }

    fn children(&self, directory: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(directory)
            .map(|entries| entries.flatten().map(|e| e.path()).collect())
            .unwrap_or_default()
    }

    fn copy_to_ingest(&self, path: &Path) -> Result<IngestCopy, CopyError> {
        let unstable = |e: std::io::Error| CopyError::Unstable(e.to_string());
        let mut source = std::fs::File::open(path).map_err(unstable)?;
        let before = source.metadata().map_err(unstable)?;
        let name = fresh_ingest_name();
        let partial = self.ingest_dir.join(format!(".{name}.partial"));
        let finished = self.ingest_dir.join(&name);
        let copy = (|| -> Result<(u64, Vec<u8>), CopyError> {
            let mut target =
                std::fs::File::options()
                    .write(true)
                    .create_new(true)
                    .open(&partial)
                    .map_err(|e| CopyError::Failed(format!("{}: {e}", partial.display())))?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0u8; 1 << 20];
            let mut size = 0u64;
            loop {
                let n = source.read(&mut buffer).map_err(unstable)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                target.write_all(&buffer[..n]).map_err(|e| CopyError::Failed(e.to_string()))?;
                size += n as u64;
            }
            target.sync_all().map_err(|e| CopyError::Failed(e.to_string()))?;
            Ok((size, hasher.finalize().to_vec()))
        })();
        let (size, sha256) = match copy {
            Ok(done) => done,
            Err(error) => {
                let _ = std::fs::remove_file(&partial);
                return Err(error);
            }
        };
        let after = source.metadata().map_err(unstable)?;
        if usn_of(&before) != usn_of(&after) || after.len() != size {
            let _ = std::fs::remove_file(&partial);
            return Err(CopyError::Unstable("the file changed while it was copied".into()));
        }
        std::fs::rename(&partial, &finished).map_err(|e| {
            let _ = std::fs::remove_file(&partial);
            CopyError::Failed(e.to_string())
        })?;
        Ok(IngestCopy { name, size, sha256, usn: usn_of(&before) })
    }

    fn adopt(
        &self,
        path: &Path,
        item_id: &[u8],
        file_id: u128,
        usn: Option<i64>,
    ) -> Result<(), AdoptError> {
        let _serialized = self.serialized();
        let md = std::fs::symlink_metadata(path).map_err(|e| AdoptError::Failed(e.to_string()))?;
        if file_id_of(&md) != file_id {
            return Err(AdoptError::Failed("not the object the request described".into()));
        }
        if usn.is_some_and(|copied| copied != usn_of(&md)) {
            return Err(AdoptError::Changed);
        }
        self.set(
            key_of(&md),
            Entry {
                item_id: item_id.to_vec(),
                is_dir: md.is_dir(),
                hydrated: true,
                size: md.len(),
                mtime_nanos: mtime_nanos(&md),
                version: Vec::new(),
            },
        );
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        if to.symlink_metadata().is_ok() {
            return Err(std::io::ErrorKind::AlreadyExists.into());
        }
        std::fs::rename(from, to)
    }

    fn unbind(&self, path: &Path) -> Result<(), String> {
        let md = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        self.forget(key_of(&md));
        Ok(())
    }

    fn discard(&self, path: &Path, file_id: u128, usn: Option<i64>) -> Result<(), AdoptError> {
        let _serialized = self.serialized();
        let md = std::fs::symlink_metadata(path).map_err(|e| AdoptError::Failed(e.to_string()))?;
        if file_id_of(&md) != file_id {
            return Err(AdoptError::Failed("not the object the request described".into()));
        }
        if usn.is_some_and(|copied| copied != usn_of(&md)) {
            return Err(AdoptError::Changed);
        }
        std::fs::remove_file(path).map_err(|e| AdoptError::Failed(e.to_string()))?;
        self.forget(key_of(&md));
        Ok(())
    }

    fn locate(&self, root: &Path, item_id: &[u8]) -> Located {
        fn scan(
            fs: &PlainFs,
            directory: &Path,
            item_id: &[u8],
            complete: &mut bool,
        ) -> Option<PathBuf> {
            let Ok(entries) = std::fs::read_dir(directory) else {
                *complete = false;
                return None;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    *complete = false;
                    continue;
                };
                let path = entry.path();
                let info = fs.placeholder_info(&path);
                if info.as_ref().and_then(|i| i.item_id.as_deref()) == Some(item_id) {
                    return Some(path);
                }
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    if let Some(found) = scan(fs, &path, item_id, complete) {
                        return Some(found);
                    }
                }
            }
            None
        }
        let mut complete = true;
        match scan(self, root, item_id, &mut complete) {
            Some(found) => Located::Found(found),
            None if complete => Located::Absent,
            None => Located::Unknown,
        }
    }

    fn confirmed_missing(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dirs {
        root: PathBuf,
        staging: PathBuf,
        handoff: PathBuf,
        fs: PlainFs,
    }

    /// A sync root, a staging directory beside it and a state directory somewhere else.
    fn setup(tag: &str) -> Dirs {
        let base = std::env::temp_dir().join(format!("plain-fs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (root, staging) = (base.join("view/CloudStorage/root"), base.join("view/.staging"));
        let (state, handoff) = (base.join("state"), base.join("state/handoff"));
        for dir in [&root, &handoff] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let fs = PlainFs::open(&state, base.join("state/ingest"), staging.clone()).unwrap();
        Dirs { root, staging, handoff, fs }
    }

    fn handoff_file(dirs: &Dirs, bytes: &[u8]) -> PathBuf {
        let path = dirs.handoff.join("h");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn staged(dirs: &Dirs) -> usize {
        std::fs::read_dir(&dirs.staging).unwrap().count()
    }

    /// The fetched bytes take the name from the staging directory (which is not part of the sync
    /// root), and nothing is left staged.
    #[test]
    fn a_fetch_is_staged_outside_the_root_and_installed() {
        let dirs = setup("install");
        let path = dirs.root.join("f.bin");
        dirs.fs.create_placeholder(&path, b"item", 5, 1_000_000_000, &[1; 32], false).unwrap();
        let from = handoff_file(&dirs, b"hello");
        assert!(!dirs.staging.starts_with(&dirs.root));
        assert_eq!(dirs.fs.hydrate_from(&path, b"item", &[1; 32], &from), Ok(5));
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        let info = dirs.fs.placeholder_info(&path).unwrap();
        assert!(!info.dehydrated && info.in_sync);
        assert_eq!(staged(&dirs), 0);
        assert_eq!(std::fs::read_dir(&dirs.root).unwrap().count(), 1, "nothing else in the root");
    }

    /// A placeholder the namespace moved to another version while the fetch ran is not filled
    /// with the old version's bytes.
    #[test]
    fn bytes_of_an_older_version_are_not_installed() {
        let dirs = setup("version");
        let path = dirs.root.join("f.bin");
        dirs.fs.create_placeholder(&path, b"item", 5, 1_000_000_000, &[1; 32], false).unwrap();
        dirs.fs.update_placeholder(&path, b"item", 6, 2_000_000_000, &[2; 32]).unwrap();
        let from = handoff_file(&dirs, b"hello");
        assert!(dirs.fs.hydrate_from(&path, b"item", &[1; 32], &from).is_err());
        let info = dirs.fs.placeholder_info(&path).unwrap();
        assert!(info.dehydrated && info.size == 6);
        assert_eq!(staged(&dirs), 0);
    }

    /// A file the user authored is bound without a version; once the version is recorded it can be
    /// evicted and fetched back, and before that it is not evicted.
    #[test]
    fn an_authored_file_is_evicted_only_with_its_version_recorded() {
        let dirs = setup("authored");
        let path = dirs.root.join("mine.txt");
        std::fs::write(&path, b"mine").unwrap();
        let md = std::fs::symlink_metadata(&path).unwrap();
        dirs.fs.adopt(&path, b"item", file_id_of(&md), None).unwrap();
        assert!(dirs.fs.evict(&path, b"item").is_err(), "evicted without a version");
        assert_eq!(std::fs::read(&path).unwrap(), b"mine");

        dirs.fs.record_version(&path, b"item", &[7; 32]);
        dirs.fs.evict(&path, b"item").unwrap();
        let (item, version, size) = dirs.fs.placeholder_target(&path).unwrap();
        assert_eq!((item.as_slice(), version, size), (&b"item"[..], [7; 32], 4));
        let from = handoff_file(&dirs, b"mine");
        assert_eq!(dirs.fs.hydrate_from(&path, b"item", &[7; 32], &from), Ok(4));
        assert_eq!(std::fs::read(&path).unwrap(), b"mine");
    }

    /// A file the user changed or replaced is never overwritten by an install.
    #[test]
    fn a_changed_file_is_not_overwritten() {
        let dirs = setup("changed");
        let path = dirs.root.join("f.bin");
        dirs.fs.create_placeholder(&path, b"item", 5, 1_000_000_000, &[1; 32], false).unwrap();
        // The user replaces the name with their own file.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"mine").unwrap();
        let from = handoff_file(&dirs, b"hello");
        assert!(dirs.fs.hydrate_from(&path, b"item", &[1; 32], &from).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"mine");
        assert_eq!(staged(&dirs), 0);
    }

    /// Two files on different devices can share an inode number: the record tells them apart.
    #[test]
    fn the_record_is_keyed_by_device_and_inode() {
        assert_ne!((1u64, 7u64), (2u64, 7u64));
        let line = encode(
            (3, 9),
            &Entry {
                item_id: vec![1],
                is_dir: false,
                hydrated: true,
                size: 4,
                mtime_nanos: 5,
                version: vec![6],
            },
        );
        assert_eq!(decode(&line).map(|(key, _)| key), Some((3, 9)));
    }
}
