//! The Windows implementation of the authoring [`Local`] trait: the real file system, the
//! Cloud Files placeholder state and the NTFS change journal. The policy that decides what a
//! local change means lives in `yadorilink_windows_provider_policy::provider_authoring`, which
//! is re-exported here so callers keep one path.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use yadorilink_fs_platform::durable_dir::{move_durably, publish_durably, Replace};

pub use yadorilink_windows_provider_policy::provider_authoring::*;

/// The Windows implementation of [`Local`].
pub struct WindowsLocal {
    pub ingest_dir: PathBuf,
}

impl Local for WindowsLocal {
    fn stat(&self, path: &Path) -> Option<LocalStat> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        let placeholder = crate::provider_namespace::placeholder_info(path);
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos() as i64);
        // A placeholder is a reparse point too, but not a link the user made.
        let is_symlink = placeholder.is_none() && metadata.file_type().is_symlink();
        Some(LocalStat {
            is_dir: metadata.is_dir(),
            is_symlink,
            size: metadata.len(),
            mtime_unix_nanos: mtime,
            placeholder,
            file_id: crate::provider_namespace::file_id(path),
        })
    }

    fn children(&self, directory: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(directory)
            .map(|entries| entries.flatten().map(|e| e.path()).collect())
            .unwrap_or_default()
    }

    fn copy_to_ingest(&self, path: &Path) -> Result<IngestCopy, CopyError> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        // Readers and deleters are allowed, writers are not: NTFS does not always record a
        // second overwrite made through one open handle as a new USN record, so equal USNs
        // before and after cannot rule out a write during the copy. A writer already in makes
        // this open fail (copied again later); none can enter while the copy is read and hashed.
        const SHARE_READ_DELETE: u32 = 1 | 4;
        let mut source = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SHARE_READ_DELETE)
            .open(path)
            .map_err(|e| CopyError::Unstable(e.to_string()))?;
        let before = source.metadata().map_err(|e| CopyError::Unstable(e.to_string()))?;
        // Without a per-file USN nothing can tell a re-save of this very file from the bytes
        // copied here, so on such a volume nothing is copied, and so nothing is marked in sync.
        let usn_before = match crate::provider_namespace::file_usn(source.as_raw_handle()) {
            Ok(Some(usn)) => usn,
            Ok(None) => {
                return Err(CopyError::Failed(
                    "CfAPI provider mode requires a usable per-file USN guard (change journal)"
                        .into(),
                ))
            }
            Err(code) => return Err(CopyError::Unstable(format!("reading the USN: error {code}"))),
        };
        let name = fresh_ingest_name();
        let partial = self.ingest_dir.join(format!(".{name}.partial"));
        let finished = self.ingest_dir.join(&name);
        let copy = (|| -> Result<(u64, Vec<u8>), CopyError> {
            let mut target = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&partial)
                .map_err(|e| CopyError::Failed(format!("{}: {e}", partial.display())))?;
            let mut hasher = Sha256::new();
            let mut buffer = vec![0u8; 1 << 20];
            let mut size = 0u64;
            loop {
                let n = source.read(&mut buffer).map_err(|e| CopyError::Unstable(e.to_string()))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                target.write_all(&buffer[..n]).map_err(|e| CopyError::Failed(e.to_string()))?;
                size += n as u64;
            }
            yadorilink_fs_platform::flush::sync_file(&target)
                .map_err(|e| CopyError::Failed(e.to_string()))?;
            Ok((size, hasher.finalize().to_vec()))
        })();
        let (size, sha256) = match copy {
            Ok(done) => done,
            Err(error) => {
                let _ = std::fs::remove_file(&partial);
                return Err(error);
            }
        };
        let after = source.metadata().map_err(|e| CopyError::Unstable(e.to_string()))?;
        let usn_after = crate::provider_namespace::file_usn(source.as_raw_handle())
            .map_err(|code| CopyError::Unstable(format!("reading the USN: error {code}")))?;
        if usn_after != Some(usn_before)
            || before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
            || after.len() != size
        {
            let _ = std::fs::remove_file(&partial);
            return Err(CopyError::Unstable("the file changed while it was copied".into()));
        }
        // The copy is on disk under its name before the request that names it is journaled.
        publish_durably(&partial, &finished, Replace::No).map_err(|e| {
            let _ = std::fs::remove_file(&partial);
            CopyError::Failed(e.to_string())
        })?;
        Ok(IngestCopy { name, size, sha256, usn: usn_before })
    }

    fn adopt(
        &self,
        path: &Path,
        item_id: &[u8],
        file_id: u128,
        usn: Option<i64>,
    ) -> Result<(), AdoptError> {
        crate::provider_namespace::bind_to_item(path, item_id, file_id, usn)
    }

    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        // Never replacing, and durable: the kept bytes are the user's only copy under this name.
        move_durably(from, to, Replace::No)
    }

    fn unbind(&self, path: &Path) -> Result<(), String> {
        crate::provider_namespace::revert_to_plain(path)
    }

    fn discard(&self, path: &Path, file_id: u128, usn: Option<i64>) -> Result<(), AdoptError> {
        crate::provider_namespace::remove_object(path, file_id, usn)
    }

    fn locate(&self, root: &Path, item_id: &[u8]) -> Located {
        fn scan(directory: &Path, item_id: &[u8], complete: &mut bool) -> Option<PathBuf> {
            let Ok(entries) = std::fs::read_dir(directory) else {
                *complete = false;
                return None;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    *complete = false;
                    continue;
                };
                // The host's own Stage placeholder is where an item is being published, not where
                // the user put it.
                if yadorilink_fs_platform::reserved_namespace::is_artefact_component(
                    &entry.file_name(),
                ) {
                    continue;
                }
                let path = entry.path();
                let info = crate::provider_namespace::placeholder_info(&path);
                if info.as_ref().and_then(|i| i.item_id.as_deref()) == Some(item_id) {
                    return Some(path);
                }
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    if let Some(found) = scan(&path, item_id, complete) {
                        return Some(found);
                    }
                }
            }
            None
        }
        let mut complete = true;
        match scan(root, item_id, &mut complete) {
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

    /// Real NTFS: a writer that is open when the copy starts makes it Unstable, and the same file
    /// is copied once the writer is closed.
    #[cfg(windows)]
    #[test]
    #[ignore = "real file system; run on a Windows machine"]
    fn a_real_copy_is_refused_while_a_writer_is_open() {
        let dir = std::env::temp_dir().join(format!("yl-writer-{}", std::process::id()));
        let ingest = dir.join("ingest");
        std::fs::create_dir_all(&ingest).unwrap();
        let path = dir.join("f.txt");
        std::fs::write(&path, b"abc").unwrap();
        let local = WindowsLocal { ingest_dir: ingest };
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(matches!(local.copy_to_ingest(&path), Err(CopyError::Unstable(_))));
        drop(writer);
        let copy = local.copy_to_ingest(&path).expect("copied once the writer is closed");
        assert_eq!(copy.size, 3);
        let _ = std::fs::remove_dir_all(dir);
    }
}
