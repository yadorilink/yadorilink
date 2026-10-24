//! The host's durable record of the Stage placeholders it is about to create.
//!
//! `CfCreatePlaceholders` has no write-through flag, so a provider item is created under a
//! reserved Stage name and published by a durable no-replace move (see
//! `cfapi::create_item_placeholder`). The Stage name is never recognised by its shape: before
//! the placeholder exists, its exact path is made durable here, and the record is dropped once
//! the name is gone for good. What a crash leaves is therefore named by a record, and
//! [`StageLedger::recover`] retires exactly the recorded paths; it never looks at a directory
//! to decide that an entry is ours.
//!
//! One file per record, so a record is created by one durable no-replace publish and never by a
//! rewrite of a file that holds the others: `<sha256 of the path>.rec` containing the path.
//! The directory is the host's own (below the root's authoring state), so a `.tmp` beside the
//! records is an unfinished record write and nothing else.
//!
//! Windows documents no durability for an unlink, so a record is not dropped on the boundary of
//! its own removal: [`StageLedger::recover`] removes a recorded path that is still there and
//! drops a record only when it finds the path absent (the next recovery, or the same one for a
//! path that was already gone).

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use yadorilink_fs_platform::durable_dir::{
    publish_durably, DurableNamespace, NameLedger, NoLedger, Replace,
};

/// What one [`StageLedger::recover`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Recorded paths that were still there and were removed (their records stay until a
    /// recovery finds the path absent).
    pub removed: Vec<PathBuf>,
    /// Records dropped because the recorded path is absent.
    pub dropped: usize,
    /// Recorded paths left as they are: not removable, or not a placeholder of an item.
    pub kept: Vec<PathBuf>,
}

pub struct StageLedger {
    dir: PathBuf,
}

impl StageLedger {
    pub fn at(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The ledger of the sync root `root_id`, in the host's per-root state.
    pub fn for_root(root_id: &[u8]) -> Self {
        let hex: String = root_id.iter().map(|b| format!("{b:02x}")).collect();
        Self::at(crate::host_paths::container().join("authoring").join(hex).join("stage-ledger"))
    }

    fn record_file(&self, path: &Path) -> PathBuf {
        let digest = Sha256::digest(path.to_string_lossy().as_bytes());
        let name: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{name}.rec"))
    }

    fn ensure_dir(&self) -> io::Result<()> {
        let existing = self.dir.ancestors().find(|dir| dir.is_dir());
        match existing {
            Some(existing) => match DurableNamespace::open_unless_gate_closed(existing) {
                Ok(Some(ns)) => ns.create_dir_all(&self.dir, &NoLedger).map_err(io::Error::from),
                Ok(None) => std::fs::create_dir_all(&self.dir),
                Err(error) => Err(error.into()),
            },
            None => std::fs::create_dir_all(&self.dir),
        }
    }

    /// Retires what the records name. `owns` says whether the object at a recorded path is a
    /// placeholder of an item (a path that now holds anything else is left alone and its record
    /// kept). Removal is never recursive.
    pub fn recover(&self, owns: &dyn Fn(&Path) -> bool) -> Recovery {
        let mut report = Recovery::default();
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return report };
        for entry in entries.flatten() {
            let file = entry.path();
            match file.extension().and_then(|e| e.to_str()) {
                // An unfinished record write: the Stage was never created (the record precedes it).
                Some("tmp") => {
                    let _ = std::fs::remove_file(&file);
                }
                Some("rec") => self.recover_one(&file, owns, &mut report),
                _ => {}
            }
        }
        report
    }

    fn recover_one(&self, record: &Path, owns: &dyn Fn(&Path) -> bool, report: &mut Recovery) {
        let Ok(text) = std::fs::read_to_string(record) else { return };
        let path = PathBuf::from(text);
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if std::fs::remove_file(record).is_ok() {
                    report.dropped += 1;
                }
            }
            Err(_) => report.kept.push(path),
            Ok(meta) => {
                if !owns(&path) {
                    eprintln!(
                        "yadorilink-cfapi-host: the recorded Stage path {} holds no item placeholder; leaving it",
                        path.display()
                    );
                    report.kept.push(path);
                    return;
                }
                let removed = if meta.is_dir() {
                    std::fs::remove_dir(&path)
                } else {
                    std::fs::remove_file(&path)
                };
                match removed {
                    Ok(()) => report.removed.push(path),
                    Err(error) => {
                        eprintln!(
                            "yadorilink-cfapi-host: could not remove the recorded Stage placeholder {}: {error}",
                            path.display()
                        );
                        report.kept.push(path);
                    }
                }
            }
        }
    }
}

impl NameLedger for StageLedger {
    fn record(&self, path: &Path) -> io::Result<()> {
        let Some(text) = path.to_str() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a Stage path that is not UTF-8",
            ));
        };
        self.ensure_dir()?;
        let record = self.record_file(path);
        let tmp = record.with_extension("tmp");
        let mut out = std::fs::File::create(&tmp)?;
        io::Write::write_all(&mut out, text.as_bytes())?;
        yadorilink_fs_platform::flush::sync_file(&out)?;
        drop(out);
        match publish_durably(&tmp, &record, Replace::No) {
            Ok(()) => Ok(()),
            // The same path recorded twice is the same record.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn release(&self, path: &Path) {
        let _ = std::fs::remove_file(self.record_file(path));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("yl-stage-ledger-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Recovery retires exactly the recorded paths: an unrecorded entry that looks like a Stage
    /// name is left alone, a recorded one the caller does not own is kept with its record, and a
    /// recorded path that is absent only drops its record.
    #[test]
    fn recovery_touches_only_recorded_paths_it_owns() {
        let dir = scratch("recover");
        let ledger = StageLedger::at(dir.join("ledger"));
        let (mine, foreign, gone, unrecorded) =
            (dir.join("mine"), dir.join("foreign"), dir.join("gone"), dir.join("unrecorded"));
        for path in [&mine, &foreign, &unrecorded] {
            std::fs::write(path, b"x").unwrap();
        }
        for path in [&mine, &foreign, &gone] {
            ledger.record(path).unwrap();
        }
        ledger.record(&mine).unwrap(); // the same path twice is one record
        let report = ledger.recover(&|path| path == mine);
        assert_eq!(report.removed, vec![mine.clone()]);
        assert_eq!(report.kept, vec![foreign.clone()]);
        assert_eq!(report.dropped, 1);
        assert!(!mine.exists() && foreign.exists() && unrecorded.exists());
        // The removed path's record goes with the next recovery, which finds it absent.
        let again = ledger.recover(&|_| false);
        assert_eq!(again.dropped, 1);
        assert_eq!(again.kept, vec![foreign]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
