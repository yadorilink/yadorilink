//! The one shared watcher-event decomposition helper.
//!
//! `SimulatedFolderWatchSource` is pure channel plumbing -- it delivers
//! whatever `FsChangeEvent`s a scenario hands it, so before this module
//! every `dst_*.rs` scenario hand-reproduced the OS-event decomposition
//! `watcher.rs` performs (a rename -> `Removed(old)` + `CreatedOrModified
//! (new)` per `RenameMode::Both`; a whole-directory rename -> `Removed
//! (dir)` + one `CreatedOrModified` per moved child; canonically
//! `dst_directory_chaos.rs`'s `deliver_local_rename` / `deliver_local_dir_
//! rename`). Those copies could drift silently from `watcher.rs`'s real
//! classification. `decompose` centralizes it once, and the plain-build
//! conformance test (`tests/watcher_decompose_conformance.rs`) pins the
//! output against the *real* notify-backed watcher so the two cannot
//! diverge without CI catching it.
//!
//! Deliberately simulator-independent (imports only the library's
//! `FsChangeKind`): the conformance test includes this exact source via
//! `#[path]` and compiles it *without* `--cfg turmoil`, so one source of
//! truth serves both the simulated scenarios and the real-watcher
//! conformance check.

use std::collections::HashMap;

use yadorilink_filesystem_sync::watcher::FsChangeKind;

/// A high-level filesystem operation a scenario performs, before it is
/// decomposed into the watch-event sequence a real watcher would emit.
/// Paths are forward-slash relative paths under the synced root.
#[derive(Debug, Clone)]
pub enum FsOp {
    /// A newly created file (`EventKind::Create`).
    Create { path: String },
    /// An in-place content change to an existing file (`EventKind::Modify`).
    Modify { path: String },
    /// A file deletion (`EventKind::Remove`).
    Delete { path: String },
    /// A single-file rename/move (`RenameMode::Both`).
    Rename { from: String, to: String },
    /// A whole-directory rename. `children` are the moved entries' paths
    /// relative to `from_dir` (the leaf names / nested subpaths under it).
    DirRename { from_dir: String, to_dir: String, children: Vec<String> },
}

/// A decomposed watch event: the classified kind plus the path it applies
/// to (forward-slash relative to the synced root), i.e. exactly the
/// `(path, FsChangeKind)` pair `watcher.rs`'s classifier produces, minus
/// the absolute-path prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub path: String,
    pub kind: FsChangeKind,
}

impl WatchEvent {
    fn created(path: impl Into<String>) -> Self {
        Self { path: path.into(), kind: FsChangeKind::CreatedOrModified }
    }
    fn removed(path: impl Into<String>) -> Self {
        Self { path: path.into(), kind: FsChangeKind::ObservedRemoval }
    }
}

fn join(dir: &str, child: &str) -> String {
    if dir.is_empty() {
        child.to_string()
    } else {
        format!("{dir}/{child}")
    }
}

/// Decomposes `op` into the classified watch-event sequence `watcher.rs`
/// emits for the corresponding real OS event(s):
///
/// - create / modify -> `CreatedOrModified(path)`
/// - delete -> `Removed(path)`
/// - rename -> `Removed(from)` then `CreatedOrModified(to)` (`RenameMode::Both`)
/// - directory rename -> `Removed(from_dir)` then one `CreatedOrModified`
///   per child at its new location under `to_dir` (the `deliver_local_dir_
///   rename` fan-out; the vacated directory's single `Removed` is what
///   `local_change.rs`'s orphan cascade turns into a tombstone for every
///   nested live row).
pub fn decompose(op: &FsOp) -> Vec<WatchEvent> {
    match op {
        FsOp::Create { path } | FsOp::Modify { path } => vec![WatchEvent::created(path.clone())],
        FsOp::Delete { path } => vec![WatchEvent::removed(path.clone())],
        FsOp::Rename { from, to } => {
            vec![WatchEvent::removed(from.clone()), WatchEvent::created(to.clone())]
        }
        FsOp::DirRename { from_dir, to_dir, children } => {
            let mut events = vec![WatchEvent::removed(from_dir.clone())];
            for child in children {
                events.push(WatchEvent::created(join(to_dir, child)));
            }
            events
        }
    }
}

/// Scenario-controlled coalescing of an event burst into its net effect
/// per path: the last kind observed for a path wins, and the surviving
/// events are ordered by each path's *last* occurrence -- modeling the
/// OS/debounce layer collapsing a rapid burst on the same path into one
/// event, which is an input a scenario deliberately varies rather than a
/// fidelity detail to hide, so it is expressed through this
/// same helper to keep the coalesced shape realistic.
pub fn coalesce(events: Vec<WatchEvent>) -> Vec<WatchEvent> {
    let mut order: Vec<String> = Vec::new();
    let mut last: HashMap<String, FsChangeKind> = HashMap::new();
    for e in events {
        if last.insert(e.path.clone(), e.kind).is_some() {
            order.retain(|p| p != &e.path);
        }
        order.push(e.path);
    }
    order.into_iter().map(|p| WatchEvent { kind: last[&p], path: p }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_modify_classify_as_created_or_modified() {
        assert_eq!(
            decompose(&FsOp::Create { path: "a.txt".into() }),
            vec![WatchEvent::created("a.txt")]
        );
        assert_eq!(
            decompose(&FsOp::Modify { path: "a.txt".into() }),
            vec![WatchEvent::created("a.txt")]
        );
    }

    #[test]
    fn delete_classifies_as_removed() {
        assert_eq!(
            decompose(&FsOp::Delete { path: "a.txt".into() }),
            vec![WatchEvent::removed("a.txt")]
        );
    }

    #[test]
    fn rename_matches_rename_mode_both() {
        assert_eq!(
            decompose(&FsOp::Rename { from: "old.txt".into(), to: "new.txt".into() }),
            vec![WatchEvent::removed("old.txt"), WatchEvent::created("new.txt")]
        );
    }

    #[test]
    fn dir_rename_fans_out_to_removed_dir_plus_created_children() {
        let events = decompose(&FsOp::DirRename {
            from_dir: "d1".into(),
            to_dir: "d2".into(),
            children: vec!["a.bin".into(), "sub/b.bin".into()],
        });
        assert_eq!(
            events,
            vec![
                WatchEvent::removed("d1"),
                WatchEvent::created("d2/a.bin"),
                WatchEvent::created("d2/sub/b.bin"),
            ]
        );
    }

    #[test]
    fn coalesce_collapses_a_burst_to_the_last_kind_per_path() {
        let coalesced = coalesce(vec![
            WatchEvent::created("a.txt"),
            WatchEvent::created("a.txt"),
            WatchEvent::removed("a.txt"),
        ]);
        assert_eq!(coalesced, vec![WatchEvent::removed("a.txt")]);
    }

    #[test]
    fn coalesce_preserves_distinct_paths_by_last_occurrence() {
        let coalesced = coalesce(vec![
            WatchEvent::created("a.txt"),
            WatchEvent::created("b.txt"),
            WatchEvent::created("a.txt"),
        ]);
        // a.txt's last occurrence is after b.txt, so it orders last.
        assert_eq!(coalesced, vec![WatchEvent::created("b.txt"), WatchEvent::created("a.txt")]);
    }
}
