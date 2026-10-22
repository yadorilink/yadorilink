//! Case `Op` applier: turns one entry of the Case IR's operation
//! vocabulary (`case_ir::Op`) into a concrete filesystem mutation under a
//! device's root directory, so a generator can drive a whole scenario
//! straight from a serialized `Case` instead of every scenario hand-coding
//! its own `std::fs` calls (as the retired two-device scenario does today with its
//! private `deliver_local_write`/`remove_file_if_present` helpers).
//!
//! Determinism is the whole point: every mtime is stamped from the passed
//! `HarnessClock`'s virtual "now" (never a wall clock, never RNG), the same
//! way the scenarios' `stamp_deterministic_mtime` does, so replaying the
//! same `(op, clock)` reproduces the same bytes and the same mtime. That
//! keeps a real filesystem write's kernel-stamped mtime and the simulated
//! virtual clock on one timeline (see `peer_session.rs`'s `now_unix_nanos`
//! doc comment for why they otherwise diverge under a virtual clock).
//!
//! The exec-bit conflict class is real product behaviour, so `Chmod`
//! actually runs: on unix it sets the file executable (`0o755`) or not
//! (`0o644`) according to `exec_bit`, which is exactly the owner-exec bit
//! that decides that conflict class; on a non-unix host it is a documented
//! no-op. `ConflictingConcurrent` is a two-device scenario-level grouping
//! hint, not a single-device mutation, so the applier refuses to invent
//! one action for it and says so explicitly.
//!
//! The small fs helpers live here; the deterministic virtual clock is the
//! one shared `dst_support::clock::HarnessClock` (this module used to carry
//! its own copy, predating that shared seam — now unified so a single clock
//! stamps every harness mutation and drives every session-visible `now`).
//!
//! `#![cfg(turmoil)]`-gated like every DST support module.

#![cfg(turmoil)]
#![allow(dead_code)] // the generator that drives this lands separately

use std::io;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use super::case_ir::{ContentTable, Op};
use super::clock::HarnessClock;

/// Executable mode a `Chmod { exec_bit: true }` sets: `rwxr-xr-x`, the
/// conventional mode of an executable file. The owner-exec bit (`0o100`)
/// is the one that actually decides the exec-bit conflict class; the full
/// canonical mode is used (rather than toggling only `0o100` on top of
/// whatever mode the file happened to have) so the result is deterministic
/// and independent of the umask the file was first created under.
#[cfg(unix)]
const EXEC_MODE: u32 = 0o755;

/// Non-executable counterpart of [`EXEC_MODE`] (`rw-r--r--`), what
/// `Chmod { exec_bit: false }` sets.
#[cfg(unix)]
const NON_EXEC_MODE: u32 = 0o644;

/// What applying one [`Op`] changed on disk, recorded so a later oracle can
/// prove the applier did what the `Case` asked (mtime, bytes, resulting
/// mode) rather than re-deriving it. Paths are the `Op`'s own root-relative
/// paths, not absolute, so an effect log stays device-independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppliedEffect {
    /// `Write`/`Edit`: `path` was created or overwritten with `len` bytes,
    /// its mtime stamped to `mtime_unix_nanos` (the clock's virtual now).
    Wrote { path: String, len: usize, mtime_unix_nanos: i64 },
    /// `Delete`: `path` is gone. A target that was already absent (a racing
    /// op removed it first) is tolerated and still reported here, matching
    /// the scenarios' `remove_file_if_present` NotFound tolerance.
    Removed { path: String },
    /// `Rename`/`Move`: `from` now lives at `to`; any missing parent
    /// directories of `to` were created (a `Move` across subdirs).
    Renamed { from: String, to: String },
    /// `Mkdir`: a directory now exists at `path` (parents created too).
    DirCreated { path: String },
    /// `Rmdir`: the empty directory at `path` was removed.
    DirRemoved { path: String },
    /// `RmTree`: `path` and everything under it are gone. `observed` is
    /// every object the removal saw (the directory itself included), root-
    /// relative and sorted: the observed-remove set a recursive delete may
    /// replicate deletes for, and nothing more. An already-absent `path` (a
    /// racing op removed it first) is tolerated with an empty set.
    TreeRemoved { path: String, observed: Vec<String> },
    /// `RenameTree`: the directory `from` now lives at `to`. `observed` is
    /// every object that moved (the directory itself included), as its
    /// root-relative path *before* the rename, sorted.
    TreeRenamed { from: String, to: String, observed: Vec<String> },
    /// `Chmod` on unix: `path`'s mode was set so its owner-exec bit equals
    /// `exec_bit`; `mode` is the resulting full mode (`0o755`/`0o644`).
    ChmodApplied { path: String, exec_bit: bool, mode: u32 },
    /// `Chmod` that changed nothing: either the target does not exist (a
    /// racing op removed it — tolerated like `Delete`) or the host has no
    /// unix permission bits. `reason` documents which.
    ChmodNoop { path: String, reason: &'static str },
    /// `ConflictingConcurrent`: not a single-device filesystem action at
    /// all but a scenario-level hint that two devices' ops target racing
    /// paths, so the applier applies nothing and reports why. The caller
    /// (a scenario driver) is expected to expand it into the two concrete
    /// per-device ops itself.
    NotASingleOpAction { detail: String },
}

/// Applies one `op` to the device rooted at `root`, deterministically.
///
/// Every path in `op` is interpreted relative to `root`. `Write`/`Edit`
/// bytes come from `content_table` (see [`content_for`]). Returns the
/// [`AppliedEffect`] describing what changed; propagates a genuine
/// `io::Error` (a real permissions/ENOSPC/etc. failure), but tolerates the
/// benign "target already gone" races the way the existing scenarios do.
pub fn apply_op(
    clock: &HarnessClock,
    root: &Path,
    op: &Op,
    content_table: &ContentTable,
) -> io::Result<AppliedEffect> {
    match op {
        // Write and Edit are the same on-disk action — create-or-overwrite
        // with the referenced content. The Case IR keeps them distinct only
        // so a generator/oracle can tell "first appearance" from "in-place
        // change"; the filesystem cannot.
        Op::Write { path, content_id } | Op::Edit { path, content_id } => {
            let bytes = content_for(content_table, *content_id);
            write_file(clock, root, path, &bytes)?;
            Ok(AppliedEffect::Wrote {
                path: path.clone(),
                len: bytes.len(),
                mtime_unix_nanos: clock.now_nanos(),
            })
        }

        Op::Delete { path } => {
            remove_file_if_present(&root.join(path))?;
            Ok(AppliedEffect::Removed { path: path.clone() })
        }

        // Rename and Move are one filesystem primitive (`rename(2)`); Move
        // simply tends to cross subdirectories, so parents of the
        // destination are created first for both.
        Op::Rename { from, to } | Op::Move { from, to } => {
            rename(root, from, to)?;
            Ok(AppliedEffect::Renamed { from: from.clone(), to: to.clone() })
        }

        Op::Mkdir { path } => {
            std::fs::create_dir_all(root.join(path))?;
            Ok(AppliedEffect::DirCreated { path: path.clone() })
        }

        Op::Rmdir { path } => {
            std::fs::remove_dir(root.join(path))?;
            Ok(AppliedEffect::DirRemoved { path: path.clone() })
        }

        Op::RmTree { path } => {
            let full = root.join(path);
            let observed = observed_subtree(root, &full)?;
            match std::fs::remove_dir_all(&full) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            Ok(AppliedEffect::TreeRemoved { path: path.clone(), observed })
        }

        Op::RenameTree { from, to } => {
            let observed = observed_subtree(root, &root.join(from))?;
            rename(root, from, to)?;
            Ok(AppliedEffect::TreeRenamed { from: from.clone(), to: to.clone(), observed })
        }

        Op::Chmod { path, exec_bit } => chmod(root, path, *exec_bit),

        // Deliberately not a single-op action: two ops on two devices that
        // are expected to race is a scenario construct, not a mutation, and
        // mis-applying it as one would fabricate an effect that never
        // happened. Report explicitly instead.
        Op::ConflictingConcurrent { paths } => Ok(AppliedEffect::NotASingleOpAction {
            detail: format!(
                "ConflictingConcurrent over {} path(s) is a two-device scenario grouping hint, \
                 not a single-device op — expand it into the concrete per-device ops instead",
                paths.len()
            ),
        }),
    }
}

/// Bytes a `Write`/`Edit` should put on disk for `content_id`: the Case's
/// recorded content when present, otherwise a deterministic id-derived
/// placeholder. The fallback keeps an op that references an id the table
/// never populated replaying to the same bytes every time (rather than
/// failing, or silently writing nothing) while staying distinguishable per
/// id — useful for cheaply generated cases that don't bother filling the
/// table for every op.
fn content_for(content_table: &ContentTable, content_id: u64) -> Vec<u8> {
    match content_table.get(content_id) {
        Some(bytes) => bytes.clone(),
        None => format!("content-{content_id}").into_bytes(),
    }
}

/// Create-or-overwrite `path` under `root` with `bytes`, creating parent
/// directories as needed, then stamp its mtime from the harness clock —
/// the same write-then-stamp the scenarios' `deliver_local_write` does.
fn write_file(clock: &HarnessClock, root: &Path, path: &str, bytes: &[u8]) -> io::Result<()> {
    let full = root.join(path);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&full, bytes)?;
    stamp_mtime(&full, clock.now_nanos())
}

/// Stamp `path`'s mtime to the virtual `now_unix_nanos`, identical in
/// approach to the scenarios' `stamp_deterministic_mtime` (`File::set_times`,
/// stable since Rust 1.75, needs no extra crate). A negative virtual now is
/// clamped to the epoch.
fn stamp_mtime(path: &Path, now_unix_nanos: i64) -> io::Result<()> {
    let modified = UNIX_EPOCH + Duration::from_nanos(now_unix_nanos.max(0) as u64);
    let file = std::fs::File::options().write(true).open(path)?;
    file.set_times(std::fs::FileTimes::new().set_modified(modified))
}

/// Remove `path` if present, tolerating an already-absent target (a racing
/// op won). Mirrors the scenarios' `remove_file_if_present`.
fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Rename `from` to `to` under `root`, creating any missing parent
/// directories of the destination first (so a `Move` into a subdir that
/// does not exist yet succeeds).
fn rename(root: &Path, from: &str, to: &str) -> io::Result<()> {
    let to_full = root.join(to);
    if let Some(parent) = to_full.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(root.join(from), to_full)
}

/// Every object at or under `top` (never following a symlink), as sorted
/// forward-slash paths relative to `root`. An absent `top` observes nothing.
fn observed_subtree(root: &Path, top: &Path) -> io::Result<Vec<String>> {
    fn visit(root: &Path, at: &Path, out: &mut Vec<String>) -> io::Result<()> {
        let meta = match std::fs::symlink_metadata(at) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if let Ok(rel) = at.strip_prefix(root) {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
        if meta.is_dir() {
            for entry in std::fs::read_dir(at)? {
                visit(root, &entry?.path(), out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(root, top, &mut out)?;
    out.sort();
    Ok(out)
}

/// Set `path`'s owner-exec bit to `exec_bit` by writing the canonical
/// executable (`0o755`) or non-executable (`0o644`) mode. A missing target
/// is tolerated as a no-op (same rationale as `Delete`'s NotFound
/// tolerance): a racing op may have removed it.
#[cfg(unix)]
fn chmod(root: &Path, path: &str, exec_bit: bool) -> io::Result<AppliedEffect> {
    use std::os::unix::fs::PermissionsExt;

    let full = root.join(path);
    match std::fs::metadata(&full) {
        Ok(_) => {
            let mode = if exec_bit { EXEC_MODE } else { NON_EXEC_MODE };
            std::fs::set_permissions(&full, std::fs::Permissions::from_mode(mode))?;
            Ok(AppliedEffect::ChmodApplied { path: path.to_string(), exec_bit, mode })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Ok(AppliedEffect::ChmodNoop { path: path.to_string(), reason: "target does not exist" })
        }
        Err(e) => Err(e),
    }
}

/// Non-unix hosts have no owner-exec bit, so `Chmod` is a documented no-op
/// rather than an error — a `Case` produced on unix still replays here, it
/// just cannot reproduce the exec-bit conflict class.
#[cfg(not(unix))]
fn chmod(_root: &Path, path: &str, exec_bit: bool) -> io::Result<AppliedEffect> {
    let _ = exec_bit;
    Ok(AppliedEffect::ChmodNoop {
        path: path.to_string(),
        reason: "non-unix host has no owner-exec bit",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock() -> HarnessClock {
        // An arbitrary but fixed virtual "now" well past the epoch. The
        // shared clock seeds "now" as `seed * 1e9`, so this seed reproduces
        // the same fixed 1.7e18-nanos origin the applier tests assert against.
        HarnessClock::from_seed(1_700_000_000)
    }

    fn content_table() -> ContentTable {
        let mut t = ContentTable::default();
        t.insert(1, b"hello world".to_vec());
        t
    }

    #[test]
    fn write_creates_file_with_content_table_bytes() {
        let root = tempfile::tempdir().unwrap();
        let table = content_table();
        let op = Op::Write { path: "a.txt".to_string(), content_id: 1 };

        let effect = apply_op(&clock(), root.path(), &op, &table).unwrap();

        assert_eq!(std::fs::read(root.path().join("a.txt")).unwrap(), b"hello world");
        assert_eq!(
            effect,
            AppliedEffect::Wrote {
                path: "a.txt".to_string(),
                len: 11,
                mtime_unix_nanos: clock().now_nanos(),
            }
        );
    }

    #[test]
    fn edit_overwrites_existing_file() {
        let root = tempfile::tempdir().unwrap();
        let table = content_table();
        std::fs::write(root.path().join("a.txt"), b"stale").unwrap();

        let op = Op::Edit { path: "a.txt".to_string(), content_id: 1 };
        apply_op(&clock(), root.path(), &op, &table).unwrap();

        assert_eq!(std::fs::read(root.path().join("a.txt")).unwrap(), b"hello world");
    }

    #[test]
    fn write_falls_back_to_deterministic_content_for_unknown_id() {
        let root = tempfile::tempdir().unwrap();
        let table = ContentTable::default(); // id 7 never inserted
        let op = Op::Write { path: "a.txt".to_string(), content_id: 7 };

        apply_op(&clock(), root.path(), &op, &table).unwrap();

        assert_eq!(std::fs::read(root.path().join("a.txt")).unwrap(), b"content-7");
    }

    #[test]
    fn write_creates_parent_directories() {
        let root = tempfile::tempdir().unwrap();
        let table = content_table();
        let op = Op::Write { path: "nested/deep/a.txt".to_string(), content_id: 1 };

        apply_op(&clock(), root.path(), &op, &table).unwrap();

        assert!(root.path().join("nested/deep/a.txt").exists());
    }

    #[test]
    fn delete_removes_file() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), b"x").unwrap();
        let op = Op::Delete { path: "a.txt".to_string() };

        let effect = apply_op(&clock(), root.path(), &op, &ContentTable::default()).unwrap();

        assert!(!root.path().join("a.txt").exists());
        assert_eq!(effect, AppliedEffect::Removed { path: "a.txt".to_string() });
    }

    #[test]
    fn delete_of_missing_file_is_tolerated() {
        let root = tempfile::tempdir().unwrap();
        let op = Op::Delete { path: "gone.txt".to_string() };

        let effect = apply_op(&clock(), root.path(), &op, &ContentTable::default()).unwrap();

        assert_eq!(effect, AppliedEffect::Removed { path: "gone.txt".to_string() });
    }

    #[test]
    fn rename_moves_file() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), b"payload").unwrap();
        let op = Op::Rename { from: "a.txt".to_string(), to: "b.txt".to_string() };

        let effect = apply_op(&clock(), root.path(), &op, &ContentTable::default()).unwrap();

        assert!(!root.path().join("a.txt").exists());
        assert_eq!(std::fs::read(root.path().join("b.txt")).unwrap(), b"payload");
        assert_eq!(
            effect,
            AppliedEffect::Renamed { from: "a.txt".to_string(), to: "b.txt".to_string() }
        );
    }

    #[test]
    fn move_across_subdirs_creates_parent_dirs() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), b"payload").unwrap();
        let op = Op::Move { from: "a.txt".to_string(), to: "sub/dir/b.txt".to_string() };

        apply_op(&clock(), root.path(), &op, &ContentTable::default()).unwrap();

        assert!(!root.path().join("a.txt").exists());
        assert_eq!(std::fs::read(root.path().join("sub/dir/b.txt")).unwrap(), b"payload");
    }

    #[test]
    fn mkdir_creates_directory_and_rmdir_removes_it() {
        let root = tempfile::tempdir().unwrap();

        let mk = apply_op(
            &clock(),
            root.path(),
            &Op::Mkdir { path: "d".to_string() },
            &ContentTable::default(),
        )
        .unwrap();
        assert!(root.path().join("d").is_dir());
        assert_eq!(mk, AppliedEffect::DirCreated { path: "d".to_string() });

        let rm = apply_op(
            &clock(),
            root.path(),
            &Op::Rmdir { path: "d".to_string() },
            &ContentTable::default(),
        )
        .unwrap();
        assert!(!root.path().join("d").exists());
        assert_eq!(rm, AppliedEffect::DirRemoved { path: "d".to_string() });
    }

    #[test]
    fn rm_tree_removes_a_non_empty_directory_and_reports_what_it_saw() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("t/sub/empty")).unwrap();
        std::fs::write(root.path().join("t/a.txt"), b"a").unwrap();
        std::fs::write(root.path().join("t/sub/b.txt"), b"b").unwrap();
        std::fs::write(root.path().join("t-sibling.txt"), b"keep").unwrap();

        let effect = apply_op(
            &clock(),
            root.path(),
            &Op::RmTree { path: "t".to_string() },
            &ContentTable::default(),
        )
        .unwrap();

        assert!(!root.path().join("t").exists());
        assert!(root.path().join("t-sibling.txt").exists());
        assert_eq!(
            effect,
            AppliedEffect::TreeRemoved {
                path: "t".to_string(),
                observed: ["t", "t/a.txt", "t/sub", "t/sub/b.txt", "t/sub/empty"]
                    .map(String::from)
                    .to_vec(),
            }
        );

        let again = apply_op(
            &clock(),
            root.path(),
            &Op::RmTree { path: "t".to_string() },
            &ContentTable::default(),
        )
        .unwrap();
        assert_eq!(again, AppliedEffect::TreeRemoved { path: "t".to_string(), observed: vec![] });
    }

    #[test]
    fn rename_tree_moves_every_descendant_under_a_new_parent() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("from/empty")).unwrap();
        std::fs::write(root.path().join("from/f.txt"), b"f").unwrap();

        let effect = apply_op(
            &clock(),
            root.path(),
            &Op::RenameTree { from: "from".to_string(), to: "new/to".to_string() },
            &ContentTable::default(),
        )
        .unwrap();

        assert!(!root.path().join("from").exists());
        assert!(root.path().join("new/to/empty").is_dir());
        assert_eq!(std::fs::read(root.path().join("new/to/f.txt")).unwrap(), b"f");
        assert_eq!(
            effect,
            AppliedEffect::TreeRenamed {
                from: "from".to_string(),
                to: "new/to".to_string(),
                observed: ["from", "from/empty", "from/f.txt"].map(String::from).to_vec(),
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn chmod_sets_and_clears_owner_exec_bit_observably() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("s.sh"), b"#!/bin/sh\n").unwrap();

        // exec_bit = true -> 0o755, owner-exec bit observable in metadata.
        let on = apply_op(
            &clock(),
            root.path(),
            &Op::Chmod { path: "s.sh".to_string(), exec_bit: true },
            &ContentTable::default(),
        )
        .unwrap();
        assert_eq!(
            on,
            AppliedEffect::ChmodApplied { path: "s.sh".to_string(), exec_bit: true, mode: 0o755 }
        );
        let mode = std::fs::metadata(root.path().join("s.sh")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        assert_ne!(mode & 0o100, 0, "owner-exec bit should be set");

        // exec_bit = false -> 0o644, owner-exec bit cleared.
        let off = apply_op(
            &clock(),
            root.path(),
            &Op::Chmod { path: "s.sh".to_string(), exec_bit: false },
            &ContentTable::default(),
        )
        .unwrap();
        assert_eq!(
            off,
            AppliedEffect::ChmodApplied { path: "s.sh".to_string(), exec_bit: false, mode: 0o644 }
        );
        let mode = std::fs::metadata(root.path().join("s.sh")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        assert_eq!(mode & 0o100, 0, "owner-exec bit should be cleared");
    }

    #[cfg(unix)]
    #[test]
    fn chmod_of_missing_file_is_a_noop() {
        let root = tempfile::tempdir().unwrap();
        let effect = apply_op(
            &clock(),
            root.path(),
            &Op::Chmod { path: "gone".to_string(), exec_bit: true },
            &ContentTable::default(),
        )
        .unwrap();

        assert!(matches!(effect, AppliedEffect::ChmodNoop { .. }));
    }

    #[test]
    fn conflicting_concurrent_is_reported_not_applied() {
        let root = tempfile::tempdir().unwrap();
        let before: Vec<_> = std::fs::read_dir(root.path()).unwrap().collect();

        let op = Op::ConflictingConcurrent { paths: vec!["a".to_string(), "b".to_string()] };
        let effect = apply_op(&clock(), root.path(), &op, &ContentTable::default()).unwrap();

        assert!(matches!(effect, AppliedEffect::NotASingleOpAction { .. }));
        // Nothing was written to the device root.
        let after: Vec<_> = std::fs::read_dir(root.path()).unwrap().collect();
        assert_eq!(before.len(), after.len());
    }

    #[test]
    fn replay_is_deterministic_same_op_and_clock_same_mtime() {
        let table = content_table();
        let op = Op::Write { path: "a.txt".to_string(), content_id: 1 };

        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();

        let effect_a = apply_op(&clock(), root_a.path(), &op, &table).unwrap();
        let effect_b = apply_op(&clock(), root_b.path(), &op, &table).unwrap();

        // Same recorded effect (bytes len + stamped mtime).
        assert_eq!(effect_a, effect_b);

        // And the same mtime actually landed on disk in both runs.
        let mtime_a = std::fs::metadata(root_a.path().join("a.txt")).unwrap().modified().unwrap();
        let mtime_b = std::fs::metadata(root_b.path().join("a.txt")).unwrap().modified().unwrap();
        assert_eq!(mtime_a, mtime_b);
    }
}
