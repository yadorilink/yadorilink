//! The on-disk half of "this group is synced": every file the index says is current must be on
//! disk with exactly the indexed bytes before a replacement is confirmed.
//!
//! The status predicate (`group_is_synced`) rests on the index's bookkeeping. For a database
//! restored from a backup that is not proof that the files are really here, so the confirm waits
//! for this check, which reads the disk. Fail closed: a missing, truncated, different or
//! unreadable entry fails it, and nothing on disk is ever changed.
//!
//! * Incremental: each pass hashes a bounded amount (bytes and entries) from a cursor, on a
//!   blocking thread, so a large folder never stalls the runtime and no pass sleeps.
//! * A verified entry keeps a stat fingerprint taken BEFORE it was hashed (size, mtime and, where
//!   the platform has them, inode, device and ctime). A completed verification never authorizes a
//!   confirm by itself: [`refresh`] runs immediately before every confirm call, re-stats every
//!   entry and re-hashes any whose fingerprint changed, so a file damaged after the verification
//!   (for example while the service answered 409) stops the confirm. A stat taken
//!   within a couple of seconds of the file's mtime is "racy" (a same-size rewrite in the same
//!   timestamp tick leaves it unchanged), so such an entry is re-read instead of trusted. The
//!   order is: verify, then [`refresh`] of every group (this is the settle step: it re-reads every
//!   racy entry), then the stat-only final sweep, which never reads content and fails closed on any
//!   entry still racy (it settles on a later pass). Where the
//!   platform has no ctime/inode (not unix) a same-size rewrite with a restored mtime is not
//!   noticed; that is a documented limit, and the window between the refresh and the confirm call
//!   remains.
//! * With several groups the refresh of each is followed, once all are refreshed, by a stat-only
//!   [`still_unchanged`] pass over all of them, so a long re-hash of a later group never widens
//!   an earlier group's window beyond a stat sweep.
//! * Entries added to the index after a snapshot was taken are verified at the next reload (the
//!   snapshot is renewed after any mismatch); the refresh before a confirm covers the snapshot.
//! * Every parent directory of an entry must be a real directory, never a link, so an entry is
//!   never read through a link that leaves the folder.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use yadorilink_local_storage::{
    disk_matches_expected_object, DiskContentComparison, ExpectedObject,
};
use yadorilink_replica_domain::file::{BlockInfo, RecordKind};

/// Content hashed per pass, shared by the groups still being verified. A single file may
/// overshoot it; it is checked whole.
pub(super) const BYTE_BUDGET_PER_PASS: u64 = 1 << 30;
/// Entries (files, links, directories) examined per pass, shared the same way.
pub(super) const ENTRY_BUDGET_PER_PASS: usize = 20_000;

/// One current, non-deleted index entry and what the disk must hold for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedEntry {
    pub(crate) path: String,
    pub(crate) kind: RecordKind,
    pub(crate) blocks: Vec<BlockInfo>,
    pub(crate) symlink_target: Option<Vec<u8>>,
}

/// What a stat said about an entry when it was verified.
#[derive(Clone, Copy, Debug)]
pub(super) struct Fingerprint {
    size: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
    /// The mtime was within [`RACY_WINDOW`] of the moment of the stat (or unknown or in the
    /// future): a same-size rewrite in the same timestamp tick would leave the stat unchanged, so
    /// a matching stat is not proof of unchanged content. Not part of the comparison.
    racy: bool,
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(unix)]
        let same_identity = self.identity == other.identity;
        #[cfg(not(unix))]
        let same_identity = true;
        self.size == other.size && self.modified == other.modified && same_identity
    }
}

impl Eq for Fingerprint {}

/// Timestamps are coarse (a filesystem tick, a cached clock, FAT's two seconds): a file modified
/// less than this long before it was stat-ed can be rewritten without its stat changing.
const RACY_WINDOW: Duration = Duration::from_secs(2);

fn fingerprint(path: &Path) -> Option<Fingerprint> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino(), metadata.ctime(), metadata.ctime_nsec())
    };
    let modified = metadata.modified().ok();
    let racy = modified
        .is_none_or(|m| SystemTime::now().duration_since(m).map_or(true, |age| age < RACY_WINDOW));
    Some(Fingerprint {
        size: metadata.len(),
        modified,
        #[cfg(unix)]
        identity,
        racy,
    })
}

/// Whether the stat recorded when an entry verified still proves its content unchanged: the stat
/// matches and the recorded one was not racy (a racy one proves nothing, so the bytes are read).
fn stat_proves_unchanged(path: &Path, recorded: Option<Fingerprint>) -> bool {
    recorded.is_some_and(|r| !r.racy) && fingerprint(path) == recorded
}

/// One group's verification: its index snapshot, the fingerprints of what verified, and a cursor.
pub(super) struct GroupState {
    pub(super) entries: Vec<ExpectedEntry>,
    pub(super) fingerprints: Vec<Option<Fingerprint>>,
    /// Every entry before this position verified in this snapshot.
    pub(super) next: usize,
    /// Every entry verified (a refresh still has to pass before each confirm).
    pub(super) done: bool,
    /// After a failure: the snapshot is stale or the disk is damaged. The next pass reads a fresh
    /// snapshot and resumes at the first path not before this one, keeping earlier progress.
    pub(super) resume_at: Option<String>,
}

impl GroupState {
    pub(super) fn fresh(entries: Vec<ExpectedEntry>) -> Self {
        let fingerprints = vec![None; entries.len()];
        Self { entries, fingerprints, next: 0, done: false, resume_at: None }
    }

    /// Replaces the snapshot, keeping the fingerprint of every entry whose content identity is
    /// unchanged, wherever it sits: one legitimate edit costs only that entry, not everything
    /// after the cursor. The cursor goes back to the resume point; entries after it whose
    /// fingerprint still matches the disk are skipped by [`verify_step`] without hashing.
    pub(super) fn reload(&mut self, entries: Vec<ExpectedEntry>) {
        let resume = self.resume_at.take().unwrap_or_default();
        let mut fingerprints = vec![None; entries.len()];
        for (index, entry) in entries.iter().enumerate() {
            if let Ok(old) = self.entries.binary_search_by(|o| o.path.cmp(&entry.path)) {
                if self.entries[old] == *entry {
                    fingerprints[index] = self.fingerprints[old];
                }
            }
        }
        self.next = entries.partition_point(|e| e.path.as_str() < resume.as_str());
        self.done = false;
        self.entries = entries;
        self.fingerprints = fingerprints;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// Everything before this position verified; more remains.
    Progress { next: usize },
    /// Every entry verified.
    Complete,
    /// The entry at `index` is not exactly as indexed.
    Failed { index: usize, why: String },
}

/// Verifies `state.entries[state.next..]` until the budget is spent, recording fingerprints.
pub(super) fn verify_step(
    root: &Path,
    state: &mut GroupState,
    byte_budget: u64,
    entry_budget: usize,
) -> Step {
    let mut bytes = 0u64;
    // Only entries that were actually hashed count toward the budgets; skipping one whose
    // fingerprint still matches is free (the pre-confirm refresh stats every entry unbounded).
    let mut hashed = 0usize;
    let mut parents = HashSet::new();
    while state.next < state.entries.len() {
        if hashed >= entry_budget || bytes >= byte_budget {
            return Step::Progress { next: state.next };
        }
        let index = state.next;
        // Verified before and still the same on disk: no need to hash it again.
        let unchanged = parents_are_directories(root, &state.entries[index].path, &mut parents)
            .is_ok()
            && stat_proves_unchanged(
                &root.join(&state.entries[index].path),
                state.fingerprints[index],
            );
        if unchanged {
            state.next += 1;
            continue;
        }
        if let Err(why) = verify_one(root, state, index, &mut parents) {
            return Step::Failed { index, why: format!("{}: {why}", state.entries[index].path) };
        }
        bytes += state.entries[index].blocks.iter().map(|b| u64::from(b.size)).sum::<u64>();
        hashed += 1;
        state.next += 1;
    }
    state.done = true;
    Step::Complete
}

/// The fresh check made immediately before every confirm call: re-stats every entry and re-hashes
/// any whose fingerprint (or parent chain) is not what was verified. Cheap while nothing changed.
pub(super) fn refresh(root: &Path, state: &mut GroupState) -> Step {
    let mut parents = HashSet::new();
    for index in 0..state.entries.len() {
        let unchanged = parents_are_directories(root, &state.entries[index].path, &mut parents)
            .is_ok()
            && stat_proves_unchanged(
                &root.join(&state.entries[index].path),
                state.fingerprints[index],
            );
        if unchanged {
            continue;
        }
        if let Err(why) = verify_one(root, state, index, &mut parents) {
            return Step::Failed { index, why: format!("{}: {why}", state.entries[index].path) };
        }
    }
    Step::Complete
}

/// A stat-only look at every entry, run last (after [`refresh`] of every group, which re-reads
/// every entry whose stat proves nothing) so the time between the fresh check of the first group
/// and the confirm call does not include another group's re-hashing. It never reads file
/// content: an entry whose fingerprint or parent chain is not what was verified fails it, and so
/// does one whose recorded stat is still racy (modified within the window of its stat, or the
/// clock went backwards): that fails closed as "changed", and the next pass re-reads it once it
/// has settled.
pub(super) fn still_unchanged(root: &Path, state: &GroupState) -> Step {
    let mut parents = HashSet::new();
    for index in 0..state.entries.len() {
        let unchanged = parents_are_directories(root, &state.entries[index].path, &mut parents)
            .is_ok()
            && stat_proves_unchanged(
                &root.join(&state.entries[index].path),
                state.fingerprints[index],
            );
        if !unchanged {
            return Step::Failed {
                index,
                why: format!("{}: changed since it was verified", state.entries[index].path),
            };
        }
    }
    Step::Complete
}

fn verify_one(
    root: &Path,
    state: &mut GroupState,
    index: usize,
    parents: &mut HashSet<PathBuf>,
) -> Result<(), &'static str> {
    verify_one_observed(root, state, index, parents, &|| {})
}

/// [`verify_one`] with a hook that runs between reading the bytes and the closing stat.
pub(super) fn verify_one_observed(
    root: &Path,
    state: &mut GroupState,
    index: usize,
    parents: &mut HashSet<PathBuf>,
    after_read: &dyn Fn(),
) -> Result<(), &'static str> {
    let entry = &state.entries[index];
    parents_are_directories(root, &entry.path, parents)?;
    let full = root.join(&entry.path);
    // Taken before the bytes are read, and compared again after: a change while hashing means the
    // bytes read are not (all) what is at the path now, so the entry is not verified.
    let before = fingerprint(&full).ok_or("cannot be read")?;
    verify_entry(&full, entry)?;
    after_read();
    if fingerprint(&full) != Some(before) {
        return Err("changed while it was being read");
    }
    state.fingerprints[index] = Some(before);
    Ok(())
}

/// Every directory between the folder and the entry must be a real directory, not a link.
fn parents_are_directories(
    root: &Path,
    relative: &str,
    checked: &mut HashSet<PathBuf>,
) -> Result<(), &'static str> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.components().any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("not a path inside the folder");
    }
    let Some(parent) = relative.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    if checked.contains(parent) {
        return Ok(());
    }
    let mut current = root.to_path_buf();
    for part in parent.components() {
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err("a parent is not a plain directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err("missing on disk")
            }
            Err(_) => return Err("cannot be read"),
        }
    }
    checked.insert(parent.to_path_buf());
    Ok(())
}

fn verify_entry(full: &Path, entry: &ExpectedEntry) -> Result<(), &'static str> {
    let expected = match entry.kind {
        RecordKind::File => ExpectedObject::File { blocks: &entry.blocks },
        RecordKind::Symlink => ExpectedObject::Symlink { target: entry.symlink_target.as_deref() },
        RecordKind::Directory => ExpectedObject::Directory,
    };
    match disk_matches_expected_object(full, expected) {
        Ok(DiskContentComparison::Matched) => Ok(()),
        Ok(DiskContentComparison::Absent) => Err("missing on disk"),
        Ok(DiskContentComparison::PresentButDifferent) => Err("differs from the indexed content"),
        Err(_) => Err("cannot be read"),
    }
}
