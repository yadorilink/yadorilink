//! Files the capture scan could not read, and whether the person has to act.
//!
//! The scan already skips an unreadable file (its path joins the failed prefixes, so nothing is
//! inferred as deleted under it). This ledger is what makes the skip visible: it remembers, per
//! folder group and for this run only, which files failed and why, classifies each failure once
//! here so Status and the CLI share one answer, and drops an entry as soon as the file reads again
//! or is gone. It is deliberately not persisted: the startup scan reads every file again, so an
//! item that still holds after a restart is rediscovered by the first pass.

use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A read failure of the same kind this many passes in a row, over at least
/// [`PERSISTENT_AFTER`], is no longer treated as passing.
pub const PERSISTENT_ATTEMPTS: u32 = 3;
/// See [`PERSISTENT_ATTEMPTS`].
pub const PERSISTENT_AFTER: Duration = Duration::from_secs(300);

/// Why a file could not be read, as a stable code a shell or the CLI can match on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnreadableReason {
    /// The operating system refused access: the person has to change the file's permissions.
    PermissionDenied,
    /// The path is not a regular file any more (a directory where a file was, or the reverse).
    NotRegularFile,
    /// Any other read error (a vanished file, a busy file, a device error).
    ReadFailed,
}

impl UnreadableReason {
    #[must_use]
    pub fn from_io(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            ErrorKind::IsADirectory | ErrorKind::NotADirectory => Self::NotRegularFile,
            _ => Self::ReadFailed,
        }
    }

    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::PermissionDenied => "permission_denied",
            Self::NotRegularFile => "not_a_regular_file",
            Self::ReadFailed => "read_failed",
        }
    }
}

/// Whether a failure is expected to pass by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnreadableClass {
    /// Retried by the next pass; not shown to the person yet.
    Transient,
    /// Will not pass without the person: shown as an attention item.
    NeedsUser,
}

/// THE classification, used for every consumer. A refusal or a wrong kind of object does not heal
/// by waiting; anything else becomes persistent only by failing again and again over time.
#[must_use]
pub fn classify(reason: UnreadableReason, attempts: u32, failing_for: Duration) -> UnreadableClass {
    match reason {
        UnreadableReason::PermissionDenied | UnreadableReason::NotRegularFile => {
            UnreadableClass::NeedsUser
        }
        UnreadableReason::ReadFailed
            if attempts >= PERSISTENT_ATTEMPTS && failing_for >= PERSISTENT_AFTER =>
        {
            UnreadableClass::NeedsUser
        }
        UnreadableReason::ReadFailed => UnreadableClass::Transient,
    }
}

/// One file the person has to deal with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnreadableFile {
    /// Root-relative path, `/`-separated.
    pub path: String,
    pub reason: UnreadableReason,
}

#[derive(Clone, Copy)]
struct Entry {
    reason: UnreadableReason,
    first_seen: Instant,
    attempts: u32,
    class: UnreadableClass,
    /// Failed in the pass in progress (see [`UnreadableFileLedger::begin_pass`]).
    touched: bool,
}

/// What recording a failure established, so the caller logs a change once and a repeat quietly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// New path, a different reason, or a move to [`UnreadableClass::NeedsUser`].
    pub worth_logging: bool,
    pub class: UnreadableClass,
}

#[derive(Default)]
pub struct UnreadableFileLedger {
    groups: Mutex<HashMap<String, BTreeMap<String, Entry>>>,
}

impl UnreadableFileLedger {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, BTreeMap<String, Entry>>> {
        self.groups.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Notes that `path` failed to read in a pass that ran at `now`.
    pub fn record_failure(
        &self,
        group_id: &str,
        path: &str,
        reason: UnreadableReason,
        now: Instant,
    ) -> Recorded {
        let mut groups = self.lock();
        let entries = groups.entry(group_id.to_owned()).or_default();
        let previous = entries.get(path).copied();
        let (first_seen, attempts) = match previous {
            Some(entry) if entry.reason == reason => (entry.first_seen, entry.attempts + 1),
            _ => (now, 1),
        };
        let class = classify(reason, attempts, now.saturating_duration_since(first_seen));
        let worth_logging = match previous {
            None => true,
            Some(entry) => {
                entry.reason != reason
                    || (entry.class != class && class == UnreadableClass::NeedsUser)
            }
        };
        entries
            .insert(path.to_owned(), Entry { reason, first_seen, attempts, class, touched: true });
        Recorded { worth_logging, class }
    }

    /// The path read fine (or was captured): it is no longer a problem.
    pub fn forget(&self, group_id: &str, path: &str) {
        let mut groups = self.lock();
        if let Some(entries) = groups.get_mut(group_id) {
            entries.remove(path);
            if entries.is_empty() {
                groups.remove(group_id);
            }
        }
    }

    /// A pass over `group_id` starts: failures recorded from now on belong to it. Passes of one
    /// group never overlap (the reconcile gate), so one mark per entry is enough.
    pub fn begin_pass(&self, group_id: &str) {
        if let Some(entries) = self.lock().get_mut(group_id) {
            entries.values_mut().for_each(|entry| entry.touched = false);
        }
    }

    /// A pass that read the whole tree ends: only what failed in it stays, together with the
    /// entries `unreached` says the pass could not reach (under a directory it could not walk),
    /// whose state it cannot speak for.
    pub fn settle_full_pass(&self, group_id: &str, unreached: impl Fn(&str) -> bool) {
        let mut groups = self.lock();
        if let Some(entries) = groups.get_mut(group_id) {
            entries.retain(|path, entry| entry.touched || unreached(path));
            if entries.is_empty() {
                groups.remove(group_id);
            }
        }
    }

    /// A pass that does not re-read files it already knows (the add-only backstop) cannot tell a
    /// file recovered from one still failing, so each standing entry is checked on its own,
    /// without reading content or opening anything that is not a regular file (a replacement
    /// FIFO would block): gone, or a symlink, ends any entry; a regular file ends a refusal or a
    /// wrong-kind entry once it opens. A read error that happens past `open` is only ended by a
    /// pass that reads the file again, so it keeps counting toward being persistent.
    pub fn probe_standing(&self, group_id: &str, root: &Path) {
        let standing: Vec<(String, UnreadableReason)> = {
            let groups = self.lock();
            groups
                .get(group_id)
                .map(|e| e.iter().map(|(path, entry)| (path.clone(), entry.reason)).collect())
                .unwrap_or_default()
        };
        for (path, reason) in standing {
            let full = root.join(&path);
            let recovered = match std::fs::symlink_metadata(&full) {
                Err(error) => error.kind() == ErrorKind::NotFound,
                Ok(meta) if meta.file_type().is_symlink() => true,
                // A directory (reported itself, or a file's path it replaced) ends, whatever the
                // reason, once it lists again end to end.
                Ok(meta) if meta.is_dir() => {
                    std::fs::read_dir(&full).is_ok_and(|mut list| list.all(|e| e.is_ok()))
                }
                Ok(meta) if !meta.is_file() => false,
                Ok(_) => match reason {
                    UnreadableReason::ReadFailed => false,
                    UnreadableReason::NotRegularFile => true,
                    UnreadableReason::PermissionDenied => std::fs::File::open(&full).is_ok(),
                },
            };
            if recovered {
                self.forget(group_id, &path);
            }
        }
    }

    /// Every standing entry of `group_id`, transient ones included.
    #[cfg(test)]
    pub(crate) fn standing(&self, group_id: &str) -> Vec<String> {
        self.lock().get(group_id).map(|e| e.keys().cloned().collect()).unwrap_or_default()
    }

    /// The files of `group_id` that need the person, sorted by path.
    #[must_use]
    pub fn needing_user(&self, group_id: &str) -> Vec<UnreadableFile> {
        let groups = self.lock();
        groups
            .get(group_id)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, entry)| entry.class == UnreadableClass::NeedsUser)
                    .map(|(path, entry)| UnreadableFile {
                        path: path.clone(),
                        reason: entry.reason,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &str = "g";

    #[test]
    fn a_refusal_needs_the_person_at_once() {
        assert_eq!(
            classify(UnreadableReason::PermissionDenied, 1, Duration::ZERO),
            UnreadableClass::NeedsUser
        );
        assert_eq!(
            classify(UnreadableReason::NotRegularFile, 1, Duration::ZERO),
            UnreadableClass::NeedsUser
        );
    }

    #[test]
    fn another_read_error_is_passing_until_it_repeats_over_time() {
        let r = UnreadableReason::ReadFailed;
        assert_eq!(classify(r, 1, Duration::ZERO), UnreadableClass::Transient);
        // Many attempts, not long enough.
        assert_eq!(classify(r, 50, PERSISTENT_AFTER / 2), UnreadableClass::Transient);
        // Long enough, too few attempts.
        assert_eq!(classify(r, 2, PERSISTENT_AFTER * 2), UnreadableClass::Transient);
        assert_eq!(classify(r, PERSISTENT_ATTEMPTS, PERSISTENT_AFTER), UnreadableClass::NeedsUser);
    }

    #[test]
    fn io_kinds_map_to_reasons() {
        assert_eq!(
            UnreadableReason::from_io(ErrorKind::PermissionDenied),
            UnreadableReason::PermissionDenied
        );
        assert_eq!(
            UnreadableReason::from_io(ErrorKind::IsADirectory),
            UnreadableReason::NotRegularFile
        );
        assert_eq!(UnreadableReason::from_io(ErrorKind::TimedOut), UnreadableReason::ReadFailed);
    }

    #[test]
    fn a_repeated_failure_logs_once_and_a_transient_one_is_not_listed() {
        let ledger = UnreadableFileLedger::default();
        let t0 = Instant::now();
        let first = ledger.record_failure(GROUP, "a", UnreadableReason::PermissionDenied, t0);
        let again = ledger.record_failure(GROUP, "a", UnreadableReason::PermissionDenied, t0);
        assert!(first.worth_logging);
        assert!(!again.worth_logging, "the same path and reason is not logged twice");
        // A different reason is news.
        assert!(
            ledger.record_failure(GROUP, "a", UnreadableReason::NotRegularFile, t0).worth_logging
        );

        ledger.record_failure(GROUP, "busy", UnreadableReason::ReadFailed, t0);
        let listed = ledger.needing_user(GROUP);
        assert_eq!(listed.len(), 1, "a transient failure is not shown");
        assert_eq!(listed[0].path, "a");
    }

    #[test]
    fn a_read_error_becomes_listed_and_logged_once_when_it_persists() {
        let ledger = UnreadableFileLedger::default();
        let t0 = Instant::now();
        let r = UnreadableReason::ReadFailed;
        for i in 0..2 {
            let rec = ledger.record_failure(GROUP, "p", r, t0 + Duration::from_secs(i * 200));
            assert_eq!(rec.class, UnreadableClass::Transient);
        }
        assert!(ledger.needing_user(GROUP).is_empty());
        let rec = ledger.record_failure(GROUP, "p", r, t0 + PERSISTENT_AFTER);
        assert_eq!(rec.class, UnreadableClass::NeedsUser);
        assert!(rec.worth_logging, "the move to needing the person is logged once");
        assert_eq!(ledger.needing_user(GROUP).len(), 1);
        let after = ledger.record_failure(GROUP, "p", r, t0 + PERSISTENT_AFTER * 2);
        assert!(!after.worth_logging);
    }

    #[test]
    fn a_full_pass_keeps_only_what_failed_in_it_and_forget_removes_one() {
        let ledger = UnreadableFileLedger::default();
        let t = Instant::now();
        for p in ["a", "b", "c"] {
            ledger.record_failure(GROUP, p, UnreadableReason::PermissionDenied, t);
        }
        ledger.begin_pass(GROUP);
        for p in ["b", "c"] {
            ledger.record_failure(GROUP, p, UnreadableReason::PermissionDenied, t);
        }
        ledger.settle_full_pass(GROUP, |_| false);
        ledger.forget(GROUP, "c");
        let left: Vec<_> = ledger.needing_user(GROUP).into_iter().map(|f| f.path).collect();
        assert_eq!(left, ["b"]);
        ledger.begin_pass(GROUP);
        // An entry the pass could not reach is kept, not read as recovered.
        ledger.settle_full_pass(GROUP, |path| path == "b");
        assert_eq!(ledger.needing_user(GROUP).len(), 1);
        ledger.begin_pass(GROUP);
        ledger.settle_full_pass(GROUP, |_| false);
        assert!(ledger.needing_user(GROUP).is_empty());
    }

    #[test]
    fn a_probe_ends_only_what_opening_proves_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let readable = dir.path().join("readable.txt");
        std::fs::write(&readable, b"x").unwrap();
        let ledger = UnreadableFileLedger::default();
        let t = Instant::now();
        // A read error past `open` is not ended by an open that works.
        ledger.record_failure(GROUP, "readable.txt", UnreadableReason::ReadFailed, t);
        ledger.probe_standing(GROUP, dir.path());
        assert_eq!(ledger.needing_user(GROUP).len(), 0, "still transient, but still standing");
        ledger.record_failure(GROUP, "readable.txt", UnreadableReason::ReadFailed, t);
        ledger.record_failure(GROUP, "readable.txt", UnreadableReason::ReadFailed, t);
        ledger.probe_standing(GROUP, dir.path());
        // Attempts kept counting (three passes), so only the time is missing.
        let later = t + PERSISTENT_AFTER;
        assert_eq!(
            ledger.record_failure(GROUP, "readable.txt", UnreadableReason::ReadFailed, later).class,
            UnreadableClass::NeedsUser
        );
        // A refusal ends once the file opens; a file that is gone ends too.
        ledger.record_failure(GROUP, "readable.txt", UnreadableReason::PermissionDenied, t);
        ledger.record_failure(GROUP, "gone.txt", UnreadableReason::PermissionDenied, t);
        ledger.probe_standing(GROUP, dir.path());
        assert!(ledger.needing_user(GROUP).is_empty());
    }

    /// A directory that listed badly for any reason is over once it lists again.
    #[test]
    fn a_probe_ends_a_directory_report_of_any_reason_once_it_lists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let ledger = UnreadableFileLedger::default();
        let t = Instant::now();
        ledger.record_failure(GROUP, "sub", UnreadableReason::ReadFailed, t);
        ledger.probe_standing(GROUP, dir.path());
        assert!(ledger.standing(GROUP).is_empty());
    }
}
