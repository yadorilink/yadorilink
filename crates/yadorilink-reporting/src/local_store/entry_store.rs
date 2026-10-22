//! Shared bounded-storage engine behind `queue.rs` and
//! `error_candidates.rs`. Both are "a directory of JSON files,
//! each a full `ReportEnvelope` plus small metadata, bounded by a
//! `RetentionPolicy`" — the only real differences are the directory name
//! and the default caps, so the file-scanning/retention logic lives here
//! once instead of twice.
//!
//! Retention age is measured from each file's on-disk mtime, not from the
//! `queued_at` string embedded in its metadata: `yadorilink-reporting`'s
//! `QueuedReportMetadata::queued_at` is a caller-supplied RFC 3339 string
//! with no parser round-trip anywhere in this crate (see `time.rs`), and
//! mtime is both simpler to use for eviction math and more trustworthy
//! (it can't be skewed by hand-editing a file's contents).

use std::path::{Path, PathBuf};

use crate::queue::{QueuedReportMetadata, RetentionPolicy};
use crate::schema::ReportEnvelope;
use serde::{Deserialize, Serialize};

use super::error::{ReportingResult, ReportingStorageError};
use super::time::{now_rfc3339, system_time_to_unix_seconds};

/// One stored entry: the exact envelope plus the metadata shown by
/// list/show commands. Kept as a single file per entry (`<id>.json`) so a
/// directory listing of the store *is* the queue/candidate list, and
/// deleting one report is one `remove_file` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    metadata: QueuedReportMetadata,
    envelope: ReportEnvelope,
}

pub struct EntryStore {
    dir: PathBuf,
    policy: RetentionPolicy,
}

impl EntryStore {
    pub fn new(dir: impl Into<PathBuf>, policy: RetentionPolicy) -> Self {
        EntryStore { dir: dir.into(), policy }
    }

    /// `id` reaches this store directly from IPC/CLI input
    /// (`report queue show/delete <id>`), unvalidated by anything upstream
    /// -- rejects anything that isn't a single plain path component before
    /// building a path from it, so `id` can never escape `self.dir`: a
    /// path separator would make `format!("{id}.json")` more than one
    /// component, and a leading `/` would make `PathBuf::join` treat it as
    /// absolute and discard `self.dir` entirely (the `.json` suffix always
    /// appended below means a bare `.`/`..` can never resolve to either
    /// special path component on its own, but they're rejected too, as a
    /// plain well-formed-id sanity check). A legitimate id is always the
    /// UUID `insert` generates, which satisfies all of this trivially.
    fn entry_path(&self, id: &str) -> ReportingResult<PathBuf> {
        if id.is_empty() || id == "." || id == ".." || id.contains('/') || id.contains('\\') {
            return Err(ReportingStorageError::InvalidEntryId(id.to_string()));
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    /// Persists `envelope` as a new entry with a fresh, locally-generated
    /// ID (never derived from any account/device identity, same reasoning
    /// as `consent_store::new_reporter_id`), applies the retention policy
    /// immediately afterward, and returns the new entry's metadata.
    pub fn insert(&self, envelope: ReportEnvelope) -> ReportingResult<QueuedReportMetadata> {
        yadorilink_fs_platform::durable_dir::create_dir_all_durably(&self.dir)?;
        let report_id = uuid::Uuid::new_v4().to_string();
        let size_bytes = serde_json::to_vec(&envelope)?.len();
        let metadata = QueuedReportMetadata {
            report_id: report_id.clone(),
            report_type: envelope.report_type.clone(),
            queued_at: now_rfc3339(),
            size_bytes,
            submit_attempts: 0,
        };
        let entry = StoredEntry { metadata: metadata.clone(), envelope };
        let json = serde_json::to_string_pretty(&entry)?;
        // Always a freshly-generated UUID above -- never fails validation.
        let path = self.entry_path(&report_id)?;
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &path)?;
        // Best-effort: a retention-eviction failure shouldn't fail the
        // insert that triggered it. The freshly-inserted entry itself is
        // never a retention target (see `apply_retention`'s doc comment).
        if let Err(e) = self.apply_retention() {
            tracing::warn!(error = %e, dir = %self.dir.display(), "reporting: retention sweep failed after insert");
        }
        Ok(metadata)
    }

    fn read_entry(&self, path: &Path) -> ReportingResult<StoredEntry> {
        let contents = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&contents)?)
    }

    /// Lists every entry's metadata plus its file mtime, oldest-eviction
    /// order not guaranteed (callers needing sorted order sort themselves;
    /// `list` below sorts by `queued_at` for display).
    fn scan(&self) -> ReportingResult<Vec<(String, QueuedReportMetadata, u64)>> {
        let mut out = Vec::new();
        let read_dir = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue; // skips stray .json.tmp leftovers from an interrupted write too
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
            let stored = match self.read_entry(&path) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, path = %path.display(), "reporting: skipping unreadable entry during scan");
                    continue;
                }
            };
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(system_time_to_unix_seconds)
                .unwrap_or(0);
            out.push((stem.to_string(), stored.metadata, mtime));
        }
        Ok(out)
    }

    pub fn list(&self) -> ReportingResult<Vec<QueuedReportMetadata>> {
        let mut entries = self.scan()?;
        entries.sort_by(|a, b| a.1.queued_at.cmp(&b.1.queued_at));
        Ok(entries.into_iter().map(|(_, meta, _)| meta).collect())
    }

    pub fn show(&self, id: &str) -> ReportingResult<Option<ReportEnvelope>> {
        // A syntactically-invalid id (see `entry_path`'s doc comment) can
        // never have a corresponding entry -- treated the same as a
        // genuine NotFound, not surfaced as a distinct error.
        let path = match self.entry_path(id) {
            Ok(path) => path,
            Err(ReportingStorageError::InvalidEntryId(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        match self.read_entry(&path) {
            Ok(stored) => Ok(Some(stored.envelope)),
            Err(ReportingStorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Returns `true` if an entry existed and was removed, `false` if
    /// there was nothing to delete (not an error — deleting an
    /// already-gone entry, e.g. from a concurrent retention sweep, is a
    /// no-op, not a failure; a syntactically-invalid id, see
    /// `entry_path`'s doc comment, is treated the same way, since it can
    /// never have a corresponding entry either).
    pub fn delete(&self, id: &str) -> ReportingResult<bool> {
        let path = match self.entry_path(id) {
            Ok(path) => path,
            Err(ReportingStorageError::InvalidEntryId(_)) => return Ok(false),
            Err(e) => return Err(e),
        };
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Deletes every entry in the store. Returns the number removed.
    pub fn flush(&self) -> ReportingResult<usize> {
        let entries = self.scan()?;
        let mut removed = 0;
        for (id, _, _) in entries {
            if self.delete(&id)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// records one more failed submission attempt against `id`
    /// (used by the queue-retry sweep's backoff — see `retry.rs`),
    /// returning the new attempt count, or `None` if the entry no longer
    /// exists (e.g. deleted concurrently). Rewrites the entry file in
    /// place, preserving the envelope untouched; this does bump the
    /// file's mtime (and therefore, per this module's age-tracking, its
    /// retention clock) — an accepted trade-off, since a report actively
    /// being retried is exactly the kind of entry that shouldn't be
    /// evicted for "looking old" while still under active retry.
    pub fn increment_submit_attempts(&self, id: &str) -> ReportingResult<Option<u32>> {
        let path = match self.entry_path(id) {
            Ok(path) => path,
            Err(ReportingStorageError::InvalidEntryId(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut stored = match self.read_entry(&path) {
            Ok(s) => s,
            Err(ReportingStorageError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        stored.metadata.submit_attempts += 1;
        let new_count = stored.metadata.submit_attempts;
        let json = serde_json::to_string_pretty(&stored)?;
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &path)?;
        Ok(Some(new_count))
    }

    /// Applies `self.policy` against the current contents and deletes
    /// whatever it says to evict, returning the evicted IDs. Uses file
    /// mtime (via `scan`) as the age source, not the metadata's
    /// `queued_at` string — see this module's doc comment.
    pub fn apply_retention(&self) -> ReportingResult<Vec<String>> {
        let entries = self.scan()?;
        let now = super::time::now_unix_seconds();
        let metas: Vec<QueuedReportMetadata> =
            entries.iter().map(|(_, meta, _)| meta.clone()).collect();
        let mtimes: std::collections::HashMap<String, u64> =
            entries.iter().map(|(_, meta, mtime)| (meta.report_id.clone(), *mtime)).collect();
        let evict = self
            .policy
            .entries_to_evict(&metas, now, |m| mtimes.get(&m.report_id).copied().unwrap_or(now));
        for id in &evict {
            self.delete(id)?;
        }
        Ok(evict)
    }
}

#[cfg(test)]
mod tests;
