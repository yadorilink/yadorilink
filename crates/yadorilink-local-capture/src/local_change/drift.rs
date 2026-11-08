//! The periodic drift check: a metadata-only comparison of the disk with the index, to find what a
//! filesystem watcher never reported (an overflow, a sleep, a network file system, an event stream
//! that was torn down and recreated).
//!
//! It changes nothing. It returns the paths that look different, and the caller sends each one
//! through the same per-path route a live watcher event takes, so the conflict and tombstone rules
//! are the live ones and not those of a bulk reconcile (which is not safe to run this often).
//!
//! What it compares: for an indexed file that is present on disk, size and modification time (the
//! stat gate every capture path uses); for a tombstoned path, whether something is on disk again;
//! for an indexed path that is not on disk, whether it is gone (confirmed by a second look).
//! What it cannot see: a rewrite that keeps both size and modification time. Reading every file to
//! find those is not "cheap", and the startup scan still does it.
//!
//! Safe against a missing volume: the root is verified against the identity recorded for the link
//! (a different or unmounted volume is an error, never a mass deletion), the walk does not cross a
//! device boundary, a directory that cannot be read suppresses the "gone" verdicts under it, and a
//! pass that would report more than half of the folder gone reports none of them.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_sync_sqlite::file_index::IndexedStatRow;

use super::path_policy::{
    is_excluded_from_sync, path_to_wire_relative_string, skip_reason_for_inadmissible_wire_path,
};
use super::scan::path_is_within_failed_subtree;
use super::LocalChangeProcessor;
use crate::error::LocalCaptureError;

/// How a pass is limited.
#[derive(Debug, Clone, Copy)]
pub struct DriftOptions {
    /// Entries looked at per second, at most. The walk sleeps to stay under it.
    pub max_entries_per_sec: u32,
    /// Wall-clock time after which the pass stops, reports what it found and says it is incomplete
    /// (no "gone" verdicts then: the inventory is partial).
    pub budget: Duration,
    /// The most candidates one pass returns.
    pub max_candidates: usize,
}

impl Default for DriftOptions {
    fn default() -> Self {
        Self {
            max_entries_per_sec: 20_000,
            budget: Duration::from_secs(30 * 60),
            max_candidates: 20_000,
        }
    }
}

/// Why a path is a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftKind {
    /// Indexed as present, on disk with another size or modification time.
    Changed,
    /// Indexed as deleted, and something is on disk again.
    Reappeared,
    /// Indexed as present, and gone from disk.
    Gone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftCandidate {
    pub rel_path: String,
    pub kind: DriftKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriftReport {
    pub candidates: Vec<DriftCandidate>,
    /// Entries looked at on disk.
    pub walked: u64,
    /// Whether the whole folder was walked (and so the "gone" verdicts are complete).
    pub complete: bool,
    /// Why "gone" verdicts were withheld, when they were.
    pub gone_withheld: Option<String>,
}

impl LocalChangeProcessor {
    /// Compares the disk under `root` with the index of `group_id`; see the module doc.
    pub fn detect_drift(
        &self,
        group_id: &str,
        root: &Path,
        options: DriftOptions,
    ) -> Result<DriftReport, LocalCaptureError> {
        let root = self.verified_root_of_established_link(group_id, root)?;
        let root = root.path();
        let ignore_set = self.ignore_set_for(group_id)?;
        let rows: HashMap<String, IndexedStatRow> = self
            .state
            .list_indexed_stat_rows(group_id)?
            .into_iter()
            .map(|row| (row.path.clone(), row))
            .collect();
        let materialization = self.state.list_materialization_states(group_id)?;

        let started = Instant::now();
        let mut report = DriftReport { complete: true, ..DriftReport::default() };
        let mut seen: HashSet<String> = HashSet::new();
        let mut failed_prefixes: Vec<String> = Vec::new();
        let mut scan_attributable = true;
        let walker = walkdir::WalkDir::new(root)
            .follow_links(false)
            .same_file_system(true)
            .into_iter()
            .filter_entry(|entry| {
                if entry.depth() == 0 {
                    return true;
                }
                if entry.file_type().is_dir()
                    && yadorilink_filesystem_sync::device_boundary::is_foreign_device_dir(
                        root,
                        entry.path(),
                    )
                {
                    return false;
                }
                let Ok(rel) = entry.path().strip_prefix(root) else { return false };
                !is_excluded_from_sync(rel, entry.file_type().is_dir(), &ignore_set)
            });
        for entry in walker {
            report.walked += 1;
            throttle(report.walked, started, options.max_entries_per_sec);
            if report.walked.is_multiple_of(256) && started.elapsed() > options.budget {
                report.complete = false;
                report.gone_withheld = Some("the pass ran out of time".into());
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    match error
                        .path()
                        .and_then(|p| p.strip_prefix(root).ok())
                        .and_then(path_to_wire_relative_string)
                    {
                        Some(rel) => failed_prefixes.push(rel),
                        None => scan_attributable = false,
                    }
                    continue;
                }
            };
            let Ok(rel) = entry.path().strip_prefix(root) else { continue };
            let Some(rel) = path_to_wire_relative_string(rel) else { continue };
            if rel.is_empty() || skip_reason_for_inadmissible_wire_path(&rel).is_some() {
                continue;
            }
            seen.insert(rel.clone());
            let Some(row) = rows.get(&rel) else { continue };
            let file_type = entry.file_type();
            if row.deleted {
                if file_type.is_file() || file_type.is_symlink() {
                    push(&mut report, &rel, DriftKind::Reappeared, options.max_candidates);
                }
                continue;
            }
            // Only a file the daemon holds as a physical object is compared: a placeholder or a
            // file being fetched or removed legitimately differs from its row.
            if !file_type.is_file()
                || row.kind != RecordKind::File
                || materialization.get(&rel).copied() != Some(MaterializationState::Present)
            {
                continue;
            }
            let Ok(metadata) = entry.metadata() else { continue };
            if metadata.len() != row.size || mtime_differs(&metadata, row.mtime_unix_nanos) {
                push(&mut report, &rel, DriftKind::Changed, options.max_candidates);
            }
        }

        if !report.complete {
            return Ok(report);
        }
        if !scan_attributable {
            report.gone_withheld = Some("a read error could not be attributed to a folder".into());
            return Ok(report);
        }
        // Paths the index holds as present that the walk did not see.
        let mut gone: Vec<&IndexedStatRow> = rows
            .values()
            .filter(|row| {
                !row.deleted
                    && !seen.contains(&row.path)
                    && (row.kind == RecordKind::Directory
                        || materialization.get(&row.path).copied()
                            == Some(MaterializationState::Present))
                    && !is_excluded_from_sync(
                        Path::new(&row.path),
                        row.kind == RecordKind::Directory,
                        &ignore_set,
                    )
                    && !path_is_within_failed_subtree(&row.path, &failed_prefixes)
            })
            .collect();
        let present_rows = rows.values().filter(|row| !row.deleted).count();
        if gone.len() > 100 && gone.len() * 2 > present_rows {
            report.gone_withheld = Some(format!(
                "{} of {} indexed paths look gone: more likely the wrong folder than deletions",
                gone.len(),
                present_rows
            ));
            return Ok(report);
        }
        // A "gone" verdict list that does not fit is withheld whole: a partial list of deletions
        // from an incomplete report is not a verdict.
        if report.candidates.len() + gone.len() > options.max_candidates {
            report.complete = false;
            report.gone_withheld = Some(format!(
                "{} paths look gone, more than a pass carries; none of them is sent",
                gone.len()
            ));
            return Ok(report);
        }
        gone.sort_by(|a, b| a.path.cmp(&b.path));
        for row in gone {
            // A second, individual look: only "not found" is a verdict.
            let still_gone = matches!(
                std::fs::symlink_metadata(root.join(&row.path)),
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound
            );
            if still_gone {
                push(&mut report, &row.path, DriftKind::Gone, options.max_candidates);
            }
        }
        Ok(report)
    }
}

fn push(report: &mut DriftReport, rel: &str, kind: DriftKind, max: usize) {
    if report.candidates.len() < max {
        report.candidates.push(DriftCandidate { rel_path: rel.to_owned(), kind });
    } else {
        report.complete = false;
        report.gone_withheld.get_or_insert_with(|| {
            format!("more than {max} paths differ; the rest is left for the next pass")
        });
    }
}

/// Timestamps that differ by less than this are the same: FAT keeps two seconds, HFS+ one, so a
/// file received from a peer with a finer clock never reads back with the indexed time there, and
/// would be a candidate in every pass forever.
const MTIME_TOLERANCE_NANOS: i64 = 2_000_000_000;

/// Whether the file's modification time differs from the indexed one by more than the tolerance
/// (an unreadable time differs).
fn mtime_differs(metadata: &std::fs::Metadata, indexed_nanos: i64) -> bool {
    let Some(on_disk) = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
    else {
        return true;
    };
    (on_disk - indexed_nanos).abs() >= MTIME_TOLERANCE_NANOS
}

/// Sleeps so that `walked` entries took at least `walked / rate` seconds since `started`.
fn throttle(walked: u64, started: Instant, rate: u32) {
    if rate == 0 || !walked.is_multiple_of(512) {
        return;
    }
    let due = Duration::from_secs_f64(walked as f64 / f64::from(rate));
    if let Some(wait) = due.checked_sub(started.elapsed()) {
        std::thread::sleep(wait);
    }
}
