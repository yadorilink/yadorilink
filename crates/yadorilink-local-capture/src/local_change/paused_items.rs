//! Local capture's half of a paused item (see
//! `yadorilink_sync_sqlite::paused_items` for the whole contract).
//!
//! A local edit to a paused path is not authored. Authoring is what makes a
//! change servable to peers, and a change, once in history, is also the
//! parent of every later change of the group, so it cannot be withheld
//! from one peer exchange after the fact; holding it before authoring is
//! the only place the hold can live. Nothing is recorded instead -- in
//! particular not a dirty-journal row, which would block remote admission
//! of every change to that path for as long as the pause lasts. The edited
//! bytes on disk are the whole backlog, and
//! [`LocalChangeProcessor::capture_resumed_item`] reads them back on
//! resume. An edit captured then is parented on the version its bytes were
//! based on (the path's last placed state), not on whatever remote change
//! was admitted meanwhile, so an edit made on both sides while paused
//! surfaces as an ordinary conflict.

use std::collections::BTreeSet;
use std::path::Path;

use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::FsChangeKind;
use yadorilink_sync_sqlite::paused_items::path_is_covered;

use super::path_policy::path_to_wire_relative_string;
use super::{now_unix_nanos, FlushOutcome, LocalChangeProcessor};
use crate::error::LocalCaptureError;

impl LocalChangeProcessor {
    /// The paused items of `group_id`, read fresh: a pause or resume takes
    /// effect on the very next event.
    ///
    /// Together with the held paths, which local capture must leave
    /// unauthored in exactly the same way -- edits and offline deletions
    /// alike -- for a different reason: whatever is on disk under them
    /// belongs to no row this device placed (see
    /// `yadorilink_sync_sqlite::held_path`). Unlike a pause,
    /// nothing is captured when such a hold is released: the
    /// reconciliation that releases it has already removed what was stale
    /// and moved anything else aside under a name of its own, which local
    /// capture sees as a new file.
    pub(super) fn paused_items(&self, group_id: &str) -> Result<Vec<String>, LocalCaptureError> {
        let mut held = self.state.paused_items(group_id)?;
        held.extend(self.state.held_path_names(group_id)?);
        // A group a rebootstrap freezes is paused as a whole: nothing is authored for it,
        // and the edits stay on disk for the scan that follows the freeze.
        if self.state.group_frozen(group_id)? {
            held.push(String::new());
        }
        Ok(held)
    }

    pub(super) fn is_paused(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<bool, LocalCaptureError> {
        Ok(path_is_covered(&self.paused_items(group_id)?, rel_path))
    }

    /// Whether `rel_path` is under an item the user paused, leaving out
    /// the held paths. A hold is released by a
    /// reconciliation that owns the path's lock while it works, so only a
    /// check made under that lock sees whether it still stands.
    pub(super) fn is_under_user_pause(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<bool, LocalCaptureError> {
        Ok(path_is_covered(&self.state.paused_items(group_id)?, rel_path))
    }

    /// Captures every local change a pause of `item` held, once the pause
    /// is gone: each path the index knows under `item`, plus each file now
    /// on disk under it, goes through the ordinary debounce-flush path,
    /// which re-reads it from disk and authors only what actually differs
    /// (an edit, a new file, or -- for an indexed path no longer on disk --
    /// a deletion). Unchanged paths resolve to nothing.
    pub async fn capture_resumed_item(
        &self,
        group_id: &str,
        root: &Path,
        item: &str,
    ) -> Result<FlushOutcome, LocalCaptureError> {
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let item_set = [item.to_string()];
        let mut paths: BTreeSet<String> = self
            .state
            .list_files(group_id)?
            .into_iter()
            .filter(|record| !record.deleted && path_is_covered(&item_set, &record.path))
            .map(|record| record.path)
            .collect();
        for entry in walkdir::WalkDir::new(canonical_root.join(item))
            .follow_links(false)
            .same_file_system(true)
            .into_iter()
            .filter_entry(|entry| {
                !(entry.file_type().is_dir()
                    && yadorilink_filesystem_sync::device_boundary::is_foreign_device_dir(
                        &canonical_root,
                        entry.path(),
                    ))
            })
            .filter_map(Result::ok)
            .filter(|entry| !entry.file_type().is_dir())
        {
            if let Some(rel) = entry
                .path()
                .strip_prefix(&canonical_root)
                .ok()
                .and_then(path_to_wire_relative_string)
            {
                paths.insert(rel);
            }
        }
        if paths.is_empty() {
            return Ok(FlushOutcome::default());
        }
        // The kind is only a trigger: each path's real kind is re-derived
        // from disk before it is acted on.
        let observed_at = now_unix_nanos();
        let events = paths
            .into_iter()
            .map(|rel| (canonical_root.join(rel), FsChangeKind::CreatedOrModified, observed_at))
            .collect();
        self.process_flush(group_id, root, DebounceFlush::Paths(events)).await
    }
}

#[cfg(test)]
mod tests;
