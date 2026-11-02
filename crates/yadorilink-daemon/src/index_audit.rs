//! Finds stored file records whose block list cannot be read back, without a status having to
//! scan every row.
//!
//! A row written by this daemon is checked before it is committed (`check_block_list`), so what
//! this finds is damage done to a row afterwards: bit rot, an editor, a partial restore. It walks
//! the live rows in bounded steps while the status builder runs, remembers which `(group, path)`
//! failed, and checks those rows again on every pass until they read back, so a folder is marked
//! damaged for exactly as long as a row of it is. A pass that merely does not meet a bad row
//! removes nothing: a row behind the cursor can be damaged while the pass is under way.
//!
//! Damage a row suffers is reported within [`STEP_GAP`] times the number of steps the table needs
//! (ten minutes for a table of 100,000 rows), instead of on the next status call as before. The
//! first pass after the daemon starts runs to the end of the table at once.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use yadorilink_sync_sqlite::file_index::{DamagedRow, FileIndexRepository};

use crate::queries::link_status::LinkFacts;

/// Rows read per step.
const ROWS_PER_STEP: usize = 5_000;
/// The least time between two steps after the first pass.
const STEP_GAP: Duration = Duration::from_secs(30);

#[derive(Default)]
struct State {
    /// Where the next step resumes (a rowid).
    cursor: i64,
    last_step: Option<Instant>,
    /// Group -> its live rows that failed, by rowid (a row is found again by its rowid, not by a
    /// name a damaged value might not give back faithfully), with the path for display.
    damaged: BTreeMap<String, BTreeMap<i64, String>>,
}

pub(crate) struct IndexAudit {
    state: Mutex<State>,
    step_gap: Duration,
}

impl Default for IndexAudit {
    fn default() -> Self {
        Self { state: Mutex::new(State::default()), step_gap: STEP_GAP }
    }
}

impl IndexAudit {
    /// Brings the audit up to date and marks the damaged folders in `links`. Reads only; a read
    /// that fails changes nothing, so a recorded path stays recorded.
    pub(crate) fn refresh(&self, files: &FileIndexRepository, links: &mut [LinkFacts]) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.advance(&mut state, files);
        for link in links {
            link.index_damaged_path =
                state.damaged.get(link.group_id()).and_then(|rows| rows.values().next()).cloned();
        }
    }

    fn advance(&self, state: &mut State, files: &FileIndexRepository) {
        recheck_recorded(state, files);
        let first_pass = state.last_step.is_none();
        if first_pass || state.last_step.is_some_and(|at| at.elapsed() >= self.step_gap) {
            let started = Instant::now();
            // The first pass runs to the end of the table; one that fails midway is resumed from
            // where it stopped by the next build, so the table is read through once at start
            // however it goes.
            let mut completed = !first_pass;
            while let Some(table_done) = step(state, files) {
                if !first_pass {
                    break;
                }
                if table_done {
                    completed = true;
                    break;
                }
            }
            if completed {
                state.last_step = Some(started);
            }
        }
    }
}

/// Drops the recorded paths whose row reads back now or is no longer live.
fn recheck_recorded(state: &mut State, files: &FileIndexRepository) {
    for (group, rows) in &mut state.damaged {
        rows.retain(|rowid, path| {
            let row = DamagedRow { rowid: *rowid, group_id: group.clone(), path: path.clone() };
            files.live_block_list_damaged(&row).unwrap_or(true)
        });
    }
    state.damaged.retain(|_, rows| !rows.is_empty());
}

/// One step. `None`: the read failed (nothing changed). `Some(true)`: the end of the table was
/// reached and the cursor is back at the start. `Some(false)`: more rows follow.
fn step(state: &mut State, files: &FileIndexRepository) -> Option<bool> {
    let audit = match files.audit_live_block_lists(state.cursor, ROWS_PER_STEP) {
        Ok(audit) => audit,
        Err(error) => {
            tracing::warn!(%error, "the audit of stored block lists could not read a step");
            return None;
        }
    };
    for row in audit.damaged {
        state.damaged.entry(row.group_id).or_default().insert(row.rowid, row.path);
    }
    match audit.next_rowid {
        Some(next) => {
            state.cursor = next;
            Some(false)
        }
        None => {
            state.cursor = 0;
            Some(true)
        }
    }
}

#[cfg(test)]
mod tests;
