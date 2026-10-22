//! Folder Rewind: preview, start and follow. The wording of every refusal
//! and run comes from the daemon.

use std::time::{SystemTime, UNIX_EPOCH};

use super::{about, ClientCore};
use crate::dto::{self, RewindPreview, RewindRun, RewindStartOutcome};
use crate::error::DesktopError;
use crate::ops;

impl ClientCore {
    /// What rewinding the folder `group_id` to `at` would change. Changes
    /// nothing.
    ///
    /// # Errors
    /// `InvalidInput` for a time before 1970; daemon failures.
    pub async fn rewind_preview(
        &self,
        group_id: String,
        at: SystemTime,
    ) -> Result<RewindPreview, DesktopError> {
        let nanos = at
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|since| i64::try_from(since.as_nanos()).ok())
            .ok_or_else(|| DesktopError::invalid_input("that time is out of range", "at"))?;
        let plan = ops::rewind::preview(group_id, nanos, false).await.map_err(about("group_id"))?;
        Ok(dto::rewind_preview(&plan))
    }

    /// Starts the rewind a preview showed, named by the preview's
    /// `target_unix_nanos` and `plan_id`. A folder that changed since is
    /// refused rather than re-planned.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn rewind_execute(
        &self,
        group_id: String,
        target_unix_nanos: i64,
        plan_id: Vec<u8>,
    ) -> Result<RewindStartOutcome, DesktopError> {
        let start = ops::rewind::execute(group_id, target_unix_nanos, plan_id)
            .await
            .map_err(about("group_id"))?;
        Ok(dto::rewind_start(start))
    }

    /// The folder's most recent rewind run, `None` when it never had one.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn rewind_latest(&self, group_id: String) -> Result<Option<RewindRun>, DesktopError> {
        let run = ops::rewind::status(group_id).await.map_err(about("group_id"))?;
        Ok(run.as_ref().map(dto::rewind_run))
    }

    /// How the run `run_id` (the one a start answered with) stands. When the
    /// folder's latest run is a different one, or there is none, the run can
    /// no longer be followed and this answers a stopped run worded
    /// `RUN_MISSING_MESSAGE`.
    ///
    /// # Errors
    /// Daemon failures.
    pub async fn rewind_follow(
        &self,
        group_id: String,
        run_id: String,
    ) -> Result<RewindRun, DesktopError> {
        let run = ops::rewind::status(group_id).await.map_err(about("group_id"))?;
        Ok(match run.filter(|run| run.run_id == run_id) {
            Some(run) => dto::rewind_run(&run),
            None => dto::rewind_run_missing(run_id),
        })
    }
}
