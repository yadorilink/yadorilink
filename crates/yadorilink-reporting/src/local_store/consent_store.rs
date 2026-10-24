//! On-disk persistence for `yadorilink_reporting::ConsentState`. This is
//! also where "local reporting config storage" lives — `ConsentState`
//! already carries `prompt_to_report_enabled` and
//! `endpoint_override`, so one JSON file covers consent *and* the
//! configurable knobs; there's no separate config file.
//!
//! Two invariants this module exists to uphold:
//! - A fresh install must never eagerly write a non-default consent file,
//!   and must never generate an anonymous reporter ID before the user
//!   opts in. `load` returns `ConsentState::default`
//!   without touching disk when no file exists yet; `save` is only ever
//!   called from an explicit mutation method.
//! - The anonymous reporter ID is a fresh random UUID (`new_reporter_id`),
//!   never derived from this device's `device_id` or any coordination-plane
//!   account identifier — this module has no access to either
//!   of those anyway, by construction (`ConsentStore` only ever sees a
//!   directory path).

use std::path::{Path, PathBuf};

use crate::consent::ConsentState;

use super::error::ReportingResult;

/// Generates a fresh anonymous reporter ID. A plain random UUIDv4 has no
/// relationship to any yadorilink account ID or device ID — those are
/// assigned by the coordination plane / `device_config::DeviceConfig`,
/// neither of which this function (or this module) ever reads.
pub fn new_reporter_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub struct ConsentStore {
    path: PathBuf,
}

impl ConsentStore {
    pub fn new(reporting_dir: impl AsRef<Path>) -> Self {
        ConsentStore { path: reporting_dir.as_ref().join("consent.json") }
    }

    /// Loads the persisted consent state, or the safe default if no file
    /// has ever been written (fresh install, or reporting has never been
    /// touched) — this branch deliberately does **not** write anything to
    /// disk, so simply calling `load` can never turn a fresh install into
    /// one with a reporting directory/file on disk.
    pub fn load(&self) -> ReportingResult<ConsentState> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ConsentState::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Best-effort read for call sites that must never fail: falls back to
    /// the safe (reporting-disabled) default and logs a warning rather
    /// than propagating. This is what a non-reporting-specific call site
    /// (e.g. "should I even bother collecting a counter") should use.
    pub fn load_or_default(&self) -> ConsentState {
        match self.load() {
            Ok(state) => state,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %self.path.display(),
                    "reporting: failed to load consent state; treating reporting as disabled"
                );
                ConsentState::default()
            }
        }
    }

    /// Writes `state` to disk, creating the reporting directory (durably) if needed.
    /// Writes to a temp file, flushes it and publishes it over the target by a
    /// durable move, so a crash mid-write can't leave a half-written,
    /// unparseable consent file behind (`load` would otherwise treat that as a
    /// hard error), and a withdrawn consent can't come back after a power loss.
    pub fn save(&self, state: &ConsentState) -> ReportingResult<()> {
        if let Some(parent) = self.path.parent() {
            yadorilink_fs_platform::durable_dir::create_dir_all_durably(parent)?;
        }
        let json = serde_json::to_string_pretty(state)?;
        let tmp_path = self.path.with_extension("json.tmp");
        let flushed = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(json.as_bytes())?;
            yadorilink_fs_platform::flush::sync_file(&file)
        })();
        if let Err(error) = flushed {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(error.into());
        }
        yadorilink_fs_platform::durable_dir::publish_durably(
            &tmp_path,
            &self.path,
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        )?;
        Ok(())
    }

    fn mutate(&self, f: impl FnOnce(&mut ConsentState)) -> ReportingResult<ConsentState> {
        let mut state = self.load()?;
        f(&mut state);
        self.save(&state)?;
        Ok(state)
    }

    pub fn opt_in_usage(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.opt_in_usage(new_reporter_id))
    }

    pub fn opt_in_error_reporting(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.opt_in_error_reporting(new_reporter_id))
    }

    pub fn opt_in_crash_reporting(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.opt_in_crash_reporting(new_reporter_id))
    }

    pub fn disable_all_submission(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.disable_all_submission())
    }

    /// Always mints a brand new ID, severing any
    /// correlation with previously-submitted reports, without touching
    /// the submission-enabled flags.
    pub fn reset_reporter_id(&self) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.reset_reporter_id(new_reporter_id))
    }

    pub fn set_prompt_to_report_enabled(&self, enabled: bool) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.prompt_to_report_enabled = enabled)
    }

    pub fn set_queue_retry_enabled(&self, enabled: bool) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.queue_retry_enabled = enabled)
    }

    pub fn set_endpoint_override(&self, endpoint: Option<String>) -> ReportingResult<ConsentState> {
        self.mutate(|state| state.endpoint_override = endpoint)
    }
}

#[cfg(test)]
mod tests;
