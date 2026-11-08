//! A folder's ignore rules, read and replaced through the control API.
//!
//! The rules are one text per folder group, owned by the daemon (see
//! [`IgnoreRulesStore`]). Hosts never touch the file: `set` validates the text with the same
//! parser the engine reads it with, replaces the stored text durably, and has the engine apply
//! it, so paths that became ignored or stopped being ignored are picked up at once.

use std::sync::Arc;

use yadorilink_fs_platform::ignore_patterns::{IgnoreConfigError, IgnoreRulesStore};

use crate::daemon_state::DaemonState;

/// Why `get` or `set` refused.
#[derive(Debug, PartialEq, Eq)]
pub enum IgnoreRulesError {
    /// No folder of this device belongs to the group.
    UnknownGroup(String),
    /// The text has an unusable line: nothing was stored.
    Invalid(IgnoreConfigError),
    /// The rules could not be read or stored.
    Failed(String),
}

impl std::fmt::Display for IgnoreRulesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownGroup(group) => write!(f, "no folder of this device is linked to {group}"),
            Self::Invalid(error) => write!(f, "{error}"),
            Self::Failed(message) => write!(f, "{message}"),
        }
    }
}

pub struct IgnoreRulesService {
    state: Arc<DaemonState>,
}

impl IgnoreRulesService {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    fn require_group(&self, group_id: &str) -> Result<(), IgnoreRulesError> {
        let links = self
            .state
            .replica_coordinator
            .link_repository()
            .list_links()
            .map_err(|error| IgnoreRulesError::Failed(error.to_string()))?;
        if links.iter().any(|link| !link.orphaned && link.group_id == group_id) {
            Ok(())
        } else {
            Err(IgnoreRulesError::UnknownGroup(group_id.to_string()))
        }
    }

    /// The group's rules text; empty when it has none.
    pub fn get(&self, group_id: &str) -> Result<String, IgnoreRulesError> {
        self.require_group(group_id)?;
        IgnoreRulesStore::new(self.state.config_dir())
            .read(group_id)
            .map_err(|error| IgnoreRulesError::Failed(error.to_string()))
    }

    /// Replaces the group's rules with `text` and applies them.
    pub async fn set(&self, group_id: &str, text: &str) -> Result<(), IgnoreRulesError> {
        self.require_group(group_id)?;
        IgnoreRulesStore::new(self.state.config_dir()).write(group_id, text).map_err(|error| {
            match error {
                invalid @ IgnoreConfigError::InvalidLine { .. } => {
                    IgnoreRulesError::Invalid(invalid)
                }
                other => IgnoreRulesError::Failed(other.to_string()),
            }
        })?;
        self.apply(group_id).await
    }

    /// Has the engine act on the stored rules: paths parked because they were ignored are
    /// re-armed when they no longer are, and the folder is scanned once so newly ignored paths
    /// leave the index and newly allowed ones enter it. The rules are stored either way; when
    /// the scan cannot run now (a path is paused, the link is stopping) the error says so and
    /// the host sets the rules again once it can.
    async fn apply(&self, group_id: &str) -> Result<(), IgnoreRulesError> {
        crate::convergence::engine::run_ignore_recheck_pass(&self.state, group_id).await;
        match self.state.link_runtime_for(group_id) {
            Some(runtime) => runtime.capture_whole_group(group_id).await.map_err(|error| {
                IgnoreRulesError::Failed(format!(
                    "the rules are saved, but applying them to the folder did not run: {error}"
                ))
            }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests;
