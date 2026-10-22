//! `UpdateStatus`'s read model, also embedded in `Status`'s own response
//! (`daemon_control.proto`'s doc comment on why they're two separate flat
//! messages rather than one nested inside the other). Depends only on
//! `UpdateManager`, already an owner-shaped `Arc` on `DaemonState` -- no
//! strangler adapter needed.

use std::sync::Arc;

use crate::update::manager::UpdateManager;

#[derive(Debug, Clone)]
pub(crate) struct UpdateStatusView {
    pub(crate) current_version: String,
    pub(crate) channel: String,
    pub(crate) install_source: String,
    pub(crate) last_check_unix: i64,
    pub(crate) state: String,
    pub(crate) available_version: String,
    pub(crate) release_notes_url: String,
    pub(crate) mandatory: bool,
    /// The running version is below the signed minimum supported version.
    pub(crate) update_required: bool,
    pub(crate) holdback_reason: String,
    pub(crate) last_error_category: String,
    pub(crate) last_error_message: String,
    pub(crate) automatic_checks_enabled: bool,
    /// `generated_at` of the newest manifest accepted for this channel; empty before the first.
    pub(crate) manifest_generated_at: String,
}

pub(crate) struct UpdateStatusQueryService {
    manager: Arc<UpdateManager>,
}

impl UpdateStatusQueryService {
    pub(crate) fn new(manager: Arc<UpdateManager>) -> Self {
        Self { manager }
    }

    pub(crate) fn snapshot(&self) -> UpdateStatusView {
        let policy = self.manager.policy.load_or_default();
        UpdateStatusView {
            current_version: self.manager.current_version().to_string(),
            channel: policy.channel.clone(),
            install_source: self.manager.platform_info().install_source.clone(),
            last_check_unix: policy.last_check_unix.unwrap_or(0),
            state: policy.state.as_str().to_string(),
            available_version: policy.available_version.clone().unwrap_or_default(),
            release_notes_url: policy.available_release_notes_url.clone().unwrap_or_default(),
            mandatory: policy.mandatory,
            update_required: policy.update_required(self.manager.current_version()),
            holdback_reason: policy.holdback_reason.clone().unwrap_or_default(),
            last_error_category: policy.last_error_category.clone().unwrap_or_default(),
            last_error_message: policy.last_error_message.clone().unwrap_or_default(),
            automatic_checks_enabled: policy.automatic_checks_enabled,
            manifest_generated_at: self
                .manager
                .accepted_generation()
                .map(|g| g.generated_at)
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_with_minimum(running: &str, minimum: Option<&str>) -> UpdateStatusView {
        let dir = tempfile::tempdir().unwrap();
        let manager =
            Arc::new(UpdateManager::new(dir.path(), semver::Version::parse(running).unwrap()));
        manager
            .policy
            .update(|p| p.minimum_supported_version = minimum.map(str::to_owned))
            .unwrap();
        UpdateStatusQueryService::new(manager).snapshot()
    }

    /// The status the apps and `yadorilink status` read carries "update required" exactly when
    /// the running version is below the signed minimum.
    #[test]
    fn the_status_says_update_required_only_below_the_minimum() {
        assert!(snapshot_with_minimum("0.2.0", Some("0.3.0")).update_required);
        assert!(!snapshot_with_minimum("0.3.0", Some("0.3.0")).update_required);
        assert!(!snapshot_with_minimum("0.2.0", None).update_required);
    }
}
