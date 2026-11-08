//! Whether this device may use the network for peer traffic right now.
//!
//! Two inputs decide it. The user's setting, [`NetworkPolicy::sync_on_metered`], is stored beside
//! the other daemon settings and is off by default: a metered connection (cellular, a capped
//! plan) pauses syncing with peers. The host's report, [`NetworkCost`], says what the connection
//! is; the engine never guesses it, and what the host has not said is treated as unmetered.
//!
//! While paused the engine neither dials peers nor serves them. Nothing local stops: folders are
//! still watched and recorded, and sync catches up when the policy allows traffic again.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// What the host says about the connection the device is on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NetworkCost {
    /// Not reported yet, or the host cannot tell.
    #[default]
    Unknown,
    Unmetered,
    Metered,
}

/// The setting and the latest host report, as one value so a change of either wakes watchers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyState {
    pub sync_on_metered: bool,
    pub cost: NetworkCost,
    /// The host has reported a cost since the engine started (whatever it reported).
    pub cost_known: bool,
}

impl PolicyState {
    /// Whether peer traffic may flow.
    #[must_use]
    pub fn peer_traffic_allowed(self) -> bool {
        self.cost != NetworkCost::Metered || self.sync_on_metered
    }

    /// Peer traffic is held back because the connection is metered.
    #[must_use]
    pub fn paused_on_metered(self) -> bool {
        !self.peer_traffic_allowed()
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Stored {
    sync_on_metered: bool,
}

pub struct NetworkPolicy {
    path: PathBuf,
    state: watch::Sender<PolicyState>,
}

impl NetworkPolicy {
    /// The policy stored in `config_dir`; an unreadable file reads as the default (pause on
    /// metered), the safe side for a metered connection.
    pub fn open(config_dir: impl AsRef<Path>) -> Self {
        let path = config_dir.as_ref().join("network_policy.json");
        let stored = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|error| {
                tracing::warn!(%error, path = %path.display(), "network policy unreadable; using the default");
                Stored::default()
            }),
            Err(_) => Stored::default(),
        };
        let state = PolicyState {
            sync_on_metered: stored.sync_on_metered,
            cost: NetworkCost::Unknown,
            cost_known: false,
        };
        Self { path, state: watch::channel(state).0 }
    }

    #[must_use]
    pub fn current(&self) -> PolicyState {
        *self.state.borrow()
    }

    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<PolicyState> {
        self.state.subscribe()
    }

    /// Stores the setting (temp file, then rename) and applies it.
    ///
    /// # Errors
    /// The setting could not be saved; it is then not applied.
    pub fn set_sync_on_metered(&self, enabled: bool) -> std::io::Result<PolicyState> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&Stored { sync_on_metered: enabled })?)?;
        std::fs::rename(&tmp, &self.path)?;
        self.state.send_modify(|state| state.sync_on_metered = enabled);
        Ok(self.current())
    }

    /// Records what the host reports about the connection.
    pub fn report_cost(&self, cost: NetworkCost) -> PolicyState {
        self.state.send_if_modified(|state| {
            let changed = state.cost != cost || !state.cost_known;
            state.cost = cost;
            state.cost_known = true;
            changed
        });
        self.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metered_pauses_by_default_and_the_setting_lifts_it() {
        let dir = tempfile::tempdir().unwrap();
        let policy = NetworkPolicy::open(dir.path());
        assert!(policy.current().peer_traffic_allowed(), "nothing reported: not metered");
        assert!(policy.report_cost(NetworkCost::Metered).paused_on_metered());
        assert!(policy.set_sync_on_metered(true).unwrap().peer_traffic_allowed());
        assert!(!policy.set_sync_on_metered(false).unwrap().peer_traffic_allowed());
        assert!(policy.report_cost(NetworkCost::Unmetered).peer_traffic_allowed());
        assert!(policy.report_cost(NetworkCost::Unknown).peer_traffic_allowed());
    }

    #[test]
    fn the_setting_survives_a_reopen_the_host_report_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let policy = NetworkPolicy::open(dir.path());
        policy.set_sync_on_metered(true).unwrap();
        policy.report_cost(NetworkCost::Metered);
        let reopened = NetworkPolicy::open(dir.path()).current();
        assert!(reopened.sync_on_metered);
        assert_eq!(reopened.cost, NetworkCost::Unknown);
    }

    #[test]
    fn the_cost_is_known_only_after_a_report_and_a_restart_forgets_it() {
        let dir = tempfile::tempdir().unwrap();
        let policy = NetworkPolicy::open(dir.path());
        assert!(!policy.current().cost_known, "a fresh engine has no report");
        // Any report counts, including "the host cannot tell".
        assert!(policy.report_cost(NetworkCost::Unknown).cost_known);
        assert!(!NetworkPolicy::open(dir.path()).current().cost_known, "a restart resets it");
    }

    #[test]
    fn an_unreadable_file_reads_as_the_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("network_policy.json"), "{ not json").unwrap();
        assert!(!NetworkPolicy::open(dir.path()).current().sync_on_metered);
    }

    #[test]
    fn a_report_that_changes_nothing_wakes_nobody() {
        let dir = tempfile::tempdir().unwrap();
        let policy = NetworkPolicy::open(dir.path());
        policy.report_cost(NetworkCost::Metered);
        let mut watcher = policy.subscribe();
        watcher.mark_unchanged();
        policy.report_cost(NetworkCost::Metered);
        assert!(!watcher.has_changed().unwrap());
    }
}
