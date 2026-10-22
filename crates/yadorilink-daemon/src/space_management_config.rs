//! The automatic space management setting: Off or On. A small JSON file beside the other daemon settings, read at the start of
//! every pass so a change applies without a restart. A missing or unreadable file means Off.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpaceManagementConfig {
    pub enabled: bool,
}

pub struct SpaceManagementStore {
    path: PathBuf,
}

impl SpaceManagementStore {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        Self { path: config_dir.as_ref().join("space_management.json") }
    }

    /// The stored setting, or Off when none was ever written.
    pub fn load(&self) -> std::io::Result<SpaceManagementConfig> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(SpaceManagementConfig::default())
            }
            Err(e) => Err(e),
        }
    }

    /// For callers that must not fail: a setting that cannot be read is Off.
    pub fn load_or_off(&self) -> SpaceManagementConfig {
        self.load().unwrap_or_else(|error| {
            tracing::warn!(%error, path = %self.path.display(), "space management setting unreadable; treating it as Off");
            SpaceManagementConfig::default()
        })
    }

    /// Persists the setting (temp file, then rename) and returns what was stored.
    pub fn set(&self, enabled: bool) -> std::io::Result<SpaceManagementConfig> {
        let config = SpaceManagementConfig { enabled };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&config)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_install_is_off() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!SpaceManagementStore::new(dir.path()).load_or_off().enabled);
    }

    #[test]
    fn the_setting_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        SpaceManagementStore::new(dir.path()).set(true).unwrap();
        assert!(SpaceManagementStore::new(dir.path()).load_or_off().enabled);
        SpaceManagementStore::new(dir.path()).set(false).unwrap();
        assert!(!SpaceManagementStore::new(dir.path()).load_or_off().enabled);
    }

    #[test]
    fn an_unreadable_file_reads_as_off() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("space_management.json"), "{ not json").unwrap();
        assert!(!SpaceManagementStore::new(dir.path()).load_or_off().enabled);
    }
}
