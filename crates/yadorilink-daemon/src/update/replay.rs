//! Replay (rollback) protection for the signed channel manifest.
//!
//! A manifest signature never expires, so an attacker who can serve bytes could replay an older
//! signed manifest (for example one from before a kill switch). The client therefore persists,
//! per channel, the newest accepted `generated_at` together with the sha256 of the accepted
//! envelope bytes, and refuses:
//!
//! * an envelope whose `generated_at` is older than the stored one, and
//! * an envelope with an equal `generated_at` whose bytes differ from the accepted ones (two
//!   different signed bodies for one instant could otherwise swap an older body in after a newer
//!   one).
//!
//! An equal `generated_at` with identical bytes is the legitimate republish and is accepted.
//! Only server-supplied values are compared, so the local clock never matters. The state sits
//! next to the trust store; deleting it resets the guard and is not a threat this covers (a
//! brand-new install has no stored value, so the first check accepts any validly signed
//! manifest). A damaged state file is moved aside and treated the same way.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    #[error("manifest generated_at '{0}' is not a YYYY-MM-DDTHH:MM:SSZ timestamp")]
    BadGeneratedAt(String),
    #[error("manifest generated at {offered} is older than the accepted one from {accepted}")]
    Older { offered: String, accepted: String },
    #[error("a different manifest was served for the already accepted generated_at {0}")]
    DifferentAtEqual(String),
    #[error("replay state storage failed: {0}")]
    Storage(String),
}

/// What the client accepted last for one channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedGeneration {
    pub generated_at: String,
    pub envelope_sha256: String,
    /// The channel's feed had no manifest (404) after this generation was accepted. The floor
    /// itself stays; a cached copy of the envelope must not be used while this is set.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_manifest: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayFile {
    #[serde(default)]
    channels: BTreeMap<String, AcceptedGeneration>,
}

pub struct ReplayStore {
    path: PathBuf,
    /// Held across load, compare and save so two concurrent checks cannot both pass against the
    /// same old value and then overwrite each other with the older one.
    lock: std::sync::Mutex<()>,
}

/// Strict `YYYY-MM-DDTHH:MM:SSZ` (the only form the publisher emits), parsed so that two
/// accepted values compare as instants.
fn parse_generated_at(raw: &str) -> Result<chrono::NaiveDateTime, ReplayError> {
    let bad = || ReplayError::BadGeneratedAt(raw.chars().take(40).collect());
    if raw.len() != 20 {
        return Err(bad());
    }
    chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%SZ").map_err(|_| bad())
}

pub fn envelope_sha256(envelope_bytes: &str) -> String {
    hex::encode(Sha256::digest(envelope_bytes.as_bytes()))
}

impl ReplayStore {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        ReplayStore {
            path: config_dir.as_ref().join("update_replay_floor.json"),
            lock: std::sync::Mutex::new(()),
        }
    }

    fn load(&self) -> Result<ReplayFile, ReplayError> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|e| ReplayError::Storage(format!("persisted state is unreadable: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ReplayFile::default()),
            Err(e) => Err(ReplayError::Storage(e.to_string())),
        }
    }

    /// Like `load`, but a file that is present and damaged is moved aside (kept for inspection,
    /// replacing an earlier one) and the check proceeds as a first run. Refusing forever would
    /// stop update checks on an installed app with no way back; expiry still bounds what a
    /// replayed manifest can do. A file that cannot be moved aside is still an error.
    fn load_or_quarantine(&self) -> Result<ReplayFile, ReplayError> {
        let damaged = match self.load() {
            Ok(file)
                if file.channels.values().all(|g| parse_generated_at(&g.generated_at).is_ok()) =>
            {
                return Ok(file);
            }
            Ok(_) => true,
            Err(ReplayError::Storage(_)) => self.path.exists(),
            Err(e) => return Err(e),
        };
        if damaged {
            let aside = self.path.with_file_name("update_replay_floor.json.damaged");
            yadorilink_fs_platform::durable_dir::publish_durably(
                &self.path,
                &aside,
                yadorilink_fs_platform::durable_dir::Replace::Yes,
            )
            .map_err(|e| {
                ReplayError::Storage(format!("damaged state could not be moved aside: {e}"))
            })?;
        }
        Ok(ReplayFile::default())
    }

    fn save(&self, file: &ReplayFile) -> std::io::Result<()> {
        use std::io::Write;

        use yadorilink_fs_platform::durable_dir::{
            create_dir_all_durably, publish_durably, Replace,
        };

        if let Some(parent) = self.path.parent() {
            create_dir_all_durably(parent)?;
        }
        let json = serde_json::to_string_pretty(file).map_err(std::io::Error::other)?;
        let tmp = self.path.with_file_name(".update_replay_floor.json.tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        yadorilink_fs_platform::flush::sync_file(&f)?;
        drop(f);
        publish_durably(&tmp, &self.path, Replace::Yes)
    }

    /// What was last accepted for `channel`, for `update status`. A store that cannot be read
    /// reports nothing here; `accept` is the call that fails closed.
    pub fn accepted(&self, channel: &str) -> Option<AcceptedGeneration> {
        let _serialized = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.load().ok()?.channels.get(channel).cloned()
    }

    /// Records durably that `channel`'s feed has no manifest now, so a cached envelope for the
    /// accepted generation is never used again (until that generation is accepted anew). The
    /// floor itself is kept. A channel with no accepted generation has nothing to mark.
    pub fn mark_no_manifest(&self, channel: &str) -> Result<(), ReplayError> {
        let _serialized = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.load_or_quarantine()?;
        match file.channels.get_mut(channel) {
            Some(kept) if !kept.no_manifest => kept.no_manifest = true,
            _ => return Ok(()),
        }
        self.save(&file).map_err(|e| ReplayError::Storage(e.to_string()))
    }

    /// Decides whether an already signature-verified manifest may be acted on, and records it.
    /// The new value is durably stored before `Ok` is returned: a manifest is never acted on
    /// under a floor that a restart could forget.
    pub fn accept(
        &self,
        channel: &str,
        generated_at: &str,
        envelope_bytes: &str,
    ) -> Result<(), ReplayError> {
        let offered_at = parse_generated_at(generated_at)?;
        let offered_hash = envelope_sha256(envelope_bytes);
        let _serialized = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.load_or_quarantine()?;
        if let Some(kept) = file.channels.get(channel) {
            let kept_at = parse_generated_at(&kept.generated_at)
                .map_err(|_| ReplayError::Storage("persisted generated_at is invalid".into()))?;
            if offered_at < kept_at {
                return Err(ReplayError::Older {
                    offered: generated_at.to_string(),
                    accepted: kept.generated_at.clone(),
                });
            }
            if offered_at == kept_at {
                if kept.envelope_sha256 != offered_hash {
                    return Err(ReplayError::DifferentAtEqual(generated_at.to_string()));
                }
                if !kept.no_manifest {
                    return Ok(());
                }
                // The same signed bytes served again after a 404: usable once more, falling
                // through to store the cleared marker.
            }
        }
        file.channels.insert(
            channel.to_string(),
            AcceptedGeneration {
                generated_at: generated_at.to_string(),
                envelope_sha256: offered_hash,
                no_manifest: false,
            },
        );
        self.save(&file).map_err(|e| ReplayError::Storage(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
