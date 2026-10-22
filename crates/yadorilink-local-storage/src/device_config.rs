//! The on-disk `device.json` shape, shared by the daemon and client-core so the
//! two cannot diverge. Only the current shape is accepted: unknown fields and
//! missing fields fail deserialization; version policy lives with each loader.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfig {
    pub device_id: String,
    pub coordination_addr: String,
    /// Base64-encoded public half of this device's registered Ed25519
    /// change-signing key -- this device's one key, and the one that
    /// authenticates its transport. Required.
    pub signing_public_key: String,
    /// Current config shape marker. Missing markers are rejected by serde.
    pub config_version: u32,
}

/// Current pre-release `device.json` shape. Older development files are not
/// migrated.
pub const CONFIG_VERSION: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    const OLD_FILE: &str = r#"{"device_id":"d","coordination_addr":"http://c","signing_public_key":"k","config_version":3}"#;

    #[test]
    fn existing_files_still_parse() {
        let cfg: DeviceConfig = serde_json::from_str(OLD_FILE).unwrap();
        assert_eq!((cfg.device_id.as_str(), cfg.config_version), ("d", CONFIG_VERSION));
        let round: DeviceConfig =
            serde_json::from_str(&serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(round.signing_public_key, "k");
    }

    #[test]
    fn unknown_and_missing_fields_are_rejected() {
        let extra = OLD_FILE.replace("\"config_version\":3", "\"config_version\":3,\"x\":1");
        assert!(serde_json::from_str::<DeviceConfig>(&extra).is_err());
        let missing = OLD_FILE.replace(",\"config_version\":3", "");
        assert!(serde_json::from_str::<DeviceConfig>(&missing).is_err());
    }
}
