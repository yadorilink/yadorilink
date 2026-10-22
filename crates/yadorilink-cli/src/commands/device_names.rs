//! Device ids as people know them, for the commands that print devices.

/// Device ids as people know them: this device, a device on the account by its
/// name, anything else as "another device". Never a raw id. Names come from the
/// account's device list when it can be read; nothing here fails a command.
#[derive(Debug, Default)]
pub(crate) struct DeviceNames {
    pub(crate) own_device_id: Option<String>,
    pub(crate) names: std::collections::HashMap<String, String>,
}

impl DeviceNames {
    pub(crate) async fn load() -> Self {
        // Names are a nicety on top of local results: an offline or slow
        // coordination service costs at most this long, then ids read as
        // "another device".
        const NAME_LOOKUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
        let names = tokio::time::timeout(
            NAME_LOOKUP_BUDGET,
            yadorilink_client_core::ops::devices::list_devices(),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .map(|devices| devices.into_iter().map(|d| (d.device_id, d.device_name)).collect())
        .unwrap_or_default();
        Self { own_device_id: yadorilink_client_core::ops::shares::own_device_id(), names }
    }

    pub(crate) fn label(&self, device_id: &str) -> String {
        if device_id.is_empty() {
            return "an unknown device".to_string();
        }
        if self.own_device_id.as_deref() == Some(device_id) {
            return "this device".to_string();
        }
        match self.names.get(device_id) {
            Some(name) if !name.trim().is_empty() => name.clone(),
            _ => "another device".to_string(),
        }
    }

    /// Whether `device_id` is this device.
    pub(crate) fn is_own(&self, device_id: &str) -> bool {
        self.own_device_id.as_deref() == Some(device_id)
    }

    /// The name the account gives `device_id`, when the device list could be read and has one.
    pub(crate) fn name_of(&self, device_id: &str) -> Option<&str> {
        self.names.get(device_id).map(String::as_str).filter(|name| !name.trim().is_empty())
    }
}
