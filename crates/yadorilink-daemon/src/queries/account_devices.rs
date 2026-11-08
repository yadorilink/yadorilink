//! The account's device list, for front ends that name devices.

use std::sync::Arc;

use crate::queries::recovery::CoordinationConfigPort;

#[derive(Debug, Clone)]
pub(crate) struct AccountDeviceView {
    pub(crate) device_id: String,
    pub(crate) device_name: String,
    pub(crate) online: bool,
    pub(crate) is_this_device: bool,
}

pub(crate) struct AccountDevicesQueryService {
    config: Arc<dyn CoordinationConfigPort>,
    own_device_id: String,
}

impl AccountDevicesQueryService {
    pub(crate) fn new(config: Arc<dyn CoordinationConfigPort>, own_device_id: String) -> Self {
        Self { config, own_device_id }
    }

    pub(crate) async fn list(&self) -> Result<Vec<AccountDeviceView>, String> {
        let Some((addr, auth)) = self.config.coordination_client_config() else {
            return Err(
                "coordination-plane address/access token not configured on this device".to_string()
            );
        };
        let devices = crate::coordination_client::list_account_device_names(&addr, &auth).await?;
        Ok(devices
            .into_iter()
            .map(|(device_id, device_name, online)| {
                let is_this_device = device_id == self.own_device_id;
                AccountDeviceView {
                    device_id,
                    device_name,
                    online: online || is_this_device,
                    is_this_device,
                }
            })
            .collect())
    }

    /// Who is a member of which of this account's folder groups, and in what state.
    pub(crate) async fn list_share_edges(
        &self,
    ) -> Result<Vec<crate::coordination_client::EdgeInfo>, String> {
        let Some((addr, auth)) = self.config.coordination_client_config() else {
            return Err(
                "coordination-plane address/access token not configured on this device".to_string()
            );
        };
        crate::coordination_client::list_share_edges(&addr, &auth).await
    }
}
