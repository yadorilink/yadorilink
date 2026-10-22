//! This account's device registry: registering this device, listing the
//! account's devices, and removing one.

use base64::Engine;
use serde::{Deserialize, Serialize};
use yadorilink_fapi_client::CoordinationAuth;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    remove_device_command_response, RemoveDeviceCommandRequest, ReplicaMembershipCommandOutcome,
};

use crate::coordination::device_config;
use crate::coordination::http_client::{coordination_addr, get_json, post_json, require_auth};
use crate::daemon::control;
use crate::error::CoreError;

/// The device's Ed25519 key, generated on first use. It is the device's
/// whole identity: its public half is registered so peers can pin it, verify
/// this device's signed change history, and authenticate its connections.
fn signing_keypair_path() -> Result<std::path::PathBuf, CoreError> {
    Ok(device_config::config_dir()?.join("signing_key"))
}

// The coordination plane reads/writes camelCase JSON keys.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDeviceRequest<'a> {
    device_name: &'a str,
    signing_public_key_base64: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDeviceResponse {
    device_id: String,
}

/// One device registered on this account -- `GET /devices`'s own listing,
/// unscoped by folder-group membership. A device with zero linked folders
/// still appears here.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: String,
    pub online: bool,
}
#[derive(Deserialize)]
struct ListDevicesResponse {
    devices: Vec<DeviceInfo>,
}

/// Registers this device and persists the one canonical pre-release
/// `device.json` shape, returning the assigned `device_id`. A daemon that is
/// already running is restarted so it starts as this registered device.
pub async fn register_device(device_name: String) -> Result<String, CoreError> {
    // Before anything is created or the server is asked: a registration whose key and
    // `device.json` could not be kept would orphan the device.
    let signing_key_path = signing_keypair_path()?;
    crate::ops::start_over::ensure_registration_allowed(&device_config::config_dir()?)?;
    let auth = require_auth().await?;
    let signing_keypair =
        yadorilink_transport::DeviceSigningKeyPair::load_or_generate(signing_key_path)
            .map_err(|e| CoreError::Other(e.to_string()))?;

    let signing_public_key_base64 =
        base64::engine::general_purpose::STANDARD.encode(signing_keypair.public_bytes());

    let resp: RegisterDeviceResponse = post_json(
        "/devices/register",
        &RegisterDeviceRequest {
            device_name: &device_name,
            signing_public_key_base64: signing_public_key_base64.clone(),
        },
        &auth,
    )
    .await?;

    device_config::save(&device_config::DeviceConfig {
        device_id: resp.device_id.clone(),
        coordination_addr: coordination_addr(),
        signing_public_key: signing_public_key_base64,
        config_version: device_config::CONFIG_VERSION,
    })?;
    // A running daemon read `device.json` at startup and would keep acting as
    // an unregistered device until restarted.
    //
    // The registration is done by now and stays done: a restart that cannot be
    // confirmed is reported as that, with the one command that brings the daemon
    // back, not as a failed registration.
    if let Err(e) = crate::ops::daemon::restart_if_running().await {
        return Err(CoreError::Other(format!(
            "this device is registered ({}), but the daemon could not be restarted to pick it \
             up: {e}. Run `yadorilink daemon start`.",
            resp.device_id
        )));
    }
    Ok(resp.device_id)
}

/// Every device registered on this account.
pub async fn list_devices() -> Result<Vec<DeviceInfo>, CoreError> {
    let auth = require_auth().await?;
    fetch_devices(&auth, crate::ops::shares::own_device_id().as_deref()).await
}

/// The account's devices as this machine presents them; `own_device_id` is
/// this machine's own device, shown online whatever the coordination plane
/// last observed of it -- see `ops::shares::fetch_members`.
async fn fetch_devices(
    auth: &CoordinationAuth,
    own_device_id: Option<&str>,
) -> Result<Vec<DeviceInfo>, CoreError> {
    let resp: ListDevicesResponse = get_json("/devices", auth).await?;
    let mut devices = resp.devices;
    for device in &mut devices {
        if Some(device.device_id.as_str()) == own_device_id {
            device.online = true;
        }
    }
    Ok(devices)
}

/// De-registers a device from this account, revoking its access to every
/// folder group at once. The daemon first checks that doing so would not
/// leave any folder group without a confirmed-ready full replica, and asks
/// the coordination plane for every group the removed device is an eager full
/// replica of. `force` bypasses a refusal; the returned outcome then carries
/// the data-loss warning a caller must show
/// (`wording::membership_outcome_warnings`).
pub async fn remove_device(
    device_id: &str,
    force: bool,
) -> Result<ReplicaMembershipCommandOutcome, CoreError> {
    let response = control::send(ReqPayload::RemoveDeviceCommand(RemoveDeviceCommandRequest {
        device_id: device_id.to_owned(),
        force,
    }))
    .await?;
    match response.payload {
        Some(RespPayload::RemoveDeviceCommand(response)) => match response.result {
            Some(remove_device_command_response::Result::Outcome(outcome)) => Ok(outcome),
            Some(remove_device_command_response::Result::Error(error)) => {
                Err(CoreError::from_command_error(error))
            }
            None => Err(CoreError::Other("daemon returned an empty remove result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to device removal".into())),
    }
}

#[cfg(test)]
mod tests;
