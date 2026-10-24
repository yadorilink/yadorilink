//! `yadorilink device ...`: this account's device registry.

use yadorilink_client_core::ops::devices as ops;

use crate::error::CliError;

use yadorilink_client_core::ops::devices::DeviceInfo;

/// `yadorilink device register [--name <name>]`.
pub async fn register(device_name: String) -> Result<(), CliError> {
    let device_id =
        ops::register_device(device_name, &yadorilink_client_core::ops::daemon::default_launch())
            .await?;
    println!("Registered device: {device_id}");
    Ok(())
}

fn device_line(device: &DeviceInfo) -> String {
    format!(
        "{}  {}  {}",
        device.device_id,
        device.device_name,
        if device.online { "online" } else { "offline" }
    )
}

/// `yadorilink device list`.
pub async fn list() -> Result<(), CliError> {
    for device in ops::list_devices().await? {
        println!("{}", device_line(&device));
    }
    Ok(())
}

/// `yadorilink device remove <device> [--force]`. Before de-registering the
/// device on the coordination plane, the daemon checks that doing so would
/// not leave any folder group without a confirmed-ready full replica.
/// `--force` bypasses a refusal with a data-loss warning and an audit log
/// line.
pub async fn remove(device_id: String, force: bool, yes: bool) -> Result<(), CliError> {
    super::confirm_destructive(
        &format!(
            "Remove device {device_id} and revoke its access to every folder group? Files \
             already on that device stay on its disk."
        ),
        yes,
    )?;
    let outcome = ops::remove_device(&device_id, force).await?;
    crate::commands::membership_render::render_membership_outcome("remove", &outcome);
    println!("Removed device: {device_id}");
    Ok(())
}

/// `yadorilink device start-over [--name <name>] [--yes]`: see
/// `yadorilink_client_core::ops::start_over`.
pub async fn start_over(name: String, yes: bool) -> Result<(), CliError> {
    use yadorilink_client_core::ops::start_over::{start_over, StartOverProgress};
    if !yadorilink_client_core::ops::start_over::pending() {
        super::confirm_destructive(
            "Start over as a new device? This computer is signed out and gets a new device \
             identity; its old device stays on your account, signed out. Files on this computer \
             and its synced history are kept, and the folders you linked are joined again.",
            yes,
        )?;
    }
    let ports = yadorilink_client_core::ops::start_over::MachinePorts {
        launch: yadorilink_client_core::ops::daemon::default_launch(),
    };
    match start_over(&ports, true, name).await? {
        StartOverProgress::SignInRequired { retired_device_id } => {
            println!(
                "The old device identity {retired_device_id} is retired and this computer is \
                 signed out. Run `yadorilink login`, then `yadorilink device start-over` again \
                 to register it as a new device."
            );
        }
        StartOverProgress::Finished(report) => {
            println!(
                "Registered new device {} (replacing {}).",
                report.new_device_id, report.retired_device_id
            );
            for path in &report.rejoined {
                println!("Joined again: {path}");
            }
            for failed in &report.not_rejoined {
                println!("Not joined: {} ({})", failed.local_path, failed.message);
            }
            if !report.complete {
                return Err(CliError::Other(
                    "some folders could not be joined again; run `yadorilink device start-over` \
                     again to retry"
                        .to_owned(),
                ));
            }
            println!(
                "The old device {} is still listed on your account as signed out. Remove it with \
                 `yadorilink device remove {} --force` once the new device has your folders.",
                report.retired_device_id, report.retired_device_id
            );
        }
    }
    Ok(())
}

/// `yadorilink device acknowledge-replacement [--yes]`: see
/// `yadorilink_client_core::ops::start_over::acknowledge_possible_loss`.
pub fn acknowledge_replacement(yes: bool) -> Result<(), CliError> {
    use yadorilink_client_core::ops::start_over::acknowledge_possible_loss;
    super::confirm_destructive(
        "This computer was restored from a backup and cannot check whether changes made after \
         that backup are missing. Confirm the replacement anyway? Anything changed after the \
         backup may be gone for good if no other device holds it.",
        yes,
    )?;
    if acknowledge_possible_loss()? {
        println!(
            "Acknowledged. The replacement is confirmed once every folder is complete on this \
             computer."
        );
    } else {
        println!("No replacement is waiting for confirmation.");
    }
    Ok(())
}

/// `yadorilink device manage <device>`: opens the device's management page
/// through the same operation the app uses, prints its address, and keeps
/// the session open until Ctrl-C or until the daemon ends it.
pub async fn manage(device_id: String) -> Result<(), CliError> {
    use yadorilink_client_core::ops::nas_admin::{open_nas_admin, NasAdminOpen};
    use yadorilink_client_core::wording::nas_admin_failure_message;
    match open_nas_admin(device_id).await? {
        NasAdminOpen::Failed(failure) => {
            Err(CliError::Other(nas_admin_failure_message(failure).to_string()))
        }
        NasAdminOpen::Opened(session) => {
            println!("{}", session.local_url());
            eprintln!("Open the address above in a browser. Press Ctrl-C to close it.");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => session.close(),
                () = session.ended() => eprintln!("The management session ended."),
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_line_is_pinned_verbatim() {
        let mut device = DeviceInfo {
            device_id: "device-1".into(),
            device_name: "my-laptop".into(),
            online: true,
        };
        assert_eq!(device_line(&device), "device-1  my-laptop  online");
        device.online = false;
        assert_eq!(device_line(&device), "device-1  my-laptop  offline");
    }
}
