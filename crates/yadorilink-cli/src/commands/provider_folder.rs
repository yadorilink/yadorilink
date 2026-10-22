//! Provider-backed folders (macOS File Provider): a folder with no directory. The operating system
//! shows it under the File Provider location; the daemon owns its content.

use yadorilink_client_core::ops::{links as link_ops, shares};

use crate::error::CliError;

/// `provider-folder create <name>`: a new group and a provider folder for it.
pub async fn create(
    display_name: String,
    group_name: Option<String>,
    on_demand: bool,
) -> Result<(), CliError> {
    let group_name = group_name.unwrap_or_else(|| display_name.clone());
    let created =
        shares::create_provider_folder(group_name, display_name.clone(), on_demand).await?;
    print_created(&display_name, &created.root_id);
    Ok(())
}

/// `provider-folder join <group-id> <name>`: an existing group as a provider folder.
pub async fn join(
    group_id: String,
    display_name: String,
    group_name: Option<String>,
    on_demand: bool,
) -> Result<(), CliError> {
    let group_name = group_name.unwrap_or_else(|| display_name.clone());
    let created =
        shares::join_provider_folder(group_id, group_name, display_name.clone(), on_demand).await?;
    print_created(&display_name, &created.root_id);
    Ok(())
}

/// `provider-folder remove <name>`: unlinks it; the operating system removes the domain and keeps
/// the downloaded files.
pub async fn remove(display_name: String, force: bool) -> Result<(), CliError> {
    let links = link_ops::list_links().await?;
    let Some(link) = links.iter().find(|l| l.provider_display_name == display_name) else {
        return Err(CliError::Other(format!("no provider folder named '{display_name}'")));
    };
    let handoff = link_ops::send_unlink_key(&link.local_path, force, Some(&link.group_id)).await?;
    println!(
        "Removed provider folder '{display_name}'. The downloaded files are kept where the \
         operating system moved them; `yadorilink status` shows the location once it has."
    );
    if let Some(result) = handoff {
        println!("  handoff completed: target={}", result.target_device_id);
    }
    Ok(())
}

fn print_created(display_name: &str, root_id: &str) {
    let short: String = root_id.chars().take(8).collect();
    println!(
        "Created provider folder '{display_name}' (root {short}). {}",
        where_it_shows_up(display_name)
    );
}

#[cfg(windows)]
fn where_it_shows_up(display_name: &str) -> String {
    format!(
        "It shows up as %USERPROFILE%\\YadoriLink\\{display_name} once the YadoriLink Cloud Files \
         host (yadorilink-cfapi-host) is running."
    )
}

#[cfg(not(windows))]
fn where_it_shows_up(_display_name: &str) -> String {
    "Enable File Provider in System Settings > General > Login Items & Extensions > File \
     Providers to show it in Finder."
        .to_string()
}
