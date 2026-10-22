//! `yadorilink account ...`: the self-service account-deletion lifecycle and
//! the account data export.
//!
//! Both operate only on server-side coordination records; neither ever
//! touches the folders synced on the user's machines. A lost or replaced
//! device re-establishes its identity by signing in and registering as a new
//! device -- there is no exported identity artifact to import.

use std::path::PathBuf;

use yadorilink_client_core::ops::account as ops;

use crate::error::CliError;

use yadorilink_client_core::ops::account::DeletionStatus;
use yadorilink_client_core::wording::LOCAL_FIRST_NOTICE;

pub async fn delete_request() -> Result<(), CliError> {
    let requested = ops::request_deletion().await?;
    println!("{LOCAL_FIRST_NOTICE}\n");
    println!("Account deletion requested. Nothing is deleted yet. To confirm, run:\n");
    println!("    yadorilink account delete confirm {}\n", requested.confirmation_token);
    println!(
        "This confirmation token is shown only once. After you confirm, a grace period \
starts during which you can still cancel with `yadorilink account delete cancel`."
    );
    Ok(())
}

pub async fn delete_confirm(confirmation_token: String) -> Result<(), CliError> {
    let status = ops::confirm_deletion(confirmation_token).await?;
    println!("{LOCAL_FIRST_NOTICE}\n");
    println!("{}", status_line(&status));
    println!(
        "You can still cancel with `yadorilink account delete cancel` until the grace period ends; \
only finalization is irreversible."
    );
    Ok(())
}

pub async fn delete_cancel() -> Result<(), CliError> {
    let status = ops::cancel_deletion().await?;
    println!("Account deletion cancelled. Your account is {}.", status.state);
    Ok(())
}

pub async fn delete_status() -> Result<(), CliError> {
    println!("{}", status_line(&ops::deletion_status().await?));
    Ok(())
}

/// Generates the export and either writes it to `output_path` or prints it.
/// Writing the export is a create/write of the user's own data -- there is no
/// deletion of any local folder anywhere in this path.
pub async fn export(output_path: Option<PathBuf>) -> Result<(), CliError> {
    let pretty = ops::export_account_json().await?;
    match output_path {
        Some(path) => {
            std::fs::write(&path, pretty)?;
            println!("Wrote your account data export to {}.", path.display());
        }
        None => println!("{pretty}"),
    }
    println!(
        "\nThis export contains only your coordination-plane records -- never your file \
contents, file or folder names, or paths, which the server never holds."
    );
    Ok(())
}

fn status_line(status: &DeletionStatus) -> String {
    match status.state.as_str() {
        "grace" => format!(
            "Account deletion is scheduled: the grace period ends in about {} (unix time {}). \
Finalization is irreversible.",
            format_remaining(status.remaining_secs.unwrap_or(0)),
            status.grace_expires_at_unix.unwrap_or(0),
        ),
        "requested" => "Account deletion has been requested but not yet confirmed.".to_string(),
        "active" => "Your account is active. No deletion is in progress.".to_string(),
        other => format!("Account deletion state: {other}."),
    }
}

/// Coarse, human-readable rendering of a remaining-grace duration.
fn format_remaining(secs: i64) -> String {
    let secs = secs.max(0);
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_remaining_renders_coarse_buckets() {
        assert_eq!(format_remaining(-5), "0m");
        assert_eq!(format_remaining(90), "1m");
        assert_eq!(format_remaining(3 * 3600 + 600), "3h 10m");
        assert_eq!(format_remaining(2 * 86_400 + 5 * 3600), "2d 5h");
    }

    fn status(state: &str) -> DeletionStatus {
        DeletionStatus {
            state: state.into(),
            grace_expires_at_unix: Some(1_800_000_000),
            remaining_secs: Some(2 * 86_400 + 5 * 3600),
        }
    }

    #[test]
    fn status_lines_are_pinned_verbatim() {
        assert_eq!(
            status_line(&status("grace")),
            "Account deletion is scheduled: the grace period ends in about 2d 5h (unix time \
             1800000000). Finalization is irreversible."
        );
        assert_eq!(
            status_line(&status("requested")),
            "Account deletion has been requested but not yet confirmed."
        );
        assert_eq!(
            status_line(&status("active")),
            "Your account is active. No deletion is in progress."
        );
        assert_eq!(status_line(&status("frozen")), "Account deletion state: frozen.");
    }
}
