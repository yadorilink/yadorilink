//! CLI surface for the connectivity doctor and the recent
//! connection-attempt traces — mirrors
//! `yadorilink_daemon::connection_trace`'s wire shape exactly.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{ConnectivityDoctorRequest, ListConnectionTracesRequest};

use yadorilink_local_storage::{daemon_lock, install_check, ownership, service_registrations};

use crate::control_client;
use crate::error::CliError;

/// The installation cross-check rows (see `yadorilink_local_storage::install_check`): what the
/// ownership record says against the install layout, the running daemon and the OS service
/// registrations. Reads only; works with no daemon running.
async fn installation_rows() -> Vec<install_check::Finding> {
    let Ok(config_dir) = yadorilink_client_core::coordination::device_config::config_dir() else {
        return Vec::new();
    };
    let record = ownership::read(&config_dir);
    let lock = daemon_lock::probe(&config_dir);
    let running = yadorilink_client_core::ops::daemon::identify().await.ok().map(|identity| {
        install_check::RunningInstall {
            install_source: identity.install_source,
            install_root: identity.install_root,
            version: identity.version,
            release_id: identity.release_id,
            engine_api_version: identity.engine_api_version,
        }
    });
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let recorded_root = match &record {
        ownership::RecordState::Present(r) => Some(r.install_root.as_str()),
        _ => None,
    };
    let roots = service_registrations::Roots::detect(home, recorded_root)
        .with_system_root(std::env::var_os("SystemRoot"));
    install_check::check(&install_check::Facts {
        config_dir: &config_dir,
        record: &record,
        lock: &lock,
        running: running.as_ref(),
        local: &yadorilink_client_core::daemon::control::local_descriptor(),
        roots: &roots,
    })
}

fn print_installation_rows(rows: &[install_check::Finding]) {
    for row in rows {
        let marker = match row.severity {
            install_check::Severity::Ok => "OK",
            install_check::Severity::Warn => "WARN",
            install_check::Severity::Error => "ERROR",
        };
        println!("[{marker}] {}: {}", row.check, row.detail);
    }
}

/// Where a background daemon writes its log on Windows, so a failure with no console can be found.
fn daemon_log_row() -> Option<String> {
    use yadorilink_fs_platform::state_dir::{
        checked_state_dir, daemon_log_file, process_override, Env, PathOverride,
    };
    if !cfg!(windows) {
        return None;
    }
    let path = match process_override(PathOverride::LogFile) {
        Ok(Some(path)) => path,
        // With a config directory override the daemon logs to stderr unless told otherwise.
        Ok(None) if Env::from_process().config_dir.is_some() => return None,
        Ok(None) => daemon_log_file(&checked_state_dir(&Env::from_process()).ok()?),
        Err(_) => return None,
    };
    Some(format!("[OK] daemon log: {}", path.display()))
}

pub async fn doctor() -> Result<(), CliError> {
    print_installation_rows(&installation_rows().await);
    if let Some(row) = daemon_log_row() {
        println!("{row}");
    }
    let resp =
        control_client::send(ReqPayload::ConnectivityDoctor(ConnectivityDoctorRequest {})).await?;
    let Some(RespPayload::ConnectivityDoctor(result)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    for category in result.categories {
        let marker = match category.status.as_str() {
            "ok" => "OK",
            "warn" => "WARN",
            _ => "ERROR",
        };
        println!("[{marker}] {}: {}", category.name, category.detail);
    }
    Ok(())
}

/// The resolved connection-attempt history: what this daemon tried, and
/// how each attempt ended.
pub async fn traces(peer_device_id: Option<String>) -> Result<(), CliError> {
    let resp =
        control_client::send(ReqPayload::ListConnectionTraces(ListConnectionTracesRequest {
            peer_device_id: peer_device_id.unwrap_or_default(),
        }))
        .await?;
    let Some(RespPayload::ListConnectionTraces(list)) = resp.payload else {
        return Err(CliError::Other("unexpected daemon response".into()));
    };
    if list.traces.is_empty() {
        println!("No connection attempts recorded yet.");
    }
    for trace in list.traces {
        let peer =
            if trace.peer_device_id.is_empty() { "-".to_string() } else { trace.peer_device_id };
        let failure = if trace.failure_category.is_empty() {
            String::new()
        } else {
            format!(" ({})", trace.failure_category)
        };
        println!(
            "{}  peer={peer}  source={}  class={}  outcome={}{failure}  auth={}  selected={}",
            trace.recorded_at_unix_nanos,
            trace.candidate_source,
            trace.address_class,
            trace.outcome,
            trace.authorization_decision,
            trace.selected,
        );
    }

    Ok(())
}
