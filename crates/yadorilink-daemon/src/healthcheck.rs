//! `yadorilink-daemon --healthcheck`: the probe a container runtime or service supervisor runs.
//!
//! It dials the daemon's own control socket (the path the daemon itself would use for this
//! environment) and asks for a status; any well-formed answer means the daemon is up and serving
//! its control plane. It creates nothing and never starts a daemon.

use yadorilink_http_api::control_client::ControlClient;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload;
use yadorilink_ipc_proto::daemonctl::StatusRequest;

/// The probe against an explicit client. `Ok` when the daemon answered.
pub async fn probe(client: &ControlClient) -> Result<(), String> {
    client.send(Payload::Status(StatusRequest {})).await.map(|_| ()).map_err(|e| e.to_string())
}

/// Process entry: `0` healthy, `1` not.
pub async fn run_from_env() -> i32 {
    #[cfg(unix)]
    let client = match crate::app::DaemonConfig::from_env() {
        Ok(config) => ControlClient::new(config.control_socket_path),
        Err(e) => {
            eprintln!("unhealthy: {e}");
            return 1;
        }
    };
    #[cfg(windows)]
    let client = ControlClient::new(crate::device_config::control_pipe_name());
    match probe(&client).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("unhealthy: {e}");
            1
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_daemon_is_unhealthy() {
        let dir = tempfile::tempdir().unwrap();
        let client = ControlClient::new(dir.path().join("absent.sock"));
        assert!(probe(&client).await.is_err());
    }
}
