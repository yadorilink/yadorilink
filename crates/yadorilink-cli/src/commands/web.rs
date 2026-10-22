//! `yadorilink web status`: how to open the daemon's local web dashboard,
//! including from another computer over an SSH tunnel.
//!
//! Read-only and secret-free: it reads the port the daemon recorded next to
//! its token (`http-api-port`, written only once the listener is up and
//! removed at every daemon start) and prints the token file's path, never the
//! token itself, so nothing secret reaches the terminal, a URL or the shell
//! history.

use std::path::Path;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::HealthRequest;

use crate::control_client;
use crate::device_config;
use crate::error::CliError;

/// The daemon's names for these files in its state directory.
const PORT_FILE_NAME: &str = "http-api-port";
const TOKEN_FILE_NAME: &str = "http-api-token";

pub async fn status() -> Result<(), CliError> {
    // A port file only describes a running daemon's listener.
    control_client::send(ReqPayload::Health(HealthRequest {})).await?;
    let dir = device_config::config_dir()?;
    let port = read_port(&dir.join(PORT_FILE_NAME))?;
    print!("{}", render(port, &dir.join(TOKEN_FILE_NAME)));
    Ok(())
}

fn read_port(path: &Path) -> Result<Option<u16>, CliError> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            text.lines().next().unwrap_or_default().trim().parse().map(Some).map_err(|_| {
                CliError::Other(format!("{} does not hold a port number", path.display()))
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CliError::Other(format!("cannot read {}: {e}", path.display()))),
    }
}

fn render(port: Option<u16>, token_path: &Path) -> String {
    let Some(port) = port else {
        return "Web dashboard: not running. It is turned off by YADORILINK_HTTP_API_DISABLE, \
                or it failed to start; the daemon log says why.\n"
            .to_owned();
    };
    format!(
        "Web dashboard: listening on 127.0.0.1:{port}, this computer only.\n\
         Open on this computer: http://127.0.0.1:{port}/\n\
         From another computer, forward the same port over SSH:\n\
         \x20   ssh -N -L {port}:127.0.0.1:{port} <user>@<this-host>\n\
         then open http://127.0.0.1:{port}/ there. A different local port is refused.\n\
         Access token: in {token}; on Linux and macOS only the daemon's own account can read it. \
         The daemon writes a new one each time it starts; paste it into the dashboard.\n",
        token = token_path.display(),
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn file_names_match_the_ones_the_daemon_writes() {
        assert_eq!(PORT_FILE_NAME, yadorilink_http_api::PORT_FILE_NAME);
        assert_eq!(TOKEN_FILE_NAME, yadorilink_http_api::TOKEN_FILE_NAME);
    }

    #[test]
    fn a_listening_dashboard_prints_the_tunnel_and_url_with_one_port() {
        let out = render(Some(8484), &PathBuf::from("/var/lib/yadorilink/http-api-token"));
        assert_eq!(
            out,
            "Web dashboard: listening on 127.0.0.1:8484, this computer only.\n\
             Open on this computer: http://127.0.0.1:8484/\n\
             From another computer, forward the same port over SSH:\n\
             \x20   ssh -N -L 8484:127.0.0.1:8484 <user>@<this-host>\n\
             then open http://127.0.0.1:8484/ there. A different local port is refused.\n\
             Access token: in /var/lib/yadorilink/http-api-token; on Linux and macOS only the \
             daemon's own account can read it. The daemon writes a new one each time it starts; paste it into \
             the dashboard.\n"
        );
    }

    #[test]
    fn the_output_never_carries_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join(TOKEN_FILE_NAME);
        std::fs::write(&token_path, "0123456789abcdef").unwrap();
        for port in [Some(8484), None] {
            let out = render(port, &token_path);
            assert!(!out.contains("0123456789abcdef"), "{out}");
            assert!(!out.contains('?'), "no query string: {out}");
        }
    }

    #[test]
    fn a_missing_port_file_means_not_listening() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_port(&dir.path().join(PORT_FILE_NAME)).unwrap(), None);
        std::fs::write(dir.path().join(PORT_FILE_NAME), "18484\n").unwrap();
        assert_eq!(read_port(&dir.path().join(PORT_FILE_NAME)).unwrap(), Some(18484));
        std::fs::write(dir.path().join(PORT_FILE_NAME), "18484\nnonce\n").unwrap();
        assert_eq!(read_port(&dir.path().join(PORT_FILE_NAME)).unwrap(), Some(18484));
        std::fs::write(dir.path().join(PORT_FILE_NAME), "nope").unwrap();
        assert!(read_port(&dir.path().join(PORT_FILE_NAME)).is_err());
        assert!(render(None, &dir.path().join(TOKEN_FILE_NAME))
            .starts_with("Web dashboard: not running."));
    }
}
