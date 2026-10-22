//! Configuration this adapter is started with. Deliberately plain data with
//! no environment-variable parsing of its own -- the daemon binary (the
//! only production caller) already owns exactly this convention for every
//! other local runtime path (`yadorilink_daemon::app::DaemonConfig::from_env`),
//! so env-var handling stays there rather than being duplicated here. This
//! keeps `HttpApiConfig` trivially constructible from a test too.

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct HttpApiConfig {
    /// The daemon's own existing control-socket path (Unix) this adapter
    /// dials for every request -- see `control_client.rs`.
    #[cfg(unix)]
    pub control_socket_path: PathBuf,
    /// The daemon's own existing control-pipe name (Windows) this adapter
    /// dials for every request.
    #[cfg(windows)]
    pub control_pipe_name: String,
    /// Where the freshly generated bearer token is written on every start
    /// (see `token.rs`). The parent directory is created if missing.
    pub token_path: PathBuf,
    /// Where the port actually bound is written, as decimal text, once the
    /// adapter is listening. Not a secret: it lets a local helper print the
    /// dashboard address without reading the token or asking the daemon.
    /// The daemon removes it before every start, so it exists only while
    /// this run's listener does.
    pub port_path: PathBuf,
    /// TCP port this adapter binds on both `127.0.0.1` and `[::1]`. `0`
    /// requests an OS-assigned ephemeral port on each (used by tests);
    /// `serve` reports back whichever port was actually bound.
    pub port: u16,
    /// Additional exact `Origin` values to accept, beyond this adapter's
    /// own loopback origins -- e.g. `http://localhost:5173` for a local Web
    /// UI dev server proxying API calls through to this adapter during
    /// development. Never a wildcard; empty in production.
    pub extra_allowed_origins: Vec<String>,
}
