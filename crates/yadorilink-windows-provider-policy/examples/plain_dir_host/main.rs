//! A provider host over a plain directory, for tests. Not shipped.
//!
//! It speaks the shell-socket host protocol the way the macOS File Provider host and the Windows
//! Cloud Files host do (attach, register a root as a ready provider folder, show the namespace as
//! placeholders, serve fetches into the daemon's handoff directory, drop copies on the daemon's
//! eviction request, report the materialized set, send what the user did in the folder), so a
//! daemon accepts On-Demand folders on a machine with no signed provider host. The loop and every
//! decision in it are the real host's (`yadorilink_windows_provider_policy::host`); only the
//! operating-system side, a directory with a sidecar record instead of Cloud Files placeholders,
//! is replaced. See `control.rs` for how an open-triggered fetch is requested.
//!
//! ```text
//! plain_dir_host --socket <daemon config dir>/shell.sock --state-dir <dir> --view-parent <dir> \
//!                --control <socket path>
//! ```
//!
//! A root shows up as `<view-parent>/CloudStorage/StandIn-<name>`, the shape of a macOS File
//! Provider location, which is how the daemon maps a path back to its folder.

#[cfg(unix)]
mod app;
#[cfg(unix)]
mod backend;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod daemon;
#[cfg(unix)]
mod eager;
#[cfg(unix)]
mod flight;
#[cfg(unix)]
mod plain_fs;

#[cfg(unix)]
fn main() {
    app::run();
}

#[cfg(not(unix))]
fn main() {
    eprintln!("plain-dir-host: this stand-in needs a unix host (sockets and file modes)");
    std::process::exit(2);
}
