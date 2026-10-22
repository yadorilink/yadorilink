//! Library surface for `yadorilink-cli`, split out so integration tests (and
//! `main.rs`) share the same command implementations.

pub mod commands;
pub mod error;

// The daemon control-socket client and the config directory live in
// `yadorilink-client-core`, shared with the desktop app; the commands that
// have no typed operation there yet reach them under these names.
pub(crate) use yadorilink_client_core::coordination::device_config;
pub(crate) use yadorilink_client_core::daemon::control as control_client;
