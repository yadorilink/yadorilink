//! The typed operations every front end drives. Each returns a typed result
//! or a [`crate::CoreError`] and prints nothing.

pub mod account;
pub mod auth;
pub mod daemon;
pub mod device_supersede;
pub mod devices;
pub mod diagnostics;
pub mod files;
pub mod folders;
pub mod handoff;
pub mod links;
pub mod nas_admin;
pub mod paths;
pub(crate) mod provider_pending;
pub mod rewind;
pub mod shares;
pub mod start_over;
pub mod storage;
pub mod transfers;
pub mod updates;
