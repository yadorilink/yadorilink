//! The client application layer shared by every YadoriLink front end.
//!
//! The command-line tool and the desktop app both reach the local daemon
//! through [`daemon::control`] and the coordination plane through
//! [`coordination`], and drive the same typed operations. Nothing in this
//! crate prints, prompts or exits: every operation returns a typed result or
//! a [`CoreError`], and each front end decides how to present it.
//!
//! Two layers:
//! - [`ops`]: typed, lossless operations over the daemon's control protocol
//!   and the coordination plane, for the command-line tool and the desktop
//!   app.
//! - [`ClientCore`]: the product facade a desktop front end binds to. It
//!   speaks only product types ([`dto`]) and the seven-case [`DesktopError`],
//!   and holds the long-lived handles in [`session`].

// `DesktopError::DaemonUnavailable` carries the engine-mismatch descriptors inline (an FFI enum
// cannot box them); the error is the cold path of every call.
#![allow(clippy::result_large_err)]

// The foreign-language binding for the product types (`dto`, `DesktopError`),
// only when a binding crate asks for it.
#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();

pub mod coordination;
pub mod daemon;
/// The shared meaning of problems that need the user (see `yadorilink-product-view`).
pub use yadorilink_product_view as attention;
pub mod dto;
pub mod error;
mod facade;
pub mod ops;
pub mod session;
pub mod wording;

pub use error::{CoreError, DesktopError, Hint};
pub use facade::{
    account_status_in, new_login_session_in, new_reauthentication_session_in, ClientCore,
    DEFAULT_STATUS_INTERVAL,
};
