//! `DaemonState`-backed implementations of `crate::queries`' read ports.
//! The only place in this crate allowed to hold `Arc<DaemonState>` for a
//! *query* (as opposed to `application`'s command-side adapters) -- see
//! `crate::queries::link_status`'s own doc comment for why that's a
//! deliberate strangler step, not a shortcut.

pub(crate) mod diagnostics_bundle;
pub(crate) mod handoff_readiness;
pub(crate) mod link_status;
pub(crate) mod recovery;
