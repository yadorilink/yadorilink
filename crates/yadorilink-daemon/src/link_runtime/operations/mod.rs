//! Per-link operations dispatched through [`super::RootLease`]. Each
//! submodule wraps one thing this crate does to a link's on-disk/indexed
//! state, admitting a `LinkOperation` for the whole call rather than
//! leaving each caller to remember to. Two of the three operations named
//! in this crate's `link_runtime` design are represented here:
//! [`capture_local_change`] and [`repair_materialization`] -- see each
//! module's own doc for what it covers.

pub(crate) mod capture_local_change;
pub(crate) mod repair_materialization;
