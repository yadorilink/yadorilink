//! HTTP-backed implementations of `application::ports::*Coordination`
//! traits -- the only place in this crate that builds a coordination-plane
//! request URL or `reqwest::Client` for these use cases.

pub(crate) mod enrollment;
pub(crate) mod group_admin;
pub(crate) mod membership;
pub(crate) mod role_loss;
