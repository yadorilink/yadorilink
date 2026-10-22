//! The coordination-plane client: where this installation's credential and
//! device identity live, and the only request helpers that reach the
//! coordination service.

pub mod credential_store;
pub mod device_config;
pub mod http_client;
