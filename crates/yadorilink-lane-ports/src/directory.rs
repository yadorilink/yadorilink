//! Who a transport identity belongs to, and what they may be told.
//!
//! # Two identities, deliberately not the same one
//!
//! A peer has an iroh endpoint identity (which key terminated the QUIC
//! connection) and a Yadori device identity (which member of a group it is).
//! They are separate keys and the substrate is explicit that the first is
//! carrier identity only: it never contributes to whether a Change may be
//! admitted.
//!
//! But disclosure is a different question from admission. Deciding *what to
//! tell this connection* does require knowing who is on the other end, so the
//! binding between the two identities has to come from somewhere trustworthy.
//! It comes from the coordination plane, alongside the address information
//! that plane already publishes.
//!
//! **This binding is not yet published by the coordination plane.** Until it
//! is, nothing populates a directory in production and every peer resolves to
//! `None`, which means no disclosure. That is the fail-closed direction: a
//! peer whose identity cannot be established is told nothing, rather than
//! being assumed to be whoever the transport says it is.

use std::collections::{HashMap, HashSet};

/// Resolves transport identities to devices, and answers what a device may be
/// told about.
pub trait PeerDirectory: Send + Sync {
    /// The device this endpoint identity belongs to, as published by the
    /// coordination plane.
    ///
    /// `None` means the binding is unknown. It must never be inferred from
    /// the connection itself: a peer asserting a device identity over its own
    /// transport is asserting exactly the thing being checked.
    fn device_for_endpoint(&self, endpoint: &[u8; 32]) -> Option<String>;

    /// Whether `device_id` is authorized for `group_id`.
    fn is_authorized(&self, device_id: &str, group_id: &str) -> bool;
}

/// A directory held in memory, replaced wholesale from the netmap.
///
/// Replaced rather than patched, for the same reason
/// `replace_peer_netmap_metadata` replaces its authorization sets: a
/// revocation must not be able to leave a stale entitlement behind merely
/// because the transport session was already connected.
#[derive(Debug, Default)]
pub struct StaticPeerDirectory {
    endpoints: HashMap<[u8; 32], String>,
    authorized: HashSet<(String, String)>,
}

impl StaticPeerDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `endpoint` is `device_id`, as published by the
    /// coordination plane.
    pub fn bind_endpoint(&mut self, endpoint: [u8; 32], device_id: impl Into<String>) {
        self.endpoints.insert(endpoint, device_id.into());
    }

    /// Record that `device_id` is authorized for `group_id`.
    pub fn authorize(&mut self, device_id: impl Into<String>, group_id: impl Into<String>) {
        self.authorized.insert((device_id.into(), group_id.into()));
    }
}

impl PeerDirectory for StaticPeerDirectory {
    fn device_for_endpoint(&self, endpoint: &[u8; 32]) -> Option<String> {
        self.endpoints.get(endpoint).cloned()
    }

    fn is_authorized(&self, device_id: &str, group_id: &str) -> bool {
        self.authorized.contains(&(device_id.to_owned(), group_id.to_owned()))
    }
}
