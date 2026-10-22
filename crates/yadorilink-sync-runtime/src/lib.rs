//! The sync runtime: owns the substrate endpoint, dials peers and routes
//! inbound lane streams to the handlers that own them. It decides nothing
//! about what is authorized, admissible or what a change means.

mod runtime;

pub use runtime::{
    AcceptedLinkHook, DialedLinkHook, IncompatibleLaneHook, LaneStreamHook, ServeHandle,
    SyncRuntime, SyncRuntimeError,
};
