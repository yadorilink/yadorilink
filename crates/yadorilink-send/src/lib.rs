//! Track Send: a one-shot, Taildrop/Resilio-style P2P file send/receive
//! lane. Deliberately separate from the sync/materialization lane this
//! workspace's other crates implement -- see this crate's `Cargo.toml` for
//! the dependency-graph argument (no dependency on `yadorilink-sync-wire`,
//! `yadorilink-sync-sqlite`, `yadorilink-peer-session`, or
//! `yadorilink-daemon`) and `store.rs`'s own module doc comment for the
//! storage-side argument (its own database file, its own schema, no native-state
//! table ever created or read).
//!
//! Layering:
//! - [`manifest`]: chunks a source path into an ephemeral, offer-scoped
//!   manifest -- never admitted to native state.
//! - [`store`]: this device's own local record of outbound offers and
//!   inbound transfers -- a separate database file, a separate schema.
//! - [`wire`]: length-prefixed protobuf framing for Track Send's own ALPN
//!   connections, reusing the sync protocol's own generic framing helpers.
//! - [`session`]: [`session::SendService`], the orchestration layer CLI/
//!   daemon integration calls into.
//!
//! Scope for v1: same-account devices only. Every outbound offer requires a
//! fresh, short-lived, sender+receiver-bound Track Send rendezvous grant --
//! obtained unconditionally by `offer_send` and enforced unconditionally by
//! `handle_offer` -- regardless of whether the target device is ALSO
//! visible through the coordination plane's (group-scoped, and
//! cross-account-inclusive) netmap. Ordinary netmap/sync
//! authorization only ever supplies device addressing elsewhere (e.g. a
//! receiver's pull-phase dial back to a sender it already accepted an offer
//! from); it is never treated as sufficient to send or receive on its own.
//! See [`session::DeviceDirectory`]'s own doc comment for why cross-account
//! send stays out of scope by construction rather than merely unimplemented,
//! and `crates/yadorilink-daemon`'s `send_transfer` module for the grant
//! primitive's full design (this crate itself only calls
//! [`session::DeviceDirectory::request_grant`]/`consume_grant`; it has no
//! idea a coordination plane exists).

pub mod error;
pub mod manifest;
pub mod session;
pub mod store;
pub mod wire;

pub use error::{failure, Result, SendError};
pub use session::{
    DeviceDirectory, GrantedDevice, InboxEntry, ReceiveOutcome, ResolvedDevice, SendOfferOutcome,
    SendService, SentEntry, TransferDirection,
};
