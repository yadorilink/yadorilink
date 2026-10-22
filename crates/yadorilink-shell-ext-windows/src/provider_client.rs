//! The provider-root protocol client over the daemon's named pipe.
//!
//! The requests, their timeouts, the fail-closed rule (a transport failure is `None`, never an
//! empty success) and the shown-version table live in
//! `yadorilink_windows_provider_policy::provider_client`; this module supplies the one thing that
//! is Windows-specific, the connection, and keeps the call shapes the rest of the host uses.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use tokio::net::windows::named_pipe::NamedPipeClient;
use yadorilink_ipc_proto::shellipc::{
    MaterializeToTempResponse, ProviderApplyChangeRequest, ProviderApplyChangeResponse,
    ProviderItem,
};
use yadorilink_windows_provider_policy::provider_client as policy;

pub use policy::{
    set_shown_versions, shown_version, version_hash_of, FetchTarget, MATERIALIZE_TIMEOUT,
    RECORD_TIMEOUT,
};

/// Connects to the daemon's shell pipe, with the daemon's identity verified.
#[derive(Clone, Copy, Debug, Default)]
pub struct Pipe;

impl policy::Connect for Pipe {
    type Stream = NamedPipeClient;

    async fn connect(&self) -> std::io::Result<NamedPipeClient> {
        crate::ipc_client::connect().await
    }
}

/// Every child of folder `parent` (empty: the root container), all pages. `None` when any page
/// could not be confirmed.
pub fn enumerate_children(root: &[u8], parent: &[u8]) -> Option<Vec<ProviderItem>> {
    policy::enumerate_children(&Pipe, root, parent)
}

/// Asks the daemon for bytes of `item`, as a verified file in its handoff directory.
pub fn materialize(
    root: &[u8],
    item: &[u8],
    request_id: &[u8],
    target: Option<FetchTarget>,
) -> Option<MaterializeToTempResponse> {
    policy::materialize(&Pipe, root, item, request_id, target)
}

/// [`materialize`] with its own `timeout`, abandoned (the connection dropped) once `cancel` is
/// set.
pub(crate) fn materialize_within(
    timeout: Duration,
    cancel: &AtomicBool,
    root: &[u8],
    item: &[u8],
    request_id: &[u8],
    target: Option<FetchTarget>,
) -> Option<MaterializeToTempResponse> {
    policy::materialize_within(&Pipe, timeout, cancel, root, item, request_id, target)
}

/// Sends one change the user made to the daemon and returns its answer; `None` when the daemon
/// could not be asked or did not answer.
pub fn apply(
    root: &[u8],
    request: ProviderApplyChangeRequest,
) -> Option<ProviderApplyChangeResponse> {
    policy::apply(&Pipe, root, request)
}

/// Tells the daemon that the user is reading `item` (it pauses background prefetch).
pub fn note_fetch_activity(root: &[u8], item: &[u8]) {
    policy::note_fetch_activity(&Pipe, root, item)
}
