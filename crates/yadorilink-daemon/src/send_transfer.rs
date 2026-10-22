//! Track Send daemon integration: a one-shot P2P file send/receive lane,
//! deliberately separate from the sync/materialization machinery every
//! other module in this crate ultimately serves. See `yadorilink-send`'s
//! own crate doc comment for the full design; this module is only the
//! daemon-side glue that:
//!
//! - implements [`yadorilink_send::DeviceDirectory`] against this
//!   daemon's already-known device list (`PeerAuthorityState::peer_signing_key`/
//!   `device_id_for_signing_key`, the iroh substrate reachability the
//!   coordination plane reported, and grant-derived peers -- all
//!   connectivity/identity bookkeeping, never anything native-state- or
//!   materialization-related);
//! - decides who may open a connection on Track Send's own ALPN
//!   ([`track_send_admission`]): a device with a live grant, or the
//!   receiver of an offer this device's user sent and it accepted. Folder
//!   group membership is never a reason, in either direction;
//! - waits for the reconciliation stack's iroh endpoint to exist, then
//!   builds and publishes this device's one `yadorilink_send::SendService`
//!   over it;
//! - runs its inbound-connection dispatcher for as long as that endpoint;
//! - exposes the two thin control-socket-facing wrappers
//!   ([`SendTransferService`] for `send`/`receive`,
//!   [`InboxQueries`] for `inbox`) that `adapters::build_application_
//!   services`/`build_query_services` wire in like any other narrow
//!   port -- `control_context.rs`'s own doc comment is explicit that
//!   `ControlContext` itself must never gain a raw `DaemonState` field,
//!   so this module deliberately does not ask for one.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use yadorilink_ipc_proto::daemonctl::RetryDirection;

use yadorilink_send::{
    DeviceDirectory, GrantedDevice, InboxEntry, ReceiveOutcome, ResolvedDevice, SendOfferOutcome,
    SendService,
};
use yadorilink_sync_substrate::{AdmitWhen, PeerAdmission, PeerId};

use crate::daemon_state::{DaemonState, SendGrantPeer};

/// How often this device checks whether the reconciliation stack's iroh
/// endpoint exists yet, before Track Send has anything to dial or accept
/// on. Only matters for the (short) window right after daemon startup.
const ENDPOINT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Who may open a connection on Track Send's ALPN to this device.
///
/// Exactly two reasons, both about Track Send itself:
///
/// - a live grant names the device (`DaemonState::send_grant_peers`, TTL
///   pruned on every read): the sender this device was told to expect, or
///   the receiver this device's own grant request named;
/// - this device sent it an offer that it accepted, so it may come back to
///   pull the content after the grant has expired -- but only while the
///   device is still one this device's netmap pins. An accepted offer is a
///   durable record that never expires; on its own it would keep admitting
///   a device for the life of the send database, including after that
///   device was removed from the account. Past the grant, the device's
///   current authority is what admits it, exactly as for any other
///   connection from it.
///
/// Being a pinned sync peer is not on its own a reason, and admission here
/// is not a reason to be a sync peer: the sync ALPN has its own admission.
/// Pinned means the netmap lists the device with its key, which is identity,
/// not folder-group membership. An admitted connection still cannot deliver
/// an offer without presenting a grant the coordination plane consumes
/// (`SendService::handle_offer`).
///
/// Read live on every connection, so an expired grant or a withdrawn device
/// stops admitting on the next one; `PeerConnectivityRuntime::revoke_device`
/// asks it again to close the Track Send connections a withdrawn device
/// already has. Weak, so the policy does not keep the daemon state alive.
pub(crate) fn track_send_admission(state: &Arc<DaemonState>) -> Arc<dyn PeerAdmission> {
    let state = Arc::downgrade(state);
    AdmitWhen::new(move |peer: &PeerId| {
        let Some(state) = state.upgrade() else {
            return false;
        };
        let key = peer.as_bytes();
        state.send_grant_peer_by_key(key).is_some()
            || (state.authority.device_id_for_signing_key(key).is_some()
                && state.send_service().is_some_and(|service| service.expects_pull_from(key)))
    })
}

/// Weak, for the same reason as [`track_send_admission`]: the state owns
/// the `SendService` this directory is handed to, so a strong reference back
/// would keep the state alive for as long as the service is.
struct DaemonDeviceDirectory {
    state: std::sync::Weak<DaemonState>,
}

#[async_trait::async_trait]
impl DeviceDirectory for DaemonDeviceDirectory {
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
        let state = self.state.upgrade()?;
        if let Some(signing_key) = state.authority.peer_signing_key(device_query) {
            // Where its iroh endpoint answers, as the coordination plane
            // last reported it; the endpoint's own lookup knows the same.
            let reachability =
                state.peer_connectivity.substrate_reachability(device_query).unwrap_or_default();
            return Some(ResolvedDevice {
                device_id: device_query.to_string(),
                signing_key,
                direct_addresses: reachability.direct,
                relay_urls: reachability.relays,
            });
        }
        // Fallback for a device this daemon has no ordinary netmap
        // relationship with, but currently knows about through a Track
        // Send grant -- see `DaemonState::send_grant_peers`'s own doc
        // comment. This is what lets `receive_transfer`'s later pull-dial
        // resolve a grant-based sender: `handle_offer` recorded it here
        // (via `consume_grant`, keyed by the authenticated peer key) the
        // moment it accepted that sender's offer.
        let grant_peer = state.send_grant_peer_by_device_id(device_query)?;
        Some(ResolvedDevice {
            device_id: grant_peer.device_id,
            signing_key: grant_peer.signing_key,
            direct_addresses: grant_peer.reachability.direct,
            relay_urls: grant_peer.reachability.relays,
        })
    }

    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
        let state = self.state.upgrade()?;
        state
            .authority
            .device_id_for_signing_key(signing_key)
            .or_else(|| state.send_grant_peer_by_key(signing_key).map(|p| p.device_id))
    }

    async fn request_grant(&self, receiver_device_query: &str) -> Option<GrantedDevice> {
        let state = self.state.upgrade()?;
        let config = state.coordination_client_config()?.clone();
        let grant = crate::coordination_client::request_send_authorization(
            &config.addr,
            &config.auth,
            &state.device_id,
            receiver_device_query,
        )
        .await
        .inspect_err(|e| {
            tracing::debug!(
                error = %e,
                target = receiver_device_query,
                "Track Send authorization request failed"
            );
        })
        .ok()?;
        // Symmetric bookkeeping with the receiver side's own record below:
        // this device (the sender) may be dialed BACK during the pull
        // phase -- `track_send_admission` admits the receiver's key for as
        // long as this record lives -- and `device_id_for_key`/`resolve`
        // fall back to this same cache for any later grant-scoped lookup
        // naming the receiver.
        state.record_send_grant_peer(SendGrantPeer {
            device_id: grant.receiver_device_id.clone(),
            signing_key: grant.receiver_signing_key,
            reachability: grant.receiver_reachability.clone(),
            grant_id: grant.grant_id.clone(),
            nonce: grant.nonce.clone(),
            expires_at_unix: grant.expires_at_unix,
        });
        Some(GrantedDevice {
            device: ResolvedDevice {
                device_id: grant.receiver_device_id,
                signing_key: grant.receiver_signing_key,
                direct_addresses: grant.receiver_reachability.direct,
                relay_urls: grant.receiver_reachability.relays,
            },
            grant_id: grant.grant_id,
            grant_nonce: grant.nonce,
            expires_at_unix: grant.expires_at_unix,
        })
    }

    async fn consume_grant(
        &self,
        grant_id: &str,
        grant_nonce: &str,
        peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        // The load-bearing identity binding: `pending.device_id` was
        // derived from `peer_key` -- the handshake-authenticated key (iroh
        // endpoint id) THIS connection actually holds the private half of
        // -- never from
        // anything the offer's own envelope claims. See `consume_grant`'s
        // own trait doc comment.
        let state =
            self.state.upgrade().ok_or_else(|| "the daemon is shutting down".to_string())?;
        let pending = state.send_grant_peer_by_key(peer_key).ok_or_else(|| {
            "no pending Track Send authorization for this connection's authenticated key"
                .to_string()
        })?;
        // Cheap local reject for an obviously-wrong grant id/nonce before
        // spending a coordination-plane round trip -- defense in depth,
        // not the real guard; see `SendGrantPeer`'s own doc comment.
        if pending.grant_id != grant_id || pending.nonce != grant_nonce {
            return Err("send authorization is invalid, expired, or already used".to_string());
        }
        let config = state
            .coordination_client_config()
            .ok_or_else(|| "not connected to the coordination plane".to_string())?
            .clone();
        crate::coordination_client::consume_send_authorization(
            &config.addr,
            &config.auth,
            grant_id,
            grant_nonce,
            &pending.device_id,
            &state.device_id,
        )
        .await?;
        Ok(())
    }
}

/// Waits for this device's reconciliation stack -- and so its iroh
/// endpoint, which answers Track Send's ALPN -- to exist, then builds and
/// publishes this device's `SendService` over that endpoint and serves the
/// Track Send connections it admits.
///
/// `config_dir` is this device's own config directory -- Track Send's own
/// subdirectory of it (`config_dir/send`) is sibling to, and never shares a
/// file with, `block_store_root`/`sync_db_path` (the sync engine's paths).
/// Threaded in explicitly by the caller (production: `DaemonConfig::
/// config_dir`, matching every other per-device path this daemon derives
/// from it) rather than re-read from `crate::device_config::config_dir()`
/// in here, since that reads a single process-wide env var -- fine for one
/// device per process in production, but wrong for a test harness running
/// several `DaemonState`s in one process (`tests/support/topology.rs`),
/// where each device needs its OWN isolated Track Send store.
///
/// Spawned as a `supervise::spawn_logged` background task alongside
/// `peer_orchestrator::run` -- only when this device is logged in and
/// registered (Track Send needs the same coordination-plane device
/// identity `peer_orchestrator` does), never started otherwise.
pub async fn run(
    state: Arc<DaemonState>,
    config_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (node, inbound) = loop {
        if let Some(driver) = state.peer_session_driver() {
            let endpoint = driver.stack().endpoint();
            let Some(inbound) = endpoint.take_track_send_inbound() else {
                return Err("Track Send's inbound queue was already taken".into());
            };
            break (endpoint.node(), inbound);
        }
        tokio::time::sleep(ENDPOINT_POLL_INTERVAL).await;
    };

    let base_dir = config_dir.join("send");
    let store_db_path = base_dir.join("store.sqlite3");
    let block_store_root = base_dir.join("blocks");
    let default_inbox_dir = base_dir.join("inbox");
    let directory: Arc<dyn DeviceDirectory> =
        Arc::new(DaemonDeviceDirectory { state: Arc::downgrade(&state) });

    let service = Arc::new(SendService::new(
        node,
        store_db_path,
        block_store_root,
        directory,
        default_inbox_dir,
    )?);
    state.set_send_service(service.clone());

    service.run_inbound_dispatcher(inbound).await;
    Ok(())
}

/// The `send`/`receive` half of Track Send's control-socket surface --
/// `ApplicationServices`' one Track Send field, matching every other
/// mutating command's own service. Read-only `inbox` is
/// [`InboxQueries`] instead, in `QueryServices`, mirroring this crate's
/// existing command/query split (e.g. `link_lifecycle` vs `link_status`).
/// Rejects a path the daemon would otherwise resolve against its own working
/// directory, which is unrelated to the directory the user typed it in.
fn require_absolute(what: &str, path: &str) -> Result<(), String> {
    if std::path::Path::new(path).is_absolute() {
        Ok(())
    } else {
        Err(format!("the {what} must be an absolute path, got {path:?}"))
    }
}

pub(crate) struct SendTransferService {
    state: Arc<DaemonState>,
}

impl SendTransferService {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    fn service(&self) -> Result<Arc<SendService>, String> {
        self.state.send_service().ok_or_else(|| {
            "Track Send is not ready yet (this device has no coordination-plane connectivity \
             established)"
                .to_string()
        })
    }

    pub(crate) async fn send(
        &self,
        source_path: &str,
        target_device: &str,
    ) -> Result<SendOfferOutcome, String> {
        require_absolute("source path", source_path)?;
        let service = self.service()?;
        service
            .offer_send(std::path::Path::new(source_path), target_device)
            .await
            .map_err(|e| e.to_string())
    }

    pub(crate) async fn receive(
        &self,
        transfer_id: &str,
        destination_dir: Option<&str>,
    ) -> Result<ReceiveOutcome, String> {
        if let Some(dir) = destination_dir {
            require_absolute("destination directory", dir)?;
        }
        let service = self.service()?;
        let destination_dir = destination_dir.map(std::path::Path::new);
        service.receive_transfer(transfer_id, destination_dir).await.map_err(|e| e.to_string())
    }

    pub(crate) fn cancel(&self, transfer_id: &str) -> Result<(), String> {
        self.service()?.cancel_transfer(transfer_id).map_err(|e| e.to_string())
    }

    /// Retries a transfer by id: resumes a received one, or offers a sent one again.
    pub(crate) async fn retry(
        &self,
        transfer_id: &str,
        expected: RetryDirection,
    ) -> Result<RetryOutcome, String> {
        let service = self.service()?;
        let direction = service.transfer_direction(transfer_id).map_err(|e| e.to_string())?;
        check_retry_direction(transfer_id, direction, expected).map_err(|e| e.to_string())?;
        match direction {
            Some(yadorilink_send::TransferDirection::Sent) => service
                .retry_sent_transfer(transfer_id)
                .await
                .map(RetryOutcome::Offered)
                .map_err(|e| e.to_string()),
            Some(yadorilink_send::TransferDirection::Received) => service
                .retry_transfer(transfer_id)
                .await
                .map(RetryOutcome::Received)
                .map_err(|e| e.to_string()),
            None => {
                Err(yadorilink_send::SendError::UnknownTransfer(transfer_id.to_string())
                    .to_string())
            }
        }
    }
}

/// Refuses a retry meant for the other side of a transfer, before anything is done: it must not
/// resume a receive or offer a transfer the caller did not mean.
pub(crate) fn check_retry_direction(
    transfer_id: &str,
    actual: Option<yadorilink_send::TransferDirection>,
    expected: RetryDirection,
) -> Result<(), yadorilink_send::SendError> {
    use yadorilink_send::{SendError, TransferDirection};
    match (actual, expected) {
        (Some(TransferDirection::Sent), RetryDirection::Received) => {
            Err(SendError::NotReceived(transfer_id.to_string()))
        }
        (Some(TransferDirection::Received), RetryDirection::Sent) => {
            Err(SendError::NotSent(transfer_id.to_string()))
        }
        _ => Ok(()),
    }
}

/// What a retry did.
pub(crate) enum RetryOutcome {
    Received(ReceiveOutcome),
    Offered(SendOfferOutcome),
}

pub(crate) struct InboxQueries {
    state: Arc<DaemonState>,
}

impl InboxQueries {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub(crate) fn list(&self) -> Result<Vec<InboxEntry>, String> {
        let service = self.state.send_service().ok_or_else(|| {
            "Track Send is not ready yet (this device has no coordination-plane connectivity \
             established)"
                .to_string()
        })?;
        service.list_inbox().map_err(|e| e.to_string())
    }

    pub(crate) fn list_sent(&self) -> Result<Vec<yadorilink_send::SentEntry>, String> {
        let service = self.state.send_service().ok_or_else(|| {
            "Track Send is not ready yet (this device has no coordination-plane connectivity \
             established)"
                .to_string()
        })?;
        service.list_sent().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests;
