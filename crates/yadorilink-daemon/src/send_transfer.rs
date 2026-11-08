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
use yadorilink_ipc_proto::daemonctl::{ApplicationErrorCode, RetryDirection, SendLinkState};

use yadorilink_send::{
    DeviceDirectory, GrantedDevice, InboxEntry, ReceiveOutcome, ResolvedDevice, SendOfferOutcome,
    SendService,
};
use yadorilink_sync_substrate::{AdmitWhen, PeerAdmission, PeerId};

use crate::coordination_client::{SendLinkCallError, SendLinkCallKind};
use crate::daemon_state::{DaemonState, SendGrantPeer};

mod link_book;
mod redeem_book;
pub(crate) use link_book::LinkBook;
use link_book::LinkRecord;
pub(crate) use redeem_book::RedeemBook;
use redeem_book::RedeemRecord;

/// How often this device checks whether the reconciliation stack's iroh
/// endpoint exists yet, before Track Send has anything to dial or accept
/// on. Only matters for the (short) window right after daemon startup.
const ENDPOINT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How long a Send link's background send waits for Track Send to come up (it needs this
/// device's coordination-plane connectivity, which a freshly started engine takes tens of
/// seconds to establish) before it reports "not ready, try again".
const SERVICE_READY_WAIT: Duration = Duration::from_secs(120);

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
            // The recipient of a Send link is on another account: no netmap lists it, and the
            // grant it came in with is gone minutes after the offer. The link's own offer admits
            // it to fetch, to report how its receive ended, or to be told of a cancel.
            || state.send_service().is_some_and(|service| service.expects_link_recipient(key))
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
        // `link:<id>` names a redeemed cross-account Send link: the grant is
        // then the link's pair-bound one (the recipient picked the device),
        // not a same-account `POST /send/authorization`.
        let grant = match link_id_of(receiver_device_query) {
            Some(link_id) => {
                crate::coordination_client::request_send_link_authorization(
                    &config.addr,
                    &config.auth,
                    link_id,
                    &state.device_id,
                )
                .await
            }
            None => {
                crate::coordination_client::request_send_authorization(
                    &config.addr,
                    &config.auth,
                    &state.device_id,
                    receiver_device_query,
                )
                .await
            }
        }
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
            link_id: link_id_of(receiver_device_query).map(str::to_owned),
        })
    }

    fn link_offer_recorded(&self, link_id: &str, transfer_id: &str) {
        let Some(state) = self.state.upgrade() else { return };
        // The person's consent is the redeem on this device: an offer under a link this device
        // did not redeem (or already received) is like any other and waits for an explicit receive.
        let Some(redeemed) = state.redeemed_send_links.take(link_id) else {
            tracing::info!(link_id, transfer_id, "Send link: offer under a link this device did not redeem; waiting for an explicit receive");
            return;
        };
        let Some(service) = state.send_service() else { return };
        let transfer_id = transfer_id.to_owned();
        let link_id = link_id.to_owned();
        tracing::info!(%link_id, %transfer_id, "Send link: receiving the offer of a redeemed link");
        tokio::spawn(async move {
            let destination = std::path::PathBuf::from(&redeemed.destination_dir);
            match service.receive_transfer(&transfer_id, Some(&destination)).await {
                Ok(outcome) => tracing::info!(
                    %link_id, %transfer_id, bytes = outcome.bytes_received,
                    "Send link: received"
                ),
                Err(error) => tracing::warn!(
                    %link_id, %transfer_id, %error,
                    "Send link: the receive stopped; it can be retried from the inbox"
                ),
            }
        });
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
        // The grant this offer presents, among the ones on record for this key: a sender with two
        // Send links to this device has two at once.
        let pending = state.send_grant_for(peer_key, grant_id).ok_or_else(|| {
            "no pending Track Send authorization for this connection's authenticated key"
                .to_string()
        })?;
        // Cheap local reject for an obviously-wrong nonce before spending a
        // coordination-plane round trip -- defense in depth, not the real
        // guard; see `SendGrantPeer`'s own doc comment.
        if pending.nonce != grant_nonce {
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
    reconcile_links_at_startup(&state.send_links, &service);

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

/// The paths of a request, each checked absolute.
fn absolute_sources(paths: &[String]) -> Result<Vec<std::path::PathBuf>, String> {
    paths
        .iter()
        .map(|path| {
            require_absolute("source path", path)?;
            Ok(std::path::PathBuf::from(path))
        })
        .collect()
}

/// The `target_device` prefix that names a cross-account Send link instead of
/// a device on this account.
const LINK_TARGET_PREFIX: &str = "link:";

fn link_id_of(target: &str) -> Option<&str> {
    target.strip_prefix(LINK_TARGET_PREFIX).filter(|id| !id.is_empty())
}

/// How long `send` to a link waits for the recipient to redeem it.
const LINK_REDEEM_WAIT: Duration = Duration::from_secs(10 * 60);
const LINK_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// What a link's state means for a sender about to send under it.
#[derive(Debug, PartialEq, Eq)]
enum LinkReadiness {
    /// Redeemed: the recipient picked a device; request the grant now.
    Ready,
    /// Not redeemed yet.
    Waiting,
    Refused(ApplicationErrorCode, &'static str),
}

fn link_readiness(state: &str) -> LinkReadiness {
    match state {
        "redeemed" => LinkReadiness::Ready,
        "open" => LinkReadiness::Waiting,
        "granted" => LinkReadiness::Refused(
            ApplicationErrorCode::SendLinkAlreadyUsed,
            "this send link was already used; create a new one",
        ),
        "cancelled" => LinkReadiness::Refused(
            ApplicationErrorCode::SendLinkCancelled,
            "this send link was canceled",
        ),
        "expired" => LinkReadiness::Refused(
            ApplicationErrorCode::SendLinkExpired,
            "this send link expired; create a new one",
        ),
        _ => LinkReadiness::Refused(
            ApplicationErrorCode::SendLinkInvalid,
            "this send link is not usable",
        ),
    }
}

/// A link as its sender sees it.
pub(crate) struct LinkStatusView {
    pub(crate) state: SendLinkState,
    pub(crate) receiver_device_name: String,
    pub(crate) transfer_id: String,
    /// The closed failure code of the interrupted link's transfer (or of the send that never got
    /// one); empty when none is on record.
    pub(crate) failure: String,
}

/// The link state a front end shows. `transfer` is the link's transfer, when this daemon started
/// it: its sent-list status, and whether it stopped with a reason on record. A granted link whose
/// transfer this device has no record of (the link was made elsewhere) is shown as going.
///
/// `send_failed`: a send under the link stopped before an offer was accepted, so there is no
/// transfer to ask. By then the service has usually spent the link's one grant ("granted"),
/// which would read as going forever; it is interrupted.
fn link_state(
    service_state: &str,
    transfer: Option<(&str, bool)>,
    send_failed: bool,
) -> SendLinkState {
    match service_state {
        "open" => SendLinkState::Waiting,
        "redeemed" => SendLinkState::Redeemed,
        "cancelled" => SendLinkState::Cancelled,
        "expired" => SendLinkState::Expired,
        "granted" => match transfer {
            Some(("completed", _)) => SendLinkState::Done,
            Some(("declined" | "canceled", _) | (_, true)) => SendLinkState::Interrupted,
            None if send_failed => SendLinkState::Interrupted,
            _ => SendLinkState::Transferring,
        },
        _ => SendLinkState::Unspecified,
    }
}

/// Why a link's send stopped when this device's engine did, kept on the link.
const ENGINE_STOPPED_REASON: &str =
    "this device's engine stopped before the transfer finished; create a new link";

/// A link whose send began in an earlier process of this engine can never finish: the offer, the
/// grant and the pull all belonged to that process, and the link's one grant is spent. Marks it
/// interrupted, so a front end says to create a new link instead of showing it as going forever:
/// the transfer it started is stopped (the receiver is told so if it comes to pull), and the link
/// records why. There is no resume. A transfer that already finished, or a link that never sent
/// anything, is left as it is.
pub(crate) fn reconcile_link(links: &LinkBook, service: &SendService, link_id: &str) {
    let Some(record) = links.list().into_iter().find(|l| l.link_id == link_id) else {
        // Not a link this device made: nothing here knows how its send went.
        return;
    };
    if let Some(transfer_id) = &record.transfer_id {
        let going = service.list_sent().is_ok_and(|sent| {
            sent.iter().any(|t| {
                &t.transfer_id == transfer_id && matches!(t.status, "offered" | "accepted")
            })
        });
        if going {
            if let Err(error) = service.cancel_transfer(transfer_id) {
                tracing::warn!(link_id, transfer_id, %error, "Send link: could not stop the transfer the engine left behind");
                return;
            }
            tracing::info!(
                link_id,
                transfer_id,
                "Send link: the engine restarted mid-transfer; interrupted"
            );
        }
    } else if record.send_failure.is_none() {
        tracing::info!(
            link_id,
            "Send link: the engine restarted before the send got an answer; interrupted"
        );
    } else {
        return;
    }
    if record.send_failure.is_none() {
        links.set_send_failure(link_id, Some(ENGINE_STOPPED_REASON));
    }
}

/// Startup: every link whose transfer was still going when the previous process ended is
/// interrupted now (see [`reconcile_link`]), whether or not anyone asks for its status.
fn reconcile_links_at_startup(links: &LinkBook, service: &SendService) {
    for record in links.list() {
        if record.transfer_id.is_some() {
            reconcile_link(links, service, &record.link_id);
        }
    }
}

/// A refusal of a send command: the text for a details view, and the typed code a front end
/// words itself when the failure is one it can tell apart.
#[derive(Debug)]
pub(crate) struct SendFailure {
    pub(crate) code: Option<ApplicationErrorCode>,
    pub(crate) message: String,
}

impl SendFailure {
    fn typed(code: ApplicationErrorCode, message: impl Into<String>) -> Self {
        Self { code: Some(code), message: message.into() }
    }
}

impl From<String> for SendFailure {
    fn from(message: String) -> Self {
        Self { code: None, message }
    }
}

impl From<SendLinkCallError> for SendFailure {
    fn from(error: SendLinkCallError) -> Self {
        let code = match error.kind {
            SendLinkCallKind::Unreachable => ApplicationErrorCode::CoordinationTransport,
            SendLinkCallKind::SignInRequired => ApplicationErrorCode::LocalIdentityUnavailable,
            SendLinkCallKind::NotFound => ApplicationErrorCode::SendLinkInvalid,
            SendLinkCallKind::FeatureDisabled => ApplicationErrorCode::SendLinksDisabled,
            SendLinkCallKind::PreviewUnverified => ApplicationErrorCode::SendPreviewUnverified,
            SendLinkCallKind::Other | SendLinkCallKind::Conflict => {
                return Self { code: None, message: error.message }
            }
        };
        Self::typed(code, error.message)
    }
}

impl From<yadorilink_send::SendError> for SendFailure {
    fn from(error: yadorilink_send::SendError) -> Self {
        use yadorilink_send::SendError;
        let code = if error.is_no_space() {
            Some(ApplicationErrorCode::SendNoSpace)
        } else if error.is_local_network_blocked() {
            Some(ApplicationErrorCode::SendLocalNetworkBlocked)
        } else if error.is_unreachable() || matches!(error, SendError::SenderGone(_)) {
            Some(ApplicationErrorCode::SendPeerUnreachable)
        } else if matches!(error, SendError::ReceiverStalled | SendError::TransferCanceled(_)) {
            Some(ApplicationErrorCode::SendInterrupted)
        } else {
            None
        };
        Self { code, message: error.to_string() }
    }
}

/// An inbox row in the wire shape the control socket answers with.
pub(crate) fn inbox_entry_to_proto(
    t: InboxEntry,
) -> yadorilink_ipc_proto::daemonctl::InboxTransfer {
    use yadorilink_ipc_proto::daemonctl::{InboxFileSummary, InboxTransfer};
    InboxTransfer {
        transfer_id: t.transfer_id,
        sender_device_id: t.sender_device_id,
        files: t
            .files
            .into_iter()
            .map(|(relative_path, size)| InboxFileSummary { relative_path, size })
            .collect(),
        total_size: t.total_size,
        offered_at_unix_nanos: t.offered_at_unix_nanos,
        status: t.status.to_string(),
        failure: t.failure.unwrap_or_default(),
        link_id: t.link_id,
        received_bytes: t.received_bytes,
        files_done: t.files_done,
        files_total: t.files_total,
        destination_dir: t.destination_dir.unwrap_or_default(),
    }
}

/// A sent-list row in the wire shape the control socket answers with.
pub(crate) fn sent_entry_to_proto(
    t: yadorilink_send::SentEntry,
) -> yadorilink_ipc_proto::daemonctl::SentTransferEntry {
    use yadorilink_ipc_proto::daemonctl::{InboxFileSummary, SentTransferEntry};
    SentTransferEntry {
        transfer_id: t.transfer_id,
        target_device_id: t.target_device_id,
        files: t
            .files
            .into_iter()
            .map(|(relative_path, size)| InboxFileSummary { relative_path, size })
            .collect(),
        total_size: t.total_size,
        created_at_unix_nanos: t.created_at_unix_nanos,
        status: t.status.to_string(),
        failure: t.failure.unwrap_or_default(),
        can_retry: t.can_retry,
        bytes_sent: t.bytes_sent,
    }
}

/// A link of the sender's list with its status.
pub(crate) struct ListedLink {
    pub(crate) link_id: String,
    pub(crate) created_at_unix: i64,
    pub(crate) expires_at_unix: i64,
    pub(crate) file_count: u32,
    pub(crate) view: LinkStatusView,
}

pub(crate) struct SendTransferService {
    state: Arc<DaemonState>,
    /// The links whose send began in this process. A link whose send began in an earlier process
    /// has nothing driving it any more (see [`reconcile_link`]).
    sending_here: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl SendTransferService {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state, sending_here: std::sync::Mutex::new(std::collections::HashSet::new()) }
    }

    /// The links this device created and the transfer each `link:<id>` send started, kept across
    /// restarts so a link's status can say how its transfer went.
    fn links(&self) -> &LinkBook {
        &self.state.send_links
    }

    fn service(&self) -> Result<Arc<SendService>, String> {
        self.state.send_service().ok_or_else(|| {
            "Track Send is not ready yet (this device has no coordination-plane connectivity \
             established)"
                .to_string()
        })
    }

    /// The Track Send service, waiting up to `wait` for a freshly started engine to publish it.
    /// Not ready in time is a retryable refusal typed as a coordination-plane problem, never a
    /// generic failure a front end could mistake for a spent or interrupted send.
    async fn wait_for_service(&self, wait: Duration) -> Result<Arc<SendService>, SendFailure> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(service) = self.state.send_service() {
                return Ok(service);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(SendFailure::typed(
                    ApplicationErrorCode::CoordinationTransport,
                    "Track Send is not ready yet (this device has not connected to the \
                     coordination plane); try again in a moment",
                ));
            }
            tokio::time::sleep(ENDPOINT_POLL_INTERVAL).await;
        }
    }

    pub(crate) async fn send(
        &self,
        source_paths: &[String],
        target_device: &str,
    ) -> Result<SendOfferOutcome, SendFailure> {
        let sources = absolute_sources(source_paths)?;
        if sources.is_empty() {
            return Err("name at least one file or folder to send".to_string().into());
        }
        let Some(link_id) = link_id_of(target_device) else {
            let service = self.service()?;
            return Ok(service.offer_send_many(&sources, target_device).await?);
        };
        // A link send runs in the background right after the link is made, which on a freshly
        // started engine is before Track Send is up: wait for it rather than fail the send.
        let service = self.wait_for_service(SERVICE_READY_WAIT).await?;
        // Every phase of a link send is logged, and a send that stops is recorded on the link:
        // the caller runs this in the background, and the service's own link state cannot tell
        // "the grant was spent and the offer failed" from "going".
        tracing::info!(link_id, "Send link: waiting for the recipient to redeem");
        self.sending_here
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(link_id.to_owned());
        self.links().set_send_failure(link_id, None);
        let result = async {
            self.wait_for_redeem(link_id).await?;
            tracing::info!(link_id, "Send link: redeemed; requesting the grant and offering");
            Ok::<_, SendFailure>(service.offer_send_many(&sources, target_device).await?)
        }
        .await;
        match &result {
            Ok(outcome) => {
                tracing::info!(
                    link_id,
                    transfer_id = %outcome.transfer_id,
                    "Send link: the recipient accepted the offer"
                );
                self.links().set_transfer(link_id, &outcome.transfer_id);
            }
            Err(failure) => {
                tracing::warn!(link_id, error = %failure.message, code = ?failure.code, "Send link: the send stopped");
                self.links().set_send_failure(link_id, Some(&failure.message));
            }
        }
        result
    }

    fn coordination(&self) -> Result<crate::daemon_state::CoordinationClientConfig, SendFailure> {
        self.state.coordination_client_config().cloned().ok_or_else(|| {
            // No sign-in on this device: there is nobody to act as.
            SendFailure::typed(
                ApplicationErrorCode::LocalIdentityUnavailable,
                "not connected to the coordination plane",
            )
        })
    }

    /// Mints a one-use expiring cross-account Send link for this device.
    pub(crate) async fn create_link(
        &self,
        ttl_seconds: u32,
        source_paths: &[String],
    ) -> Result<crate::coordination_client::CreatedSendLink, SendFailure> {
        let sources = absolute_sources(source_paths)?;
        // Same canonical form the later send uses, so the names shown here are the names sent.
        let sources = sources
            .iter()
            .map(|p| std::fs::canonicalize(p).map_err(|e| SendFailure::from(e.to_string())))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?
            .into_iter()
            .collect::<Vec<_>>();
        let files = if sources.is_empty() {
            Vec::new()
        } else {
            yadorilink_send::manifest::list_offered_files_multi(&sources)
                .map_err(SendFailure::from)?
        };
        let config = self.coordination()?;
        let created = crate::coordination_client::create_send_link(
            &config.addr,
            &config.auth,
            &self.state.device_id,
            (ttl_seconds > 0).then_some(ttl_seconds),
            &files,
        )
        .await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        self.links().record(
            LinkRecord {
                link_id: created.link_id.clone(),
                created_at_unix: now,
                expires_at_unix: created.expires_at_unix,
                file_count: u32::try_from(files.len()).unwrap_or(u32::MAX),
                transfer_id: None,
                send_failure: None,
            },
            now,
        );
        Ok(created)
    }

    /// The links this device created, newest first, each with its status. A link the service
    /// no longer knows is dropped from the list.
    pub(crate) async fn list_links(&self) -> Result<Vec<ListedLink>, SendFailure> {
        let mut listed = Vec::new();
        for record in self.links().list() {
            match self.link_status(&record.link_id).await {
                Ok(view) => listed.push(ListedLink {
                    link_id: record.link_id,
                    created_at_unix: record.created_at_unix,
                    expires_at_unix: record.expires_at_unix,
                    file_count: record.file_count,
                    view,
                }),
                Err(SendFailure { code: Some(ApplicationErrorCode::SendLinkInvalid), .. }) => {
                    self.links().forget(&record.link_id);
                }
                Err(other) => return Err(other),
            }
        }
        Ok(listed)
    }

    /// What a code's link carries and who sends it, without redeeming it.
    pub(crate) async fn preview_link(
        &self,
        code: &str,
    ) -> Result<crate::coordination_client::SendLinkPreview, SendFailure> {
        let config = self.coordination()?;
        Ok(crate::coordination_client::preview_send_link(&config.addr, &config.auth, code).await?)
    }

    /// Redeems a code with `device_id` (empty = this device) and returns the link id and the folder
    /// the files will be received into.
    ///
    /// Redeeming is the person's one consent: when the receiving device is this one, the offer that
    /// arrives under the link is received by the engine into `destination_dir` (empty = a folder of
    /// the engine's own choosing) without another step. For another device of the account, that
    /// device's engine receives it only if it was told the same; this one has nothing to receive.
    pub(crate) async fn redeem_link(
        &self,
        code: &str,
        device_id: &str,
        destination_dir: &str,
    ) -> Result<(String, String), SendFailure> {
        if !destination_dir.is_empty() {
            require_absolute("destination directory", destination_dir)?;
        }
        let config = self.coordination()?;
        let this_device = device_id.is_empty() || device_id == self.state.device_id;
        let device_id =
            if device_id.is_empty() { self.state.device_id.as_str() } else { device_id };
        // The service answers every refusal of a code alike, so a refusal here is `Invalid`.
        let link_id = crate::coordination_client::redeem_send_link(
            &config.addr,
            &config.auth,
            code,
            device_id,
        )
        .await?;
        if !this_device {
            return Ok((link_id, String::new()));
        }
        let destination_dir = if destination_dir.is_empty() {
            self.state
                .config_dir()
                .join("send")
                .join("inbox")
                .join(&link_id)
                .to_string_lossy()
                .into_owned()
        } else {
            destination_dir.to_owned()
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        self.state.redeemed_send_links.record(
            RedeemRecord {
                link_id: link_id.clone(),
                destination_dir: destination_dir.clone(),
                redeemed_at_unix: now,
            },
            now,
        );
        Ok((link_id, destination_dir))
    }

    /// Cancels the link at the service and stops the transfer this device started under it, if
    /// one is going: the recipient's pull is refused as canceled and the sender's list agrees.
    pub(crate) async fn cancel_link(&self, link_id: &str) -> Result<(), SendFailure> {
        let config = self.coordination()?;
        crate::coordination_client::cancel_send_link(&config.addr, &config.auth, link_id).await?;
        if let (Some(transfer_id), Ok(service)) =
            (self.links().transfer_of(link_id), self.service())
        {
            if let Err(error) = service.cancel_transfer(&transfer_id) {
                tracing::warn!(link_id, transfer_id, %error, "Send link: could not stop the transfer under a canceled link");
            }
        }
        Ok(())
    }

    /// The sender's view of one link: the service's state, and for a link whose send started on
    /// this daemon, how that transfer is going.
    pub(crate) async fn link_status(&self, link_id: &str) -> Result<LinkStatusView, SendFailure> {
        let config = self.coordination()?;
        let status =
            crate::coordination_client::send_link_status(&config.addr, &config.auth, link_id)
                .await?;
        if status.state == "granted" && !self.is_sending_here(link_id) {
            if let Ok(service) = self.service() {
                reconcile_link(self.links(), &service, link_id);
            }
        }
        let transfer_id = self.links().transfer_of(link_id);
        let transfer = match &transfer_id {
            Some(id) => self
                .service()
                .ok()
                .and_then(|service| service.list_sent().ok())
                .and_then(|sent| sent.into_iter().find(|entry| &entry.transfer_id == id)),
            None => None,
        };
        let send_failure = self.links().send_failure_of(link_id);
        let failure = transfer
            .as_ref()
            .and_then(|t| t.failure.clone())
            .or_else(|| send_failure.clone())
            .unwrap_or_default();
        Ok(LinkStatusView {
            failure,
            state: link_state(
                &status.state,
                transfer.as_ref().map(|t| (t.status, t.failure.is_some())),
                send_failure.is_some(),
            ),
            receiver_device_name: status.receiver_device_name.unwrap_or_default(),
            transfer_id: transfer_id.unwrap_or_default(),
        })
    }

    fn is_sending_here(&self, link_id: &str) -> bool {
        self.sending_here
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(link_id)
    }

    /// Waits until the recipient has redeemed the link, so the grant the
    /// offer asks for next has a device to be bound to.
    async fn wait_for_redeem(&self, link_id: &str) -> Result<(), SendFailure> {
        let config = self.coordination()?;
        let deadline = tokio::time::Instant::now() + LINK_REDEEM_WAIT;
        loop {
            let status =
                crate::coordination_client::send_link_status(&config.addr, &config.auth, link_id)
                    .await?;
            match link_readiness(&status.state) {
                LinkReadiness::Ready => return Ok(()),
                LinkReadiness::Refused(code, why) => return Err(SendFailure::typed(code, why)),
                LinkReadiness::Waiting => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("the recipient has not redeemed the send link yet; run send again \
                            once they have"
                    .to_string()
                    .into());
            }
            tokio::time::sleep(LINK_POLL_INTERVAL).await;
        }
    }

    pub(crate) async fn receive(
        &self,
        transfer_id: &str,
        destination_dir: Option<&str>,
    ) -> Result<ReceiveOutcome, SendFailure> {
        if let Some(dir) = destination_dir {
            require_absolute("destination directory", dir)?;
        }
        let service = self.service()?;
        let destination_dir = destination_dir.map(std::path::Path::new);
        Ok(service.receive_transfer(transfer_id, destination_dir).await?)
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
