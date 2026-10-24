//! Local IPC between the daemon and OS shell extensions (Windows Explorer
//! icon overlay/context-menu handler, macOS Finder Sync extension).
//! Framed as length-prefixed protobuf
//! (`yadorilink_ipc_proto::framing`), not gRPC, since Explorer/Finder call
//! synchronously and frequently — full HTTP/2 setup overhead risks
//! visible UI lag.
//!
//! Unlike the daemon control socket (one request/response per connection),
//! this is a persistent duplex connection: the daemon proactively pushes
//! `StatusPush` updates while continuing to answer the client's
//! `StatusQuery`/`ContextActionRequest` messages on the same connection.
//!
//! Transport: Unix domain socket on macOS/Linux (the "over
//! XPC" sandbox bridging for a real macOS Finder Sync extension is
//! properly section 10's job; what's implemented
//! here is the daemon-side socket those XPC-relayed bytes would ultimately
//! reach). Windows named pipe is implemented behind
//! `#[cfg(windows)]` and has not been compiled or run on this
//! (non-Windows) development machine; verify on real Windows hardware
//! before relying on it.
//!
//! The message handling here (`handle_connection` and the provider handlers) is the engine's
//! provider surface and is compiled in every build, including the embedded host, which serves
//! it over in-memory channels. Only the socket and pipe transports and the reference client
//! belong to the desktop process model (`process-model` feature).

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ContextAction, ContextActionResponse, DomainEvidence, FolderFileEntry, HydrateResponse,
    HydrationPolicy, ListFolderFilesResponse, ListLinkedRootsResponse, ListProviderFoldersResponse,
    LocalState as ShellLocalState, LocalTransition as ShellLocalTransition, LocalWriteKind,
    LocalWriteResponse, ProviderFolder, ShellIpcMessage, StatusResponse,
};

use crate::shell_context::ShellContext;
use crate::shell_status::{resolve_materialization_state, resolve_status_detail};

// Only the transports below accept connections.
#[cfg(feature = "process-model")]
// apple-cfg: ios-explicit only the AF_UNIX transport, which iOS does not compile, uses it
#[cfg(not(target_os = "ios"))]
const MAX_SHELL_IPC_CONNECTIONS: usize = 64;

fn shell_entry_kind(
    kind: yadorilink_replica_domain::file::RecordKind,
) -> yadorilink_ipc_proto::shellipc::EntryKind {
    use yadorilink_ipc_proto::shellipc::EntryKind;
    use yadorilink_replica_domain::file::RecordKind;
    match kind {
        RecordKind::File => EntryKind::File,
        RecordKind::Directory => EntryKind::Directory,
        RecordKind::Symlink => EntryKind::Symlink,
    }
}

/// The local state a shell is told for a path: whether an object stands and,
/// independently, whether the content of the CURRENT version is usable. A
/// regular file's object is current only where a usable proof names the
/// version the row holds now (`exact`); an older object stands without current
/// content, which makes a platform provider ask for the contents while still
/// knowing the object exists. `None` is unknown (no row).
pub(crate) fn to_shell_local_state(
    state: Option<yadorilink_replica_domain::session_state::MaterializationState>,
    exact: bool,
) -> Option<ShellLocalState> {
    use crate::application::ports::LocalTransition;
    crate::shell_status::local_presence(state, exact).map(|presence| ShellLocalState {
        local_object_present: presence.object_present,
        current_content_present: presence.current_content_present,
        transition: match presence.transition {
            LocalTransition::None => ShellLocalTransition::None,
            LocalTransition::Hydrating => ShellLocalTransition::Hydrating,
            LocalTransition::Evicting => ShellLocalTransition::Evicting,
        } as i32,
    })
}

/// The provider roots the host should register as domains: every declared root whose
/// link is live, with its hydration policy and whether its namespace is queryable
/// (`registration_ready`). A read error is an error, never an empty list.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn provider_folders(
    context: &ShellContext,
) -> Result<Vec<ProviderFolder>, crate::sync_error::SyncError> {
    use yadorilink_replica_domain::session_state::MaterializationPolicy;
    let links = context.replica_coordinator.link_repository().list_links()?;
    let mut folders = Vec::new();
    for root in context.replica_coordinator.provider_repository().list_declared_roots()? {
        // An orphaned link's authorization is gone: `list_declared_roots` never returns
        // its root, and the policy comes from the live link.
        let Some(link) = links.iter().find(|link| link.group_id == root.group_id && !link.orphaned)
        else {
            continue;
        };
        let root_id = hex::decode(&root.root_id).map_err(|_| {
            crate::sync_error::SyncError::CorruptState("a provider root id is not hex".into())
        })?;
        folders.push(ProviderFolder {
            root_id,
            group_id: root.group_id.clone().into_bytes(),
            display_name: root.display_name.clone(),
            hydration_policy: match link.materialization_policy {
                MaterializationPolicy::Eager => HydrationPolicy::Eager,
                MaterializationPolicy::OnDemand => HydrationPolicy::OnDemand,
            } as i32,
            registration_ready: root.namespace_ready,
            latest_evidence_seq: root.latest_evidence_seq,
            read_only: provider_enumerate::group_is_read_only(context, &root.group_id),
        });
    }
    Ok(folders)
}

/// The domains the daemon wants removed: the roots with a requested removal intent.
fn provider_removals(
    context: &ShellContext,
) -> Result<Vec<yadorilink_ipc_proto::shellipc::ProviderRemoval>, crate::sync_error::SyncError> {
    let mut removals = Vec::new();
    for removal in context.replica_coordinator.provider_repository().removals()? {
        if !removal.requested {
            continue;
        }
        // A requested removal whose id is not hex is corrupt state, not a removal to skip.
        let root_id = hex::decode(&removal.root_id).map_err(|_| {
            crate::sync_error::SyncError::CorruptState("a provider removal id is not hex".into())
        })?;
        removals.push(yadorilink_ipc_proto::shellipc::ProviderRemoval {
            root_id,
            display_name: removal.display_name,
        });
    }
    Ok(removals)
}

/// Persists one readiness evidence message for the root it names. An unknown root is
/// logged and ignored; a write failure is logged (the evidence is simply not recorded,
/// which can only keep a root not ready).
/// Whether the daemon knows the root. A lookup that fails is logged and answers "no": the callers
/// ignore what the host reported about a root rather than act on a root they could not confirm.
fn root_is_known(repo: &yadorilink_sync_sqlite::provider::ProviderRepository, root: &str) -> bool {
    match repo.group_of_root(root) {
        Ok(group) => group.is_some(),
        Err(error) => {
            tracing::warn!(root_id = %root, %error, "could not look up the provider root; ignored");
            false
        }
    }
}

fn record_provider_evidence(
    context: &ShellContext,
    root_id: &[u8],
    what: &str,
    record: impl FnOnce(
        &yadorilink_sync_sqlite::provider::ProviderRepository,
        &str,
    ) -> Result<bool, yadorilink_sync_sqlite::SyncSqliteError>,
) {
    let root = hex::encode(root_id);
    match record(context.replica_coordinator.provider_repository(), &root) {
        Ok(true) => {}
        Ok(false) => tracing::warn!(root_id = %root, "{what} for an unknown provider root ignored"),
        Err(error) => tracing::warn!(root_id = %root, %error, "could not record {what}"),
    }
}

/// Applies a domain removal: a requested removal is finished (state deleted, the preserved location
/// recorded); a domain the user removed replaces the root. Then the host is prompted to list again,
/// so it sees the replacement root or the finished removal.
fn apply_domain_removal(context: &ShellContext, root_id: &[u8], preserved_location: &str) {
    let repo = context.replica_coordinator.provider_repository();
    let group = repo.group_of_root(&hex::encode(root_id)).ok().flatten();
    record_provider_evidence(context, root_id, "domain removal", |repo, root| {
        repo.domain_removed(root, preserved_location)
    });
    match group.and_then(|group| repo.declaration_for_group(&group).ok()) {
        Some(yadorilink_sync_sqlite::provider::ProviderDeclaration::Provider(root)) => {
            context.provider_host.push_folders_changed(&root.root_id);
        }
        _ => context.provider_host.push_folders_changed(""),
    }
}

pub async fn handle_connection<R, W>(
    mut read_half: R,
    mut write_half: W,
    context: Arc<ShellContext>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut push_rx = context.telemetry.subscribe_status();
    // Messages the daemon pushes to THIS connection (provider requests for the host app).
    let (host_tx, mut host_rx) = tokio::sync::mpsc::unbounded_channel::<ShellIpcMessage>();
    // Materializations this connection started; they end with it.
    let materializations = MaterializeRequests::default();
    let handshakes = Arc::new(provider_apply::Handshakes::default());
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel::<Delivery>();
    // When this connection ends while it is the attached host, there is no host and no evidence.
    let _host_gone = HostDisconnect { context: &context, tx: host_tx.clone() };
    loop {
        tokio::select! {
            biased;

            incoming = read_message::<ShellIpcMessage>(&mut read_half) => {
                match incoming? {
                    None => return Ok(()), // client disconnected
                    Some(msg) => {
                        if let Some(Payload::ExtensionHandshake(handshake)) = &msg.payload {
                            handshakes.note(&handshake.root_id);
                        }
                        if materialize_message(&context, &materializations, &reply_tx, &msg)
                            || provider_apply::apply_message(
                                &context, &materializations, &handshakes, &reply_tx, &msg,
                            )
                            || provider_channel_message(&context, &host_tx, &msg).await
                        {
                            continue;
                        }
                        if let Some(response) =
                            provider_enumerate::answer(&context, &handshakes, &msg).await
                        {
                            write_message(&mut write_half, &response).await?;
                            continue;
                        }
                        if let Some(response) = handle_message(&context, msg).await {
                            write_message(&mut write_half, &response).await?;
                        }
                    }
                }
            }

            delivery = reply_rx.recv() => {
                if let Some(delivery) = delivery {
                    let written = write_message(&mut write_half, &delivery.message).await;
                    // The sender learns whether the framed write really completed.
                    if let Some(done) = delivery.written {
                        let _ = done.send(written.is_ok());
                    }
                    written?;
                }
            }

            pushed = host_rx.recv() => {
                if let Some(message) = pushed {
                    write_message(&mut write_half, &message).await?;
                }
            }

            push = push_rx.recv() => {
                if let Ok(push) = push {
                    write_message(&mut write_half, &ShellIpcMessage { payload: Some(Payload::StatusPush(push)) }).await?;
                }
            }
        }
    }
}

/// Detaches the host and forgets what it reported when the connection that was the host ends.
struct HostDisconnect<'a> {
    context: &'a ShellContext,
    tx: tokio::sync::mpsc::UnboundedSender<ShellIpcMessage>,
}

impl Drop for HostDisconnect<'_> {
    fn drop(&mut self) {
        if self.context.provider_host.detach(&self.tx) {
            self.context.membership.clear();
        }
    }
}

/// The provider channel's connection-level messages: the host's acknowledgements complete the
/// publication step that is waiting for them, and the app's domain state attaches this
/// connection as the host (replaying every pending publication, and detecting a rolled-back
/// database). Returns true when the message was consumed here.
async fn provider_channel_message(
    context: &ShellContext,
    host_tx: &tokio::sync::mpsc::UnboundedSender<ShellIpcMessage>,
    msg: &ShellIpcMessage,
) -> bool {
    match &msg.payload {
        // Only the attached host's acknowledgements complete a publication step: any other
        // connection on the user-owned socket could otherwise declare an eviction done.
        Some(Payload::ProviderEvictDone(done)) => {
            if context.provider_host.is_attached(host_tx) {
                context.provider_host.complete_evict(done);
            }
            true
        }
        Some(Payload::ProviderSignalDone(done)) => {
            if context.provider_host.is_attached(host_tx) {
                context.provider_host.complete_signal(done);
            }
            true
        }
        Some(Payload::ProviderMaterializedReport(report)) => {
            // A report for a root the daemon does not know (a stale root_id after a rebootstrap)
            // is ignored: no state, no answer.
            let root = hex::encode(&report.root_id);
            let repo = context.replica_coordinator.provider_repository();
            // Only the attached host's reports are evidence: any other connection on the
            // user-owned socket could claim anything. An unknown root is ignored too.
            let known = root_is_known(repo, &root);
            if known && context.provider_host.is_attached(host_tx) {
                let latest_issued = repo.latest_evidence_seq(&root).unwrap_or_else(|error| {
                    tracing::warn!(root_id = %root, %error, "could not read the evidence sequence; report ignored");
                    None
                });
                if let Some(latest_issued) = latest_issued {
                    let (ack, departed) =
                        context.membership.apply_reporting_departures(report, latest_issued);
                    context.provider_host.send_to_host(Payload::ProviderReportAck(ack));
                    // The OS dropped its copy of these without being asked: free the daemon's
                    // half, if a full replica takes custody of the version.
                    if !departed.is_empty() {
                        context.reclaim_queue.schedule(&root, departed);
                    }
                }
            }
            true
        }
        // The Eager driver's query: what should the host ask the OS to download next.
        Some(Payload::NextProviderDownloadsRequest(request)) => {
            if context.provider_host.is_attached(host_tx) {
                let handoff_root = context.handoff.get();
                let inputs = crate::provider_eager::EagerInputs {
                    coordinator: &context.replica_coordinator,
                    membership: &context.membership,
                    staging_dir: handoff_root.as_ref().map(|h| h.staging_dir()),
                    host_attached: true,
                };
                let response = context.eager.next_downloads(&inputs, request);
                let _ = host_tx.send(ShellIpcMessage {
                    payload: Some(Payload::NextProviderDownloadsResponse(response)),
                });
            }
            true
        }
        // The OS refused a download request before any fetch: hold the item back for a while.
        Some(Payload::ProviderDownloadRejected(rejected)) => {
            if context.provider_host.is_attached(host_tx) {
                if let Ok(item) = ItemIdBytes::try_from(rejected.item_id.as_slice()) {
                    context.eager.record_rejection(
                        &context.replica_coordinator,
                        &hex::encode(&rejected.root_id),
                        &item,
                    );
                }
            }
            true
        }
        Some(Payload::ProviderDomainState(state)) => {
            let root = hex::encode(&state.root_id);
            let repo = context.replica_coordinator.provider_repository();
            // An unknown or old root_id is ignored entirely: it neither attaches a host nor
            // counts as evidence. The one exception is the report of an ORPHAN domain (registered
            // for a root this database does not know): it is only recorded, for `status`, and
            // changes nothing, so the domain stays available for recovery.
            // A lookup that FAILS is not an unknown root: neither the orphan note nor an attach may
            // be decided on a guess. The host reports again; nothing is recorded now.
            let known = match repo.group_of_root(&root) {
                Ok(group) => group.is_some(),
                Err(error) => {
                    tracing::warn!(root_id = %root, %error, "could not look up the provider root; domain state ignored");
                    return true;
                }
            };
            // The rollback check compares the host's acknowledged revision with ours. It must not
            // be skipped by a failed read, so the revision is read before the host is attached.
            let ours = if state.evidence() == DomainEvidence::Removed {
                None
            } else {
                match repo.namespace_revision(&root) {
                    Ok(ours) => ours,
                    Err(error) => {
                        tracing::warn!(root_id = %root, %error, "could not read the namespace revision; domain state ignored");
                        return true;
                    }
                }
            };
            if !known {
                if state.evidence() == DomainEvidence::Orphan
                    && context.provider_host.is_attached(host_tx)
                {
                    context.provider_host.note_orphan(&root);
                }
                return true;
            }
            // Rollback evidence and the replay of pending work are accepted only from the
            // attached host connection; a second connection cannot take the host over.
            let was_attached = context.provider_host.is_attached(host_tx);
            if !context.provider_host.try_attach(host_tx.clone()) {
                return false;
            }
            if !was_attached {
                // A different host took over: what the previous one reported says nothing now.
                context.membership.clear();
            }
            // The report of a removal is handled with the evidence below; it is neither a rollback
            // check nor a replay.
            if state.evidence() == DomainEvidence::Removed {
                return false;
            }
            // The host remembers the highest revision it acknowledged; a daemon revision below it
            // means this database was restored: the OS holds state the daemon no longer knows.
            // The root is replaced (a new root_id); the host sees the old one vanish from the
            // provider-folder snapshot and removes that domain.
            if ours.is_some_and(|ours| state.last_acked_namespace_revision > ours) {
                context
                    .publication
                    .rebootstrap_root(&root, "the daemon's namespace revision is behind the host's")
                    .await;
                return true;
            }
            // A removal is the engine's verdict, never the host's: the host only reports what it
            // read (and reports absence only for a domain it observed registered, so a registration
            // report lost to a disconnect cannot strand the root). Anything but an absent reading
            // breaks the run, and the verdict needs consecutive readings from the attached host.
            // Otherwise the domain and the root are left exactly as they are.
            if state.evidence() == DomainEvidence::Absent {
                if context.provider_host.note_absent(&root) {
                    apply_domain_removal(context, &state.root_id, "");
                }
                return true;
            }
            context.provider_host.clear_absent(&root);
            if state.evidence() == DomainEvidence::Registered {
                // Reconnect replay: every pending item runs its evict and signal again.
                context.publication.kick(&root);
            }
            false
        }
        _ => false,
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::excessive_nesting,
    reason = "exhaustive dispatch over every shell IPC `Payload` variant; keeping \
              the single `match` in one place is what makes the request/response \
              pairing for each variant reviewable and keeps the compiler's \
              exhaustiveness check on the protocol enum. The deep arm is the \
              per-file placeholder-generation fold, whose nesting is the \
              option/result chain (link -> materialization state -> Windows \
              placeholder generation) evaluated inline per listing entry."
)]
async fn handle_message(context: &ShellContext, msg: ShellIpcMessage) -> Option<ShellIpcMessage> {
    match msg.payload {
        Some(Payload::StatusQuery(q)) => {
            let path = q.path;
            let status = resolve_status_detail(&context.replica_coordinator, &path);
            let materialization_state =
                resolve_materialization_state(&context.replica_coordinator, &path);
            let exact = crate::shell_status::resolve_content_is_current(
                &context.replica_coordinator,
                &path,
            );
            let pause =
                crate::shell_status::resolve_item_pause(&context.replica_coordinator, &path);
            let local_state = to_shell_local_state(materialization_state, exact);
            let free_up_space_offered =
                context.queries.linked_path.resolve(&path).is_some_and(|(group_id, rel_path)| {
                    let materialization = &context.application.materialization;
                    crate::file_actions::free_up_space_offered(&crate::file_actions::ItemFacts {
                        known: local_state.is_some(),
                        current_content_present: local_state
                            .as_ref()
                            .is_some_and(|s| s.current_content_present),
                        in_transition: local_state
                            .as_ref()
                            .is_some_and(|s| s.transition() != ShellLocalTransition::None),
                        is_file: std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()),
                        provider_folder: false,
                        reclaim_gate_open: materialization.evict_supported(&group_id),
                        // A policy that cannot be read offers nothing.
                        retention: materialization.retention(&group_id, &rel_path).ok().map(|r| {
                            crate::file_actions::Retention {
                                pinned: r.pinned,
                                explicit: r.explicit,
                            }
                        }),
                    })
                });
            let badge = crate::shell_status::shell_badge(status.state, local_state.as_ref());
            let actions_available = crate::shell_status::actions_available(status.state);
            Some(ShellIpcMessage {
                payload: Some(Payload::StatusResponse(StatusResponse {
                    badge: badge as i32,
                    actions_available,
                    item_paused: pause.paused,
                    paused_by_ancestor: pause.by_ancestor,
                    free_up_space_offered,
                    path,
                    state: status.state as i32,
                    local_state,
                    status_detail: status.detail.unwrap_or_default(),
                })),
            })
        }
        Some(Payload::HydrateRequest(req)) => {
            let response = match context.queries.linked_path.resolve(&req.path) {
                Some((group_id, rel_path)) => {
                    match context.application.materialization.hydrate(&group_id, &rel_path).await {
                        Ok(_) => HydrateResponse { ok: true, error: String::new() },
                        Err(e) => HydrateResponse { ok: false, error: e.to_string() },
                    }
                }
                None => HydrateResponse {
                    ok: false,
                    error: "path is not under any linked folder".into(),
                },
            };
            Some(ShellIpcMessage { payload: Some(Payload::HydrateResponse(response)) })
        }
        Some(Payload::ContextActionRequest(req)) => {
            let response = match ContextAction::try_from(req.action) {
                Ok(ContextAction::ViewStatus) => {
                    ContextActionResponse { ok: true, error: String::new() }
                }
                // shell-integration spec "Pause sync for a single item":
                // the same application pause/resume service the control
                // socket's link-level pause goes through, scoped to one
                // file or folder of the link.
                Ok(ContextAction::PauseItem) => {
                    match context.queries.linked_path.resolve(&req.path) {
                        Some((group_id, rel_path)) => {
                            match context.application.pause_resume.pause_item(&group_id, &rel_path)
                            {
                                Ok(()) => ContextActionResponse { ok: true, error: String::new() },
                                Err(e) => ContextActionResponse { ok: false, error: e.to_string() },
                            }
                        }
                        None => ContextActionResponse {
                            ok: false,
                            error: "path is not under any linked folder".into(),
                        },
                    }
                }
                Ok(ContextAction::ResumeItem) => {
                    match context.queries.linked_path.resolve(&req.path) {
                        Some((group_id, rel_path)) => {
                            match context
                                .application
                                .pause_resume
                                .resume_item(&group_id, &rel_path)
                                .await
                            {
                                Ok(()) => ContextActionResponse { ok: true, error: String::new() },
                                Err(e) => ContextActionResponse { ok: false, error: e.to_string() },
                            }
                        }
                        None => ContextActionResponse {
                            ok: false,
                            error: "path is not under any linked folder".into(),
                        },
                    }
                }
                // The same daemon operation `yadorilink evict` (control_socket)
                // drives, exposed via the shell extension's context menu.
                Ok(ContextAction::EvictItem) => {
                    match context.queries.linked_path.resolve(&req.path) {
                        Some((group_id, rel_path)) => {
                            match context.application.materialization.evict(&group_id, &rel_path) {
                                // `Ok` alone does not mean the
                                // file was actually freed -- `evict_file`
                                // can return `Ok` while leaving it fully
                                // materialized (busy, not yet
                                // `Present`, or changed on disk right
                                // before the commit). `ok: true` here must
                                // mean "the action was performed," not
                                // merely "the request didn't error" -- see
                                // `EvictOutcome::dehydrated`'s own doc
                                // comment for the exact prior gap this
                                // closes (the shell extension used to
                                // report every non-erroring request as a
                                // successful eviction).
                                Ok(outcome) if outcome.dehydrated => {
                                    ContextActionResponse { ok: true, error: String::new() }
                                }
                                Ok(_) => ContextActionResponse {
                                    ok: false,
                                    error: "not evicted: the file may be busy, not fully synced, \
                                            or was just modified"
                                        .into(),
                                },
                                Err(e) => ContextActionResponse { ok: false, error: e.to_string() },
                            }
                        }
                        None => ContextActionResponse {
                            ok: false,
                            error: "path is not under any linked folder".into(),
                        },
                    }
                }
                _ => ContextActionResponse { ok: false, error: "unknown context action".into() },
            };
            Some(ShellIpcMessage { payload: Some(Payload::ContextActionResponse(response)) })
        }
        // A gap (see shellipc.proto's doc comment
        // on these two messages): lets a platform virtual-filesystem
        // provider (Windows cfapi) discover which linked folders are
        // OnDemand and enumerate their files to register sync roots and
        // create placeholders.
        //
        // `list_links()`'s `Err` must NOT collapse into an empty `Vec` here
        // (a prior `unwrap_or_default()` did exactly that) -- a DB/read
        // error is "cannot currently confirm the desired state," not "the
        // desired state is confirmed empty." A macOS caller
        // (`DomainRegistration.swift`) reconciles OS-level domain
        // registrations against this response, including REMOVING
        // registrations absent from it; silently reporting an empty
        // snapshot on a transient read error would tell that caller to
        // remove every registered domain. `snapshot_available` makes the
        // distinction explicit on the wire instead of relying on the
        // client inferring it from a transport-level failure.
        Some(Payload::ListProviderFoldersRequest(request)) => {
            // The host app tells the daemon where its app group container is (once; additive).
            if !request.app_group_container.is_empty() {
                context.handoff.adopt(&request.app_group_container);
            }
            // The removals are part of the snapshot: an unreadable removal list is not "none".
            let snapshot = provider_folders(context)
                .and_then(|folders| Ok((folders, provider_removals(context)?)));
            let response = match snapshot {
                Ok((folders, removals)) => {
                    ListProviderFoldersResponse { folders, snapshot_available: true, removals }
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "failed to list provider roots for ListProviderFoldersRequest; reporting \
                         snapshot_available=false rather than an empty snapshot"
                    );
                    ListProviderFoldersResponse {
                        folders: Vec::new(),
                        snapshot_available: false,
                        removals: Vec::new(),
                    }
                }
            };
            Some(ShellIpcMessage { payload: Some(Payload::ListProviderFoldersResponse(response)) })
        }
        // The Finder extension's `directoryURLs`: every live folder link. A link-table read
        // error is `snapshot_available: false`, never an empty snapshot, so the extension keeps
        // the set it last confirmed instead of dropping every root.
        Some(Payload::ListLinkedRootsRequest(_)) => {
            let response = match context.replica_coordinator.link_repository().list_links() {
                Ok(links) => ListLinkedRootsResponse {
                    local_paths: links
                        .iter()
                        .filter(|link| !link.orphaned)
                        .filter_map(|link| link.location.folder_path().map(str::to_owned))
                        .collect(),
                    snapshot_available: true,
                },
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "ListLinkedRootsRequest could not read the links; reporting \
                         snapshot_available=false rather than an empty snapshot"
                    );
                    ListLinkedRootsResponse { local_paths: Vec::new(), snapshot_available: false }
                }
            };
            Some(ShellIpcMessage { payload: Some(Payload::ListLinkedRootsResponse(response)) })
        }
        // Readiness evidence from the host app and the extension. No response: the
        // evidence is persisted and the next listing/status reflects it.
        Some(Payload::ProviderDomainState(state)) => {
            // Only OBSERVED evidence changes the root: a registration, or the confirmed removal of a
            // domain that was registered. "Unknown" (an unreadable list) and "not registered yet"
            // are no-ops: the root is never rebootstrapped on a guess.
            let evidence = state.evidence();
            match evidence {
                DomainEvidence::Registered => {
                    record_provider_evidence(
                        context,
                        &state.root_id,
                        "domain state",
                        |repo, root| repo.set_domain_registered(root, true),
                    );
                }
                // The removal of a domain: a requested removal is finished (state deleted, the
                // preserved location recorded); a domain the user removed replaces the root.
                DomainEvidence::Removed => {
                    apply_domain_removal(context, &state.root_id, &state.preserved_location)
                }
                _ => {}
            }
            None
        }
        Some(Payload::ExtensionHandshake(handshake)) => {
            record_provider_evidence(
                context,
                &handshake.root_id,
                "extension handshake",
                |repo, root| repo.record_extension_handshake(root, now_unix_nanos()),
            );
            None
        }
        Some(Payload::ProviderError(error)) => {
            record_provider_evidence(context, &error.root_id, "provider error", |repo, root| {
                repo.record_provider_error(root, &error.description)
            });
            None
        }
        // Every read below fails the whole listing closed
        // (`snapshot_available: false`, no entries) rather than collapsing
        // into `[]` -- the macOS File Provider treats a successful
        // enumeration as authoritative, so an empty listing that merely
        // could not be read would tell it the folder has zero files. Same
        // contract as `ListOnDemandFoldersRequest` above.
        Some(Payload::ListFolderFilesRequest(req)) => {
            let listing: Result<Vec<FolderFileEntry>, String> = 'listing: {
                let links = match context.replica_coordinator.link_repository().list_links() {
                    Ok(links) => links,
                    Err(e) => break 'listing Err(format!("failed to list links: {e}")),
                };
                // An orphaned link is no longer a live sync target -- treat
                // it the same as "no such link" here, so its folder is
                // never enumerated for placeholder registration either.
                // Neither has a listing to confirm.
                let Some(l) = links.into_iter().find(|l| l.key() == req.local_path && !l.orphaned)
                else {
                    break 'listing Err("local_path is not a currently linked, live folder".into());
                };
                let files = match context
                    .replica_coordinator
                    .file_index_repository()
                    .list_files_with_kind(&l.group_id)
                {
                    Ok(files) => files,
                    Err(e) => break 'listing Err(format!("failed to list files: {e}")),
                };
                // Only needed to mint/persist a Windows CfAPI
                // generation for entries reported as `Remote`
                // below -- looked up once per link, not once per
                // file. `None` (link not currently running) means
                // every such entry's `placeholder_generation` stays
                // unset this poll; `cfapi_host.rs`'s `sync_placeholders`
                // already treats an unset generation as "not yet
                // ready to create, retry next poll", so this degrades
                // to a delayed placeholder creation, never a wrong one.
                let runtime = context.links.runtime(&req.local_path);
                let mut entries = Vec::new();
                for (f, record_kind) in files.into_iter().filter(|(f, _)| !f.deleted) {
                    let local_state = match context
                        .replica_coordinator
                        .materialization_state_repository()
                        .get_materialization_state(&l.group_id, &f.path)
                    {
                        Ok(s) => to_shell_local_state(
                            s,
                            record_kind != yadorilink_replica_domain::file::RecordKind::File
                                || context
                                    .replica_coordinator
                                    .local_copy_names_current_version(&l.group_id, &f.path)
                                    .unwrap_or(false),
                        ),
                        Err(e) => {
                            break 'listing Err(format!(
                                "failed to read the materialization state of {}: {e}",
                                f.path
                            ));
                        }
                    };
                    let needs_placeholder = local_state.as_ref().is_some_and(|s| {
                        !s.current_content_present
                            && s.transition == ShellLocalTransition::None as i32
                    });
                    let placeholder_generation = if cfg!(windows) && needs_placeholder {
                        runtime.as_ref().and_then(|runtime| {
                            match runtime
                                .ensure_windows_placeholder_generation(&l.group_id, &f.path)
                            {
                                Ok(generation) => Some(generation),
                                Err(error) => {
                                    tracing::warn!(
                                        group_id = %l.group_id,
                                        path = %f.path,
                                        error = %error,
                                        "failed to mint/persist a Windows CfAPI \
                                         placeholder generation; cfapi-host will retry \
                                         creating this placeholder next poll"
                                    );
                                    None
                                }
                            }
                        })
                    } else {
                        None
                    };
                    entries.push(FolderFileEntry {
                        relative_path: f.path,
                        size: f.size,
                        mtime_unix_nanos: f.mtime_unix_nanos,
                        local_state,
                        placeholder_generation,
                        kind: shell_entry_kind(record_kind) as i32,
                        item_id: Vec::new(),
                    });
                }
                Ok(entries)
            };
            let response = match listing {
                Ok(entries) => ListFolderFilesResponse { entries, snapshot_available: true },
                Err(error) => {
                    tracing::warn!(
                        local_path = %req.local_path,
                        %error,
                        "ListFolderFilesRequest could not confirm the folder's listing; \
                         reporting snapshot_available=false rather than an empty listing"
                    );
                    ListFolderFilesResponse { entries: Vec::new(), snapshot_available: false }
                }
            };
            Some(ShellIpcMessage { payload: Some(Payload::ListFolderFilesResponse(response)) })
        }
        // The OS virtual-filesystem's own create/modify/delete
        // callback (macOS `NSFileProviderReplicatedExtension`'s
        // `createItem`/`modifyItem`/`deleteItem`) notifies the daemon that a
        // local write already landed on disk. Routes through the same
        // `LocalChangeProcessor::process_event` path a live filesystem
        // watcher's own event would take -- see `shellipc.proto`'s own doc
        // comment on `LocalWriteRequest` and
        // `LinkFlushHandle::capture_local_write`'s own doc for why no
        // File-Provider-specific sync logic exists here.
        Some(Payload::LocalWriteRequest(req)) => {
            let response = 'resolve: {
                let kind = match LocalWriteKind::try_from(req.kind) {
                    Ok(LocalWriteKind::CreatedOrModified) => {
                        crate::link_runtime::operations::capture_local_change::LocalWrite::CreatedOrModified
                    }
                    // The provider's `deleteItem` is the user deleting the
                    // logical item, not an observation of a missing file.
                    Ok(LocalWriteKind::Deleted) => {
                        crate::link_runtime::operations::capture_local_change::LocalWrite::Deleted
                    }
                    Ok(LocalWriteKind::Unspecified) | Err(_) => {
                        break 'resolve LocalWriteResponse {
                            ok: false,
                            error: "unknown or unspecified write kind".into(),
                        };
                    }
                };
                // An orphaned link's coordination-side authorization is
                // permanently gone -- same exclusion `ListFolderFilesRequest`
                // and `ListOnDemandFoldersRequest` above already apply, for
                // the same reason: this must never accept a File-Provider
                // write for a link that's no longer a live sync target.
                // A read failure is not evidence that the folder is
                // unlinked, so it is reported as what it is.
                let links = match context.replica_coordinator.link_repository().list_links() {
                    Ok(links) => links,
                    Err(e) => {
                        break 'resolve LocalWriteResponse {
                            ok: false,
                            error: format!("could not read the linked folders: {e}"),
                        };
                    }
                };
                let Some(group_id) = links
                    .into_iter()
                    .find(|l| l.key() == req.local_path && !l.orphaned)
                    .map(|l| l.group_id)
                else {
                    break 'resolve LocalWriteResponse {
                        ok: false,
                        error: "local_path is not a currently linked, live folder".into(),
                    };
                };
                let Some(runtime) = context.links.runtime(&req.local_path) else {
                    break 'resolve LocalWriteResponse {
                        ok: false,
                        error: "link is not currently running".into(),
                    };
                };
                match runtime.capture_local_write(&group_id, &req.relative_path, kind).await {
                    Ok(_) => LocalWriteResponse { ok: true, error: String::new() },
                    Err(e) => LocalWriteResponse { ok: false, error: e },
                }
            };
            Some(ShellIpcMessage { payload: Some(Payload::LocalWriteResponse(response)) })
        }
        // User activity on a provider root pauses its prefetch (one push) and is remembered.
        Some(Payload::ProviderActivity(activity)) => {
            let root = hex::encode(&activity.root_id);
            let known = root_is_known(context.replica_coordinator.provider_repository(), &root);
            if known
                && context.prefetch.on_activity(
                    &root,
                    &activity.item_id,
                    activity.activity_kind(),
                    std::time::Instant::now(),
                )
            {
                context
                    .provider_host
                    .send_to_host(crate::provider_prefetch::Action::Pause(root).into_payload());
            }
            None
        }
        Some(Payload::ProviderPrefetchDone(done)) => {
            context.prefetch.on_done(
                &hex::encode(&done.root_id),
                done.hint_id,
                done.result(),
                std::time::Instant::now(),
            );
            None
        }
        _ => None, // StatusResponse/StatusPush/ContextActionResponse/... are server->client only
    }
}

/// Test seam for sibling modules: dispatches one message and reports whether a
/// `LocalWriteResponse` said `ok`.
#[cfg(test)]
pub(crate) async fn handle_message_for_tests(context: &ShellContext, msg: ShellIpcMessage) -> bool {
    match handle_message(context, msg).await.and_then(|m| m.payload) {
        Some(Payload::LocalWriteResponse(r)) => r.ok,
        _ => false,
    }
}

#[cfg(test)]
mod item_pause_tests;
#[cfg(test)]
mod linked_roots_tests;
#[cfg(test)]
mod list_folder_files_tests;
#[cfg(test)]
mod local_write_tests;
#[cfg(test)]
mod provider_tests;

mod provider_apply;
mod provider_enumerate;
mod provider_materialize;
use provider_materialize::{materialize_message, Delivery, MaterializeRequests};

type ItemIdBytes = yadorilink_sync_sqlite::provider::ItemId;

/// Reference client implementation: the shell extension's
/// native shim (Rust via `windows-rs` on Windows per or an FFI
/// core called from the Swift `FinderSync` extension on macOS) follows
/// this exact pattern — bounded timeout, `Unspecified` (no overlay) on
/// any failure, never blocking the file manager UI waiting on a daemon
/// that might not be running.
#[cfg(feature = "process-model")]
pub mod client {
    #[cfg(unix)]
    use std::path::Path;
    use std::time::Duration;

    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
    use yadorilink_ipc_proto::shellipc::{
        ShellIpcMessage, StatusQuery, SyncState as ShellSyncState,
    };

    const DEFAULT_TIMEOUT: Duration = Duration::from_millis(200);

    #[cfg(unix)]
    pub async fn query_status(socket_path: &Path, path: &str) -> ShellSyncState {
        tokio::time::timeout(DEFAULT_TIMEOUT, query_inner(socket_path, path))
            .await
            .unwrap_or(Ok(ShellSyncState::Unspecified))
            .unwrap_or(ShellSyncState::Unspecified)
    }

    #[cfg(unix)]
    async fn query_inner(socket_path: &Path, path: &str) -> std::io::Result<ShellSyncState> {
        let mut stream = tokio::net::UnixStream::connect(socket_path).await?;
        query_over(&mut stream, path).await
    }

    /// Windows local IPC support: the Windows counterpart to the `#[cfg(unix)]`
    /// `query_status` above — same bounded-timeout, fail-soft-to-`Unspecified`
    /// contract, but connects to a named pipe (`pipe_name`, e.g.
    /// `\\.\pipe\yadorilink-<user>`) instead of a Unix socket path. A busy pipe
    /// gets a few short retries, matching `control_client`'s connect logic.
    #[cfg(windows)]
    pub async fn query_status(pipe_name: &str, path: &str) -> ShellSyncState {
        tokio::time::timeout(DEFAULT_TIMEOUT, query_inner(pipe_name, path))
            .await
            .unwrap_or(Ok(ShellSyncState::Unspecified))
            .unwrap_or(ShellSyncState::Unspecified)
    }

    #[cfg(windows)]
    async fn query_inner(pipe_name: &str, path: &str) -> std::io::Result<ShellSyncState> {
        use tokio::net::windows::named_pipe::ClientOptions;

        const ERROR_PIPE_BUSY: i32 = 231;
        const MAX_ATTEMPTS: u32 = 5;
        const RETRY_DELAY: Duration = Duration::from_millis(50);

        let mut attempt = 0;
        let mut stream = loop {
            match ClientOptions::new().open(pipe_name) {
                Ok(client) => break client,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < MAX_ATTEMPTS => {
                    attempt += 1;
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(e) => return Err(e),
            }
        };
        query_over(&mut stream, path).await
    }

    async fn query_over<S>(stream: &mut S, path: &str) -> std::io::Result<ShellSyncState>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        write_message(
            stream,
            &ShellIpcMessage {
                payload: Some(Payload::StatusQuery(StatusQuery { path: path.to_string() })),
            },
        )
        .await?;
        let resp = read_message::<ShellIpcMessage>(stream).await?;
        Ok(match resp.and_then(|m| m.payload) {
            Some(Payload::StatusResponse(r)) => {
                ShellSyncState::try_from(r.state).unwrap_or(ShellSyncState::Unspecified)
            }
            _ => ShellSyncState::Unspecified,
        })
    }
}

// apple-cfg: ios-explicit the iOS host serves the provider surface over in-memory channels only; no
// AF_UNIX path logic is compiled for it
#[cfg(all(unix, not(target_os = "ios"), feature = "process-model"))]
pub mod unix_transport {
    use std::path::Path;
    use std::sync::Arc;

    use tokio::net::UnixListener;
    use tokio::sync::Semaphore;

    use crate::shell_context::ShellContext;

    pub async fn serve(socket_path: &Path, context: Arc<ShellContext>) -> std::io::Result<()> {
        let _ = std::fs::remove_file(socket_path);
        prepare_private_socket_parent(socket_path)?;
        let listener = UnixListener::bind(socket_path)?;
        // Status queries can reveal which folders are linked and their
        // sync state — restrict to the owning user, same reasoning as
        // `control_socket::serve`.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(path = %socket_path.display(), "shell-integration IPC listening (unix socket)");

        let connection_slots = Arc::new(Semaphore::new(super::MAX_SHELL_IPC_CONNECTIONS));
        loop {
            let connection_slot = connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("shell IPC semaphore closed"))?;
            let (stream, _) = listener.accept().await?;
            let context = context.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                let (read_half, write_half) = stream.into_split();
                if let Err(e) = super::handle_connection(read_half, write_half, context).await {
                    tracing::debug!(error = %e, "shell IPC connection ended");
                }
            });
        }
    }

    fn prepare_private_socket_parent(socket_path: &Path) -> std::io::Result<()> {
        // Only a directory this call creates is made private. An existing one
        // is not ours to chmod: on macOS it can be the App Group container
        // root, which the system owns. The socket itself is restricted to the
        // owning user right after it is bound.
        if let Some(parent) = socket_path.parent() {
            if !parent.is_dir() {
                std::fs::create_dir_all(parent)?;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::prepare_private_socket_parent;
        use std::os::unix::fs::PermissionsExt;

        fn mode(path: &std::path::Path) -> u32 {
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        #[test]
        fn a_directory_it_creates_is_private_and_an_existing_one_is_left_alone() {
            let root = tempfile::tempdir().unwrap();
            let created = root.path().join("new");
            prepare_private_socket_parent(&created.join("shell.sock")).unwrap();
            assert_eq!(mode(&created), 0o700);

            let existing = root.path().join("existing");
            std::fs::create_dir(&existing).unwrap();
            std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o750)).unwrap();
            prepare_private_socket_parent(&existing.join("shell.sock")).unwrap();
            assert_eq!(
                mode(&existing),
                0o750,
                "the system-owned container root must not be chmod'd"
            );
        }
    }
}

/// Windows named-pipe transport (Windows local IPC support: verified
/// against a real Windows 11 VM — see `control_socket::windows_transport`'s
/// doc comment for the concurrent-connection pipe-instance race this
/// structure specifically avoids).
#[cfg(all(windows, feature = "process-model"))]
pub mod windows_transport {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::sync::Semaphore;

    use crate::shell_context::ShellContext;
    use crate::windows_pipe_security::PipeSecurityAttributes;

    // See the identical helpers in `control_socket::windows_transport`:
    // `PipeSecurityAttributes` is `!Send` (raw `*mut c_void`), so it's built
    // and consumed inside a plain, non-async helper rather than as a local in
    // `serve`'s async fn body — that keeps it out of `serve`'s generator
    // state entirely, so the future `essential.spawn` (`main.rs`) wraps it in
    // stays `Send` regardless of how the loop below evolves.
    fn create_first_pipe_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
        let mut attrs = PipeSecurityAttributes::new_current_user_and_system_only()?;
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(pipe_name, attrs.as_mut_ptr())
        }
    }

    fn create_next_pipe_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
        let mut attrs = PipeSecurityAttributes::new_current_user_and_system_only()?;
        unsafe {
            ServerOptions::new().create_with_security_attributes_raw(pipe_name, attrs.as_mut_ptr())
        }
    }

    /// `pipe_name` should look like `\\.\pipe\yadorilink-<user>`.
    pub async fn serve(pipe_name: &str, context: Arc<ShellContext>) -> std::io::Result<()> {
        tracing::info!(pipe_name, "shell-integration IPC listening (named pipe)");
        let mut server = create_first_pipe_server(pipe_name)?;
        let connection_slots = Arc::new(Semaphore::new(super::MAX_SHELL_IPC_CONNECTIONS));

        loop {
            let connection_slot = connection_slots
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| std::io::Error::other("shell IPC semaphore closed"))?;
            let next_server = create_next_pipe_server(pipe_name)?;
            server.connect().await?;
            let connected = server;
            server = next_server;

            let context = context.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                let (read_half, mut write_half) = tokio::io::split(connected);
                if let Err(e) = super::handle_connection(read_half, &mut write_half, context).await
                {
                    tracing::debug!(error = %e, "shell IPC connection ended");
                }
                let _ = write_half.shutdown().await;
            });
        }
    }
}
