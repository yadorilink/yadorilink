//! `ProviderApplyChange`: the provider write path over the shell connection.
//!
//! One request is one logical OS action. Before anything is read or written the daemon checks the
//! caller (below), then, for an operation it may already have decided, answers from its stored
//! result WITHOUT ingesting anything. Otherwise it ingests the extension's copy (when the request
//! carries contents), decides and commits the change in one transaction together with the
//! operation record, and answers from the committed rows.
//!
//! Who may ask (the v1 trust, the same limit as the host attach: a guard against stray and stale
//! connections, not authentication): the request must come on a connection that sent an
//! `ExtensionHandshake` naming the same root, while a host app is attached, for a root that is
//! known and ready, and the group's authorization (the authoring layer's own refusal) decides the
//! role. A failure never evicts or drops the user's local bytes; the failure codes say what the
//! extension does with them.
//!
//! The embedding app (iOS) asks without a socket, through [`apply_for_app`]: the caller is the
//! process that owns the engine, so there is no connection to vouch for and no host to be
//! attached. What the app's write needs is the declared root without an error of its own; the
//! domain being registered with the OS, or an extension having run once, is evidence about the
//! Files app and not about this engine's data, so it is not required. Every other check (the
//! group's authorization, the base, the identity of the operation, durable before acknowledged)
//! is the same code.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    EntryKind as WireEntryKind, ProviderAppliedItem, ProviderApplyCancel,
    ProviderApplyChangeRequest, ProviderApplyChangeResponse, ProviderApplyFailure,
    ProviderApplyOutcome, ProviderChangeKind, ShellIpcMessage,
};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::Readiness;
use yadorilink_sync_sqlite::provider::ItemId;
use yadorilink_sync_sqlite::provider_write::{
    ApplyError, ApplyInput, ApplyResult, BaseVersion, ChangeKind, ContentInput, EntryKind,
    MetadataInput, OutcomeKind,
};

use super::provider_materialize::{
    registry_key, send_plain, MaterializeRequests, Reply, ReservedId,
};
use crate::provider_ingest::IngestError;
use crate::shell_context::ShellContext;

const KIND_APPLY: u8 = b'A';

/// The commit point of one request. A cancel wins only while the request is still `RUNNING`; the
/// worker claims `COMMITTING` right before it opens the transaction, and from then on the
/// response is the real outcome, never CANCELLED: the OS must not be told a committed change
/// failed.
const RUNNING: u8 = 0;
const CANCELLED: u8 = 1;
const COMMITTING: u8 = 2;

type Gate = Arc<std::sync::atomic::AtomicU8>;

/// Who is asking, which decides what vouches for the request.
enum Caller<'a> {
    /// A connection of the shell socket: it must have sent the extension handshake for the root,
    /// with a host app attached, and the root must be ready.
    Extension(&'a Arc<Handshakes>),
    /// The process that owns the engine.
    App,
}

/// What one connection knows: the roots whose extension handshake it sent, and the commit gate
/// of each apply request it has in flight.
#[derive(Default)]
pub(crate) struct Handshakes {
    roots: Mutex<HashSet<Vec<u8>>>,
    gates: Mutex<std::collections::HashMap<Vec<u8>, Gate>>,
}

impl Handshakes {
    pub(crate) fn note(&self, root_id: &[u8]) {
        self.roots.lock().unwrap_or_else(|p| p.into_inner()).insert(root_id.to_vec());
    }

    pub(super) fn has(&self, root_id: &[u8]) -> bool {
        self.roots.lock().unwrap_or_else(|p| p.into_inner()).contains(root_id)
    }

    fn gate_of(&self, key: &[u8]) -> Option<Gate> {
        self.gates.lock().unwrap_or_else(|p| p.into_inner()).get(key).cloned()
    }
}

/// Removes the gate of a request when it is completely done.
struct GateGuard {
    handshakes: Arc<Handshakes>,
    key: Vec<u8>,
}

impl Drop for GateGuard {
    fn drop(&mut self) {
        self.handshakes.gates.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.key);
    }
}

/// Test seam: runs at a named point of one request (keyed by request id), to inject a cancel.
#[cfg(test)]
pub(crate) static POINT_HOOKS: Mutex<Option<PointHooks>> = Mutex::new(None);

#[cfg(test)]
type PointHooks = std::collections::HashMap<(&'static str, Vec<u8>), Arc<dyn Fn() + Send + Sync>>;

#[cfg(test)]
fn point(name: &'static str, request_id: &[u8]) {
    let hook = POINT_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .and_then(|hooks| hooks.get(&(name, request_id.to_vec())).cloned());
    if let Some(hook) = hook {
        hook();
    }
}

/// How one request ended, before it is turned into a response.
struct Failure {
    code: ProviderApplyFailure,
    error: String,
    suggested_name: String,
}

impl Failure {
    fn new(code: ProviderApplyFailure, error: impl Into<String>) -> Self {
        Self { code, error: error.into(), suggested_name: String::new() }
    }
}

/// Handles the apply-change messages of a connection. Returns true when `msg` was one.
pub(crate) fn apply_message(
    context: &Arc<ShellContext>,
    requests: &MaterializeRequests,
    handshakes: &Arc<Handshakes>,
    reply: &Reply,
    msg: &ShellIpcMessage,
) -> bool {
    match &msg.payload {
        Some(Payload::ProviderApplyChangeRequest(request)) => {
            start(context, requests, handshakes, reply, request.clone());
            true
        }
        Some(Payload::ProviderApplyCancel(ProviderApplyCancel { request_id })) => {
            let key = registry_key(KIND_APPLY, request_id);
            // A cancel after the commit point changes nothing: the real outcome is answered.
            let wins = handshakes.gate_of(&key).is_some_and(|gate| {
                gate.compare_exchange(RUNNING, CANCELLED, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            });
            if !wins {
                return true;
            }
            let claimed = requests
                .inflight
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_mut(&registry_key(KIND_APPLY, request_id))
                .and_then(Option::take);
            if let Some(handle) = claimed {
                handle.abort();
                send_plain(
                    reply,
                    response_of(
                        request_id,
                        &[],
                        0,
                        Err(Failure::new(ProviderApplyFailure::Cancelled, "cancelled")),
                    ),
                );
            }
            true
        }
        _ => false,
    }
}

fn start(
    context: &Arc<ShellContext>,
    requests: &MaterializeRequests,
    handshakes: &Arc<Handshakes>,
    reply: &Reply,
    request: ProviderApplyChangeRequest,
) {
    let key = registry_key(KIND_APPLY, &request.request_id);
    let mut inflight = requests.inflight.lock().unwrap_or_else(|p| p.into_inner());
    if inflight.len() >= super::provider_materialize::MAX_INFLIGHT_REQUESTS
        || inflight.contains_key(&key)
    {
        send_plain(
            reply,
            response_of(
                &request.request_id,
                &request.session_id,
                request.operation_seq,
                Err(Failure::new(
                    ProviderApplyFailure::Retry,
                    "too many requests, or a duplicate id",
                )),
            ),
        );
        return;
    }
    let (context, reply, registry, handshakes) =
        (context.clone(), reply.clone(), requests.inflight.clone(), handshakes.clone());
    let reserved = ReservedId { registry: registry.clone(), id: key.clone() };
    let task_key = key.clone();
    let gate: Gate = Arc::new(std::sync::atomic::AtomicU8::new(RUNNING));
    handshakes.gates.lock().unwrap_or_else(|p| p.into_inner()).insert(key.clone(), gate.clone());
    let gate_guard = GateGuard { handshakes: handshakes.clone(), key: key.clone() };
    let handle = tokio::spawn(async move {
        let _reserved = reserved;
        let _gate_guard = gate_guard;
        let outcome = run(&context, Caller::Extension(&handshakes), &request, &gate).await;
        if let Err(failure) = &outcome {
            log_refusal(&request, failure);
        }
        // The one terminal transition: only the side that takes the handle answers.
        let claimed = registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&task_key)
            .and_then(Option::take);
        if claimed.is_none() {
            return;
        }
        // Before the answer, so a status after the host sees it shows the change.
        context.telemetry.command_completed();
        send_plain(
            &reply,
            response_of(&request.request_id, &request.session_id, request.operation_seq, outcome),
        );
    });
    inflight.insert(key, Some(handle.abort_handle()));
}

/// The stable fields of a request, hashed: a replay is compared by this, with no re-ingest.
fn fingerprint(request: &ProviderApplyChangeRequest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut put = |tag: &str, bytes: &[u8]| {
        hasher.update((tag.len() as u32).to_be_bytes());
        hasher.update(tag.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    put("kind", &request.kind.to_be_bytes());
    put("item", &request.item_id);
    put("parent", &[request.parent_item_id.is_some() as u8]);
    put("parent-id", request.parent_item_id.as_deref().unwrap_or(&[]));
    put("name", &[request.name.is_some() as u8]);
    put("name-value", request.name.as_deref().unwrap_or("").as_bytes());
    put("entry", &request.entry_kind.to_be_bytes());
    put("base", &request.base_version_hash);
    if let Some(content) = &request.content {
        put("content-size", &content.size.to_be_bytes());
        put("content-sha", &content.sha256);
    }
    put("symlink", &request.symlink_target);
    if let Some(meta) = &request.metadata {
        put("exec", &meta.exec.map_or(Vec::new(), |e| vec![u8::from(e)]));
        put("mtime", &meta.mtime_unix_nanos.map_or(Vec::new(), |m| m.to_be_bytes().to_vec()));
    }
    put("recursive", &[request.recursive as u8]);
    // Only when present, so the fingerprint of every earlier operation is unchanged.
    if let Some(restore) = &request.restore_from {
        put("restore-path", restore.path.as_bytes());
        put("restore-version", &restore.version_hash);
    }
    // The view the operation was made against: a retry with another view is another operation.
    for (tag, value) in [
        ("base-generation", request.base_generation),
        ("parent-generation", request.parent_generation),
        ("observed-revision", request.observed_revision),
    ] {
        put(tag, &[value.is_some() as u8]);
        put(tag, &value.unwrap_or(0).to_be_bytes());
    }
    hasher.finalize().into()
}

fn item_id_of(bytes: &[u8]) -> Result<ItemId, Failure> {
    ItemId::try_from(bytes)
        .map_err(|_| Failure::new(ProviderApplyFailure::NotFound, "an item id is not 16 bytes"))
}

/// The upload of an operation that carries bytes is journaled by operation identity BEFORE any
/// refusal (readiness, authorization, size, the base): whatever happens next, a retry, a restart or
/// a recovery finds it, and the age sweep never removes it. A retry of an undecided operation reuses
/// the upload journaled for it (its identity carries the same bytes), and the retry's own copy is
/// removed as redundant. `None` when the request carries no bytes or no valid identity.
/// Whether the file at `path` is exactly the declared upload (size and SHA-256).
fn upload_matches(
    path: &std::path::Path,
    source: &yadorilink_ipc_proto::shellipc::ProviderContentSource,
) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else { return false };
    if file.metadata().map_or(true, |m| m.len() != source.size) {
        return false;
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(_) => return false,
        }
    }
    hasher.finalize().as_slice() == source.sha256.as_slice()
}

fn journal_upload(
    context: &Arc<ShellContext>,
    handoff: &crate::provider_handoff::HandoffRoot,
    repo: &yadorilink_sync_sqlite::provider::ProviderRepository,
    root: &str,
    request: &ProviderApplyChangeRequest,
) -> Result<Option<String>, Failure> {
    let Some(source) = &request.content else { return Ok(None) };
    let carries_bytes = matches!(
        ProviderChangeKind::try_from(request.kind),
        Ok(ProviderChangeKind::Create | ProviderChangeKind::Modify)
    );
    if !carries_bytes
        || request.session_id.is_empty()
        || request.session_id.len() > 64
        || request.operation_seq == 0
    {
        return Ok(None);
    }
    let journal = |name: &str| -> Result<(), Failure> {
        repo.journal_pending_ingest(
            root,
            &request.session_id,
            request.operation_seq,
            name,
            context.writer.now_ms(),
        )
        .map_err(|e| Failure::new(ProviderApplyFailure::Retry, format!("{e:?}")))
    };
    let journaled = repo
        .pending_ingest_name(root, &request.session_id, request.operation_seq)
        .ok()
        .flatten()
        .filter(|name| *name != source.ingest_name && handoff.ingest_dir().join(name).exists());
    // A copy is discarded only once it is VERIFIED redundant (declared size and digest). A journaled
    // copy that no longer verifies (truncated, corrupted, or never fully durable) is replaced by
    // the retry's fresh copy when that one verifies; when neither does, both are kept (the journal
    // keeps the first) and the retry is refused.
    let dir = handoff.ingest_dir();
    let used = match journaled {
        None => source.ingest_name.clone(),
        Some(prior) if upload_matches(&dir.join(&prior), source) => {
            let _ = std::fs::remove_file(dir.join(&source.ingest_name));
            prior
        }
        Some(prior) if upload_matches(&dir.join(&source.ingest_name), source) => {
            journal(&source.ingest_name)?;
            let _ = std::fs::remove_file(dir.join(&prior));
            return Ok(Some(source.ingest_name.clone()));
        }
        Some(_) => {
            return Err(Failure::new(
                ProviderApplyFailure::IngestUnstable,
                "neither the journaled upload nor the retry's copy matches the declared digest",
            ));
        }
    };
    journal(&used)?;
    Ok(Some(used))
}

/// One request of the embedding app: the same decision and commit as a socket request, answered
/// as the wire response (a typed refusal is a response, never an error of the call). Nothing
/// cancels it once started; a caller that gave up replays the same operation identity to learn
/// the outcome.
pub(crate) async fn apply_for_app(
    context: &Arc<ShellContext>,
    request: &ProviderApplyChangeRequest,
) -> ProviderApplyChangeResponse {
    let gate: Gate = Arc::new(std::sync::atomic::AtomicU8::new(RUNNING));
    let outcome = run(context, Caller::App, request, &gate).await;
    if let Err(failure) = &outcome {
        log_refusal(request, failure);
    }
    response_for(&request.request_id, &request.session_id, request.operation_seq, outcome)
}

fn log_refusal(request: &ProviderApplyChangeRequest, failure: &Failure) {
    // The message can quote a file or folder name ("x is taken"): it is logged only at debug.
    tracing::debug!(error = %failure.error, "the refused provider change's message");
    tracing::warn!(
        code = ?failure.code,
        kind = request.kind,
        item = %hex::encode(&request.item_id),
        operation_seq = request.operation_seq,
        base_generation = ?request.base_generation,
        parent_generation = ?request.parent_generation,
        "a provider change was not applied"
    );
}

async fn run(
    context: &Arc<ShellContext>,
    caller: Caller<'_>,
    request: &ProviderApplyChangeRequest,
    gate: &Gate,
) -> Result<ApplyResult, Failure> {
    // Who may ask.
    if let Caller::Extension(handshakes) = &caller {
        if !handshakes.has(&request.root_id) || !context.provider_host.host_connected() {
            return Err(Failure::new(
                ProviderApplyFailure::NotReady,
                "no extension handshake on this connection, or no host app is attached",
            ));
        }
    }
    let Some(handoff) = context.handoff.get() else {
        return Err(Failure::new(ProviderApplyFailure::NotReady, "no temp root is configured"));
    };
    let root = hex::encode(&request.root_id);
    let repo = context.replica_coordinator.provider_repository();

    let upload = journal_upload(context, &handoff, repo, &root, request)?;
    let declared = repo
        .list_declared_roots()
        .map_err(|e| Failure::new(ProviderApplyFailure::NotReady, e.to_string()))?
        .into_iter()
        .find(|r| r.root_id == root)
        .ok_or_else(|| Failure::new(ProviderApplyFailure::NotReady, "unknown provider root"))?;
    let ready = match caller {
        Caller::Extension(_) => declared.readiness() == Readiness::Ready,
        Caller::App => declared.error_description.is_none(),
    };
    if !ready {
        return Err(Failure::new(ProviderApplyFailure::NotReady, "the provider root is not ready"));
    }

    // A device that is not a writer of the group gets no success for a change its peers reject:
    // refused before anything is ingested or committed; the extension keeps the local bytes.
    if !context.writer.may_author(&declared.group_id) {
        return Err(Failure::new(
            ProviderApplyFailure::NotAuthorized,
            "this device is not a writer of the group",
        ));
    }

    // What the request says.
    let kind = match ProviderChangeKind::try_from(request.kind) {
        Ok(ProviderChangeKind::Create) => ChangeKind::Create,
        Ok(ProviderChangeKind::Modify) => ChangeKind::Modify,
        Ok(ProviderChangeKind::Delete) => ChangeKind::Delete,
        _ => return Err(Failure::new(ProviderApplyFailure::NotFound, "no change kind")),
    };
    if request.session_id.is_empty() || request.session_id.len() > 64 || request.operation_seq == 0
    {
        return Err(Failure::new(ProviderApplyFailure::StaleOperation, "no operation identity"));
    }
    // The base is the version identifier the daemon emitted: 40 bytes, the content hash then the
    // item's generation (big endian). Empty means the extension has none (an UNKNOWN base);
    // anything else is malformed. The generation inside the identifier is the base generation;
    // a separately named one must agree.
    let (base, base_generation) = match request.base_version_hash.len() {
        0 => (BaseVersion::Unknown, request.base_generation),
        40 => {
            let (hash, generation) = request.base_version_hash.split_at(32);
            let generation = u64::from_be_bytes(generation.try_into().expect("8"));
            if request.base_generation.is_some_and(|named| named != generation) {
                return Err(Failure::new(
                    ProviderApplyFailure::InvalidBase,
                    "the base generation disagrees with the base identifier",
                ));
            }
            (BaseVersion::Opaque(VersionHash(hash.try_into().expect("32"))), Some(generation))
        }
        _ => {
            return Err(Failure::new(
                ProviderApplyFailure::InvalidBase,
                "a base is not a 40-byte version identifier",
            ))
        }
    };
    let item_id = match (kind, request.item_id.is_empty()) {
        (ChangeKind::Create, _) => None,
        (_, true) => return Err(Failure::new(ProviderApplyFailure::NotFound, "no item")),
        (_, false) => Some(item_id_of(&request.item_id)?),
    };
    let new_parent = match &request.parent_item_id {
        None => None,
        Some(bytes) if bytes.is_empty() => Some(None),
        Some(bytes) => Some(Some(item_id_of(bytes)?)),
    };
    // A create's parent field absent means the root, as for an empty one.
    let new_parent =
        if kind == ChangeKind::Create { Some(new_parent.flatten()) } else { new_parent };
    let metadata = request.metadata.unwrap_or_default();
    let fingerprint = fingerprint(request);

    // An operation already decided is answered from its record: nothing is read or ingested.
    match repo.check_replay(&root, &request.session_id, request.operation_seq, &fingerprint) {
        Ok(Some(result)) => {
            // Decided before: this attempt's own upload and any journal row are not needed.
            if let Some(source) = &request.content {
                let _ = std::fs::remove_file(handoff.ingest_dir().join(&source.ingest_name));
            }
            if let Some(used) = &upload {
                let _ = std::fs::remove_file(handoff.ingest_dir().join(used));
                let _ =
                    repo.clear_pending_ingest(&root, &request.session_id, request.operation_seq);
            }
            return Ok(result);
        }
        Ok(None) => {}
        Err(error) => return Err(map_error(error, &request.content)),
    }

    // A restore takes its contents from a retained version. The blocks are held (or fetched) and
    // kept from deletion until the change commits.
    let _restore_activity =
        request.restore_from.as_ref().map(|_| context.writer.state().begin_write_activity());
    let restored = match &request.restore_from {
        None => None,
        Some(source) => {
            let by_app = matches!(caller, Caller::App);
            let (group, item) = (&declared.group_id, item_id);
            Some(
                restore_for_request(context, by_app, request, (group, &root), item, kind, source)
                    .await?,
            )
        }
    };

    // The extension's copy, when there is one.
    let mut ingested_name: Option<String> = None;
    let content = match (&request.content, request.entry_kind, kind) {
        (Some(source), _, ChangeKind::Create | ChangeKind::Modify) => {
            let used = upload.clone().unwrap_or_else(|| source.ingest_name.clone());
            let ingested =
                ingest_copy(context, &handoff, &declared.group_id, source, &used).await?;
            ingested_name = Some(used);
            Some(ingested)
        }
        _ => restored.as_ref().and_then(|r| r.content.clone()),
    };

    let input = ApplyInput {
        root_id: root.clone(),
        session_id: request.session_id.clone(),
        operation_seq: request.operation_seq,
        fingerprint,
        kind,
        item_id,
        new_parent,
        name: request.name.clone(),
        entry_kind: entry_kind_of(request, restored.as_ref()),
        base,
        content,
        symlink_target: (!request.symlink_target.is_empty())
            .then(|| request.symlink_target.clone()),
        metadata: metadata_input(&metadata, restored.as_ref()),
        restore: restored.is_some(),
        announce_to_os: restored.as_ref().is_some_and(|r| r.announce_to_os),
        recursive: request.recursive,
        max_subtree: yadorilink_sync_sqlite::provider_write::DEFAULT_MAX_SUBTREE,
        base_generation,
        parent_generation: request.parent_generation,
        observed_revision: request.observed_revision,
        now_ms: context.writer.now_ms(),
    };

    // The authoring identity and the lease for this root's domain.
    let author = context
        .writer
        .author(&declared.group_id)
        .map_err(|e| Failure::new(ProviderApplyFailure::NotAuthorized, e))?;
    let lease = context
        .writer
        .lease(&root, &declared.group_id, &handoff.domain_dir(&root))
        .map_err(|e| Failure::new(ProviderApplyFailure::NotReady, e))?;
    let announce_to_os = input.announce_to_os;
    let (coordinator, device_id) =
        (context.replica_coordinator.clone(), context.writer.device_id());
    let gate = gate.clone();
    let writer = context.writer.clone();
    let group_id = declared.group_id.clone();
    #[cfg(test)]
    let request_id = request.request_id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        point("before_commit_point", &request_id);
        // The commit point: from here the change may commit, and a cancel no longer wins.
        if gate.compare_exchange(RUNNING, COMMITTING, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Err(ApplyError::Retry("cancelled before the commit point".into()));
        }
        // Asked again at the commit point: the policy may have changed while the copy was read.
        if !writer.may_author(&group_id) {
            return Err(ApplyError::NotAuthorized);
        }
        #[cfg(test)]
        point("at_commit_point", &request_id);
        let operation = lease
            .begin_operation()
            .map_err(|e| ApplyError::Db(yadorilink_sync_sqlite::SyncSqliteError::from(e)))?;
        let local = yadorilink_sync_sqlite::local_author::LocalAuthor::of_key(&author);
        coordinator.provider_repository().apply_change(
            &input,
            &local,
            &device_id,
            &operation.permit(),
        )
    })
    .await
    .map_err(|e| Failure::new(ProviderApplyFailure::Retry, e.to_string()))?;

    if outcome.is_ok() {
        push_evidence(context, repo, &root);
        context.writer.after_commit(&declared.group_id).await;
        if announce_to_os {
            // The OS does not hold these bytes: announce the new version and signal it now.
            context.publication.kick(&root);
        }
    }

    // The copy is spent once the change committed or can never commit.
    // Only a committed change spends the copy. Any refusal leaves it for the ingest sweep (which
    // ages it out): the repository has already kept the bytes durably when it could, and a refusal
    // it could not keep them for (not authorized, not ready, a full disk) must not consume them.
    let spent = outcome.is_ok();
    if let (true, Some(name)) = (spent, ingested_name) {
        let _ = std::fs::remove_file(handoff.ingest_dir().join(name));
        // The retry's own copy, when the journaled upload was reused.
        if let Some(source) = &request.content {
            let _ = std::fs::remove_file(handoff.ingest_dir().join(&source.ingest_name));
        }
    }
    outcome.map_err(|error| map_error(error, &request.content))
}

/// Reads the copy `used` (the journaled upload, or the request's own) and stores its blocks.
async fn ingest_copy(
    context: &Arc<ShellContext>,
    handoff: &crate::provider_handoff::HandoffRoot,
    group_id: &str,
    source: &yadorilink_ipc_proto::shellipc::ProviderContentSource,
    used: &str,
) -> Result<ContentInput, Failure> {
    // Before the file is read: when the volume cannot take the blocks of a file this size with its
    // headroom, the answer is LOW_DISK and the staged copy is kept for a retry. Held until the
    // blocks are stored.
    let _space = context
        .writer
        .reserve_space(source.size)
        .map_err(|m| Failure::new(ProviderApplyFailure::LowDisk, m))?;
    let dir = handoff.ingest_dir().to_path_buf();
    let (name, size, sha) = (used.to_owned(), source.size, source.sha256.clone());
    let writer = context.writer.clone();
    let ingested = tokio::task::spawn_blocking(move || {
        crate::provider_ingest::ingest(&dir, &name, size, &sha, &writer.store())
    })
    .await
    .map_err(|e| Failure::new(ProviderApplyFailure::Retry, e.to_string()))?
    .map_err(map_ingest)?;
    let hashes: Vec<Vec<u8>> = ingested.blocks.iter().map(|b| b.hash.clone()).collect();
    context
        .writer
        .record_provenance(group_id, &hashes)
        .map_err(|e| Failure::new(ProviderApplyFailure::Retry, e))?;
    // The journaled copy is verified: this retry's own copy is redundant.
    if used != source.ingest_name {
        let _ = std::fs::remove_file(handoff.ingest_dir().join(&source.ingest_name));
    }
    Ok(ContentInput { blocks: ingested.blocks, size: ingested.size })
}

/// What a restore asks the write to author: the retained version's contents and execute flag.
struct Restored {
    /// The bytes came from another item's version (a conflict copy restored over its original),
    /// so the OS does not hold them: the new version is announced and the OS fetches it, as it
    /// does for a change from a peer.
    announce_to_os: bool,
    content: Option<ContentInput>,
    entry_kind: EntryKind,
    exec: bool,
}

/// The kind the change authors: a restore's is the version's, any other change's is the request's.
fn entry_kind_of(request: &ProviderApplyChangeRequest, restored: Option<&Restored>) -> EntryKind {
    match restored {
        Some(restored) => restored.entry_kind,
        None => match WireEntryKind::try_from(request.entry_kind) {
            Ok(WireEntryKind::Directory) => EntryKind::Directory,
            Ok(WireEntryKind::Symlink) => EntryKind::Symlink,
            _ => EntryKind::File,
        },
    }
}

/// The metadata the change sets. A restore without metadata of its own gets the version's
/// execute flag.
fn metadata_input(
    metadata: &yadorilink_ipc_proto::shellipc::ProviderItemMetadata,
    restored: Option<&Restored>,
) -> MetadataInput {
    MetadataInput {
        exec: metadata.exec.or(restored.map(|r| r.exec)),
        mtime_unix_nanos: metadata.mtime_unix_nanos,
    }
}

/// The contents a restore request asks for. Only the embedding app may restore, and the request
/// names a version instead of bytes and is a create or a modify.
async fn restore_for_request(
    context: &Arc<ShellContext>,
    by_app: bool,
    request: &ProviderApplyChangeRequest,
    (group_id, root): (&str, &str),
    item: Option<ItemId>,
    kind: ChangeKind,
    source: &yadorilink_ipc_proto::shellipc::ProviderRestoreSource,
) -> Result<Restored, Failure> {
    if !by_app {
        return Err(Failure::new(
            ProviderApplyFailure::NotFound,
            "a restore is asked for by the embedding app only",
        ));
    }
    if request.content.is_some() || kind == ChangeKind::Delete {
        return Err(Failure::new(
            ProviderApplyFailure::IngestRejected,
            "a restore names a version instead of bytes, and is a create or a modify",
        ));
    }
    restore_content(context, group_id, root, item, kind, source).await
}

/// Resolves a restore's version and makes its blocks local. The version must be a retained,
/// non-deleted version of the file or folder at the source's path; a MODIFY must be for the live
/// item at that very path.
async fn restore_content(
    context: &Arc<ShellContext>,
    group_id: &str,
    root: &str,
    item: Option<ItemId>,
    kind: ChangeKind,
    source: &yadorilink_ipc_proto::shellipc::ProviderRestoreSource,
) -> Result<Restored, Failure> {
    use yadorilink_replica_domain::file::RecordKind;
    let not_found = |text: &str| Failure::new(ProviderApplyFailure::NotFound, text);
    let hash: [u8; 32] = source
        .version_hash
        .as_slice()
        .try_into()
        .map_err(|_| not_found("a version hash is not 32 bytes"))?;
    let mut announce_to_os = false;
    if let (ChangeKind::Modify, Some(item)) = (kind, item) {
        let at = context.replica_coordinator.provider_repository().path_for_item(root, &item);
        // Live at the version's own path, or at the original path of a conflict copy whose
        // version it is (Keep this restores the copy over its original).
        let named_path = |path: &String| {
            *path == source.path
                || yadorilink_replica_domain::conflict::conflict_copy_source_path(&source.path)
                    == *path
        };
        if !matches!(&at, Ok(Some((path, true))) if named_path(path)) {
            return Err(not_found("the item is not live at the path of the version"));
        }
        announce_to_os = !matches!(&at, Ok(Some((path, true))) if *path == source.path);
    }
    let versions = context
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group_id, &source.path)
        .map_err(|e| Failure::new(ProviderApplyFailure::Retry, e.to_string()))?;
    let version =
        versions.into_iter().find(|v| !v.deleted && v.version_hash.0 == hash).ok_or_else(|| {
            Failure::new(
                ProviderApplyFailure::VersionUnavailable,
                "that version is not retained any more",
            )
        })?;
    let exec = version.exec;
    match version.record_kind {
        RecordKind::Symlink => Err(not_found("a symlink cannot be restored")),
        RecordKind::Directory if kind != ChangeKind::Create => {
            Err(not_found("a folder is restored by creating it"))
        }
        RecordKind::Directory => Ok(Restored {
            announce_to_os: false,
            content: None,
            entry_kind: EntryKind::Directory,
            exec: false,
        }),
        RecordKind::File => {
            context.writer.ensure_blocks(group_id, &version.blocks).await.map_err(|error| {
                use crate::provider_writer::EnsureBlocksError as E;
                match error {
                    E::LowDisk(message) => Failure::new(ProviderApplyFailure::LowDisk, message),
                    E::Unavailable => Failure::new(
                        ProviderApplyFailure::VersionUnavailable,
                        "no reachable device holds the bytes of that version",
                    ),
                    E::Failed(message) => Failure::new(ProviderApplyFailure::Retry, message),
                }
            })?;
            Ok(Restored {
                announce_to_os,
                content: Some(ContentInput { blocks: version.blocks, size: version.size }),
                entry_kind: EntryKind::File,
                exec,
            })
        }
    }
}

/// The change recorded the handoff of the version it authored: tell the host, which echoes the
/// sequence in the reports it begins afterwards.
fn push_evidence(
    context: &ShellContext,
    repo: &yadorilink_sync_sqlite::provider::ProviderRepository,
    root: &str,
) {
    match repo.latest_evidence_seq(root) {
        Ok(Some(seq)) => context.provider_host.evidence_tick(root, seq),
        Ok(None) => {}
        Err(error) => tracing::warn!(%error, "could not read the evidence sequence to push"),
    }
}

fn map_ingest(error: IngestError) -> Failure {
    match error {
        IngestError::Rejected(m) => Failure::new(ProviderApplyFailure::IngestRejected, m),
        IngestError::Unstable(m) => Failure::new(ProviderApplyFailure::IngestUnstable, m),
        IngestError::TooLarge => Failure::new(ProviderApplyFailure::TooLarge, "too many blocks"),
        IngestError::LowDisk(m) => Failure::new(ProviderApplyFailure::LowDisk, m),
        IngestError::Store(m) => Failure::new(ProviderApplyFailure::Retry, m),
    }
}

fn map_error(
    error: ApplyError,
    content: &Option<yadorilink_ipc_proto::shellipc::ProviderContentSource>,
) -> Failure {
    use ProviderApplyFailure as F;
    let disk_full = error.is_disk_full();
    match error {
        ApplyError::NotFound(m) => Failure::new(F::NotFound, m),
        ApplyError::InvalidName(m) => Failure::new(F::InvalidName, m),
        ApplyError::NameCollision(m) => Failure::new(F::NameCollision, m),
        ApplyError::DirectoryNotEmpty(m) => Failure::new(F::DirectoryNotEmpty, m),
        ApplyError::KeepLocal { path } => {
            let mut failure =
                Failure::new(F::KeepLocal, "keep the local bytes and send them as a new item");
            if let Some(path) = path {
                // The conflict-copy name of the path, labelled by the bytes' digest.
                let digest: [u8; 32] = content
                    .as_ref()
                    .and_then(|c| <[u8; 32]>::try_from(c.sha256.as_slice()).ok())
                    .unwrap_or([0u8; 32]);
                let copy =
                    yadorilink_replica_domain::conflict::native_copy_path(&path, "local", &digest);
                failure.suggested_name = copy.rsplit('/').next().unwrap_or(&copy).to_owned();
            }
            failure
        }
        ApplyError::StaleView(m) => Failure::new(F::StaleView, m),
        ApplyError::TooManySessions => {
            Failure::new(F::NotReady, "too many extension sessions for this domain")
        }
        ApplyError::NotAuthorized => {
            Failure::new(F::NotAuthorized, "this device is not a writer of the group")
        }
        ApplyError::StaleOperation => Failure::new(F::StaleOperation, "a processed operation"),
        ApplyError::OperationMismatch => Failure::new(F::OperationMismatch, "another change"),
        ApplyError::Retry(m) => Failure::new(F::Retry, m),
        ApplyError::Db(_) if disk_full => Failure::new(F::LowDisk, "the database is full"),
        ApplyError::Db(yadorilink_sync_sqlite::SyncSqliteError::AuthoringRefused { refusal }) => {
            Failure::new(F::NotAuthorized, format!("{refusal:?}"))
        }
        ApplyError::Db(other) => Failure::new(F::Retry, other.to_string()),
    }
}

fn response_of(
    request_id: &[u8],
    session_id: &[u8],
    operation_seq: u64,
    outcome: Result<ApplyResult, Failure>,
) -> ShellIpcMessage {
    ShellIpcMessage {
        payload: Some(Payload::ProviderApplyChangeResponse(response_for(
            request_id,
            session_id,
            operation_seq,
            outcome,
        ))),
    }
}

fn response_for(
    request_id: &[u8],
    session_id: &[u8],
    operation_seq: u64,
    outcome: Result<ApplyResult, Failure>,
) -> ProviderApplyChangeResponse {
    let mut message = ProviderApplyChangeResponse {
        request_id: request_id.to_vec(),
        session_id: session_id.to_vec(),
        operation_seq,
        ok: false,
        failure: ProviderApplyFailure::None as i32,
        error: String::new(),
        outcome: ProviderApplyOutcome::Unspecified as i32,
        item: None,
        suggested_name: String::new(),
        replayed: false,
    };
    match outcome {
        Ok(result) => {
            message.ok = true;
            message.replayed = result.replayed;
            message.outcome = match result.outcome {
                OutcomeKind::Applied | OutcomeKind::Deleted => ProviderApplyOutcome::Applied,
                OutcomeKind::Concurrent => ProviderApplyOutcome::Concurrent,
                OutcomeKind::FileSurvived => ProviderApplyOutcome::FileSurvived,
            } as i32;
            message.item = result.item.map(|item| ProviderAppliedItem {
                item_id: item.item_id.to_vec(),
                parent_item_id: item.parent_item_id.map(|p| p.to_vec()).unwrap_or_default(),
                name: item.name,
                entry_kind: match item.kind {
                    EntryKind::File => WireEntryKind::File,
                    EntryKind::Directory => WireEntryKind::Directory,
                    EntryKind::Symlink => WireEntryKind::Symlink,
                } as i32,
                content_version: super::provider_enumerate::versioned(
                    &item.content_version.0,
                    item.generation,
                ),
                metadata_version: super::provider_enumerate::versioned(
                    &item.metadata_version,
                    item.generation,
                ),
                size: item.size,
                mtime_unix_nanos: item.mtime_unix_nanos,
                exec: item.exec,
                current: item.current,
                namespace_revision: item.namespace_revision,
                parent_generation: item.parent_generation,
            });
        }
        Err(failure) => {
            message.failure = failure.code as i32;
            message.error = failure.error;
            message.suggested_name = failure.suggested_name;
        }
    }
    message
}

#[cfg(test)]
mod tests;
