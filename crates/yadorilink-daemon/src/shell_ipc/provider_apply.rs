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
        let outcome = run(&context, &handshakes, &request, &gate).await;
        if let Err(failure) = &outcome {
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
        // The one terminal transition: only the side that takes the handle answers.
        let claimed = registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&task_key)
            .and_then(Option::take);
        if claimed.is_none() {
            return;
        }
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
        put("mode", &meta.unix_mode.map_or(Vec::new(), |m| m.to_be_bytes().to_vec()));
        put("mtime", &meta.mtime_unix_nanos.map_or(Vec::new(), |m| m.to_be_bytes().to_vec()));
        put("replace-xattrs", &[meta.replace_xattrs as u8]);
        for xattr in &meta.xattrs {
            put("xattr-name", xattr.name.as_bytes());
            put("xattr-value", &xattr.value);
        }
    }
    put("recursive", &[request.recursive as u8]);
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

async fn run(
    context: &Arc<ShellContext>,
    handshakes: &Arc<Handshakes>,
    request: &ProviderApplyChangeRequest,
    gate: &Gate,
) -> Result<ApplyResult, Failure> {
    // Who may ask.
    if !handshakes.has(&request.root_id) || !context.provider_host.host_connected() {
        return Err(Failure::new(
            ProviderApplyFailure::NotReady,
            "no extension handshake on this connection, or no host app is attached",
        ));
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
    if declared.readiness() != Readiness::Ready {
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
    let metadata = request.metadata.clone().unwrap_or_default();
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

    // The extension's copy, when there is one.
    let mut ingested_name: Option<String> = None;
    let content = match (&request.content, request.entry_kind, kind) {
        (Some(source), _, ChangeKind::Create | ChangeKind::Modify) => {
            let dir = handoff.ingest_dir().to_path_buf();
            let used = upload.clone().unwrap_or_else(|| source.ingest_name.clone());
            let (name, size, sha) = (used.clone(), source.size, source.sha256.clone());
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
                .record_provenance(&declared.group_id, &hashes)
                .map_err(|e| Failure::new(ProviderApplyFailure::Retry, e))?;
            // The journaled copy is verified: this retry's own copy is redundant.
            if used != source.ingest_name {
                let _ = std::fs::remove_file(handoff.ingest_dir().join(&source.ingest_name));
            }
            ingested_name = Some(used);
            Some(ContentInput { blocks: ingested.blocks, size: ingested.size })
        }
        _ => None,
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
        entry_kind: match WireEntryKind::try_from(request.entry_kind) {
            Ok(WireEntryKind::Directory) => EntryKind::Directory,
            Ok(WireEntryKind::Symlink) => EntryKind::Symlink,
            _ => EntryKind::File,
        },
        base,
        content,
        symlink_target: (!request.symlink_target.is_empty())
            .then(|| request.symlink_target.clone()),
        metadata: MetadataInput {
            unix_mode: metadata.unix_mode,
            mtime_unix_nanos: metadata.mtime_unix_nanos,
            xattrs: metadata.replace_xattrs.then(|| {
                metadata.xattrs.iter().map(|x| (x.name.clone(), x.value.clone())).collect()
            }),
        },
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
        context.writer.after_commit(&declared.group_id).await;
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
                unix_mode: item.unix_mode,
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
    ShellIpcMessage { payload: Some(Payload::ProviderApplyChangeResponse(message)) }
}

#[cfg(test)]
mod tests;
