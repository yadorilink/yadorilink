//! `MaterializeToTemp`: the extension asks for the CURRENT version's bytes of one provider item.
//!
//! The same hydration primitive as the on-access path runs with a temp sink: the bytes are
//! assembled in the daemon's staging directory, verified and fsynced, renamed into the handoff
//! directory, and only then is the response (carrying just the handoff name) sent. After the
//! response went out, the handoff is recorded in the evidence ledger and a sweep is scheduled for
//! a file the OS never took. A request whose version moved, whose item has a publication pending,
//! or whose root is not ready fails with the matching reason and never returns old bytes.
//!
//! A request runs as its own task so a cancel for its `request_id` (or the connection closing)
//! can abort it: the assembly removes its own temp file when dropped, the guarded row reverts, and
//! nothing between the final rename and the response awaits, so an abort can never leave a named
//! file behind.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedSender;
use tokio::task::AbortHandle;
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    MaterializeCancel, MaterializeFailure, MaterializeProgress, MaterializeToTempRequest,
    MaterializeToTempResponse, ShellIpcMessage,
};
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_sync_sqlite::provider::ItemId;

use crate::application::ports::{AssemblyProgress, ByteRange, TempMaterialization, TempOutcome};
use crate::provider_publication::{fetch_gate, FetchGate};
use crate::shell_context::ShellContext;
use crate::sync_error::SyncError;

/// One outgoing message of a connection and, when the sender cares, where to report whether the
/// framed write to the socket completed. A response is only "delivered" when that write did.
pub(crate) struct Delivery {
    pub(crate) message: ShellIpcMessage,
    pub(crate) written: Option<tokio::sync::oneshot::Sender<bool>>,
}

/// The connection's outgoing channel for materialization responses.
pub(crate) type Reply = UnboundedSender<Delivery>;

pub(crate) fn send_plain(reply: &Reply, message: ShellIpcMessage) {
    let _ = reply.send(Delivery { message, written: None });
}

/// Queues `message` and waits for the connection to report the socket write; false when the
/// connection is gone or the write failed.
pub(crate) async fn send_and_wait(reply: &Reply, message: ShellIpcMessage) -> bool {
    let (written, done) = tokio::sync::oneshot::channel();
    if reply.send(Delivery { message, written: Some(written) }).is_err() {
        return false;
    }
    done.await.unwrap_or(false)
}

/// The requests one connection has in flight, by `request_id`. Dropping it (the connection
/// closing) aborts all of them.
///
/// An entry reserves the request id, and its abort handle is the request's right to answer: the
/// task and a cancel compete to TAKE the handle, and only the one that took it sends the
/// request's terminal response. The id itself stays reserved until the task is completely done
/// (response delivered, files cleaned up, or the task dropped), so a retry with the same id
/// cannot start in between and share a handoff name with the first attempt.
#[derive(Default, Clone)]
pub(crate) struct MaterializeRequests {
    pub(crate) inflight: Arc<Mutex<HashMap<Vec<u8>, Option<AbortHandle>>>>,
}

impl Drop for MaterializeRequests {
    fn drop(&mut self) {
        for (_, handle) in self.inflight.lock().unwrap_or_else(|p| p.into_inner()).drain() {
            if let Some(handle) = handle {
                handle.abort();
            }
        }
    }
}

/// Releases a request id when its task ends in any way (completion, abort, panic).
pub(crate) struct ReservedId {
    pub(crate) registry: Arc<Mutex<HashMap<Vec<u8>, Option<AbortHandle>>>>,
    pub(crate) id: Vec<u8>,
}

impl Drop for ReservedId {
    fn drop(&mut self) {
        self.registry.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.id);
    }
}

type Failure = (MaterializeFailure, String);

/// The key of a request in the connection's registry: its kind and its id, so the
/// materialization and the apply-change ids of one connection cannot clash.
pub(crate) fn registry_key(kind: u8, request_id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(request_id.len() + 1);
    key.push(kind);
    key.extend_from_slice(request_id);
    key
}

const KIND_MATERIALIZE: u8 = b'M';

/// How many materializations one connection may have in flight (running or waiting for a slot).
pub(crate) const MAX_INFLIGHT_REQUESTS: usize = 64;

/// A file named in `handoff/` that is removed on every way out (an abort, a lost claim, an
/// undelivered response) unless it is kept once its response was delivered.
struct HandoffFile {
    path: Option<std::path::PathBuf>,
    /// A file registered with the handoff root before its response (a window): removing the file
    /// also drops that registration.
    tracked: Option<(Arc<crate::provider_handoff::HandoffRoot>, String, ItemId, String)>,
}

impl HandoffFile {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path), tracked: None }
    }

    fn keep(&mut self) {
        self.path = None;
        self.tracked = None;
    }
}

impl Drop for HandoffFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let removed = match std::fs::remove_file(&path) {
                Ok(()) => true,
                Err(error) => error.kind() == std::io::ErrorKind::NotFound,
            };
            if let Some((root, root_id, item, name)) = self.tracked.take() {
                if removed {
                    root.forget_delivered(&root_id, &item, &name);
                } else if tokio::runtime::Handle::try_current().is_ok() {
                    // Still on disk: it stays tracked (a newer version revokes it) and its
                    // lifetime sweep retries the removal.
                    root.sweep_later(root_id, item, name);
                }
            }
        }
    }
}

/// What a finished request leaves to do after its response was sent.
struct Handoff {
    root: String,
    item: ItemId,
    name: String,
    version: VersionHash,
    file: HandoffFile,
    /// The file holds a window of the version, not the version.
    ranged: bool,
}

/// Test seams: a hook keyed by (point, key) that can stall or interfere at a named point.
#[cfg(test)]
pub(crate) type HookFn =
    Arc<dyn Fn() -> crate::application::ports::BoxFuture<'static, ()> + Send + Sync>;

#[cfg(test)]
pub(crate) static HOOKS: Mutex<Option<HashMap<(&'static str, String), HookFn>>> = Mutex::new(None);

#[cfg(test)]
async fn hook(point: &'static str, key: &[u8]) {
    let found = HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .and_then(|hooks| hooks.get(&(point, hex::encode(key))).cloned());
    if let Some(found) = found {
        found().await;
    }
}

/// Handles the materialization messages of a connection. Returns true when `msg` was one.
pub(crate) fn materialize_message(
    context: &Arc<ShellContext>,
    requests: &MaterializeRequests,
    reply: &Reply,
    msg: &ShellIpcMessage,
) -> bool {
    match &msg.payload {
        Some(Payload::MaterializeToTempRequest(request)) => {
            start(context, requests, reply, request.clone());
            true
        }
        Some(Payload::MaterializeCancel(MaterializeCancel { request_id })) => {
            let claimed = requests
                .inflight
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get_mut(&registry_key(KIND_MATERIALIZE, request_id))
                .and_then(Option::take);
            // A request that already answered (or was cancelled) has nothing to cancel: its
            // entry is gone, so exactly one terminal response is ever sent.
            if let Some(handle) = claimed {
                handle.abort();
                send_plain(
                    reply,
                    response(request_id, Err((MaterializeFailure::Cancelled, "cancelled".into()))),
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
    reply: &Reply,
    request: MaterializeToTempRequest,
) {
    let id = request.request_id.clone();
    // Spawn and register under one lock: the task's own claim waits for it.
    let mut inflight = requests.inflight.lock().unwrap_or_else(|p| p.into_inner());
    // A bounded number of requests per connection (each is a task, and a waiting one holds no
    // slot): beyond it the extension is told to come back later.
    if inflight.len() >= MAX_INFLIGHT_REQUESTS {
        send_plain(
            reply,
            response(
                &id,
                Err((MaterializeFailure::NotReady, "too many requests in flight".into())),
            ),
        );
        return;
    }
    if inflight.contains_key(&registry_key(KIND_MATERIALIZE, &id)) {
        send_plain(
            reply,
            response(
                &id,
                Err((MaterializeFailure::NotFound, "that request id is already in flight".into())),
            ),
        );
        return;
    }
    let (context, reply, registry) = (context.clone(), reply.clone(), requests.inflight.clone());
    let task_id = id.clone();
    let reserved =
        ReservedId { registry: registry.clone(), id: registry_key(KIND_MATERIALIZE, &id) };
    let handle = tokio::spawn(async move {
        let _reserved = reserved;
        let progress = request.report_progress.then(|| Arc::new(AssemblyProgress::default()));
        let outcome = match &progress {
            Some(progress) => run_reporting(&context, &request, progress, &reply).await,
            None => run(&context, &request, None).await,
        };
        if let Err((failure, error)) = &outcome {
            // The message can quote a path: debug only.
            tracing::debug!(%error, "the failed provider fetch's message");
            tracing::warn!(?failure, "a provider fetch failed");
        }
        #[cfg(test)]
        hook("before_claim", &task_id).await;
        // The one terminal transition: only the side that removes the entry answers.
        let claimed = registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&registry_key(KIND_MATERIALIZE, &task_id))
            .and_then(Option::take);
        if claimed.is_none() {
            // A cancel answered first; the file this request named in `handoff/` is dropped
            // (and so removed) with `outcome`.
            return;
        }
        match outcome {
            Err(failure) => send_plain(&reply, response(&task_id, Err(failure))),
            Ok((answer, handoff)) => {
                // The last progress message: the content is verified. Queued before the
                // response on the same channel, so it cannot arrive after it.
                if let Some(progress) = &progress {
                    progress.finish();
                    if let Some((completed, total)) = progress.snapshot() {
                        send_plain(&reply, progress_message(&task_id, completed, total, true));
                    }
                }
                // Delivered means the framed write completed, not that it was queued.
                if send_and_wait(&reply, response(&task_id, Ok(answer))).await {
                    after_response(&context, handoff);
                }
                // else nobody was told about the file: it is not a handoff, and dropping it
                // removes it.
            }
        }
    });
    inflight.insert(registry_key(KIND_MATERIALIZE, &id), Some(handle.abort_handle()));
}

/// The handoff is recorded only now: a response that was never delivered leaves no ledger entry.
///
/// If the item moved on to another version between the final check and the OS taking the file,
/// the OS may now hold the old bytes while the publication of the new version has already run
/// (it evicted nothing, because nothing was there yet). The presence-evidence ledger refuses the stale handoff, and
/// the item is put back to "published at the version that was handed over", so the ordinary
/// pending state evicts it and signals the new version again.
fn after_response(context: &ShellContext, mut handoff: Handoff) {
    // Registered BEFORE the presence-evidence ledger is written: a newer version of the item that commits from now
    // on finds the file and revokes it before it evicts. One that committed earlier is seen by
    // the presence-evidence ledger (below) and the file is dropped here.
    if handoff.ranged {
        // The OS gets a window of the bytes, never the file: no handoff is recorded, so the item
        // stays "not present" and nothing may evict or reclaim on the strength of it. Nor is the
        // content recorded as served: that summary vouches for a whole version's content, which
        // a window is not. The file has been registered for revocation since before the response
        // was sent (see `run`); here it only ages out like any unconsumed handoff.
        handoff.file.keep();
        if let Some(root) = context.handoff.get() {
            root.sweep_later(handoff.root.clone(), handoff.item, handoff.name.clone());
        }
        return;
    }
    if let Some(root) = context.handoff.get() {
        root.note_delivered(&handoff.root, handoff.item, &handoff.name);
    }
    match crate::provider_evidence::record_handoff(
        &context.replica_coordinator,
        &context.provider_host,
        &handoff.root,
        &handoff.item,
        handoff.version,
    ) {
        Ok(Some(_)) => {
            handoff.file.keep();
            if let Some(root) = context.handoff.get() {
                root.sweep_later(handoff.root.clone(), handoff.item, handoff.name.clone());
            }
        }
        Ok(None) => {
            // The item moved on: the file is dropped (and so removed) when `handoff` goes out of
            // scope, if the OS has not taken it, and the item goes back to "published at the
            // version handed over" so that, if it did, the ordinary pending state evicts it.
            let repo = context.replica_coordinator.provider_repository();
            match repo.reopen_stale_handoff(&handoff.root, &handoff.item, handoff.version) {
                Ok(true) => context.publication.kick(&handoff.root),
                Ok(false) => {}
                Err(error) => tracing::warn!(%error, "could not re-fence a stale provider handoff"),
            }
        }
        Err(error) => {
            tracing::warn!(%error, "could not record a provider handoff; the item stays not present");
        }
    }
}

struct Answer {
    name: String,
    version: VersionHash,
    generation: u64,
    size: u64,
    range: Option<ByteRange>,
}

/// How often a changed progress is sent.
const PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

fn progress_message(request_id: &[u8], completed: u64, total: u64, done: bool) -> ShellIpcMessage {
    ShellIpcMessage {
        payload: Some(Payload::MaterializeProgress(MaterializeProgress {
            request_id: request_id.to_vec(),
            completed,
            total,
            done,
        })),
    }
}

/// [`run`], sending the request's progress while it runs whenever it changed. Everything runs in
/// the request's own task, so a cancel that aborts it stops the reports with it.
async fn run_reporting(
    context: &ShellContext,
    request: &MaterializeToTempRequest,
    progress: &Arc<AssemblyProgress>,
    reply: &Reply,
) -> Result<(Answer, Handoff), Failure> {
    let work = run(context, request, Some(progress.clone()));
    tokio::pin!(work);
    let mut ticker = tokio::time::interval(PROGRESS_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last = None;
    loop {
        tokio::select! {
            outcome = &mut work => return outcome,
            _ = ticker.tick() => {
                let now = progress.snapshot();
                if now != last {
                    if let Some((completed, total)) = now {
                        send_plain(reply, progress_message(&request.request_id, completed, total, false));
                    }
                    last = now;
                }
            }
        }
    }
}

async fn run(
    context: &ShellContext,
    request: &MaterializeToTempRequest,
    progress: Option<Arc<AssemblyProgress>>,
) -> Result<(Answer, Handoff), Failure> {
    let fail = |failure, text: &str| -> Failure { (failure, text.to_string()) };
    let Some(handoff_root) = context.handoff.get() else {
        return Err(fail(MaterializeFailure::NotReady, "no temp root is configured"));
    };
    let Some(name) = handoff_root.name_for(&request.request_id) else {
        return Err(fail(MaterializeFailure::NotFound, "invalid request id"));
    };
    let root = hex::encode(&request.root_id);
    let repo = context.replica_coordinator.provider_repository();
    let declared = repo
        .list_declared_roots()
        .map_err(|e| fail(MaterializeFailure::NotReady, &e.to_string()))?;
    let Some(declared) = declared.into_iter().find(|r| r.root_id == root) else {
        return Err(fail(MaterializeFailure::NotFound, "unknown provider root"));
    };
    if !matches!(declared.readiness(), yadorilink_replica_domain::session_state::Readiness::Ready) {
        return Err(fail(MaterializeFailure::NotReady, "the provider root is not ready"));
    }
    let item: ItemId = request
        .item_id
        .as_slice()
        .try_into()
        .map_err(|_| fail(MaterializeFailure::NotFound, "invalid item id"))?;
    let requested = match request.requested_version_hash.as_slice() {
        [] => None,
        bytes => Some(VersionHash(
            bytes.try_into().map_err(|_| fail(MaterializeFailure::NotFound, "invalid version"))?,
        )),
    };
    // A window is only meaningful for one exact version: bytes of "whatever is current" could
    // not be told apart from another version's.
    let range = match (request.ranged, requested) {
        (false, _) => None,
        (true, Some(_)) => {
            Some(ByteRange { offset: request.range_offset, len: request.range_length })
        }
        (true, None) => {
            return Err(fail(
                MaterializeFailure::RangeNotSatisfiable,
                "a ranged request must name the version",
            ));
        }
    };
    match fetch_gate(&context.replica_coordinator, &root, &item)
        .map_err(|e| fail(MaterializeFailure::NotFound, &e.to_string()))?
    {
        FetchGate::Allowed => {}
        FetchGate::PublicationPending => {
            return Err(fail(
                MaterializeFailure::PublicationPending,
                "a newer version is being published",
            ));
        }
        FetchGate::NotFound => return Err(fail(MaterializeFailure::NotFound, "unknown item")),
    }
    let path = match repo.path_for_item(&root, &item) {
        Ok(Some((path, true))) => path,
        _ => return Err(fail(MaterializeFailure::NotFound, "the item is gone")),
    };
    let staging_file = handoff_root.staging_file(&name);
    // The version this attempt is for: a failure is charged to it, never to a newer one.
    let attempted = repo.current_version_hash(&root, &item).ok().flatten();
    // A slot among the daemon-wide assemblies. An item the Eager driver handed out takes one of
    // the Eager class only, so the user's own fetches always have slots left.
    // Counted as requested content from here, so an open queued for a slot is not idle.
    let _requested = context.requested_opens.begin(&declared.group_id);
    let eager = context.eager.was_requested(&root, &item);
    let permits = context.eager.limiter.acquire(eager).await;
    let assembled = context
        .application
        .materialization
        .materialize_to_temp(TempMaterialization {
            group_id: &declared.group_id,
            path: &path,
            requested_version: requested,
            staging_file: &staging_file,
            range,
            progress,
        })
        .await
        .map_err(failure_of);
    drop(permits);
    // Content nobody could supply is a failure of this version (backoff for the Eager driver);
    // content that arrived clears it.
    match &assembled {
        Err((MaterializeFailure::Unobtainable, _)) => {
            if let Some(attempted) = attempted {
                context.eager.record_failure(&context.replica_coordinator, &root, &item, attempted);
            }
        }
        // A window is not the content the Eager driver is after.
        Ok(TempOutcome::Assembled(assembled)) if assembled.range.is_none() => {
            context.eager.record_success(&context.replica_coordinator, &root, &item);
        }
        _ => {}
    }
    let assembled = assembled?;
    let assembled = match assembled {
        TempOutcome::Assembled(assembled) => assembled,
        TempOutcome::VersionOutOfDate => {
            return Err(fail(MaterializeFailure::VersionOutOfDate, "the version is not current"));
        }
        TempOutcome::RangeNotSatisfiable => {
            return Err(fail(
                MaterializeFailure::RangeNotSatisfiable,
                "the range starts past the end of the version",
            ));
        }
    };
    // From here nothing awaits until the response is sent. The item must still be at the version
    // that was assembled, and not behind a newer pending one, right before it is named.
    if !matches!(
        repo.current_version_hash(&root, &item),
        Ok(Some(current)) if current == assembled.version_hash
    ) {
        let _ = std::fs::remove_file(&assembled.assembled);
        return Err(fail(MaterializeFailure::VersionOutOfDate, "the version is not current"));
    }
    if !matches!(fetch_gate(&context.replica_coordinator, &root, &item), Ok(FetchGate::Allowed)) {
        let _ = std::fs::remove_file(&assembled.assembled);
        return Err(fail(
            MaterializeFailure::PublicationPending,
            "a newer version is being published",
        ));
    }
    // A file that does not hold exactly the bytes the response will name is never handed over
    // since the OS would otherwise take a short file for the whole item.
    let on_disk = std::fs::metadata(&assembled.assembled).map(|m| m.len()).ok();
    if assembled.range.is_none() && on_disk != Some(assembled.size) {
        let _ = std::fs::remove_file(&assembled.assembled);
        return Err((
            MaterializeFailure::Unobtainable,
            "the assembled file does not hold the version's bytes".into(),
        ));
    }
    #[cfg(test)]
    hook("final_gap", &item).await;
    // BEFORE anything may reach the OS: the content we MAY HAVE handed over is recorded durably
    // and monotonically (the item's sticky served summary), and the transaction has committed
    // before the file is named to anyone. If it fails, nothing is served. Nothing later (a
    // failed send, a restart, a signal) ever un-records it. A window is not a whole version's
    // content: it records nothing and is paired with no generation (the version was checked
    // current just above, and again after the response is sent).
    let generation = if assembled.range.is_some() {
        0
    } else {
        match repo.record_may_serve(&root, &item, assembled.version_hash) {
            Ok(Some(generation)) => generation,
            Ok(None) => {
                let _ = std::fs::remove_file(&assembled.assembled);
                return Err(fail(
                    MaterializeFailure::VersionOutOfDate,
                    "the version is not current",
                ));
            }
            Err(error) => {
                let _ = std::fs::remove_file(&assembled.assembled);
                return Err((MaterializeFailure::Unobtainable, error.to_string()));
            }
        }
    };
    handoff_root
        .publish(&assembled.assembled, &name)
        .map_err(|e| (MaterializeFailure::Unobtainable, e.to_string()))?;
    let mut file = HandoffFile::new(handoff_root.handoff_file(&name));
    if assembled.range.is_some() {
        // A window records no served content, so a newer version's publication finds it only
        // through this registration: it is made BEFORE the response can be read, and the version
        // is checked again with it in place. A version that commits after this check revokes the
        // file; one that committed before is seen here. On any failure `file` removes both the
        // file and the registration.
        handoff_root.note_delivered(&root, item, &name);
        file.tracked = Some((handoff_root.clone(), root.clone(), item, name.clone()));
        if !matches!(
            repo.current_version_hash(&root, &item),
            Ok(Some(current)) if current == assembled.version_hash
        ) {
            return Err(fail(MaterializeFailure::VersionOutOfDate, "the version is not current"));
        }
        if !matches!(fetch_gate(&context.replica_coordinator, &root, &item), Ok(FetchGate::Allowed))
        {
            return Err(fail(
                MaterializeFailure::PublicationPending,
                "a newer version is being published",
            ));
        }
    }
    Ok((
        Answer {
            name: name.clone(),
            version: assembled.version_hash,
            generation,
            size: assembled.size,
            range: assembled.range,
        },
        Handoff {
            file,
            root,
            item,
            name,
            version: assembled.version_hash,
            ranged: assembled.range.is_some(),
        },
    ))
}

/// The reason a failed hydration is reported under: a missing file, a full disk, or content no
/// reachable peer could supply.
fn failure_of(error: SyncError) -> Failure {
    match error {
        SyncError::NotFound(message) => (MaterializeFailure::NotFound, message),
        SyncError::DiskPressure { .. } => (MaterializeFailure::LowDisk, error.to_string()),
        other => (MaterializeFailure::Unobtainable, other.to_string()),
    }
}

fn response(request_id: &[u8], answer: Result<Answer, Failure>) -> ShellIpcMessage {
    let message = match answer {
        Ok(answer) => MaterializeToTempResponse {
            request_id: request_id.to_vec(),
            ok: true,
            failure: MaterializeFailure::None as i32,
            error: String::new(),
            handoff_name: answer.name,
            version_hash: answer.version.0.to_vec(),
            size: answer.size,
            // A window is paired with no generation: only a whole-version handoff is.
            content_version: if answer.range.is_some() {
                Vec::new()
            } else {
                super::provider_enumerate::versioned(&answer.version.0, answer.generation)
            },
            ranged: answer.range.is_some(),
            range_offset: answer.range.map_or(0, |r| r.offset),
            range_length: answer.range.map_or(0, |r| r.len),
        },
        Err((failure, error)) => MaterializeToTempResponse {
            request_id: request_id.to_vec(),
            ok: false,
            failure: failure as i32,
            error,
            handoff_name: String::new(),
            version_hash: Vec::new(),
            size: 0,
            content_version: Vec::new(),
            ranged: false,
            range_offset: 0,
            range_length: 0,
        },
    };
    ShellIpcMessage { payload: Some(Payload::MaterializeToTempResponse(message)) }
}

#[cfg(test)]
mod tests;
