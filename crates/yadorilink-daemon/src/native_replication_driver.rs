//! The async driver of native replication for one peer connection: both
//! roles at once. It *serves* every stream the peer opens (answering
//! requests, ingesting pushed delta batches) and *reconciles* on demand
//! (asks the peer for its summary and frontier diff; the peer's answer
//! pushes the missing deltas back on streams of their own, which this
//! side's serve loop ingests). The synchronous decisions live in
//! [`crate::native_replication_session`]; this module only moves bytes and
//! keeps each database call short and synchronous.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::history_truncation::RetainedSummary;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::protocol5::{self, Message, RefusalReason};
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::native_replication;
use yadorilink_sync_substrate::{NativeReplicationConnection, NativeReplicationWriter};

use crate::native_recovery::RecoveryPort;
use crate::native_replication_session::{
    self as session, IngestReport, PeerAccess, RecoveryChunkIn, ReplicationError,
};

/// How long a stream may take to read or flush before it is abandoned.
const STREAM_STEP: Duration = Duration::from_secs(30);

/// Streams one connection may have in flight at once. Beyond it the
/// accept loop stops accepting, so a peer that floods requests waits on the
/// transport's own stream limit instead of multiplying work here.
const STREAMS_IN_FLIGHT: usize = 8;

type SharesGroup = dyn Fn(&FolderGroupId) -> bool + Send + Sync;
type KeyLookup = dyn Fn(&AuthorId) -> Option<VerifyingKey> + Send + Sync;
type AuthorityLookup =
    dyn Fn(&FolderGroupId, &[u8; 32], &[u8; 32]) -> Option<VerifyingKey> + Send + Sync;
type PolicyPointLookup = session::GroupPolicyPointFor<'static>;
/// What a connection reports when its peer no longer holds the history this replica needs: the
/// checkpoint the peer's retained history begins at, when it names one.
pub type TruncationNote = dyn Fn(&FolderGroupId, Option<RetainedSummary>) + Send + Sync;
type GroupsToSync = dyn Fn() -> Vec<FolderGroupId> + Send + Sync;
pub type ActivitySignal = dyn Fn() + Send + Sync;

/// What a peer connection needs from the daemon, as plain closures so the
/// driver depends on no daemon state type.
#[derive(Clone)]
pub struct ReplicationEnv {
    pub db: Arc<SyncDatabase>,
    /// This device's id, naming whose join timeline a milestone belongs to.
    pub local_device_id: String,
    /// Whether `group` is hosted here and shared with this peer.
    pub shares_group: Arc<SharesGroup>,
    pub key_for: Arc<KeyLookup>,
    pub authority_key: Arc<AuthorityLookup>,
    /// Whether the group's verified policy chain vouches for a checkpoint's
    /// pinned policy point.
    pub policy_point: Arc<PolicyPointLookup>,
    /// The groups to reconcile with this peer.
    pub groups: Arc<GroupsToSync>,
    /// Sealing this device's state for the peer, and joining a state the peer
    /// sealed.
    pub recovery: Arc<dyn RecoveryPort>,
    /// Recovery bundles being received from this peer, and when each group
    /// last asked for one.
    pub recovery_state: Arc<RecoveryState>,
    /// Called each time this peer's traffic changed this replica: a delta
    /// batch admitted at least one delta, or a recovery bundle was joined.
    /// The daemon feeds its idle detector from it.
    pub activity: Arc<ActivitySignal>,
    /// Called as soon as this peer refuses a request because it no longer holds the history
    /// this replica needs, before anything is asked of it in answer, so the record is there
    /// when the sealed state it then sends arrives.
    pub truncated: Arc<TruncationNote>,
}

/// The longest a partly received bundle is kept, and the most of them.
const ASSEMBLY_TTL: Duration = Duration::from_secs(300);
const MAX_ASSEMBLIES: usize = 4;
/// The most bytes one requested bundle may total, and the most a connection
/// holds in partly received bundles at once: below what the chunk limits alone
/// would allow, so a peer cannot pin the protocol's worst case.
const MAX_REQUEST_BYTES: usize = 256 * 1024 * 1024;
const MAX_ASSEMBLING_BYTES: usize = 512 * 1024 * 1024;
/// How long a group waits before asking the same peer for recovery again.
const RECOVERY_COOLDOWN: Duration = Duration::from_secs(60);
/// How soon this side serves the same group's recovery to the same peer again.
/// Sealing takes the writer gate and a coordination round trip, so a member
/// (a viewer included) must not be able to make it repeat without limit; it is
/// shorter than [`RECOVERY_COOLDOWN`] so an honest requester is never refused.
const SERVE_RECOVERY_COOLDOWN: Duration = Duration::from_secs(30);

struct Partial {
    count: u32,
    chunks: std::collections::BTreeMap<u32, Vec<u8>>,
    bytes: usize,
    started: std::time::Instant,
}

/// A recovery request this side issued and has not seen answered.
struct Outstanding {
    group: String,
    issued: std::time::Instant,
}

/// Per-connection recovery bookkeeping.
#[derive(Default)]
pub struct RecoveryState {
    assembling: std::sync::Mutex<std::collections::HashMap<([u8; 16], String), Partial>>,
    asked: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// When this side last began sealing a group's state for this peer.
    served: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// The requests this connection issued: a chunk is accepted only for one of
    /// them, so a peer cannot make this side buffer a bundle nobody asked for.
    outstanding: std::sync::Mutex<std::collections::HashMap<[u8; 16], Outstanding>>,
    dropped: std::sync::atomic::AtomicU64,
}

impl RecoveryState {
    /// Adds one chunk of a requested bundle; the whole bundle's bytes once every
    /// chunk is in. A chunk for a request this side did not issue (or that has
    /// finished, failed or expired) is dropped.
    fn add(&self, chunk: RecoveryChunkIn) -> Option<(FolderGroupId, Vec<u8>)> {
        let key = (chunk.request_id.0, chunk.group_id.0.clone());
        let mut outstanding = self.outstanding.lock().unwrap_or_else(|p| p.into_inner());
        outstanding.retain(|_, request| request.issued.elapsed() < ASSEMBLY_TTL);
        let solicited =
            outstanding.get(&key.0).is_some_and(|request| request.group == chunk.group_id.0);
        if !solicited {
            drop(outstanding);
            self.note_dropped(&chunk);
            return None;
        }
        let mut assembling = self.assembling.lock().unwrap_or_else(|p| p.into_inner());
        assembling.retain(|key, partial| {
            partial.started.elapsed() < ASSEMBLY_TTL && outstanding.contains_key(&key.0)
        });
        let held: usize = assembling.values().map(|partial| partial.bytes).sum();
        if !assembling.contains_key(&key) && assembling.len() >= MAX_ASSEMBLIES {
            return None;
        }
        let partial = assembling.entry(key.clone()).or_insert_with(|| Partial {
            count: chunk.count,
            chunks: Default::default(),
            bytes: 0,
            started: std::time::Instant::now(),
        });
        let added = if partial.chunks.contains_key(&chunk.index) { 0 } else { chunk.bytes.len() };
        if partial.count != chunk.count
            || partial.bytes + added > MAX_REQUEST_BYTES
            || held + added > MAX_ASSEMBLING_BYTES
        {
            assembling.remove(&key);
            outstanding.remove(&key.0);
            return None;
        }
        if partial.chunks.insert(chunk.index, chunk.bytes).is_none() {
            partial.bytes += added;
        }
        if partial.chunks.len() as u32 != partial.count {
            return None;
        }
        let partial = assembling.remove(&key)?;
        outstanding.remove(&key.0);
        Some((chunk.group_id, partial.chunks.into_values().flatten().collect()))
    }

    fn note_dropped(&self, chunk: &RecoveryChunkIn) {
        let dropped = self.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if dropped.is_multiple_of(100) {
            tracing::warn!(
                group = %chunk.group_id.0,
                dropped = dropped + 1,
                "native recovery: dropped a chunk of a bundle this device did not ask for"
            );
        }
    }

    /// Whether `group` may ask now; when it may, records the ask and registers
    /// the request id the answer must carry.
    fn begin(&self, group: &FolderGroupId) -> Option<protocol5::RequestId> {
        let mut asked = self.asked.lock().unwrap_or_else(|p| p.into_inner());
        if asked.get(&group.0).is_some_and(|at| at.elapsed() < RECOVERY_COOLDOWN) {
            return None;
        }
        asked.insert(group.0.clone(), std::time::Instant::now());
        let request_id = session::new_request_id();
        let mut outstanding = self.outstanding.lock().unwrap_or_else(|p| p.into_inner());
        outstanding.retain(|_, request| request.issued.elapsed() < ASSEMBLY_TTL);
        outstanding.insert(
            request_id.0,
            Outstanding { group: group.0.clone(), issued: std::time::Instant::now() },
        );
        Some(request_id)
    }

    /// Whether this side may seal `group` for this peer now; when it may,
    /// records that it did.
    fn admit_serve(&self, group: &FolderGroupId) -> bool {
        let mut served = self.served.lock().unwrap_or_else(|p| p.into_inner());
        if served.get(&group.0).is_some_and(|at| at.elapsed() < SERVE_RECOVERY_COOLDOWN) {
            return false;
        }
        served.insert(group.0.clone(), std::time::Instant::now());
        true
    }

    /// A serve that failed sealed nothing for this peer, so its retry is not a repeat.
    fn forget_serve(&self, group: &FolderGroupId) {
        self.served.lock().unwrap_or_else(|p| p.into_inner()).remove(&group.0);
    }

    /// Forgets a request that will not be answered.
    /// The ask that never reached an answer does not count against the cooldown: the next
    /// reconcile round may ask again at once.
    fn abandon(&self, request_id: protocol5::RequestId) {
        let issued =
            self.outstanding.lock().unwrap_or_else(|p| p.into_inner()).remove(&request_id.0);
        if let Some(issued) = issued {
            self.asked.lock().unwrap_or_else(|p| p.into_inner()).remove(&issued.group);
        }
        self.assembling
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|key, _| key.0 != request_id.0);
    }
}

impl ReplicationEnv {
    fn answer(&self, bytes: &[u8]) -> Result<session::Answer, ReplicationError> {
        let access = PeerAccess {
            shares_group: &*self.shares_group,
            key_for: &*self.key_for,
            authority_key: &*self.authority_key,
            policy_point: &*self.policy_point,
        };
        let message = protocol5::decode_message(bytes)?;
        // Only a delta batch writes. Everything else is answered from one read
        // snapshot, so a peer's request (whose cost grows with what it names)
        // never holds the writer gate other work waits on.
        if session::answer_writes(&message) {
            // The closure may run again: the database retries a transient lock, and
            // `to_sqlite` keeps such an error recognisable for exactly that.
            self.db
                .write(|conn| {
                    session::answer_message(conn, &access, message.clone()).map_err(to_sqlite)
                })
                .map_err(ReplicationError::Storage)
        } else {
            self.db
                .read_snapshot(|conn| {
                    session::answer_message(conn, &access, message.clone()).map_err(to_sqlite)
                })
                .map_err(ReplicationError::Storage)
        }
    }
}

/// A database closure's error type: the session error, flattened. A storage error is passed
/// through as it is, not turned into text: the database retries a closure only when its error
/// is a transient `SQLITE_LOCKED`/`SQLITE_BUSY`, and flattening that into a string made a table
/// lock another connection held for a moment fail the whole answer, so the peer's round failed
/// and was retried only after the unproductive-round backoff (seconds).
fn to_sqlite(error: ReplicationError) -> yadorilink_sync_sqlite::SyncSqliteError {
    match error {
        ReplicationError::Storage(error) => error,
        other => yadorilink_sync_sqlite::SyncSqliteError::CorruptState(other.to_string()),
    }
}

/// Writes `bytes` and finishes the stream, all within [`STREAM_STEP`]: a
/// peer that stops reading cannot hold a task (or anything the task waits
/// on) for longer.
async fn send_and_finish(writer: &mut NativeReplicationWriter, bytes: &[u8]) -> bool {
    let sent = tokio::time::timeout(STREAM_STEP, async {
        if writer.write_all(bytes).await.is_err() || writer.finish().is_err() {
            return false;
        }
        writer.flushed(STREAM_STEP).await;
        true
    })
    .await;
    sent.unwrap_or(false)
}

/// Serves `connection` until it ends: each stream the peer opens carries one
/// message. Streams are handled concurrently, so a slow batch does not
/// block a summary.
pub async fn serve(env: ReplicationEnv, connection: NativeReplicationConnection) {
    let in_flight = Arc::new(tokio::sync::Semaphore::new(STREAMS_IN_FLIGHT));
    loop {
        let Ok(permit) = in_flight.clone().acquire_owned().await else { break };
        let Ok((writer, reader)) = connection.accept_stream().await else { break };
        let (env, connection) = (env.clone(), connection.clone());
        tokio::spawn(async move {
            serve_stream(env, connection, writer, reader).await;
            drop(permit);
        });
    }
}

async fn serve_stream(
    env: ReplicationEnv,
    connection: NativeReplicationConnection,
    mut writer: NativeReplicationWriter,
    mut reader: yadorilink_sync_substrate::NativeReplicationReader,
) {
    let read =
        tokio::time::timeout(STREAM_STEP, reader.read_to_end(protocol5::MAX_MESSAGE_BYTES)).await;
    let Ok(Ok(bytes)) = read else { return };
    // Database work runs on a blocking thread, never on an async worker.
    let answering = env.clone();
    let answered = tokio::task::spawn_blocking(move || answering.answer(&bytes)).await;
    let answer = match answered {
        Ok(Ok(answer)) => answer,
        Ok(Err(error)) => {
            tracing::warn!(%error, "native replication: a message could not be answered");
            return;
        }
        Err(_) => return,
    };
    if let Some(report) = &answer.ingested {
        log_ingest(report);
        if report.admitted > 0 {
            yadorilink_fs_platform::join_timeline::mark(
                &env.local_device_id,
                &report.group,
                yadorilink_fs_platform::join_timeline::Milestone::MetadataAdmitted,
            );
            (env.activity)();
        }
    }
    if let Some(request_id) = answer.recovery_refused {
        env.recovery_state.abandon(request_id);
        return;
    }
    if let Some(chunk) = answer.recovery_chunk {
        if let Some((group, bundle)) = env.recovery_state.add(chunk) {
            let (port, group_owned) = (env.recovery.clone(), group.clone());
            let applied =
                tokio::task::spawn_blocking(move || port.apply(&group_owned, &bundle)).await;
            match applied {
                Ok(Ok(changed)) => {
                    yadorilink_fs_platform::join_timeline::mark(
                        &env.local_device_id,
                        &group.0,
                        yadorilink_fs_platform::join_timeline::Milestone::SealedStateApplied,
                    );
                    (env.activity)();
                    tracing::info!(group = %group.0, changed, "native recovery: joined a peer's sealed state");
                }
                Ok(Err(error)) => {
                    tracing::warn!(group = %group.0, %error, "native recovery: a peer's sealed state was refused");
                }
                Err(_) => {}
            }
        }
        return;
    }
    if let Some((request_id, group)) = answer.recovery_request {
        if !env.recovery_state.admit_serve(&group) {
            let refusal = protocol5::encode_message(&Message::Refused {
                request_id,
                reason: protocol5::RefusalReason::Overloaded,
            });
            if let Ok(refusal) = refusal {
                send_and_finish(&mut writer, &refusal).await;
            }
            return;
        }
        // The requester's stream is answered at once; sealing waits on the
        // authority and the bundle follows as pushes.
        let _ = writer.finish();
        serve_recovery(&env, &connection, request_id, &group).await;
        return;
    }
    if let Some(reply) = answer.reply {
        send_and_finish(&mut writer, &reply).await;
    }
    for push in answer.pushes {
        // Access is asked again before every batch: a peer that loses the
        // group while a long answer is being sent gets no further deltas.
        if let Some(group) = &answer.push_group {
            if !(env.shares_group)(group) {
                return;
            }
        }
        if !push_message(&connection, &push).await {
            return;
        }
    }
}

/// Seals this device's state of `group` and pushes it to the peer in chunks.
async fn serve_recovery(
    env: &ReplicationEnv,
    connection: &NativeReplicationConnection,
    request_id: protocol5::RequestId,
    group: &FolderGroupId,
) {
    let bundle = match env.recovery.serve(group).await {
        Ok(bundle) => bundle,
        Err(reason) => {
            tracing::debug!(group = %group.0, ?reason, "native recovery: could not serve a peer");
            env.recovery_state.forget_serve(group);
            // The request was accepted, so the peer is waiting for a bundle: say it will not
            // come, instead of leaving the peer to wait out its ask cooldown.
            if let Ok(refusal) = protocol5::encode_message(&Message::Refused { request_id, reason })
            {
                push_message(connection, &refusal).await;
            }
            return;
        }
    };
    let chunks: Vec<&[u8]> = bundle.chunks(protocol5::MAX_RECOVERY_CHUNK_BYTES - 1024).collect();
    if chunks.len() as u32 > protocol5::MAX_RECOVERY_CHUNKS {
        tracing::warn!(group = %group.0, bytes = bundle.len(), "native recovery: the bundle is too large to send");
        return;
    }
    let count = chunks.len() as u32;
    for (index, bytes) in chunks.into_iter().enumerate() {
        if !(env.shares_group)(group) {
            return;
        }
        let Ok(message) = protocol5::encode_message(&Message::RecoveryChunk {
            request_id,
            group_id: group.clone(),
            index: index as u32,
            count,
            bytes: bytes.to_vec(),
        }) else {
            return;
        };
        if !push_message(connection, &message).await {
            return;
        }
    }
}

/// Asks the peer to seal its state of `group` for this device. One ask per
/// group per cooldown; the bundle arrives as pushes this side's serve loop
/// assembles and joins.
pub async fn request_recovery(
    env: &ReplicationEnv,
    connection: &NativeReplicationConnection,
    group: &FolderGroupId,
) -> bool {
    // A group whose rebootstrap runs has the state it is installing: another sealed state
    // would only be refused.
    let (db, group_owned) = (env.db.clone(), group.clone());
    let running = tokio::task::spawn_blocking(move || {
        db.read(|conn| {
            yadorilink_sync_sqlite::native_rebootstrap::rebootstrap_status(conn, &group_owned)
                .map(|status| status.is_some())
        })
    })
    .await;
    if !matches!(running, Ok(Ok(false))) {
        return false;
    }
    let Some(request_id) = env.recovery_state.begin(group) else {
        return false;
    };
    let asked = ask_recovery(connection, request_id, group).await;
    if !asked {
        env.recovery_state.abandon(request_id);
    } else {
        yadorilink_fs_platform::join_timeline::mark(
            &env.local_device_id,
            &group.0,
            yadorilink_fs_platform::join_timeline::Milestone::RecoveryRequestAccepted,
        );
    }
    asked
}

async fn ask_recovery(
    connection: &NativeReplicationConnection,
    request_id: protocol5::RequestId,
    group: &FolderGroupId,
) -> bool {
    let Ok(bytes) = protocol5::encode_message(&Message::RecoveryRequest {
        request_id,
        group_id: group.clone(),
    }) else {
        return false;
    };
    let Ok(Ok((mut writer, mut reader))) =
        tokio::time::timeout(STREAM_STEP, connection.open_stream()).await
    else {
        return false;
    };
    if !send_and_finish(&mut writer, &bytes).await {
        return false;
    }
    // A refusal comes back on this stream; success is a stream that ends empty.
    let reply =
        tokio::time::timeout(STREAM_STEP, reader.read_to_end(protocol5::MAX_MESSAGE_BYTES)).await;
    match reply {
        Ok(Ok(bytes)) if recovery_request_accepted(&bytes) => true,
        Ok(Ok(bytes)) => {
            tracing::debug!(group = %group.0, reply = ?protocol5::decode_message(&bytes), "native recovery: the peer refused");
            false
        }
        _ => false,
    }
}

/// Sends `bytes` as one message on a stream of its own.
async fn push_message(connection: &NativeReplicationConnection, bytes: &[u8]) -> bool {
    let Ok(Ok((mut writer, _reader))) =
        tokio::time::timeout(STREAM_STEP, connection.open_stream()).await
    else {
        return false;
    };
    send_and_finish(&mut writer, bytes).await
}

fn log_ingest(report: &IngestReport) {
    if !report.rejected.is_empty() {
        tracing::warn!(rejected = ?report.rejected, "native replication: deltas were refused");
    }
    tracing::debug!(
        admitted = report.admitted,
        duplicates = report.duplicates,
        held = report.held,
        "native replication: delta batch ingested"
    );
}

/// What one reconcile round found for a group.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupRound {
    /// The peer's summary equals this replica's live state.
    InSync,
    /// The roots differ: a frontier diff was requested, and the peer will
    /// push what this side lacks (`newer` is how many authors are ahead).
    Requested { newer: usize },
    /// The roots differ although the peer is ahead of nothing here. Either this replica is ahead
    /// of a peer that has not pulled yet (the usual case, and it ends by itself), or the
    /// difference is not one deltas can repair (retirement, or a fork).
    Divergent,
    /// The peer refused (not a member, or no longer holds the history).
    Refused(RefusalReason),
    /// The exchange did not complete.
    Failed,
}

async fn request(connection: &NativeReplicationConnection, bytes: &[u8]) -> Option<Message> {
    let (mut writer, mut reader) =
        tokio::time::timeout(STREAM_STEP, connection.open_stream()).await.ok()?.ok()?;
    if !send_and_finish(&mut writer, bytes).await {
        return None;
    }
    let reply =
        tokio::time::timeout(STREAM_STEP, reader.read_to_end(protocol5::MAX_MESSAGE_BYTES)).await;
    protocol5::decode_message(&reply.ok()?.ok()?).ok()
}

/// One reconcile round for every group in `env.groups`.
pub async fn reconcile(
    env: &ReplicationEnv,
    connection: &NativeReplicationConnection,
) -> Vec<(FolderGroupId, GroupRound)> {
    let mut rounds = Vec::new();
    for group in (env.groups)() {
        let round = reconcile_group(env, connection, &group).await;
        rounds.push((group, round));
    }
    rounds
}

pub(crate) async fn reconcile_group(
    env: &ReplicationEnv,
    connection: &NativeReplicationConnection,
    group: &FolderGroupId,
) -> GroupRound {
    yadorilink_fs_platform::join_timeline::note_reconcile_round(&env.local_device_id, &group.0);
    // A round running means a session to this peer is usable for the group,
    // including one attached before the group was linked here.
    yadorilink_fs_platform::join_timeline::mark(
        &env.local_device_id,
        &group.0,
        yadorilink_fs_platform::join_timeline::Milestone::PeerSessionUsable,
    );
    yadorilink_fs_platform::join_timeline::mark(
        &env.local_device_id,
        &group.0,
        yadorilink_fs_platform::join_timeline::Milestone::FirstReconcileRound,
    );
    let Ok((_, summary_bytes)) = session::summary_request(group) else { return GroupRound::Failed };
    let Some(response) = request(connection, &summary_bytes).await else {
        return GroupRound::Failed;
    };
    if let Message::Refused { reason, .. } = response {
        return GroupRound::Refused(reason);
    }
    yadorilink_fs_platform::join_timeline::mark(
        &env.local_device_id,
        &group.0,
        yadorilink_fs_platform::join_timeline::Milestone::SummaryReceived,
    );
    let (db, group_owned) = (env.db.clone(), group.clone());
    let compared = tokio::task::spawn_blocking(move || {
        // Matching roots do not mean complete: a head whose content version
        // never arrived leaves the roots equal, so such a group is asked again.
        let in_sync = db.read(|conn| {
            let matches =
                session::summary_matches(conn, &group_owned, &response).map_err(to_sqlite)?;
            let unresolved = native_replication::unresolved_head_positions(conn, &group_owned)?;
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(matches && unresolved.is_empty())
        })?;
        if in_sync {
            return Ok(None);
        }
        db.read(|conn| session::frontier_diff_request(conn, &group_owned).map_err(to_sqlite))
            .map(Some)
    })
    .await;
    let diff_bytes = match compared {
        Ok(Ok(None)) => return GroupRound::InSync,
        Ok(Ok(Some((_, bytes)))) => bytes,
        _ => return GroupRound::Failed,
    };
    // A replica that holds nothing, or that a verified closure has put out of step with its
    // peers' history, takes the peer's sealed state first; the frontier diff below still runs
    // and fills in whatever it can.
    let (db, group_owned) = (env.db.clone(), group.clone());
    let needs_sealed_state = tokio::task::spawn_blocking(move || {
        db.read(|conn| {
            let holds_nothing = native_replication::frontier_entries(conn, &group_owned, false)
                .map(|entries| entries.is_empty())
                .map_err(|error| {
                    yadorilink_sync_sqlite::SyncSqliteError::CorruptState(error.to_string())
                })?;
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(
                holds_nothing
                    || !yadorilink_sync_sqlite::native_closure::needs_rebootstrap(
                        conn,
                        &group_owned,
                    )?
                    .is_empty(),
            )
        })
    })
    .await;
    if matches!(needs_sealed_state, Ok(Ok(true))) {
        request_recovery(env, connection, group).await;
    }
    let diff_reply = request(connection, &diff_bytes).await;
    if diff_reply.is_some() {
        yadorilink_fs_platform::join_timeline::mark(
            &env.local_device_id,
            &group.0,
            yadorilink_fs_platform::join_timeline::Milestone::FrontierDiffAnswered,
        );
    }
    match diff_reply {
        Some(Message::FrontierDiffResponse { entries, .. }) if entries.is_empty() => {
            GroupRound::Divergent
        }
        Some(Message::FrontierDiffResponse { entries, .. }) => {
            GroupRound::Requested { newer: entries.len() }
        }
        Some(Message::Refused { reason, .. }) => {
            // The peer's log no longer reaches this replica, so deltas cannot
            // catch it up: it takes the peer's sealed state, which it joins when
            // that state extends the history it holds. A missing body and a
            // history that begins above the request both mean that.
            if let Some(summary) = truncation_from_delta_refusal(&reason) {
                (env.truncated)(group, summary);
            }
            if matches!(reason, RefusalReason::NotFound | RefusalReason::HistoryTruncated { .. }) {
                request_recovery(env, connection, group).await;
            }
            GroupRound::Refused(reason)
        }
        _ => GroupRound::Failed,
    }
}

/// What a peer's refusal of a delta-range request says about its history: `Some` when the
/// history this replica needs is gone from the peer (with the checkpoint it names, when it
/// names one). A `NotFound` here means a delta in the requested range is gone from the peer's
/// own log. The reply to a request for the peer's sealed state is a different question and
/// never reaches this: a peer that cannot seal says nothing about its history.
fn truncation_from_delta_refusal(reason: &RefusalReason) -> Option<Option<RetainedSummary>> {
    match reason {
        RefusalReason::HistoryTruncated { checkpoint_id, frontier_root } => {
            Some(Some(RetainedSummary {
                checkpoint_id: *checkpoint_id,
                frontier_root: *frontier_root,
            }))
        }
        RefusalReason::NotFound => Some(None),
        _ => None,
    }
}

/// Whether the reply to a request for the peer's sealed state is the stream ending empty,
/// which is how the peer accepts it; any refusal, a `NotFound` included, is not a start.
fn recovery_request_accepted(reply: &[u8]) -> bool {
    reply.is_empty()
}

/// Pushes the just-published `hashes` of `group` to the peer as delta
/// batches. A peer missing an earlier delta holds them and pulls the gap on
/// its next reconcile.
pub async fn push_published(
    env: &ReplicationEnv,
    connection: &NativeReplicationConnection,
    group: &FolderGroupId,
    hashes: &[DeltaHash],
) {
    let (db, group_owned, hashes_owned) = (env.db.clone(), group.clone(), hashes.to_vec());
    let entries = tokio::task::spawn_blocking(move || {
        db.read(|conn| native_replication::entries_for_hashes(conn, &group_owned, &hashes_owned))
    })
    .await;
    let Ok(Ok(entries)) = entries else { return };
    let Ok(batches) = session::delta_batches(group, entries) else { return };
    for batch in batches {
        push_message(connection, &batch).await;
    }
}

#[cfg(test)]
mod tests;
