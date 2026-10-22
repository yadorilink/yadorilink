//! The publication state machine of a provider root (design 2.1 and 2.2).
//!
//! When the CONTENT of an item the OS may hold changes, the new version must not reach the OS
//! while its old bytes can still be read from cache. So: the fence is ON from the commit (it is
//! DERIVED: the published version differs from the current one and the content differs, see
//! `ProviderRepository::publication`), the OS's old copy is evicted, and only after that is the
//! new version signalled; the daemon then records it as published and the fence is OFF. A
//! metadata-only change is signalled without any eviction.
//!
//! Nothing about progress is stored: every step is idempotent and starts again from the
//! committed rows (evict again, which answers NOT_MATERIALIZED when already dataless, then
//! signal again). So a crash, a restart, a reconnect of the host and a lost acknowledgement are
//! all the same thing: run the pass again.
//!
//! An item the OS keeps open (EBUSY) is retried alone, with backoff, by its own task. No lock
//! of any kind is held across a retry or an acknowledgement wait, a bounded number of evict
//! requests are in flight per root, and nothing waits for another item: a pile of busy items
//! blocks neither the other items, nor the root, nor a sync commit. Nothing forces the update.
//!
//! Published state that cannot be resolved is lost evidence (invariant I2): the root is
//! rebootstrapped with a new `root_id`, never repaired by assuming the OS holds the current
//! version.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::Instant;
use yadorilink_sync_sqlite::provider::{ItemId, Publication};

use crate::application::ports::BoxFuture;
use crate::replica_coordinator::ReplicaCoordinator;

/// What the host app answered to an eviction request (`EvictResult`), or why it could not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EvictOutcome {
    Evicted,
    /// Already dataless: counts as done.
    NotMaterialized,
    /// A process holds the file open or mapped: retry this item only.
    Busy,
    Error(String),
    /// No host is connected: retried like an error; the host's reconnect runs a pass.
    NotConnected,
}

/// The host side of the provider channel (the menu-bar app), as the publication machine
/// needs it. A fake in tests; `provider_host_link::ProviderHostLink` in production.
pub(crate) trait ProviderHost: Send + Sync {
    fn evict<'a>(
        &'a self,
        root_id: &'a str,
        item: ItemId,
        target: [u8; 32],
    ) -> BoxFuture<'a, EvictOutcome>;

    /// Announces `namespace_revision` (for these items, or for the whole namespace when `items`
    /// is empty) and returns whether the OS FINISHED processing it: the host calls
    /// `signalEnumerator` and then waits for the system to finish the changes below the parent
    /// directory(ies) named by `parent_ids` (an empty id is the root container), and only then
    /// reports success. `false`: it could not (no host, the wait is unavailable, failed or timed
    /// out), and the item stays pending.
    fn signal<'a>(
        &'a self,
        root_id: &'a str,
        namespace_revision: u64,
        items: Vec<ItemId>,
        parent_ids: Vec<Vec<u8>>,
    ) -> BoxFuture<'a, bool>;

    /// Tells the host the set of provider folders changed (`new_root_id` replaced another root):
    /// it lists them again and reconciles its domains. Not acknowledged: the listing is the
    /// state, this only prompts a host that is connected now.
    fn folders_changed(&self, new_root_id: &str);

    /// Takes back handoff files of `item` that were delivered but the OS has not consumed. Called
    /// before an eviction of the item: an old handoff the OS takes after the new version was
    /// published would leave old bytes with no fence. False when a file could not be taken back:
    /// the publication then retries instead of evicting past it.
    fn revoke_unconsumed_handoffs(&self, root_id: &str, item: &ItemId) -> bool;
}

/// May the OS fetch the item's bytes now? While the fence is ON the answer is "not yet": the
/// daemon serves nothing for the item (the extension maps it to `.cannotSynchronize`, which
/// the OS retries), because after the eviction a first read would otherwise be answered with
/// the NEW version while the OS still believes the old one. `fetchContents` is never given a
/// requested version, so the fence is on the daemon's side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FetchGate {
    Allowed,
    PublicationPending,
    NotFound,
}

pub(crate) fn fetch_gate(
    coordinator: &ReplicaCoordinator,
    root_id: &str,
    item: &ItemId,
) -> Result<FetchGate, crate::sync_error::SyncError> {
    let repo = coordinator.provider_repository();
    Ok(match repo.publication(root_id, item)? {
        None => FetchGate::NotFound,
        // The ANNOUNCED version may be fetched from the announcement on (never anything newer).
        Some(Publication::ContentPending) if repo.announced_is_current(root_id, item)? => {
            FetchGate::Allowed
        }
        Some(Publication::ContentPending) => FetchGate::PublicationPending,
        Some(_) => FetchGate::Allowed,
    })
}

/// What a user's edit was built on, against what the daemon holds now.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EditBase {
    /// Built on the current version: an ordinary edit.
    Fresh,
    /// Built on a version that is no longer current (the OS showed the PUBLISHED version while a
    /// newer one was pending): a CONCURRENT edit of that base. It is authored as an edit of the
    /// base, so the existing conflict semantics keep both versions; the newer one is never
    /// overwritten.
    Concurrent,
}

/// `modifyItem`'s `baseVersion` is the only truthful version signal the OS gives; this is the
/// rule that uses it. `None` when the item is gone.
#[cfg(test)]
pub(crate) fn classify_edit(
    coordinator: &ReplicaCoordinator,
    root_id: &str,
    item: &ItemId,
    base: yadorilink_replica_domain::ids::VersionHash,
) -> Result<Option<EditBase>, crate::sync_error::SyncError> {
    Ok(coordinator.provider_repository().current_version_hash(root_id, item)?.map(|current| {
        if current == base {
            EditBase::Fresh
        } else {
            EditBase::Concurrent
        }
    }))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicationConfig {
    /// First retry delay for a busy item; doubles up to `backoff_cap`.
    pub(crate) backoff_initial: Duration,
    pub(crate) backoff_cap: Duration,
    /// Workers per root: attempts in flight at once, however many items are pending.
    pub(crate) max_in_flight: usize,
    /// How long an announced version waits before OUR timer releases it: the
    /// fence decides WHEN a version is exposed, never whether an edit is safe.
    pub(crate) release_after: Duration,
    /// The clock the timer reads (milliseconds since the epoch).
    pub(crate) now_ms: fn() -> i64,
}

fn system_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

impl PublicationConfig {
    /// The configuration of the daemon's shell context: the defaults, with the timers shortened in
    /// tests so a test that waits for the driver to go idle does not wait for the real minute.
    pub(crate) fn for_shell_context() -> Self {
        #[cfg(test)]
        return Self {
            backoff_initial: Duration::from_millis(20),
            backoff_cap: Duration::from_millis(100),
            release_after: Duration::from_millis(300),
            ..Self::default()
        };
        #[cfg(not(test))]
        Self::default()
    }
}

impl Default for PublicationConfig {
    fn default() -> Self {
        Self {
            // The signal is repeated by our own schedule: 5 s, doubling to a minute.
            backoff_initial: Duration::from_secs(5),
            backoff_cap: Duration::from_secs(60),
            max_in_flight: 4,
            release_after: Duration::from_secs(20),
            now_ms: system_now_ms,
        }
    }
}

/// How one attempt on one item ended.
enum Attempt {
    /// Published (or nothing left to do).
    Done,
    /// Try again after the item's backoff (no host, nothing could be done yet).
    Retry,
    /// Try again at the next re-signal OR when the release timer is due, whichever is first.
    RetrySoon(Duration),
    /// The item moved on while the attempt ran: start over for the latest version at once.
    Restart,
    /// Published state cannot be resolved: the root's evidence is lost.
    Lost(String),
}

/// One worker's result.
enum Finished {
    Item(ItemId, Attempt),
    Root(bool),
}

/// What a running worker task is doing, so a worker that ends without a result (it panicked) can
/// still be given back to the runner's bookkeeping.
#[derive(Clone, Copy)]
enum Running {
    Item(ItemId),
    Root,
}

struct Runner {
    wake: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
}

/// Publishes the pending items of provider roots with a BOUNDED pool: per root one runner task
/// and at most `max_in_flight` workers, however many items are pending. A busy item is not
/// retried in place: its attempt ends and the worker moves to the next item, so a pile of busy
/// items blocks neither the other items nor the root. Finished workers are reaped as they end;
/// dropping the driver aborts every runner.
struct Shared {
    coordinator: Arc<ReplicaCoordinator>,
    host: Arc<dyn ProviderHost>,
    config: PublicationConfig,
    runners: Arc<Mutex<HashMap<String, Runner>>>,
}

/// The driver handle. The runner tasks hold the shared state, not this handle, so dropping the
/// last handle aborts every runner (and with it every retry and in-flight attempt).
pub(crate) struct PublicationDriver {
    shared: Arc<Shared>,
}

impl Drop for PublicationDriver {
    fn drop(&mut self) {
        for (_, runner) in self.shared.runners.lock().unwrap_or_else(|p| p.into_inner()).drain() {
            runner.handle.abort();
        }
    }
}

impl PublicationDriver {
    pub(crate) fn new(
        coordinator: Arc<ReplicaCoordinator>,
        host: Arc<dyn ProviderHost>,
        config: PublicationConfig,
    ) -> Self {
        Self { shared: Arc::new(Shared { coordinator, host, config, runners: Arc::default() }) }
    }

    pub(crate) fn kick(&self, root_id: &str) {
        self.shared.kick(root_id);
    }

    #[cfg(test)]
    pub(crate) async fn idle(&self) {
        self.shared.idle().await;
    }

    pub(crate) async fn rebootstrap_root(&self, root_id: &str, reason: &str) {
        self.shared.rebootstrap_root(root_id, reason).await;
    }
}

impl Shared {
    /// Makes sure `root_id` has a runner and tells it to look again. This is the crash-recovery
    /// pass at start, the replay on a host reconnect and the trigger after a commit: all the same
    /// operation, because nothing about progress is stored.
    fn kick(self: &Arc<Self>, root_id: &str) {
        let mut runners = self.runners.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(runner) = runners.get(root_id) {
            if !runner.handle.is_finished() {
                runner.wake.notify_one();
                return;
            }
        }
        let wake = Arc::new(Notify::new());
        let (this, root, notify) = (self.clone(), root_id.to_owned(), wake.clone());
        let handle = tokio::spawn(async move { this.run(&root, notify).await });
        runners.insert(root_id.to_owned(), Runner { wake, handle });
    }

    /// Waits until no root has a runner (tests).
    #[cfg(test)]
    async fn idle(&self) {
        loop {
            let busy = {
                let mut runners = self.runners.lock().unwrap_or_else(|p| p.into_inner());
                runners.retain(|_, runner| !runner.handle.is_finished());
                !runners.is_empty()
            };
            if !busy {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    async fn rebootstrap_root(&self, root_id: &str, reason: &str) {
        let repo = self.coordinator.provider_repository();
        let group = match repo.group_of_root(root_id) {
            Ok(Some(group)) => group,
            _ => return,
        };
        let new_root = match repo.rebootstrap_root(&group) {
            Ok(new_root) => new_root,
            Err(error) => {
                tracing::warn!(root_id, %error, "could not rebootstrap a provider root");
                return;
            }
        };
        // The host learns of it from the provider-folder snapshot: the old root_id is gone from
        // it, so the host removes that domain on this connection and on every later launch. A
        // host that is connected now is prompted to list again rather than wait for a launch.
        tracing::warn!(root_id, reason, "provider state lost: root rebootstrapped");
        self.host.folders_changed(&new_root);
    }

    fn next_delay(&self, delay: Duration) -> Duration {
        (delay * 2).min(self.config.backoff_cap)
    }

    async fn run(self: Arc<Self>, root_id: &str, wake: Arc<Notify>) {
        let repo = self.coordinator.provider_repository();
        let mut workers: JoinSet<Finished> = JoinSet::new();
        let mut queue: VecDeque<ItemId> = VecDeque::new();
        let mut queued: HashSet<ItemId> = HashSet::new();
        let mut in_flight: HashSet<ItemId> = HashSet::new();
        let mut running: HashMap<tokio::task::Id, Running> = HashMap::new();
        // Items waiting for their backoff (when they may run again), and the delay each one backs
        // off by next. An item is in at most one of: queued, in flight, waiting.
        let mut waiting: HashMap<ItemId, Instant> = HashMap::new();
        let mut delays: HashMap<ItemId, Duration> = HashMap::new();
        let mut root_signal: Option<(Instant, Duration)> = None;
        let mut root_signal_in_flight = false;
        let mut rescan = true;
        loop {
            if rescan {
                rescan = false;
                match repo.pending_items(root_id) {
                    Ok(pending) => {
                        let fresh = pending
                            .into_iter()
                            .map(|item| item.item_id)
                            .filter(|id| !in_flight.contains(id) && !waiting.contains_key(id));
                        enqueue_new(&mut queued, &mut queue, fresh);
                    }
                    // Only state that is known to be corrupt replaces the root. Any other read
                    // error (busy, pool, I/O) says nothing about the state: keep the root, retry.
                    Err(error @ yadorilink_sync_sqlite::SyncSqliteError::CorruptState(_)) => {
                        self.rebootstrap_root(root_id, &error.to_string()).await;
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(root_id, %error, "could not read the pending publications; will retry");
                        tokio::time::sleep(self.config.backoff_initial).await;
                        rescan = true;
                        continue;
                    }
                }
                if !root_signal_in_flight
                    && root_signal.is_none()
                    && !matches!(repo.unannounced_changes(root_id), Ok(None))
                {
                    // A failed read schedules the signal too: it is retried (with backoff) until
                    // the read can say whether anything is unannounced.
                    root_signal = Some((Instant::now(), self.config.backoff_initial));
                }
            }
            // Items whose backoff has passed run again.
            let now = Instant::now();
            let due: Vec<ItemId> =
                waiting.iter().filter(|(_, at)| **at <= now).map(|(id, _)| *id).collect();
            for id in due {
                waiting.remove(&id);
                if !in_flight.contains(&id) && queued.insert(id) {
                    queue.push_back(id);
                }
            }
            // Fill the workers.
            while workers.len() < self.config.max_in_flight {
                let signal_due = root_signal.is_some_and(|(at, _)| at <= Instant::now());
                if signal_due && !root_signal_in_flight {
                    root_signal_in_flight = true;
                    let this = self.clone();
                    let root = root_id.to_owned();
                    let worker =
                        workers.spawn(async move { Finished::Root(this.signal_root(&root).await) });
                    running.insert(worker.id(), Running::Root);
                    continue;
                }
                let Some(id) = queue.pop_front() else { break };
                queued.remove(&id);
                in_flight.insert(id);
                let this = self.clone();
                let root = root_id.to_owned();
                let worker =
                    workers.spawn(async move { Finished::Item(id, this.attempt(&root, id).await) });
                running.insert(worker.id(), Running::Item(id));
            }
            // Nothing running, queued or waiting: look once more under the registry lock (a
            // `kick` takes it too, so a kick cannot be lost) and leave if there is still nothing.
            if workers.is_empty() && queue.is_empty() && waiting.is_empty() && root_signal.is_none()
            {
                let mut runners = self.runners.lock().unwrap_or_else(|p| p.into_inner());
                let more = repo.pending_items(root_id).map(|p| !p.is_empty()).unwrap_or(true)
                    || !matches!(repo.unannounced_changes(root_id), Ok(None));
                if !more {
                    runners.remove(root_id);
                    return;
                }
                rescan = true;
                continue;
            }
            let next_due = waiting
                .values()
                .copied()
                .chain(root_signal.map(|(at, _)| at))
                .min()
                .map(|at| at.saturating_duration_since(Instant::now()));
            tokio::select! {
                Some(done) = workers.join_next_with_id(), if !workers.is_empty() => {
                    let finished = match done {
                        Ok((task, finished)) => {
                            running.remove(&task);
                            finished
                        }
                        // A worker cancelled from outside: the runtime is shutting down (the
                        // driver aborts the whole runner instead), so this runner is going too.
                        Err(error) if error.is_cancelled() => break,
                        // A worker that panicked produced no result, and its item must not stay
                        // "in flight" for ever: nothing would retry it, and the runner would
                        // find work pending that it believes is already being done and spin on
                        // it without ever waiting. Retry it after its backoff like a failed one.
                        Err(error) => {
                            tracing::error!(root_id, %error, "a publication worker panicked; retrying");
                            match running.remove(&error.id()) {
                                Some(Running::Item(id)) => Finished::Item(id, Attempt::Retry),
                                Some(Running::Root) => Finished::Root(false),
                                None => {
                                    rescan = true;
                                    continue;
                                }
                            }
                        }
                    };
                    match finished {
                        Finished::Item(id, attempt) => {
                            in_flight.remove(&id);
                            match attempt {
                                Attempt::Done => { delays.remove(&id); }
                                Attempt::Restart => {
                                    delays.remove(&id);
                                    if queued.insert(id) { queue.push_back(id); }
                                }
                                Attempt::RetrySoon(due) => {
                                    let delay = delays
                                        .get(&id)
                                        .map_or(self.config.backoff_initial, |d| self.next_delay(*d));
                                    delays.insert(id, delay);
                                    waiting.insert(id, Instant::now() + delay.min(due));
                                }
                                Attempt::Retry => {
                                    let delay = delays
                                        .get(&id)
                                        .map_or(self.config.backoff_initial, |d| self.next_delay(*d));
                                    delays.insert(id, delay);
                                    waiting.insert(id, Instant::now() + delay);
                                }
                                Attempt::Lost(reason) => {
                                    self.rebootstrap_root(root_id, &reason).await;
                                    workers.abort_all();
                                    break;
                                }
                            }
                            rescan = true;
                        }
                        Finished::Root(acked) => {
                            root_signal_in_flight = false;
                            if acked {
                                root_signal = None;
                                rescan = true;
                            } else if let Some((_, delay)) = root_signal {
                                let delay = self.next_delay(delay);
                                root_signal = Some((Instant::now() + delay, delay));
                            }
                        }
                    }
                }
                _ = wake.notified() => { rescan = true; }
                _ = tokio::time::sleep(next_due.unwrap_or(Duration::from_secs(1))) => {}
            }
        }
        self.runners.lock().unwrap_or_else(|p| p.into_inner()).remove(root_id);
    }

    /// A root-level signal for every namespace change nobody announced (a rename of an unchanged
    /// version, a create, a delete, a parent change). True when the host acknowledged it.
    async fn signal_root(&self, root_id: &str) -> bool {
        let repo = self.coordinator.provider_repository();
        // Only a successful read that finds nothing unannounced is "done"; a failed read is not
        // acknowledged, so the signal is retried with backoff.
        let changes = match repo.unannounced_changes(root_id) {
            Ok(Some(changes)) => changes,
            Ok(None) => return true,
            Err(error) => {
                tracing::warn!(root_id, %error, "could not read the unannounced changes; will retry");
                return false;
            }
        };
        // The revision only advances with logged events: this signal announces the latest one.
        let Ok(Some(revision)) = repo.namespace_revision(root_id) else { return false };
        if !self.host.signal(root_id, revision, Vec::new(), vec![Vec::new()]).await {
            return false;
        }
        repo.mark_announced(root_id, changes).is_ok()
    }

    /// One try at publishing one item, bound to ONE version: the version current when it starts.
    /// It evicts (content changes only), signals, and clears the fence only if that very version
    /// is still current; a newer version committed meanwhile is never published by this try's
    /// acknowledgement, and is evicted and signalled by the next one.
    /// How long a hint (eviction, signal and its wait) may be awaited: never past the moment our
    /// own timer releases the item, so a host that never answers cannot hold an attempt open.
    fn hint_budget(
        &self,
        repo: &yadorilink_sync_sqlite::provider::ProviderRepository,
        root_id: &str,
        item: &ItemId,
    ) -> Duration {
        let after_ms = self.config.release_after.as_millis() as i64;
        let now = (self.config.now_ms)();
        match repo.release_due_in(root_id, item, now, after_ms) {
            Ok(Some(ms)) => Duration::from_millis(ms.max(1) as u64),
            // Not announced yet: the whole window.
            _ => self.config.release_after,
        }
    }

    async fn attempt(&self, root_id: &str, item: ItemId) -> Attempt {
        let repo = self.coordinator.provider_repository();
        // Only corrupt state loses the root; any other read error is retried with backoff.
        let lost = |error: yadorilink_sync_sqlite::SyncSqliteError| match error {
            yadorilink_sync_sqlite::SyncSqliteError::CorruptState(_) => {
                Attempt::Lost(error.to_string())
            }
            error => {
                tracing::warn!(root_id, %error, "could not read the publication state; will retry");
                Attempt::Retry
            }
        };
        let after_ms = self.config.release_after.as_millis() as i64;
        let now = || (self.config.now_ms)();
        // The timer is checked first: a version announced long enough ago is released whatever
        // the signals did. A newer version committed meanwhile starts a new episode.
        match repo.release_expired(root_id, &item, now(), after_ms) {
            Ok(true) => return Attempt::Restart,
            Ok(false) => {}
            Err(error) => return lost(error),
        }
        let publication = match repo.publication(root_id, &item) {
            Ok(Some(publication)) => publication,
            Ok(None) => return Attempt::Done, // retired
            Err(error) => return lost(error),
        };
        let target = match repo.current_version_hash(root_id, &item) {
            Ok(Some(target)) => target,
            Ok(None) => return Attempt::Done,
            Err(error) => return lost(error),
        };
        match publication {
            Publication::Published | Publication::Unpublished => return Attempt::Done,
            Publication::MetadataOnly => {}
            Publication::ContentPending => {
                if !self.host.revoke_unconsumed_handoffs(root_id, &item) {
                    return Attempt::Retry;
                }
                // Eviction is a HINT that shortens the stale window; whatever it answers (busy,
                // an error, no host) the announcement goes ahead, and nothing waits for it.
                let _ = tokio::time::timeout(
                    self.hint_budget(repo, root_id, &item),
                    self.host.evict(root_id, item, target.0),
                )
                .await;
                // The version may have moved during the eviction: start over for the latest.
                match repo.current_version_hash(root_id, &item) {
                    Ok(Some(current)) if current == target => {}
                    Ok(None) => return Attempt::Done,
                    Ok(Some(_)) => return Attempt::Restart,
                    Err(error) => return lost(error),
                }
            }
        }
        // The announcement and its change event are durable BEFORE the signal, in one
        // transaction: whenever the OS asks for changes the event exists and the shown view is
        // the new version. The event's sequence is the revision the signal carries.
        let announced = match repo.announce_version(root_id, &item, target, now()) {
            Ok(Some(announced)) => announced,
            Ok(None) => return Attempt::Restart,
            Err(_) => return Attempt::Retry,
        };
        let parents = vec![announced.parent_item_id];
        // The signal (and the host's wait below the parent folder) is a HINT: its outcome only
        // schedules the next attempt, it never publishes. It is repeated by our own schedule.
        let _ = tokio::time::timeout(
            self.hint_budget(repo, root_id, &item),
            self.host.signal(root_id, announced.seq, vec![item], parents),
        )
        .await;
        // Published by a handoff of the announced version (provenance), by the timer,
        // or still pending: then the next attempt is when the timer is due or the next re-signal,
        // whichever is first.
        match repo.release_expired(root_id, &item, now(), after_ms) {
            Ok(true) => return Attempt::Restart,
            Ok(false) => {}
            Err(error) => return lost(error),
        }
        match repo.publication(root_id, &item) {
            Ok(Some(Publication::Published | Publication::Unpublished)) | Ok(None) => Attempt::Done,
            Ok(Some(_)) => match repo.release_due_in(root_id, &item, now(), after_ms) {
                Ok(Some(ms)) => Attempt::RetrySoon(Duration::from_millis(ms.max(1) as u64)),
                _ => Attempt::Retry,
            },
            Err(error) => lost(error),
        }
    }
}

/// Queues each id once: not while it is already queued.
fn enqueue_new(
    queued: &mut HashSet<ItemId>,
    queue: &mut VecDeque<ItemId>,
    ids: impl Iterator<Item = ItemId>,
) {
    for id in ids {
        if queued.insert(id) {
            queue.push_back(id);
        }
    }
}

#[cfg(test)]
mod tests;
