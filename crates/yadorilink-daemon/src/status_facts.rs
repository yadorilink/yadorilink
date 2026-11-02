//! Serves `Status` and `ListLinks` from facts a builder collects off the request path.
//!
//! A status read used to build its answer on the request: every ledger, block-index, filesystem
//! and shell-closure read it needs ran there, and any of them could wait on something the request
//! does not own (the disk's journal, a pooled connection, a volume). Now one builder task reads
//! them, publishes an immutable [`StatusFacts`], and a request joins the latest facts with what the
//! daemon holds in memory (peers, transfers, rates). The request path touches no SQLite, file or
//! block index.
//!
//! Only status surfaces read the facts. A caller that decides something from the answer (a gate, a
//! confirmation) keeps collecting in place with [`crate::status_report::build_status`] or
//! `LinkStatusReadPort::list_links`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::{watch, Notify};
use tokio::time::Instant;
use yadorilink_ipc_proto::daemonctl::StatusResponse;

use crate::queries::link_status::LinkStatusView;
use crate::runtime_telemetry::RuntimeTelemetry;
use crate::status_report::{collect_status, compose_status, CollectedStatus, StatusSources};

/// Builds triggered by ledger writes are at least this far apart, so a burst of commits (a large
/// receive commits a few times a second) costs one build. Chosen against the 1 Hz poll of the CLI
/// and the shells: a build per commit would multiply the reads the polls used to make. Revisit
/// when one build exceeds ~100 ms on a 10,000-file folder.
pub(crate) const BUILD_MIN_GAP: Duration = Duration::from_millis(250);
/// Facts older than this are rebuilt before a request is answered. Everything nothing signals
/// (free space, probes, files) changes on a human time scale.
pub(crate) const BUILD_MAX_AGE: Duration = Duration::from_secs(5);
/// How long a request waits for facts built after it arrived (a state-changing command finished,
/// or the facts are old). A build takes milliseconds; past this the request answers with the
/// latest facts and their true age rather than wait on a stuck disk.
pub(crate) const FRESHNESS_WAIT: Duration = Duration::from_millis(500);
/// How long the very first request waits for the first build.
pub(crate) const FIRST_BUILD_WAIT: Duration = Duration::from_secs(5);
/// Facts this old no longer stand a positive claim (protected, available) on: one missed rebuild
/// is tolerated, two mean the builder is stuck.
pub(crate) const POSITIVE_CLAIM_MAX_AGE: Duration = Duration::from_secs(10);
/// The builder keeps facts fresh on ledger writes only while someone has asked for them lately.
const DEMAND_WINDOW: Duration = Duration::from_secs(30);

/// One published collection.
pub(crate) struct StatusFacts {
    /// When the build started: every fact in it was observed at or after this.
    pub(crate) built_at: Instant,
    /// The command epoch read before the build started.
    pub(crate) built_epoch: u64,
    /// Which build this was, counted as builds start.
    pub(crate) started_seq: u64,
    pub(crate) collected: Result<Arc<CollectedStatus>, String>,
}

/// Where the builder reads from; a test replaces it to stall or count builds.
pub(crate) trait FactsSource: Send + Sync + 'static {
    fn collect(&self) -> Result<CollectedStatus, String>;
    /// Signals when a ledger write changed rows.
    fn data_changes(&self) -> watch::Receiver<u64>;
}

struct ProductionSource(Arc<StatusSources>);

impl FactsSource for ProductionSource {
    fn collect(&self) -> Result<CollectedStatus, String> {
        collect_status(&self.0)
    }

    fn data_changes(&self) -> watch::Receiver<u64> {
        self.0.queries.runtime_status.data_changes()
    }
}

struct Inner {
    source: Arc<dyn FactsSource>,
    telemetry: Arc<RuntimeTelemetry>,
    latest: watch::Sender<Option<Arc<StatusFacts>>>,
    kick: Notify,
    /// A request is waiting: build now, ignoring [`BUILD_MIN_GAP`].
    urgent: AtomicBool,
    /// Builds started so far.
    started_builds: AtomicU64,
    last_demand: Mutex<Option<Instant>>,
}

impl Inner {
    fn recent_demand(&self) -> bool {
        self.last_demand
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some_and(|at| at.elapsed() < DEMAND_WINDOW)
    }

    async fn run(self: Arc<Self>) {
        let mut data = self.source.data_changes();
        let mut last_start: Option<Instant> = None;
        loop {
            let demand = self.recent_demand();
            tokio::select! {
                () = self.kick.notified() => {}
                changed = data.changed(), if demand => {
                    // The sender goes with the database: the daemon is shutting down.
                    if changed.is_err() {
                        return;
                    }
                }
            }
            if !self.urgent.load(Ordering::Acquire) {
                if let Some(started) = last_start {
                    tokio::time::sleep(BUILD_MIN_GAP.saturating_sub(started.elapsed())).await;
                }
            }
            // This build answers every request that asked until now.
            self.urgent.store(false, Ordering::Release);
            // Count the build as started, then read the marks: a request that saw this count
            // before it started read its epoch earlier still, so the build covers that epoch.
            // Marking the ledger position before collecting keeps a write landing during the
            // build pending for the next one.
            let started_seq = self.started_builds.fetch_add(1, Ordering::AcqRel) + 1;
            data.borrow_and_update();
            let built_epoch = self.telemetry.command_epoch();
            let built_at = Instant::now();
            last_start = Some(built_at);
            let source = self.source.clone();
            let collected = match tokio::task::spawn_blocking(move || source.collect()).await {
                Ok(collected) => collected.map(Arc::new),
                Err(_) => Err("the status builder failed".to_owned()),
            };
            self.latest.send_replace(Some(Arc::new(StatusFacts {
                built_at,
                built_epoch,
                started_seq,
                collected,
            })));
        }
    }
}

/// The builder and its latest facts. The builder starts with the first request (it needs the
/// runtime the request runs on) and stops when this is dropped.
pub(crate) struct StatusHub {
    inner: Arc<Inner>,
    sources: Arc<StatusSources>,
    task: OnceLock<tokio::task::AbortHandle>,
}

impl Drop for StatusHub {
    fn drop(&mut self) {
        if let Some(task) = self.task.get() {
            task.abort();
        }
    }
}

impl StatusHub {
    pub(crate) fn new(sources: Arc<StatusSources>, telemetry: Arc<RuntimeTelemetry>) -> Self {
        let source = Arc::new(ProductionSource(sources.clone()));
        Self::with_source(sources, telemetry, source)
    }

    pub(crate) fn with_source(
        sources: Arc<StatusSources>,
        telemetry: Arc<RuntimeTelemetry>,
        source: Arc<dyn FactsSource>,
    ) -> Self {
        let inner = Arc::new(Inner {
            source,
            telemetry,
            latest: watch::channel(None).0,
            kick: Notify::new(),
            urgent: AtomicBool::new(false),
            started_builds: AtomicU64::new(0),
            last_demand: Mutex::new(None),
        });
        Self { inner, sources, task: OnceLock::new() }
    }

    /// The latest facts, after waiting (bounded) for ones built after this request arrived if a
    /// state-changing command has finished since the latest were built or they are old.
    async fn facts(&self) -> Result<Arc<StatusFacts>, String> {
        *self.inner.last_demand.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        self.task.get_or_init(|| tokio::spawn(self.inner.clone().run()).abort_handle());
        let required_epoch = self.inner.telemetry.command_epoch();
        // A build in progress may have read before this request's command finished; only one
        // that starts after this point counts.
        let started_before = self.inner.started_builds.load(Ordering::Acquire);
        let mut latest = self.inner.latest.subscribe();
        let current = latest.borrow().clone();
        let (needs_newer, wait) = match &current {
            None => (true, FIRST_BUILD_WAIT),
            Some(facts) => (
                facts.built_epoch < required_epoch || facts.built_at.elapsed() > BUILD_MAX_AGE,
                FRESHNESS_WAIT,
            ),
        };
        if needs_newer {
            self.inner.urgent.store(true, Ordering::Release);
            self.inner.kick.notify_one();
            let _ = tokio::time::timeout(
                wait,
                latest.wait_for(|facts| {
                    facts.as_ref().is_some_and(|f| f.started_seq > started_before)
                }),
            )
            .await;
        }
        let facts = self.inner.latest.borrow().clone();
        facts.ok_or_else(|| "status is starting".to_owned())
    }

    /// The whole status, as the wire type.
    pub(crate) async fn status(&self) -> Result<StatusResponse, String> {
        let facts = self.facts().await?;
        let collected = facts.collected.clone()?;
        let age = facts.built_at.elapsed();
        let mut response = compose_status(&self.sources, &collected, age > POSITIVE_CLAIM_MAX_AGE);
        response.snapshot_age_ms = u64::try_from(age.as_millis()).unwrap_or(u64::MAX);
        Ok(response)
    }

    /// The per-link views of `ListLinks`.
    pub(crate) async fn list_links(&self) -> Result<Vec<LinkStatusView>, String> {
        let facts = self.facts().await?;
        let collected = facts.collected.clone()?;
        let mut links = self.sources.queries.link_status.compose_links(&collected.runtime.links);
        if facts.built_at.elapsed() > POSITIVE_CLAIM_MAX_AGE {
            for link in &mut links {
                link.withhold_positive_claims();
            }
        }
        Ok(links)
    }

    /// Records that a state-changing request has finished.
    pub(crate) fn command_completed(&self) {
        self.inner.telemetry.command_completed();
    }
}

#[cfg(test)]
impl StatusHub {
    pub(crate) fn subscribe_facts(&self) -> watch::Receiver<Option<Arc<StatusFacts>>> {
        self.inner.latest.subscribe()
    }

    pub(crate) fn started_builds(&self) -> u64 {
        self.inner.started_builds.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests;
