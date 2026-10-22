//! Opt-in: record which carriers a daemon's transfers actually used.
//!
//! A benchmark that reports a transfer rate is making a claim about a path,
//! and from outside the process there is no way to check it. The daemon knows
//! -- every link it dials can be watched -- but nothing carried that knowledge
//! out, so a harness could observe only that bytes arrived, not how.
//!
//! This writes the answer to a file named by `YADORILINK_PATH_WITNESS_PATH`.
//! Absent that variable the whole thing is inert: no hook, no watchers, no
//! file. It is measurement apparatus, not a feature.
//!
//! # Why installation is not a request that arrives later
//!
//! The hook is installed between the sync stack starting and the
//! peer session driver starting, and that placement is the whole design.
//!
//! A "begin witnessing now" control message would be simpler and would be
//! wrong. `SyncStack::link_to` hands back a cached link without dialling when
//! one is already alive, so a hook installed after any link exists never sees
//! that link -- and the bytes crossing it would be invisible to a measurement
//! that believed it was watching everything. The window between the stack
//! existing and the driver running is the last moment at which no link can yet
//! have been opened, so installing there is what makes "every connection" true
//! rather than merely likely.
//!
//! A run therefore has to start from a cold daemon. That is a constraint on
//! the harness, and a cheap one next to a number nobody can defend.
//!
//! # What the report actually covers
//!
//! Not "every connection this daemon ever had". Precisely: every connection
//! the transfer used between the cold start and the seal taken at shutdown.
//!
//! The difference is a race that is real and does not matter here. `flush`
//! reads whether anything arrived late and then writes the file, so a dial
//! landing between those two steps is missed. It cannot make the report
//! wrong for a measurement shaped like the canary's, because the seal is
//! taken during a shutdown begun only after the transfer was confirmed
//! complete from outside -- and a connection established after that point
//! cannot retroactively have carried a payload that had already arrived. The
//! hook also runs after the connection exists but before its first lane, so
//! an unwatched connection cannot have moved anything earlier either.
//!
//! Enumerating every connection up to process exit would mean stopping the
//! driver before taking the verdict. That is a heavier shutdown ordering
//! than any measurement here needs, so it is deliberately not done.

use std::sync::{Arc, Mutex, OnceLock};

use yadorilink_sync_substrate::{PathWatcher, PathWitness, TransferVerdict};

/// Names the file this daemon writes its path evidence to.
const PATH_VAR: &str = "YADORILINK_PATH_WITNESS_PATH";
/// How many bytes the direct paths are expected to have carried, so a run
/// that only ever handshook is refused rather than reported as direct.
const EXPECT_VAR: &str = "YADORILINK_PATH_WITNESS_EXPECT_BYTES";

/// Collects a watcher for every link the daemon dials, and writes the verdict
/// when the daemon shuts down.
pub struct PathWitnessSink {
    output: std::path::PathBuf,
    expected_direct_bytes: u64,
    collected: Mutex<Collected>,
}

/// The watcher set, and whether it is still accepting additions.
///
/// Sealing is what makes "every connection" checkable rather than assumed.
/// `flush` takes the watchers and then awaits them, and the driver is still
/// running at that moment, so without a seal a link dialled in between would
/// push its watcher into the emptied set and be written out of the report --
/// leaving a file that claims to describe every connection while silently
/// omitting one.
///
/// Sealing cannot prevent that dial, only notice it. Noticing is enough: a
/// report that admits it may be missing a connection is inconclusive, and an
/// inconclusive run is discarded rather than believed.
#[derive(Default)]
struct Collected {
    watchers: Vec<PathWatcher>,
    sealed: bool,
    /// A link was dialled after the seal, so the set is not complete.
    dialled_after_seal: bool,
}

static SINK: OnceLock<Option<Arc<PathWitnessSink>>> = OnceLock::new();

/// Validates the measurement configuration and installs it for this process.
///
/// Called once at startup. An error here must stop the daemon: the whole
/// contract of this instrument is that a measurement it cannot stand behind
/// is refused, and a daemon that starts with a misconfigured instrument
/// produces a file that looks like evidence and is not.
///
/// The specific hazard is a typo in the expected size. Falling back to a
/// default floor would let `EXPECT_BYTES=1073741824x` start cleanly and then
/// certify any connection that carried a single direct byte as a successful
/// gigabyte transfer -- fail-open, in the one place that exists to fail
/// closed.
pub fn configure_from_env() -> anyhow::Result<()> {
    let configured = validate()?;
    // Ignored if already set: a second call cannot change where this
    // process's evidence goes, so two halves of one run cannot disagree.
    let _ = SINK.set(configured);
    Ok(())
}

/// The validation half, separated so it can be tested without touching the
/// process-global the installer writes to.
fn validate() -> anyhow::Result<Option<Arc<PathWitnessSink>>> {
    let configured = match (std::env::var_os(PATH_VAR), std::env::var(EXPECT_VAR)) {
        // The ordinary case: no instrument, nothing to validate.
        (None, Err(_)) => None,
        (None, Ok(_)) => anyhow::bail!(
            "refusing to start: {EXPECT_VAR} is set but {PATH_VAR} is not, so this daemon \
             would measure which carriers its transfers use and write the answer nowhere"
        ),
        (Some(_), Err(_)) => anyhow::bail!(
            "refusing to start: {PATH_VAR} is set without {EXPECT_VAR}, so there is no size \
             to hold the run to and a connection carrying one byte would satisfy it"
        ),
        (Some(output), Ok(raw)) => {
            let expected_direct_bytes: u64 = raw.trim().parse().map_err(|_| {
                anyhow::anyhow!(
                    "refusing to start: {EXPECT_VAR} is {raw:?}, which is not a byte count"
                )
            })?;
            if expected_direct_bytes == 0 {
                anyhow::bail!(
                    "refusing to start: {EXPECT_VAR} is zero, which every connection satisfies \
                     including one that carried nothing"
                );
            }
            tracing::info!(
                path = ?output,
                expected_direct_bytes,
                "recording which carriers this daemon's transfers use"
            );
            Some(PathWitnessSink::new(output.into(), expected_direct_bytes))
        }
    };
    Ok(configured)
}

/// This process's sink, or `None` when no instrument was configured.
pub fn sink() -> Option<Arc<PathWitnessSink>> {
    SINK.get().cloned().flatten()
}

impl PathWitnessSink {
    /// A sink writing to `output`, independent of the environment.
    ///
    /// The environment is how a daemon started by a harness gets one; this
    /// is how a test gets one without a process-global that a second test
    /// would then inherit.
    pub fn new(output: std::path::PathBuf, expected_direct_bytes: u64) -> Arc<Self> {
        Arc::new(Self {
            output,
            expected_direct_bytes,
            collected: Mutex::new(Collected::default()),
        })
    }

    /// Watch every link `stack` dials OR accepts from here on.
    ///
    /// Must be called before anything can have opened a link -- see the
    /// module doc for why a later installation silently misses cached ones.
    ///
    /// Both directions, deliberately: a reconciliation's bulk-fetch
    /// connection is dialled by whichever side is behind, so the side that
    /// already holds the content only ever *accepts* it. Watching dials
    /// alone found this the hard way during the 1 GiB direct-path canary --
    /// the sender's witness saw a handful of small reconciliation dials and
    /// none of the ~1 GiB the receiver pulled, and reported `not_direct` for
    /// a transfer that was, in fact, entirely direct. A witness that can
    /// only ever see one direction cannot be trusted alone for a pass/fail
    /// gate.
    pub fn install(self: &Arc<Self>, stack: &crate::sync_adapter::SyncStack) {
        let offer = |sink: std::sync::Weak<Self>| {
            Arc::new(move |link: &yadorilink_sync_substrate::PeerLink| {
                let Some(sink) = sink.upgrade() else {
                    return;
                };
                sink.offer(|| link.watch_paths());
            })
        };
        stack.when_link_dialed(offer(Arc::downgrade(self)));
        stack.when_link_accepted(offer(Arc::downgrade(self)));
    }

    /// Takes a watcher for a newly dialled link, unless the set is sealed.
    ///
    /// The watcher is built lazily so that a dial arriving after the seal
    /// costs nothing: there is no point subscribing to a connection whose
    /// evidence can no longer reach the report.
    fn offer(&self, watch: impl FnOnce() -> PathWatcher) {
        let mut collected = self.collected.lock().expect("witness watchers poisoned");
        if collected.sealed {
            // Too late to be in the report. Recorded rather than dropped: a
            // connection this instrument did not watch is exactly what would
            // make the report wrong, and the run has to be told.
            collected.dialled_after_seal = true;
            return;
        }
        collected.watchers.push(watch());
    }

    /// Whether a link was dialled after the set was sealed.
    fn dialled_after_seal(&self) -> bool {
        self.collected.lock().expect("witness watchers poisoned").dialled_after_seal
    }

    /// Finish every watcher, judge the set, and write the result.
    ///
    /// Judged across all connections at once rather than one at a time: a
    /// relay on any connection outranks lost events on any other, and a
    /// payload split by a redial has to be summed rather than demanded of
    /// each. `verdict_for` owns both rules so this and the in-process gates
    /// cannot drift apart.
    pub async fn flush(&self) {
        // Seal and take under one lock. From here on a link that is dialled
        // cannot join a set that has already been read, and is recorded as
        // missed instead of vanishing into it.
        let watchers = {
            let mut collected = self.collected.lock().expect("witness watchers poisoned");
            collected.sealed = true;
            std::mem::take(&mut collected.watchers)
        };
        let mut witnesses = Vec::with_capacity(watchers.len());
        for watcher in watchers {
            witnesses.push(watcher.finish().await);
        }
        let verdict = match self.dialled_after_seal() {
            // A connection opened while the report was being assembled, so
            // this file cannot claim to describe every connection. That is
            // the absence of an answer, not a relay: nothing here says the
            // transfer used one, only that something went unwatched.
            true => TransferVerdict::Inconclusive(
                "a link was dialled while the report was being assembled, so at least one \
                 connection went unwatched"
                    .into(),
            ),
            false => yadorilink_sync_substrate::verdict_for(&witnesses, self.expected_direct_bytes),
        };

        let report = render(&verdict, &witnesses, self.expected_direct_bytes);
        // A failure to write is logged, never propagated: this is
        // instrumentation, and a daemon that refused to shut down because it
        // could not file a report would be a worse problem than a missing
        // report. The harness treats an absent file as a run with no
        // evidence, which is the correct reading.
        if let Err(error) = std::fs::write(&self.output, report) {
            tracing::error!(%error, path = ?self.output, "could not write the path evidence");
        } else {
            tracing::info!(path = ?self.output, ?verdict, "wrote the path evidence");
        }
    }
}

/// Renders the verdict and the per-connection detail as JSON.
///
/// Written by hand rather than derived: `PathWitness` belongs to another
/// crate, and making it `Serialize` for one diagnostic would put a wire
/// format on a type that has none. Every connection is listed, not just the
/// totals, so a run that is refused can be argued with rather than merely
/// disbelieved.
fn render(verdict: &TransferVerdict, witnesses: &[PathWitness], expected: u64) -> String {
    let (name, reason, direct_bytes) = match verdict {
        TransferVerdict::Direct { direct_bytes } => ("direct", String::new(), *direct_bytes),
        TransferVerdict::NotDirect(why) => {
            ("not_direct", why.clone(), witnesses.iter().map(PathWitness::direct_bytes).sum())
        }
        TransferVerdict::Inconclusive(why) => {
            ("inconclusive", why.clone(), witnesses.iter().map(PathWitness::direct_bytes).sum())
        }
    };
    let connections: Vec<String> = witnesses
        .iter()
        .map(|w| {
            format!(
                "{{\"direct_tx_bytes\":{},\"direct_rx_bytes\":{},\
                 \"relay_tx_bytes\":{},\"relay_rx_bytes\":{},\
                 \"other_tx_bytes\":{},\"other_rx_bytes\":{},\
                 \"direct_path_opened\":{},\"relay_path_opened\":{},\"incomplete\":{}}}",
                w.direct_tx_bytes,
                w.direct_rx_bytes,
                w.relay_tx_bytes,
                w.relay_rx_bytes,
                w.other_tx_bytes,
                w.other_rx_bytes,
                w.direct_path_opened,
                w.relay_path_opened,
                w.incomplete,
            )
        })
        .collect();
    format!(
        "{{\"verdict\":\"{}\",\"reason\":{},\"direct_bytes\":{},\
         \"expected_direct_bytes\":{},\"connections\":[{}]}}\n",
        name,
        json_string(&reason),
        direct_bytes,
        expected,
        connections.join(","),
    )
}

/// Escapes the few characters a reason string can contain that JSON forbids.
///
/// The reasons are built by `verdict_for` from numbers and fixed text, so
/// this is narrow on purpose; anything richer would be a reason to reach for
/// a real encoder rather than to grow this.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod configuration_tests;

#[cfg(test)]
mod seal_tests;
