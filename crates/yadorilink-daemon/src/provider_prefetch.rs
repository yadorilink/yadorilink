//! The bounded, idle-only, breadth-first prefetch scheduler of a provider root.
//!
//! The daemon decides which folder to warm; the host app lists it under its user-visible URL and
//! answers `ProviderPrefetchDone`. Everything here is in memory (the queue is recomputed from the
//! rows after a restart) and every number is configuration with the documented defaults.
//!
//! Rules: user activity on a root (`ProviderActivity`) pauses it (one `paused = true` push), the
//! activity caused by the outstanding hint's own folder is ignored, after `idle` without activity the
//! daemon pushes `paused = false` and the next hint; one hint is outstanding per root; a folder is
//! offered once per session; a session ends at its item budget; a host that answers `SKIPPED` backs
//! the root off for twelve idle periods.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ActivityKind, PrefetchResult, ProviderPrefetchControl, ProviderPrefetchHint,
};
use yadorilink_sync_sqlite::provider::ProviderRepository;

/// How many times one folder is offered without a DONE before the queue moves past it.
const MAX_ATTEMPTS: u32 = 5;

#[derive(Clone, Debug)]
pub(crate) struct PrefetchConfig {
    pub(crate) depth: u32,
    pub(crate) children: u32,
    pub(crate) items: u64,
    pub(crate) idle: Duration,
    pub(crate) hint_timeout: Duration,
    /// How many recently used folders are remembered per root.
    pub(crate) recent: usize,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            depth: 3,
            children: 1_000,
            items: 20_000,
            idle: Duration::from_secs(5),
            hint_timeout: Duration::from_secs(30),
            recent: 64,
        }
    }
}

/// What the scheduler asks the caller to send to the host.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Pause(String),
    Resume(String),
    Hint { root: String, hint_id: u64, folder: Vec<u8> },
}

struct Outstanding {
    hint_id: u64,
    folder: Vec<u8>,
    since: Instant,
    /// The candidate this hint warms: the cursor moves past it only when the host says DONE.
    candidate: (u32, String),
    /// The candidate's real number of direct children: the budget a DONE answer spends.
    children: u32,
}

#[derive(Default)]
struct RootState {
    last_activity: Option<Instant>,
    paused: bool,
    /// Recently used items (folders enumerated, files fetched), newest last, bounded.
    recent: VecDeque<Vec<u8>>,
    hint: Option<Outstanding>,
    next_hint_id: u64,
    cursor: Option<(u32, String)>,
    spent: u64,
    /// Unanswered or refused offers of the CURRENT candidate; after `MAX_ATTEMPTS` it is given up.
    attempts: u32,
    backoff_until: Option<Instant>,
    /// The session's offered folders were exhausted or its budget spent.
    finished: bool,
}

impl RootState {
    /// One more refused or unanswered offer of `candidate`; past the bound the queue moves on.
    fn fail_current(&mut self, candidate: (u32, String)) {
        self.attempts += 1;
        if self.attempts >= MAX_ATTEMPTS {
            self.cursor = Some(candidate);
            self.attempts = 0;
        }
    }
}

pub(crate) struct PrefetchScheduler {
    config: PrefetchConfig,
    roots: Mutex<HashMap<String, RootState>>,
}

impl PrefetchScheduler {
    pub(crate) fn new(config: PrefetchConfig) -> Self {
        Self { config, roots: Mutex::new(HashMap::new()) }
    }

    /// Records user activity. True when this is the first since the root last ran, i.e. a pause is to
    /// be pushed.
    pub(crate) fn on_activity(
        &self,
        root: &str,
        item: &[u8],
        _kind: ActivityKind,
        now: Instant,
    ) -> bool {
        let mut roots = self.roots.lock().unwrap_or_else(|p| p.into_inner());
        let state = roots.entry(root.to_owned()).or_default();
        // The folder an outstanding hint is warming is the app's own doing, not the user's.
        if state.hint.as_ref().is_some_and(|hint| hint.folder == item) {
            return false;
        }
        if let Some(position) = state.recent.iter().position(|seen| seen == item) {
            state.recent.remove(position);
        }
        state.recent.push_back(item.to_vec());
        while state.recent.len() > self.config.recent {
            state.recent.pop_front();
        }
        state.last_activity = Some(now);
        // A new burst of activity ends the previous session's exhaustion: more may be reachable.
        let newly_paused = !state.paused;
        state.paused = true;
        newly_paused
    }

    /// The host's answer to a hint.
    pub(crate) fn on_done(&self, root: &str, hint_id: u64, result: PrefetchResult, now: Instant) {
        let mut roots = self.roots.lock().unwrap_or_else(|p| p.into_inner());
        let Some(state) = roots.get_mut(root) else { return };
        if state.hint.as_ref().is_none_or(|hint| hint.hint_id != hint_id) {
            return;
        }
        let Some(hint) = state.hint.take() else { return };
        match result {
            // Only DONE moves the queue on, and only a DONE spends the item budget (by the folder's
            // real number of children): a folder re-offered after a skip warmed nothing and cost nothing.
            PrefetchResult::Done => {
                state.spent += u64::from(hint.children.max(1));
                state.cursor = Some(hint.candidate);
                state.attempts = 0;
            }
            // A skip or a failure may be transient (battery, power, busy, the OS momentarily unable):
            // the candidate is kept and offered again after the root has backed off, up to a bound.
            _ => {
                state.backoff_until = Some(now + self.config.idle * 12);
                state.fail_current(hint.candidate);
            }
        }
    }

    /// The most recently used items of a root, newest first.
    #[cfg(test)]
    pub(crate) fn recent(&self, root: &str) -> Vec<Vec<u8>> {
        let roots = self.roots.lock().unwrap_or_else(|p| p.into_inner());
        roots.get(root).map_or_else(Vec::new, |s| s.recent.iter().rev().cloned().collect())
    }

    /// One scheduling step for `root`: resumes after the idle period and offers the next folder.
    pub(crate) fn tick(
        &self,
        root: &str,
        repo: &ProviderRepository,
        enabled: bool,
        now: Instant,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut roots = self.roots.lock().unwrap_or_else(|p| p.into_inner());
        let state = roots.entry(root.to_owned()).or_default();
        if !enabled {
            return actions;
        }
        if state.paused {
            let idle =
                state.last_activity.is_none_or(|at| now.duration_since(at) >= self.config.idle);
            if !idle {
                return actions;
            }
            state.paused = false;
            actions.push(Action::Resume(root.to_owned()));
            // A new idle session starts with a fresh budget and queue.
            state.spent = 0;
            state.cursor = None;
            state.finished = false;
        }
        if let Some(hint) = &state.hint {
            if now.duration_since(hint.since) < self.config.hint_timeout {
                return actions;
            }
            // An offer the host never answered counts as an attempt of that candidate.
            if let Some(hint) = state.hint.take() {
                state.fail_current(hint.candidate);
            }
        }
        if state.finished || state.backoff_until.is_some_and(|until| now < until) {
            return actions;
        }
        if state.spent >= self.config.items {
            state.finished = true;
            return actions;
        }
        let after = state.cursor.as_ref().map(|(depth, path)| (*depth, path.as_str()));
        // Only a successful, empty read proves there is nothing left to warm. A failed read is
        // retried on a later tick and never finishes the session.
        let candidates = match repo.prefetch_candidates(
            root,
            self.config.depth,
            self.config.children,
            after,
            1,
        ) {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::warn!(root, %error, "could not read the prefetch candidates; will retry");
                return actions;
            }
        };
        let Some((depth, path, children)) = candidates.into_iter().next() else {
            state.finished = true;
            return actions;
        };
        let folder = match repo.mint_item(root, &path) {
            Ok(folder) => folder,
            Err(error) => {
                tracing::warn!(root, %error, "could not mint the prefetch folder; will retry");
                return actions;
            }
        };
        state.next_hint_id += 1;
        let hint_id = state.next_hint_id;
        state.hint = Some(Outstanding {
            hint_id,
            folder: folder.to_vec(),
            since: now,
            candidate: (depth, path),
            children,
        });
        actions.push(Action::Hint { root: root.to_owned(), hint_id, folder: folder.to_vec() });
        actions
    }
}

impl Action {
    pub(crate) fn into_payload(self) -> Payload {
        match self {
            Action::Pause(root) => Payload::ProviderPrefetchControl(ProviderPrefetchControl {
                root_id: hex::decode(root).unwrap_or_default(),
                paused: true,
            }),
            Action::Resume(root) => Payload::ProviderPrefetchControl(ProviderPrefetchControl {
                root_id: hex::decode(root).unwrap_or_default(),
                paused: false,
            }),
            Action::Hint { root, hint_id, folder } => {
                Payload::ProviderPrefetchHint(ProviderPrefetchHint {
                    root_id: hex::decode(root).unwrap_or_default(),
                    hint_id,
                    folder_item_ids: vec![folder],
                })
            }
        }
    }
}

/// Drives the scheduler for every declared root of a macOS provider that is Eager-or-OnDemand and
/// ready, once a second, sending to the attached host.
pub(crate) async fn run(context: std::sync::Arc<crate::shell_context::ShellContext>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        if !context.provider_host.host_connected() {
            continue;
        }
        let repo = context.replica_coordinator.provider_repository();
        let roots = match repo.list_declared_roots() {
            Ok(roots) => roots,
            Err(error) => {
                tracing::warn!(%error, "could not list the provider roots for prefetch; will retry");
                continue;
            }
        };
        for root in roots {
            let ready =
                root.readiness() == yadorilink_replica_domain::session_state::Readiness::Ready;
            for action in context.prefetch.tick(&root.root_id, repo, ready, Instant::now()) {
                context.provider_host.send_to_host(action.into_payload());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheduler() -> PrefetchScheduler {
        PrefetchScheduler::new(PrefetchConfig {
            idle: Duration::from_secs(5),
            hint_timeout: Duration::from_secs(30),
            recent: 3,
            ..PrefetchConfig::default()
        })
    }

    /// Activity pauses a root once, is remembered in a bounded most-recent-first list, and the folder
    /// of the outstanding hint is not the user's activity.
    #[test]
    fn activity_pauses_once_is_bounded_and_ignores_the_hinted_folder() {
        let s = scheduler();
        let t = Instant::now();
        assert!(s.on_activity("r", b"a", ActivityKind::Enumerate, t));
        assert!(
            !s.on_activity("r", b"b", ActivityKind::Fetch, t),
            "a second activity pushed a second pause"
        );
        for item in [b"c", b"d", b"a"] {
            s.on_activity("r", item, ActivityKind::Enumerate, t);
        }
        assert_eq!(s.recent("r"), [b"a".to_vec(), b"d".to_vec(), b"c".to_vec()]);
        s.roots.lock().unwrap().get_mut("r").unwrap().hint = Some(Outstanding {
            hint_id: 1,
            folder: b"h".to_vec(),
            since: t,
            candidate: (1, "h".into()),
            children: 1,
        });
        s.roots.lock().unwrap().get_mut("r").unwrap().last_activity = None;
        s.on_activity("r", b"h", ActivityKind::Enumerate, t);
        assert!(
            s.roots.lock().unwrap()["r"].last_activity.is_none(),
            "the hint's own folder counted as activity"
        );
    }

    /// A skipped answer backs the root off; a stale hint id is ignored; the outstanding hint is cleared.
    #[test]
    fn answers_clear_the_hint_and_skips_back_off() {
        let s = scheduler();
        let t = Instant::now();
        s.roots.lock().unwrap().entry("r".into()).or_default().hint = Some(Outstanding {
            hint_id: 7,
            folder: b"f".to_vec(),
            since: t,
            candidate: (1, "f".into()),
            children: 1,
        });
        s.on_done("r", 6, PrefetchResult::Done, t);
        assert!(s.roots.lock().unwrap()["r"].hint.is_some(), "a stale answer cleared the hint");
        s.on_done("r", 7, PrefetchResult::Skipped, t);
        let roots = s.roots.lock().unwrap();
        assert!(roots["r"].hint.is_none());
        assert_eq!(roots["r"].backoff_until, Some(t + Duration::from_secs(60)));
    }

    /// A failed candidate read is not "no candidates": the session is not finished and the next
    /// tick that can read offers the folder without any new user activity.
    #[test]
    fn a_candidate_read_error_does_not_finish_the_session() {
        use crate::provider_read_fault::{declared_root, Fault, GROUP};
        let (coordinator, root) = declared_root();
        coordinator
            .database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                tx.execute(
                    "INSERT INTO provider_dirs (group_id, path, parent_path) VALUES (?1, 'd', '')",
                    [GROUP],
                )?;
                Ok(())
            })
            .unwrap();
        let repo = coordinator.provider_repository();
        let s = scheduler();
        let t = Instant::now();

        let fault = Fault::inject(&coordinator, "provider_dirs", "parent_path");
        assert!(s.tick(&root, repo, true, t).is_empty());
        assert!(
            !s.roots.lock().unwrap()[&root].finished,
            "an unreadable candidate list finished the session"
        );
        fault.restore();

        let actions = s.tick(&root, repo, true, t);
        assert!(matches!(actions.as_slice(), [Action::Hint { .. }]), "{} actions", actions.len());
    }
}
