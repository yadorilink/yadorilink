//! Wakes a per-group maintenance loop (the hazard re-check in
//! `engine_wrapper.rs`) promptly whenever a group's admitted native frontier
//! advances or a materialization job reaches `Completed`. It tracks WHICH
//! groups actually became dirty: a busy group's frontier churn must not turn
//! into work for every other quiet linked group on every wake.
//!
//! State is a per-group `requested`/`completed` generation pair, not a
//! plain dirty flag/set. A plain dirty set (insert on mark, remove on
//! drain) makes correctness depend on every consumer exit path -- ran
//! cleanly, skipped on guard contention, transient error, retry-required --
//! re-marking dirty on every path that did not truly finish the work, with
//! no structural guard against missing one. A `mark_dirty` that lands
//! between a consumer's drain and its completion is silently absorbed by
//! that drain either way, so a frontier change during an in-flight audit
//! can be lost. Generations make "is there unretired work" a monotonic
//! comparison instead: `pending()` reports a group whenever `requested >
//! completed`, and only an explicit `complete(group, generation)` call --
//! made only once a pass has genuinely verified that generation's work --
//! advances `completed`. A `mark_dirty` racing an in-flight pass simply
//! bumps `requested` past the generation that pass is targeting, so
//! `pending()` reports the group again immediately after `complete` is
//! called for the stale generation: nothing to lose, because nothing is
//! cleared just by looking at it.
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Default)]
struct GroupGenerations {
    requested: u64,
    completed: u64,
}

pub struct GroupWake {
    groups: Mutex<BTreeMap<String, GroupGenerations>>,
    notify: tokio::sync::Notify,
}

impl Default for GroupWake {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupWake {
    pub fn new() -> Self {
        Self { groups: Mutex::new(BTreeMap::new()), notify: tokio::sync::Notify::new() }
    }

    /// Marks `group_id` dirty (bumping its requested generation) and wakes
    /// the consumer loop. Safe under any
    /// number of concurrent producers (native admission, job completion):
    /// repeated marks for the same group arriving before it is next
    /// completed all coalesce into the same target generation the next
    /// pass claims via `pending`.
    pub fn mark_dirty(&self, group_id: &str) {
        {
            let mut groups = self.groups.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            groups.entry(group_id.to_string()).or_default().requested += 1;
        }
        self.notify.notify_one();
    }

    /// Every group whose requested generation is ahead of its completed
    /// generation, paired with the generation a pass claiming it right now
    /// should aim to complete. Read-only -- unlike the old `drain()`,
    /// nothing is consumed or reset here. A pass must call `complete` with
    /// the paired generation once it has genuinely verified that
    /// generation's state, and only then does the group stop being
    /// reported. A pass that could not actually run (guard contention,
    /// transient error, retry-required) simply does not call `complete`,
    /// and the group keeps being reported on every subsequent `pending`
    /// call with no separate re-mark required.
    pub fn pending(&self) -> BTreeMap<String, u64> {
        self.groups
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, g)| g.requested > g.completed)
            .map(|(group_id, g)| (group_id.clone(), g.requested))
            .collect()
    }

    /// Records that `group_id`'s work has been genuinely
    /// verified through `generation` (the value `pending` returned for it
    /// when the now-finishing pass started). Monotonic: never regresses
    /// `completed`, so an out-of-order or duplicate call from a slow pass
    /// can never un-complete a generation a newer pass already recorded.
    /// If `mark_dirty` landed while the pass ran, `requested` is now ahead
    /// of `generation`, so `pending` reports the group again immediately --
    /// this is the mechanism that makes an event arriving mid-audit
    /// provoke exactly one follow-up audit rather than being lost.
    pub fn complete(&self, group_id: &str, generation: u64) {
        let mut groups = self.groups.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(g) = groups.get_mut(group_id) {
            if generation > g.completed {
                g.completed = generation;
            }
        }
    }

    /// Resolves once `mark_dirty` is called (or spuriously) -- callers must
    /// always pair this with a fallback timeout in a `select!`, exactly
    /// like `MaterializationWake::materialization_wake_notified`.
    pub async fn wake_notified(&self) {
        self.notify.notified().await;
    }
}

#[cfg(test)]
mod tests;
