#![cfg(test)]

use std::sync::{Arc, Mutex};

type Hook = Arc<dyn Fn(&str) + Send + Sync>;
static POST_SNAPSHOT: Mutex<Option<Hook>> = Mutex::new(None);

pub(crate) fn set_post_snapshot_hook(hook: Option<Hook>) {
    *POST_SNAPSHOT.lock().unwrap_or_else(|p| p.into_inner()) = hook;
}

pub(crate) fn fire_post_snapshot(group_id: &str) {
    // Clone the Arc out and release the registry lock before invoking, so a
    // hook that blocks (the deterministic startup-race tests do) never holds
    // this lock while parked.
    let hook = POST_SNAPSHOT.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if let Some(hook) = hook {
        hook(group_id);
    }
}

static POST_INDEX_ONLY_COMMIT: Mutex<Option<Hook>> = Mutex::new(None);

pub(crate) fn set_post_index_only_commit_hook(hook: Option<Hook>) {
    *POST_INDEX_ONLY_COMMIT.lock().unwrap_or_else(|p| p.into_inner()) = hook;
}

/// Fires at the first instant a not-yet-native-backed scan's rows are
/// durable -- exactly what a restart there would come back to, and the
/// only point from which "a restart can never see a row without the
/// metadata this scan observed for it" is observable at all. Reading
/// the index from this hook is what lets a test check that property
/// without killing a process mid-scan.
pub(crate) fn fire_post_index_only_commit(group_id: &str) {
    // Same release-before-invoke discipline as `fire_post_snapshot`
    // above, for the same reason.
    let hook = POST_INDEX_ONLY_COMMIT.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if let Some(hook) = hook {
        hook(group_id);
    }
}

type PathHook = Arc<dyn Fn(&str, &str) + Send + Sync>;
static PRE_TOMBSTONE_RECHECK: Mutex<Option<PathHook>> = Mutex::new(None);

pub(crate) fn set_pre_tombstone_recheck_hook(hook: Option<PathHook>) {
    *PRE_TOMBSTONE_RECHECK.lock().unwrap_or_else(|p| p.into_inner()) = hook;
}

pub(crate) fn fire_pre_tombstone_recheck(group_id: &str, path: &str) {
    // Same release-before-invoke discipline as `fire_post_snapshot`
    // above, for the same reason.
    let hook = PRE_TOMBSTONE_RECHECK.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if let Some(hook) = hook {
        hook(group_id, path);
    }
}

static PRE_CHUNK_COMMIT_RECHECK: Mutex<Option<PathHook>> = Mutex::new(None);

pub(crate) fn set_pre_chunk_commit_recheck_hook(hook: Option<PathHook>) {
    *PRE_CHUNK_COMMIT_RECHECK.lock().unwrap_or_else(|p| p.into_inner()) = hook;
}

/// Fires once per tombstone candidate immediately before the FINAL,
/// guard-held-through-commit re-verification that runs right before a
/// chunk actually writes -- distinct from `fire_pre_tombstone_recheck`
/// above, which fires earlier, at candidacy-decision time. A test that
/// only sets this hook (leaving the other one unset) can inject a race
/// specifically in the window the candidacy-time re-check alone cannot
/// close: after a candidate legitimately passed that first check and
/// was added to the batch, but before its own chunk's actual commit.
pub(crate) fn fire_pre_chunk_commit_recheck(group_id: &str, path: &str) {
    let hook = PRE_CHUNK_COMMIT_RECHECK.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if let Some(hook) = hook {
        hook(group_id, path);
    }
}

static PRE_UPSERT_COMMIT_RECHECK: Mutex<Option<PathHook>> = Mutex::new(None);

pub(crate) fn set_pre_upsert_commit_recheck_hook(hook: Option<PathHook>) {
    *PRE_UPSERT_COMMIT_RECHECK.lock().unwrap_or_else(|p| p.into_inner()) = hook;
}

/// Fires once per content upsert a scan is about to commit, right before
/// it takes the path's lock and re-checks that disk is still what the
/// scan read: a test can hold that lock, or change the file, in exactly
/// the window between the scan's read and its commit.
pub(crate) fn fire_pre_upsert_commit_recheck(group_id: &str, path: &str) {
    let hook = PRE_UPSERT_COMMIT_RECHECK.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if let Some(hook) = hook {
        hook(group_id, path);
    }
}
