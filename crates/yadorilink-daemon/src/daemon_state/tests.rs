#![cfg(test)]

use super::*;
use crate::background_custody::NotCorroboratedReason;
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::FileRecord;

/// `YADORILINK_CONFIG_DIR` is a process-global env var (same pattern
/// used by `tests/reporting_ipc.rs` and `yadorilink-cli`'s
/// `tests/materialization.rs`) — every test in this module that
/// touches it holds this mutex for its whole body, so concurrently-
/// running tests in this same lib test binary never observe each
/// other's override. Shared with `device_config.rs` and
/// `reporting/retry.rs` (see `crate::test_support`'s doc comment) —
/// a module-local mutex here alone does not serialize against those
/// other modules' own tests touching the same env var.
use crate::test_support::CONFIG_ENV_MUTEX;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

mod group_readiness {
    use super::*;

    const GROUP: &str = "readiness-group";

    fn link(state: &DaemonState) {
        let root = tempfile::tempdir().unwrap().keep();
        state
            .replica_coordinator
            .link_repository()
            .add_link(&root.to_string_lossy(), GROUP)
            .unwrap();
    }

    #[tokio::test]
    async fn an_unknown_group_is_not_joined() {
        let state = test_state();
        assert_eq!(state.group_readiness(GROUP), GroupReadiness::NotJoined);
        assert!(!state.group_readiness(GROUP).is_ready());
    }

    /// The state a freshly created or joined group actually sits in, and
    /// the whole reason this predicate exists: linked, nothing wrong,
    /// simply waiting for the coordination plane's policy to land.
    /// `resolve_group_policy` cannot express this -- it answers
    /// `Withhold`, which is the same thing it says about a stale policy.
    #[tokio::test]
    async fn a_linked_group_with_no_policy_yet_is_awaiting_policy() {
        let state = test_state();
        link(&state);
        assert_eq!(state.group_readiness(GROUP), GroupReadiness::AwaitingPolicy);
        assert!(!state.group_readiness(GROUP).is_ready());
        // The distinction this test is really about: the authorization
        // primitive collapses this case into the same answer it gives a
        // stale policy, which is correct for it and useless for a caller
        // deciding whether waiting will help.
        assert!(matches!(state.resolve_group_policy(GROUP), GroupPolicyResolution::Withhold));
    }

    #[tokio::test]
    async fn a_linked_group_with_a_verified_policy_is_ready() {
        let state = test_state();
        link(&state);
        state.authority.install_test_group_policy_bootstrap(GROUP);
        assert_eq!(state.group_readiness(GROUP), GroupReadiness::Ready);
        assert!(state.group_readiness(GROUP).is_ready());
    }

    /// Distinguished from `AwaitingPolicy` on purpose: a stale policy is
    /// not expected to clear by waiting, so a caller that treats every
    /// not-ready answer as "wait longer" would wait forever here.
    #[tokio::test]
    async fn a_stale_policy_is_reported_as_stale_not_as_awaiting() {
        let state = test_state();
        link(&state);
        state.authority.install_test_group_policy_bootstrap(GROUP);
        state.mark_group_policy_stale(GROUP);
        assert_eq!(state.group_readiness(GROUP), GroupReadiness::PolicyStale);

        state.authority.clear_group_policy_stale(GROUP);
        assert_eq!(state.group_readiness(GROUP), GroupReadiness::Ready);
    }

    /// A group this device merely knows a peer writes to is NOT joined
    /// here, even though `group_is_introduced` counts it. Readiness is
    /// about whether THIS device can use the group, and a peer naming it
    /// gives this device nothing to use.
    #[tokio::test]
    async fn a_group_only_a_peer_writes_to_is_not_joined() {
        let state = test_state();
        state.set_peer_group_writer("device-b", GROUP, true);
        assert_eq!(state.group_readiness(GROUP), GroupReadiness::NotJoined);
    }
}

/// `group_id`'s real current durability-root digest -- what a genuine
/// `full_replica_handoff_proof` round-trip would have
/// captured at confirmation time. `has_fresh_custody_confirmation`
/// requires this to still match, so a fixture-only test digest (an
/// arbitrary byte array) would never register as fresh; tests that
/// need a confirmation to actually count use this instead.
/// The digest a real cycle would publish: the CURRENT-state one, not
/// the whole-root-set one.
fn real_digest(state: &DaemonState, group_id: &str) -> [u8; 32] {
    state.local_root_set_summary(group_id).unwrap().current_digest
}

/// Indexes one current file record for `group_id`, changing its
/// durability-root digest -- the minimal way to make a previously
/// confirmed digest stale.
fn upsert_file(state: &DaemonState, group_id: &str, path: &str) {
    use yadorilink_replica_domain::file::{BlockInfo, FileRecord};

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            group_id,
            &FileRecord {
                path: path.into(),
                size: 4,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash: vec![1u8; 32], offset: 0, size: 4 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
}

/// Records `peer` as holding a granted custody hold on `version` of `a.bin`.
fn grant_hold(state: &DaemonState, peer: &str, version: &VersionHash) {
    let key = yadorilink_sync_sqlite::remote_custody_hold::HoldKey {
        group_id: "group-a".into(),
        path: "a.bin".into(),
        version_hash: version.0,
        peer_id: peer.into(),
    };
    let holds = state.replica_coordinator.remote_custody_hold_repository();
    holds.record_requested(&key, 0, [0; 16]).unwrap();
    holds.mark_granted(&key).unwrap();
}

#[tokio::test]
async fn custody_stamp_revalidation_rejects_wrong_peer_generation_change_and_demotion() {
    let state = test_state();
    state.set_peer_group_writer("peer-b", "group-a", true);
    state.authority.set_peer_group_full_replica("peer-b", "group-a", true);
    let confirmer = crate::adapters::runtime::custody::P2pCustodyConfirmer::new(&state);
    let stamp = CustodyStamp::new("peer-b".into(), state.authority.membership_generation());
    let version = VersionHash([1; 32]);
    grant_hold(&state, "peer-b", &version);
    grant_hold(&state, "peer-c", &version);
    let valid = |stamp: &CustodyStamp| {
        confirmer.confirmation_still_valid("group-a", "a.bin", &version, stamp)
    };

    assert!(valid(&stamp));
    assert!(!valid(&CustodyStamp::new("peer-c".into(), stamp.membership_generation())));

    state.set_peer_group_writer("peer-c", "unrelated-group", true);
    assert!(!valid(&stamp));

    let current_stamp = CustodyStamp::new("peer-b".into(), state.authority.membership_generation());
    assert!(valid(&current_stamp));
    state.authority.set_peer_group_full_replica("peer-b", "group-a", false);
    assert!(!valid(&current_stamp));
}

/// A stamp backed by no granted hold (never recorded, or only requested, or
/// for another version) is not valid, whatever the peer's authorization.
#[tokio::test]
async fn custody_stamp_revalidation_requires_a_granted_hold_for_that_version() {
    let state = test_state();
    state.set_peer_group_writer("peer-b", "group-a", true);
    state.authority.set_peer_group_full_replica("peer-b", "group-a", true);
    let confirmer = crate::adapters::runtime::custody::P2pCustodyConfirmer::new(&state);
    let stamp = CustodyStamp::new("peer-b".into(), state.authority.membership_generation());
    let version = VersionHash([1; 32]);

    assert!(!confirmer.confirmation_still_valid("group-a", "a.bin", &version, &stamp), "no row");
    grant_hold(&state, "peer-b", &version);
    assert!(confirmer.confirmation_still_valid("group-a", "a.bin", &version, &stamp));
    assert!(!confirmer.confirmation_still_valid("group-a", "a.bin", &VersionHash([2; 32]), &stamp));
    assert!(!confirmer.confirmation_still_valid("group-a", "other.bin", &version, &stamp));
}

// --- Custody-confirmation cache mechanics ----

/// A transient `NotConfirmed` round must not erase a still-fresh
/// `Confirmed` record -- otherwise the staleness bound's "tolerate one
/// missed sweep" property would be meaningless.
#[tokio::test]
async fn not_confirmed_does_not_downgrade_a_still_fresh_confirmed_record() {
    let state = test_state();
    let generation = state.authority.membership_generation();
    let digest = real_digest(&state, "group-1");
    state.publish_background_custody(
        "group-1",
        BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("peer-b".into()),
            current_digest: digest,
            roots_digest_matched: true,
        },
        generation,
        0,
    );
    assert!(state.has_fresh_custody_confirmation("group-1"));

    state.publish_background_custody(
        "group-1",
        BackgroundCustodyEvidence::NotCorroborated { reason: NotCorroboratedReason::NoUsableReply },
        generation,
        0,
    );
    assert!(
        state.has_fresh_custody_confirmation("group-1"),
        "a round that merely failed to reach anyone must not clobber a still-fresh positive"
    );

    // A peer that answered and disagreed is a different fact, and it
    // does retract. Without this, a group whose only holder has just
    // told this device their states differ would keep reporting itself
    // protected for the rest of the staleness window.
    state.publish_background_custody(
        "group-1",
        BackgroundCustodyEvidence::NotCorroborated {
            reason: NotCorroboratedReason::CurrentStateDiffers,
        },
        generation,
        0,
    );
    assert!(
        !state.has_fresh_custody_confirmation("group-1"),
        "a contradicting reply must retract the positive it contradicts"
    );
}

/// `NotConfirmed` is still written (and `has_ever_been_custody_swept`
/// still becomes true) the FIRST time, when there's no existing
/// record to preserve.
#[tokio::test]
async fn not_confirmed_is_recorded_when_nothing_cached_yet() {
    let state = test_state();
    assert!(!state.durability.has_ever_been_custody_swept("group-1"));
    state.publish_background_custody(
        "group-1",
        BackgroundCustodyEvidence::NotCorroborated {
            reason: NotCorroboratedReason::NoCandidatePeer,
        },
        state.authority.membership_generation(),
        0,
    );
    assert!(state.durability.has_ever_been_custody_swept("group-1"));
    assert!(!state.has_fresh_custody_confirmation("group-1"));
}

/// A vacuous (no-peer) confirmation only counts as fresh while the
/// group's CURRENT durability-root digest still matches what was
/// confirmed -- otherwise a group going empty -> non-empty could ride
/// a stale vacuous confirmation as `Protected` for up to the full
/// staleness bound.
#[tokio::test]
async fn vacuous_confirmation_requires_current_digest_still_match() {
    let state = test_state();
    let empty_digest = real_digest(&state, "group-1");
    state.publish_background_custody(
        "group-1",
        BackgroundCustodyEvidence::Corroborated {
            peer_device_id: None,
            current_digest: empty_digest,
            roots_digest_matched: true,
        },
        state.authority.membership_generation(),
        0,
    );
    assert!(
        state.has_fresh_custody_confirmation("group-1"),
        "a vacuous confirmation is fresh evidence while the group's digest is unchanged"
    );

    upsert_file(&state, "group-1", "a.bin");
    assert!(
        !state.has_fresh_custody_confirmation("group-1"),
        "a vacuous confirmation must stop counting as fresh once the group's digest has \
         moved off what was actually confirmed, even within the staleness bound"
    );
}

/// A REAL (non-vacuous) peer confirmation is invalidated by a content
/// change exactly like the vacuous case -- the digest check applies
/// uniformly, closing the gap where only the vacuous case used to be
/// gated (previously this device could
/// report `Protected` on a stale non-vacuous confirmation while
/// `fetch_availability` correctly showed `UnavailableNow` for content
/// no peer had actually confirmed).
#[tokio::test]
async fn non_vacuous_confirmation_is_also_invalidated_by_a_content_change() {
    let state = test_state();
    let digest_before = real_digest(&state, "group-1");
    state.publish_background_custody(
        "group-1",
        BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("peer-b".into()),
            current_digest: digest_before,
            roots_digest_matched: true,
        },
        state.authority.membership_generation(),
        0,
    );
    assert!(state.has_fresh_custody_confirmation("group-1"));

    upsert_file(&state, "group-1", "a.bin");
    assert!(
        !state.has_fresh_custody_confirmation("group-1"),
        "a non-vacuous confirmation must also stop counting as fresh once the group's \
         digest has moved off what the confirming peer actually proved"
    );
}

/// A membership-generation change since the confirmation was recorded
/// invalidates it outright, regardless of age.
#[tokio::test]
async fn confirmation_under_a_stale_membership_generation_is_not_fresh() {
    let state = test_state();
    let old_generation = state.authority.membership_generation();
    let digest = real_digest(&state, "group-1");
    state.publish_background_custody(
        "group-1",
        BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("peer-b".into()),
            current_digest: digest,
            roots_digest_matched: true,
        },
        old_generation,
        0,
    );
    assert!(state.has_fresh_custody_confirmation("group-1"));

    state.set_peer_group_writer("peer-c", "unrelated-group", true);
    assert_ne!(state.authority.membership_generation(), old_generation);
    assert!(
        !state.has_fresh_custody_confirmation("group-1"),
        "any membership generation change since confirmation must invalidate it"
    );
}

/// `clear_custody_confirmation` both drops the cached record and bumps
/// the group's epoch -- the epoch is what `refresh_custody_
/// confirmation` uses to detect and discard an in-flight round-trip
/// that started before an unlink and would otherwise resurrect a
/// cleared entry.
#[tokio::test]
async fn clear_custody_confirmation_drops_the_record_and_bumps_the_epoch() {
    let state = test_state();
    let generation = state.authority.membership_generation();
    state.publish_background_custody(
        "group-1",
        BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("peer-b".into()),
            current_digest: [3u8; 32],

            roots_digest_matched: true,
        },
        generation,
        0,
    );
    let epoch_before = state.durability.custody_confirmation_epoch("group-1");

    state.durability.clear_custody_confirmation("group-1");

    assert!(!state.durability.has_ever_been_custody_swept("group-1"));
    assert!(!state.has_fresh_custody_confirmation("group-1"));
    assert_ne!(
        state.durability.custody_confirmation_epoch("group-1"),
        epoch_before,
        "clearing must bump the epoch so an in-flight refresh started before this call \
         can detect it happened and drop its stale result"
    );
}

/// Directly pins the TOCTOU `record_custody_confirmation_outcome`
/// closes: a publish carrying a stale (pre-clear) `epoch_before` must
/// be dropped outright, never landing in the cache at all -- even
/// though nothing else about the confirmation looks wrong. This simulates the
/// in-flight-round-trip race without needing real concurrency: capture
/// the epoch, clear (as if an unlink raced ahead of the round-trip),
/// then publish using the stale, pre-clear epoch (as
/// `refresh_custody_confirmation` would with what it captured before
/// the round-trip started).
#[tokio::test]
async fn publish_with_a_stale_epoch_is_dropped_not_resurrected() {
    let state = test_state();
    let generation = state.authority.membership_generation();
    let epoch_before = state.durability.custody_confirmation_epoch("group-1");

    state.durability.clear_custody_confirmation("group-1");

    state.publish_background_custody(
        "group-1",
        BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("peer-b".into()),
            current_digest: [9u8; 32],

            roots_digest_matched: true,
        },
        generation,
        epoch_before,
    );

    assert!(
        !state.durability.has_ever_been_custody_swept("group-1"),
        "a publish carrying a stale pre-clear epoch must be dropped entirely, not \
         resurrect a cache entry for a group that was unlinked mid-round-trip"
    );
}

/// `custody_confirmation_cache` is purely in-memory
/// (`DaemonState`'s own `Mutex<HashMap<...>>` field, never persisted
/// to `replica_coordinator`'s DB) -- so a daemon restart, simulated
/// here by reopening a REAL on-disk `ReplicaCoordinator` database
/// under a SECOND `DaemonState` (genuinely fresh in-process fields,
/// same persisted on-disk state -- not merely a second `DaemonState`
/// sharing one still-open in-memory connection), must never let a
/// group that was `Protected` under the first process instance keep
/// reading `Protected` under the second before a real post-restart
/// confirmation sweep has run: never flash/retain a stale Protected
/// state solely because the last process said Protected. It holds
/// purely as a structural consequence of the cache's design (the cache
/// simply doesn't exist yet in the new process), not because of any
/// restart-specific logic; this test pins that consequence explicitly
/// so a future refactor (e.g. persisting the cache for a "faster warm
/// start") cannot silently reintroduce a stale-Protected-across-
/// restart bug without breaking a named test.
///
/// Asserts the EXACT expected state (`Unknown`), not merely
/// `!= Protected` -- the restart path also forbids manufacturing `AtRisk`
/// purely from the startup uncertainty window, so a
/// regression landing there must fail this test too.
#[tokio::test]
async fn restart_never_shows_a_stale_protected_status() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("sync.sqlite3");

    // First "process": open the real on-disk DB, confirm the group via
    // a REAL sweep round (`refresh_custody_confirmation`, not a
    // manually-planted cache entry) against a genuinely empty group --
    // `full_replica_handoff_ready` confirms an empty root set
    // vacuously, without needing a live peer -- and observe Protected.
    {
        let coordinator = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
        let first = DaemonState::new("device-a".into(), coordinator, store.clone());
        first
            .replica_coordinator
            .link_repository()
            .add_link(store_dir.path().to_str().unwrap(), "group-1")
            .unwrap();
        first.refresh_custody_confirmation("group-1").await;
        assert_eq!(
            first.group_durability_status("group-1"),
            GroupDurabilityStatus::Protected,
            "sanity check: the first process instance genuinely observes Protected after \
             a real confirmation sweep"
        );
    } // `first` and its `coordinator` are dropped here -- the DB file
      // itself is all that persists, exactly like a real process exit.

    // "Restart": a second DaemonState reopening the SAME on-disk
    // database file, with entirely fresh in-memory fields -- exactly
    // what a real process restart produces.
    let coordinator = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
    let second = DaemonState::new("device-a".into(), coordinator, store);
    assert_eq!(
        second.group_durability_status("group-1"),
        GroupDurabilityStatus::Unknown,
        "a fresh process must report Unknown (never Protected, and never \
         AtRisk/AtRisk) for a group before its OWN confirmation sweep has run, \
         even though the prior process instance had just confirmed it"
    );
}

// --- Mandatory handoff-lease digest-match decision (source side) ----

/// The safety property this whole mechanism exists for: a target's
/// grant whose attested `root_digest` matches the source's own current
/// digest yields the lease id, so the source may present it.
#[test]
fn handoff_lease_grant_digest_match_yields_the_lease_id() {
    let digest = [7u8; 32];
    let grant = PeerHandoffLeaseGrant {
        lease_id: "lease-abc".to_string(),
        root_digest: digest,
        expires_at_unix: 12345,
        ttl_seconds: 900,
    };
    assert_eq!(handoff_lease_grant_matches_digest(&grant, digest), Some("lease-abc".to_string()));
}

/// A digest MISMATCH must decline (`None`), never yield a lease id --
/// the target attested a different root set than what this device
/// currently holds, so the lease does not cover it. This is exactly the
/// case the caller must treat as "do not relinquish the local role."
#[test]
fn handoff_lease_grant_digest_mismatch_declines() {
    let mut other_digest = [7u8; 32];
    other_digest[0] = 8;
    let grant = PeerHandoffLeaseGrant {
        lease_id: "lease-abc".to_string(),
        root_digest: other_digest,
        expires_at_unix: 12345,
        ttl_seconds: 900,
    };
    assert_eq!(handoff_lease_grant_matches_digest(&grant, [7u8; 32]), None);
}

// --- Degraded-link state tests ----

/// a link enters Degraded on disk pressure — `is_link_degraded`
/// flips true and the reason is recorded.
#[tokio::test]
async fn mark_link_degraded_makes_the_link_report_degraded_with_a_reason() {
    let state = test_state();
    assert!(!state.is_link_degraded("/links/photos"));

    state.mark_link_degraded("/links/photos", "disk pressure on /links/photos".to_string());

    assert!(state.is_link_degraded("/links/photos"));
    let info = state.degraded_link_info("/links/photos").unwrap();
    assert_eq!(info.reason, "disk pressure on /links/photos");
    assert_eq!(info.backoff_attempt, 0);
}

/// a link leaves Degraded once cleared — the mirror case,
/// and the trigger `hydration::hydrate_inner`'s success path uses
/// directly (a snappier recovery signal beyond the periodic re-check).
#[tokio::test]
async fn clear_link_degraded_removes_the_entry() {
    let state = test_state();
    state.mark_link_degraded("/links/photos", "disk pressure".to_string());
    assert!(state.is_link_degraded("/links/photos"));

    state.clear_link_degraded("/links/photos");
    assert!(!state.is_link_degraded("/links/photos"));
    // Clearing an already-clear (or never-degraded) link is a safe no-op.
    state.clear_link_degraded("/links/photos");
    assert!(!state.is_link_degraded("/links/photos"));
}

/// Repeated disk pressure on the same link produces
/// backoff re-checks, not a tight retry loop — each re-mark bumps the
/// backoff attempt count and pushes `next_recheck_unix` further out
/// (via `BackoffConfig::DEGRADED_LINK_RECHECK`'s doubling schedule),
/// rather than resetting to the same short interval every time.
#[tokio::test]
async fn repeated_disk_pressure_increases_backoff_instead_of_resetting_it() {
    let state = test_state();
    state.mark_link_degraded("/links/photos", "disk pressure".to_string());
    let first = state.degraded_link_info("/links/photos").unwrap();
    assert_eq!(first.backoff_attempt, 0);

    state.mark_link_degraded("/links/photos", "disk pressure".to_string());
    let second = state.degraded_link_info("/links/photos").unwrap();
    assert_eq!(second.backoff_attempt, 1);
    assert!(
        second.next_recheck_unix >= first.next_recheck_unix,
        "backoff must not shrink on repeated pressure"
    );
    // The original onset time is preserved across re-marks, not reset —
    // `yadorilink status` should be able to report how long a link has
    // been degraded, not just "since the last re-check."
    assert_eq!(second.since_unix, first.since_unix);

    state.mark_link_degraded("/links/photos", "disk pressure".to_string());
    let third = state.degraded_link_info("/links/photos").unwrap();
    assert_eq!(third.backoff_attempt, 2);
    assert!(third.next_recheck_unix >= second.next_recheck_unix);
}

/// a Degraded link recovers once its volume's free-space
/// check succeeds again — exercised through the real periodic
/// `recheck_degraded_links` sweep (not just the mark/clear API
/// directly), using an isolated `YADORILINK_CONFIG_DIR` so this test's
/// governance config never touches the real host config directory
/// (same pattern `tests/reporting_ipc.rs` already established for this
/// exact env var).
#[tokio::test]
async fn recheck_degraded_links_clears_a_link_once_headroom_check_succeeds() {
    let _guard = CONFIG_ENV_MUTEX.lock().await;
    let config_dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

    let state = test_state();
    let link_root = tempfile::tempdir().unwrap();
    let link_path = link_root.path().to_string_lossy().to_string();

    // Mark the link degraded directly (bypassing a real preflight
    // call) so this test only exercises the re-check/clear half.
    state.mark_link_degraded(&link_path, "disk pressure".to_string());
    assert!(state.is_link_degraded(&link_path));

    // A headroom override of `0` ("no headroom required") always
    // classifies as `Ok` for any real volume — configuring it via the
    // same `GovernanceConfigStore` `recheck_degraded_links` itself
    // reads simulates "space was freed" without needing a real
    // multi-gigabyte write.
    state.governance_config.set_headroom_override_bytes(Some(0)).unwrap();
    // Force the entry's backoff window to be due right now (avoids
    // this test waiting out even the 5s initial backoff).
    state.links.force_degraded_recheck_due_now(&link_path, now_unix());

    state.recheck_degraded_links();

    assert!(
        !state.is_link_degraded(&link_path),
        "expected the link to clear once headroom check succeeds"
    );

    std::env::remove_var("YADORILINK_CONFIG_DIR");
}

/// the mirror case — a link stays Degraded (rescheduled with
/// bumped backoff, not cleared) when its volume is still under
/// pressure at re-check time.
#[tokio::test]
async fn recheck_degraded_links_reschedules_a_link_still_under_pressure() {
    let _guard = CONFIG_ENV_MUTEX.lock().await;
    let config_dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

    let state = test_state();
    let link_root = tempfile::tempdir().unwrap();
    let link_path = link_root.path().to_string_lossy().to_string();

    state.mark_link_degraded(&link_path, "disk pressure".to_string());
    // A headroom override far larger than any real disk's free space
    // keeps this link `Critical` no matter what.
    state.governance_config.set_headroom_override_bytes(Some(u64::MAX / 2)).unwrap();
    state.links.force_degraded_recheck_due_now(&link_path, now_unix());
    let before = state.degraded_link_info(&link_path).unwrap();

    state.recheck_degraded_links();

    assert!(state.is_link_degraded(&link_path), "still under pressure — must stay degraded");
    let after = state.degraded_link_info(&link_path).unwrap();
    assert!(
        after.backoff_attempt > before.backoff_attempt,
        "a still-failing re-check must bump backoff, not just repeat the same window"
    );

    std::env::remove_var("YADORILINK_CONFIG_DIR");
}

#[tokio::test]
async fn release_owned_handoff_lease_releases_local_pin_and_worker_lease() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let state = test_state();
    let server = MockServer::start().await;
    state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    state
        .replica_coordinator
        .handoff_lease_repository()
        .record_handoff_lease(
            "group-release",
            "lease-release",
            [9u8; 32],
            &[],
            now_unix(),
            now_unix() + 900,
        )
        .unwrap();
    Mock::given(method("POST"))
        .and(path("/shares/groups/group-release/handoff/lease/lease-release/release"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "state": "released" })),
        )
        .expect(1)
        .mount(&server)
        .await;

    assert!(state.release_owned_handoff_lease("group-release", "lease-release").await);

    let leases = state
        .replica_coordinator
        .handoff_lease_repository()
        .list_handoff_leases_for_group("group-release")
        .unwrap();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].state, HandoffLeaseState::Released);
}

/// The digest-mismatch abort path: if the group's durability-root set
/// changes between the readiness digest `request_handoff_lease` captures
/// up front and the atomic local pin that follows the coordination service
/// round trip, the mismatch must be caught, both halves of the
/// now-meaningless lease released, and `None` returned — never a lease
/// that claims to pin a set it no longer actually matches. The mismatch
/// is engineered deterministically, not via a timing race: the mock
/// the coordination service handler below only runs once the real HTTP
/// request has actually been sent — which is strictly after
/// `full_replica_handoff_ready_digest` already ran synchronously earlier
/// in `request_handoff_lease` — and it inserts a new file into the group
/// before answering, so the atomic pin that follows the response
/// re-enumerates a set the readiness check never saw.
#[tokio::test]
async fn request_handoff_lease_aborts_and_releases_both_pins_on_a_digest_mismatch() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    let state = test_state();
    let server = MockServer::start().await;
    state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );

    let sync_state_for_handler = state.replica_coordinator.clone();
    Mock::given(method("POST"))
        .and(path("/shares/groups/group-1/handoff/lease"))
        .respond_with(move |_req: &Request| {
            let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
            sync_state_for_handler
                .file_index_repository()
                .upsert_file_with_origin(
                    "group-1",
                    &FileRecord {
                        path: "b.txt".to_string(),
                        size: 5,
                        mtime_unix_nanos: 0,
                        blocks: vec![],
                        deleted: false,
                    },
                    "device-b",
                    &permit,
                )
                .unwrap();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "leaseId": "lease-xyz",
                "expiresAt": now_unix() + 900,
                "ttlSeconds": 900,
            }))
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/shares/groups/group-1/handoff/lease/lease-xyz/release"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    // `group-1` starts EMPTY, so `full_replica_handoff_ready_digest`'s
    // check is vacuously satisfied (an empty root set needs no
    // confirming peer) — the readiness digest captured here is the
    // empty-set digest, before the mock handler above adds `b.txt`.
    let grant = state.request_handoff_lease("group-1").await;

    assert!(
        grant.is_none(),
        "a digest mismatch between attestation and atomic pin must decline, not grant"
    );

    // The local pin must have been written (provisionally) and then
    // explicitly released, not left dangling as a live-looking
    // 'provisional' row.
    let local_leases = state
        .replica_coordinator
        .handoff_lease_repository()
        .list_handoff_leases_for_group("group-1")
        .unwrap();
    assert_eq!(local_leases.len(), 1);
    assert_eq!(local_leases[0].lease_id, "lease-xyz");
    assert_eq!(local_leases[0].state, HandoffLeaseState::Released);

    // The coordination service's copy must have been released too — the
    // release endpoint (and only it, once) was actually called.
    let requests = server.received_requests().await.unwrap();
    let release_calls = requests
        .iter()
        .filter(|r| r.url.path() == "/shares/groups/group-1/handoff/lease/lease-xyz/release")
        .count();
    assert_eq!(release_calls, 1, "the Worker-side lease must be explicitly released exactly once");
}

/// The symmetric-cleanup path: if the atomic LOCAL pin errors AFTER the
/// Worker has already granted the lease, `request_handoff_lease` must
/// still attempt to release the Worker-side lease (so it does not sit
/// granted with no local pin until its TTL) and return `None`, exactly
/// like the digest-mismatch abort. The local storage error is forced
/// deterministically: the sync database is file-backed, and a second
/// connection drops the `handoff_leases` table between the Worker POST
/// (mocked to succeed) and the atomic pin's `INSERT` into that table, so
/// the pin fails with a genuine storage error while the durability-root
/// enumeration that precedes it still reads the intact `files` table.
#[tokio::test]
async fn request_handoff_lease_releases_the_worker_lease_when_the_local_pin_fails() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("sync.db");
    let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);

    let server = MockServer::start().await;
    state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );

    // The POST handler drops `handoff_leases` out from under the pool via
    // an independent connection to the same file before answering, so the
    // atomic pin's INSERT that follows the response hits a genuine "no
    // such table" storage error. `files` is untouched, so the
    // enumeration inside the atomic call still succeeds — only the pin
    // write fails, which is exactly the post-POST error path under test.
    let db_path_for_handler = db_path.clone();
    Mock::given(method("POST"))
        .and(path("/shares/groups/group-1/handoff/lease"))
        .respond_with(move |_req: &Request| {
            let conn = rusqlite::Connection::open(&db_path_for_handler).unwrap();
            conn.execute("DROP TABLE handoff_leases", []).unwrap();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "leaseId": "lease-xyz",
                "expiresAt": now_unix() + 900,
                "ttlSeconds": 900,
            }))
        })
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/shares/groups/group-1/handoff/lease/lease-xyz/release"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let grant = state.request_handoff_lease("group-1").await;

    assert!(grant.is_none(), "a failed local pin after a granted lease must decline, not grant");

    // The Worker-side lease must have been released best-effort, even
    // though the local pin never landed.
    let requests = server.received_requests().await.unwrap();
    let release_calls = requests
        .iter()
        .filter(|r| r.url.path() == "/shares/groups/group-1/handoff/lease/lease-xyz/release")
        .count();
    assert_eq!(
        release_calls, 1,
        "a local-pin error after a granted lease must still release the Worker lease"
    );
}

/// The clock-skew bug this change closes, end to end: a coordination
/// Worker whose clock runs BEHIND this target device's own is simulated
/// by mocking a grant whose absolute `expiresAt` already reads as being
/// in the past relative to this device's own clock, alongside a normal,
/// still-valid `ttlSeconds`. Before the fix, `request_handoff_lease`
/// stored that stale absolute value verbatim as the local pin deadline,
/// so the very next local retention sweep would have dropped the pin
/// immediately -- reopening the GC race the lease exists to close. After
/// the fix, the local pin is derived from this device's own clock plus
/// `ttlSeconds` (plus the fixed safety margin) and is unaffected by the
/// Worker's stale absolute value.
#[tokio::test]
async fn request_handoff_lease_pins_locally_from_this_devices_own_clock_even_when_the_workers_absolute_expiry_is_already_stale(
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let state = test_state();
    let server = MockServer::start().await;
    state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );

    let ttl_seconds = 900i64;
    Mock::given(method("POST"))
        .and(path("/shares/groups/group-1/handoff/lease"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "leaseId": "lease-skewed",
            // Already in the past relative to this device's own clock --
            // simulating a coordination Worker whose clock runs behind
            // this target's. Under the pre-fix behavior (storing this
            // verbatim as the local pin deadline) the local pin would
            // already read as expired the instant it lands.
            "expiresAt": now_unix() - 10_000,
            "ttlSeconds": ttl_seconds,
        })))
        .mount(&server)
        .await;

    // `group-1` starts empty, so the readiness check is vacuously
    // satisfied (see the digest-mismatch test above) -- what is under
    // test here is the local pin deadline arithmetic, not readiness.
    let local_now_before_request = now_unix();
    let (grant, _root_digest) = state
        .request_handoff_lease("group-1")
        .await
        .expect("an empty root set is vacuously ready; the grant must still be produced");
    let local_now_after_request = now_unix();
    assert_eq!(grant.ttl_seconds, ttl_seconds);

    let leases = state
        .replica_coordinator
        .handoff_lease_repository()
        .list_handoff_leases_for_group("group-1")
        .unwrap();
    assert_eq!(leases.len(), 1);
    let recorded = &leases[0];
    assert_eq!(recorded.lease_id, "lease-skewed");

    // The recorded LOCAL expiry must not already be in the past just
    // because the Worker's absolute `expiresAt` was stale -- it must sit
    // close to this device's own now + ttl (+ the fixed safety margin).
    let earliest_local_now = local_now_before_request.min(local_now_after_request);
    let latest_local_now = local_now_before_request.max(local_now_after_request);
    assert!(
        recorded.expires_at_unix > latest_local_now,
        "the local pin must not read as already expired just because the Worker's absolute \
         expiresAt was stale relative to this device's own clock"
    );
    let earliest_deadline = earliest_local_now
        + ttl_seconds
        + yadorilink_sync_sqlite::handoff_lease::HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS;
    let latest_deadline = latest_local_now
        + ttl_seconds
        + yadorilink_sync_sqlite::handoff_lease::HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS;
    assert!(
        recorded.expires_at_unix >= earliest_deadline - 5
            && recorded.expires_at_unix <= latest_deadline + 5,
        "the local pin deadline must equal this device's own now + ttlSeconds (+ a fixed \
         safety margin), not the Worker's stale absolute expiresAt; got {}, expected in {}..={}",
        recorded.expires_at_unix,
        earliest_deadline,
        latest_deadline
    );
}

/// Trust-boundary fail-closed: a coordination grant carrying a
/// non-positive `ttlSeconds` (a buggy/hostile response the current Worker
/// never emits) must be rejected -- `request_handoff_lease` returns
/// `None`, records NO local pin, and best-effort releases the Worker-side
/// lease -- rather than deriving a too-short local deadline that would
/// lapse immediately and reopen the GC race. Checked for both a zero and
/// a negative TTL.
#[tokio::test]
async fn request_handoff_lease_rejects_a_non_positive_worker_ttl_and_records_no_pin() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    for bad_ttl in [0i64, -30] {
        let state = test_state();
        let server = MockServer::start().await;
        state.set_coordination_client_config(
            server.uri(),
            yadorilink_fapi_client::test_support::offline_auth(),
        );

        Mock::given(method("POST"))
            .and(path("/shares/groups/group-1/handoff/lease"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "leaseId": "lease-badttl",
                "expiresAt": now_unix() + 900,
                "ttlSeconds": bad_ttl,
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/shares/groups/group-1/handoff/lease/lease-badttl/release"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        // `group-1` starts empty -> readiness is vacuously satisfied, so
        // the request reaches the TTL boundary check under test.
        let grant = state.request_handoff_lease("group-1").await;
        assert!(grant.is_none(), "a non-positive Worker ttl ({bad_ttl}) must decline, not grant");

        // No local pin was written for the rejected grant.
        let local_leases = state
            .replica_coordinator
            .handoff_lease_repository()
            .list_handoff_leases_for_group("group-1")
            .unwrap();
        assert!(
            local_leases.is_empty(),
            "a rejected non-positive-ttl grant must record no local pin"
        );

        // The Worker-side lease was released best-effort exactly once.
        let requests = server.received_requests().await.unwrap();
        let release_calls = requests
            .iter()
            .filter(|r| r.url.path() == "/shares/groups/group-1/handoff/lease/lease-badttl/release")
            .count();
        assert_eq!(
            release_calls, 1,
            "a rejected non-positive-ttl grant must still release the Worker lease"
        );
    }
}

// --- Removed-device handoff ticket (Stage C) -------------------------

/// An empty root set is vacuously ready and needs no lease -- the
/// responder half must grant a ticket with no `lease_id`, not decline
/// just because there is no confirming peer to ask (there is nothing to
/// hand off in the first place). No session/coordination config needed
/// at all for this case.
#[tokio::test]
async fn own_ticket_for_an_empty_root_set_is_granted_with_no_lease_id() {
    let state = test_state();
    let grant = state
        .obtain_own_handoff_ticket("empty-group")
        .await
        .expect("an empty root set is vacuously ready and must still grant a ticket");
    assert_eq!(grant.lease_id, None);
    assert_eq!(grant.target_device_id, None);
}

/// `obtain_handoff_ticket_from_device` is the OFFLINE-detection seam: no
/// live session for the named device (this daemon has never connected
/// to it, or the connection already tore down) must fail closed
/// immediately, with no timeout and no attempt to attest anything --
/// this is exactly what routes an offline removed device to the
/// existing interim path in `durability_force.rs`.
#[tokio::test]
async fn obtain_ticket_from_an_unreachable_device_is_none() {
    let state = test_state();
    assert!(
        state.obtain_handoff_ticket_from_device("group-1", "device-b").await.is_none(),
        "no live session for the target device must be treated as offline/unreachable"
    );
}

#[tokio::test]
async fn forced_durability_unknown_latch_survives_daemon_restart() {
    let database_dir = tempfile::tempdir().unwrap();
    let database_path = database_dir.path().join("sync-state.sqlite");
    let before_restart = ReplicaCoordinator::open(&database_path).unwrap();
    before_restart
        .role_loss_operation_repository()
        .latch_group_durability_unknown("group-1")
        .unwrap();
    drop(before_restart);

    let restarted_store_dir = tempfile::tempdir().unwrap();
    let restarted = DaemonState::new(
        "device-a".into(),
        Arc::new(ReplicaCoordinator::open(&database_path).unwrap()),
        Arc::new(SegmentBlockStore::new(restarted_store_dir.path()).unwrap()),
    );

    assert_eq!(
        restarted.group_durability_status("group-1"),
        GroupDurabilityStatus::Unknown,
        "force history must remain latched after reopening the durable index"
    );
    restarted.clear_group_durability_latch("group-1").unwrap();
    let after_clear = ReplicaCoordinator::open(&database_path).unwrap();
    assert!(after_clear
        .role_loss_operation_repository()
        .list_durability_unknown_latches()
        .unwrap()
        .is_empty());
}

// --- Startup-window placeholder-auth race (watcher before policy load) ---
//
// `app::run` resumes every already-linked folder's filesystem watcher
// (the daemon's own `LinkRuntimeController::start`, driven by `sync_state.list_links()`)
// before it spawns the peer/netmap orchestrator task that eventually
// calls `replace_group_policy_states`. Until that first netmap fetch
// completes, `group_policy_state(group_id)` is `None` for every group —
// including one that already has real, established policy elsewhere in
// the swarm and is only missing it locally because this process just
// started. The local-emission auth provider registered below
// (`DaemonState::new`) must tell that case apart from a group that has
// never had any policy at all, rather than falling back to the
// placeholder (all-zero) policy_head for both.

/// Under checkpoint-based admission a local delta carries no
/// authorization stamp at all (it stays Pending until the native checkpoint
/// flush obtains one), but committing it to native state at all while this
/// device cannot yet vouch for its own policy view is still wrong: the
/// resulting Pending delta can never legitimately obtain a checkpoint if
/// this device turns out not to be a writer, so it must never be journaled
/// as if authorship were settled. "Never had policy" and "policy not loaded
/// by this process yet" must therefore take different branches: the latter
/// withholds the edit instead of landing it in native state.
#[tokio::test]
async fn local_edit_before_policy_load_must_not_enter_the_dag_with_a_placeholder_stamp_for_an_already_linked_group(
) {
    use yadorilink_replica_domain::file::FileMeta;
    use yadorilink_replica_domain::file::RecordKind;

    let state = test_state();
    let group = "group-1";

    // The group is already linked locally -- exactly the precondition
    // `app::run` checks (`sync_state.list_links()`) before resuming its
    // watcher ahead of the orchestrator. A brand-new group being shared
    // for the first time never reaches this state before its own policy
    // is established, so this precondition is what separates "existing
    // group, not loaded yet" from "genuinely policy-free group".
    state.replica_coordinator.link_repository().add_link("/links/photos", group).unwrap();

    // The startup-gap precondition: the orchestrator has not completed
    // its first netmap fetch, so nothing has populated policy state for
    // this group, and — distinct from the case
    // `is_group_policy_stale` guards — it is not marked stale either.
    assert!(state.authority.group_policy_state(group).is_none());
    assert!(!state.authority.is_group_policy_stale(group));

    // A local edit races ahead of that fetch, through the daemon's real
    // local-emission auth provider (the one `DaemonState::new` registers
    // on `sync_state`), exactly as a live watcher callback would drive it.
    let emitter = crate::test_support::local_seam::replica_author_key(
        &state.replica_coordinator,
        "device-a",
        ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]),
    )
    .unwrap();
    let version = yadorilink_replica_domain::file::FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let record = FileRecord {
        path: "note.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let result = crate::test_support::local_seam::commit_local_upsert(
        &state.replica_coordinator,
        group,
        &record,
        "device-a",
        &version,
        None,
        &emitter,
        &permit,
    );

    // An already-linked group's policy merely being unresolved
    // since startup must not be treated like a genuinely policy-free group
    // and stamped PLACEHOLDER. The unified resolver reports it `Withhold`
    // (introduced-but-not-loaded-yet), so local emission fails closed with
    // `PolicyUnavailable` — withheld exactly like the stale-policy case
    // (`local_change::stale_policy_withholds_...`), keeping the edit
    // journaled dirty to re-emit with a real authorization context once
    // the group's real policy loads, rather than landing a placeholder
    // stamp every valid-policy peer rejects.
    assert!(
        matches!(result, Err(yadorilink_sync_sqlite::SyncSqliteError::PolicyUnavailable)),
        "local emission for an already-linked, policy-not-yet-loaded group must withhold \
         (PolicyUnavailable), not stamp a placeholder-auth change; got {result:?}"
    );
    assert!(
        state.replica_coordinator.sqlite().native_group_heads(group).unwrap().is_empty(),
        "an already-linked group whose policy state has not loaded yet this run must not get \
         a placeholder-auth delta committed to its native state"
    );
}

/// `enable_disk_headroom_enforcement` must reach the executor that actually
/// runs the materialize-time preflight, not just the block store.
///
/// These are two independent mechanisms with the same name: the block
/// store's own `headroom_enforced` guards a block *write*, while
/// `LocalConvergenceExecutor::preflight_disk_headroom` guards
/// *materializing a file into a sync root* -- the one that produces
/// `DiskPressure` and degrades the link. The second was silently turned off
/// for every session by the change collapsing the peer-session facade,
/// which deleted the facade constructor's
///
/// ```text
/// inner.set_headroom_enforced(dependencies.headroom_enforced);
/// ```
///
/// while leaving `PeerSyncSessionDeps::headroom_enforced` in place for the
/// orchestrator to keep filling in from
/// `DaemonState::disk_headroom_enforcement_enabled()`. The value was
/// collected on every connection and dropped. The executor is the owner of
/// this preflight now, so the enforcement decision belongs at the point
/// this state constructs one -- which is also why this asserts on the
/// executor rather than on a session.
#[tokio::test]
async fn enabling_headroom_enforcement_reaches_the_convergence_executor() {
    let state = test_state();
    assert!(
        !state.local_convergence().headroom_enforced(),
        "sanity: off by default, exactly as the block store's own flag is"
    );

    state.enable_disk_headroom_enforcement();

    assert!(
        state.local_convergence().headroom_enforced(),
        "the materialize-time preflight must be on once this daemon enabled enforcement"
    );
}

/// The persisted governance headroom override must reach the
/// materialize-time preflight too, not only the block store.
///
/// `GovernanceConfig::headroom_override_bytes` is applied to
/// `SegmentBlockStore` in two places (`DaemonState::new` and
/// `adapters::runtime::governance`), and `recheck_degraded_links` reads it
/// directly when re-classifying a degraded volume. The executor's own
/// preflight is the one place it never arrived: the facade that could have
/// carried it had a `headroom_override_bytes` dependency field, but no
/// daemon code ever populated it -- unlike `headroom_enforced`, which was
/// populated and then dropped. So an operator who configures a reserve gets
/// it enforced on block writes and on degraded-link re-checks, while the
/// materialize preflight silently keeps using the built-in
/// `max(1 GiB, 5%)` formula. Older and separate from that regression.
#[tokio::test]
async fn the_governance_headroom_override_reaches_the_convergence_executor() {
    let _guard = CONFIG_ENV_MUTEX.lock().await;
    let config_dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", config_dir.path());

    let state = test_state();
    assert_eq!(
        state.local_convergence().headroom_override_bytes(),
        None,
        "sanity: unconfigured means the built-in formula"
    );

    state.governance_config.set_headroom_override_bytes(Some(7_000_000_000)).unwrap();

    assert_eq!(
        state.local_convergence().headroom_override_bytes(),
        Some(7_000_000_000),
        "the configured reserve must be the one the materialize preflight checks against"
    );

    std::env::remove_var("YADORILINK_CONFIG_DIR");
}

/// The release is acknowledged only when the coordination service ended its
/// lease too: a service that answers with an error leaves the lease usable.
#[tokio::test]
async fn a_release_the_coordination_service_rejects_is_not_acknowledged() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let state = test_state();
    let server = MockServer::start().await;
    state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    Mock::given(method("POST"))
        .and(path("/shares/groups/group-release/handoff/lease/lease-release/release"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    assert!(!state.release_owned_handoff_lease("group-release", "lease-release").await);
}

/// A release for a lease this device never granted is not acknowledged, even
/// though the coordination service answers such a release with success.
#[tokio::test]
async fn a_release_for_a_lease_this_device_never_granted_is_not_acknowledged() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let state = test_state();
    let server = MockServer::start().await;
    state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    Mock::given(method("POST"))
        .and(path("/shares/groups/group-release/handoff/lease/someone-elses/release"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    assert!(!state.release_owned_handoff_lease("group-release", "someone-elses").await);
}

fn pinned_version(path: &str) -> (String, i64) {
    (path.to_string(), 1)
}

/// The ordering that makes the ACK safe: the local retention pin is dropped
/// only after the coordination plane reports the lease ended. A lease a
/// running removal still holds keeps its pin, and the peer is not acknowledged;
/// a retry once the plane has released it drops the pin and acknowledges.
#[tokio::test]
async fn a_lease_the_plane_leaves_reserved_keeps_its_local_pin_until_a_retry_releases_it() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let state = test_state();
    let server = MockServer::start().await;
    state.set_coordination_client_config(
        server.uri(),
        yadorilink_fapi_client::test_support::offline_auth(),
    );
    let repo = state.replica_coordinator.handoff_lease_repository();
    repo.record_handoff_lease(
        "group-release",
        "lease-release",
        [9u8; 32],
        &[pinned_version("a.txt")],
        now_unix(),
        now_unix() + 900,
    )
    .unwrap();
    let release_path = "/shares/groups/group-release/handoff/lease/lease-release/release";
    Mock::given(method("POST"))
        .and(path(release_path))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "state": "reserved-not-released" })),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    assert!(!state.release_owned_handoff_lease("group-release", "lease-release").await);
    assert!(
        repo.leased_version_keys_for_group("group-release", now_unix())
            .unwrap()
            .contains(&pinned_version("a.txt")),
        "the pin must outlive a lease the plane still holds"
    );

    Mock::given(method("POST"))
        .and(path(release_path))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "state": "gone" })),
        )
        .mount(&server)
        .await;
    assert!(state.release_owned_handoff_lease("group-release", "lease-release").await);
    assert!(repo.leased_version_keys_for_group("group-release", now_unix()).unwrap().is_empty());
}

/// A failed or unconfigured release leaves the pin too: the plane's lease may
/// still be live.
#[tokio::test]
async fn a_release_that_does_not_reach_the_plane_keeps_the_local_pin() {
    let state = test_state();
    let repo = state.replica_coordinator.handoff_lease_repository();
    repo.record_handoff_lease(
        "group-release",
        "lease-release",
        [9u8; 32],
        &[pinned_version("a.txt")],
        now_unix(),
        now_unix() + 900,
    )
    .unwrap();

    assert!(!state.release_owned_handoff_lease("group-release", "lease-release").await);
    assert!(!repo.leased_version_keys_for_group("group-release", now_unix()).unwrap().is_empty());
}
