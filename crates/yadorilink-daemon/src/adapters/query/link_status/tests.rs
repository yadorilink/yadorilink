#![cfg(test)]

use super::*;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

pub(super) const GROUP: &str = "group-1";
pub(super) const PATH: &str = "/tmp/photos";

pub(super) fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

/// Indexes one current file record. `upsert_file` mimics a LOCAL write
/// (this device authoring new content), so it defaults to `Present`
/// -- explicitly overridden to `Remote` when `hydrated` is
/// `false`, to simulate a record synced in from a peer whose content
/// hasn't been fetched yet.
pub(super) fn upsert_file(state: &DaemonState, path: &str, hydrated: bool) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
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
    let target =
        if hydrated { MaterializationState::Present } else { MaterializationState::Remote };
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, path, target, &permit)
        .unwrap();
}

/// The group's REAL current durability-root digest -- confirmation
/// records must carry this exact digest to read as fresh, per
/// `DaemonState::fetch_available_via_confirmed_peer`'s content-binding
/// check, so tests that plant a confirmation directly (rather than
/// through a real peer round-trip) need the real value, not an
/// arbitrary placeholder.
/// The digest a real cycle would publish: the CURRENT-state one, not
/// the whole-root-set one. They differ as soon as a group retains any
/// superseded version, and a test seeding the wrong one would exercise
/// a comparison no production reader performs.
pub(super) fn real_digest(state: &DaemonState) -> [u8; 32] {
    state.local_root_set_summary(GROUP).unwrap().current_digest
}

fn reader_for(state: Arc<DaemonState>) -> DaemonLinkStatusReader {
    DaemonLinkStatusReader::new(state)
}

/// An eager link, every current file already hydrated locally, reports
/// `FullCopy` -- never derived from `materialization_policy` alone.
#[tokio::test]
async fn eager_link_fully_hydrated_is_full_copy() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    upsert_file(&state, "a.bin", true);

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].local_storage_state, LocalStorageState::FullCopy);
    assert_eq!(views[0].fetch_availability, FetchAvailability::AvailableNow);
}

/// An eager link still catching up (a placeholder present) must NOT
/// report `FullCopy` -- the exact conflation `LocalStorageState` removes (the
/// prior CLI-side reconstruction only distinguished on-demand from
/// "everything else").
#[tokio::test]
async fn eager_link_still_catching_up_is_partially_materialized() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    upsert_file(&state, "a.bin", true);
    upsert_file(&state, "b.bin", false);

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].local_storage_state, LocalStorageState::PartiallyMaterialized);
}

/// An on-demand link reports `OnDemand` regardless of hydration state
/// -- placeholders are its normal steady state, not "catching up."
#[tokio::test]
async fn on_demand_link_is_on_demand_regardless_of_hydration() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].local_storage_state, LocalStorageState::OnDemand);
}

fn set_state(state: &DaemonState, path: &str, target: MaterializationState) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, path, target, &permit)
        .unwrap();
}

fn on_demand_state() -> Arc<DaemonState> {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    state
}

/// An idle On-Demand folder (placeholders only) requests nothing; a file being hydrated and an
/// open queued for an assembly slot each are one request; a file being evicted is not.
#[tokio::test]
async fn requested_content_counts_fetches_and_queued_opens_but_not_eviction() {
    let state = on_demand_state();
    upsert_file(&state, "idle.bin", false);
    upsert_file(&state, "evict.bin", true);
    set_state(&state, "evict.bin", MaterializationState::Evicting);
    let requested = |state: &Arc<DaemonState>| {
        reader_for(state.clone()).list_links().unwrap()[0].requested_content_count
    };
    assert_eq!(requested(&state), 0);

    let queued = state.requested_opens.begin(GROUP);
    assert_eq!(requested(&state), 1);
    drop(queued);
    assert_eq!(requested(&state), 0);

    upsert_file(&state, "open.bin", false);
    set_state(&state, "open.bin", MaterializationState::Hydrating);
    let views = reader_for(state.clone()).list_links().unwrap();
    assert_eq!(views[0].requested_content_count, 1);
    assert_eq!(views[0].hydrating_count, 1, "evicting is not hydrating");
}

/// An Eager folder asks for every file it does not have yet.
#[tokio::test]
async fn eager_requested_content_is_the_unmaterialized_files() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    upsert_file(&state, "a.bin", true);
    upsert_file(&state, "b.bin", false);
    upsert_file(&state, "c.bin", false);
    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].requested_content_count, 2);
}

/// A file not yet hydrated locally, with NO reachable full-replica
/// peer, is `UnavailableNow` -- not merely "durability unknown," a
/// distinct claim.
#[tokio::test]
async fn missing_content_with_no_reachable_peer_is_unavailable_now() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].fetch_availability, FetchAvailability::UnavailableNow);
}

/// A file not yet hydrated locally, but a peer holds a REAL,
/// content-confirmed custody record for this group (not merely a
/// netmap "declared full-replica" claim -- see
/// `DaemonState::fetch_available_via_confirmed_peer`'s own doc comment
/// for why content-blind netmap metadata alone isn't sufficient
/// evidence) AND is
/// currently reachable, is `AvailableNow`.
#[tokio::test]
async fn missing_content_with_a_confirmed_reachable_peer_is_available_now() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "peer-b",
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
    );
    let digest = real_digest(&state);
    state.publish_background_custody(
        GROUP,
        crate::background_custody::BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("peer-b".into()),
            current_digest: digest,

            roots_digest_matched: true,
        },
        state.authority.membership_generation(),
        0,
    );

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].fetch_availability, FetchAvailability::AvailableNow);
}

/// A REAL content-confirmed custody record whose confirming peer is
/// NOT currently reachable must not be trusted as `AvailableNow` -- the
/// confirmation proves the peer held the content as of its own
/// staleness window, not that it can be reached right now.
#[tokio::test]
async fn confirmed_peer_that_is_not_currently_reachable_is_unavailable_now() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);
    // No reachability recorded for peer-b at all.
    let digest = real_digest(&state);
    state.publish_background_custody(
        GROUP,
        crate::background_custody::BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("peer-b".into()),
            current_digest: digest,

            roots_digest_matched: true,
        },
        state.authority.membership_generation(),
        0,
    );

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].fetch_availability, FetchAvailability::UnavailableNow);
}

/// A netmap-declared full-replica writer that is reachable, but has
/// NEVER been content-confirmed, must not be trusted as `AvailableNow`
/// -- declared role + reachability alone is not content proof.
#[tokio::test]
async fn declared_full_replica_without_content_confirmation_is_unavailable_now() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);
    state.set_peer_group_writer("peer-b", GROUP, true);
    state.authority.set_peer_group_full_replica("peer-b", GROUP, true);
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "peer-b",
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
    );

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(
        views[0].fetch_availability,
        FetchAvailability::UnavailableNow,
        "a declared-but-never-confirmed complete-copy peer must not make AvailableNow"
    );
}

/// A HIGH-severity false-`AvailableNow` gap this guards against:
/// a peer confirms the group's root set, then a NEW file
/// arrives locally as a placeholder (changing the group's real
/// durability-root set) WITHOUT bumping `membership_generation`
/// (content/root-set changes never do -- only peer authorization
/// changes do). The confirmation's own digest no longer matches the
/// group's current root digest, so it must stop counting as fresh
/// evidence, even though its generation binding alone would still
/// consider it valid.
#[tokio::test]
async fn confirmation_predating_a_new_placeholder_is_unavailable_now() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", true);
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "peer-b",
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
    );
    // Confirmed while the root set was just {a.bin}.
    let digest_before = real_digest(&state);
    state.publish_background_custody(
        GROUP,
        crate::background_custody::BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("peer-b".into()),
            current_digest: digest_before,

            roots_digest_matched: true,
        },
        state.authority.membership_generation(),
        0,
    );

    // A new file arrives as a placeholder -- the root set changes, but
    // membership_generation does not.
    let generation_before = state.authority.membership_generation();
    upsert_file(&state, "b.bin", false);
    assert_eq!(
        state.authority.membership_generation(),
        generation_before,
        "sanity check: a content change alone must not bump membership_generation"
    );
    assert_ne!(
        real_digest(&state),
        digest_before,
        "sanity check: the root digest must actually change when a new file is indexed"
    );

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(
        views[0].fetch_availability,
        FetchAvailability::UnavailableNow,
        "a confirmation whose digest predates a new placeholder must not read as AvailableNow"
    );
}

/// A group latched `Unknown` (a `--force` override bypassed
/// the handoff gate) must ALSO report `fetch_availability: Unknown`,
/// even with an otherwise-fresh confirmed+reachable peer -- an earlier
/// `daemon_wide_evidence_uncertain` omitted this per-group latch, so a group could show `durability
/// unknown` while `fetch_availability` still read `AvailableNow`.
#[tokio::test]
async fn latched_unknown_group_reports_fetch_availability_unknown() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "peer-b",
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
    );
    let digest = real_digest(&state);
    state.publish_background_custody(
        GROUP,
        crate::background_custody::BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("peer-b".into()),
            current_digest: digest,

            roots_digest_matched: true,
        },
        state.authority.membership_generation(),
        0,
    );
    state.latch_group_durability_unknown(GROUP).unwrap();

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].fetch_availability, FetchAvailability::Unknown);
}

/// Local certainty must win outright: every current file already
/// hydrated locally is `AvailableNow` even while this group is
/// latched `Unknown` -- daemon-wide "cannot confirm PEER
/// custody" uncertainty has nothing to do with whether THIS device's
/// own disk state is legible.
#[tokio::test]
async fn fully_hydrated_locally_is_available_now_even_when_latched_unknown() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    upsert_file(&state, "a.bin", true);
    state.latch_group_durability_unknown(GROUP).unwrap();

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].fetch_availability, FetchAvailability::AvailableNow);
}

/// A REACHABLE peer that is NOT a full-replica writer for this group
/// proves nothing about fetchability -- `FetchAvailability` must not
/// degrade into a bare alias for `PeerReachability`.
#[tokio::test]
async fn a_reachable_peer_that_is_not_a_full_replica_does_not_count() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);
    // Reachable, but never declared a full replica or writer for this
    // group.
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "peer-b",
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
    );

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(
        views[0].fetch_availability,
        FetchAvailability::UnavailableNow,
        "a reachable non-complete-copy peer must not make fetch_availability AvailableNow"
    );
}

/// A group whose policy is marked stale must report `Unknown`, not
/// `UnavailableNow` -- "cannot currently confirm" is a distinct claim
/// from "confirmed not obtainable," and reuses the SAME daemon-wide
/// uncertainty signal `durability_status` itself fails closed on.
#[tokio::test]
async fn policy_stale_group_reports_fetch_availability_unknown() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    upsert_file(&state, "a.bin", false);
    state.mark_group_policy_stale(GROUP);

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].fetch_availability, FetchAvailability::Unknown);
}

/// A paused Eager folder requests nothing new, and an open that already has a `Hydrating` row
/// is one request, not two.
#[tokio::test]
async fn paused_eager_requests_nothing_and_a_hydrating_open_is_counted_once() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    upsert_file(&state, "b.bin", false);
    state.replica_coordinator.link_repository().set_paused(PATH, true).unwrap();
    assert_eq!(reader_for(state.clone()).list_links().unwrap()[0].requested_content_count, 0);

    let state = on_demand_state();
    upsert_file(&state, "open.bin", false);
    set_state(&state, "open.bin", MaterializationState::Hydrating);
    let _open = state.requested_opens.begin(GROUP);
    assert_eq!(reader_for(state).list_links().unwrap()[0].requested_content_count, 1);
}

/// Indexes a placeholder (`Remote`) whose single block is `hash`, so a test controls whether the
/// bytes are held locally.
fn upsert_placeholder_with_block(state: &DaemonState, path: &str, hash: &[u8]) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: path.into(),
                size: 4,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash: hash.to_vec(), offset: 0, size: 4 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    set_state(state, path, MaterializationState::Remote);
}

/// Stores a block and returns its raw hash.
fn store_block(state: &DaemonState, bytes: &[u8]) -> Vec<u8> {
    hex::decode(state.block_store.put(bytes).unwrap().as_str()).unwrap()
}

fn fetch_availability(state: &Arc<DaemonState>) -> FetchAvailability {
    reader_for(state.clone()).list_links().unwrap()[0].fetch_availability
}

/// A placeholder whose every block this device already holds, and holds for this group, reads
/// fine, so status must not say fetching is unconfirmed (no peer needed).
#[tokio::test]
async fn placeholder_with_all_blocks_held_locally_is_available_now() {
    let state = on_demand_state();
    let hash = store_block(&state, b"data");
    state.replica_coordinator.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();
    upsert_placeholder_with_block(&state, "a.bin", &hash);
    assert_eq!(fetch_availability(&state), FetchAvailability::AvailableNow);
}

/// Bytes in the store without provenance for this group are not the group's content: a read
/// would fetch them again, so they prove nothing.
#[tokio::test]
async fn blocks_held_without_group_provenance_are_not_available() {
    let state = on_demand_state();
    let hash = store_block(&state, b"data");
    upsert_placeholder_with_block(&state, "a.bin", &hash);
    assert_eq!(fetch_availability(&state), FetchAvailability::UnavailableNow);
}

/// One placeholder with a block this device lacks keeps the whole folder unconfirmed.
#[tokio::test]
async fn one_placeholder_missing_a_block_keeps_the_folder_unavailable() {
    let state = on_demand_state();
    let held = store_block(&state, b"data");
    state.replica_coordinator.record_block_provenance(GROUP, std::slice::from_ref(&held)).unwrap();
    upsert_placeholder_with_block(&state, "held.bin", &held);
    upsert_placeholder_with_block(&state, "gone.bin", &[9u8; 32]);
    assert_eq!(fetch_availability(&state), FetchAvailability::UnavailableNow);
}

/// A file being evicted is losing its bytes, so local blocks do not make it available.
#[tokio::test]
async fn an_evicting_file_does_not_count_as_held_locally() {
    let state = on_demand_state();
    let hash = store_block(&state, b"data");
    state.replica_coordinator.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();
    upsert_placeholder_with_block(&state, "a.bin", &hash);
    set_state(&state, "a.bin", MaterializationState::Evicting);
    assert_eq!(fetch_availability(&state), FetchAvailability::UnavailableNow);
}

/// The check is bounded: past the budget the answer fails closed to the peer-based derivation
/// instead of reading an unbounded number of rows on every status call.
#[tokio::test]
async fn more_placeholders_than_the_budget_fail_closed() {
    let state = on_demand_state();
    let hash = store_block(&state, b"data");
    state.replica_coordinator.record_block_provenance(GROUP, std::slice::from_ref(&hash)).unwrap();
    for i in 0..=LOCAL_BLOCK_CHECK_FILE_BUDGET {
        upsert_placeholder_with_block(&state, &format!("f{i}.bin"), &hash);
    }
    assert_eq!(fetch_availability(&state), FetchAvailability::UnavailableNow);
}
