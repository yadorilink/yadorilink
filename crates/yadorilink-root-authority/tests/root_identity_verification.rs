//! This crate's own `#[cfg(test)]` compilation and this integration-test
//! binary are distinct builds of `ReplicaCoordinator` (same reasoning as
//! `materialization_local_capture.rs`'s identical relocation in Phase
//! 7D-8.6's move of `LocalChangeProcessor`), so the coverage that needs a
//! concrete, real `ReplicaCoordinator` has to live in a binary that links
//! `yadorilink-daemon` as an ordinary external dependency -- which an
//! external `tests/*.rs` binary always does, regardless of `cfg(test)`.
//! `only_the_top_level_marker_is_recognized` (pure,
//! zero-`ReplicaCoordinator`) stayed behind in
//! `yadorilink-root-authority::root_identity`'s own `#[cfg(test)]` module
//! instead of moving here -- see that module's doc.

use std::path::{Path, PathBuf};

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME;
use yadorilink_root_authority::error::RootAuthorityError;
use yadorilink_root_authority::root_identity::{
    read_root_marker_for_test, write_root_marker_for_test, VerifiedRoot,
};

/// A registered link is the production shape, and the token column lives on
/// that row — without one there is nothing to persist a token *to*, so a
/// test that skipped this would silently only exercise the marker half of
/// the check.
fn linked_state(root: &Path, group_id: &str) -> ReplicaCoordinator {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state.link_repository().add_link(&root.to_string_lossy(), group_id).unwrap();
    state
}

/// A fresh link (empty index, empty folder) adopts: there is nothing to
/// lose, and this is how every new link acquires its identity.
#[test]
fn a_fresh_empty_root_is_adopted_and_marked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = linked_state(&root, "group-1");

    let verified = VerifiedRoot::open(&root, "group-1", &state).unwrap();

    assert_eq!(verified.path(), root);
    assert!(root.join(ROOT_MARKER_FILE_NAME).exists(), "adoption must leave a marker");
    assert!(
        state.link_repository().link_root_token_for_group("group-1").unwrap().is_some(),
        "adoption must persist the token it wrote into the marker"
    );
}

#[test]
fn one_surviving_indexed_file_does_not_adopt_an_unmarked_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = linked_state(&root, "group-1");
    let record = |path: &str| FileRecord {
        path: path.into(),
        size: 1,
        mtime_unix_nanos: 1,
        blocks: vec![],
        deleted: false,
    };
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &record("survivor.txt"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &record("missing.txt"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    std::fs::write(root.join("survivor.txt"), b"x").unwrap();

    assert!(VerifiedRoot::open(&root, "group-1", &state).is_err());
    assert!(!root.join(ROOT_MARKER_FILE_NAME).exists());
}

/// Regression test for the race `root_adoption_lock` closes: two
/// concurrent callers racing to adopt the same still-unmarked root must
/// not each mint and write their own token -- `write_marker` and
/// `set_link_root_token_for_group` are two separate, non-atomic writes,
/// so two unsynchronized adopters can leave the marker-on-disk and the
/// persisted-in-DB token disagreeing forever (found via a self-hosted
/// Linux CI runner tracing `directory_conflict_matrix.rs`'s concurrent-
/// rename scenario: two `adopt_unmarked_root` calls for the same root
/// ~90us apart, both `had_persisted=false`, minting two different
/// tokens). Real OS threads plus a barrier force the two `open()` calls
/// to actually overlap; looped since the original race was probabilistic
/// (roughly 1 in 40 adoptions on a loaded host).
#[test]
fn concurrent_adoption_of_the_same_unmarked_root_never_disagrees_with_itself() {
    for _ in 0..50 {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        // File-backed (WAL), not `open_in_memory`: that backend's
        // shared-cache mode manufactures `SQLITE_LOCKED` under this
        // test's deliberately extreme 8-way concurrency -- a lock class
        // `busy_timeout` does not retry and production's real WAL+pool
        // path essentially never reaches. That's a harness artifact of
        // the in-memory backend, not the race this test exists to catch.
        let db_dir = tempfile::tempdir().unwrap();
        let state = ReplicaCoordinator::open(db_dir.path().join("state.sqlite3")).unwrap();
        state.link_repository().add_link(&root.to_string_lossy(), "group-1").unwrap();
        let state = std::sync::Arc::new(state);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));

        let results: Vec<_> = (0..8)
            .map(|_| {
                let state = state.clone();
                let root = root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    VerifiedRoot::open(&root, "group-1", state.as_ref())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();

        // A racing adoption of a still-unmarked root must still succeed
        // for both callers -- losing the race to adopt first is not
        // itself an error, only disagreeing about the outcome is.
        for r in &results {
            assert!(r.is_ok(), "a racing adoption must still succeed: {r:?}");
        }
        // Decisive check: re-opening afterward must succeed cleanly. If
        // the two racers had written disagreeing tokens, this would fail
        // with a permanent "root token is not the one this link adopted"
        // error.
        assert!(
            VerifiedRoot::open(&root, "group-1", state.as_ref()).is_ok(),
            "re-opening after a racing adoption must not find a mismatched token"
        );
    }
}

/// The token is an identity nonce, not a derivation: two folders alike in
/// every visible respect must still be distinguishable.
#[test]
fn each_adoption_mints_a_distinct_token() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let root_a = dir_a.path().canonicalize().unwrap();
    let root_b = dir_b.path().canonicalize().unwrap();
    let state_a = linked_state(&root_a, "group-1");
    let state_b = linked_state(&root_b, "group-1");
    VerifiedRoot::open(&root_a, "group-1", &state_a).unwrap();
    VerifiedRoot::open(&root_b, "group-1", &state_b).unwrap();

    assert_ne!(
        state_a.link_repository().link_root_token_for_group("group-1").unwrap(),
        state_b.link_repository().link_root_token_for_group("group-1").unwrap()
    );
}

/// Re-opening an already-adopted root is the steady state and must be
/// stable — in particular it must not re-mint, which would make the token
/// meaningless.
#[test]
fn reopening_an_adopted_root_keeps_its_token() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = linked_state(&root, "group-1");
    VerifiedRoot::open(&root, "group-1", &state).unwrap();
    let first = state.link_repository().link_root_token_for_group("group-1").unwrap();
    assert!(first.is_some(), "adoption must have persisted a token to re-check against");

    VerifiedRoot::open(&root, "group-1", &state).unwrap();

    assert_eq!(first, state.link_repository().link_root_token_for_group("group-1").unwrap());
}

/// A marker naming another group means the mount landed in the wrong place.
#[test]
fn a_marker_for_another_group_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = linked_state(&root, "group-1");
    write_root_marker_for_test(&root, "someone-elses-group", "aa");

    let err = VerifiedRoot::open(&root, "group-1", &state).unwrap_err();

    assert!(matches!(err, RootAuthorityError::RootIdentityMismatch(_)), "got {err:?}");
}

/// A corrupt marker must fail closed, not fall through to the
/// "no marker, adopt me" path — that would let a single truncated byte
/// re-arm the bug.
#[test]
fn an_unparsable_marker_is_an_error_not_an_absent_marker() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = linked_state(&root, "group-1");
    std::fs::write(root.join(ROOT_MARKER_FILE_NAME), b"{ this is not json").unwrap();

    assert!(VerifiedRoot::open(&root, "group-1", &state).is_err());
}

/// The explicit way past a refusal. `readopt` is the only thing that may
/// re-establish identity, and it must actually work — otherwise a user
/// whose folder legitimately emptied is stuck forever.
#[test]
fn readopt_replaces_the_token_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = linked_state(&root, "group-1");
    VerifiedRoot::open(&root, "group-1", &state).unwrap();
    let original = state.link_repository().link_root_token_for_group("group-1").unwrap();
    assert!(original.is_some(), "the folder must be adopted before it can be re-adopted");

    VerifiedRoot::readopt(&root, "group-1", &state).unwrap();
    let readopted = state.link_repository().link_root_token_for_group("group-1").unwrap();

    assert_ne!(original, readopted, "re-adoption must mint a new identity");
    assert!(
        VerifiedRoot::open(&root, "group-1", &state).is_ok(),
        "the folder must verify cleanly afterwards"
    );
}

/// A root that does not exist at all still errors — the pre-existing guard
/// this module subsumed, kept honest.
#[test]
fn a_missing_root_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("never-created");
    let state = linked_state(&missing, "group-1");

    assert!(VerifiedRoot::open(&missing, "group-1", &state).is_err());
}

// --- One live link per group -------------------------------------------

/// The gate must refuse BEFORE the adoption dispatch, which writes. A check
/// placed after it would let `adopt_unmarked_root` write a marker and stamp
/// the row first.
#[test]
fn verified_root_open_refuses_before_writing_anything() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let state = linked_state(a.path(), "group-1");
    state
        .link_repository()
        .force_second_live_link_for_test(&b.path().to_string_lossy(), "group-1")
        .unwrap();

    let err = VerifiedRoot::open(a.path(), "group-1", &state)
        .expect_err("an ambiguous group must not produce a VerifiedRoot");
    assert!(matches!(err, RootAuthorityError::AmbiguousLink { .. }), "got {err:?}");

    assert!(
        !a.path().join(ROOT_MARKER_FILE_NAME).exists(),
        "the refusal must not have written a marker into either folder"
    );
    assert!(!b.path().join(ROOT_MARKER_FILE_NAME).exists());
    assert_eq!(
        state.link_repository().link_root_tokens_for_group_unchecked_for_test("group-1").unwrap(),
        vec![None, None],
        "the refusal must not have stamped a token onto either row"
    );
}

/// The laundering mechanism: `adopt_unmarked_root` reuses the token already
/// persisted for the group, so the SECOND root would write the FIRST root's
/// token into its own marker -- after which BOTH folders verify
/// successfully, forever, and their mutual tombstoning is permanent and
/// invisible.
#[test]
fn adopt_does_not_launder_a_second_root_with_the_first_roots_token() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let state = linked_state(a.path(), "group-1");
    VerifiedRoot::open(a.path(), "group-1", &state).unwrap();
    assert!(a.path().join(ROOT_MARKER_FILE_NAME).exists(), "A adopts normally");

    state
        .link_repository()
        .force_second_live_link_for_test(&b.path().to_string_lossy(), "group-1")
        .unwrap();

    let err = VerifiedRoot::open(b.path(), "group-1", &state)
        .expect_err("the second root must not adopt");
    assert!(matches!(err, RootAuthorityError::AmbiguousLink { .. }), "got {err:?}");
    assert!(
        !b.path().join(ROOT_MARKER_FILE_NAME).exists(),
        "B must not be handed A's token: with it, both roots verify forever"
    );
}

/// `readopt` mints, writes the marker and persists the token all BEFORE the
/// `Self::open` that would catch the ambiguity -- so a check only in `open`
/// fans a fresh token onto both rows and only then refuses.
#[test]
fn readopt_refuses_without_minting_or_stamping() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let state = linked_state(a.path(), "group-1");
    state.link_repository().set_link_root_token_for_group("group-1", "tok-a").unwrap();
    state
        .link_repository()
        .force_second_live_link_for_test(&b.path().to_string_lossy(), "group-1")
        .unwrap();

    let err = VerifiedRoot::readopt(a.path(), "group-1", &state)
        .expect_err("readopt must refuse an ambiguous group");
    assert!(matches!(err, RootAuthorityError::AmbiguousLink { .. }), "got {err:?}");

    assert!(
        !a.path().join(ROOT_MARKER_FILE_NAME).exists(),
        "readopt must not write a marker before refusing"
    );
    // Order-independent: the rows are ordered by `local_path`, and which of
    // the two temp dirs sorts first is not this test's subject. The property
    // is that the ONLY token present is still the pre-existing one -- no
    // freshly minted token was fanned onto either row.
    let mut tokens =
        state.link_repository().link_root_tokens_for_group_unchecked_for_test("group-1").unwrap();
    tokens.sort();
    assert_eq!(
        tokens,
        vec![None, Some("tok-a".to_string())],
        "readopt must not mint a fresh token onto the rows before refusing"
    );
}

/// Zero links still adopts: the check is `> 1`, not `!= 1`. Driving a scan
/// against a bare directory with no link row registered is a documented,
/// live case.
#[test]
fn zero_links_still_adopts() {
    let dir = tempfile::tempdir().unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();

    VerifiedRoot::open(dir.path(), "group-1", &state)
        .expect("a group with no link row must still adopt");
}

// --- One orphaned + one live link on a group: the brick ------------------

/// The identity the DEAD root adopted while it was still live. A fixed
/// value, so a test can assert the LIVE root did not inherit it.
const DEAD_TOKEN: &str = "dead0000000000000000000000000000";

/// Drives the group into "1 orphaned + 1 live link" through the ORDINARY
/// PUBLIC API ONLY -- no raw SQL. That is the point: this state is not a
/// corruption and not an attack, it is what an ordinary join that never
/// activated leaves behind when the user retries the join at a different
/// folder.
///
/// The orphaned root's `local_path` sorts BEFORE the live one's, which is
/// the ordering that makes an unfiltered `ORDER BY local_path`
/// first-row-wins read pick the DEAD root's row. Root A is also fully
/// adopted (marker on disk, token on its row) BEFORE it is orphaned, since
/// that is what a real join at A does and it is the only way the dead
/// token lands on A's row rather than B's.
///
/// The token stamped onto the orphaned root A is [`DEAD_TOKEN`].
fn one_orphaned_one_live(group: &str) -> (ReplicaCoordinator, tempfile::TempDir, PathBuf, PathBuf) {
    // ONE `TempDir` holding both roots, returned to the caller: two sibling
    // `TempDir`s inside a third would have the parent dropped here, deleting
    // both roots out from under the test.
    let parent = tempfile::tempdir().unwrap();
    let root_a = parent.path().canonicalize().unwrap().join("aaa-root");
    let root_b = parent.path().canonicalize().unwrap().join("bbb-root");
    std::fs::create_dir(&root_a).unwrap();
    std::fs::create_dir(&root_b).unwrap();
    assert!(root_a < root_b, "root A must sort first for this test to mean anything");

    let state = ReplicaCoordinator::open_in_memory().unwrap();

    // 1. The user joins the group at folder A. The daemon commits the link
    //    together with the pending-enrollment marker guarding its
    //    still-unconfirmed coordination-side activation.
    state
        .add_link_with_pending_enrollment_for_test(
            &root_a.to_string_lossy(),
            group,
            "op-1",
            "device-1",
        )
        .unwrap();

    // 1b. A is adopted, exactly as a real link at A is: marker on disk,
    //     token on A's row. Done WHILE A IS LIVE -- that is the only way the
    //     token lands on A's row, and it is what makes A a dead root that
    //     still carries an identity once step 2 orphans it.
    write_root_marker_for_test(&root_a, group, DEAD_TOKEN);
    state.link_repository().set_link_root_token_for_group(group, DEAD_TOKEN).unwrap();

    // 2. That join never activates (the daemon was offline past the TTL, so
    //    reconciliation gets `Deleted`). The link is orphaned and the marker
    //    dropped -- ONE transaction, the daemon's real reconciliation step.
    //    `root_token` is deliberately PRESERVED by that write.
    state
        .enrollment_repository()
        .orphan_link_and_remove_pending_enrollment(&root_a.to_string_lossy(), "op-1")
        .unwrap();

    // 3. The user retries the join, this time at folder B. Zero LIVE rows
    //    exist for the group, so both the Rust chokepoint's live check and
    //    the schema trigger's `EXISTS(... orphaned = 0 ...)` accept it.
    state.link_repository().add_link(&root_b.to_string_lossy(), group).unwrap();

    (state, parent, root_a, root_b)
}

/// THE BRICK. A group holding one orphaned and one live link is a state the
/// ambiguity GATE calls legal (it counts only LIVE rows -- there is exactly
/// one) but the by-`group_id` token WRITER used to see as two rows, making
/// its fan-out assert fire forever.
///
/// The consequence is not a warning: the group's SOLE LIVE ROW can never be
/// verified again on this device, and `readopt` -- the documented escape
/// hatch out of every other refusal in this module -- cannot save it either,
/// because it mints and writes the marker BEFORE the write that fails. The
/// user's group is permanently unsyncable, reachable with no attacker and no
/// corruption.
///
/// Asserts BOTH constructors, because a fix that only unbricks `open` would
/// leave the escape hatch bricked.
#[test]
fn a_group_with_one_orphaned_and_one_live_link_still_verifies_its_live_root() {
    let (state, _parent, _root_a, root_b) = one_orphaned_one_live("group-1");

    let verified = VerifiedRoot::open(&root_b, "group-1", &state).expect(
        "the group's SOLE LIVE root must verify: an orphaned sibling row is not a \
                 second root, and the gate itself calls this state legal",
    );
    assert_eq!(verified.path(), root_b);

    // The escape hatch must work too -- it is what the refusal's own message
    // sends the user to, and it writes before it can fail.
    VerifiedRoot::readopt(&root_b, "group-1", &state)
        .expect("re-adopting the group's sole live root must work in this state");
}

/// R4: the LIVE root must not inherit the DEAD root's identity.
///
/// With the orphaned row sorting first and carrying a token, an unfiltered
/// first-row-wins read hands `adopt_unmarked_root` the DEAD root's token,
/// which it stamps into the LIVE root's marker (`persisted.unwrap_or_else`).
/// That manufactures the "two folders sharing one token, permanently
/// indistinguishable" state this whole module exists to prevent -- on the
/// READ side, where no writer assert can see it.
#[test]
fn the_live_root_does_not_inherit_the_orphaned_roots_token() {
    use sha2::{Digest, Sha256};

    let (state, _parent, _root_a, root_b) = one_orphaned_one_live("group-1");
    let dead_token = DEAD_TOKEN.to_string();

    // The LIVE root B is unmarked but corroborated: one indexed file of the
    // group is present in it, so adoption proceeds.
    std::fs::write(root_b.join("present.txt"), b"hi").unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "present.txt".into(),
                size: 2,
                mtime_unix_nanos: 1,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: Sha256::digest(b"hi").to_vec(),
                    offset: 0,
                    size: 2,
                }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    VerifiedRoot::open(&root_b, "group-1", &state).expect("the live root must adopt");

    let (marker_b_group, marker_b_token) =
        read_root_marker_for_test(&root_b).expect("B must have been marked");
    let _ = marker_b_group;
    assert_ne!(
        marker_b_token, dead_token,
        "the LIVE root must mint its OWN identity, never inherit the orphaned root's -- two \
         folders sharing one token are permanently indistinguishable by the very check meant \
         to tell them apart"
    );

    // And row-level: the orphaned row's token must be UNCHANGED, and the
    // live row must carry B's own.
    let tokens =
        state.link_repository().link_root_tokens_for_group_unchecked_for_test("group-1").unwrap();
    assert_eq!(
        tokens,
        vec![Some(dead_token), Some(marker_b_token)],
        "the orphaned row's token must survive untouched and the live row must hold its own"
    );
}

/// R3: the token-absent case must NOT re-arm adoption.
///
/// Once the reader is orphan-filtered, a group whose ONLY row is orphaned
/// reads `token = None`. `None` must change only WHICH token a legitimate
/// adoption stamps (reuse vs mint) -- never WHETHER adoption happens. The
/// bare-mountpoint refusal is gated by on-disk evidence alone and is
/// token-blind, and this pins that: it must still refuse.
///
/// Asserts the ABSENCE OF A MARKER, not merely the `Err`. The marker is what
/// adoption writes, so its absence is the direct evidence that adoption did
/// not happen -- an `Err` returned after a marker was written would still be
/// a blessed bare mountpoint.
#[test]
fn a_token_absent_group_still_refuses_to_adopt_a_bare_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();

    // A link that exists but is orphaned: zero LIVE rows => token reads None.
    state.link_repository().add_link(&root.to_string_lossy(), "group-1").unwrap();
    state.link_repository().set_link_root_token_for_group("group-1", "sometoken").unwrap();
    state.link_repository().mark_link_orphaned(&root.to_string_lossy()).unwrap();
    assert_eq!(
        state.link_repository().link_root_token_for_group("group-1").unwrap(),
        None,
        "an all-orphaned group must read no token -- this test is about what happens NEXT"
    );

    // The index says this group has a file; the root is empty. That is the
    // unmount signature.
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "gone.txt".into(),
                size: 1,
                mtime_unix_nanos: 1,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    VerifiedRoot::open(&root, "group-1", &state)
        .expect_err("a token-absent group must still refuse a root with none of its files");
    assert!(
        !root.join(ROOT_MARKER_FILE_NAME).exists(),
        "the refusal must not have adopted: a marker here means the bare mountpoint was \
         blessed, which is the whole-folder loss this module exists to prevent"
    );
}

/// R3b: the same, with NO link row at all -- the other route to a `None`
/// token read. `zero_links_still_adopts` pins that this case ADOPTS when the
/// evidence supports it; this pins that the evidence, not the token, is what
/// decides.
#[test]
fn a_group_with_no_link_row_still_refuses_to_adopt_a_bare_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();

    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &yadorilink_replica_domain::file::FileRecord {
                path: "gone.txt".into(),
                size: 1,
                mtime_unix_nanos: 1,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    VerifiedRoot::open(&root, "group-1", &state)
        .expect_err("no link row must not weaken the bare-root refusal");
    assert!(!root.join(ROOT_MARKER_FILE_NAME).exists(), "the refusal must not have adopted");
}

#[test]
fn peer_verification_never_adopts_an_unmarked_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state.link_repository().add_link(&root.to_string_lossy(), "group-1").unwrap();

    VerifiedRoot::verify(&root, "group-1", &state)
        .expect_err("peer verification must require a prior explicit/startup adoption");
    assert!(!root.join(ROOT_MARKER_FILE_NAME).exists());
    assert_eq!(state.link_repository().link_root_token_for_group("group-1").unwrap(), None);

    VerifiedRoot::open(&root, "group-1", &state).unwrap();
    VerifiedRoot::verify(&root, "group-1", &state).unwrap();
}

/// An adopted folder whose marker is gone, with nothing indexed on disk to
/// vouch for it, is what the empty mountpoint of an unmounted volume looks
/// like. Marking it would send every later write to the volume underneath.
#[test]
fn an_adopted_root_that_lost_its_marker_with_nothing_to_corroborate_is_not_remarked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = linked_state(&root, "group-1");
    VerifiedRoot::open(&root, "group-1", &state).unwrap();
    std::fs::remove_file(root.join(ROOT_MARKER_FILE_NAME)).unwrap();

    let refused = VerifiedRoot::open(&root, "group-1", &state);

    assert!(matches!(refused, Err(RootAuthorityError::RootIdentityMismatch(_))), "{refused:?}");
    assert!(!root.join(ROOT_MARKER_FILE_NAME).exists(), "the bare directory must not be marked");
}

/// A folder carrying its marker but sitting on another volume than the one
/// recorded for the link (a copy on a replacement disk mounted at the same
/// path) is refused by every constructor, so nothing is written into it.
#[test]
fn a_root_off_its_recorded_volume_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let state = linked_state(&root, "group-1");
    VerifiedRoot::open(&root, "group-1", &state).unwrap();
    let here = yadorilink_fs_platform::volume_identity::StableVolumeId::observe(&root)
        .unwrap()
        .to_string();

    state.link_repository().set_capture_volume_identity_for_group("group-1", &here).unwrap();
    VerifiedRoot::verify(&root, "group-1", &state).expect("on its recorded volume");

    state
        .link_repository()
        .set_capture_volume_identity_for_group("group-1", "uuid:another-disk")
        .unwrap();
    for refused in [
        VerifiedRoot::verify(&root, "group-1", &state),
        VerifiedRoot::open(&root, "group-1", &state),
    ] {
        assert!(matches!(refused, Err(RootAuthorityError::RootIdentityMismatch(_))), "{refused:?}");
    }
}
