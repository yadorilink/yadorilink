//! The replica that seals a checkpoint adopts it the way a joiner adopts a
//! bundle's: the frontier it covers is persisted and it counts as trusted, in one
//! step, and only once the seal authorization has verified.

use super::*;
use crate::native_checkpoint_frontier::{
    checkpoint_coverage, most_recently_adopted_checkpoint, CheckpointCoverage,
};

fn count(c: &Connection, table: &str) -> i64 {
    c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0)).unwrap()
}

fn frontier_of(bundle: &NativeBootstrap) -> NativeAuthorFrontier {
    yadorilink_replica_domain::native_frontier::frontier_of_states(&bundle.author_states().unwrap())
}

#[test]
fn sealing_adopts_the_checkpoint_with_the_frontier_it_covers() {
    let (source, _a, _b) = source();
    let bundle = built(&source);
    let id = bundle.checkpoint.checkpoint_hash().0;
    assert!(most_recently_adopted_checkpoint(&source, &group()).unwrap().is_none());

    adopt_own_seal(&source, &group(), &bundle, &Policy).unwrap();

    let trusted = most_recently_adopted_checkpoint(&source, &group()).unwrap().unwrap();
    assert_eq!(trusted.checkpoint_id, id);
    assert_eq!(trusted.author_state_root, bundle.checkpoint.author_state_root.0);
    let coverage = checkpoint_coverage(&source, &group(), &id).unwrap();
    assert_eq!(coverage.frontier(), frontier_of(&bundle));
    assert!(!coverage.frontier().is_empty());
    assert_eq!(coverage.recomputed_root(), bundle.checkpoint.author_state_root.0);
}

#[test]
fn adopting_the_same_seal_again_changes_nothing() {
    let (source, _a, _b) = source();
    let bundle = built(&source);
    adopt_own_seal(&source, &group(), &bundle, &Policy).unwrap();
    let first = most_recently_adopted_checkpoint(&source, &group()).unwrap();
    adopt_own_seal(&source, &group(), &bundle, &Policy).unwrap();
    assert_eq!(most_recently_adopted_checkpoint(&source, &group()).unwrap(), first);
    assert_eq!(count(&source, "native_checkpoints"), 1);
    assert_eq!(count(&source, "native_checkpoint_frontier") as usize, bundle.authors.len());
}

#[test]
fn a_seal_the_policy_does_not_vouch_for_adopts_nothing() {
    let (source, _a, _b) = source();
    let bundle = built(&source);
    adopt_own_seal(&source, &group(), &bundle, &ViewersOnly).unwrap_err();
    assert!(most_recently_adopted_checkpoint(&source, &group()).unwrap().is_none());
    for table in
        ["native_checkpoints", "native_checkpoint_seal_evidence", "native_checkpoint_frontier"]
    {
        assert_eq!(count(&source, table), 0, "{table}");
    }
}

#[test]
fn a_bundle_without_its_seal_adopts_nothing() {
    let (source, _a, _b) = source();
    let mut bundle = built(&source);
    bundle.seal = None;
    adopt_own_seal(&source, &group(), &bundle, &Policy).unwrap_err();
    assert!(most_recently_adopted_checkpoint(&source, &group()).unwrap().is_none());
    assert_eq!(count(&source, "native_checkpoints"), 0);
}

#[test]
fn a_checkpoint_installed_without_a_verified_seal_is_not_trusted() {
    let (source, _a, _b) = source();
    let checkpoint =
        crate::native_store::seal_checkpoint(&source, &group(), &sealer_key()).unwrap();
    crate::native_store::install_checkpoint(
        &source,
        &group(),
        &checkpoint,
        &sealer_key().verifying_key(),
    )
    .unwrap();
    assert_eq!(count(&source, "native_checkpoints"), 1);
    assert!(most_recently_adopted_checkpoint(&source, &group()).unwrap().is_none());
}

#[test]
fn the_most_recently_adopted_checkpoint_is_the_last_one_adopted() {
    let (source, a, _b) = source();
    let first = built(&source);
    adopt_own_seal(&source, &group(), &first, &Policy).unwrap();

    let key = device_key(1);
    let seq = crate::native_store::load_frontier(&source, &group()).unwrap()[&a].seq.get() + 1;
    let tip = crate::native_store::load_frontier(&source, &group()).unwrap()[&a].tip;
    publish(&source, &a, &key, put_delta(&a, seq, Some(tip), "z", 4));
    let second = built(&source);
    assert_ne!(first.checkpoint.checkpoint_hash(), second.checkpoint.checkpoint_hash());
    adopt_own_seal(&source, &group(), &second, &Policy).unwrap();

    let trusted = most_recently_adopted_checkpoint(&source, &group()).unwrap().unwrap();
    assert_eq!(trusted.checkpoint_id, second.checkpoint.checkpoint_hash().0);
    let older =
        checkpoint_coverage(&source, &group(), &first.checkpoint.checkpoint_hash().0).unwrap();
    assert_eq!(older, CheckpointCoverage { states: first.author_states().unwrap() });
}

#[test]
fn a_failure_while_adopting_the_own_seal_leaves_nothing() {
    let (source, _a, _b) = source();
    let bundle = built(&source);
    source
        .execute_batch(
            "CREATE TEMP TRIGGER own_seal_failpoint BEFORE INSERT ON main.native_checkpoint_frontier \
             BEGIN SELECT RAISE(ABORT, 'injected crash'); END;",
        )
        .unwrap();
    let error = adopt_own_seal(&source, &group(), &bundle, &Policy).unwrap_err();
    assert!(error.to_string().contains("injected crash"), "{error}");
    assert!(most_recently_adopted_checkpoint(&source, &group()).unwrap().is_none());
    assert_eq!(count(&source, "native_checkpoints"), 0);
    assert_eq!(count(&source, "native_checkpoint_seal_evidence"), 0);
}

#[test]
fn a_joiner_trusts_the_checkpoint_it_joined_from() {
    let (source, _a, _b) = source();
    let bundle = built(&source);
    let fresh = conn();
    join_bundle(bundle.clone(), &fresh).unwrap();
    let trusted = most_recently_adopted_checkpoint(&fresh, &group()).unwrap().unwrap();
    assert_eq!(trusted.checkpoint_id, bundle.checkpoint.checkpoint_hash().0);
}

/// The latest trusted checkpoint follows the adoption time, not the checkpoints'
/// ages: an older one adopted at a later time is the latest.
#[test]
fn the_most_recently_adopted_checkpoint_follows_adoption_time_and_not_checkpoint_age() {
    let (source, a, _b) = source();
    let first = built(&source);
    adopt_own_seal(&source, &group(), &first, &Policy).unwrap();
    let key = device_key(1);
    let frontier = crate::native_store::load_frontier(&source, &group()).unwrap();
    let (seq, tip) = (frontier[&a].seq.get() + 1, frontier[&a].tip);
    publish(&source, &a, &key, put_delta(&a, seq, Some(tip), "z", 4));
    let second = built(&source);
    adopt_own_seal(&source, &group(), &second, &Policy).unwrap();

    source
        .execute(
            "UPDATE native_checkpoints SET installed_at_unixtime = installed_at_unixtime + 100 \
             WHERE checkpoint_hash = ?1",
            [first.checkpoint.checkpoint_hash().0.as_slice()],
        )
        .unwrap();

    let latest = most_recently_adopted_checkpoint(&source, &group()).unwrap().unwrap();
    assert_eq!(latest.checkpoint_id, first.checkpoint.checkpoint_hash().0);
}

/// Nothing in production code reads `most_recently_adopted_checkpoint` (it orders
/// by adoption, which is not monotone along the frontier), so admission and the
/// choice of a rebootstrap target cannot depend on it being the furthest
/// checkpoint. A new production consumer fails this test and has to decide what
/// it needs instead (frontier coverage or the history floor). The old
/// `latest_*checkpoint` names are gone.
#[test]
fn the_diagnostic_most_recently_adopted_checkpoint_is_not_used_by_admission_or_target_choice() {
    fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "tests") {
                    continue;
                }
                sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs")
                && !path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
            {
                out.push(path);
            }
        }
    }
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for member in std::fs::read_dir(&crates).unwrap() {
        let src = member.unwrap().path().join("src");
        if src.is_dir() {
            sources(&src, &mut files);
        }
    }
    assert!(files.len() > 100, "the scan found {} files", files.len());
    let mentioning = |needle: &str| -> Vec<_> {
        files
            .iter()
            .filter(|path| std::fs::read_to_string(path).unwrap().contains(needle))
            .collect()
    };
    let users: Vec<_> = mentioning("most_recently_adopted_checkpoint")
        .into_iter()
        .filter(|path| !path.ends_with("native_checkpoint_frontier.rs"))
        .collect();
    assert!(users.is_empty(), "production readers of the diagnostic checkpoint: {users:?}");
    for old in ["latest_trusted_checkpoint", "latest_checkpoint"] {
        let users = mentioning(old);
        assert!(users.is_empty(), "the old name {old} is still used: {users:?}");
    }
}
