//! Test-only reference for [`crate::native_store::install_verified_delta_inner`]:
//! the install as it was before it became incremental, loading the whole
//! group's `NativeState`, applying the delta to it, and replacing every
//! persisted head and context row of the group. It is deliberately a plain
//! full-state implementation, so a differential test can hold the incremental
//! install to exactly what it persists and returns.

use ed25519_dalek::VerifyingKey;
use rusqlite::Connection;

use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath};
use yadorilink_replica_domain::native_frontier;
use yadorilink_replica_domain::native_state::{AuthorError, HeadPayload, RemoteOp};
use yadorilink_replica_domain::signed_delta::NativeDelta;

use crate::error::SyncSqliteError;
use crate::native_store::{
    frontier_entry_get, install_state, load_state, record_installed_delta, InstallOutcome,
};

/// [`crate::native_store::install_verified_delta_inner`] over the whole
/// group's state.
pub(crate) fn install_verified_delta_full_state(
    conn: &Connection,
    group_id: &FolderGroupId,
    delta: &NativeDelta,
    author_public_key: &VerifyingKey,
) -> Result<InstallOutcome, SyncSqliteError> {
    delta
        .verify_signature(author_public_key)
        .map_err(|_| SyncSqliteError::InvalidInput("delta signature does not verify".into()))?;
    if delta.group_id != *group_id {
        return Err(SyncSqliteError::InvalidInput(format!(
            "delta is signed for group {:?}, not the group {group_id:?} this call was made against",
            delta.group_id
        )));
    }

    let current = frontier_entry_get(conn, group_id, &delta.author)?;
    native_frontier::check_chain_advance(current.as_ref(), delta.prev, delta.seq).map_err(
        |err| {
            SyncSqliteError::InvalidInput(format!(
                "delta does not continue its author's frontier chain: {err}"
            ))
        },
    )?;

    let delta_hash = delta.delta_hash();
    let mut state = load_state(conn, group_id)?;

    let mut ops_by_path: std::collections::BTreeMap<SyncPath, RemoteOp> =
        std::collections::BTreeMap::new();
    for op in &delta.ops {
        let entry = ops_by_path.entry(op.path.clone()).or_insert_with(|| RemoteOp {
            path: op.path.clone(),
            removes: Vec::new(),
            put: None,
        });
        entry.removes.extend(op.removes.iter().cloned());
        entry.put =
            op.put.as_ref().map(|put| HeadPayload { version: put.version, provenance: delta_hash });
    }
    let ops: Vec<RemoteOp> = ops_by_path.into_values().collect();

    let dot =
        state.receive_verified(&delta.author, delta.seq, &ops).map_err(|err: AuthorError| {
            SyncSqliteError::InvalidInput(format!("verified delta was malformed: {err}"))
        })?;
    if dot.seq != delta.seq {
        return Err(SyncSqliteError::CorruptState(format!(
            "verified delta claimed seq {:?} but the state's own next dot was {:?}",
            delta.seq, dot.seq
        )));
    }
    if let Err(violation) = state.check_invariants() {
        return Ok(InstallOutcome::WouldViolateInvariant(violation));
    }

    install_state(conn, group_id, &state)?;
    record_installed_delta(conn, group_id, delta)?;
    Ok(InstallOutcome::Installed(dot))
}

/// Helpers for differential tests that run two databases side by side.
pub(crate) mod support {
    use rusqlite::Connection;

    /// A small deterministic generator (splitmix64) so a failing sequence
    /// reproduces from its seed.
    pub(crate) struct Rng(pub(crate) u64);

    impl Rng {
        pub(crate) fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        pub(crate) fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        pub(crate) fn chance(&mut self, percent: u64) -> bool {
            self.next() % 100 < percent
        }
    }

    /// Every row of every native table, and the identity of each projection
    /// obligation (without its timestamps), in a canonical order. The state
    /// token is left out: it is random per write, so two databases that hold
    /// the same state never hold the same token.
    pub(crate) fn dump_native(c: &Connection) -> Vec<String> {
        let mut tables: Vec<String> = c
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name LIKE 'native\\_%' ESCAPE '\\' \
                 AND name <> 'native_state_generation' ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        tables.push("projection_obligations".to_owned());
        let mut out = Vec::new();
        for table in tables {
            let select = if table == "projection_obligations" {
                "SELECT group_id, path, invalidation_generation, state, origin FROM \
                 projection_obligations"
                    .to_owned()
            } else {
                format!("SELECT * FROM {table}")
            };
            let mut stmt = c.prepare(&select).unwrap();
            let columns = stmt.column_count();
            let mut rows: Vec<String> = stmt
                .query_map([], |row| {
                    let mut cells = Vec::with_capacity(columns);
                    for column in 0..columns {
                        cells.push(format!("{:?}", row.get_ref(column).unwrap()));
                    }
                    Ok(cells.join("|"))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows.sort();
            out.push(format!("{table}: {rows:?}"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, VersionHash};
    use yadorilink_replica_domain::native_state::{DeltaHash, Dot};
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, HeadRef};

    use super::support::{self, Rng};
    use super::*;
    use crate::native_store::{install_verified_delta_inner, load_frontier};

    fn group() -> FolderGroupId {
        FolderGroupId("g1".into())
    }

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&c).unwrap();
        c
    }

    fn author_id(index: usize) -> AuthorId {
        AuthorId {
            device: DeviceId(format!("device-{index}")),
            incarnation: IncarnationId([index as u8 + 1; 16]),
        }
    }

    /// What a verdict or error text contains, one entry per kind the
    /// generator has to reach.
    const VERDICT_KINDS: [&str; 4] = [
        "ok Installed",
        "ok WouldViolateInvariant",
        "does not continue its author's frontier chain",
        "verified delta was malformed",
    ];

    const PATHS: [&str; 7] = ["a", "a/b", "a/b/c", "a/d", "e", "e/f", "g"];

    fn outcome(result: Result<InstallOutcome, SyncSqliteError>) -> String {
        match result {
            Ok(outcome) => format!("ok {outcome:?}"),
            Err(error) => format!("err {error}"),
        }
    }

    /// One random delta of `author`, built from what the incremental side
    /// holds: removals of live heads (mostly with their true provenance, some
    /// with a wrong one), of dots nobody has seen, and of a dot named twice;
    /// puts of assorted versions.
    fn random_delta(
        rng: &mut Rng,
        incremental: &Connection,
        keys: &[SigningKey],
        who: usize,
    ) -> NativeDelta {
        let author = author_id(who);
        let state = crate::native_store::load_state(incremental, &group()).unwrap();
        let frontier = load_frontier(incremental, &group()).unwrap();
        let entry = frontier.get(&author);
        let (seq, prev) = match entry {
            None => (AuthorSeq::FIRST, None),
            Some(entry) => (entry.seq.checked_next().unwrap(), Some(entry.tip)),
        };
        // Sometimes break the chain: a duplicate, a skipped seq, a wrong prev.
        let (seq, prev) = match rng.below(40) {
            0 => (entry.map_or(AuthorSeq::FIRST, |e| e.seq), prev),
            1 => (AuthorSeq(seq.get() + 2), prev),
            2 => (seq, Some(DeltaHash([0xAB; 32]))),
            _ => (seq, prev),
        };

        let mut paths: Vec<&str> = Vec::new();
        for _ in 0..1 + rng.below(3) {
            let path = PATHS[rng.below(PATHS.len())];
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        let mut ops = Vec::new();
        for path in paths {
            let sync = SyncPath(path.into());
            let mut removes = Vec::new();
            for head in state.heads_at(&sync) {
                if rng.chance(55) {
                    let header = if rng.chance(85) {
                        head.payload.provenance
                    } else {
                        DeltaHash([0xEE; 32])
                    };
                    removes.push(HeadRef { dot: head.dot, provenance: header });
                }
            }
            if rng.chance(12) {
                // A dot of an author this replica has never heard of.
                removes.push(HeadRef {
                    dot: Dot { author: author_id(9), seq: AuthorSeq(1 + rng.below(3) as u64) },
                    provenance: DeltaHash([0x77; 32]),
                });
            }
            if rng.chance(4) && !removes.is_empty() {
                let dup = removes[0].clone();
                removes.push(dup);
            }
            let put = rng
                .chance(70)
                .then(|| DeltaPut { version: VersionHash([1 + rng.below(4) as u8; 32]) });
            ops.push(DeltaOp { path: sync, removes, put });
        }
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author,
            seq,
            prev,
            ops,
            signature: [0u8; 64],
        };
        delta.sign(&keys[who]);
        delta
    }

    /// How many seeds the comparison below runs. Each seed is a 24-step sequence checked
    /// against the reference row by row, which is CPU-bound and single-threaded: 1500 seeds
    /// take 700-850 s in a debug build, 200 take about 95 s. The verdict-coverage floor below
    /// (20 of each kind) needs at least 200 seeds with these generators. The default is the
    /// short run for pull requests and sweeps; set `NATIVE_REFERENCE_SEEDS=1500` for the
    /// exhaustive run (periodic or exploratory runs).
    const DEFAULT_SEEDS: u64 = 200;

    fn seed_count() -> u64 {
        match std::env::var("NATIVE_REFERENCE_SEEDS") {
            Ok(value) => value
                .parse()
                .unwrap_or_else(|_| panic!("NATIVE_REFERENCE_SEEDS must be a number: {value:?}")),
            Err(_) => DEFAULT_SEEDS,
        }
    }

    /// The incremental install and the full-state reference agree on every
    /// verdict, every error, and every persisted row, for random sequences of
    /// concurrent authors' deltas: removals of live, stale and unseen dots,
    /// deltas refused for the invariant, and duplicate delivery.
    #[test]
    fn the_incremental_install_matches_the_full_state_reference() {
        let keys: Vec<SigningKey> =
            (0..4).map(|i| SigningKey::from_bytes(&[i as u8 + 11; 32])).collect();
        let mut verdicts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for seed in 0..seed_count() {
            let mut rng = Rng(seed);
            let incremental = conn();
            let reference = conn();
            let mut earlier: Vec<(NativeDelta, usize)> = Vec::new();
            for step in 0..24 {
                let (delta, who) = if !earlier.is_empty() && rng.chance(8) {
                    // Duplicate delivery of something already installed.
                    earlier[rng.below(earlier.len())].clone()
                } else {
                    let who = rng.below(keys.len());
                    (random_delta(&mut rng, &incremental, &keys, who), who)
                };
                let key = keys[who].verifying_key();
                let got =
                    outcome(install_verified_delta_inner(&incremental, &group(), &delta, &key));
                let want =
                    outcome(install_verified_delta_full_state(&reference, &group(), &delta, &key));
                assert_eq!(got, want, "seed {seed} step {step}: verdicts differ");
                assert_eq!(
                    support::dump_native(&incremental),
                    support::dump_native(&reference),
                    "seed {seed} step {step}: persisted rows differ after {got}"
                );
                for kind in VERDICT_KINDS {
                    if got.contains(kind) {
                        *verdicts.entry(kind.to_owned()).or_default() += 1;
                    }
                }
                if got.starts_with("ok Installed") {
                    earlier.push((delta, who));
                }
            }
        }
        // The generator must actually reach every kind of verdict, or the
        // comparison above proves little.
        for kind in VERDICT_KINDS {
            let seen = verdicts.get(kind).copied().unwrap_or(0);
            assert!(
                seen >= 20,
                "the generator reached {kind:?} only {seen} times in {} seeds (fewer than {DEFAULT_SEEDS} \
                 cannot reach every verdict kind): {verdicts:?}",
                seed_count()
            );
        }
    }
}
