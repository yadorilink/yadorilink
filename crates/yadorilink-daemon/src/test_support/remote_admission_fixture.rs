//! Admits a delta by another author the way a peer's delivery does -- a
//! `NativeDelta` signed by that author's device key, run through native
//! admission, with the projection work a received delta owes -- in one
//! synchronous write.
//!
//! For tests that need "a peer's change is admitted history here" as a
//! setup step, without driving a peer session.

use yadorilink_replica_domain::author::fixtures;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{DeltaHash, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, HeadRef, NativeDelta};
use yadorilink_sync_sqlite::native_admission::{admit_native_delta, NativeAdmission};

use crate::replica_coordinator::ReplicaCoordinator;

/// One path edit of a remote delta: what it writes and the heads of the path
/// it supersedes, named by the hash of the delta that wrote each (empty: the
/// edit is concurrent with whatever the path holds).
pub enum RemoteOp {
    Put { path: String, version: VersionHash, observing: Vec<DeltaHash> },
    Delete { path: String, observing: Vec<DeltaHash> },
}

impl RemoteOp {
    fn path(&self) -> &str {
        match self {
            RemoteOp::Put { path, .. } | RemoteOp::Delete { path, .. } => path,
        }
    }

    fn observing(&self) -> &[DeltaHash] {
        match self {
            RemoteOp::Put { observing, .. } | RemoteOp::Delete { observing, .. } => observing,
        }
    }
}

/// A put of `version` at `path` superseding the heads `observing` names.
pub fn put(path: &str, version: VersionHash, observing: Vec<DeltaHash>) -> RemoteOp {
    RemoteOp::Put { path: path.to_owned(), version, observing }
}

/// A delete of `path` superseding the heads `observing` names.
pub fn delete(path: &str, observing: Vec<DeltaHash>) -> RemoteOp {
    RemoteOp::Delete { path: path.to_owned(), observing }
}

/// Signs `ops` as `device`'s next delta in `group` and admits it here.
/// The versions in `versions` are stored here, as a peer's batch carries them;
/// a put whose version is not passed names content this replica does not hold.
pub fn admit_remote(
    coordinator: &ReplicaCoordinator,
    group: &str,
    device: &str,
    ops: Vec<RemoteOp>,
    versions: &[FileVersion],
) -> NativeDelta {
    let author = fixtures::author(device, 1);
    let key = fixtures::signing_key(&author.device);
    let group_id = FolderGroupId(group.to_owned());
    let delta = coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            for op in &ops {
                if let RemoteOp::Put { version, .. } = op {
                    if let Some(carried) = versions.iter().find(|v| v.version_hash == *version) {
                        yadorilink_sync_sqlite::dag_store::put_file_version(conn, group, carried)?;
                    }
                }
            }
            let entry =
                yadorilink_sync_sqlite::native_store::frontier_entry_get(conn, &group_id, &author)?;
            let (seq, prev) = match &entry {
                None => (1, None),
                Some(entry) => (entry.seq.get() + 1, Some(entry.tip)),
            };
            let mut delta_ops = Vec::with_capacity(ops.len());
            for op in &ops {
                let heads = yadorilink_sync_sqlite::native_store::native_heads_at(
                    conn,
                    &group_id,
                    &SyncPath(op.path().to_owned()),
                )?;
                let removes: Vec<HeadRef> = heads
                    .iter()
                    .filter(|head| {
                        op.observing().iter().any(|hash| hash.0 == head.payload.provenance.0)
                    })
                    .map(|head| HeadRef {
                        dot: head.dot.clone(),
                        provenance: head.payload.provenance,
                    })
                    .collect();
                delta_ops.push(DeltaOp {
                    path: SyncPath(op.path().to_owned()),
                    removes,
                    put: match op {
                        RemoteOp::Put { version, .. } => Some(DeltaPut { version: *version }),
                        RemoteOp::Delete { .. } => None,
                    },
                });
            }
            let mut delta = NativeDelta {
                group_id: group_id.clone(),
                author: author.clone(),
                seq: yadorilink_replica_domain::ids::AuthorSeq(seq),
                prev,
                ops: delta_ops,
                recursive_part: None,
                signature: [0; 64],
            };
            delta.sign(&key);
            let verifying = key.verifying_key();
            let admission = admit_native_delta(conn, &group_id, &delta, &|a| {
                (a == &author).then_some(verifying)
            })?;
            assert!(
                matches!(admission, NativeAdmission::Admitted { .. }),
                "the fixture's delta is admitted: {admission:?}"
            );
            Ok(delta)
        })
        .unwrap();
    delta
}

/// The fork `device` makes of its own losing heads, admitted here the way a
/// peer's delivery does: the deltas of
/// [`yadorilink_replica_domain::native_fork::plan_own_forks`] over this
/// replica's state, signed by `device`. The number of deltas admitted.
pub fn admit_remote_forks(coordinator: &ReplicaCoordinator, group: &str, device: &str) -> usize {
    use yadorilink_replica_domain::native_fork::{plan_own_forks, ForkLimits};
    let author = fixtures::author(device, 1);
    let key = fixtures::signing_key(&author.device);
    let group_id = FolderGroupId(group.to_owned());
    coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let state = yadorilink_sync_sqlite::native_store::load_state(conn, &group_id)?;
            let mut kinds = std::collections::HashMap::new();
            for heads in state.heads.values() {
                for payload in heads.values() {
                    let kind = yadorilink_sync_sqlite::dag_store::get_file_version(
                        conn,
                        group,
                        &payload.version,
                    )?
                    .map(|version| version.meta.record_kind);
                    kinds.insert(payload.version, kind);
                }
            }
            let plan = plan_own_forks(
                &state,
                &author,
                |version| kinds.get(version).copied().flatten(),
                ForkLimits { max_ops_per_delta: 64, max_bytes_per_delta: usize::MAX },
            )
            .expect("a fork plan");
            let mut admitted = 0;
            for planned in plan.deltas {
                let entry = yadorilink_sync_sqlite::native_store::frontier_entry_get(
                    conn, &group_id, &author,
                )?;
                let (seq, prev) = match &entry {
                    None => (1, None),
                    Some(entry) => (entry.seq.get() + 1, Some(entry.tip)),
                };
                let mut delta = NativeDelta {
                    group_id: group_id.clone(),
                    author: author.clone(),
                    seq: yadorilink_replica_domain::ids::AuthorSeq(seq),
                    prev,
                    ops: planned
                        .ops
                        .into_iter()
                        .map(|op| DeltaOp { path: op.path, removes: op.removes, put: op.put })
                        .collect(),
                    recursive_part: None,
                    signature: [0; 64],
                };
                delta.sign(&key);
                let verifying = key.verifying_key();
                let admission = admit_native_delta(conn, &group_id, &delta, &|a| {
                    (a == &author).then_some(verifying)
                })?;
                assert!(
                    matches!(admission, NativeAdmission::Admitted { .. }),
                    "the fork delta is admitted: {admission:?}"
                );
                admitted += 1;
            }
            Ok(admitted)
        })
        .unwrap()
}

/// [`admit_remote`] of one put of `version` at `path`, superseding nothing
/// (an empty basis: concurrent with whatever the path holds).
pub fn admit_remote_put(
    coordinator: &ReplicaCoordinator,
    group: &str,
    device: &str,
    path: &str,
    version: &FileVersion,
) -> NativeDelta {
    admit_remote(
        coordinator,
        group,
        device,
        vec![put(path, version.version_hash, Vec::new())],
        std::slice::from_ref(version),
    )
}

/// The heads native shows at `path` here, named the way an edit observing
/// them names them.
pub fn current_heads(coordinator: &ReplicaCoordinator, group: &str, path: &str) -> Vec<DeltaHash> {
    coordinator
        .database()
        .read(|conn| {
            yadorilink_sync_sqlite::native_store::native_heads_at(
                conn,
                &FolderGroupId(group.to_owned()),
                &SyncPath(path.to_owned()),
            )
        })
        .unwrap()
        .into_iter()
        .map(|head| head.payload.provenance)
        .collect()
}

/// [`admit_remote`] of one put of `version` at `path` that supersedes every
/// head native shows there, without storing the version here.
pub fn admit_remote_superseding_put(
    coordinator: &ReplicaCoordinator,
    group: &str,
    device: &str,
    path: &str,
    version: VersionHash,
) -> NativeDelta {
    let observing = current_heads(coordinator, group, path);
    admit_remote(coordinator, group, device, vec![put(path, version, observing)], &[])
}

/// What a delta built by [`admit_remote_ops`] names as observed at each
/// path it writes.
pub enum Basis {
    /// Every present head of the path: the delta supersedes what the path
    /// holds now.
    CurrentHeads,
    /// Nothing: the delta is concurrent with whatever the path holds.
    Nothing,
}

/// [`admit_remote`] of capture-shaped `ops` (a move split into its delete
/// and its put), each put's version read from this replica's store.
pub fn admit_remote_ops(
    coordinator: &ReplicaCoordinator,
    group: &str,
    device: &str,
    ops: &[yadorilink_replica_domain::local_op::Op],
    basis: Basis,
) -> NativeDelta {
    use yadorilink_replica_domain::local_op::Op;
    let basis_at = |path: &str| -> Vec<DeltaHash> {
        match basis {
            Basis::Nothing => Vec::new(),
            Basis::CurrentHeads => current_heads(coordinator, group, path),
        }
    };
    let mut remote_ops = Vec::new();
    let mut versions = Vec::new();
    let mut put_of = |path: &str, version: &VersionHash| {
        versions.push(
            coordinator
                .database()
                .read(|conn| {
                    yadorilink_sync_sqlite::dag_store::get_file_version(conn, group, version)
                })
                .unwrap()
                .expect("the version is stored here"),
        );
        put(path, *version, basis_at(path))
    };
    for op in ops {
        match op {
            Op::Put { path, version, .. } => remote_ops.push(put_of(path.as_str(), version)),
            Op::Delete { path } => remote_ops.push(delete(path.as_str(), basis_at(path.as_str()))),
            Op::Move { from, to, version } => {
                remote_ops.push(delete(from.as_str(), basis_at(from.as_str())));
                remote_ops.push(put_of(to.as_str(), version));
            }
        }
    }
    remote_ops.sort_by(|a, b| a.path().cmp(b.path()));
    admit_remote(coordinator, group, device, remote_ops, &versions)
}
