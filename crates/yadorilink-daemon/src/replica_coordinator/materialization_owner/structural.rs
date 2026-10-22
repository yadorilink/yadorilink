//! Owner operations of the structural-directory ledger
//! (`yadorilink_sync_sqlite::structural_origin`): which directories this
//! device created only to hold descendants, and which directories whose
//! entry is deleted it keeps on disk because they are not empty.
//!
//! A lane never calls the ledger's primitives itself. The `mkdir` helper
//! reaches the two-phase origin protocol through
//! `yadorilink_filesystem_sync::materialization_execution::
//! GroupStructuralLedger`, which calls the three port methods backed by
//! [`ReplicaCoordinator::record_structural_directory_intent`],
//! [`ReplicaCoordinator::complete_structural_directory_origin`] and
//! [`ReplicaCoordinator::abandon_structural_directory_intent`]; recovery,
//! adoption, rekeying and forgetting are the operations below.

use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_sync_sqlite::structural_origin::StructuralOriginCompletion;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::super::ReplicaCoordinator;

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// How many names of one directory level are planned for themselves before the whole level is
/// planned instead. A name costs a few indexed reads; a level costs its size, so for a directory
/// of ten thousand entries the two meet at a couple of thousand names, and a smaller directory
/// meets earlier.
const SCOPED_PLAN_NAME_LIMIT: usize = 32;

impl ReplicaCoordinator {
    /// Phase 1 of a structural `mkdir`: the intent and the fence bump for
    /// `path`, committed before the syscall.
    pub(crate) fn record_structural_directory_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().dag_record_structural_intent(group_id, path, now_unix_nanos())?;
        Ok(())
    }

    /// Phase 2 of a structural `mkdir` that created the directory. A
    /// refusal (no pending intent, a moved fence, not a directory) is not
    /// an error: the directory is `OriginUnknown`, which keeps it and
    /// authors nothing.
    pub(crate) fn complete_structural_directory_origin(
        &self,
        group_id: &str,
        path: &str,
        identity: &FileIdentity,
    ) -> Result<(), SyncSqliteError> {
        let completion = self.sqlite().dag_complete_structural_origin(
            group_id,
            path,
            identity,
            now_unix_nanos(),
        )?;
        if completion != StructuralOriginCompletion::Recorded {
            tracing::info!(
                group_id,
                path,
                ?completion,
                "a structural directory this device created was not recorded as structural; \
                 it is kept and treated as of unknown origin"
            );
        }
        Ok(())
    }

    /// Phase 2 of a structural `mkdir` that did not create the directory.
    pub(crate) fn abandon_structural_directory_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().dag_abandon_structural_intent(group_id, path)?;
        Ok(())
    }

    /// Startup recovery: at startup no `mkdir` is in flight, so every
    /// structural intent is an interrupted one and is resolved (never
    /// completed). Must run before any link starts. See
    /// [`Self::resolve_unresolved_structural_intents`].
    pub(crate) fn drop_interrupted_structural_intents_at_startup(
        &self,
    ) -> Result<Vec<(String, String)>, SyncSqliteError> {
        self.resolve_unresolved_structural_intents(None, None)
    }

    /// Link start: the intents of `group_id` that startup had to keep because
    /// its root could not be looked at then. Nothing of this link runs yet, so
    /// none is in flight.
    pub fn resolve_structural_intents_at_link_start(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, String)>, SyncSqliteError> {
        self.resolve_unresolved_structural_intents(Some(group_id), None)
    }

    /// A `mkdir` writer that is leaving without having completed or abandoned
    /// its intent (an error it could not report to the ledger, or a panic
    /// unwinding): resolves that one intent now, as recovery would.
    pub fn resolve_interrupted_structural_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.resolve_unresolved_structural_intents(Some(group_id), Some(path)).map(|_| ())
    }

    /// Drops each structural intent (of `group_id`, and of `path` when given;
    /// of every group when `None`) and, in the
    /// same transaction, records the directory now at its path -- which
    /// may be the one the interrupted `mkdir` created -- as of lost
    /// provenance, bound to its identity: capture then keeps it and
    /// authors nothing, rather than reading a directory with no record as
    /// one a user made. Returns the intents dropped.
    ///
    /// An intent is dropped with nothing recorded only when its root is
    /// there and nothing that could be the `mkdir`'s directory is at the
    /// path. One whose root cannot be looked at -- no live link for the
    /// group, a root not (yet) mounted, an observation that failed -- is
    /// kept: it still reads as a `mkdir` in flight, never as a user's
    /// directory, and the next link start of its group resolves it once the
    /// root is back.
    fn resolve_unresolved_structural_intents(
        &self,
        group_id: Option<&str>,
        path: Option<&str>,
    ) -> Result<Vec<(String, String)>, SyncSqliteError> {
        let intents = self.sqlite().dag_list_unresolved_structural_intents(group_id)?;
        let resolutions: Vec<_> = intents
            .into_iter()
            .filter(|intent| path.is_none_or(|p| intent.path == p))
            .filter_map(|intent| {
                let found = self.directory_an_interrupted_mkdir_may_have_made(&intent)?;
                Some((intent, found))
            })
            .collect();
        self.sqlite()
            .dag_drop_structural_intents_recording_lost_provenance(&resolutions, now_unix_nanos())
    }

    /// What is at an interrupted structural intent's path: `Some(Some(_))`
    /// a directory (the one the `mkdir` may have made), `Some(None)`
    /// nothing that could be, `None` when that cannot be told now.
    fn directory_an_interrupted_mkdir_may_have_made(
        &self,
        intent: &yadorilink_sync_sqlite::structural_origin::UnresolvedStructuralIntent,
    ) -> Option<Option<FileIdentity>> {
        let (group_id, path) = (intent.group_id.as_str(), intent.path.as_str());
        let root = match self.link_repository().live_link_local_path_for_group(group_id) {
            Ok(Some(root)) => std::path::PathBuf::from(root),
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(group_id, path, %error, "could not find the root of an interrupted structural intent; kept");
                return None;
            }
        };
        if !std::fs::metadata(&root).is_ok_and(|meta| meta.is_dir()) {
            return None;
        }
        // A path reached through a symlinked component is not in this
        // folder: nothing of the `mkdir`'s can be there.
        let Ok(target) = yadorilink_local_storage::resolve_read_path_without_traversal(
            &root,
            std::path::Path::new(path),
        ) else {
            return Some(None);
        };
        match FileIdentity::observe_path(&target) {
            Ok(identity) => Some(
                (identity.object_kind
                    == yadorilink_fs_platform::fs_identity::ObjectKind::Directory)
                    .then_some(identity),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(None),
            Err(error) => {
                tracing::warn!(group_id, path, %error, "could not observe the path of an interrupted structural intent; kept");
                None
            }
        }
    }

    /// Records the directory now at `path` (observed as `identity`) as
    /// structural: its explicit entry was deleted while live descendants
    /// keep it on disk.
    pub(crate) fn adopt_as_structural_directory(
        &self,
        group_id: &str,
        path: &str,
        identity: &FileIdentity,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().dag_adopt_structural_directory(group_id, path, identity, now_unix_nanos())
    }

    /// Settles a directory removed from disk: nothing is structural or
    /// retained at `path` any more.
    pub(crate) fn forget_removed_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().dag_forget_structural_origin(group_id, path)?;
        self.sqlite().clear_retained_directory(group_id, path)?;
        Ok(())
    }

    /// Raises an obligation for every planned entry with no live row.
    pub(crate) fn arm_native_plan_gaps(&self, group_id: &str) -> Result<usize, SyncSqliteError> {
        self.file_index_repository().arm_native_plan_gaps(group_id)
    }

    /// Records that the directory at `path` stays on disk although its
    /// entry is settled as deleted, with `reason` for status. `removable`
    /// is the identity of the directory a delete aimed at, which goes once
    /// it is empty; `None` keeps whatever directory is there for good.
    pub(crate) fn keep_retained_directory(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        removable: Option<&FileIdentity>,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().record_retained_directory(group_id, path, reason, removable, now_unix_nanos())
    }

    /// Whether `observed`, the directory now at `path`, is the very object
    /// this device materialized for the path's explicit Directory entry --
    /// the identity its `ExactObject{Directory}` settlement published. Only
    /// that directory is what a Directory tombstone deletes: a directory
    /// the user put in its place (or one whose identity this device never
    /// recorded) is not, however empty.
    pub(crate) fn is_materialized_directory_object(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &std::path::Path,
        observed: &FileIdentity,
    ) -> Result<bool, SyncSqliteError> {
        use yadorilink_fs_platform::fs_identity::IdentityComparison;
        Ok(self.sqlite().dag_materialized_directory_identity(group_id, path)?.is_some_and(
            |recorded| {
                recorded.compare(
                    observed,
                    super::super::peer_replica_state::cached_birth_time_granularity(sync_root),
                ) == IdentityComparison::SameObject
            },
        ))
    }

    /// Whether `observed`, the directory now at `path`, is the very one an
    /// earlier delete aimed at and retained -- and so may be removed once
    /// it is empty. A directory recorded as kept, or a different object at
    /// the same path (it inherits nothing), is not.
    pub(crate) fn is_removable_retained_directory(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &std::path::Path,
        observed: &FileIdentity,
    ) -> Result<bool, SyncSqliteError> {
        use yadorilink_fs_platform::fs_identity::IdentityComparison;
        use yadorilink_sync_sqlite::structural_origin::RetainedDirectory;
        Ok(match self.sqlite().retained_directory(group_id, path)? {
            RetainedDirectory::RemovableWhenEmpty(recorded) => {
                recorded.compare(
                    observed,
                    super::super::peer_replica_state::cached_birth_time_granularity(sync_root),
                ) == IdentityComparison::SameObject
            }
            RetainedDirectory::None | RetainedDirectory::Kept => false,
        })
    }

    /// Open half of removing a directory an earlier delete retained, now
    /// that it may have become empty: bump the path's fence (tx) before
    /// the `rmdir`. Returns the fence value the removal settles under.
    pub(crate) fn begin_retained_directory_removal(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<i64, yadorilink_peer_session::PeerSessionError> {
        self.begin_directory_removal(group_id, path, "retained_directory_rmdir")
    }

    /// Open half of any non-recursive `rmdir` the namespace decides (a
    /// retained directory now empty, a structural directory nothing needs
    /// any more, a replicated directory an entry supersedes): bump the
    /// path's fence (tx) before the syscall. Returns the fence value the
    /// removal settles under.
    pub(crate) fn begin_directory_removal(
        &self,
        group_id: &str,
        path: &str,
        why: &'static str,
    ) -> Result<i64, yadorilink_peer_session::PeerSessionError> {
        self.dag_bump_mutation_fence(group_id, path, why)
    }

    /// The fence value evidence about the directory standing at `path` is
    /// valid under, when nothing was mutated to get it there (or the
    /// structural `mkdir` already bumped it): a snapshot, never a bump.
    pub(crate) fn directory_settlement_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<i64, yadorilink_peer_session::PeerSessionError> {
        self.dag_snapshot_mutation_fence(group_id, path)
    }

    /// Drops the retained record for `path`: it holds an entry again.
    pub(crate) fn release_retained_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.sqlite().clear_retained_directory(group_id, path)
    }

    /// The reason a directory at `path` is retained, if it is.
    pub(crate) fn retained_directory_reason(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.sqlite().retained_directory_reason(group_id, path)
    }

    /// Whether anything strictly below `path` holds a live content head.
    pub(crate) fn has_live_descendant(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.sqlite().dag_has_live_descendant(group_id, path)
    }

    /// What the ledger says about the directory `observed` at `path` now:
    /// structural (this device made or adopted exactly this object for
    /// descendants), pending, or of unknown origin.
    pub(crate) fn structural_origin_status(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &std::path::Path,
        observed: Option<&FileIdentity>,
    ) -> Result<yadorilink_sync_sqlite::structural_origin::StructuralOriginStatus, SyncSqliteError>
    {
        Ok(self.sqlite().dag_structural_directory_origin(group_id, path)?.status(
            observed,
            super::super::peer_replica_state::cached_birth_time_granularity(sync_root),
        ))
    }

    /// What the namespace requires at `path` on its own account (one
    /// transaction), from native state.
    pub(crate) fn desired_path_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<yadorilink_sync_sqlite::desired_state::DesiredPathState, SyncSqliteError> {
        self.sqlite().native_desired_path_state(group_id, path)
    }

    /// Whether `version` is a Present file at a path other than `path`.
    pub(crate) fn version_present_elsewhere(
        &self,
        group_id: &str,
        path: &str,
        version: &yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<bool, SyncSqliteError> {
        self.file_index_repository().version_present_elsewhere(group_id, path, version)
    }

    /// The displacement guard for `path` about to show `planned`.
    pub(crate) fn displacement_guard(
        &self,
        group_id: &str,
        path: &str,
        planned: Option<&yadorilink_replica_domain::ids::VersionHash>,
        folds_onto_path: &dyn Fn(&str) -> bool,
    ) -> Result<yadorilink_sync_sqlite::displacement_guard::DisplacementGuard, SyncSqliteError>
    {
        self.file_index_repository().displacement_guard(group_id, path, planned, folds_onto_path)
    }

    /// One directory level of native's materialization plan: the exact live
    /// head behind every node.
    pub(crate) fn native_plan_level(
        &self,
        group_id: &str,
        parent: &str,
    ) -> Result<yadorilink_replica_domain::native_plan::NativeLevelPlan, SyncSqliteError> {
        self.file_index_repository().native_plan_level(group_id, parent)
    }

    /// The node of [`Self::native_plan_level`] at `path`, read without the rest of its level.
    pub(crate) fn native_plan_node(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_replica_domain::native_plan::NativePlannedNode>, SyncSqliteError>
    {
        self.file_index_repository().native_plan_node(group_id, path)
    }

    /// The nodes of [`Self::native_plan_level`] at `names`. A handful of
    /// names is read for themselves; past [`SCOPED_PLAN_NAME_LIMIT`] the whole level is
    /// planned once, which then costs less than naming each (the plan holds the requested nodes
    /// and others, which callers ignore).
    pub(crate) fn native_plan_for_names(
        &self,
        group_id: &str,
        parent: &str,
        names: &std::collections::BTreeSet<String>,
    ) -> Result<yadorilink_replica_domain::native_plan::NativeLevelPlan, SyncSqliteError> {
        if names.len() > SCOPED_PLAN_NAME_LIMIT {
            self.native_plan_level(group_id, parent)
        } else {
            self.native_plan_nodes(group_id, parent, names)
        }
    }

    /// The nodes of [`Self::native_plan_level`] at `names`.
    pub(crate) fn native_plan_nodes(
        &self,
        group_id: &str,
        parent: &str,
        names: &std::collections::BTreeSet<String>,
    ) -> Result<yadorilink_replica_domain::native_plan::NativeLevelPlan, SyncSqliteError> {
        self.file_index_repository().native_plan_nodes(group_id, parent, names)
    }
}
