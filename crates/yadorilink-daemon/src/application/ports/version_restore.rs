//! What `VersionRestoreService` needs from `hydration`'s restore engine --
//! a distinct port from `MaterializationPort`: restoring a specific
//! retained version (or the most recent trashed one) is a different use
//! case from hydrate/evict, not a variation of it.

use crate::sync_error::SyncError;

use super::common::BoxFuture;

/// What a folder restore did: the trashed entries it put back, the ones
/// it could not (with why), and whether the recursive operation it
/// restores is only partly known here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrashOperationRestore {
    pub restored: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub partial: bool,
}

/// What to do with a conflict copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConflictChoice {
    KeepThis,
    KeepBoth,
}

/// A refused or failed resolution. Every refusal leaves the folder as it was.
#[derive(Debug)]
pub(crate) enum ResolveConflictError {
    /// Not a live conflict copy of this folder.
    NotAConflictCopy(String),
    /// A copy this action cannot resolve.
    NotResolvable(String),
    /// The original or the copy holds changes that are not recorded yet.
    UnrecordedLocalChanges(String),
    Failed(SyncError),
}

impl From<SyncError> for ResolveConflictError {
    fn from(error: SyncError) -> Self {
        ResolveConflictError::Failed(error)
    }
}

impl std::fmt::Display for ResolveConflictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveConflictError::NotAConflictCopy(path) => {
                write!(f, "{path} is not a kept conflict copy")
            }
            ResolveConflictError::NotResolvable(why) => {
                write!(f, "this conflict copy cannot be resolved here: {why}")
            }
            ResolveConflictError::UnrecordedLocalChanges(path) => write!(
                f,
                "{path} has changes that are not synced yet; nothing was changed. Try again in a \
                 moment"
            ),
            ResolveConflictError::Failed(error) => write!(f, "{error}"),
        }
    }
}

pub(crate) trait VersionRestorePort: Send + Sync {
    /// `Ok(None)` when no superseded version exists to restore to --
    /// distinct from an error reading the version history.
    fn most_recent_superseded_version_seq(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<i64>, SyncError>;

    fn restore_to_version<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        version_seq: i64,
    ) -> BoxFuture<'a, Result<(), SyncError>>;

    fn restore_trashed<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), SyncError>>;

    /// Restores every trashed entry the recursive operation that removed
    /// the trashed entry at `path` removed.
    fn restore_trashed_operation<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<TrashOperationRestore, SyncError>>;

    /// Keep this / Keep both for the conflict copy at `copy_path`; answers the
    /// absolute path that holds the copy's content afterwards.
    fn resolve_conflict<'a>(
        &'a self,
        group_id: &'a str,
        copy_path: &'a str,
        choice: ConflictChoice,
    ) -> BoxFuture<'a, Result<std::path::PathBuf, ResolveConflictError>>;
}
