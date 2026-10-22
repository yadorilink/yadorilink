//! The local capture port's authoring methods on the signed
//! seams of the file index (`commit_local_mutations_batch`,
//! `commit_recursive_operation`),
//! each authoring as the author the handle names. Every authoring refusal
//! reaches the caller as [`SyncSqliteError::AuthoringRefused`]
//! (`StaleAuthor` and `OwnAuthorAhead` rotate the incarnation). A write
//! whose row no longer shows what was captured is refused with
//! [`SyncSqliteError::LocalWriteCaptureStale`] and writes nothing; capture
//! leaves the path journaled dirty and captures it again.

use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_replica_domain::file::{FileRecord, FileVersion};
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;
use yadorilink_sync_sqlite::file_index::{
    FileIndexRepository, LocalCaptureActualStateEvidence, SignedEmissionContext,
};
use yadorilink_sync_sqlite::local_author::LocalAuthor;
use yadorilink_sync_sqlite::native_rebootstrap::CaptureAuthority;
use yadorilink_sync_sqlite::SyncSqliteError;

/// The author `author` signs as, authoring under the final capture pass's capability when the
/// group's rebootstrap is running one.
fn local_author<'a>(
    author: &'a LocalAuthorKey,
    capture: Option<&'a CaptureAuthority>,
) -> LocalAuthor<'a> {
    LocalAuthor { capture, ..LocalAuthor::of_key(author) }
}

/// `LocalMutationStore::commit_local_mutations_batch`: mutations at unrelated
/// paths share one signed delta, each superseding what its row showed at
/// capture.
// One argument per fact the batch needs.
#[allow(clippy::too_many_arguments)]
pub fn commit_local_mutations_batch(
    files: &FileIndexRepository,
    group_id: &str,
    mutations: &[PreparedLocalMutation],
    evidence: &[Option<LocalCaptureActualStateEvidence>],
    origin_device_id: &str,
    author: &LocalAuthorKey,
    capture: Option<&CaptureAuthority>,
    permit: &RootCommitPermit<'_>,
) -> Result<(), SyncSqliteError> {
    let author = local_author(author, capture);
    files.commit_local_mutations_batch(
        group_id,
        mutations,
        evidence,
        origin_device_id,
        SignedEmissionContext { author: &author, permit },
    )
}

/// `LocalMutationStore::commit_captured_directory` with an author handle:
/// one `Upsert` of the directory through
/// `commit_local_mutations_batch`, shown what the path's row holds now.
/// The caller holds the path's lock from the directory verdict through this
/// commit, so that is the row the verdict was taken on (after the
/// write-through deletion of a copy the directory replaced, which the
/// capture commits first under the same lock).
// One argument per part of the captured directory.
#[allow(clippy::too_many_arguments)]
pub fn commit_captured_directory(
    files: &FileIndexRepository,
    group_id: &str,
    record: &FileRecord,
    op: &Op,
    version: &FileVersion,
    meta: &LocalFileMetaColumns,
    identity: Option<&FileIdentity>,
    origin_device_id: &str,
    author: &LocalAuthorKey,
    capture: Option<&CaptureAuthority>,
    permit: &RootCommitPermit<'_>,
) -> Result<(), SyncSqliteError> {
    let author = local_author(author, capture);
    // Native's witness first, then the row it accompanies (see the
    // prepare sites in `yadorilink-local-capture`).
    let native_witness = files.native_capture_witness(group_id, &record.path)?;
    let mutation = PreparedLocalMutation::Upsert {
        record: record.clone(),
        op: op.clone(),
        version: version.clone(),
        meta: Some(meta.clone()),
        native_witness: Some(native_witness),
    };
    let evidence = identity.map(|filesystem_identity| LocalCaptureActualStateEvidence::Present {
        filesystem_identity: *filesystem_identity,
    });
    files.commit_local_mutations_batch(
        group_id,
        std::slice::from_ref(&mutation),
        &[evidence],
        origin_device_id,
        SignedEmissionContext { author: &author, permit },
    )?;
    Ok(())
}

/// `LocalMutationStore::commit_directory_removal` with an author handle:
/// one signed recursive delete of `root` over `tombstones`, each with
/// `Absent` evidence.
// One argument per fact the removal needs.
#[allow(clippy::too_many_arguments)]
pub fn commit_directory_removal(
    files: &FileIndexRepository,
    group_id: &str,
    root: &str,
    tombstones: &[PreparedLocalMutation],
    origin_device_id: &str,
    author: &LocalAuthorKey,
    capture: Option<&CaptureAuthority>,
    permit: &RootCommitPermit<'_>,
) -> Result<(), SyncSqliteError> {
    let author = local_author(author, capture);
    let evidence = vec![Some(LocalCaptureActualStateEvidence::Absent); tombstones.len()];
    files.commit_recursive_operation(
        group_id,
        RecursiveOperationKind::RmTree { root: SyncPath(root.to_string()) },
        tombstones,
        &evidence,
        origin_device_id,
        SignedEmissionContext { author: &author, permit },
    )?;
    Ok(())
}

/// `LocalMutationStore::commit_directory_rename`: one signed recursive
/// rename.
// One argument per fact the rename needs.
#[allow(clippy::too_many_arguments)]
pub fn commit_directory_rename(
    files: &FileIndexRepository,
    group_id: &str,
    from: &str,
    to: &str,
    mutations: &[PreparedLocalMutation],
    evidence: &[Option<LocalCaptureActualStateEvidence>],
    origin_device_id: &str,
    author: &LocalAuthorKey,
    capture: Option<&CaptureAuthority>,
    permit: &RootCommitPermit<'_>,
) -> Result<(), SyncSqliteError> {
    let author = local_author(author, capture);
    files.commit_recursive_operation(
        group_id,
        RecursiveOperationKind::RenameTree {
            from: SyncPath(from.to_string()),
            to: SyncPath(to.to_string()),
        },
        mutations,
        evidence,
        origin_device_id,
        SignedEmissionContext { author: &author, permit },
    )?;
    Ok(())
}
