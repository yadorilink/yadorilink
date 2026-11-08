//! The `history` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

/// `yadorilink versions <path>`.
pub(super) async fn list_versions(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ListVersionsRequest,
) -> RespPayload {
    match context.queries.file_history.list_versions(&r.absolute_path) {
        Ok(Some(versions)) => match context.queries.file_history.not_kept_spans(&r.absolute_path) {
            Ok(spans) => RespPayload::ListVersions(ListVersionsResponse {
                versions: versions.into_iter().map(version_to_proto).collect(),
                not_kept: spans.unwrap_or_default().into_iter().map(not_kept_to_proto).collect(),
            }),
            Err(e) => RespPayload::Error(e.to_string()),
        },
        Ok(None) => RespPayload::Error("path is not under any linked folder".into()),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

/// `yadorilink restore <path> [--version <id>]`. An
/// absent `version_seq` resolves to the most recent superseded
/// version (spec "Restore without a version defaults to the most
/// recent superseded version") via `VersionRestoreService`; there
/// being none to restore to is reported as a clear error rather
/// than silently no-op'ing.
pub(super) async fn restore_version(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RestoreVersionRequest,
) -> RespPayload {
    match context.queries.linked_path.resolve_any(&r.absolute_path) {
        Some((group_id, path)) => {
            match context
                .application
                .version_restore
                .restore_version(&group_id, &path, r.version_seq)
                .await
            {
                Ok(true) => RespPayload::RestoreVersion(RestoreVersionResponse {}),
                Ok(false) => RespPayload::Error("no superseded version to restore to".into()),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }
        None => RespPayload::Error("path is not under any linked folder".into()),
    }
}

/// `yadorilink trash list`. Unlike the per-file requests
/// above, this spans every linked folder at once (no `absolute_path`
/// to resolve) — mirrors `list_link_statuses`'s own per-link
/// iteration below.
pub(super) async fn list_trash(context: &crate::control_context::ControlContext) -> RespPayload {
    match context.queries.file_history.list_trash() {
        Ok(files) => RespPayload::ListTrash(ListTrashResponse {
            files: files.into_iter().map(trashed_file_view_to_proto).collect(),
        }),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

/// `yadorilink conflicts list`. Same "spans every linked folder at
/// once" shape as `ListTrash` above.
pub(super) async fn list_conflicts(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    match context.queries.file_history.list_conflicts() {
        Ok(files) => RespPayload::ListConflicts(ListConflictsResponse {
            files: files.into_iter().map(conflicted_file_view_to_proto).collect(),
        }),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

/// The Activity page: recent file events across every linked folder.
pub(super) async fn list_activity(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ListActivityRequest,
) -> RespPayload {
    match context
        .queries
        .file_history
        .list_activity(crate::queries::file_history::activity_query_from_proto(&r))
    {
        Ok(events) => RespPayload::ListActivity(ListActivityResponse {
            events: events
                .into_iter()
                .map(crate::queries::file_history::activity_view_to_proto)
                .collect(),
        }),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

/// Keep this / Keep both: the daemon decides and performs it.
pub(super) async fn resolve_conflict(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ResolveConflictRequest,
) -> RespPayload {
    RespPayload::ResolveConflict(super::resolve_conflict(context, &r).await)
}

/// `yadorilink trash restore <path>`.
pub(super) async fn restore_trash(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RestoreTrashRequest,
) -> RespPayload {
    match context.queries.linked_path.resolve_any(&r.absolute_path) {
        Some((group_id, path)) => {
            match context.application.version_restore.restore_trashed(&group_id, &path).await {
                Ok(()) => RespPayload::RestoreTrash(RestoreTrashResponse {}),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }
        None => RespPayload::Error("path is not under any linked folder".into()),
    }
}

/// `yadorilink trash restore --folder <path>`.
pub(super) async fn restore_trash_operation(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RestoreTrashOperationRequest,
) -> RespPayload {
    match context.queries.linked_path.resolve_any(&r.absolute_path) {
        Some((group_id, path)) => {
            match context
                .application
                .version_restore
                .restore_trashed_operation(&group_id, &path)
                .await
            {
                Ok(outcome) => RespPayload::RestoreTrashOperation(RestoreTrashOperationResponse {
                    restored_paths: outcome.restored,
                    failed: outcome
                        .failed
                        .into_iter()
                        .map(|(path, error)| RestoreTrashOperationFailure { path, error })
                        .collect(),
                    partial: outcome.partial,
                }),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }
        None => RespPayload::Error("path is not under any linked folder".into()),
    }
}

/// What a rebootstrap set aside: list it, restore a version as one ordinary write,
/// discard an item.
pub(super) async fn list_preserved(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    match context.application.preserved.list().await {
        Ok(items) => {
            RespPayload::ListPreserved(yadorilink_ipc_proto::daemonctl::ListPreservedResponse {
                items: items.into_iter().map(preserved_item_to_proto).collect(),
            })
        }
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn restore_preserved(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RestorePreservedRequest,
) -> RespPayload {
    match context.application.preserved.restore(r.group_id, r.item_id).await {
        Ok(()) => RespPayload::RestorePreserved(
            yadorilink_ipc_proto::daemonctl::RestorePreservedResponse {},
        ),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn retry_preserved(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::RetryPreservedRequest,
) -> RespPayload {
    match context.application.preserved.retry(r.group_id, r.item_id).await {
        Ok(()) => {
            RespPayload::RetryPreserved(yadorilink_ipc_proto::daemonctl::RetryPreservedResponse {})
        }
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn discard_preserved(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::DiscardPreservedRequest,
) -> RespPayload {
    match context.application.preserved.discard(r.group_id, r.item_id).await {
        Ok(()) => RespPayload::DiscardPreserved(
            yadorilink_ipc_proto::daemonctl::DiscardPreservedResponse {},
        ),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn list_retained_originals(
    context: &crate::control_context::ControlContext,
) -> RespPayload {
    match context.application.preserved.list_retained().await {
        Ok(items) => RespPayload::ListRetainedOriginals(
            yadorilink_ipc_proto::daemonctl::ListRetainedOriginalsResponse {
                items: items
                    .into_iter()
                    .map(|item| yadorilink_ipc_proto::daemonctl::RetainedOriginal {
                        group_id: item.group_id,
                        group_removed: item.group_removed,
                        path: item.path,
                        recovery_id: item.recovery_id,
                        size: item.size,
                        reachable: item.reachable,
                    })
                    .collect(),
            },
        ),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn release_retained_originals(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ReleaseRetainedOriginalsRequest,
) -> RespPayload {
    match context.application.preserved.release_retained(r.group_id).await {
        Ok(outcomes) => RespPayload::ReleaseRetainedOriginals(
            yadorilink_ipc_proto::daemonctl::ReleaseRetainedOriginalsResponse {
                releases: outcomes
                    .into_iter()
                    .map(|(path, outcome)| retained_release_to_proto(path, outcome))
                    .collect(),
            },
        ),
        Err(e) => RespPayload::Error(e.to_string()),
    }
}

pub(super) async fn list_provider_pending(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ListProviderPendingRequest,
) -> RespPayload {
    match context.provider_status.pending_items(r.limit) {
        Ok(items) => RespPayload::ListProviderPending(
            yadorilink_ipc_proto::daemonctl::ListProviderPendingResponse { items },
        ),
        Err(error) => RespPayload::Error(error),
    }
}
