//! `EnumerateChildren` and `ProviderItem` over the shell connection.
//!
//! Requests carry no id: they are answered INLINE, in order, on the connection that asked, so
//! the extension matches a response to its request by position (it opens another connection for
//! concurrency). Who may ask is the caller check of the write path: a handshake for the root on
//! this connection, a host app attached, and a root that is known and whose namespace is
//! queryable (until then the answer is NOT_READY, never an empty folder).

use std::sync::Arc;

use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ChangeScope, EntryKind as WireEntryKind, EnumerateChangesRequest, EnumerateChangesResponse,
    EnumerateChildrenRequest, EnumerateChildrenResponse, EnumerateFailure,
    EnumerateWorkingSetRequest, EnumerateWorkingSetResponse, ProviderItem, ProviderItemRequest,
    ProviderItemResponse, ShellIpcMessage,
};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_sync_sqlite::provider_enumerate::{
    ChangeScope as StoreScope, ChangesError, EnumerateError, ShownItem,
};

use super::provider_apply::Handshakes;
use crate::shell_context::ShellContext;

/// The most items a page carries, and the encoded bytes it stops at (a quarter of the frame).
const MAX_LIMIT: usize = 1000;
const DEFAULT_LIMIT: usize = 500;
const PAGE_BYTES: usize = 256 * 1024;

const CHILDREN_TAG: &[u8; 2] = b"E2";
const WORKING_SET_TAG: &[u8; 2] = b"W2";

/// A page cursor: its kind, the first page's anchor, the ROOT it belongs to, and the rest. A
/// token is only ever valid for the root and the folder that issued it.
fn encode_token(tag: &[u8; 2], anchor: u64, root: &[u8], scope: &[u8], last: &[u8]) -> Vec<u8> {
    let mut token = tag.to_vec();
    token.extend_from_slice(&anchor.to_be_bytes());
    token.push(root.len() as u8);
    token.extend_from_slice(root);
    token.push(scope.len() as u8);
    token.extend_from_slice(scope);
    token.extend_from_slice(last);
    token
}

/// `(anchor, last)` when the token is of kind `tag` and was issued for exactly this root and
/// scope (the folder, for children; empty for the working set).
fn decode_token(tag: &[u8; 2], token: &[u8], root: &[u8], scope: &[u8]) -> Option<(u64, Vec<u8>)> {
    let rest = token.strip_prefix(tag.as_slice())?;
    let anchor = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
    let root_len = *rest.get(8)? as usize;
    let found_root = rest.get(9..9 + root_len)?;
    let rest = rest.get(9 + root_len..)?;
    let scope_len = *rest.first()? as usize;
    let found_scope = rest.get(1..1 + scope_len)?;
    if found_root != root || found_scope != scope {
        return None;
    }
    Some((anchor, rest.get(1 + scope_len..)?.to_vec()))
}

/// An OS-visible version identifier: the 32-byte hash and the item generation (8 bytes, big
/// endian), so a version that returns to earlier content still has a new identifier.
pub(crate) fn versioned(hash: &[u8; 32], generation: u64) -> Vec<u8> {
    let mut out = hash.to_vec();
    out.extend_from_slice(&generation.to_be_bytes());
    out
}

fn wire_item(item: &ShownItem, read_only: bool) -> ProviderItem {
    ProviderItem {
        read_only,
        eviction_allowed: item.eviction_allowed,
        item_id: item.item_id.to_vec(),
        parent_item_id: item.parent_item_id.clone(),
        name: item.name.clone(),
        entry_kind: match item.kind {
            RecordKind::File => WireEntryKind::File,
            RecordKind::Directory => WireEntryKind::Directory,
            RecordKind::Symlink => WireEntryKind::Symlink,
        } as i32,
        size: item.size,
        mtime_unix_nanos: item.mtime_unix_nanos,
        unix_mode: item.unix_mode,
        content_version: versioned(&item.content_version.0, item.generation),
        metadata_version: versioned(&item.metadata_version, item.generation),
        content_pending: item.content_pending,
        symlink_target: item.symlink_target.clone(),
        parent_generation: item.parent_generation,
    }
}

/// Whether this device may NOT author into the group (a Reader, or a group whose policy is withheld):
/// its items, and the root listing, are shown read-only. The one rule for items and folders.
pub(super) fn group_is_read_only(context: &ShellContext, group_id: &str) -> bool {
    !context.writer.may_author(group_id)
}

fn root_is_read_only(context: &ShellContext, root_id: &str) -> bool {
    context
        .replica_coordinator
        .provider_repository()
        .group_of_root(root_id)
        .ok()
        .flatten()
        .is_some_and(|group| group_is_read_only(context, &group))
}

fn failure_of(error: &EnumerateError) -> (EnumerateFailure, String) {
    match error {
        EnumerateError::NotFound => (EnumerateFailure::NotFound, "no such live item".into()),
        EnumerateError::NotADirectory => {
            (EnumerateFailure::NotADirectory, "the item is not a folder".into())
        }
        EnumerateError::Db(error) => (EnumerateFailure::Retry, error.to_string()),
    }
}

/// The root the request names, if the caller may ask about it and its namespace is queryable.
fn admitted_root(
    context: &ShellContext,
    handshakes: &Handshakes,
    root_id: &[u8],
) -> Result<String, (EnumerateFailure, String)> {
    let not_ready = |why: &str| (EnumerateFailure::NotReady, why.to_owned());
    if !handshakes.has(root_id) || !context.provider_host.host_connected() {
        return Err(not_ready(
            "no extension handshake on this connection, or no host app attached",
        ));
    }
    let root = hex::encode(root_id);
    let declared = context
        .replica_coordinator
        .provider_repository()
        .list_declared_roots()
        .map_err(|e| (EnumerateFailure::Retry, e.to_string()))?
        .into_iter()
        .find(|r| r.root_id == root)
        .ok_or_else(|| not_ready("unknown provider root"))?;
    if !declared.namespace_ready {
        return Err(not_ready("the namespace is not queryable yet"));
    }
    Ok(root)
}

/// Answers the enumeration requests of this connection, or `None` for any other message.
pub(crate) async fn answer(
    context: &Arc<ShellContext>,
    handshakes: &Arc<Handshakes>,
    msg: &ShellIpcMessage,
) -> Option<ShellIpcMessage> {
    match &msg.payload {
        Some(Payload::EnumerateChildrenRequest(request)) => Some(ShellIpcMessage {
            payload: Some(Payload::EnumerateChildrenResponse(
                children(context, handshakes, request).await,
            )),
        }),
        Some(Payload::EnumerateChangesRequest(request)) => Some(ShellIpcMessage {
            payload: Some(Payload::EnumerateChangesResponse(
                changes(context, handshakes, request).await,
            )),
        }),
        Some(Payload::EnumerateWorkingSetRequest(request)) => Some(ShellIpcMessage {
            payload: Some(Payload::EnumerateWorkingSetResponse(
                working_set(context, handshakes, request).await,
            )),
        }),
        Some(Payload::ProviderItemRequest(request)) => Some(ShellIpcMessage {
            payload: Some(Payload::ProviderItemResponse(item(context, handshakes, request).await)),
        }),
        _ => None,
    }
}

fn children_failure(failure: EnumerateFailure, error: String) -> EnumerateChildrenResponse {
    EnumerateChildrenResponse {
        ok: false,
        failure: failure as i32,
        error,
        items: Vec::new(),
        next_page_token: Vec::new(),
        anchor: 0,
    }
}

async fn children(
    context: &Arc<ShellContext>,
    handshakes: &Handshakes,
    request: &EnumerateChildrenRequest,
) -> EnumerateChildrenResponse {
    let root = match admitted_root(context, handshakes, &request.root_id) {
        Ok(root) => root,
        Err((failure, error)) => return children_failure(failure, error),
    };
    let read_only = root_is_read_only(context, &root);
    let (first_anchor, after) = if request.page_token.is_empty() {
        (None, None)
    } else {
        match decode_token(
            CHILDREN_TAG,
            &request.page_token,
            &request.root_id,
            &request.parent_item_id,
        ) {
            Some((anchor, last)) => match String::from_utf8(last) {
                Ok(last) => (Some(anchor), Some(last)),
                Err(_) => {
                    return children_failure(
                        EnumerateFailure::TokenInvalid,
                        "the page token is malformed".into(),
                    )
                }
            },
            None => {
                return children_failure(
                    EnumerateFailure::TokenInvalid,
                    "the page token is not this folder's".into(),
                )
            }
        }
    };
    let limit = match request.limit as usize {
        0 => DEFAULT_LIMIT,
        n => n.min(MAX_LIMIT),
    };
    let coordinator = context.replica_coordinator.clone();
    let parent = request.parent_item_id.clone();
    let page = tokio::task::spawn_blocking(move || {
        coordinator.provider_repository().enumerate_children(
            &root,
            &parent,
            after.as_deref(),
            limit,
            PAGE_BYTES,
        )
    })
    .await;
    match page {
        Ok(Ok(page)) => {
            // Every page repeats the FIRST page's anchor, so the extension finishes the walk
            // with it and the change feed closes whatever happened since.
            let anchor = first_anchor.unwrap_or(page.anchor);
            EnumerateChildrenResponse {
                ok: true,
                failure: EnumerateFailure::None as i32,
                error: String::new(),
                items: page.items.iter().map(|item| wire_item(item, read_only)).collect(),
                next_page_token: page
                    .next_after
                    .map(|last| {
                        encode_token(
                            CHILDREN_TAG,
                            anchor,
                            &request.root_id,
                            &request.parent_item_id,
                            last.as_bytes(),
                        )
                    })
                    .unwrap_or_default(),
                anchor,
            }
        }
        Ok(Err(error)) => {
            let (failure, text) = failure_of(&error);
            children_failure(failure, text)
        }
        Err(error) => children_failure(EnumerateFailure::Retry, error.to_string()),
    }
}

async fn item(
    context: &Arc<ShellContext>,
    handshakes: &Handshakes,
    request: &ProviderItemRequest,
) -> ProviderItemResponse {
    let fail = |failure: EnumerateFailure, error: String| ProviderItemResponse {
        ok: false,
        failure: failure as i32,
        error,
        item: None,
        anchor: 0,
    };
    let root = match admitted_root(context, handshakes, &request.root_id) {
        Ok(root) => root,
        Err((failure, error)) => return fail(failure, error),
    };
    let read_only = root_is_read_only(context, &root);
    let Ok(item_id) = <[u8; 16]>::try_from(request.item_id.as_slice()) else {
        return fail(EnumerateFailure::NotFound, "an item id is not 16 bytes".into());
    };
    let coordinator = context.replica_coordinator.clone();
    let found = tokio::task::spawn_blocking(move || {
        coordinator.provider_repository().lookup_item(&root, &item_id)
    })
    .await;
    match found {
        Ok(Ok(Some((shown, anchor)))) => ProviderItemResponse {
            ok: true,
            failure: EnumerateFailure::None as i32,
            error: String::new(),
            item: Some(wire_item(&shown, read_only)),
            anchor,
        },
        Ok(Ok(None)) => fail(EnumerateFailure::NotFound, "no such live item".into()),
        Ok(Err(error)) => {
            let (failure, text) = failure_of(&error);
            fail(failure, text)
        }
        Err(error) => fail(EnumerateFailure::Retry, error.to_string()),
    }
}

fn changes_failure(failure: EnumerateFailure, error: String) -> EnumerateChangesResponse {
    EnumerateChangesResponse {
        ok: false,
        failure: failure as i32,
        error,
        upserts: Vec::new(),
        removed_item_ids: Vec::new(),
        next_anchor: 0,
        more: false,
    }
}

async fn changes(
    context: &Arc<ShellContext>,
    handshakes: &Handshakes,
    request: &EnumerateChangesRequest,
) -> EnumerateChangesResponse {
    let root = match admitted_root(context, handshakes, &request.root_id) {
        Ok(root) => root,
        Err((failure, error)) => return changes_failure(failure, error),
    };
    let read_only = root_is_read_only(context, &root);
    let scope = match ChangeScope::try_from(request.scope) {
        Ok(ChangeScope::WorkingSet) => StoreScope::WorkingSet,
        Ok(ChangeScope::Container) => StoreScope::Container(request.parent_item_id.clone()),
        _ => {
            return changes_failure(EnumerateFailure::NotFound, "no change scope".into());
        }
    };
    let limit = match request.limit as usize {
        0 => DEFAULT_LIMIT,
        n => n.min(MAX_LIMIT),
    };
    let since = request.since_anchor;
    let coordinator = context.replica_coordinator.clone();
    let page = tokio::task::spawn_blocking(move || {
        coordinator.provider_repository().enumerate_changes(&root, &scope, since, limit, PAGE_BYTES)
    })
    .await;
    match page {
        Ok(Ok(page)) => EnumerateChangesResponse {
            ok: true,
            failure: EnumerateFailure::None as i32,
            error: String::new(),
            upserts: page.upserts.iter().map(|item| wire_item(item, read_only)).collect(),
            removed_item_ids: page.removed.iter().map(|id| id.to_vec()).collect(),
            next_anchor: page.next_anchor,
            more: page.more,
        },
        Ok(Err(ChangesError::AnchorExpired)) => changes_failure(
            EnumerateFailure::AnchorExpired,
            "the anchor is outside the retained range: enumerate in full".into(),
        ),
        Ok(Err(ChangesError::Db(error))) => {
            changes_failure(EnumerateFailure::Retry, error.to_string())
        }
        Err(error) => changes_failure(EnumerateFailure::Retry, error.to_string()),
    }
}

fn working_set_failure(failure: EnumerateFailure, error: String) -> EnumerateWorkingSetResponse {
    EnumerateWorkingSetResponse {
        ok: false,
        failure: failure as i32,
        error,
        items: Vec::new(),
        next_page_token: Vec::new(),
        anchor: 0,
    }
}

async fn working_set(
    context: &Arc<ShellContext>,
    handshakes: &Handshakes,
    request: &EnumerateWorkingSetRequest,
) -> EnumerateWorkingSetResponse {
    let root = match admitted_root(context, handshakes, &request.root_id) {
        Ok(root) => root,
        Err((failure, error)) => return working_set_failure(failure, error),
    };
    let read_only = root_is_read_only(context, &root);
    let (first_anchor, after) = if request.page_token.is_empty() {
        (None, None)
    } else {
        match decode_token(WORKING_SET_TAG, &request.page_token, &request.root_id, &[])
            .and_then(|(anchor, last)| Some((anchor, <[u8; 16]>::try_from(last.as_slice()).ok()?)))
        {
            Some((anchor, last)) => (Some(anchor), Some(last)),
            None => {
                return working_set_failure(
                    EnumerateFailure::TokenInvalid,
                    "the page token is not this root's".into(),
                )
            }
        }
    };
    let limit = match request.limit as usize {
        0 => DEFAULT_LIMIT,
        n => n.min(MAX_LIMIT),
    };
    let coordinator = context.replica_coordinator.clone();
    let walk_root = root.clone();
    let page = tokio::task::spawn_blocking(move || {
        let repo = coordinator.provider_repository();
        let page = repo.enumerate_working_set(&walk_root, after.as_ref(), limit, PAGE_BYTES)?;
        let anchor = first_anchor.unwrap_or(page.anchor);
        Ok::<_, EnumerateError>((page, anchor))
    })
    .await;
    match page {
        Ok(Ok((page, anchor))) => EnumerateWorkingSetResponse {
            ok: true,
            failure: EnumerateFailure::None as i32,
            error: String::new(),
            items: page.items.iter().map(|item| wire_item(item, read_only)).collect(),
            next_page_token: page
                .next_after
                .map(|last| encode_token(WORKING_SET_TAG, anchor, &request.root_id, &[], &last))
                .unwrap_or_default(),
            anchor,
        },
        Ok(Err(error)) => {
            let (failure, text) = failure_of(&error);
            working_set_failure(failure, text)
        }
        Err(error) => working_set_failure(EnumerateFailure::Retry, error.to_string()),
    }
}

#[cfg(test)]
mod tests;
