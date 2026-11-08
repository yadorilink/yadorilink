//! The `items` family of control verbs: each fn is the body of one `handle_request` arm.

use super::*;

/// The folder a command line names, a plain linked folder or a File Provider folder at its
/// place in the file manager: the one resolver, and only the folder itself.
pub(super) async fn resolve_folder(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::ResolveFolderRequest,
) -> RespPayload {
    use crate::queries::linked_path::FolderPath;
    match context.queries.linked_path.resolve_folder(&r.path) {
        FolderPath::Folder(group_id) => {
            RespPayload::ResolveFolder(yadorilink_ipc_proto::daemonctl::ResolveFolderResponse {
                group_id,
            })
        }
        FolderPath::Inside(_) => RespPayload::Error(format!(
            "{} is inside a linked folder, not the folder itself: name the folder",
            r.path
        )),
        FolderPath::NotLinked => RespPayload::Error(format!("{} is not a linked folder", r.path)),
    }
}

pub(super) async fn hydrate(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::HydrateRequest,
) -> RespPayload {
    match context.queries.linked_path.resolve(&r.absolute_path) {
        Some((group_id, path)) => {
            let application = context.application.clone();
            match application.materialization.hydrate(&group_id, &path).await {
                Ok(downloaded) => RespPayload::Hydrate(HydrateResponse { downloaded }),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }
        None if context.queries.linked_path.resolve_provider(&r.absolute_path).is_some() => {
            refused(PROVIDER_DOWNLOAD, NextStep::KeepItemOnDevice)
        }
        None => RespPayload::Error("path is not under any linked folder".into()),
    }
}

pub(super) async fn evict(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::EvictRequest,
) -> RespPayload {
    match context.queries.linked_path.resolve(&r.absolute_path) {
        Some((group_id, path)) => {
            let application = context.application.clone();
            match application.materialization.evict(&group_id, &path) {
                Ok(outcome) => RespPayload::Evict(EvictResponse {
                    dehydrated: outcome.dehydrated,
                    blocks_reclaimed: outcome.blocks_reclaimed,
                    bytes_reclaimed: outcome.bytes_reclaimed,
                    not_freed_reason: outcome.not_freed.map(str::to_owned).unwrap_or_default(),
                    ..Default::default()
                }),
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }
        None if std::path::Path::new(&r.absolute_path).is_dir() => {
            // Free Up Space on a folder runs its online-only rules again: files that were left
            // on purpose (unsynced edits since shared, a copy that landed later) are looked at
            // once more. The folder's own root is a folder here too.
            use crate::queries::linked_path::FolderPath;
            let linked = &context.queries.linked_path;
            let found = linked.resolve_provider(&r.absolute_path).or_else(|| {
                match linked.resolve_folder(&r.absolute_path) {
                    FolderPath::Folder(group_id) => Some((group_id, String::new())),
                    _ => None,
                }
            });
            match found {
                Some((group_id, path)) => {
                    match context.provider_evict.reapply_rules(&group_id, &path) {
                        Ok(rules) if rules > 0 => RespPayload::Evict(EvictResponse::default()),
                        Ok(_) => RespPayload::Error(format!(
                            "{}: no online-only rule covers this folder; set it online only first",
                            r.absolute_path
                        )),
                        Err(e) => RespPayload::Error(e.to_string()),
                    }
                }
                None => RespPayload::Error("path is not under any linked folder".into()),
            }
        }
        None => match context.queries.linked_path.resolve_provider(&r.absolute_path) {
            // A file in a provider folder: the host drops the OS copy, and the daemon frees
            // its cached blocks when a full replica holds a durable lease on the version.
            Some((group_id, path)) => match context.provider_evict.evict(&group_id, &path).await {
                Ok(outcome) => RespPayload::Evict(EvictResponse {
                    dehydrated: outcome.dehydrated,
                    blocks_reclaimed: outcome.reclaimed.blocks,
                    bytes_reclaimed: outcome.reclaimed.bytes,
                    retained_reason: outcome
                        .retained
                        .map(|why| why.code().to_owned())
                        .unwrap_or_default(),
                    not_freed_reason: String::new(),
                }),
                Err(e) => RespPayload::Error(e.to_string()),
            },
            None => RespPayload::Error("path is not under any linked folder".into()),
        },
    }
}

/// The retention rule is local state keyed by (group, relative path), so a file in a provider
/// folder is as keepable as one in a plain folder; `online_only` is a provider folder's choice.
pub(super) async fn set_retention_rule(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::SetRetentionRuleRequest,
) -> RespPayload {
    use crate::application::ports::RuleChoice;
    use yadorilink_ipc_proto::daemonctl::RetentionRule;
    let rule = match r.rule() {
        RetentionRule::Keep => RuleChoice::Keep,
        RetentionRule::OnlineOnly => RuleChoice::OnlineOnly,
        RetentionRule::Default => RuleChoice::Default,
        RetentionRule::Unspecified => {
            return RespPayload::Error("a retention rule is required".into());
        }
    };
    match resolve_item(context, &r.absolute_path) {
        Some((group_id, path)) => {
            let application = context.application.clone();
            match application.materialization.set_rule(&group_id, &path, rule).await {
                Ok(mut outcome) => {
                    // The choice is recorded. In a provider folder the operating system holds the
                    // pin and the content, so the host is asked to make it agree (the File Provider
                    // host does not handle the request yet: it is not asked there).
                    if !cfg!(target_vendor = "apple")
                        && context.queries.linked_path.resolve_provider(&r.absolute_path).is_some()
                    {
                        if let Ok((choice, answer)) =
                            context.provider_evict.apply_pins(&group_id, &path).await
                        {
                            // A host that cannot pin leaves the generic note of the outcome; any
                            // other answer is the whole story and replaces it.
                            if answer != crate::provider_host_link::PinAnswer::Unsupported {
                                outcome.download_error = pin_note(choice, &answer);
                            }
                        }
                    }
                    RespPayload::SetRetentionRule(SetRetentionRuleResponse {
                        retention: Some(retention_to_proto(outcome.retention)),
                        download_error: outcome.download_error.unwrap_or_default(),
                        history_not_kept_reason: outcome
                            .history_not_kept_reason
                            .unwrap_or_default()
                            .to_owned(),
                    })
                }
                Err(e) => RespPayload::Error(e.to_string()),
            }
        }
        None => RespPayload::Error("path is not under any linked folder".into()),
    }
}

/// The text a host's answer to a pin request adds to the outcome, `None` when it needs none. The
/// rule stands in every case; this says only what could not be applied. A host that cannot pin
/// (`Unsupported`) adds nothing: the outcome keeps the generic note for a kept item.
fn pin_note(
    choice: yadorilink_ipc_proto::shellipc::PinChoice,
    answer: &crate::provider_host_link::PinAnswer,
) -> Option<String> {
    use crate::provider_host_link::PinAnswer;
    use yadorilink_ipc_proto::shellipc::PinChoice;
    let keep = choice == PinChoice::Keep;
    match answer {
        // Downloading is not an error: the pin stands and the operating system is fetching.
        PinAnswer::Done | PinAnswer::Downloading | PinAnswer::Unsupported => None,
        PinAnswer::NotFound if keep => Some(
            "this item is not shown in the folder yet; the choice is recorded and the item is \
             kept once it appears and you choose it again"
                .to_owned(),
        ),
        PinAnswer::NotFound => None,
        PinAnswer::NotConnected => Some(
            "the provider host is not running; the choice is recorded but not applied to this PC: \
             choose it again once the host is running"
                .to_owned(),
        ),
        PinAnswer::Error(why) => {
            Some(format!("the operating system could not apply the choice: {why}"))
        }
    }
}

/// The answer for an item of a provider folder. The retention is the daemon's own standing choice
/// and is always in it; with no local state (the OS gave none, or the provider is not connected)
/// the item is `known: false` and no action applies, rather than a refusal that would hide the
/// retention too. The operating system downloads and removes downloads in a provider folder, so the
/// root's eviction gate is open by construction.
fn provider_item_status(
    path: &str,
    local_state: Option<yadorilink_ipc_proto::daemonctl::LocalState>,
    retention: Option<crate::application::ports::RetentionState>,
) -> RespPayload {
    let available_actions = item_actions(ItemActionInputs {
        path,
        local_state: local_state.as_ref(),
        retention,
        provider_folder: true,
        reclaim_gate_open: true,
    });
    RespPayload::MaterializationStatus(MaterializationStatusResponse {
        known: local_state.is_some(),
        local_state,
        retention: retention.map(retention_to_proto),
        available_actions,
    })
}

pub(super) async fn materialization_status(
    context: &crate::control_context::ControlContext,
    r: yadorilink_ipc_proto::daemonctl::MaterializationStatusRequest,
) -> RespPayload {
    // A provider folder's items live in the OS's File Provider location, and the daemon
    // does not track their local state per item: name that, rather than "not linked".
    if context.queries.linked_path.resolve(&r.absolute_path).is_none()
        && context.queries.linked_path.resolve_provider(&r.absolute_path).is_some()
    {
        // The retention is the daemon's own standing choice: it is answered whether or not the item's
        // local state can be read.
        let retention = context.queries.linked_path.resolve_provider(&r.absolute_path).map_or(
            Ok(None),
            |(group_id, path)| {
                context.application.materialization.retention(&group_id, &path).map(Some)
            },
        );
        let retention = match retention {
            Ok(retention) => retention,
            Err(e) => return RespPayload::Error(e.to_string()),
        };
        // On macOS the OS marks a not-downloaded item `dataless` in the file's flags; on Windows
        // the attributes carry the recall marks. Reading them never downloads the item. On Windows
        // they only tell while the provider is connected (they hide bits once it is gone), so
        // unless the host serves this root the state is left unknown rather than guessed.
        let host_up =
            !cfg!(windows)
                || context.queries.linked_path.resolve_provider(&r.absolute_path).is_some_and(
                    |(group_id, _)| context.provider_evict.host_serves_group(&group_id),
                );
        let local_state = host_up.then(|| provider_local_state(&r.absolute_path)).flatten();
        provider_item_status(&r.absolute_path, local_state, retention)
    } else {
        match context.queries.linked_path.resolve(&r.absolute_path) {
            Some((group_id, path)) => {
                let application = context.application.clone();
                // The policy is a standing choice, so it is reported for an unindexed
                // path too; one that cannot be read fails the query rather than
                // reading as "reclaimable".
                let materialization = &application.materialization;
                match materialization.retention(&group_id, &path).and_then(|retention| {
                    materialization.status(&group_id, &path).map(|s| (retention, s))
                }) {
                    Ok((retention, Some(status))) => {
                        let local_state = local_state_to_proto(status.state);
                        let available_actions = item_actions(ItemActionInputs {
                            path: &r.absolute_path,
                            local_state: Some(&local_state),
                            retention: Some(retention),
                            provider_folder: false,
                            reclaim_gate_open: materialization.evict_supported(&group_id),
                        });
                        RespPayload::MaterializationStatus(MaterializationStatusResponse {
                            known: true,
                            local_state: Some(local_state),
                            retention: Some(retention_to_proto(retention)),
                            available_actions,
                        })
                    }
                    Ok((retention, None)) => {
                        RespPayload::MaterializationStatus(MaterializationStatusResponse {
                            known: false,
                            local_state: None,
                            retention: Some(retention_to_proto(retention)),
                            available_actions: Vec::new(),
                        })
                    }
                    Err(e) => RespPayload::Error(e.to_string()),
                }
            }
            None => RespPayload::Error("path is not under any linked folder".into()),
        }
    }
}

#[cfg(test)]
mod pin_note_tests {
    use super::{pin_note, provider_item_status};
    use crate::provider_host_link::PinAnswer;
    use yadorilink_ipc_proto::shellipc::PinChoice;

    #[test]
    fn a_pin_that_took_effect_or_is_downloading_says_nothing_and_a_failure_says_what_failed() {
        for answer in [PinAnswer::Done, PinAnswer::Downloading] {
            assert_eq!(pin_note(PinChoice::Keep, &answer), None, "{answer:?}");
            assert_eq!(pin_note(PinChoice::OnlineOnly, &answer), None, "{answer:?}");
        }
        assert!(pin_note(PinChoice::Keep, &PinAnswer::NotConnected)
            .unwrap()
            .contains("not running"));
        assert!(pin_note(PinChoice::OnlineOnly, &PinAnswer::NotConnected).is_some());
        assert!(pin_note(PinChoice::Keep, &PinAnswer::Error("boom".into()))
            .unwrap()
            .contains("boom"));
        assert!(pin_note(PinChoice::Keep, &PinAnswer::NotFound).is_some());
        // Clearing the pin of an item that is not shown has nothing to apply.
        assert_eq!(pin_note(PinChoice::OnlineOnly, &PinAnswer::NotFound), None);
    }

    #[test]
    fn a_provider_item_answers_its_retention_with_or_without_a_readable_local_state() {
        use crate::application::ports::RetentionState;
        use yadorilink_ipc_proto::daemonctl::{
            daemon_control_response::Payload, LocalState, LocalTransition, RetentionPolicy,
        };
        let kept = RetentionState { pinned: true, online_only: false, explicit: true };
        let status = |local_state| match provider_item_status("a.txt", local_state, Some(kept)) {
            Payload::MaterializationStatus(status) => status,
            other => panic!("expected a status, got {other:?}"),
        };

        // The local state could not be read (the provider is not connected, or the OS gave none):
        // not a refusal; the retention is there and nothing is offered.
        let unknown = status(None);
        assert!(!unknown.known);
        assert!(unknown.local_state.is_none());
        let retention = unknown.retention.expect("the retention is answered");
        assert_eq!(retention.policy, RetentionPolicy::Pinned as i32);
        assert!(retention.explicit);
        assert!(unknown.available_actions.is_empty(), "{:?}", unknown.available_actions);

        // A readable state: known, with the same retention.
        let known = status(Some(LocalState {
            local_object_present: false,
            current_content_present: false,
            transition: LocalTransition::None as i32,
        }));
        assert!(known.known);
        assert_eq!(known.retention, Some(retention));
    }
}
