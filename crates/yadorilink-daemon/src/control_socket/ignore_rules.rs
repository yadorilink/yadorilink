//! The `ignore_rules` family of control verbs: a folder's ignore rules.

use super::*;
use yadorilink_ipc_proto::daemonctl::{
    IgnoreRulesGetRequest, IgnoreRulesGetResponse, IgnoreRulesSetRequest, IgnoreRulesSetResponse,
};

pub(super) async fn ignore_rules_get(
    context: &crate::control_context::ControlContext,
    r: IgnoreRulesGetRequest,
) -> RespPayload {
    match context.application.ignore_rules.get(&r.group_id) {
        Ok(text) => RespPayload::IgnoreRulesGet(IgnoreRulesGetResponse { text }),
        Err(error) => RespPayload::Error(error.to_string()),
    }
}

pub(super) async fn ignore_rules_set(
    context: &crate::control_context::ControlContext,
    r: IgnoreRulesSetRequest,
) -> RespPayload {
    match context.application.ignore_rules.set(&r.group_id, &r.text).await {
        Ok(()) => RespPayload::IgnoreRulesSet(IgnoreRulesSetResponse {}),
        Err(error) => RespPayload::Error(error.to_string()),
    }
}
