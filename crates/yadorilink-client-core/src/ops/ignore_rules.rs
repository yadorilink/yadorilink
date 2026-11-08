//! A folder's ignore rules.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{IgnoreRulesGetRequest, IgnoreRulesSetRequest};

use crate::daemon::control;
use crate::error::CoreError;

/// The folder's rules text; empty when it has none.
pub async fn ignore_rules_get(group_id: &str) -> Result<String, CoreError> {
    let resp = control::send(ReqPayload::IgnoreRulesGet(IgnoreRulesGetRequest {
        group_id: group_id.into(),
    }))
    .await?;
    let Some(RespPayload::IgnoreRulesGet(answer)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    Ok(answer.text)
}

/// Replaces the folder's rules; the daemon refuses an unusable line (`line N: ...`).
pub async fn ignore_rules_set(group_id: &str, text: &str) -> Result<(), CoreError> {
    let resp = control::send(ReqPayload::IgnoreRulesSet(IgnoreRulesSetRequest {
        group_id: group_id.into(),
        text: text.into(),
    }))
    .await?;
    let Some(RespPayload::IgnoreRulesSet(_)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    Ok(())
}
