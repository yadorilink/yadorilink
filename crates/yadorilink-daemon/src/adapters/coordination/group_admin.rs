//! HTTP-backed [`GroupAdministration`] -- see that port's own doc comment.

use std::sync::Arc;

use crate::application::ports::common::BoxFuture;
use crate::application::ports::GroupAdministration;
use crate::coordination_client::SendAuthorized;
use crate::daemon_state::DaemonState;

pub(crate) struct HttpGroupAdministration {
    state: Arc<DaemonState>,
}

impl HttpGroupAdministration {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl GroupAdministration for HttpGroupAdministration {
    fn delete_folder_group<'a>(
        &'a self,
        group_id: &'a str,
        acknowledge_cross_account_members: bool,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config().cloned() else {
                return Err("not connected to the coordination plane".to_string());
            };

            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Body {
                acknowledge_cross_account_members: bool,
            }

            let response = reqwest::Client::new()
                .delete(format!("{}/shares/groups/{group_id}", config.addr))
                .json(&Body { acknowledge_cross_account_members })
                .send_authorized(&config.auth)
                .await
                .map_err(|e| format!("could not reach the coordination plane: {e}"))?;
            if response.status().is_success() {
                return Ok(());
            }
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            Err(format!("coordination plane refused to delete the folder group ({status}): {text}"))
        })
    }
}
