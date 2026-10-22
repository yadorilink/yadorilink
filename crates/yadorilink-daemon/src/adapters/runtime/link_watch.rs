//! `LinkRuntimeController`-backed [`LinkRuntimePort`].

use std::sync::Arc;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::application::ports::{BoxFuture, LinkRuntimePort};

pub(crate) struct DaemonLinkRuntimeAdapter {
    controller: Arc<LinkRuntimeController>,
}

impl DaemonLinkRuntimeAdapter {
    pub(crate) fn new(controller: Arc<LinkRuntimeController>) -> Self {
        Self { controller }
    }
}

impl LinkRuntimePort for DaemonLinkRuntimeAdapter {
    fn start_link_watch(&self, local_path: String, group_id: String) -> Result<(), String> {
        let refused_for_now = local_path.clone();
        self.controller.start(local_path, group_id).map_err(|e| {
            if matches!(e, crate::error::DaemonError::SafeStopInProgress) {
                // Left waiting: the next volume pass starts it once the stop has ended.
                self.controller.wait_unless_started(&refused_for_now);
            }
            e.to_string()
        })
    }

    fn stop_link_watch<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.controller.stop(local_path))
    }
}
