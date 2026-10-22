//! `LinkVolumeJob` -- follows each linked folder's volume: stops a link whose
//! disk went away and starts it again when the disk is back. See
//! `LinkRuntimeController::follow_link_volumes`.

use std::sync::Arc;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;

/// How often the folders' volumes are checked: a disk that comes back (a late
/// boot-time mount, a replugged drive) starts syncing within this long.
pub(crate) const TICK: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) struct LinkVolumeJob {
    controller: Arc<LinkRuntimeController>,
}

impl LinkVolumeJob {
    pub(crate) fn new(controller: Arc<LinkRuntimeController>) -> Self {
        Self { controller }
    }

    pub(crate) async fn run_once(&self) {
        self.controller.follow_link_volumes().await;
    }
}
