//! `DaemonState`-backed [`CustodyLeaseHandoffPort`]: moving the custody
//! leases this device holds for other devices off a group it stops keeping.

use std::sync::Arc;

use crate::application::ports::{BoxFuture, CustodyLeaseHandoffPort};
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonCustodyLeaseHandoffAdapter {
    state: Arc<DaemonState>,
}

impl DaemonCustodyLeaseHandoffAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl CustodyLeaseHandoffPort for DaemonCustodyLeaseHandoffAdapter {
    fn hand_off_leases<'a>(
        &'a self,
        group_id: &'a str,
    ) -> BoxFuture<'a, Result<Box<dyn Send>, String>> {
        Box::pin(async move {
            let closed = self.state.hand_off_custody_leases(group_id).await?;
            Ok(Box::new(closed) as Box<dyn Send>)
        })
    }
}
