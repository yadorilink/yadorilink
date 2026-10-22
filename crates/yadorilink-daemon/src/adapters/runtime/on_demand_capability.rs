//! Production [`OnDemandCapabilityPort`] -- delegates to
//! `DaemonState::root_allows_on_demand` (a per-root decision: a plain root never, a ready provider
//! root only with the provider-roots switch on) unless a test override is set. Routing through `DaemonState`
//! means `set_test_on_demand_allowed` reaches this port AND
//! `hydration::evict`'s own direct call to the same `DaemonState` method
//! uniformly, from one override -- see that method's own doc comment.

use std::sync::Arc;

use crate::application::ports::OnDemandCapabilityPort;
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonOnDemandCapabilityAdapter {
    state: Arc<DaemonState>,
}

impl DaemonOnDemandCapabilityAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl OnDemandCapabilityPort for DaemonOnDemandCapabilityAdapter {
    fn allows_on_demand(&self, group_id: &str) -> bool {
        self.state.root_allows_on_demand(group_id)
    }
}
