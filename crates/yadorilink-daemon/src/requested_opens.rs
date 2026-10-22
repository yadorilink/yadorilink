//! Opens the user is waiting on that have no `Hydrating` row yet: an On-Demand provider open
//! queued for a daemon-wide assembly slot is still a placeholder on disk, but it is requested
//! content. The daemon counts them per group so `LinkStatus.requested_content_count` can say so.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct RequestedOpens {
    by_group: Mutex<HashMap<String, u64>>,
}

/// Counts one open from `RequestedOpens::begin` until it is dropped (finished, failed or
/// cancelled).
pub(crate) struct OpenGuard {
    opens: Arc<RequestedOpens>,
    group_id: String,
}

impl RequestedOpens {
    pub(crate) fn begin(self: &Arc<Self>, group_id: &str) -> OpenGuard {
        *self.lock().entry(group_id.to_owned()).or_insert(0) += 1;
        OpenGuard { opens: self.clone(), group_id: group_id.to_owned() }
    }

    pub(crate) fn count(&self, group_id: &str) -> u64 {
        self.lock().get(group_id).copied().unwrap_or(0)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, u64>> {
        self.by_group.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        let mut map = self.opens.lock();
        if let Some(n) = map.get_mut(&self.group_id) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.group_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_open_until_dropped() {
        let opens = Arc::new(RequestedOpens::default());
        let a = opens.begin("g");
        let b = opens.begin("g");
        assert_eq!(opens.count("g"), 2);
        drop(a);
        assert_eq!(opens.count("g"), 1);
        drop(b);
        assert_eq!(opens.count("g"), 0);
        assert_eq!(opens.count("other"), 0);
    }
}
