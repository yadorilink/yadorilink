#![cfg(test)]

use super::*;

#[test]
fn arc_test_replica_coerces_to_port_trait() {
    use crate::test_support::TestReplica;

    let state: Arc<TestReplica> = Arc::new(TestReplica::open_in_memory().unwrap());
    let port: Arc<dyn LocalMutationStore> = state;

    let _lock = port.path_lock("group-a", "path/a.txt");
    assert_eq!(port.get_file("group-a", "path/a.txt").unwrap(), None);
}
