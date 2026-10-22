use super::*;

/// The batch is a knob with a small default, and a build yields between batches while idle
/// polling stays slow.
#[test]
fn the_batch_is_a_knob_and_a_build_yields_between_batches() {
    assert_eq!(batch_from(None), 1_000);
    assert_eq!(batch_from(Some("250")), 250);
    assert_eq!(batch_from(Some(" 4000 ")), 4_000);
    for bad in ["0", "-3", "many", ""] {
        assert_eq!(batch_from(Some(bad)), 1_000, "{bad:?}");
    }
    assert_eq!(next_delay(&Tick { projected: 1_000, became_ready: false }), YIELD);
    assert_eq!(next_delay(&Tick::default()), POLL);
    assert!(YIELD < POLL);
}

/// A change nobody announced to the OS (such as a pin changing what it may do with an item) gets
/// the root's publication driver kicked, once per pass until it is announced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unannounced_change_kicks_the_publication_driver() {
    use crate::provider_read_fault::declared_root;
    use std::sync::Mutex;
    let (coordinator, root) = declared_root();
    let store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
    let state = DaemonState::new("device-a".into(), coordinator.clone(), store);
    let kicked = Mutex::new(Vec::<String>::new());
    let kick = |root: &str| kicked.lock().unwrap().push(root.to_owned());

    pass(&state, 10, kick).await.unwrap();
    assert!(kicked.lock().unwrap().is_empty(), "a quiet root was kicked");
    coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute("UPDATE provider_roots SET change_seq = 1", [])?;
            Ok(())
        })
        .unwrap();
    pass(&state, 10, kick).await.unwrap();
    assert_eq!(*kicked.lock().unwrap(), vec![root.clone()]);
    coordinator.provider_repository().mark_announced(&root, 1).unwrap();
    pass(&state, 10, kick).await.unwrap();
    assert_eq!(kicked.lock().unwrap().len(), 1, "an announced change was kicked again");
}

/// A root listing that fails is reported as such (and projects nothing); the next pass that can
/// read resumes the work for the root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_root_list_is_not_a_pass_over_zero_roots() {
    use crate::provider_read_fault::{declared_root, Fault};
    use std::sync::Mutex;
    let (coordinator, _root) = declared_root();
    let store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
    let state = DaemonState::new("device-a".into(), coordinator.clone(), store);
    let kicked = Mutex::new(Vec::<String>::new());
    let kick = |root: &str| kicked.lock().unwrap().push(root.to_owned());

    let fault = Fault::inject(&coordinator, "links", "provider_kind");
    assert_eq!(pass(&state, 10, kick).await.unwrap(), Pass::RootsUnreadable);
    assert!(kicked.lock().unwrap().is_empty());
    fault.restore();

    assert!(matches!(pass(&state, 10, kick).await.unwrap(), Pass::Done { roots: 1, .. }));
}
