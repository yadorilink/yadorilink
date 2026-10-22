#![cfg(test)]

//! The handoff root's bookkeeping: unique names, revocation that never forgets a file it could
//! not take back, and tracking that ends with the file.

use super::*;

const ITEM: [u8; 16] = [7; 16];

fn root(lifetime: Duration) -> (tempfile::TempDir, Arc<HandoffRoot>) {
    let dir = tempfile::tempdir().unwrap();
    let root = HandoffRoot::open_with_lifetime(dir.path(), lifetime).unwrap();
    (dir, root)
}

#[test]
fn a_name_is_never_issued_twice_not_even_for_the_same_request_id() {
    let (_dir, root) = root(Duration::from_secs(60));
    let (other_dir, other) = root_pair();
    let first = root.name_for(b"req").unwrap();
    let second = root.name_for(b"req").unwrap();
    let elsewhere = other.name_for(b"req").unwrap();
    assert_ne!(first, second);
    assert_ne!(first, elsewhere, "two roots issued the same name");
    drop(other_dir);
    assert!(root.name_for(b"").is_none());
    assert!(root.name_for(&[1; 65]).is_none());
    assert!(!first.contains('/'));
}

fn root_pair() -> (tempfile::TempDir, Arc<HandoffRoot>) {
    // A nonce can repeat only across processes started in the same nanosecond; the counter keeps
    // names of one process apart, and a different start gives a different nonce.
    std::thread::sleep(Duration::from_millis(2));
    root(Duration::from_secs(60))
}

#[test]
fn a_file_that_cannot_be_revoked_stays_tracked_and_fails_the_call() {
    let (_dir, root) = root(Duration::from_secs(60));
    let name = root.name_for(b"req").unwrap();
    // A non-empty directory under the name cannot be removed as a file.
    let blocked = root.handoff_file(&name);
    std::fs::create_dir(&blocked).unwrap();
    std::fs::write(blocked.join("inner"), b"x").unwrap();
    root.note_delivered("root", ITEM, &name);

    assert!(root.revoke_unconsumed("root", &ITEM).is_err());
    assert_eq!(root.tracked_handoffs(), 1, "the failed file was forgotten");

    std::fs::remove_dir_all(&blocked).unwrap();
    assert_eq!(root.revoke_unconsumed("root", &ITEM).unwrap(), 0, "it is gone: nothing to take");
    assert_eq!(root.tracked_handoffs(), 0);
}

#[test]
fn revocation_removes_the_files_the_os_has_not_taken() {
    let (_dir, root) = root(Duration::from_secs(60));
    let (a, b) = (root.name_for(b"a").unwrap(), root.name_for(b"b").unwrap());
    std::fs::write(root.handoff_file(&a), b"old").unwrap();
    // `b` was taken by the OS: it is gone from `handoff/` already.
    root.note_delivered("root", ITEM, &a);
    root.note_delivered("root", ITEM, &b);
    assert_eq!(root.revoke_unconsumed("root", &ITEM).unwrap(), 1);
    assert!(!root.handoff_file(&a).exists());
    assert_eq!(root.tracked_handoffs(), 0);
}

#[tokio::test]
async fn tracking_ends_with_the_sweep_of_the_file() {
    let (_dir, root) = root(Duration::from_millis(50));
    let name = root.name_for(b"req").unwrap();
    std::fs::write(root.handoff_file(&name), b"bytes").unwrap();
    root.note_delivered("root", ITEM, &name);
    root.sweep_later("root".into(), ITEM, name.clone());
    for _ in 0..200 {
        if root.tracked_handoffs() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(root.tracked_handoffs(), 0, "the entry outlived its file");
    assert!(!root.handoff_file(&name).exists());
}

/// A root that cannot open yet opens on the first access after its directory becomes usable, with no
/// restart; the open hook runs exactly once.
#[test]
fn a_lazy_slot_opens_when_the_directory_appears() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("container");
    let opened = Arc::new(AtomicUsize::new(0));
    let slot = {
        let (path, opened) = (path.clone(), opened.clone());
        HandoffSlot::lazy(
            Arc::new(move || path.is_dir().then(|| path.join("provider"))),
            Arc::new(move |_| {
                opened.fetch_add(1, Ordering::SeqCst);
            }),
        )
    };
    assert!(slot.get().is_none(), "opened with no container");
    std::fs::create_dir(&path).unwrap();
    let root = slot.get().expect("did not open once the container existed");
    assert!(slot.get().is_some_and(|again| Arc::ptr_eq(&root, &again)));
    assert_eq!(opened.load(Ordering::SeqCst), 1);
}

/// The daemon knows no path of its own: the container the host app reports is adopted ONCE, only if
/// it is an absolute directory of this user, and the root opens under it with no restart; an explicitly
/// configured path wins.
#[test]
fn the_reported_app_group_container_is_adopted_once_and_validated() {
    let dir = tempfile::tempdir().unwrap();
    let container = dir.path().join("group");
    std::fs::create_dir(&container).unwrap();
    let file = dir.path().join("a-file");
    std::fs::write(&file, b"x").unwrap();
    let slot = HandoffSlot::lazy(Arc::new(|| None), Arc::new(|_| {}));
    assert!(slot.get().is_none(), "opened with nothing adopted");

    assert!(!slot.adopt("relative/path"), "a relative path was adopted");
    assert!(!slot.adopt(file.to_str().unwrap()), "a file was adopted");
    assert!(
        !slot.adopt(dir.path().join("missing").to_str().unwrap()),
        "a missing directory was adopted"
    );
    assert!(slot.get().is_none());

    assert!(slot.adopt(container.to_str().unwrap()));
    let root = slot.get().expect("the adopted container did not open");
    assert!(container.join("provider").is_dir());
    drop(root);

    // The first valid container stays: a different one is refused.
    let other = dir.path().join("other");
    std::fs::create_dir(&other).unwrap();
    assert!(!slot.adopt(other.to_str().unwrap()));
    assert!(slot.adopt(container.to_str().unwrap()), "re-reporting the adopted one is fine");

    // An explicitly configured path wins over a reported container.
    let configured = dir.path().join("configured");
    let slot = HandoffSlot::lazy(
        Arc::new({
            let configured = configured.clone();
            move || Some(configured.clone())
        }),
        Arc::new(|_| {}),
    );
    assert!(slot.adopt(container.to_str().unwrap()));
    assert!(slot.get().is_some());
    assert!(configured.is_dir() && !container.join("provider").join("x").exists());
}
