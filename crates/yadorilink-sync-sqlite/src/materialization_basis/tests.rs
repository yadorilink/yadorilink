#![cfg(test)]

use rusqlite::Connection;
use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::native_state::{DeltaHash, HeadPayload, NativeState};

use super as basis;
use super::ReflectedHeads;

const GROUP: &str = "g";

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    c
}

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.to_string()), incarnation: IncarnationId([1; 16]) }
}

fn file(mtime: i64) -> FileVersion {
    FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn payload(v: &FileVersion, tag: u8) -> HeadPayload {
    HeadPayload { version: v.version_hash, provenance: DeltaHash([tag; 32]) }
}

fn install(c: &Connection, versions: &[&FileVersion], state: &NativeState) {
    for v in versions {
        crate::dag_store::put_file_version(c, GROUP, v).unwrap();
    }
    crate::native_store::install_state(c, &FolderGroupId(GROUP.to_owned()), state).unwrap();
}

fn put(state: &mut NativeState, who: &str, path: &str, v: &FileVersion, tag: u8) {
    state.put(&author(who), SyncPath(path.into()), &[], payload(v, tag)).unwrap();
}

#[test]
fn the_encoding_ignores_head_order_and_repeats() {
    let (a, b) = ([2u8; 32], [1u8; 32]);
    assert_eq!(ReflectedHeads::of(&[a, b, a], b"id"), ReflectedHeads::of(&[b, a], b"id"));
    assert_ne!(ReflectedHeads::of(&[a], b"x"), ReflectedHeads::of(&[a], b"y"));
}

#[test]
fn a_proof_stays_current_while_its_path_does_whatever_moves_elsewhere() {
    let c = conn();
    let (va, vb, vc) = (file(1), file(2), file(3));
    let mut state = NativeState::new();
    put(&mut state, "a", "a", &va, 1);
    install(&c, &[&va, &vb, &vc], &state);
    let recorded = basis::record(&c, GROUP, "a").unwrap();
    assert!(basis::is_current(&c, GROUP, "a", &recorded).unwrap());

    // Movement at another path does not stale it.
    put(&mut state, "a", "b", &vb, 2);
    install(&c, &[&va, &vb, &vc], &state);
    assert!(basis::is_current(&c, GROUP, "a", &recorded).unwrap());

    // A concurrent head at the path does, even if the winner does not change.
    put(&mut state, "b", "a", &vc, 3);
    install(&c, &[&va, &vb, &vc], &state);
    assert!(!basis::is_current(&c, GROUP, "a", &recorded).unwrap());
}
