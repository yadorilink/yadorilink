//! The provider projector at scale: install a namespace of N paths (heads, versions, armed
//! obligations: what a checkpoint install leaves) and time the projector, in batches of 5 000,
//! and the all-parents verification. Printed, not asserted against a clock; it asserts that the
//! work scales roughly linearly between two sizes (a per-name pass over the whole level plan
//! would make the flat layout quadratic).
//!
//! `YL_PROJ_SIZES` ("10000,20000"), `YL_PROJ_LAYOUT` ("flat" | "mixed"), `YL_PROJ_BATCH` (5000).
//!
//! `cargo test -p yadorilink-sync-sqlite --release --test provider_projector_kernel -- --ignored --nocapture`

use std::sync::Arc;
use std::time::Instant;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{
    AuthorSeq, BlockHash, DeltaHash, DeviceId, FolderGroupId, SyncPath,
};
use yadorilink_replica_domain::native_state::{Dot, HeadPayload, NativeState, PathHeads};
use yadorilink_replica_domain::session_state::ProviderKind;
use yadorilink_sqlite_runtime::{DatabaseError, SyncDatabase};
use yadorilink_sync_sqlite::link::LinkRepository;
use yadorilink_sync_sqlite::provider::ProviderRepository;
use yadorilink_sync_sqlite::SyncSqliteError;

const GROUP: &str = "proj-kernel-group";
const MTIME: i64 = 1_700_000_000_000_000_000;

fn path_for(layout: &str, i: usize) -> String {
    match layout {
        "flat" => format!("f{i:07}.bin"),
        _ => format!("d{:03}/f{i:07}.bin", i % 1000),
    }
}

fn hash32(i: usize, tag: u8) -> [u8; 32] {
    let mut h = [tag; 32];
    h[..8].copy_from_slice(&(i as u64).to_be_bytes());
    h
}

fn version_of(i: usize) -> FileVersion {
    FileVersion::new(
        vec![VersionBlock { hash: BlockHash(hash32(i, 0xC3).to_vec()), size: 65536 }],
        65536,
        FileMeta {
            mtime_unix_nanos: MTIME,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn run(layout: &str, n: usize, batch: usize) -> (f64, f64) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(
        SyncDatabase::open(dir.path().join("index.db"), |conn| {
            yadorilink_sync_sqlite::init_replica_schema(conn)
                .map_err(|e| DatabaseError::CorruptSchema(e.to_string()))
        })
        .unwrap(),
    );
    LinkRepository::new(db.clone()).add_link("/provider/kernel", GROUP).unwrap();
    let repo = ProviderRepository::new(db.clone());
    let root = repo.declare_root(GROUP, ProviderKind::MacFileProvider, "Kernel").unwrap();
    repo.mark_install_done(&root).unwrap();

    let author =
        AuthorId { device: DeviceId("dev-kernel".into()), incarnation: IncarnationId([1; 16]) };
    let versions: Vec<FileVersion> = (0..n).map(version_of).collect();
    let mut state = NativeState::new();
    for (i, version) in versions.iter().enumerate() {
        let mut heads = PathHeads::new();
        heads.insert(
            Dot { author: author.clone(), seq: AuthorSeq(i as u64 + 1) },
            HeadPayload { version: version.version_hash, provenance: DeltaHash(hash32(i, 0xB2)) },
        );
        state.heads.insert(SyncPath(path_for(layout, i)), heads);
    }
    state.context.insert(author, AuthorSeq(n as u64));
    let group = FolderGroupId(GROUP.to_owned());
    let install = Instant::now();
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        for v in &versions {
            yadorilink_sync_sqlite::dag_store::put_file_version(tx, GROUP, v)?;
        }
        yadorilink_sync_sqlite::native_store::install_state(tx, &group, &state)?;
        yadorilink_sync_sqlite::native_desired_state::arm_projection_for_state_change(
            tx,
            GROUP,
            &NativeState::new(),
            &state,
        )?;
        Ok(())
    })
    .unwrap();
    eprintln!("{layout} n={n}: install {:.2}s", install.elapsed().as_secs_f64());

    let started = Instant::now();
    let mut done = 0;
    loop {
        let t = Instant::now();
        let k = repo.project_batch(GROUP, batch).unwrap();
        if k == 0 {
            break;
        }
        done += k;
        eprintln!("  batch of {k}: {:.2}s ({done}/{n})", t.elapsed().as_secs_f64());
    }
    let projected = started.elapsed().as_secs_f64();
    assert_eq!(done, n);
    let t = Instant::now();
    assert_eq!(repo.verify_namespace(GROUP).unwrap(), None);
    let verified = t.elapsed().as_secs_f64();
    eprintln!("{layout} n={n}: project {projected:.2}s, verify {verified:.2}s");
    (projected, verified)
}

#[test]
#[ignore = "scale measurement: run with --release --ignored --nocapture"]
fn the_projector_scales_linearly_on_a_flat_and_a_mixed_namespace() {
    let sizes: Vec<usize> = std::env::var("YL_PROJ_SIZES")
        .unwrap_or_else(|_| "10000,20000".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let batch = std::env::var("YL_PROJ_BATCH").ok().and_then(|v| v.parse().ok()).unwrap_or(5000);
    let layouts: Vec<String> = match std::env::var("YL_PROJ_LAYOUT") {
        Ok(l) => vec![l],
        Err(_) => vec!["flat".into(), "mixed".into()],
    };
    for layout in layouts {
        let mut times = Vec::new();
        for &n in &sizes {
            times.push((n, run(&layout, n, batch)));
        }
        if let [(n0, (p0, _)), .., (n1, (p1, _))] = times[..] {
            // Doubling the namespace must not much more than double the projection: the per-name
            // scan over a level plan made this ratio about the square of the size ratio.
            let size_ratio = n1 as f64 / n0 as f64;
            assert!(
                p1 / p0 < size_ratio * 2.5,
                "{layout}: {n0} -> {n1} took {p0:.2}s -> {p1:.2}s (not linear)"
            );
        }
    }
}

/// A cheap guard that the projector stays linear (not run only on demand): quadrupling a flat
/// namespace must not cost more than about ten times as much (a per-name pass over the whole
/// level plan costs sixteen times).
#[test]
fn the_projector_does_not_go_quadratic() {
    // One batch each: the whole flat level is one plan, the case a per-name pass over it
    // squares.
    let (small, _) = run("flat", 2_000, 2_000);
    let (large, _) = run("flat", 8_000, 8_000);
    assert!(large / small < 10.0, "2000 -> 8000 took {small:.2}s -> {large:.2}s (not linear)");
}
