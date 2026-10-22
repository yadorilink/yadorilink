//! Cheap idle/resource regression check for a converged, linked folder.
//!
//! One daemon links a folder holding a few hundred files, waits until every
//! file is indexed, lets the first reconcile settle, then samples the process
//! for an idle window. The bounds are deliberately generous: they exist to
//! catch a busy loop, a re-reconcile that never stops, a leak or runaway log
//! output, not to pin precise numbers. Baseline numbers and the re-run command
//! live in `docs/IDLE_RESOURCE_BASELINE.md`.
//!
//! Window length: `YADORILINK_IDLE_SECS` (default 20; use 300+ for a short soak).
//! File count: `YADORILINK_IDLE_FILES` (default 300).
//! Printed metrics: lines starting with `idle-baseline:`.

#![cfg(unix)]

mod support;

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

const GROUP: &str = "idle-group";
const DEFAULT_FILE_COUNT: usize = 300;

/// Idle CPU may use at most this share of one core, averaged over the window.
const MAX_IDLE_CPU_FRACTION: f64 = 0.05;
/// RSS growth across the idle window (after settling).
const MAX_RSS_GROWTH_KIB: u64 = 64 * 1024;
/// Open descriptors may not grow across the idle window.
const MAX_FD_GROWTH: usize = 8;
/// Log bytes emitted at INFO and above during the idle window.
const MAX_IDLE_LOG_BYTES: u64 = 64 * 1024;

/// Idle reads (Linux `rchar`): a fixed allowance plus, per minute of window, this
/// many bytes per file. The periodic repair pass re-reads the index about every
/// two minutes (measured ~0.4 KiB per file per pass); a per-second tick that
/// walks the tree or database would exceed this by orders of magnitude.
const READ_BASE_BYTES: u64 = 1024 * 1024;
const READ_BYTES_PER_FILE_PER_MINUTE: u64 = 4 * 1024;

static LOG_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingWriter;

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG_BYTES.fetch_add(buf.len() as u64, Ordering::Relaxed);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn cpu_seconds() -> f64 {
    // SAFETY: `getrusage` writes into the zeroed struct we pass.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    tv(usage.ru_utime) + tv(usage.ru_stime)
}

fn rss_kib() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout).trim().parse().expect("ps rss")
}

/// Bytes the process asked the kernel to read (`rchar`); Linux only. An idle
/// daemon that re-reads its tree or database every tick shows up here long
/// before it shows up as CPU.
fn read_bytes() -> Option<u64> {
    let io = std::fs::read_to_string("/proc/self/io").ok()?;
    io.lines().find_map(|l| l.strip_prefix("rchar: ")?.trim().parse().ok())
}

fn open_fds() -> usize {
    let dir = if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" };
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

#[ignore = "timed resource check -- run with --ignored (see docs/IDLE_RESOURCE_BASELINE.md)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn converged_linked_folder_stays_idle() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(|| CountingWriter)
        .try_init();
    let file_count: usize = std::env::var("YADORILINK_IDLE_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_FILE_COUNT);
    let window = Duration::from_secs(
        std::env::var("YADORILINK_IDLE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(20),
    );

    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("sync.db");
    let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
    let state = DaemonState::new("device-idle".into(), sync_state.clone(), store);
    support::ensure_device_signing_key(&state);
    // A linked group with no verified policy head withholds every write.
    sync_state.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    let root = tempfile::tempdir().unwrap();
    for i in 0..file_count {
        std::fs::write(root.path().join(format!("file-{i:04}.txt")), format!("content {i}"))
            .unwrap();
    }
    let local_path = root.path().to_string_lossy().to_string();
    sync_state.link_repository().add_link(&local_path, GROUP).unwrap();
    let controller = LinkRuntimeController::new(state.clone());
    controller.start(local_path.clone(), GROUP.into()).unwrap();

    let indexed =
        || sync_state.file_index_repository().list_files(GROUP).map(|f| f.len()).unwrap_or(0);
    let deadline = Instant::now() + Duration::from_secs(120);
    while indexed() < file_count {
        assert!(Instant::now() < deadline, "only {} of {file_count} files indexed", indexed());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Let the first reconcile and any follow-up passes finish.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let (cpu0, rss0, fd0, log0, idx0) =
        (cpu_seconds(), rss_kib(), open_fds(), LOG_BYTES.load(Ordering::Relaxed), indexed());
    let wal = db_path.with_extension("db-wal");
    let wal0 = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    let r0 = read_bytes();
    let t0 = Instant::now();
    tokio::time::sleep(window).await;
    let elapsed = t0.elapsed().as_secs_f64();
    let cpu_fraction = (cpu_seconds() - cpu0) / elapsed;
    let idle_read = read_bytes().zip(r0).map(|(a, b)| a - b);
    let (rss1, fd1) = (rss_kib(), open_fds());
    let log_bytes = LOG_BYTES.load(Ordering::Relaxed) - log0;
    let wal1 = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);

    println!(
        "idle-baseline: files={file_count} window_s={elapsed:.0} cpu_fraction={cpu_fraction:.4} \
         rss_kib={rss0}->{rss1} fds={fd0}->{fd1} log_bytes={log_bytes} wal_bytes={wal0}->{wal1} idle_rchar={idle_read:?}"
    );

    assert_eq!(indexed(), idx0, "index changed while idle");
    assert!(cpu_fraction < MAX_IDLE_CPU_FRACTION, "idle CPU {cpu_fraction:.3} cores: busy loop?");
    assert!(rss1.saturating_sub(rss0) < MAX_RSS_GROWTH_KIB, "RSS grew {rss0}->{rss1} KiB");
    assert!(fd1 <= fd0 + MAX_FD_GROWTH, "open fds grew {fd0}->{fd1}");
    assert!(log_bytes < MAX_IDLE_LOG_BYTES, "{log_bytes} log bytes while idle");
    if let Some(read) = idle_read {
        let minutes = elapsed / 60.0 + 1.0;
        let allowed = READ_BASE_BYTES
            + (READ_BYTES_PER_FILE_PER_MINUTE as f64 * minutes) as u64 * file_count as u64;
        assert!(
            read < allowed,
            "{read} bytes read while idle (allowed {allowed}): per-tick O(N) read?"
        );
    }
    assert!(wal1 < wal0 + 1024 * 1024, "WAL grew {wal0}->{wal1} bytes while idle");
    controller.stop(&local_path).await;
}
