//! Process-level idle sampler shared by the idle/resource tests
//! (`idle_resource_baseline.rs`, `idle_resource_variants.rs`). See
//! `docs/IDLE_RESOURCE_BASELINE.md`.

#![allow(dead_code)]

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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

/// Counts every INFO+ log byte the process emits.
pub fn init_log_counter() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(|| CountingWriter)
        .try_init();
}

pub fn env_num<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

pub fn idle_window() -> Duration {
    Duration::from_secs(env_num("YADORILINK_IDLE_SECS", 20))
}

pub fn cpu_seconds() -> f64 {
    // SAFETY: `getrusage` writes into the zeroed struct we pass.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    tv(usage.ru_utime) + tv(usage.ru_stime)
}

pub fn rss_kib() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout).trim().parse().expect("ps rss")
}

/// Bytes the process asked the kernel to read (`rchar`); Linux only.
pub fn read_bytes() -> Option<u64> {
    let io = std::fs::read_to_string("/proc/self/io").ok()?;
    io.lines().find_map(|l| l.strip_prefix("rchar: ")?.trim().parse().ok())
}

pub fn open_fds() -> usize {
    let dir = if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" };
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

/// OS thread count of this process.
pub fn threads() -> usize {
    if cfg!(target_os = "linux") {
        return std::fs::read_dir("/proc/self/task").map(|d| d.count()).unwrap_or(0);
    }
    let out = std::process::Command::new("ps")
        .args(["-M", "-p", &std::process::id().to_string()])
        .output()
        .expect("ps -M");
    String::from_utf8_lossy(&out.stdout).lines().count().saturating_sub(1)
}

#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub at: Instant,
    pub cpu: f64,
    pub rss_kib: u64,
    pub fds: usize,
    pub threads: usize,
    pub log_bytes: u64,
    pub rchar: Option<u64>,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        at: Instant::now(),
        cpu: cpu_seconds(),
        rss_kib: rss_kib(),
        fds: open_fds(),
        threads: threads(),
        log_bytes: LOG_BYTES.load(Ordering::Relaxed),
        rchar: read_bytes(),
    }
}

/// Catastrophic-regression gates only (busy loop, leak, log flood); the
/// measured numbers are the baseline, these are not.
pub struct Gates {
    pub max_cpu_fraction: f64,
    pub max_rss_growth_kib: u64,
    pub max_fd_growth: usize,
    pub max_thread_growth: usize,
    pub max_log_bytes: u64,
}

impl Default for Gates {
    fn default() -> Self {
        Self {
            max_cpu_fraction: 0.25,
            max_rss_growth_kib: 128 * 1024,
            max_fd_growth: 16,
            max_thread_growth: 16,
            max_log_bytes: 256 * 1024,
        }
    }
}

/// Prints one `idle-baseline:` line for the window `a..b` and checks `gates`.
pub fn report(label: &str, files: usize, a: &Snapshot, b: &Snapshot, gates: &Gates) {
    let elapsed = b.at.duration_since(a.at).as_secs_f64();
    let cpu = (b.cpu - a.cpu) / elapsed;
    let log = b.log_bytes - a.log_bytes;
    let rchar = b.rchar.zip(a.rchar).map(|(x, y)| x - y);
    println!(
        "idle-baseline: variant={label} files={files} window_s={elapsed:.0} cpu_fraction={cpu:.4} \
         rss_kib={}->{} fds={}->{} threads={}->{} log_bytes={log} idle_rchar={rchar:?}",
        a.rss_kib, b.rss_kib, a.fds, b.fds, a.threads, b.threads
    );
    assert!(cpu < gates.max_cpu_fraction, "{label}: idle CPU {cpu:.3} cores: busy loop?");
    assert!(
        b.rss_kib.saturating_sub(a.rss_kib) < gates.max_rss_growth_kib,
        "{label}: RSS grew {}->{} KiB",
        a.rss_kib,
        b.rss_kib
    );
    assert!(b.fds <= a.fds + gates.max_fd_growth, "{label}: fds grew {}->{}", a.fds, b.fds);
    assert!(
        b.threads <= a.threads + gates.max_thread_growth,
        "{label}: threads grew {}->{}",
        a.threads,
        b.threads
    );
    assert!(log < gates.max_log_bytes, "{label}: {log} log bytes while idle");
}
