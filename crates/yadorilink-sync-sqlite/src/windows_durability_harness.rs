//! Crash-test workload and verifier for the directory-entry durability
//! primitives.
//!
//! The workload calls the recovery area's own durable primitives
//! (`write_durable`, `ensure_private_dir_durably`, `sync_dir`) in a loop and
//! reports every operation to a collector over TCP once the primitive has
//! returned: that report is the claim "this is durable". The machine running
//! the workload is then killed without warning. After it restarts, the verifier
//! fetches the claims the collector received before the kill and checks that
//! every claimed name exists with the claimed content and that every claimed
//! removal stayed removed. The logic here is plain `std` and runs on every
//! platform, so it is unit-tested off Windows; only the ignored tests at the
//! bottom, which are driven from outside, are Windows-only.
//!
//! Wire format, one line per message (names are hex-ish, so no spaces):
//! `ack <cycle> <seq> <op> <path> <arg>`, where `op` is `file` (`arg` = sha256
//! of the content), `dir`, `rm`, `order` or `orderrm` (see [`Op`]; `arg` = `-`
//! unless stated).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::native_rebootstrap_recovery::{
    create_dirs_durably, ensure_private_dir_durably, write_durable,
};

/// The directory flush the primitive experiments measure; no product code path
/// relies on it any more.
fn sync_dir(dir: &Path) -> Result<(), crate::native_rebootstrap_recovery::AreaError> {
    yadorilink_fs_platform::durable_dir::durable_flush_directory(dir).map_err(Into::into)
}

/// Which flushes the workload performs. `Full` is the product behaviour; the
/// others deliberately leave primitives out so the experiment can show that it
/// is able to detect a loss (negative controls) or probe an ordering
/// assumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Product primitives: durable file writes, mkdir and remove with a parent flush.
    Full,
    /// No write-through rename, no directory flush.
    N1,
    /// Write-through rename only.
    A1,
    /// Plain rename and directory flush only.
    A2,
    /// Directory creation with a directory flush only.
    A3,
    /// An unflushed create `X`, then a write-through publish of `Y` in the same directory.
    OrderSame,
    /// As [`Mode::OrderSame`], with `X` in a different directory.
    OrderOther,
    /// An unflushed remove of `R`, then a write-through publish of `Y`.
    OrderRemove,
}

impl Mode {
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "full" => Self::Full,
            "n1" => Self::N1,
            "a1" => Self::A1,
            "a2" => Self::A2,
            "a3" => Self::A3,
            "order-same" => Self::OrderSame,
            "order-other" => Self::OrderOther,
            "order-remove" => Self::OrderRemove,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::N1 => "n1",
            Self::A1 => "a1",
            Self::A2 => "a2",
            Self::A3 => "a3",
            Self::OrderSame => "order-same",
            Self::OrderOther => "order-other",
            Self::OrderRemove => "order-remove",
        }
    }

    fn write_through(self) -> bool {
        matches!(
            self,
            Self::Full | Self::A1 | Self::OrderSame | Self::OrderOther | Self::OrderRemove
        )
    }

    fn flushes_directories(self) -> bool {
        matches!(self, Self::Full | Self::A2 | Self::A3)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// `path` was published with the sha256 in `arg`.
    File,
    /// `path` is a directory.
    Dir,
    /// `path` was removed and must stay removed.
    Remove,
    /// `path` is about to be removed; sent before the removal starts and kept by
    /// the collector whatever the kill cutoff, so a removal that lands after the
    /// kill is not mistaken for a lost file. `path` is unconstrained afterwards
    /// unless a later `rm` claims it.
    RemoveIntent,
    /// `path` (X) was created without a flush before `arg` (Y) was published
    /// with write-through: if Y is present, X must be too.
    Order,
    /// `path` (R) was removed without a flush before `arg` (Y) was published
    /// with write-through: if Y is present, R must be gone.
    OrderRemove,
    /// A rebootstrap reached the failpoint named `path`; `arg` is the hex of
    /// the old state's roots, which must be intact if the barrier was not reached.
    Failpoint,
}

impl Op {
    fn word(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Remove => "rm",
            Self::RemoveIntent => "rmintent",
            Self::Order => "order",
            Self::OrderRemove => "orderrm",
            Self::Failpoint => "fp",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        [
            Self::File,
            Self::Dir,
            Self::Remove,
            Self::RemoveIntent,
            Self::Order,
            Self::OrderRemove,
            Self::Failpoint,
        ]
        .into_iter()
        .find(|op| op.word() == word)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub seq: u64,
    pub op: Op,
    pub path: String,
    pub arg: String,
}

impl Claim {
    pub fn to_line(&self, cycle: &str) -> String {
        format!("ack {cycle} {} {} {} {}", self.seq, self.op.word(), self.path, self.arg)
    }

    /// `(cycle, claim)` of an `ack` line, or `None` for anything else.
    pub fn parse(line: &str) -> Option<(String, Claim)> {
        let mut parts = line.split_whitespace();
        if parts.next()? != "ack" {
            return None;
        }
        let cycle = parts.next()?.to_string();
        let seq = parts.next()?.parse().ok()?;
        let op = Op::parse(parts.next()?)?;
        let path = parts.next()?.to_string();
        let arg = parts.next()?.to_string();
        if parts.next().is_some() {
            return None;
        }
        Some((cycle, Claim { seq, op, path, arg }))
    }
}

/// Content derived from the name alone, so the verifier needs no copy of it:
/// `sha256(name)` repeated to a size between 4 KiB and 1 MiB.
pub fn content_for(name: &str) -> Vec<u8> {
    let digest = Sha256::digest(name.as_bytes());
    let span = (1 << 20) - 4096;
    let size =
        4096 + (u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]) as usize) % span;
    digest.iter().copied().cycle().take(size).collect()
}

fn sha_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

type Emit<'a> = dyn FnMut(&Claim) -> io::Result<()> + 'a;

pub struct Workload {
    root: PathBuf,
    mode: Mode,
    rng: Rng,
    seq: u64,
    /// Directories relative to `root` (the root itself is `""`), with their depth.
    dirs: Vec<(String, usize)>,
    live_files: Vec<String>,
}

fn io_err(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn rename_write_through(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        yadorilink_fs_platform::durable_dir::rename_no_replace_durable(from, to)
    }
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
}

impl Workload {
    /// `root` must exist and be empty of foreign entries.
    pub fn new(root: &Path, mode: Mode, seed: u64) -> Self {
        Self {
            root: root.to_path_buf(),
            mode,
            rng: Rng(seed | 1),
            seq: 0,
            dirs: vec![(String::new(), 0)],
            live_files: Vec::new(),
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn pick_dir(&mut self, max_depth: usize) -> (String, usize) {
        let candidates: Vec<_> =
            self.dirs.iter().filter(|(_, d)| *d <= max_depth).cloned().collect();
        candidates[self.rng.below(candidates.len())].clone()
    }

    /// Publishes `bytes` as `dir/name` the way this mode's primitive set allows.
    fn publish(&self, dir: &Path, name: &str, bytes: &[u8], write_through: bool) -> io::Result<()> {
        if self.mode == Mode::Full {
            return write_durable(dir, name, bytes).map_err(io_err);
        }
        let temp = dir.join(format!(".tmp-{name}"));
        let mut file = fs::File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        let target = dir.join(name);
        if write_through {
            rename_write_through(&temp, &target)?;
        } else {
            fs::rename(&temp, &target)?;
        }
        if self.mode.flushes_directories() {
            sync_dir(dir).map_err(io_err)?;
        }
        Ok(())
    }

    fn make_dir(&mut self, parent: &(String, usize)) -> io::Result<Claim> {
        let seq = self.next_seq();
        let rel = join(&parent.0, &format!("d{seq}"));
        let path = self.root.join(&rel);
        if self.mode == Mode::Full {
            ensure_private_dir_durably(&path).map_err(io_err)?;
        } else {
            fs::create_dir(&path)?;
            if self.mode.flushes_directories() {
                sync_dir(&self.root.join(&parent.0)).map_err(io_err)?;
            }
        }
        self.dirs.push((rel.clone(), parent.1 + 1));
        Ok(Claim { seq, op: Op::Dir, path: rel, arg: "-".into() })
    }

    fn make_file(&mut self, parent: &(String, usize), prefix: &str) -> io::Result<Claim> {
        let seq = self.next_seq();
        let name = format!("{prefix}{seq}");
        let bytes = content_for(&name);
        self.publish(&self.root.join(&parent.0), &name, &bytes, self.mode.write_through())?;
        Ok(Claim { seq, op: Op::File, path: join(&parent.0, &name), arg: sha_hex(&bytes) })
    }

    fn remove_live_file(&mut self, emit: &mut Emit) -> io::Result<Option<Claim>> {
        if self.live_files.is_empty() {
            return Ok(None);
        }
        let rel = self.live_files.swap_remove(self.rng.below(self.live_files.len()));
        let intent_seq = self.next_seq();
        emit(&Claim { seq: intent_seq, op: Op::RemoveIntent, path: rel.clone(), arg: "-".into() })?;
        let seq = self.next_seq();
        let path = self.root.join(&rel);
        fs::remove_file(&path)?;
        if self.mode.flushes_directories() {
            sync_dir(path.parent().unwrap_or(&self.root)).map_err(io_err)?;
        }
        Ok(Some(Claim { seq, op: Op::Remove, path: rel, arg: "-".into() }))
    }

    /// Performs one operation and returns the claims it earned, each only after
    /// the primitive behind it returned.
    pub fn step(&mut self, emit: &mut Emit) -> io::Result<Vec<Claim>> {
        match self.mode {
            Mode::A3 => {
                let parent = self.pick_dir(2);
                Ok(vec![self.make_dir(&parent)?])
            }
            Mode::OrderSame | Mode::OrderOther => self.order_step(),
            Mode::OrderRemove => self.order_remove_step(),
            _ => {
                let roll = self.rng.below(4);
                if roll == 0 {
                    let parent = self.pick_dir(2);
                    return Ok(vec![self.make_dir(&parent)?]);
                }
                if roll == 1 {
                    if let Some(claim) = self.remove_live_file(emit)? {
                        return Ok(vec![claim]);
                    }
                }
                let parent = self.pick_dir(3);
                let claim = self.make_file(&parent, "f")?;
                self.live_files.push(claim.path.clone());
                Ok(vec![claim])
            }
        }
    }

    fn order_step(&mut self) -> io::Result<Vec<Claim>> {
        if self.mode == Mode::OrderOther && self.dirs.len() < 3 {
            let root = (String::new(), 0);
            return Ok(vec![self.make_dir(&root)?]);
        }
        let y_dir = self.pick_dir(1);
        let x_dir = if self.mode == Mode::OrderSame {
            y_dir.clone()
        } else {
            loop {
                let candidate = self.pick_dir(1);
                if candidate.0 != y_dir.0 {
                    break candidate;
                }
            }
        };
        let x_seq = self.next_seq();
        let x = join(&x_dir.0, &format!("x{x_seq}"));
        // No sync, no flush: this entry is only as durable as ordering makes it.
        fs::write(self.root.join(&x), b"x")?;
        let y = self.make_file(&y_dir, "y")?;
        let order = Claim { seq: y.seq + 1, op: Op::Order, path: x, arg: y.path.clone() };
        self.seq += 1;
        Ok(vec![y, order])
    }

    fn order_remove_step(&mut self) -> io::Result<Vec<Claim>> {
        let root = (String::new(), 0);
        let r_seq = self.next_seq();
        let r_name = format!("r{r_seq}");
        write_durable(&self.root, &r_name, b"r").map_err(io_err)?;
        fs::remove_file(self.root.join(&r_name))?;
        let y = self.make_file(&root, "y")?;
        let order =
            Claim { seq: y.seq + 1, op: Op::OrderRemove, path: r_name, arg: y.path.clone() };
        self.seq += 1;
        Ok(vec![y, order])
    }
}

/// Runs the workload until `max_ops` operations are done (or forever for
/// `None`), handing every claim to `emit` as soon as its primitive returned.
pub fn run(
    root: &Path,
    mode: Mode,
    seed: u64,
    max_ops: Option<u64>,
    emit: &mut Emit,
) -> io::Result<()> {
    // Not part of the measurement: the cycle directory itself must survive.
    create_dirs_durably(root).map_err(io_err)?;
    let mut workload = Workload::new(root, mode, seed);
    let mut ops = 0;
    while max_ops.is_none_or(|max| ops < max) {
        for claim in workload.step(emit)? {
            emit(&claim)?;
        }
        ops += 1;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Violation {
    pub seq: u64,
    pub path: String,
    pub kind: &'static str,
}

#[derive(Debug, Default)]
pub struct Report {
    pub claims: usize,
    pub violations: Vec<Violation>,
}

enum Expect {
    File(String),
    Dir,
    Absent,
    Unconstrained,
}

/// Checks what is on disk under `root` against `claims`.
pub fn verify(root: &Path, claims: &[Claim]) -> Report {
    let mut ordered: Vec<&Claim> = claims.iter().collect();
    ordered.sort_by_key(|claim| claim.seq);
    let mut expected: BTreeMap<&str, (u64, Expect)> = BTreeMap::new();
    let mut violations = Vec::new();
    let mut violation = |claim: &Claim, kind| {
        violations.push(Violation { seq: claim.seq, path: claim.path.clone(), kind })
    };
    for claim in &ordered {
        match claim.op {
            Op::File => {
                expected.insert(&claim.path, (claim.seq, Expect::File(claim.arg.clone())));
            }
            Op::Dir => {
                expected.insert(&claim.path, (claim.seq, Expect::Dir));
            }
            Op::Remove => {
                expected.insert(&claim.path, (claim.seq, Expect::Absent));
            }
            Op::RemoveIntent => {
                expected.insert(&claim.path, (claim.seq, Expect::Unconstrained));
            }
            Op::Order | Op::OrderRemove | Op::Failpoint => {}
        }
    }
    let by_seq: BTreeMap<u64, &Claim> = ordered.iter().map(|c| (c.seq, *c)).collect();
    for (path, (seq, want)) in &expected {
        let claim = by_seq[seq];
        let full = root.join(path);
        match want {
            Expect::File(sha) => match fs::read(&full) {
                Ok(bytes) if &sha_hex(&bytes) == sha => {}
                Ok(_) => violation(claim, "hash_mismatch"),
                Err(_) => violation(claim, "missing"),
            },
            Expect::Dir => {
                if !full.is_dir() {
                    violation(claim, "missing_dir");
                }
            }
            Expect::Unconstrained => {}
            Expect::Absent => {
                if fs::symlink_metadata(&full).is_ok() {
                    violation(claim, "resurrected");
                }
            }
        }
    }
    for claim in &ordered {
        let published = root.join(&claim.arg);
        let present = |p: &Path| fs::symlink_metadata(p).is_ok();
        match claim.op {
            Op::Order if present(&published) && !present(&root.join(&claim.path)) => {
                violation(claim, "order_x_lost")
            }
            Op::OrderRemove if present(&published) && present(&root.join(&claim.path)) => {
                violation(claim, "order_remove_lost")
            }
            _ => {}
        }
    }
    Report { claims: claims.len(), violations }
}

impl Report {
    pub fn to_json(&self, cycle: &str, mode: &str) -> String {
        let violations: Vec<_> = self
            .violations
            .iter()
            .map(|v| serde_json::json!({"seq": v.seq, "path": v.path, "kind": v.kind}))
            .collect();
        serde_json::json!({
            "event": "verdict",
            "cycle": cycle,
            "mode": mode,
            "claims": self.claims,
            "violations": violations,
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_collecting(mode: Mode, ops: u64) -> (tempfile::TempDir, Vec<Claim>) {
        let dir = tempfile::tempdir().unwrap();
        let mut claims = Vec::new();
        run(dir.path(), mode, 7, Some(ops), &mut |claim| {
            claims.push(claim.clone());
            Ok(())
        })
        .unwrap();
        (dir, claims)
    }

    #[test]
    fn every_mode_verifies_clean_when_nothing_is_lost() {
        for mode in [
            Mode::Full,
            Mode::N1,
            Mode::A1,
            Mode::A2,
            Mode::A3,
            Mode::OrderSame,
            Mode::OrderOther,
            Mode::OrderRemove,
        ] {
            let (dir, claims) = run_collecting(mode, 40);
            assert!(!claims.is_empty(), "{mode:?}");
            let report = verify(dir.path(), &claims);
            assert_eq!(report.violations, vec![], "{mode:?}");
        }
    }

    #[test]
    fn a_lost_file_a_changed_file_a_lost_dir_and_a_resurrected_name_are_detected() {
        let (dir, claims) = run_collecting(Mode::Full, 80);
        let kinds = |claims: &[Claim]| -> Vec<&'static str> {
            verify(dir.path(), claims).violations.iter().map(|v| v.kind).collect()
        };
        let file = claims
            .iter()
            .find(|c| {
                c.op == Op::File && !claims.iter().any(|r| r.op == Op::Remove && r.path == c.path)
            })
            .unwrap();
        let path = dir.path().join(&file.path);
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"torn").unwrap();
        assert_eq!(kinds(&claims), vec!["hash_mismatch"]);
        fs::remove_file(&path).unwrap();
        assert_eq!(kinds(&claims), vec!["missing"]);
        fs::write(&path, original).unwrap();
        assert!(kinds(&claims).is_empty());

        let removed = claims.iter().find(|c| c.op == Op::Remove).unwrap();
        fs::write(dir.path().join(&removed.path), b"back").unwrap();
        assert_eq!(kinds(&claims), vec!["resurrected"]);
        fs::remove_file(dir.path().join(&removed.path)).unwrap();

        let made = claims
            .iter()
            .rev()
            .find(|c| {
                c.op == Op::Dir
                    && !claims.iter().any(|o| o.path.starts_with(&format!("{}/", c.path)))
            })
            .unwrap();
        fs::remove_dir(dir.path().join(&made.path)).unwrap();
        assert_eq!(kinds(&claims), vec!["missing_dir"]);
    }

    #[test]
    fn a_lost_unflushed_create_behind_a_published_name_is_an_ordering_violation() {
        let (dir, claims) = run_collecting(Mode::OrderSame, 10);
        assert!(verify(dir.path(), &claims).violations.is_empty());
        let order = claims.iter().find(|c| c.op == Op::Order).unwrap();
        fs::remove_file(dir.path().join(&order.path)).unwrap();
        let report = verify(dir.path(), &claims);
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].kind, "order_x_lost");
    }

    #[test]
    fn a_remove_that_did_not_persist_behind_a_published_name_is_detected() {
        let (dir, claims) = run_collecting(Mode::OrderRemove, 5);
        assert!(verify(dir.path(), &claims).violations.is_empty());
        let order = claims.iter().find(|c| c.op == Op::OrderRemove).unwrap();
        fs::write(dir.path().join(&order.path), b"r").unwrap();
        assert_eq!(verify(dir.path(), &claims).violations[0].kind, "order_remove_lost");
    }

    #[test]
    fn an_unclaimed_tail_is_not_checked() {
        let (dir, claims) = run_collecting(Mode::Full, 30);
        // Everything after the cutoff is unclaimed, except removal intents, which
        // the collector always passes on.
        let cut = claims.len() / 2;
        let kept: Vec<Claim> = claims
            .iter()
            .enumerate()
            .filter(|(i, c)| *i < cut || c.op == Op::RemoveIntent)
            .map(|(_, c)| c.clone())
            .collect();
        let late = claims[cut..].iter().rev().find(|c| c.op == Op::File).unwrap();
        fs::remove_file(dir.path().join(&late.path)).unwrap();
        assert!(verify(dir.path(), &kept).violations.is_empty());
    }

    #[test]
    fn claims_round_trip_through_the_wire_format() {
        let claim = Claim { seq: 9, op: Op::File, path: "d3/f9".into(), arg: "ab".into() };
        assert_eq!(Claim::parse(&claim.to_line("c1")), Some(("c1".into(), claim)));
        assert_eq!(Claim::parse("hello c1 full"), None);
        assert_eq!(Claim::parse("ack c1 1 file p"), None);
    }

    #[test]
    fn a_verdict_names_the_cycle_the_mode_and_each_violation() {
        for mode in ["full", "n1", "a1", "a2", "a3", "order-same", "order-other", "order-remove"] {
            assert_eq!(Mode::parse(mode).unwrap().name(), mode);
        }
        assert!(Mode::parse("other").is_none());
        let dir = tempfile::tempdir().unwrap();
        let claim = Claim { seq: 1, op: Op::File, path: "f1".into(), arg: "00".into() };
        let report = verify(dir.path(), &[claim]);
        let verdict: serde_json::Value =
            serde_json::from_str(&report.to_json("c9", Mode::N1.name())).unwrap();
        assert_eq!(verdict["cycle"], "c9");
        assert_eq!(verdict["mode"], "n1");
        assert_eq!(verdict["claims"], 1);
        assert_eq!(verdict["violations"][0]["kind"], "missing");
    }

    #[test]
    fn content_is_deterministic_and_bounded() {
        assert_eq!(content_for("f1"), content_for("f1"));
        assert_ne!(content_for("f1"), content_for("f2"));
        for name in ["a", "b", "f1000"] {
            let len = content_for(name).len();
            assert!((4096..=1 << 20).contains(&len));
        }
    }
}

/// The collector connection shared by the Windows entry points.
#[cfg(all(test, windows))]
pub(crate) mod net {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::path::PathBuf;

    use super::Claim;

    pub fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
    }

    pub struct Session {
        pub cycle: String,
        pub mode: String,
        pub root: PathBuf,
        pub stream: TcpStream,
    }

    pub fn session() -> Session {
        let cycle = env("YADORILINK_CRASH_CYCLE");
        let root = PathBuf::from(env("YADORILINK_CRASH_ROOT")).join(format!("c{cycle}"));
        let stream = TcpStream::connect(env("YADORILINK_CRASH_COLLECTOR")).expect("collector");
        stream.set_nodelay(true).unwrap();
        // The collector refuses a connection that does not open with the run's token.
        let mut stream = stream;
        writeln!(stream, "auth {}", env("YADORILINK_CRASH_TOKEN")).unwrap();
        Session { cycle, mode: env("YADORILINK_CRASH_MODE"), root, stream }
    }

    /// The claims the collector accepted for this cycle.
    pub fn fetch_claims(s: &mut Session) -> Vec<Claim> {
        writeln!(s.stream, "claims {}", s.cycle).unwrap();
        let mut claims = Vec::new();
        for line in BufReader::new(s.stream.try_clone().unwrap()).lines() {
            let line = line.unwrap();
            if line == "end" {
                break;
            }
            claims.push(Claim::parse(&line).unwrap_or_else(|| panic!("bad claim line: {line}")).1);
        }
        claims
    }

    /// Prints the verdict and reports it to the collector.
    pub fn send_verdict(s: &mut Session, verdict: &str) {
        println!("{verdict}");
        writeln!(s.stream, "verdict {} {}", s.cycle, verdict).unwrap();
        let mut reply = String::new();
        BufReader::new(s.stream.try_clone().unwrap()).read_line(&mut reply).unwrap();
        assert_eq!(reply.trim(), "ok");
    }
}

/// Windows-only entry points, started and stopped from outside (see the
/// maintainer Windows crash driver). They are `#[ignore]`d so a normal test
/// run never starts a workload that waits to be killed.
#[cfg(all(test, windows))]
mod windows_entry {
    use super::net::{fetch_claims, send_verdict, session};
    use super::*;

    /// Runs the workload until the machine is killed, claiming each operation
    /// to the collector once it returned.
    #[test]
    #[ignore = "driven by the maintainer Windows crash driver; runs until the machine is killed"]
    fn windows_durability_soak() {
        let mut s = session();
        let mode = Mode::parse(&s.mode).expect("unknown YADORILINK_CRASH_MODE");
        let seed = std::env::var("YADORILINK_CRASH_SEED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0x9E37_79B9);
        writeln!(s.stream, "hello {} {}", s.cycle, s.mode).unwrap();
        let cycle = s.cycle.clone();
        let mut stream = s.stream.try_clone().unwrap();
        run(&s.root, mode, seed, None, &mut |claim| writeln!(stream, "{}", claim.to_line(&cycle)))
            .unwrap();
    }

    /// Checks the directory against the claims the collector accepted before the
    /// kill; reports the verdict back and fails on any violation.
    #[test]
    #[ignore = "driven by the maintainer Windows crash driver after the machine restarted"]
    fn windows_durability_verify() {
        let mut s = session();
        let claims = fetch_claims(&mut s);
        let report = verify(&s.root, &claims);
        let verdict = report.to_json(&s.cycle, &s.mode);
        send_verdict(&mut s, &verdict);
        assert!(report.violations.is_empty(), "{} violations", report.violations.len());
    }
}
