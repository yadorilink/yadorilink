//! A process killed in the middle of a capability probe strands the probe's artefacts in the
//! sync root; the next owner's sweep removes them and nothing else.
//!
//! The child creates what a probe creates (a probe-named file, and a probe-named scratch
//! directory with content inside, one at the root and one in a subdirectory), reports ready
//! and then waits to be killed with SIGKILL, so no cleanup of its own can run.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use yadorilink_fs_platform::fs_capabilities::{probe_artefact_name, sweep_probe_artefacts};
use yadorilink_fs_platform::reserved_namespace::{
    artefact_component_name, is_reserved_component, ArtefactKind,
};

const DIR_ENV: &str = "YADORILINK_TEST_PROBE_RESIDUE_DIR";
const TEST: &str = "a_writer_killed_mid_probe_leaves_no_probe_residue_after_the_sweep";

fn run_child(root: &Path) {
    std::fs::create_dir_all(root.join("sub")).unwrap();
    for dir in [root.to_path_buf(), root.join("sub")] {
        let file = dir.join(probe_artefact_name("durable").unwrap());
        std::fs::write(&file, b"probe").unwrap();
        let scratch = dir.join(probe_artefact_name("nfc").unwrap());
        std::fs::create_dir(&scratch).unwrap();
        std::fs::write(scratch.join("nfc-probe-\u{e9}"), b"x").unwrap();
    }
    let mut out = std::io::stdout();
    writeln!(out, "ready").unwrap();
    out.flush().unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn residue(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            if is_reserved_component(&entry.file_name()) {
                found.push(entry.path());
            } else if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            }
        }
    }
    found.sort();
    found
}

#[test]
fn a_writer_killed_mid_probe_leaves_no_probe_residue_after_the_sweep() {
    if let Ok(dir) = std::env::var(DIR_ENV) {
        run_child(Path::new(&dir));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Content that is not residue and must survive the sweep.
    std::fs::write(root.join("report.txt"), b"user").unwrap();
    let stage = root.join(artefact_component_name(ArtefactKind::Stage, "keep").unwrap());
    std::fs::write(&stage, b"stage").unwrap();

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([TEST, "--exact", "--nocapture"])
        .env(DIR_ENV, root)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawning the probing child");
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line.starts_with("ready") {
            break;
        }
        assert!(!line.is_empty() && Instant::now() < deadline, "child never became ready");
    }
    child.kill().expect("kill -9 the child");
    child.wait().unwrap();

    let before = residue(root);
    assert_eq!(
        before.len(),
        5,
        "the kill stranded the probe artefacts (and the stage file): {before:?}"
    );

    let sweep = sweep_probe_artefacts(root);
    assert!(sweep.failed.is_empty(), "{:?}", sweep.failed);
    assert_eq!(sweep.removed.len(), 4, "{:?}", sweep.removed);

    assert_eq!(residue(root), vec![stage.clone()], "only the non-probe artefact remains");
    assert_eq!(std::fs::read(root.join("report.txt")).unwrap(), b"user");
    assert!(root.join("sub").is_dir());
    assert!(sweep_probe_artefacts(root).removed.is_empty(), "a second sweep finds nothing");
}
