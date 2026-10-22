//! The fidelity-lint
//! backstop.
//!
//! Each `dst_*.rs` scenario migrates independently to the shared
//! `dst_support` helpers (small, reviewable diffs). Once a file is
//! migrated, it must not regress to a per-scenario fork of the very thing
//! the migration removed -- a local `stamp_deterministic_mtime`, a fixed
//! settle sleep, or an `outbound_partitioned` boolean. This lint greps the
//! *migrated* files (only) for those banned patterns and fails if any
//! reappears: a blunt
//! textual check that only guards files whose migration flag is set and
//! only bans a pattern that has a designated shared replacement.
//!
//! A false positive is a one-line allowlist: put
//! `// fidelity-lint: allow <pattern>` on the same line, with a
//! justification.
//!
//! Not gated on the simulation cfg: it reads source text off disk, so it
//! runs in the ordinary `cargo test` legs (and harmlessly under the turmoil
//! build too).

use std::path::PathBuf;

/// The scenario files whose migration to the shared helpers has landed.
/// A file is added here in the same PR that migrates it. Empty until the
/// first scenario migrates: the
/// lint is a ratchet, guarding only what has been cleaned up so a
/// half-migrated tree is never falsely failed.
const MIGRATED_FILES: &[&str] = &[
    // Added as each migration lands.
    // `dst_intermittent_catchup_chaos.rs` was listed here for its
    // partition->FaultPlan swap and self-healing sweep hook, with an approved
    // exception for its fine-grained per-op mtime `stamp` fork. It was deleted
    // along with the legacy mtime index-convergence engine: every mutation it
    // published crossed the wire via `PeerSyncSession::send_index_update`, which
    // went with that engine, so the file could not compile, let alone run. Its
    // properties were re-homed rather than dropped -- see the accounting in
    // `dst_dag_catchup_chaos.rs`'s module doc. Nothing to guard, so no entry
    // here; the `stamp` exception died with the file.
];

/// A banned pattern plus the shared replacement a reviewer should reach for
/// instead -- the lint only bans a fork that has somewhere else to go.
struct Banned {
    pattern: &'static str,
    replacement: &'static str,
}

const BANNED: &[Banned] = &[
    Banned {
        pattern: "fn stamp_deterministic_mtime",
        replacement:
            "dst_support::fs_ops write/rename wrappers (stamp via the shared HarnessClock)",
    },
    Banned {
        pattern: "outbound_partitioned",
        replacement: "a dst_support network FaultPlan / FaultingChannel window",
    },
    Banned {
        pattern: "FINAL_SETTLE",
        replacement: "dst_support::settle (poll-on-check_convergence with a budget)",
    },
];

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Returns every `(line_number, line)` in `source` that contains
/// `pattern` and is NOT allow-listed on that same line.
fn offending_lines<'a>(source: &'a str, pattern: &str) -> Vec<(usize, &'a str)> {
    let allow_marker = format!("fidelity-lint: allow {pattern}");
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(pattern) && !line.contains(&allow_marker))
        .map(|(i, line)| (i + 1, line))
        .collect()
}

#[test]
fn migrated_scenarios_do_not_reintroduce_banned_patterns() {
    let dir = tests_dir();
    let mut failures = Vec::new();

    for file in MIGRATED_FILES {
        let path = dir.join(file);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("migrated file {file} is not readable: {e}"));
        for banned in BANNED {
            for (line_no, line) in offending_lines(&source, banned.pattern) {
                failures.push(format!(
                    "{file}:{line_no}: migrated scenario still contains banned pattern \
                     `{}` -- use {} instead (or allow-list this line with a justification: \
                     `// fidelity-lint: allow {}`)\n    {}",
                    banned.pattern,
                    banned.replacement,
                    banned.pattern,
                    line.trim()
                ));
            }
        }
    }

    assert!(failures.is_empty(), "fidelity-lint violations:\n{}", failures.join("\n"));
}

#[cfg(test)]
mod self_tests {
    use super::*;

    // The lint itself must actually catch a banned pattern and must respect
    // the allow-list -- proven here on synthetic sources so the ratchet is
    // not silently a no-op while MIGRATED_FILES is still empty.

    #[test]
    fn detects_a_banned_pattern() {
        let source = "let x = 1;\nfn stamp_deterministic_mtime(p: &Path) {}\n";
        let hits = offending_lines(source, "fn stamp_deterministic_mtime");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 2);
    }

    #[test]
    fn respects_an_allow_list_comment() {
        let source =
            "fn stamp_deterministic_mtime() {} // fidelity-lint: allow fn stamp_deterministic_mtime -- legacy shim, tracked\n";
        let hits = offending_lines(source, "fn stamp_deterministic_mtime");
        assert!(hits.is_empty());
    }

    #[test]
    fn clean_source_has_no_hits() {
        let source = "use dst_support::fs_ops;\nfs_ops::write(&clock, &p, b\"x\").unwrap();\n";
        for banned in BANNED {
            assert!(offending_lines(source, banned.pattern).is_empty());
        }
    }
}
