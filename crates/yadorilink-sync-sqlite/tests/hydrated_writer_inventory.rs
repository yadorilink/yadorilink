//! Every production line that stamps `MaterializationState::Present`,
//! pinned by name.
//!
//! `Present` says only that a local object stands at the path; whether that
//! object IS the row's version is the business of the actual-state
//! generation, and a stamp that claims exactness is only meaningful with a
//! usable generation naming the same version in the same durable commit. Producers were brought to that one at a time -- peer hydration,
//! daemon hydration, both repair lanes, the eager batch, restore, local
//! capture -- and each was a real defect before it was fixed. What none of
//! that prevents is the next writer: `set_materialization_state` is a
//! perfectly ordinary repository method, and stamping the claim with it is
//! a one-line change that no type rejects and no existing test notices.
//!
//! So the set is enumerated here instead. A new production stamp fails
//! this test with the file and line it was added at, and the fix is either
//! to publish the proof alongside it -- through
//! `commit_internal_materialized_state_if_fence_current` for a writer that
//! performed its own write, or the local-capture adoption path for one
//! that observed someone else's -- or, if it genuinely belongs, to add it
//! here with the reason.
//!
//! Tests and fixtures are deliberately out of scope: seeding a row into a
//! state is how a test sets up the situation it is about, and forbidding
//! that would only push fixtures into writing the column by hand.

use std::path::{Path, PathBuf};

/// One sanctioned production stamp: the file it lives in, and why it is
/// allowed to make the claim.
struct Sanctioned {
    file: &'static str,
    why: &'static str,
}

const SANCTIONED: &[Sanctioned] = &[
    Sanctioned {
        file: "crates/yadorilink-sync-sqlite/src/exact_materialized_commit.rs",
        why: "the internal-mutator commit itself -- it stamps only on the line after its own \
              CAS-published proof, inside the caller's transaction, and publishes nothing at \
              all when the CAS or the row guard fails",
    },
    Sanctioned {
        file: "crates/yadorilink-daemon/src/replica_coordinator/materialization_owner/lanes.rs",
        why: "records a version whose content is not fetched over an object that already \
              stands at the path (`Present` says only that an object exists, never that it \
              equals the version): it publishes no proof and claims none",
    },
    Sanctioned {
        file: "crates/yadorilink-daemon/src/local_convergence/materialize/eager.rs",
        why: "the reconstruct-failed arm puts a row back to what the path still holds (an \
              older object stays `Present`, an empty path is `Remote`): it publishes no \
              proof and claims none",
    },
    Sanctioned {
        file: "crates/yadorilink-sync-sqlite/src/restore_operation.rs",
        why: "restore's recovery lane, in the same transaction as the adoption that published \
              its proof; the live lane goes through the internal commit above instead",
    },
];

/// What this guard cannot see, recorded so the gap is not mistaken for
/// coverage.
///
/// `upsert_file_in_tx` copies `materialization_state` forward from the row
/// it supersedes, so a writer can leave a path reading `Present` without
/// containing the word anywhere -- the symlink lane did exactly that, and
/// no grep over setter calls would ever have found it. That shape is
/// covered by tests against the writers themselves, not from here.
///
/// A guard that quietly covers less than it appears to is worse than one
/// that says where it stops.
const CARRY_FORWARD_IS_NOT_VISIBLE_HERE: &str = "crates/yadorilink-sync-sqlite/src/file_index.rs";

/// `stamp_hydrated_after_local_emission_in_tx` writes the column with raw
/// SQL rather than through the repository method, so the scan below would
/// not see it. It is not an exception: it is the local-capture lane's own
/// named stamp, called only from inside the branches that publish an exact
/// proof in the same transaction, and every one of its call sites is in
/// the file that owns those branches.
const RAW_SQL_STAMP: &str = "crates/yadorilink-sync-sqlite/src/file_index.rs";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn production_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                // `src` only: a crate's own `tests/` directory is
                // integration-test code, which this scan does not cover.
                if name == "target" || name == "tests" || name == "benches" {
                    continue;
                }
                stack.push(path);
            } else if name.ends_with(".rs")
                && !name.contains("test_support")
                && path.components().any(|c| c.as_os_str() == "src")
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Drops a trailing line comment so brace counting ignores commented
/// braces. Approximate in the same safe direction as the sibling guard
/// this is modelled on: over-counting a brace only ever skips MORE lines
/// as test code, never fewer.
fn code_only(line: &str) -> &str {
    match line.find("//") {
        Some(at) => &line[..at],
        None => line,
    }
}

/// Every PRODUCTION line of a file, as `(1-based line number, line)`.
///
/// Skips the body of each `#[cfg(test)]`-attributed item -- a braced
/// module or a single gated statement -- and then KEEPS SCANNING.
///
/// The first version of this guard truncated at the first `#[cfg(test)]`
/// instead, and that is not a small difference. `peer_session.rs` has an
/// inline test module about 700 lines in and roughly 13,000 lines of
/// production code after it, so the guard read 4% of the file it most
/// needed to read and reported success. It missed a real production
/// `Present` stamp sitting at line ~15,000.
///
/// `.github/checks/check-mutation-boundary.py` had already been bitten by
/// exactly this and says so in its own docstring. This is that algorithm,
/// ported rather than re-invented.
fn production_lines(source: &str) -> Vec<(usize, &str)> {
    let raw: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < raw.len() {
        if raw[index].trim() == "#[cfg(test)]" {
            index += 1;
            while index < raw.len() && raw[index].trim_start().starts_with("#[") {
                index += 1;
            }
            let mut depth: i64 = 0;
            let mut opened = false;
            while index < raw.len() {
                let code = code_only(raw[index]);
                depth += code.matches('{').count() as i64 - code.matches('}').count() as i64;
                if code.contains('{') {
                    opened = true;
                }
                index += 1;
                if opened {
                    if depth <= 0 {
                        break;
                    }
                } else if code.trim_end().ends_with(';') {
                    break;
                }
            }
            continue;
        }
        out.push((index + 1, raw[index]));
        index += 1;
    }
    out
}

/// The file that declares the module a source file implements, with the
/// module's name: `a/b.rs` and `a/b/mod.rs` are both `mod b;` in `a.rs`,
/// `a/mod.rs`, or -- directly under `src` -- `lib.rs` / `main.rs`.
fn declaring_parent(path: &Path) -> Option<(Vec<PathBuf>, String)> {
    let file_stem = path.file_stem()?.to_str()?;
    if matches!(file_stem, "lib" | "main") && path.parent()?.file_name()? == "src" {
        return None;
    }
    let (module_dir, name) = if file_stem == "mod" {
        let dir = path.parent()?;
        (dir.parent()?, dir.file_name()?.to_str()?.to_owned())
    } else {
        (path.parent()?, file_stem.to_owned())
    };
    let candidates = if module_dir.file_name()? == "src" {
        vec![module_dir.join("lib.rs"), module_dir.join("main.rs")]
    } else {
        let dir_name = module_dir.file_name()?.to_str()?;
        vec![module_dir.with_file_name(format!("{dir_name}.rs")), module_dir.join("mod.rs")]
    };
    Some((candidates, name))
}

/// Whether `line` is a file-module declaration `mod <name>;`, with any
/// visibility in front.
fn declares_module(line: &str, name: &str) -> bool {
    let code = code_only(line).trim();
    let code = match code.strip_prefix("pub") {
        Some(rest) => match rest.trim_start().strip_prefix('(') {
            Some(scoped) => scoped.split_once(')').map_or(rest, |(_, after)| after),
            None => rest,
        },
        None => code,
    };
    code.trim_start() == format!("mod {name};")
}

/// A module FILE is test code when its parent declares it only under
/// `#[cfg(test)]` (`#[cfg(test)] mod tests;` in `hydration.rs` makes
/// `hydration/tests.rs` test code) or when the parent is itself test code.
/// The attribute sits on the declaration in the parent, so the scanned file
/// has no marker of its own and `production_lines` alone would read every
/// line of it as production.
///
/// Fails toward scanning: a file is skipped only when its declaration is
/// found in the parent and none of the parent's production lines carries
/// it. A shape this does not recognise (`#[path]`, a macro-made module)
/// stays in the scan.
fn is_test_only_module_file(path: &Path) -> bool {
    let Some((candidates, name)) = declaring_parent(path) else { return false };
    for parent in candidates {
        let Ok(source) = std::fs::read_to_string(&parent) else { continue };
        if !source.lines().any(|line| declares_module(line, &name)) {
            continue;
        }
        let in_production =
            production_lines(&source).iter().any(|(_, line)| declares_module(line, &name));
        return !in_production || is_test_only_module_file(&parent);
    }
    false
}

/// Every production call to a materialization-state setter that passes
/// `Present`, as `(repo-relative file, 1-based line)`.
/// The setters that can put a row into a state. `transition_*` is
/// included because it takes the target state as an argument like the
/// plain setter does, so a stamp can hide there just as easily.
const SETTERS: &[&str] = &["set_materialization_state", "transition_materialization_state"];

/// Every production call to a materialization-state setter that passes
/// `Present`, as `(repo-relative file, 1-based line)`.
fn hydrated_stamps(root: &Path) -> Vec<(String, usize)> {
    let mut found = Vec::new();
    for path in production_sources(root) {
        if is_test_only_module_file(&path) {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&path) else { continue };
        let lines = production_lines(&source);
        for (position, (line_number, line)) in lines.iter().enumerate() {
            if !SETTERS.iter().any(|setter| line.contains(setter)) {
                continue;
            }
            // The arguments may wrap; a setter call is short, so a small
            // window covers every shape here without swallowing the next
            // statement.
            let window_end = (position + 8).min(lines.len());
            let window: String = lines[position..window_end]
                .iter()
                .map(|(_, text)| *text)
                .collect::<Vec<_>>()
                .join("\n");
            let call_end = window.find(");").map_or(window.len(), |at| at + 2);
            if window[..call_end].contains("MaterializationState::Present") {
                let relative = path
                    .strip_prefix(root)
                    .expect("scanned under the workspace root")
                    .to_string_lossy()
                    .replace('\\', "/");
                found.push((relative, *line_number));
            }
        }
    }
    found
}

#[test]
fn no_production_writer_stamps_hydrated_outside_the_sanctioned_set() {
    let root = workspace_root();
    let found = hydrated_stamps(&root);

    let unsanctioned: Vec<&(String, usize)> =
        found.iter().filter(|(file, _)| !SANCTIONED.iter().any(|s| s.file == file)).collect();

    assert!(
        unsanctioned.is_empty(),
        "these production writers stamp Hydrated without being part of the sanctioned set:\n{}\n\n\
         Present is an exact claim about disk only alongside the proof that earns it, \
         published in the SAME durable commit. A writer that performed its own write \
         belongs on commit_internal_materialized_state_if_fence_current; one that observed a \
         write someone else performed belongs on the local-capture adoption path. If this stamp \
         genuinely belongs, add its file to SANCTIONED with the reason.",
        unsanctioned
            .iter()
            .map(|(file, line)| format!("  {file}:{line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // The other direction: a sanctioned entry whose stamp is gone is an
    // allowlist that has outlived the thing it allows, and a stale
    // allowlist silently re-permits whatever is added back to that file.
    for entry in SANCTIONED {
        assert!(
            found.iter().any(|(file, _)| file == entry.file),
            "{} is sanctioned to stamp Hydrated ({}) but no longer does; remove the entry \
             rather than leaving the file pre-approved",
            entry.file,
            entry.why
        );
    }
}

/// The scan reads the repository, so it is worth proving it can see
/// anything at all: a typo in the traversal would otherwise make the test
/// above pass by finding nothing.
#[test]
fn the_scan_finds_the_stamps_it_is_supposed_to_find() {
    let root = workspace_root();
    let found = hydrated_stamps(&root);
    assert!(
        found.len() >= SANCTIONED.len(),
        "the scan found {} stamps, fewer than the {} sanctioned files -- it is not reading the \
         sources it thinks it is",
        found.len(),
        SANCTIONED.len()
    );
    assert!(
        root.join(RAW_SQL_STAMP).exists(),
        "{RAW_SQL_STAMP} holds the local-capture lane's own raw-SQL stamp; if it moved, this \
         scan's coverage argument moved with it"
    );
    assert!(
        root.join(CARRY_FORWARD_IS_NOT_VISIBLE_HERE).exists(),
        "{CARRY_FORWARD_IS_NOT_VISIBLE_HERE} is where the carry-forward this scan cannot see \
         lives; if it moved, so did the limit of what this guard covers"
    );
}

/// A module file declared `#[cfg(test)] mod tests;` in its parent is test
/// code even though nothing in the file says so; its production-declared
/// parent, and a module declared without the attribute, are not.
#[test]
fn a_module_file_declared_under_cfg_test_is_not_scanned_as_production() {
    let root = workspace_root();
    let daemon = root.join("crates/yadorilink-daemon/src");
    assert!(is_test_only_module_file(&daemon.join("hydration/tests.rs")));
    assert!(is_test_only_module_file(&daemon.join("gc/tests.rs")));
    assert!(!is_test_only_module_file(&daemon.join("hydration.rs")));
    assert!(!is_test_only_module_file(&daemon.join("lib.rs")));
    assert!(declares_module("pub(crate) mod tests;", "tests"));
    assert!(declares_module("mod tests; // inline note", "tests"));
    assert!(!declares_module("mod tests_more;", "tests"));
}
