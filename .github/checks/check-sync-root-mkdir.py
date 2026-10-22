#!/usr/bin/env python3
"""Pin every production directory creation, so none inside a sync root
bypasses the structural-origin helper.

A directory the materializer creates only to hold a descendant is a
structural container: derived state that is never captured as an explicit
directory, and that goes away once nothing below it is live. The filesystem
does not say which directories those are, so the materializer records each
one it creates, around the `mkdir` itself (an intent before, the observed
identity after). That record exists only if every directory created inside
a sync root is created through
`yadorilink_local_storage::create_dir_all_never_through_a_symlink` (or
`create_explicit_directory`, which uses it for the ancestors of a
replicated directory). A single plain `create_dir_all` under a sync root
makes a directory nobody recorded, which local capture would then read as a
user's `mkdir` and replicate as an explicit directory that never goes away.

This guard scans production code (the scanner, and what counts as test
code, are those of `check-materialization-semantic-boundary.py`) for
`create_dir(`, `create_dir_all(` and `DirBuilder::new(`, and requires each
file's count per call to equal its pin in `ALLOWLIST`. Every pin outside
`materialize_write.rs` creates a directory outside any sync root (config,
state, sockets, the block store, the send inbox), or the sync root itself;
the comment on each says which. A new site fails until it is reviewed and
pinned here; a site inside a sync root must use the helper instead.

Run with no arguments to check the tree, `--list` to print every counted
site, and `--self-test` to exercise the check against synthetic fixtures.
"""

from __future__ import annotations

import argparse
import importlib.util
from collections import Counter
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "materialization_semantic_boundary",
    Path(__file__).resolve().parent / "check-materialization-semantic-boundary.py",
)
_boundary = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_boundary)

MKDIR = _boundary.call_pattern(("create_dir", "create_dir_all", "DirBuilder::new"))

C = "crates/"
ALLOWLIST: dict[str, dict[str, int]] = {
    # The helper itself: one `create_dir` per structural directory, bracketed
    # by the ledger; one for an explicit (replicated) directory, whose
    # ancestors go through the helper; and the sync root itself, which is
    # not inside any root.
    C + "yadorilink-local-storage/src/materialize_write.rs": {
        "create_dir": 2,
        "create_dir_all": 1,
    },
    # The block store's own directories (`create_dir_all_durably`: the store
    # root and its `segments/` directory, never inside a sync root).
    C + "yadorilink-local-storage/src/fs_ops.rs": {"create_dir_all": 2},
    # The case-sensitivity probe: the root itself, and a probe directory in
    # the root's reserved namespace, removed again at once.
    C + "yadorilink-peer-session/src/hazard.rs": {"create_dir": 1, "create_dir_all": 2},
    # Config, state, socket, update and report directories.
    C + "yadorilink-cli/src/commands/diagnose.rs": {"create_dir_all": 1},
    C + "yadorilink-client-core/src/facade/settings.rs": {"create_dir_all": 1},
    C + "yadorilink-daemon/src/control_socket.rs": {"create_dir_all": 1},
    C + "yadorilink-daemon/src/governance_config.rs": {"create_dir_all": 1},
    C + "yadorilink-daemon/src/peer_orchestrator.rs": {"create_dir_all": 1},
    C + "yadorilink-daemon/src/shell_ipc.rs": {"create_dir_all": 1},
    C + "yadorilink-daemon/src/space_management_config.rs": {"create_dir_all": 1},
    C + "yadorilink-daemon/src/update/policy.rs": {"create_dir_all": 1},
    C + "yadorilink-http-api/src/token.rs": {"create_dir_all": 2},
    # Reporting queue/candidate/metrics state is best-effort telemetry (plain writes);
    # every creation of the reporting/ parent itself (consent, counters) is durable.
    C + "yadorilink-reporting/src/metrics_config.rs": {"create_dir_all": 1},
    # The send inbox and its received files' directories: not a sync root.
    C + "yadorilink-send/src/session.rs": {"create_dir_all": 4},
    # Provider/native-recovery private state and the durability probe's scratch
    # directory: app-owned directories (0700), not content inside a sync root.
    C + "yadorilink-daemon/src/provider_handoff.rs": {"DirBuilder::new": 1, "create_dir_all": 1},
    # The Windows host's Stage ledger directory: the host's own state directory beside the
    # root's authoring state, never inside the user's tree.
    C + "yadorilink-windows-provider-policy/src/stage_ledger.rs": {"create_dir_all": 3},
    # The Windows uninstall guardian's helper directory in the temporary directory: outside the
    # package, any sync root and the user's data.
    C + "yadorilink-shell-ext-windows/src/package_removal.rs": {"create_dir_all": 1},
    C + "yadorilink-daemon/src/provider_writer.rs": {"DirBuilder::new": 1},
    # The daemon's own log directory (default ~/Library/Logs/yadorilink, 0700; the
    # parent of an operator-set YADORILINK_LOG_FILE otherwise): the daemon's private
    # log location, never a sync root or a path the product replicates. An operator
    # who points the override into a sync root puts the log file itself there too.
    C + "yadorilink-daemon/src/log_roll.rs": {"DirBuilder::new": 1},
    # `DurableNamespace`: the Stage-directory mkdir, the methods named after it
    # and the probe's own scratch directory.
    C + "yadorilink-fs-platform/src/durable_dir.rs": {"create_dir": 2, "create_dir_all": 2},
    C + "yadorilink-fs-platform/src/durable_dir/probe.rs": {"create_dir": 2},
    C + "yadorilink-sync-sqlite/src/native_rebootstrap_recovery.rs": {"DirBuilder::new": 3, "create_dir_all": 1},
}


def evaluate(hits: list[tuple[str, int, str, str]], allowlist: dict[str, dict[str, int]]) -> list[str]:
    errors: list[str] = []
    found: Counter[tuple[str, str]] = Counter()
    where: dict[tuple[str, str], list[int]] = {}
    for rel, number, _, api in hits:
        if api not in allowlist.get(rel, {}):
            errors.append(
                f"{rel}:{number}: `{api}` is not pinned for this file; inside a sync "
                "root, create directories through "
                "`yadorilink_local_storage::create_dir_all_never_through_a_symlink`"
            )
            continue
        found[(rel, api)] += 1
        where.setdefault((rel, api), []).append(number)
    for rel, apis in sorted(allowlist.items()):
        for api, pinned in sorted(apis.items()):
            count = found[(rel, api)]
            if count != pinned:
                lines = ", ".join(str(n) for n in where.get((rel, api), [])) or "none"
                errors.append(f"{rel}: `{api}` pinned at {pinned}, found {count} (lines: {lines})")
    return errors


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "crates/demo/src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text(
            "fn place(p: &Path) {\n"
            "    std::fs::create_dir_all(p).unwrap();\n"
            "    // std::fs::create_dir(p) in a comment is not a call\n"
            "}\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn t(p: &Path) { std::fs::create_dir(p).unwrap(); }\n"
            "}\n",
            encoding="utf-8",
        )
        hits = _boundary.scan(root, MKDIR)
        assert [(h[0], h[3]) for h in hits] == [("crates/demo/src/lib.rs", "create_dir_all")], hits
        assert evaluate(hits, {}) and "not pinned" in evaluate(hits, {})[0]
        assert evaluate(hits, {"crates/demo/src/lib.rs": {"create_dir_all": 1}}) == []
        stale = evaluate(hits, {"crates/demo/src/lib.rs": {"create_dir_all": 2}})
        assert stale and "pinned at 2, found 1" in stale[0], stale
        (src / "lib.rs").write_text("fn f() { DirBuilder::new().recursive(true); }\n", encoding="utf-8")
        hits = _boundary.scan(root, MKDIR)
        assert [h[3] for h in hits] == ["DirBuilder::new"], hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list", action="store_true", help="print every counted site")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("sync-root mkdir guard self-test passed")
        return 0
    hits = _boundary.scan(ROOT, MKDIR)
    if args.list:
        for rel, number, enclosing, api in hits:
            print(f"{rel}:{number}\t{enclosing}\t{api}")
        return 0
    errors = evaluate(hits, ALLOWLIST)
    if errors:
        print("directory creation must stay on the reviewed, pinned sites:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    total = sum(sum(apis.values()) for apis in ALLOWLIST.values())
    print(f"sync-root mkdir guard: ok ({total} pinned directory creations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
