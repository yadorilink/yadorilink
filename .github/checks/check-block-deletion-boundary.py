#!/usr/bin/env python3
"""Fail when production sync code physically deletes blocks outside the gate.

Physical block deletion has exactly two owners, and both take a
`&BlockPhysicalDeletionGuard` -- the exclusive side of `BlockLivenessGate`,
which proves no reference write (a materialization or hydration that could
still need the block) is in flight:

  * `sweep_globally_unreferenced_blocks` (filesystem-sync `block_deletion.rs`)
    for the grace-period sweep of blocks no row references; and
  * `ReplicaCoordinator::reclaim_cached_blocks` (daemon
    `replica_coordinator/block_reclamation.rs`) for custody-verified eviction,
    which also re-checks the custody's exact version, the pin and
    materialization state, the custody confirmation and the cross-row
    reference set under that guard before freeing anything.

Everything else must reach deletion through one of them. This guard fails on
a `.sweep(` or `.reclaim_cached_blocks(` call anywhere else unless the call
passes a deletion guard as its first argument (i.e. it is a call INTO one of
the gated owners, not a call on the raw `BlockReclamationStore`), and on a
direct `.delete(` in a file that handles a block store.
"""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = [
    ROOT / "crates/yadorilink-daemon/src",
    ROOT / "crates/yadorilink-filesystem-sync/src",
    ROOT / "crates/yadorilink-sync-sqlite/src",
]
# The gated owners. Each must still take the deletion guard, or it is no
# longer an owner this guard can vouch for.
OWNERS = {
    ROOT / "crates/yadorilink-filesystem-sync/src/block_deletion.rs": "sweep_globally_unreferenced_blocks",
    ROOT / "crates/yadorilink-daemon/src/replica_coordinator/block_reclamation.rs": "reclaim_cached_blocks",
}
FORWARDING_ADAPTER = ROOT / "crates/yadorilink-daemon/src/adapters/block_store_ports.rs"
DELETION_METHODS = (".sweep(", ".reclaim_cached_blocks(")
# `.reclaim_cached_blocks(deletion_guard, ...)` / `(&guard, ...)`: a call into
# a gated owner. The raw store method takes a hash slice, never a guard.
GUARDED_CALL = re.compile(r"\.(?:sweep|reclaim_cached_blocks)\(\s*&?\s*\w*guard\b")
TEST_MODULE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*(\{|;)")


def production_lines(path: Path) -> list[tuple[int, str]]:
    """Return (line number, text) for the file's non-test lines.

    Only top-level `#[cfg(test)] mod ...` items are dropped. An indented
    `#[cfg(test)]` on a statement, field or helper inside production code
    does not end production code; treating it as if it did used to hide
    everything after it from this guard.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    # A file that opens with the inner attribute is a test module living in
    # its own file: its parent declares it `#[cfg(test)] mod x;`, which a
    # per-file scanner cannot see. None of it is production.
    if lines and lines[0].strip() == "#![cfg(test)]":
        return []
    out: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == "#[cfg(test)]":
            nxt = index + 1
            while nxt < len(lines) and lines[nxt].startswith("#["):
                nxt += 1
            match = TEST_MODULE.match(lines[nxt]) if nxt < len(lines) else None
            if match and match.group(1) == ";":
                index = nxt + 1
                continue
            if match:
                depth = 0
                end = nxt
                while end < len(lines):
                    depth += lines[end].count("{") - lines[end].count("}")
                    if depth <= 0 and "{" in "".join(lines[nxt : end + 1]):
                        break
                    end += 1
                index = end + 1
                continue
        out.append((index + 1, line))
        index += 1
    return out


def main() -> int:
    violations: list[str] = []

    adapter = "\n".join(text for _, text in production_lines(FORWARDING_ADAPTER))
    for method in DELETION_METHODS:
        count = adapter.count(method)
        if count != 1:
            violations.append(
                f"{FORWARDING_ADAPTER.relative_to(ROOT)}: expected exactly one {method[:-1]} "
                f"capability forwarding call, found {count}"
            )

    for owner, function in OWNERS.items():
        text = owner.read_text(encoding="utf-8") if owner.is_file() else ""
        signature = re.search(
            rf"fn\s+{function}\s*\([^)]*?&BlockPhysicalDeletionGuard<'_>", text, re.S
        )
        if not signature:
            violations.append(
                f"{owner.relative_to(ROOT)}: expected `fn {function}` taking "
                "`&BlockPhysicalDeletionGuard<'_>`; update OWNERS if deletion moved"
            )

    for source_root in SOURCE_ROOTS:
        for path in sorted(source_root.rglob("*.rs")):
            if (
                path in OWNERS
                or path == FORWARDING_ADAPTER
                or any(part.startswith("reporting") for part in path.parts)
            ):
                continue
            lines = production_lines(path)
            block_store_context = any(
                token in text for _, text in lines for token in ("BlockStore", "BlockReclamationStore")
            )
            for line_number, line in lines:
                if line.lstrip().startswith("//"):
                    continue
                if block_store_context and ".delete(" in line:
                    violations.append(f"{path.relative_to(ROOT)}:{line_number}: direct delete")
                if any(method in line for method in DELETION_METHODS) and not GUARDED_CALL.search(line):
                    violations.append(
                        f"{path.relative_to(ROOT)}:{line_number}: physical deletion call "
                        "outside the gated owners"
                    )

    if violations:
        print(
            "physical block deletion must go through a BlockPhysicalDeletionGuard-gated owner",
            file=sys.stderr,
        )
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        return 1
    print("block deletion boundary: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
