#!/usr/bin/env python3
"""Guard for .github/checks/perf-baseline.json, the receive path's operation-count baseline.

The Rust tests that compare measured counts against the baseline are
`cargo test -p yadorilink-local-storage --test durability_op_counts` (fsync, directory
fsync, rename and block-store durability groups for a fixed workload) and the receive
cost guard in `yadorilink-daemon` (write transactions per received path, window size).

This script makes the baseline itself tamper-evident: every edit of a number must come
with a recorded reason.

Updating the baseline (only when a change is intended and reviewed):
  1. Edit the numbers in perf-baseline.json.
  2. Run `python3 .github/checks/check-perf-baseline.py --record "<why the counts changed>"`.
     It recomputes the digest, bumps `revision` and appends {revision, digest, why} to
     `changes`. A reason shorter than 20 characters is refused.
  3. Explain the change in the pull request description.
Without step 2 this check fails, so the numbers cannot move silently.

Usage:
  check-perf-baseline.py              verify
  check-perf-baseline.py --record WHY update revision/digest/changes after an edit
  check-perf-baseline.py --self-test  exercise the check on mutated copies
"""
import copy
import hashlib
import json
import pathlib
import sys
import tempfile

PATH = pathlib.Path(__file__).with_name("perf-baseline.json")
MIN_WHY = 20
META = ("revision", "digest", "changes")


def digest_of(doc):
    body = {k: v for k, v in doc.items() if k not in META}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def problems(doc):
    out = []
    if doc.get("schema") != 1:
        out.append("schema must be 1")
    for key in ("frozen_settings", "storage_workload", "write_transactions_per_received_path_max"):
        if key not in doc:
            out.append(f"missing {key}")
    changes = doc.get("changes", [])
    if doc.get("revision") != len(changes):
        out.append(f"revision {doc.get('revision')} does not equal the {len(changes)} recorded changes")
    for i, change in enumerate(changes, 1):
        if change.get("revision") != i:
            out.append(f"change {i} has revision {change.get('revision')}")
        if len(str(change.get("why", "")).strip()) < MIN_WHY:
            out.append(f"change {i} has no reason of at least {MIN_WHY} characters")
    if changes and changes[-1].get("digest") != doc.get("digest"):
        out.append("the last recorded change does not carry the stored digest")
    if not changes and doc.get("digest") not in ("", None):
        out.append("a digest without a recorded change")
    if changes and digest_of(doc) != doc.get("digest"):
        out.append(
            "the numbers differ from the last recorded change: record why with "
            "--record \"<reason>\" (see this script's header)"
        )
    return out


def record(doc, why):
    if len(why.strip()) < MIN_WHY:
        raise SystemExit(f"the reason must be at least {MIN_WHY} characters")
    doc["revision"] = len(doc["changes"]) + 1
    doc["digest"] = digest_of(doc)
    doc["changes"].append({"revision": doc["revision"], "digest": doc["digest"], "why": why.strip()})
    return doc


def self_test():
    base = record(json.load(open(PATH, encoding="utf-8")) if PATH.exists() else {}, "initial baseline recorded")
    assert not problems(base), problems(base)
    silent = copy.deepcopy(base)
    silent["write_transactions_per_received_path_max"] += 1
    assert any("differ" in p for p in problems(silent)), "a silent number edit must fail"
    reasonless = copy.deepcopy(base)
    reasonless["changes"][-1]["why"] = "x"
    assert problems(reasonless), "a change without a reason must fail"
    rev = copy.deepcopy(base)
    rev["revision"] += 1
    assert problems(rev), "a revision that skips must fail"
    tamper = copy.deepcopy(base)
    tamper["storage_workload"]["files"] += 1
    record(tamper, "workload size changed on purpose")
    assert not problems(tamper), problems(tamper)
    print("perf-baseline self-test ok")


def main(argv):
    if argv[1:2] == ["--self-test"]:
        return self_test()
    doc = json.load(open(PATH, encoding="utf-8"))
    if argv[1:2] == ["--record"]:
        if len(argv) != 3:
            raise SystemExit("usage: --record \"<why>\"")
        record(doc, argv[2])
        PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"recorded revision {doc['revision']}")
        return 0
    found = problems(doc)
    for p in found:
        print(f"perf-baseline: {p}", file=sys.stderr)
    if not doc.get("changes"):
        print("perf-baseline: no recorded revision yet", file=sys.stderr)
        return 1
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
