#!/usr/bin/env python3
"""Report-only wall-clock comparison for the receive scenario.

The operation-count guard (docs/PERF_GUARD.md) cannot see a slowdown that keeps the counts.
This compares one run of the frozen scenario with the median of the previous runs and prints a
report. It never fails on a slowdown: the exit status is non-zero only for unusable input.

A result file is JSON in one of two shapes (extra fields are ignored):
  {"seconds": x}                       a bare run, comparable with other bare runs
  {"wall_s": x, "host": ..., "tier": ..., "knobs": {...}, "passed": true}
                                       a harness result (results/receive_lane/*.result.json)
A harness run is only compared with runs of the same host, tier and knobs, so a laptop result is
never compared with a GPU box and a tuning experiment is never compared with the default run. A
harness run that did not pass is rejected. History is a directory of *.result.json files; the
newest N comparable runs by file name are used (the current file is left out), so name them
sortably (for example 2026-10-23.result.json). The scenario itself is not run here.

Usage:
  compare-receive-wallclock.py --current RESULT.json --history DIR [--last 8] [--tolerance 0.30]
  compare-receive-wallclock.py --self-test
"""
import argparse
import json
import os
import pathlib
import statistics
import sys
import tempfile

REFERENCE_SECONDS = 53.7  # frozen scenario, informational only
MIN_HISTORY = 3  # fewer runs than this: no verdict


def read_run(path):
    """Return (seconds, comparison key) for one result file."""
    try:
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        if "wall_s" in data:
            value = data["wall_s"]
            if data.get("passed") is not True:
                raise ValueError("run did not pass")
            key = (data["host"], data["tier"], json.dumps(data.get("knobs", {}), sort_keys=True))
        else:
            value, key = data["seconds"], None
    except (OSError, ValueError, KeyError, TypeError) as err:
        raise ValueError(f"{path}: unusable result file ({err})")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not value > 0:
        raise ValueError(f"{path}: seconds must be a positive number")
    return float(value), key


def history_seconds(directory, last, key, exclude=None):
    files = sorted(pathlib.Path(directory).glob("*.result.json"))
    if exclude is not None:
        files = [f for f in files if f.resolve() != pathlib.Path(exclude).resolve()]
    runs = []
    skipped = 0
    for f in files:
        try:
            runs.append(read_run(f))
        except ValueError:
            skipped += 1  # a failed or unusable old run must not block reporting on this one
    return [s for s, k in runs if k == key][-last:], skipped


def report(current, history, tolerance, key=None, skipped=0):
    lines = [
        "Receive scenario wall clock (report only)",
        f"  current: {current:.1f} s (frozen reference about {REFERENCE_SECONDS} s)",
        *([f"  comparing only runs of: {' / '.join(key[:2])}, knobs {key[2]}"] if key else []),
    ]
    if skipped:
        lines.append(f"  skipped {skipped} failed or unusable history file(s)")
    if len(history) < MIN_HISTORY:
        lines.append(f"  history: {len(history)} run(s), need {MIN_HISTORY}: no verdict yet")
        return "\n".join(lines)
    median = statistics.median(history)
    ratio = current / median
    lines.append(f"  median of last {len(history)} runs: {median:.1f} s")
    lines.append(f"  ratio: {ratio:.2f} (tolerance +{tolerance:.0%})")
    if ratio > 1 + tolerance:
        lines.append("  SLOWER than the tolerance allows (not a failure: report only)")
    elif ratio < 1 - tolerance:
        lines.append("  much faster than the median: check the run is the full scenario")
    else:
        lines.append("  within tolerance")
    return "\n".join(lines)


def harness(wall, host="gpu", tier="small", knobs=None, passed=True):
    return {"wall_s": wall, "host": host, "tier": tier, "knobs": knobs or {}, "passed": passed}


def hs(*args, **kwargs):
    return history_seconds(*args, **kwargs)[0]


def self_test():
    with tempfile.TemporaryDirectory() as d:
        hist = pathlib.Path(d, "h")
        hist.mkdir()
        for i, s in enumerate([53.0, 54.0, 55.0, 53.5]):
            hist.joinpath(f"2026-01-0{i + 1}.result.json").write_text(json.dumps({"seconds": s}), encoding="utf-8")
        h = hs(hist, 8, None)
        assert len(h) == 4
        assert "within tolerance" in report(54.0, h, 0.3)
        assert "SLOWER" in report(80.0, h, 0.3)
        assert "faster" in report(20.0, h, 0.3)
        assert "no verdict" in report(54.0, h[:2], 0.3)
        assert len(hs(hist, 2, None)) == 2
        bad = pathlib.Path(d, "bad.json")
        for text in ("not json", '{"seconds": 0}', '{"seconds": true}', "{}", "[]",
                     json.dumps(harness(50.0, passed=False)),
                     json.dumps({"wall_s": 50.0, "passed": True})):
            bad.write_text(text, encoding="utf-8")
            try:
                read_run(bad)
            except ValueError:
                continue
            raise AssertionError(f"accepted {text!r}")

        # Harness results: only the same host, tier and knobs are compared.
        runs = pathlib.Path(d, "r")
        runs.mkdir()
        rows = [("a", harness(50.0)), ("b", harness(51.0)), ("c", harness(52.0)),
                ("d", harness(500.0, host="laptop")), ("e", harness(9.0, tier="medium")),
                ("f", harness(5.0, knobs={"W": 8})), ("g", {"seconds": 1.0})]
        for name, row in rows:
            runs.joinpath(f"2026-02-01T00-{name}.result.json").write_text(json.dumps(row), encoding="utf-8")
        runs.joinpath("2026-02-01T00-a.timeline.json").write_text("[]", encoding="utf-8")
        cur = pathlib.Path(runs, "2026-02-02T00-cur.result.json")
        cur.write_text(json.dumps(harness(51.0)), encoding="utf-8")
        sec, key = read_run(cur)
        assert key == ("gpu", "small", "{}")
        assert hs(runs, 8, key, exclude=cur) == [50.0, 51.0, 52.0]
        assert hs(runs, 8, key) == [50.0, 51.0, 52.0, 51.0]
        assert hs(runs, 8, key, exclude=cur)[-2:] == [51.0, 52.0]
        assert hs(runs, 8, ("laptop", "small", "{}")) == [500.0]
        assert hs(runs, 8, None) == [1.0]
        # A failed old run on another host is skipped and counted, not fatal.
        runs.joinpath("2026-01-01T00-failed.result.json").write_text(
            json.dumps(harness(1.0, host="other", passed=False)), encoding="utf-8")
        runs.joinpath("2026-01-01T00-junk.result.json").write_text("not json", encoding="utf-8")
        found, skipped = history_seconds(runs, 8, key, exclude=cur)
        assert found == [50.0, 51.0, 52.0] and skipped == 2
        assert "skipped 2" in report(sec, found, 0.3, key, skipped)
        # A failed current run is still rejected.
        failed = pathlib.Path(runs, "2026-02-03T00-cur.result.json")
        failed.write_text(json.dumps(harness(51.0, passed=False)), encoding="utf-8")
        try:
            read_run(failed)
            raise AssertionError("accepted failed current run")
        except ValueError:
            pass
        assert "gpu / small" in report(sec, [50.0, 51.0, 52.0], 0.3, key)
    print("self-test ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--current")
    ap.add_argument("--history")
    ap.add_argument("--last", type=int, default=8)
    ap.add_argument("--tolerance", type=float, default=0.30)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.current or not args.history or args.last < 1 or args.tolerance <= 0:
        ap.error("--current and --history are required; --last >= 1; --tolerance > 0")
    try:
        seconds, key = read_run(args.current)
        history, skipped = history_seconds(args.history, args.last, key, exclude=args.current)
        text = report(seconds, history, args.tolerance, key, skipped)
    except ValueError as err:
        print(err, file=sys.stderr)
        return 2
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
