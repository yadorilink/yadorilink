#!/usr/bin/env python3
"""Installer test matrix: every cell on a clean container, one result file.

  python3 packaging/install/tests/matrix.py fixture --bin-dir DIR [--out FILE] [--cells ...]
  python3 packaging/install/tests/matrix.py live [--installer-url URL] [--version X.Y.Z] [--out FILE]

`fixture` runs acceptance.sh (the real programs against a LOCAL fixture release signed with a
test key) as an unprivileged user in each Linux image; DIR holds `yadorilink` and
`yadorilink-daemon` built by build-test-bins.sh. `live` runs live-acceptance.sh, the one-liner
against the real published release, on clean images: the cells with python3 also run the data
check cases; the `minimal` cell has only curl, unzip and a shell (what a user has). Alpine is a
refusal cell in both modes: the installer must stop with status 5 before changing anything.

Needs docker (or CONTAINER_RUNTIME) and python3 on the machine that runs it. Each cell is a fresh
container, removed afterwards. The result file (JSON) records, per cell: image, libc, passed,
failed, skipped, exit status, seconds and the tail of the log, plus the revision and the mode, so
it can be kept as release evidence. Exit status 0 only if every cell passed.
"""
import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
INSTALL_DIR = os.path.dirname(HERE)
RUNTIME = os.environ.get("CONTAINER_RUNTIME", "docker")

DEBIAN_SETUP = (
    "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null 2>&1; "
    "apt-get install -y -qq --no-install-recommends curl unzip ca-certificates {extra} >/dev/null 2>&1; "
    "useradd -m tester; "
    '. /etc/os-release; echo "image: $PRETTY_NAME, glibc $(ldd --version | head -1 | sed "s/.* //")"; '
)

# name -> (image, extra packages, kind)
LIVE_CELLS = {
    "ubuntu-22.04": ("ubuntu:22.04", "python3", "debian"),
    "ubuntu-24.04": ("ubuntu:24.04", "python3", "debian"),
    "debian-12": ("debian:12", "python3", "debian"),
    "minimal": ("debian:12-slim", "", "debian"),
    "alpine": ("alpine:3.20", "", "alpine"),
}
FIXTURE_CELLS = {
    "ubuntu-22.04": ("ubuntu:22.04", "", "debian"),
    "ubuntu-24.04": ("ubuntu:24.04", "", "debian"),
    "debian-12": ("debian:12", "", "debian"),
    "alpine": ("alpine:3.20", "", "alpine"),
}


def run(argv, timeout):
    """Run a `docker run ...` command line; on timeout the named container is removed too (killing
    the client leaves the container running on the daemon's side)."""
    name = f"yl-matrix-{os.getpid()}-{int(time.time())}"
    argv = [argv[0], argv[1], "--name", name, *argv[2:]]
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        out, rc = p.stdout + p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        rc = 124
    return rc, out, round(time.monotonic() - t0, 1)


def parse(out):
    m = re.findall(r"passed: (\d+), failed: (\d+)(?:, skipped: (\d+))?", out)
    if not m:
        return None, None, None
    p, f, s = m[-1]
    return int(p), int(f), int(s or 0)


def alpine_refusal(mode, args):
    """The installer must refuse an unsupported platform (status 5) and change nothing."""
    inner = (
        "apk add --no-cache curl unzip >/dev/null 2>&1; adduser -D tester; "
        'echo "image: $(. /etc/os-release; echo $PRETTY_NAME), musl"; '
        "su tester -c 'sh /install.sh --prefix $HOME/p --yes; echo status=$?; ls -d $HOME/p 2>&1' 2>&1"
    )
    if platform.machine() not in ("x86_64", "AMD64"):
        # The refusal is about the x86_64 Linux bundle; on another host the installer stops
        # earlier for another reason (unsupported CPU), which says nothing about musl.
        return {"passed": 0, "failed": 0, "skipped": 1, "exit": 0, "seconds": 0, "libc": "musl",
                "log_tail": f"skipped: host is {platform.machine()}, the check needs an x86_64 container"}
    installer = os.path.join(INSTALL_DIR, "install.sh")
    rc, out, secs = run([RUNTIME, "run", "--rm", "-v", f"{installer}:/install.sh:ro", "alpine:3.20", "sh", "-c", inner], 600)
    # Refused with status 5 before anything is downloaded, whatever the network does.
    ok = "status=5" in out and "no glibc dynamic loader" in out and "No such file" in out
    return {"passed": 1 if ok else 0, "failed": 0 if ok else 1, "skipped": 0, "exit": 0 if ok else 1,
            "seconds": secs, "log_tail": out[-600:], "libc": "musl"}


def debian_cell(mode, image, extra, args):
    setup = DEBIAN_SETUP.format(extra=extra)
    if mode == "fixture":
        mounts = ["-v", f"{INSTALL_DIR}:/src:ro", "-v", f"{os.path.abspath(args.bin_dir)}:/bins:ro"]
        extra_py = "python3 perl"
        setup = DEBIAN_SETUP.format(extra=extra_py)
        cmd = setup + 'exec su tester -c "cd /home/tester && sh /src/tests/acceptance.sh --bin-dir /bins"'
    else:
        mounts = ["-v", f"{os.path.join(HERE, 'live-acceptance.sh')}:/live.sh:ro"]
        flags = ""
        if args.installer_url:
            flags += f" --installer-url {args.installer_url}"
        if args.version:
            flags += f" --version {args.version}"
        cmd = setup + f'exec su tester -c "sh /live.sh{flags}"'
    rc, out, secs = run([RUNTIME, "run", "--rm", *mounts, image, "sh", "-c", cmd], 3600)
    passed, failed, skipped = parse(out)
    libc = (re.search(r"glibc ([0-9.]+)", out) or [None, "?"])[1]
    return {"passed": passed, "failed": failed, "skipped": skipped, "exit": rc, "seconds": secs,
            "log_tail": out[-1200:], "libc": f"glibc {libc}"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["fixture", "live"])
    ap.add_argument("--bin-dir")
    ap.add_argument("--installer-url")
    ap.add_argument("--version")
    ap.add_argument("--cells", help="comma-separated cell names (default: all)")
    ap.add_argument("--out", default="install-matrix.json")
    args = ap.parse_args()
    if args.mode == "fixture" and not (args.bin_dir and os.path.isdir(args.bin_dir)):
        ap.error("fixture mode needs --bin-dir (see build-test-bins.sh)")
    cells = FIXTURE_CELLS if args.mode == "fixture" else LIVE_CELLS
    names = args.cells.split(",") if args.cells else list(cells)
    unknown = [n for n in names if n not in cells]
    if unknown:
        ap.error(f"unknown cell(s) {', '.join(unknown)}; choose from {', '.join(cells)}")
    rev = subprocess.run(["git", "-C", INSTALL_DIR, "rev-parse", "--short=9", "HEAD"], capture_output=True, text=True, encoding="utf-8").stdout.strip()
    result = {"mode": args.mode, "revision": rev, "installer_url": args.installer_url or "https://yadori.link/install.sh",
              "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "cells": {}}
    for name in names:
        image, extra, kind = cells[name]
        print(f"== {name} ({image})", file=sys.stderr, flush=True)
        if kind == "alpine":
            cell = alpine_refusal(args.mode, args)
        else:
            cell = debian_cell(args.mode, image, extra, args)
        cell["image"] = image
        cell["ok"] = cell["exit"] == 0 and cell["failed"] == 0 and cell["passed"] is not None
        result["cells"][name] = cell
        print(f"   passed={cell['passed']} failed={cell['failed']} skipped={cell['skipped']} exit={cell['exit']} {cell['seconds']}s", file=sys.stderr, flush=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    bad = [n for n, c in result["cells"].items() if not c["ok"]]
    print(("all cells passed" if not bad else "FAILED cells: " + ", ".join(bad)) + f" -> {args.out}", file=sys.stderr)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
