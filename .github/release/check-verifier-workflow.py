#!/usr/bin/env python3
"""Structural gates for the verifier release workflow.

Usage: check-verifier-workflow.py [--root DIR]
       check-verifier-workflow.py --self-test

The workflow publishes the program every installer trusts to check the manifest signature, so
its shape is checked, not just its output:
  * triggered only by a `verifier-<N>` tag push (no dispatch, no pull request);
  * workflow permissions are contents: read; every `uses:` is pinned to a full commit SHA; the
    Rust toolchain is an exact version, not a moving channel;
  * verifier-build is unprivileged: contents: read only, no environment, no secrets, no
    id-token or attestations, and it runs check-verifier-reproducible.py;
  * verifier-attest (needs verifier-build) is the only job with id-token/attestations, exactly
    contents: read, id-token: write, attestations: write; no environment, secrets, cargo,
    toolchain or build step; it re-verifies by hash and creates the attestation;
  * verifier-publish (needs both) has contents: write and no id-token/attestations; it runs
    `gh attestation verify` against this repository, this workflow, the commit and the ref
    before `gh release create`; no cargo, toolchain or build step.

--self-test mutates copies of the real workflow to bypass each gate and requires a failure for
every bypass.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATHS = ("oss-public/.github/workflows/verifier-release.yml", ".github/workflows/verifier-release.yml")
BUILD, ATTEST, PUBLISH = "verifier-build", "verifier-attest", "verifier-publish"
TAG_FILTER = "verifier-[0-9]*"
SHA_USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)@(\S+)", re.M)
FORBIDDEN_IN_PROTECTED = re.compile(r"cargo |rust-toolchain|build-verifier|check-verifier-reproducible|setup-python")
SECRET_RE = re.compile(r"\bsecrets\.|\bvars\.|^\s*environment\s*:", re.M)
IDENTITY_RE = re.compile(r"\b(id-token|attestations)\s*:")

_spec = importlib.util.spec_from_file_location("check_release_gates", Path(__file__).with_name("check-release-gates.py"))
_gates = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gates)
jobs, needs, code_only = _gates.jobs, _gates.needs, _gates.code_only


def permissions(job: str) -> dict[str, str] | None:
    m = re.search(r"^    permissions:\s*\n((?:      [a-z-]+:\s*\S+\n)+)", job, re.M)
    if not m:
        return None
    return dict(re.findall(r"^      ([a-z-]+):\s*(\S+)$", m.group(1), re.M))


def workflow_path(root: Path) -> Path:
    return next((root / p for p in WORKFLOW_PATHS if (root / p).is_file()), root / WORKFLOW_PATHS[0])


def problems_in(text: str) -> list[str]:
    out: list[str] = []
    code = code_only(text)
    head = code[: code.index("\njobs:\n")] if "\njobs:\n" in code else code
    if "\njobs:\n" not in code:
        return ["the workflow has no jobs"]

    on = re.search(r"^on:\s*\n((?:[ ]+.*\n|\n)+)", head + "\n", re.M)
    on_block = on.group(1) if on else ""
    if re.findall(r"^  ([a-z_]+):", on_block, re.M) != ["push"]:
        out.append("the workflow must be triggered by a tag push only")
    if f"'{TAG_FILTER}'" not in on_block:
        out.append(f"the tag filter must be exactly '{TAG_FILTER}'")
    top = re.search(r"^permissions:\s*\n((?:  [a-z-]+:\s*\S+\n)+)", head + "\n", re.M)
    if not top or dict(re.findall(r"^  ([a-z-]+):\s*(\S+)$", top.group(1), re.M)) != {"contents": "read"}:
        out.append("workflow permissions must be exactly contents: read")

    for name, ref in SHA_USES_RE.findall(code):
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            out.append(f"{name}@{ref} is not pinned to a full commit SHA")
    tc = re.search(r"VERIFIER_RUST_TOOLCHAIN:\s*\"?([^\"\s]+)\"?", head)
    if not tc or not re.fullmatch(r"\d+\.\d+\.\d+", tc.group(1)):
        out.append("VERIFIER_RUST_TOOLCHAIN must be an exact x.y.z version")

    all_jobs = jobs(code)
    for name in (BUILD, ATTEST, PUBLISH):
        job = all_jobs.get(name)
        if job is None:
            out.append(f"missing job {name}")
            continue
        if "startsWith(github.ref, 'refs/tags/verifier-')" not in job:
            out.append(f"{name} is not restricted to a verifier tag")
    if out and any(m.startswith("missing job") for m in out):
        return out
    build, attest, publish = (all_jobs[n] for n in (BUILD, ATTEST, PUBLISH))

    if permissions(build) != {"contents": "read"}:
        out.append(f"{BUILD} must have exactly contents: read")
    if SECRET_RE.search(build) or IDENTITY_RE.search(build):
        out.append(f"{BUILD} must have no environment, secrets, vars, id-token or attestations")
    if "check-verifier-reproducible.py" not in build:
        out.append(f"{BUILD} must run check-verifier-reproducible.py")

    if needs(attest) != {BUILD}:
        out.append(f"{ATTEST} must need exactly {BUILD}")
    if permissions(attest) != {"contents": "read", "id-token": "write", "attestations": "write"}:
        out.append(f"{ATTEST} must have exactly contents: read, id-token: write, attestations: write")
    if SECRET_RE.search(attest) or FORBIDDEN_IN_PROTECTED.search(attest):
        out.append(f"{ATTEST} must have no environment, secrets, vars, cargo, toolchain or build step")
    if "sha256sum --check" not in attest:
        out.append(f"{ATTEST} must re-verify the artifact by hash")
    if not re.search(r"uses: actions/attest-build-provenance@[0-9a-f]{40}\b", attest):
        out.append(f"{ATTEST} must create the attestation with the pinned action")
    if "actions/download-artifact" not in attest or "run-id" in attest or "github-token" in attest:
        out.append(f"{ATTEST} must download only this run's artifact")

    if needs(publish) != {BUILD, ATTEST}:
        out.append(f"{PUBLISH} must need exactly {BUILD} and {ATTEST}")
    if permissions(publish) != {"contents": "write"}:
        out.append(f"{PUBLISH} must have exactly contents: write")
    if SECRET_RE.search(publish) or IDENTITY_RE.search(publish) or FORBIDDEN_IN_PROTECTED.search(publish):
        out.append(f"{PUBLISH} must have no environment, secrets, vars, id-token, cargo, toolchain or build step")
    verify = re.search(r"gh attestation verify(?:[^\n]*\\\n)*[^\n]*", publish)
    if not verify:
        out.append(f"{PUBLISH} must run gh attestation verify")
    else:
        for flag in ("--repo ", "--signer-workflow ", "--source-digest ", "--source-ref "):
            if flag not in verify.group(0):
                out.append(f"{PUBLISH} gh attestation verify lacks {flag.strip()}")
        if "verifier-release.yml" not in verify.group(0):
            out.append(f"{PUBLISH} must pin the signer workflow verifier-release.yml")
    release = publish.find("gh release create")
    if release < 0 or (verify and release < verify.start()):
        out.append(f"{PUBLISH} must verify the attestation before gh release create")
    return out


def check(root: Path) -> list[str]:
    path = workflow_path(root)
    try:
        return problems_in(path.read_text(encoding="utf-8"))
    except OSError as e:
        return [f"cannot read {path}: {e}"]


def self_test() -> int:
    text = workflow_path(ROOT).read_text(encoding="utf-8")
    base = problems_in(text)
    if base:
        print("self-test: the real workflow already fails:", *base, sep="\n  ")
        return 1

    def sub(old: str, new: str, count: int = 1):
        assert old in text, old
        return lambda t: t.replace(old, new, count)

    mutations = {
        "dispatch trigger": sub("  push:\n    tags:", "  workflow_dispatch:\n  push:\n    tags:"),
        "wrong tag filter": sub("'verifier-[0-9]*'", "'*'"),
        "wide workflow permissions": sub("permissions:\n  contents: read\n\nenv:", "permissions:\n  contents: write\n\nenv:"),
        "unpinned action": sub("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97", "actions/setup-python@v7"),
        "floating toolchain": sub('VERIFIER_RUST_TOOLCHAIN: "1.99.1"', 'VERIFIER_RUST_TOOLCHAIN: "stable"'),
        "build gets id-token": sub("    timeout-minutes: 30\n    permissions:\n      contents: read\n", "    timeout-minutes: 30\n    permissions:\n      contents: read\n      id-token: write\n"),
        "build has an environment": sub("    timeout-minutes: 30\n    permissions:", "    timeout-minutes: 30\n    environment: some-env\n    permissions:"),
        "build reads a variable": sub("      - name: Test the verifier\n", "      - name: Test the verifier\n        env:\n          X: ${{ vars.X }}\n"),
        "build skips reproducibility": sub("check-verifier-reproducible.py", "true"),
        "attest needs nothing": sub("    needs:\n      - verifier-build\n    strategy:\n      fail-fast: false\n      matrix:\n        target: [linux-x86_64, macos-aarch64]", "    strategy:\n      fail-fast: false\n      matrix:\n        target: [linux-x86_64, macos-aarch64]"),
        "attest loses attestations": sub("      attestations: write\n", ""),
        "attest builds": sub("      - name: Re-verify the build by hash only", "      - run: cargo build\n      - name: Re-verify the build by hash only"),
        "attest skips the hash check": sub("          sha256sum --check \"yadorilink-verify-${TARGET}.sha256\"\n", ""),
        "publish gets id-token": sub("    permissions:\n      contents: write\n", "    permissions:\n      contents: write\n      id-token: write\n"),
        "publish skips attestation verify": sub("gh attestation verify", "echo skip"),
        "publish unpinned signer": sub("/.github/workflows/verifier-release.yml", "/.github/workflows/other.yml"),
        "publish drops source digest": sub("              --source-digest ${{ github.sha }} \\\n", ""),
        "publish releases first": lambda t: t.replace("          for target in", "          gh release create x\n          for target in", 1),
        "job not tag restricted": sub(
            "    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/verifier-')\n    needs:\n      - verifier-build\n      - verifier-attest\n",
            "    needs:\n      - verifier-build\n      - verifier-attest\n",
        ),
        "publish builds": sub("      - name: Download the linux build", "      - run: cargo build\n      - name: Download the linux build"),
    }
    failed = 0
    for name, mutate in mutations.items():
        mutated = mutate(text)
        if mutated == text or not problems_in(mutated):
            print(f"self-test FAILED: mutation '{name}' was not caught")
            failed += 1
    print(f"self-test: {len(mutations) - failed}/{len(mutations)} mutations caught")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    root = Path(argv[1]) if len(argv) == 2 and argv[0] == "--root" else ROOT
    problems = check(root)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if not problems:
        print("verifier workflow: ok")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
