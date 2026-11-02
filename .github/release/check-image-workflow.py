#!/usr/bin/env python3
"""The container image workflow keeps its release discipline.

Usage: check-image-workflow.py [--root DIR]
       check-image-workflow.py --self-test

The Docker image workflow (docker-image.yml) publishes a package, so it is held to the same
shape as the other release artifacts:

  * it runs on release tags only, never on a pull request or a branch push;
  * every action is pinned by commit SHA;
  * the `gate` job checks the tag against the shipped versions and that Verify is green;
  * only the `attest` job holds id-token and attestations (exactly contents: read, packages:
    write, id-token: write, attestations: write); it has no environment, no secret, no
    checkout and no step that runs anything from the image; it attests the digest that
    `publish` produced, stores the attestation with the image, and verifies it against this
    repository, this workflow, this commit and this ref;
  * `build` has no id-token or attestation permission and pushes by digest;
  * the image is named `.../yadorilink`, and release.yml no longer pushes any image.

--self-test mutates copies of the real files to bypass each rule and requires the check to
fail for every bypass.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def find(root: Path, name: str) -> Path:
    for p in (f"oss-public/.github/workflows/{name}", f".github/workflows/{name}"):
        if (root / p).is_file():
            return root / p
    return root / f".github/workflows/{name}"


def jobs(text: str) -> dict[str, str]:
    body = text[text.index("\njobs:\n"):]
    starts = [(m.start(), m.group(1)) for m in re.finditer(r"^  ([A-Za-z0-9_-]+):\s*$", body, re.M)]
    return {
        name: body[start: starts[i + 1][0] if i + 1 < len(starts) else len(body)]
        for i, (start, name) in enumerate(starts)
    }


def code_only(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def job_permissions(job: str) -> dict[str, str] | None:
    m = re.search(r"^    permissions:\n((?:      [a-z-]+: \w+\n)+)", job, re.M)
    if not m:
        return None
    return dict(re.findall(r"([a-z-]+): (\w+)", m.group(1)))


def check(root: Path) -> list[str]:
    out: list[str] = []
    wf_path, rel_path = find(root, "docker-image.yml"), find(root, "release.yml")
    if not wf_path.is_file():
        return [f"{wf_path} is missing"]
    text = wf_path.read_text(encoding="utf-8")
    code = code_only(text)
    head = text[: text.index("\njobs:\n")]
    all_jobs = {name: code_only(body) for name, body in jobs(text).items()}

    on_block = re.search(r"^on:\n((?:  .*\n|\n)+)", head, re.M)
    on = on_block.group(1) if on_block else ""
    if not re.search(r"^  push:\n    tags: \['v\[0-9\]\*'\]\n", on, re.M) or re.search(r"pull_request|workflow_dispatch|branches", on):
        out.append("the workflow must run on release tags (v[0-9]*) only")
    if not re.search(r"^permissions:\n  contents: read\n", head, re.M):
        out.append("workflow-level permissions must be exactly contents: read")
    if re.search(r"id-token|attestations", code_only(head)):
        out.append("workflow-level permissions must not grant id-token or attestations")

    for line in code.splitlines():
        m = re.search(r"\buses:\s*(\S+)", line)
        if m and not re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", m.group(1)):
            out.append(f"action not pinned by commit SHA: {m.group(1)}")
    if "continue-on-error" in code or re.search(r"\|\|\s*true\b", code):
        out.append("the workflow must not swallow failures")

    for name in ("gate", "build", "publish", "attest", "check"):
        if name not in all_jobs:
            out.append(f"job {name} is missing")
    if out and any(n not in all_jobs for n in ("gate", "build", "publish", "attest", "check")):
        return out

    gate = all_jobs["gate"]
    if "check-release-version.sh" not in gate or "require-verify.sh" not in gate:
        out.append("gate must check the tag against the shipped versions and that Verify is green")
    if "build" not in code_only(all_jobs["build"]) or "gate" not in re.findall(r"needs:\s*(\S+)", all_jobs["build"]):
        out.append("build must need gate")

    for name, body in all_jobs.items():
        if name != "attest" and re.search(r"\b(id-token|attestations|artifact-metadata)\s*:", body):
            out.append(f"{name} must not hold id-token or attestations; only attest may")
    build = all_jobs["build"]
    if "push-by-digest=true" not in build or "provenance: false" not in build:
        out.append("build must push by digest")
    if job_permissions(build) != {"contents": "read", "packages": "write"}:
        out.append("build permissions must be exactly contents: read, packages: write")

    publish = all_jobs["publish"]
    if "build" not in re.findall(r"needs:\s*(\S+)", publish) or "imagetools create" not in publish:
        out.append("publish must need build and join the digests with imagetools create")
    if re.search(r"docker (run|build)\s|cargo ", publish):
        out.append("publish must build and run nothing")

    attest = all_jobs["attest"]
    if job_permissions(attest) != {"contents": "read", "packages": "write", "id-token": "write", "attestations": "write"}:
        out.append("attest permissions must be exactly contents: read, packages: write, id-token: write, attestations: write")
    if re.search(r"^    environment:", attest, re.M) or re.search(r"\b" + "sec" + r"rets\.(?!GITHUB_TOKEN)", attest) or "vars." in attest:
        out.append("attest must have no environment, secret or variable")
    if "actions/checkout" in attest or re.search(r"docker (run|pull|build)\s|cargo |\bsh -c\b", attest):
        out.append("attest must not check out code or run anything from the image")
    if "packaging/docker/test-image.sh" not in all_jobs["check"]:
        out.append("check must run packaging/docker/test-image.sh against the published digest")
    if "publish" not in re.findall(r"needs:\s*(\S+)", attest):
        out.append("attest must need publish")
    if len(re.findall(r"uses: actions/attest-build-provenance@[0-9a-f]{40}", attest)) != 1:
        out.append("attest must create the attestation with actions/attest-build-provenance pinned by SHA")
    if "subject-digest: ${{ needs.publish.outputs.digest }}" not in attest or "push-to-registry: true" not in attest:
        out.append("attest must attest the digest publish produced and store it with the image")
    step = re.search(r"gh attestation verify[^\n\\]*(?:\\\n[^\n\\]*)*", attest)
    if not step:
        out.append("attest must run gh attestation verify")
    else:
        cmd = step.group(0)
        for needed in (
            "--repo ${{ github.repository }}",
            "--signer-workflow ${{ github.repository }}/.github/workflows/docker-image.yml",
            "--source-digest ${{ github.sha }}",
            "--source-ref ${{ github.ref }}",
        ):
            if needed not in cmd:
                out.append(f"gh attestation verify must pin: {needed}")
        if "||" in cmd or step.start() < attest.find("uses: actions/attest-build-provenance"):
            out.append("gh attestation verify must follow the attestation and must not be swallowed")

    if not re.search(r"^  IMAGE: ghcr\.io/\$\{\{ github\.repository_owner \}\}/yadorilink$", head, re.M):
        out.append("IMAGE must be ghcr.io/<owner>/yadorilink")
    if "platforms: linux/${{ matrix.arch }}" not in build or not ("amd64" in build and "arm64" in text):
        out.append("build must produce linux/amd64 and linux/arm64, each natively")

    if rel_path.is_file() and re.search(r"packages:\s*write|docker/build-push-action|docker/login-action", code_only(rel_path.read_text(encoding="utf-8"))):
        out.append("release.yml must not push an image; docker-image.yml publishes it")
    return out


def self_test() -> int:
    wf_real = find(ROOT, "docker-image.yml").read_text(encoding="utf-8")
    rel_real = find(ROOT, "release.yml").read_text(encoding="utf-8")
    wf_rel = find(ROOT, "docker-image.yml").relative_to(ROOT)
    rel_rel = find(ROOT, "release.yml").relative_to(ROOT)

    def mut(src: str, old: str, new: str) -> str:
        assert old in src, f"self-test mutation target missing: {old!r}"
        return src.replace(old, new, 1)

    attest_perm = "      id-token: write\n      attestations: write\n"
    cases = {
        "untouched": (wf_real, rel_real, False),
        "runs on a pull request": (mut(wf_real, "on:\n  push:", "on:\n  pull_request:\n  push:"), rel_real, True),
        "runs on dispatch": (mut(wf_real, "on:\n  push:", "on:\n  workflow_dispatch:\n  push:"), rel_real, True),
        "unpinned action": (mut(wf_real, "docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069", "docker/setup-buildx-action@v4"), rel_real, True),
        "build gains id-token": (mut(wf_real, "      contents: read\n      packages: write\n    steps:\n      - uses: actions/checkout", "      contents: read\n      packages: write\n      id-token: write\n    steps:\n      - uses: actions/checkout"), rel_real, True),
        "attest loses attestations": (mut(wf_real, attest_perm, "      id-token: write\n"), rel_real, True),
        "attest checks out code": (mut(wf_real, "  attest:\n    needs: publish\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    permissions:\n      contents: read\n      packages: write\n      id-token: write\n      attestations: write\n    steps:\n", "  attest:\n    needs: publish\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    permissions:\n      contents: read\n      packages: write\n      id-token: write\n      attestations: write\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"), rel_real, True),
        "verify loses the source digest": (mut(wf_real, "            --source-digest ${{ github.sha }} \\\n", ""), rel_real, True),
        "verify is swallowed": (mut(wf_real, "--source-ref ${{ github.ref }}", "--source-ref ${{ github.ref }} || true"), rel_real, True),
        "attest loses the verify": (mut(wf_real, "gh attestation verify", "echo skipped"), rel_real, True),
        "check drops the behaviour test": (mut(wf_real, "packaging/docker/test-image.sh", "true"), rel_real, True),
        "wrong image name": (mut(wf_real, "/yadorilink\n", "/yadorilink-daemon\n"), rel_real, True),
        "gate drops require-verify": (mut(wf_real, "require-verify.sh", "true"), rel_real, True),
        "release.yml pushes an image": (wf_real, mut(rel_real, "permissions:\n  contents: read\n", "permissions:\n  contents: read\n  packages: write\n"), True),
    }
    failed = 0
    for name, (wf, rel, must_fail) in cases.items():
        with tempfile.TemporaryDirectory() as d:
            for path, body in ((wf_rel, wf), (rel_rel, rel)):
                target = Path(d) / path
                target.parent.mkdir(parents=True, exist_ok=True)
                with open(target, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(body)
            problems = check(Path(d))
        if must_fail and not problems:
            print(f"FAIL: bypass not detected: {name}", file=sys.stderr)
            failed += 1
        if not must_fail and problems:
            print(f"FAIL: {name} rejected: {problems}", file=sys.stderr)
            failed += 1
    if failed:
        return 1
    print("check-image-workflow self-test passed")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    root = Path(argv[argv.index("--root") + 1]) if "--root" in argv else ROOT
    problems = check(root)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if problems:
        return 1
    print("docker-image workflow shape ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
