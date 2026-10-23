#!/usr/bin/env python3
"""Structural gates for manifest signing: one workflow signs, nothing else can.

Usage: check-signing-workflow.py [--root DIR]
       check-signing-workflow.py --self-test

The manifest signing key decides what every installed client will accept, so where it can be used
is checked, not trusted:
  * `sign-manifest.yml` signs for production only: it takes no target input and carries no other
    deployment target, signing environment or trust root (the published tree holds production
    signing resources only); the signer tool `sign_request.py` is production-only as well, and no
    second trust chain file sits next to `trust-chain.json`;
  * `sign-manifest.yml` is triggered by workflow_dispatch only (no push, tag, schedule, pull
    request, workflow_run or repository_dispatch) and has workflow permissions contents: read;
  * its jobs are exactly build-signer, sign and attest;
  * build-signer and attest have no environment and no secret; the signing tool is built in
    build-signer and only checked by hash in sign (sign has no cargo, toolchain, download or
    package-manager step other than installing `cryptography`);
  * sign is the only job with an environment, and it is exactly
    `release-signing`; it needs build-signer, has contents: read only (no id-token), and a run
    must be on main;
  * the signing secrets (MANIFEST_SIGNING_KEY, MANIFEST_SIGNING_KEY_ID) are referenced in the
    step named "Sign" of sign and nowhere else; no other secret appears in the workflow;
  * attest is the only job with id-token/attestations and attests the hash-checked bundle with a
    pinned action;
  * a run: script never interpolates an input (inputs reach scripts through env only), never
    prints the environment or enables shell tracing, and nothing continues on error;
  * every action is pinned to a full commit SHA;
  * `announce-trust-chain.yml` (announcing a new public key in the trust chain without anyone holding
    the seed) has the same isolation with two jobs, build-signer and announce: workflow_dispatch only,
    contents: read, no id-token; announce is the only job with an environment (`release-signing`),
    needs build-signer, runs on main only, reads the signing secrets in its one step named "Announce"
    (which only appends the announced key, never revokes), checks the tool hash and the inputs before
    that step and re-verifies the new chain after it, and uploads exactly one artifact, the new
    `trust-chain.json` (public data), never the workspace;
  * no other workflow mentions the manifest signing key, the signing tool, the signer script or
    the manifest object store (a competing writer), whatever its trigger.

--self-test mutates copies of the real workflows to bypass each gate and requires a failure for
every bypass.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIRS = ("oss-public/.github/workflows", ".github/workflows")
SIGN_FILE = "sign-manifest.yml"
ANNOUNCE_FILE = "announce-trust-chain.yml"
ANNOUNCE = "announce"
ANNOUNCE_STEP = "Announce"
ANNOUNCE_TOOL = "announce_trust_chain.py"
BUILD, SIGN, ATTEST = "build-signer", "sign", "attest"
SIGN_STEP = "Sign"
ENVIRONMENT = "release-signing"
# Artifacts may carry one named file from these directories, never the workspace.
ARTIFACT_PATH_RE = re.compile(r"(?:signer|bundle|announce)/[A-Za-z0-9._-]+")
# The one word no published signing file may carry. Assembled so this guard does not itself carry it.
OTHER_TARGET = "sta" + "ging"
SIGNER_TOOL = "sign_request.py"
ALLOWED_SECRETS = {"MANIFEST_SIGNING_KEY", "MANIFEST_SIGNING_KEY_ID"}
USES_RE = re.compile(r"^\s*-?\s*uses:\s*(\S+)@(\S+)", re.M)
# What no other workflow may mention: a second path to the key or to the manifest store.
COMPETING_RE = re.compile(
    r"MANIFEST_SIGNING_KEY|yadorilink-sign-manifest|(?<!test_)sign_request\.py|--key-hex|yadorilink-update-manifests")
FORBIDDEN_IN_SIGN = re.compile(
    r"cargo\b|rustup|rust-toolchain|setup-protoc|\bnpx?\b|\bcurl\b|\bwget\b|actions/cache|gh release|gh run download")
LEAK_RE = re.compile(r"set\s+-[a-z]*x|\bprintenv\b|^\s*(?:\w+\s+)?env\s*(?:\||$)|\bexport\s+-p\b|"
                     r"echo[^\n]*(?:SIGNING_KEY|secrets\.)|ACTIONS_STEP_DEBUG|ACTIONS_RUNNER_DEBUG", re.M)

_spec = importlib.util.spec_from_file_location("check_release_gates", Path(__file__).with_name("check-release-gates.py"))
_gates = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gates)
jobs, needs, code_only = _gates.jobs, _gates.needs, _gates.code_only


def permissions(job: str) -> dict[str, str] | None:
    m = re.search(r"^    permissions:\s*\n((?:      [a-z-]+:\s*\S+\n)+)", job, re.M)
    return dict(re.findall(r"^      ([a-z-]+):\s*(\S+)$", m.group(1), re.M)) if m else None


def top_permissions(text: str) -> dict[str, str] | None:
    m = re.search(r"^permissions:\s*\n((?:  [a-z-]+:\s*\S+\n)+)", text, re.M)
    return dict(re.findall(r"^  ([a-z-]+):\s*(\S+)$", m.group(1), re.M)) if m else None


def triggers(text: str) -> list[str]:
    m = re.search(r"^on:\s*\n((?:[ ]+.*\n|\n)+)", text, re.M)
    return re.findall(r"^  ([a-z_]+):", m.group(1), re.M) if m else []


def steps(job: str) -> dict[str, str]:
    body = job[job.index("    steps:\n"):]
    parts = re.split(r"^      - ", body, flags=re.M)[1:]
    out = {}
    for i, part in enumerate(parts):
        m = re.search(r"^(?:name:\s*(.+)|.*\n\s+name:\s*(.+))$", part, re.M)
        out[(m.group(1) or m.group(2)).strip() if m else f"#{i}"] = part
    return out


def run_blocks(text: str) -> list[str]:
    """The text of every `run:` value (inline or block scalar)."""
    out = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", line)
        if not m:
            continue
        if m.group(2) not in ("|", "|-", ">", ">-"):
            out.append(m.group(2))
            continue
        indent, block = len(m.group(1)), []
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            block.append(nxt)
        out.append("\n".join(block))
    return out


def generic_problems(files: dict[str, str]) -> list[str]:
    out: list[str] = []
    for name, text in sorted(files.items()):
        code = code_only(text)
        for action, ref in USES_RE.findall(code):
            if not action.startswith("./") and not re.fullmatch(r"[0-9a-f]{40}", ref):
                out.append(f"{name}: {action}@{ref} is not pinned to a full commit SHA")
        if name not in (SIGN_FILE, ANNOUNCE_FILE) and COMPETING_RE.search(code):
            out.append(f"{name} mentions the manifest signing key, the signing tool or the manifest store; "
                       f"only {SIGN_FILE} signs, only {ANNOUNCE_FILE} announces keys and only the channel-publish workflow distributes")
    return out


def common_problems(name: str, code: str, group: str, what: str) -> list[str]:
    """Rules every workflow that can touch the signing key obeys."""
    out: list[str] = []
    if triggers(code) != ["workflow_dispatch"]:
        out.append(f"{name} must be triggered by workflow_dispatch only")
    if top_permissions(code) != {"contents": "read"}:
        out.append(f"{name} permissions must be exactly contents: read")
    if "continue-on-error" in code:
        out.append(f"{name} must not continue on error")
    if not re.search(rf"^concurrency:\s*\n  group:\s*{group}\n  cancel-in-progress:\s*false\s*$", code, re.M):
        out.append(f"{name} needs a concurrency group that never cancels {what}")
    if LEAK_RE.search(code):
        out.append(f"{name} must not print the environment, trace the shell or echo a secret")
    for secret in re.findall(r"secrets\.([A-Za-z0-9_]+)", code):
        if secret not in ALLOWED_SECRETS:
            out.append(f"{name} references secrets.{secret}; only the manifest signing secrets are allowed here")
    # Inputs reach scripts through env only.
    for block in run_blocks(code):
        if "${{" in block:
            out.append(f"{name}: a run script interpolates an expression; pass it through env instead")
    for line in code.splitlines():
        if "${{ inputs." in line and not re.match(
                r"^\s+(?:[A-Z][A-Z0-9_]*|group|if|environment):\s.*\$\{\{|^\s+environment:", line):
            out.append(f"{name}: input used outside env/if/group/environment: {line.strip()}")

    # Artifacts are one named file from a known directory: never the workspace or a wildcard.
    for m in re.finditer(r"uses: actions/upload-artifact@\S+.*\n(?:\s+.*\n)*?\s+path:\s*(\S+)", code + "\n"):
        if not ARTIFACT_PATH_RE.fullmatch(m.group(1)):
            out.append(f"{name}: an artifact must be one named file, not {m.group(1)!r}")
    return out


def sign_problems(files: dict[str, str]) -> list[str]:
    out: list[str] = []
    text = files.get(SIGN_FILE)
    if text is None:
        return out + [f"{SIGN_FILE} does not exist"]
    code = code_only(text)

    if re.search(OTHER_TARGET, text, re.I) or re.search(r"^      target:|inputs\.target|--target (?!production\b)", text, re.M):
        out.append(f"{SIGN_FILE} must sign for production only: no other target path and no target input")
    out += common_problems(SIGN_FILE, code, r"sign-manifest-.*", "a running signature")

    try:
        all_jobs = jobs(code)
    except ValueError:
        return out + [f"{SIGN_FILE} has no jobs"]
    if set(all_jobs) != {BUILD, SIGN, ATTEST}:
        out.append(f"{SIGN_FILE} jobs must be exactly {BUILD}, {SIGN}, {ATTEST}")
        return out
    build, sign, attest = all_jobs[BUILD], all_jobs[SIGN], all_jobs[ATTEST]

    for name, job in ((BUILD, build), (ATTEST, attest)):
        if re.search(r"^    environment\s*:", job, re.M):
            out.append(f"{name} must not use an environment")
        if "secrets." in job:
            out.append(f"{name} must not reference secrets")
    if permissions(build) not in (None, {"contents": "read"}) or re.search(r"id-token|attestations", build):
        out.append(f"{BUILD} must have no more than contents: read")
    if "signing runs from main only" not in build or "refs/heads/main" not in build:
        out.append(f"{BUILD} must refuse a run that is not on main")

    env_line = re.search(r"^    environment:\s*(.+?)\s*$", sign, re.M)
    if not env_line or env_line.group(1) != ENVIRONMENT:
        out.append(f"{SIGN} must be bound to exactly: environment: {ENVIRONMENT}")
    if needs(sign) != {BUILD}:
        out.append(f"{SIGN} must need {BUILD} (and only it)")
    if permissions(sign) != {"contents": "read"}:
        out.append(f"{SIGN} permissions must be exactly contents: read")
    if not re.search(r"^    if:.*refs/heads/main", sign, re.M):
        out.append(f"{SIGN} must not sign off main (job-level if)")
    if "secrets." in sign[: sign.index("    steps:\n")] or "secrets." in code[: code.index("\njobs:\n")]:
        out.append(f"no workflow-level or job-level env may carry a secret; only the {SIGN_STEP!r} step")
    sign_steps = steps(sign)
    for name, block in sign_steps.items():
        refs = set(re.findall(r"secrets\.([A-Za-z0-9_]+)", block))
        if refs and name != SIGN_STEP:
            out.append(f"step {name!r} references secrets; only {SIGN_STEP!r} may")
    signing = sign_steps.get(SIGN_STEP)
    if signing is None:
        return out + [f"{SIGN} has no step named {SIGN_STEP!r}"]
    if set(re.findall(r"secrets\.([A-Za-z0-9_]+)", signing)) != ALLOWED_SECRETS:
        out.append(f"step {SIGN_STEP!r} must receive exactly the signing key and its id")
    cmd = re.search(r"sign_request\.py sign\b(?:[^\n\\]|\\\n)*", signing)
    if not cmd:
        out.append(f"step {SIGN_STEP!r} must run sign_request.py sign")
    else:
        for flag in ('--signing-digest "$SIGNING_DIGEST"', "--target production", '--channel "$CHANNEL"',
                     '--root-key-id "$ROOT_KEY_ID"', '--root-public-key-hex "$ROOT_PUBLIC_KEY_HEX"',
                     "--release-dir .github/release", "--sign-tool signer/yadorilink-sign-manifest"):
            if flag not in cmd.group(0):
                out.append(f"step {SIGN_STEP!r} must pass {flag}")
    for var, src in (("ROOT_KEY_ID", "vars.RELEASE_MANIFEST_KEY_ID"),
                     ("ROOT_PUBLIC_KEY_HEX", "vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX"),
                     ("SIGNING_DIGEST", "inputs.signing_digest"), ("CHANNEL", "inputs.channel")):
        if not re.search(rf"^\s+{var}: \$\{{\{{ {re.escape(src)} \}}\}}\s*$", signing, re.M):
            out.append(f"step {SIGN_STEP!r} must bind {var} to {src}")
    names = list(sign_steps)
    for before in ("Check the signing tool", "Decode the request"):
        if before not in names or names.index(before) > names.index(SIGN_STEP):
            out.append(f"{SIGN} must run {before!r} before {SIGN_STEP!r}")
    check = sign_steps.get("Check the signing tool", "")
    if "needs.build-signer.outputs.signer_sha256" not in check or "sha256sum" not in check:
        out.append(f"{SIGN} must check the signing tool against the {BUILD} hash")
    if FORBIDDEN_IN_SIGN.search(sign):
        out.append(f"{SIGN} must not build, download or run anything but the checked signing tool and the signer script")
    for line in re.findall(r"pip install[^\n]*", sign):
        if line.split()[-1] != "cryptography":
            out.append(f"{SIGN} may install only cryptography: {line.strip()}")
    if re.search(r"id-token|attestations", sign):
        out.append(f"{SIGN} must not have id-token or attestations")

    if permissions(attest) != {"contents": "read", "id-token": "write", "attestations": "write"}:
        out.append(f"{ATTEST} permissions must be exactly contents: read, id-token: write, attestations: write")
    if needs(attest) != {SIGN}:
        out.append(f"{ATTEST} must need {SIGN} (and only it)")
    if not re.search(r"uses: actions/attest-build-provenance@[0-9a-f]{40}\b", attest):
        out.append(f"{ATTEST} must attest with a pinned actions/attest-build-provenance")
    if "needs.sign.outputs.bundle_sha256" not in attest or "sha256sum" not in attest:
        out.append(f"{ATTEST} must check the bundle hash that {SIGN} produced before attesting")
    if re.search(r"cargo\b|rust-toolchain|sign_request|yadorilink-sign-manifest", attest):
        out.append(f"{ATTEST} must not build or sign anything")
    return out


def announce_problems(files: dict[str, str]) -> list[str]:
    """The key-announcement workflow: same isolation as signing, two jobs, one secret step."""
    text = files.get(ANNOUNCE_FILE)
    if text is None:
        return [f"{ANNOUNCE_FILE} does not exist"]
    code = code_only(text)
    out: list[str] = []
    if re.search(OTHER_TARGET, text, re.I):
        out.append(f"{ANNOUNCE_FILE} must announce for production only: no other target path")
    out += common_problems(ANNOUNCE_FILE, code, "announce-trust-chain", "a running announcement")
    head = code.split("\njobs:\n")[0]
    if set(re.findall(r"^      ([a-z_]+):\s*$", head.split("\npermissions:")[0], re.M)) != {"new_key_id", "new_public_key_hex"}:
        out.append(f"{ANNOUNCE_FILE} takes exactly the inputs new_key_id and new_public_key_hex")
    if "secrets." in head:
        out.append("no workflow-level env may carry a secret")
    try:
        all_jobs = jobs(code)
    except ValueError:
        return out + [f"{ANNOUNCE_FILE} has no jobs"]
    if set(all_jobs) != {BUILD, ANNOUNCE}:
        return out + [f"{ANNOUNCE_FILE} jobs must be exactly {BUILD}, {ANNOUNCE}"]
    build, job = all_jobs[BUILD], all_jobs[ANNOUNCE]

    if re.search(r"^    environment\s*:", build, re.M) or "secrets." in build:
        out.append(f"{BUILD} must have no environment and no secret")
    if permissions(build) not in (None, {"contents": "read"}) or re.search(r"id-token|attestations", build):
        out.append(f"{BUILD} must have no more than contents: read")
    if "announcing a key runs from main only" not in build or "refs/heads/main" not in build:
        out.append(f"{BUILD} must refuse a run that is not on main")

    env_line = re.search(r"^    environment:\s*(.+?)\s*$", job, re.M)
    if not env_line or env_line.group(1) != ENVIRONMENT:
        out.append(f"{ANNOUNCE} must be bound to exactly: environment: {ENVIRONMENT}")
    if needs(job) != {BUILD}:
        out.append(f"{ANNOUNCE} must need {BUILD} (and only it)")
    if permissions(job) != {"contents": "read"} or re.search(r"id-token|attestations", job):
        out.append(f"{ANNOUNCE} permissions must be exactly contents: read")
    if not re.search(r"^    if:.*refs/heads/main", job, re.M):
        out.append(f"{ANNOUNCE} must not run off main (job-level if)")
    if "secrets." in job[: job.index("    steps:\n")]:
        out.append(f"no job-level env may carry a secret; only the {ANNOUNCE_STEP!r} step")
    job_steps = steps(job)
    for name, block in job_steps.items():
        if name != ANNOUNCE_STEP and "secrets." in block:
            out.append(f"step {name!r} references secrets; only {ANNOUNCE_STEP!r} may")
        if name != ANNOUNCE_STEP and re.search(r"yadorilink-sign-manifest|trust-set|--key-hex|MANIFEST_SIGNING_KEY", block) \
                and name not in ("Check the signing tool", "Download the signing tool"):
            out.append(f"step {name!r} must not run the signing tool or name the key")
    step = job_steps.get(ANNOUNCE_STEP)
    if step is None:
        return out + [f"{ANNOUNCE} has no step named {ANNOUNCE_STEP!r}"]
    if set(re.findall(r"secrets\.([A-Za-z0-9_]+)", step)) != ALLOWED_SECRETS:
        out.append(f"step {ANNOUNCE_STEP!r} must receive exactly the signing key and its id")
    cmd = re.search(r"signer/yadorilink-sign-manifest trust-set\b(?:[^\n\\]|\\\n)*", step)
    if not cmd:
        out.append(f"step {ANNOUNCE_STEP!r} must run signer/yadorilink-sign-manifest trust-set")
    else:
        for flag in ('--key-hex "$MANIFEST_SIGNING_KEY"', '--key-id "$MANIFEST_SIGNING_KEY_ID"',
                     '--anchor-key-id "$ROOT_KEY_ID"', '--anchor-public-key-hex "$ROOT_PUBLIC_KEY_HEX"',
                     "--chain .github/release/trust-chain.json", '--add "$NEW_KEY_ID:$NEW_PUBLIC_KEY_HEX"',
                     "--out announce/trust-chain.json"):
            if flag not in cmd.group(0):
                out.append(f"step {ANNOUNCE_STEP!r} must pass {flag}")
        if "--revoke" in cmd.group(0):
            out.append(f"step {ANNOUNCE_STEP!r} announces; it must not revoke")
    for var, src in (("ROOT_KEY_ID", "vars.RELEASE_MANIFEST_KEY_ID"),
                     ("ROOT_PUBLIC_KEY_HEX", "vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX"),
                     ("NEW_KEY_ID", "inputs.new_key_id"), ("NEW_PUBLIC_KEY_HEX", "inputs.new_public_key_hex"),
                     ("MANIFEST_SIGNING_KEY", "secrets.MANIFEST_SIGNING_KEY"),
                     ("MANIFEST_SIGNING_KEY_ID", "secrets.MANIFEST_SIGNING_KEY_ID")):
        if not re.search(rf"^\s+{var}: \$\{{\{{ {re.escape(src)} \}}\}}\s*$", step, re.M):
            out.append(f"step {ANNOUNCE_STEP!r} must bind {var} to {src}")
    names = list(job_steps)
    for before in ("Check the signing tool", "Check the announcement"):
        if before not in names or names.index(before) > names.index(ANNOUNCE_STEP):
            out.append(f"{ANNOUNCE} must run {before!r} before {ANNOUNCE_STEP!r}")
    if "Verify the new chain" not in names or names.index("Verify the new chain") < names.index(ANNOUNCE_STEP):
        out.append(f"{ANNOUNCE} must run 'Verify the new chain' after {ANNOUNCE_STEP!r}")
    check = job_steps.get("Check the signing tool", "")
    if "needs.build-signer.outputs.signer_sha256" not in check or "sha256sum" not in check:
        out.append(f"{ANNOUNCE} must check the signing tool against the {BUILD} hash")
    if f"{ANNOUNCE_TOOL} check --chain .github/release/trust-chain.json" not in job_steps.get("Check the announcement", ""):
        out.append(f"step 'Check the announcement' must run {ANNOUNCE_TOOL} check on the committed chain")
    verify = job_steps.get("Verify the new chain", "")
    if (f"{ANNOUNCE_TOOL} verify" not in verify or "--old .github/release/trust-chain.json" not in verify
            or "--new announce/trust-chain.json" not in verify or "GITHUB_STEP_SUMMARY" not in verify):
        out.append(f"step 'Verify the new chain' must run {ANNOUNCE_TOOL} verify on old and new chain and write the summary")
    if FORBIDDEN_IN_SIGN.search(job):
        out.append(f"{ANNOUNCE} must not build, download or run anything but the checked signing tool and the checker script")
    for line in re.findall(r"pip install[^\n]*", job):
        if line.split()[-1] != "cryptography":
            out.append(f"{ANNOUNCE} may install only cryptography: {line.strip()}")
    uploads = re.findall(r"uses: actions/upload-artifact@[0-9a-f]{40}\b[^\n]*\n\s+with:\n\s+name: (\S+)\n\s+path: (\S+)\n", job)
    if uploads != [("trust-chain", "announce/trust-chain.json")] or job.count("upload-artifact") != 1:
        out.append(f"{ANNOUNCE} must upload exactly one artifact: announce/trust-chain.json")
    if "persist-credentials: false" not in job:
        out.append(f"{ANNOUNCE} must check out without persisted credentials")
    return out


def problems_in(files: dict[str, str]) -> list[str]:
    return generic_problems(files) + sign_problems(files) + announce_problems(files)


def tool_problems(tool_text: str | None, release_files: list[str]) -> list[str]:
    """The published signer tool and release directory hold production signing only."""
    if tool_text is None:
        return [f"{SIGNER_TOOL} does not exist"]
    out = []
    if re.search(OTHER_TARGET, tool_text, re.I):
        out.append(f"{SIGNER_TOOL} must sign for production only: no other target, root or chain")
    if not re.search(r'^TARGETS = \("production",\)$', tool_text, re.M):
        out.append(f"{SIGNER_TOOL} must accept the production target and no other")
    if not re.search(r'^CHAIN_FILES = \{"production": "trust-chain\.json"\}$', tool_text, re.M):
        out.append(f"{SIGNER_TOOL} must know the production trust chain only")
    for name in release_files:
        if re.search(OTHER_TARGET, name, re.I) or (re.search(r"trust-chain", name) and name != "trust-chain.json"):
            out.append(f"{name}: no second trust chain or other-target file belongs next to trust-chain.json")
    return out


def load_tool(root: Path) -> tuple[str | None, list[str]]:
    d = root / ".github" / "release"
    tool = d / SIGNER_TOOL
    return (tool.read_text(encoding="utf-8") if tool.is_file() else None,
            sorted(p.name for p in d.iterdir()) if d.is_dir() else [])


def load(root: Path) -> dict[str, str]:
    d = next((root / p for p in WORKFLOW_DIRS if (root / p / SIGN_FILE).is_file()), root / WORKFLOW_DIRS[0])
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(d.glob("*.yml"))}


def self_test() -> int:
    files = load(ROOT)
    base = problems_in(files)
    if base:
        print("self-test: the real workflows already fail:", *base, sep="\n  ")
        return 1
    tool_text, release_files = load_tool(ROOT)
    tool_base = tool_problems(tool_text, release_files)
    if tool_base:
        print("self-test: the real signer tool already fails:", *tool_base, sep="\n  ")
        return 1
    sign = files[SIGN_FILE]
    ann = files[ANNOUNCE_FILE]
    release = files["release.yml"]

    def mut(text: str, old: str, new: str) -> str:
        assert old in text, f"{old!r} not found"
        return text.replace(old, new, 1)

    def other(extra: str) -> dict[str, str]:
        return {"release.yml": release + extra}

    cases: dict[str, dict[str, str]] = {
        "sign-manifest.yml removed": {SIGN_FILE: ""},
        "push trigger": {SIGN_FILE: mut(sign, "on:\n  workflow_dispatch:", "on:\n  push:\n    tags: ['v*']\n  workflow_dispatch:")},
        "tag-only trigger": {SIGN_FILE: mut(sign, "on:\n  workflow_dispatch:", "on:\n  push:\n  workflow_dispatch:")},
        "schedule trigger": {SIGN_FILE: mut(sign, "on:\n  workflow_dispatch:", "on:\n  schedule:\n    - cron: '0 0 * * *'\n  workflow_dispatch:")},
        "workflow_run trigger": {SIGN_FILE: mut(sign, "on:\n  workflow_dispatch:", "on:\n  workflow_run:\n    workflows: [Release]\n  workflow_dispatch:")},
        "workflow write permission": {SIGN_FILE: mut(sign, "permissions:\n  contents: read\n\nconcurrency", "permissions:\n  contents: write\n\nconcurrency")},
        "no concurrency group": {SIGN_FILE: mut(sign, "  cancel-in-progress: false\n\njobs", "  cancel-in-progress: true\n\njobs")},
        "extra job": {SIGN_FILE: sign + "\n  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
        "sign without environment": {SIGN_FILE: mut(sign, "    environment: release-signing\n", "")},
        "sign bound to another signing environment": {SIGN_FILE: mut(sign, "environment: release-signing", "environment: other-signing")},
        "sign bound to an expression": {SIGN_FILE: mut(sign, "environment: release-signing", "environment: ${{ inputs.channel }}")},
        "another target path comes back": {SIGN_FILE: mut(sign, "name: Sign manifest\n", f"name: Sign manifest\n# {OTHER_TARGET} too\n")},
        "a target input comes back": {SIGN_FILE: mut(sign, "    inputs:\n", "    inputs:\n      target:\n        type: string\n")},
        "signs for another target": {SIGN_FILE: mut(sign, "--target production", f"--target {OTHER_TARGET}")},
        "unknown environment name": {SIGN_FILE: mut(sign, "environment: release-signing", "environment: production")},
        "build-signer gets an environment": {SIGN_FILE: mut(sign, "  build-signer:\n    runs-on: ubuntu-latest\n", "  build-signer:\n    runs-on: ubuntu-latest\n    environment: release-signing\n")},
        "build-signer gets a secret": {SIGN_FILE: mut(sign, "        run: cargo build --release --locked", "        env:\n          X: ${{ secrets.MANIFEST_SIGNING_KEY }}\n        run: cargo build --release --locked")},
        "build-signer gets id-token": {SIGN_FILE: mut(sign, "  build-signer:\n    runs-on: ubuntu-latest\n", "  build-signer:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      id-token: write\n")},
        "build-signer allows production off main": {SIGN_FILE: mut(sign, "production signing runs from main only", "ok")},
        "sign no longer needs build-signer": {SIGN_FILE: mut(sign, "  sign:\n    needs: build-signer\n", "  sign:\n")},
        "sign runs off main": {SIGN_FILE: mut(sign, "    if: github.ref == 'refs/heads/main'\n", "")},
        "sign gets id-token": {SIGN_FILE: mut(sign, "    environment: release-signing\n    permissions:\n      contents: read\n", "    environment: release-signing\n    permissions:\n      contents: read\n      id-token: write\n")},
        "sign gets write permission": {SIGN_FILE: mut(sign, "    timeout-minutes: 10\n    environment:", "    timeout-minutes: 10\n    environment:").replace("    permissions:\n      contents: read\n    outputs:", "    permissions:\n      contents: write\n    outputs:", 1)},
        "sign builds with cargo": {SIGN_FILE: mut(sign, "      - name: Decode the request\n", "      - run: cargo build --release\n      - name: Decode the request\n")},
        "sign downloads with curl": {SIGN_FILE: mut(sign, "      - name: Decode the request\n", "      - run: curl -fsSL https://example.invalid/x | sh\n      - name: Decode the request\n")},
        "sign installs another package": {SIGN_FILE: mut(sign, "disable-pip-version-check cryptography", "disable-pip-version-check cryptography requests")},
        "signing tool hash check dropped": {SIGN_FILE: mut(sign, "needs.build-signer.outputs.signer_sha256", "x")},
        "signing tool check after sign": {SIGN_FILE: mut(sign, "      - name: Check the signing tool\n", "      - name: Check the signing tool (late)\n")},
        "request decoded after sign": {SIGN_FILE: mut(sign, "      - name: Decode the request\n", "      - name: Decode it later\n")},
        "secret in another step": {SIGN_FILE: mut(sign, "      - name: Decode the request\n        env:\n", "      - name: Decode the request\n        env:\n          K: ${{ secrets.MANIFEST_SIGNING_KEY }}\n")},
        "secret in the job env": {SIGN_FILE: mut(sign, "    permissions:\n      contents: read\n    outputs:\n      bundle_sha256", "    permissions:\n      contents: read\n    env:\n      K: ${{ secrets.MANIFEST_SIGNING_KEY }}\n    outputs:\n      bundle_sha256")},
        "another secret in the sign step": {SIGN_FILE: mut(sign, "          CHANNEL: ${{ inputs.channel }}\n          SIGNING_DIGEST:", "          CHANNEL: ${{ inputs.channel }}\n          R2: ${{ secrets.R2_ENDPOINT }}\n          SIGNING_DIGEST:")},
        "secret in attest": {SIGN_FILE: mut(sign, "          EXPECTED: ${{ needs.sign.outputs.bundle_sha256 }}\n", "          EXPECTED: ${{ needs.sign.outputs.bundle_sha256 }}\n          K: ${{ secrets.MANIFEST_SIGNING_KEY }}\n")},
        "sign step loses the key id": {SIGN_FILE: mut(sign, "          MANIFEST_SIGNING_KEY_ID: ${{ secrets.MANIFEST_SIGNING_KEY_ID }}\n", "")},
        "approved digest not passed": {SIGN_FILE: mut(sign, ' --signing-digest "$SIGNING_DIGEST"', "")},
        "target not passed": {SIGN_FILE: mut(sign, " --target production", "")},
        "channel not passed": {SIGN_FILE: mut(sign, ' --channel "$CHANNEL"', "")},
        "trust root from elsewhere": {SIGN_FILE: mut(sign, "vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX", "vars.OTHER_KEY")},
        "trust chain from elsewhere": {SIGN_FILE: mut(sign, "--release-dir .github/release", "--release-dir other")},
        "digest bound to another input": {SIGN_FILE: mut(sign, "SIGNING_DIGEST: ${{ inputs.signing_digest }}", "SIGNING_DIGEST: ${{ inputs.channel }}")},
        "input interpolated into a script": {SIGN_FILE: mut(sign, "          set -euo pipefail\n          mkdir bundle\n", "          set -euo pipefail\n          echo ${{ inputs.channel }}\n          mkdir bundle\n")},
        "shell tracing": {SIGN_FILE: mut(sign, "          set -euo pipefail\n          mkdir bundle\n", "          set -euxo pipefail\n          mkdir bundle\n")},
        "environment dump": {SIGN_FILE: mut(sign, "          set -euo pipefail\n          mkdir bundle\n", "          set -euo pipefail\n          printenv\n          mkdir bundle\n")},
        "echo of the key": {SIGN_FILE: mut(sign, "          set -euo pipefail\n          mkdir bundle\n", "          set -euo pipefail\n          echo \"$MANIFEST_SIGNING_KEY\"\n          mkdir bundle\n")},
        "continue on error": {SIGN_FILE: mut(sign, "  sign:\n    needs: build-signer\n", "  sign:\n    continue-on-error: true\n    needs: build-signer\n")},
        "attest gets an environment": {SIGN_FILE: mut(sign, "  attest:\n    needs: sign\n    runs-on: ubuntu-latest\n", "  attest:\n    needs: sign\n    runs-on: ubuntu-latest\n    environment: release-signing\n")},
        "attest without the hash check": {SIGN_FILE: mut(sign, "needs.sign.outputs.bundle_sha256", "x")},
        "attest loses attestations": {SIGN_FILE: mut(sign, "      attestations: write\n", "")},
        "attest action unpinned": {SIGN_FILE: mut(sign, "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8", "actions/attest-build-provenance@v4")},
        "unpinned action": {SIGN_FILE: mut(sign, "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97", "actions/setup-python@v7")},
        "release.yml signs": {"release.yml": release + "\n      - run: yadorilink-sign-manifest sign\n"},
        "release.yml uses the key": other("\n          K: ${{ secrets.MANIFEST_SIGNING_KEY }}\n"),
        "release.yml writes the manifest store": other("\n      - run: wrangler r2 object put yadorilink-update-manifests/beta/manifest.json\n"),
        "release.yml calls the signer script": other("\n      - run: python3 .github/release/sign_request.py sign\n"),
        "a new workflow with the key": {"stray.yml": "name: x\non:\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.MANIFEST_SIGNING_KEY }}\n"},
        # announce-trust-chain.yml
        "announce workflow removed": {ANNOUNCE_FILE: ""},
        "announce push trigger": {ANNOUNCE_FILE: mut(ann, "on:\n  workflow_dispatch:", "on:\n  push:\n  workflow_dispatch:")},
        "announce pull_request_target trigger": {ANNOUNCE_FILE: mut(ann, "on:\n  workflow_dispatch:", "on:\n  pull_request_target:\n  workflow_dispatch:")},
        "announce schedule trigger": {ANNOUNCE_FILE: mut(ann, "on:\n  workflow_dispatch:", "on:\n  schedule:\n    - cron: '0 0 * * *'\n  workflow_dispatch:")},
        "announce write permission": {ANNOUNCE_FILE: mut(ann, "permissions:\n  contents: read\n\nconcurrency", "permissions:\n  contents: write\n\nconcurrency")},
        "announce may cancel itself": {ANNOUNCE_FILE: mut(ann, "  cancel-in-progress: false\n\njobs", "  cancel-in-progress: true\n\njobs")},
        "announce extra input": {ANNOUNCE_FILE: mut(ann, "    inputs:\n", "    inputs:\n      extra:\n        type: string\n")},
        "announce extra job": {ANNOUNCE_FILE: ann + "\n  extra:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"},
        "announce without environment": {ANNOUNCE_FILE: mut(ann, "    environment: release-signing\n", "")},
        "announce bound to another environment": {ANNOUNCE_FILE: mut(ann, "environment: release-signing", "environment: other-signing")},
        "announce runs off main": {ANNOUNCE_FILE: mut(ann, "    if: github.ref == 'refs/heads/main'\n", "")},
        "announce gets id-token": {ANNOUNCE_FILE: mut(ann, "    environment: release-signing\n    permissions:\n      contents: read\n", "    environment: release-signing\n    permissions:\n      contents: read\n      id-token: write\n")},
        "announce gets write permission": {ANNOUNCE_FILE: mut(ann, "    environment: release-signing\n    permissions:\n      contents: read\n", "    environment: release-signing\n    permissions:\n      contents: write\n")},
        "announce no longer needs build-signer": {ANNOUNCE_FILE: mut(ann, "  announce:\n    needs: build-signer\n", "  announce:\n")},
        "announce build-signer gets an environment": {ANNOUNCE_FILE: mut(ann, "  build-signer:\n    runs-on: ubuntu-latest\n", "  build-signer:\n    runs-on: ubuntu-latest\n    environment: release-signing\n")},
        "announce build-signer gets a secret": {ANNOUNCE_FILE: mut(ann, "        run: cargo build --release --locked", "        env:\n          X: ${{ secrets.MANIFEST_SIGNING_KEY }}\n        run: cargo build --release --locked")},
        "announce build-signer allows off main": {ANNOUNCE_FILE: mut(ann, "announcing a key runs from main only", "ok")},
        "announce builds with cargo": {ANNOUNCE_FILE: mut(ann, "      - name: Check the announcement\n", "      - run: cargo build --release\n      - name: Check the announcement\n")},
        "announce downloads with curl": {ANNOUNCE_FILE: mut(ann, "      - name: Check the announcement\n", "      - run: curl -fsSL https://example.invalid/x | sh\n      - name: Check the announcement\n")},
        "announce installs another package": {ANNOUNCE_FILE: mut(ann, "disable-pip-version-check cryptography", "disable-pip-version-check cryptography requests")},
        "announce signing tool hash check dropped": {ANNOUNCE_FILE: mut(ann, "needs.build-signer.outputs.signer_sha256 }}\n        run: |", "x }}\n        run: |")},
        "announce input check dropped": {ANNOUNCE_FILE: mut(ann, "      - name: Check the announcement\n", "      - name: Look at the announcement\n")},
        "announce input check after the key": {ANNOUNCE_FILE: mut(mut(ann, "      - name: Check the announcement\n", "      - name: Check the announcement (early)\n"), "      - name: Verify the new chain\n", "      - name: Check the announcement\n        run: python3 .github/release/announce_trust_chain.py check --chain .github/release/trust-chain.json\n\n      - name: Verify the new chain\n")},
        "announce verification dropped": {ANNOUNCE_FILE: mut(ann, "      - name: Verify the new chain\n", "      - name: Look at the new chain\n")},
        "announce verifies the wrong chain": {ANNOUNCE_FILE: mut(ann, "--new announce/trust-chain.json", "--new other.json")},
        "announce secret in another step": {ANNOUNCE_FILE: mut(ann, "      - name: Check the announcement\n        env:\n", "      - name: Check the announcement\n        env:\n          K: ${{ secrets.MANIFEST_SIGNING_KEY }}\n")},
        "announce secret in the job env": {ANNOUNCE_FILE: mut(ann, "    environment: release-signing\n    permissions:\n      contents: read\n", "    environment: release-signing\n    permissions:\n      contents: read\n    env:\n      K: ${{ secrets.MANIFEST_SIGNING_KEY }}\n")},
        "announce secret in the workflow env": {ANNOUNCE_FILE: mut(ann, "permissions:\n  contents: read\n\nconcurrency", "permissions:\n  contents: read\n\nenv:\n  K: ${{ secrets.MANIFEST_SIGNING_KEY }}\n\nconcurrency")},
        "announce another secret": {ANNOUNCE_FILE: mut(ann, "          NEW_KEY_ID: ${{ inputs.new_key_id }}\n          NEW_PUBLIC_KEY_HEX: ${{ inputs.new_public_key_hex }}\n          ROOT_KEY_ID: ${{ vars.RELEASE_MANIFEST_KEY_ID }}\n          ROOT_PUBLIC_KEY_HEX: ${{ vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX }}\n        run: |\n          set -euo pipefail\n          mkdir announce", "          NEW_KEY_ID: ${{ inputs.new_key_id }}\n          NEW_PUBLIC_KEY_HEX: ${{ inputs.new_public_key_hex }}\n          ROOT_KEY_ID: ${{ vars.RELEASE_MANIFEST_KEY_ID }}\n          ROOT_PUBLIC_KEY_HEX: ${{ vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX }}\n          R2: ${{ secrets.R2_ENDPOINT }}\n        run: |\n          set -euo pipefail\n          mkdir announce")},
        "announce step loses the key id": {ANNOUNCE_FILE: mut(ann, "          MANIFEST_SIGNING_KEY_ID: ${{ secrets.MANIFEST_SIGNING_KEY_ID }}\n", "")},
        "announce root from elsewhere": {ANNOUNCE_FILE: mut(ann, "          ROOT_PUBLIC_KEY_HEX: ${{ vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX }}\n        run: |\n          set -euo pipefail\n          mkdir announce", "          ROOT_PUBLIC_KEY_HEX: ${{ vars.OTHER_KEY }}\n        run: |\n          set -euo pipefail\n          mkdir announce")},
        "announce chain from elsewhere": {ANNOUNCE_FILE: mut(ann, "            --chain .github/release/trust-chain.json \\\n            --add", "            --chain other.json \\\n            --add")},
        "announce adds another key": {ANNOUNCE_FILE: mut(ann, '--add "$NEW_KEY_ID:$NEW_PUBLIC_KEY_HEX"', "--add spare:abc")},
        "announce also revokes": {ANNOUNCE_FILE: mut(ann, '--out announce/trust-chain.json\n\n      - name: Verify', '--revoke root --out announce/trust-chain.json\n\n      - name: Verify')},
        "announce key id bound to another input": {ANNOUNCE_FILE: mut(ann, "NEW_KEY_ID: ${{ inputs.new_key_id }}\n          NEW_PUBLIC_KEY_HEX: ${{ inputs.new_public_key_hex }}\n          ROOT_KEY_ID: ${{ vars.RELEASE_MANIFEST_KEY_ID }}\n          ROOT_PUBLIC_KEY_HEX: ${{ vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX }}\n        run: |\n          set -euo pipefail\n          mkdir announce", "NEW_KEY_ID: ${{ inputs.new_public_key_hex }}\n          NEW_PUBLIC_KEY_HEX: ${{ inputs.new_public_key_hex }}\n          ROOT_KEY_ID: ${{ vars.RELEASE_MANIFEST_KEY_ID }}\n          ROOT_PUBLIC_KEY_HEX: ${{ vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX }}\n        run: |\n          set -euo pipefail\n          mkdir announce")},
        "announce input interpolated into a script": {ANNOUNCE_FILE: mut(ann, "          set -euo pipefail\n          mkdir announce\n", "          set -euo pipefail\n          echo ${{ inputs.new_key_id }}\n          mkdir announce\n")},
        "announce shell tracing": {ANNOUNCE_FILE: mut(ann, "          set -euo pipefail\n          mkdir announce\n", "          set -euxo pipefail\n          mkdir announce\n")},
        "announce environment dump": {ANNOUNCE_FILE: mut(ann, "          set -euo pipefail\n          mkdir announce\n", "          set -euo pipefail\n          printenv\n          mkdir announce\n")},
        "announce echo of the key": {ANNOUNCE_FILE: mut(ann, "          set -euo pipefail\n          mkdir announce\n", "          set -euo pipefail\n          echo \"$MANIFEST_SIGNING_KEY\"\n          mkdir announce\n")},
        "announce continue on error": {ANNOUNCE_FILE: mut(ann, "  announce:\n    needs: build-signer\n", "  announce:\n    continue-on-error: true\n    needs: build-signer\n")},
        "announce uploads the workspace": {ANNOUNCE_FILE: mut(ann, "          path: announce/trust-chain.json\n", "          path: .\n")},
        "announce uploads a wildcard": {ANNOUNCE_FILE: mut(ann, "          path: announce/trust-chain.json\n", "          path: announce/*\n")},
        "announce uploads a second artifact": {ANNOUNCE_FILE: ann + "\n      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2\n        with:\n          name: more\n          path: signer/yadorilink-sign-manifest\n"},
        "announce persists credentials": {ANNOUNCE_FILE: mut(ann, "  announce:\n    needs: build-signer\n    if: github.ref == 'refs/heads/main'\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    environment: release-signing\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false\n", "  announce:\n    needs: build-signer\n    if: github.ref == 'refs/heads/main'\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    environment: release-signing\n    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n")},
        "announce unpinned action": {ANNOUNCE_FILE: mut(ann, "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97", "actions/setup-python@v7")},
        "announce names another target": {ANNOUNCE_FILE: mut(ann, "name: Announce trust chain\n", f"name: Announce trust chain\n# {OTHER_TARGET} too\n")},
        "sign-manifest uploads the workspace": {SIGN_FILE: mut(sign, "          path: bundle/bundle.json\n", "          path: .\n")},
        "a new workflow with --key-hex": {"stray.yml": "name: x\non:\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: tool sign --key-hex abc\n"},
    }
    tool_cases: dict[str, tuple[str | None, list[str]]] = {
        "signer tool removed": (None, release_files),
        "signer tool names another target": (tool_text + f"\n# {OTHER_TARGET}\n", release_files),
        "signer tool accepts another target": (mut(tool_text, 'TARGETS = ("production",)', f'TARGETS = ("{OTHER_TARGET}", "production")'), release_files),
        "signer tool knows a second chain": (mut(tool_text, 'CHAIN_FILES = {"production": "trust-chain.json"}', f'CHAIN_FILES = {{"production": "trust-chain.json", "x": "x-trust-chain.json"}}'), release_files),
        "a second chain file appears": (tool_text, [*release_files, f"{OTHER_TARGET}-trust-chain.json"]),
        "a differently named chain file appears": (tool_text, [*release_files, "other-trust-chain.json"]),
    }
    failed = 0
    for name, (t, names) in tool_cases.items():
        if not tool_problems(t, names):
            print(f"self-test FAILED: mutation '{name}' was not caught")
            failed += 1
    for name, change in cases.items():
        if not problems_in({**files, **change}):
            print(f"self-test FAILED: mutation '{name}' was not caught")
            failed += 1
    # The retired writers must stay gone.
    for retired in ("update-controls.yml", "republish-update-manifest.yml"):
        if retired in files:
            print(f"self-test FAILED: {retired} is back")
            failed += 1
    total = len(cases) + len(tool_cases)
    print(f"self-test: {total - failed}/{total} mutations caught")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    root = Path(argv[1]) if len(argv) == 2 and argv[0] == "--root" else ROOT
    found = problems_in(load(root)) + tool_problems(*load_tool(root))
    for line in found:
        print(f"signing workflow check failed: {line}", file=sys.stderr)
    for retired in ("update-controls.yml", "republish-update-manifest.yml"):
        if retired in load(root):
            print(f"signing workflow check failed: {retired} must stay retired", file=sys.stderr)
            return 1
    if not found:
        print("signing workflow: ok")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
