#!/usr/bin/env python3
"""Required release gates: dev manifest key rejection, trust root, release config.

Usage: check-release-gates.py [--root DIR]          static wiring checks
       check-release-gates.py --config              also check the release key
                                                    in the environment
       check-release-gates.py --self-test

Static checks (over the working tree):
  * the development key listed here is the one the daemon still pins;
  * the release workflow's unprivileged engine-build job builds the daemon with
    that feature on every target, and it is the only job that builds or runs a
    binding generator (a pinned third-party tool): it has no environment, no
    secrets and read-only permissions;
  * the independent engine-attest job (needs engine-build) is the only job with
    id-token/attestations: exactly contents: read, id-token: write,
    attestations: write; no environment, secrets, vars, generator, cargo or
    build step; it downloads only this run's engine-build artifact, re-verifies
    it by hash and creates the build-provenance attestation (pinned by SHA);
  * the protected engine-bundle job needs engine-attest, runs
    `gh attestation verify` (this repository, its release.yml, the commit)
    before it hashes or writes provenance, then only downloads that artifact,
    verifies it by hash and writes provenance with the bundle's release gates
    and the attestation identity; it has no build, toolchain or generator step;
  * the release workflow has an unconditional `release-gates` job that runs
    this script, and every job that publishes or builds a release artifact
    lists it in `needs`.

--config checks the release manifest key from YADORILINK_RELEASE_MANIFEST_KEY_ID
and YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX: both set, the key 64 hex
characters, and not the development key. It never prints the key material
beyond a length/shape message.

--self-test mutates copies of the real files to bypass each gate and requires
the check to fail for every bypass.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEV_KEY = "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3"
FEATURE = "yadorilink-daemon/enforce-release-trust-root"
# The release workflow lives in the overlay directory in the source tree and at
# .github/workflows in the published tree; whichever exists is the one checked.
WORKFLOW = next(
    (p for p in ("oss-public/.github/workflows/release.yml", ".github/workflows/release.yml") if (ROOT / p).is_file()),
    ".github/workflows/release.yml",
)
MANIFEST = "crates/yadorilink-daemon/src/update/manifest.rs"
BUNDLE_BUILDER = ".github/release/build-engine-bundle.py"
LAYOUT_DOC = ".github/release/engine-bundle-layout.md"
FILES = (WORKFLOW, MANIFEST, BUNDLE_BUILDER, LAYOUT_DOC)
# Every bundle target ships these two files: the pointer to its corresponding
# source and the third-party licence notice. The builder adds them to every
# layout (NOTICE_FILES), verify requires them, and the layout doc lists them.
NOTICE_FILES = ("SOURCE.txt", "THIRD-PARTY-LICENSES")
NOTICE_GENERATOR = "generate-third-party-licenses.sh"
GATE_JOB = "release-gates"
# Jobs that hold the release environment also verify the release key itself.
CONFIG_JOBS = ("engine-build", "engine-bundle", "nightly-release", "beta-release")
CONFIG_COMMAND = "python3 .github/release/check-release-gates.py --config"
# The update manifest is signed only by sign-manifest.yml; check-signing-workflow.py enforces
# that (no job of this workflow may build, sign or publish a manifest).
GATED_JOBS = ("engine-build", "engine-attest", "engine-bundle", "nightly-release", "beta-release")
UNPRIVILEGED_JOB = "engine-build"
ATTEST_JOB = "engine-attest"
ATTEST_PERMISSIONS = {"contents": "read", "id-token": "write", "attestations": "write"}
ATTEST_ACTION_RE = re.compile(r"uses: actions/attest(-build-provenance)?@[0-9a-f]{40}\b")
IDENTITY_PERMISSION_RE = re.compile(r"\b(id-token|attestations|artifact-metadata)\s*:")
PROTECTED_BUNDLE_JOB = "engine-bundle"
# Anything that builds or runs the pinned third-party generators. Only the
# unprivileged job may mention these (comments are ignored).
GENERATOR_RE = re.compile(r"generate-(csharp|swift)-binding|csharp-bindgen|uniffi-bindgen")
# Build steps that have no place in the protected bundle job.
PROTECTED_FORBIDDEN_RE = re.compile(r"cargo |cargo-about|generate-third-party-licenses|rust-toolchain|setup-protoc|build-engine-bundle\.py build|check-engine-artifact")
GATE_COMMANDS = (
    "python3 .github/release/check-release-gates.py --self-test",
    "python3 .github/release/build-engine-bundle.py --self-test",
    "python3 .github/release/csharp-binding.py --self-test",
    "python3 .github/release/third-party-licenses.py --self-test",
    "python3 .github/checks/check-engine-artifact.py --self-test",
    "python3 .github/checks/validate-engine-identity.py --self-test",
    "python3 .github/checks/check-release-dir-secrets.py --self-test",
    "python3 .github/release/check-signing-workflow.py",
    "python3 .github/release/check-signing-workflow.py --self-test",
    "python3 .github/release/test_sign_request.py",
)


def jobs(workflow: str) -> dict[str, str]:
    body = workflow[workflow.index("\njobs:\n"):]
    starts = [(m.start(), m.group(1)) for m in re.finditer(r"^  ([A-Za-z0-9_-]+):\s*$", body, re.M)]
    return {
        name: body[start: starts[i + 1][0] if i + 1 < len(starts) else len(body)]
        for i, (start, name) in enumerate(starts)
    }


def code_only(text: str) -> str:
    """The text without full-line YAML comments."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def needs(job: str) -> set[str]:
    inline = re.search(r"^    needs:\s*\[([^\]]*)\]", job, re.M)
    if inline:
        return {n.strip() for n in inline.group(1).split(",") if n.strip()}
    single = re.search(r"^    needs:\s*([A-Za-z0-9_-]+)\s*$", job, re.M)
    if single:
        return {single.group(1)}
    block = re.search(r"^    needs:\s*\n((?:      - .*\n?)+)", job, re.M)
    return {line.strip()[2:].strip() for line in block.group(1).splitlines()} if block else set()


def static_problems(root: Path) -> list[str]:
    def read(rel: str) -> str:
        try:
            return (root / rel).read_text(encoding="utf-8")
        except OSError as e:
            return f"\0unreadable {rel}: {e}"

    out = []
    manifest, workflow = read(MANIFEST), read(WORKFLOW)
    if f'public_key_hex: "{DEV_KEY}"' not in manifest:
        out.append(f"{MANIFEST} no longer pins the development key this gate rejects")

    if workflow.startswith("\0") or "\njobs:\n" not in workflow:
        return out + [f"{WORKFLOW} is unreadable or has no jobs"]
    all_jobs = jobs(workflow)
    gate = all_jobs.get(GATE_JOB)
    if gate is None:
        return out + [f"{WORKFLOW} has no {GATE_JOB} job"]
    if re.search(r"^    if:", gate, re.M):
        out.append(f"{GATE_JOB} must run unconditionally (no job-level if)")
    if "continue-on-error" in gate:
        out.append(f"{GATE_JOB} must not use continue-on-error")
    if "--config" in gate:
        out.append(f"{GATE_JOB} has no release environment; verify the key with --config in the jobs that do")
    for line in gate.splitlines():
        if "continue-on-error" in line or re.search(r"\|\|\s*true\b", line):
            out.append(f"{GATE_JOB} must not swallow failures: {line.strip()}")
    for cmd in GATE_COMMANDS:
        if cmd not in gate:
            out.append(f"{GATE_JOB} must run: {cmd}")
    for name in GATED_JOBS:
        if name not in all_jobs:
            out.append(f"{WORKFLOW} has no {name} job")
        elif GATE_JOB not in needs(all_jobs[name]):
            out.append(f"{name} must list {GATE_JOB} in needs")
    build_job = all_jobs.get(UNPRIVILEGED_JOB, "")
    if build_job.count(FEATURE) < 3:
        out.append(f"{UNPRIVILEGED_JOB} must build the daemon with enforce-release-trust-root on every target and record it")
    if not re.search(r"^    permissions:\s*\n      contents: read\s*$", build_job, re.M):
        out.append(f"{UNPRIVILEGED_JOB} must set job permissions to contents: read only")
    if re.search(r"^    environment:", build_job, re.M):
        out.append(f"{UNPRIVILEGED_JOB} runs third-party generators and must not use a protected environment")
    if "secrets." in code_only(build_job):
        out.append(f"{UNPRIVILEGED_JOB} must not reference secrets")
    if "ENGINE_PROVENANCE_SIGN_CMD" in build_job or "--sign-cmd" in build_job:
        out.append(f"{UNPRIVILEGED_JOB} must not hold the provenance signing hook")
    if "generate-csharp-binding.sh" not in code_only(build_job):
        out.append(f"{UNPRIVILEGED_JOB} must generate the C# binding")
    if NOTICE_GENERATOR not in code_only(build_job) or "--third-party-licenses" not in code_only(build_job):
        out.append(f"{UNPRIVILEGED_JOB} must generate the third-party licenses and pass them to the bundle build")
    builder, layout_doc = read(BUNDLE_BUILDER), read(LAYOUT_DOC)
    notice_line = re.search(r"^NOTICE_FILES = \((.*)\)\s*$", builder, re.M)
    reserved_line = re.search(r"^RESERVED = \((.*)\)\s*$", builder, re.M)
    for name in NOTICE_FILES:
        if not notice_line or f'"{name}"' not in notice_line.group(1):
            out.append(f"{BUNDLE_BUILDER} NOTICE_FILES must list {name}, shipped in every bundle target")
        if not reserved_line or "NOTICE_FILES" not in reserved_line.group(1):
            out.append(f"{BUNDLE_BUILDER} RESERVED must include NOTICE_FILES so verify requires {name}")
        if f"`{name}`" not in layout_doc:
            out.append(f"{LAYOUT_DOC} must list {name} for every bundle target")
    if builder.startswith("\0") or "for need in RESERVED:" not in builder:
        out.append(f"{BUNDLE_BUILDER} verify must require every RESERVED file")
    for name, job in all_jobs.items():
        if name != UNPRIVILEGED_JOB and GENERATOR_RE.search(code_only(job)):
            out.append(f"{name} must not build or run a binding generator; only {UNPRIVILEGED_JOB} (unprivileged) may")
    bundle = all_jobs.get(PROTECTED_BUNDLE_JOB, "")
    if UNPRIVILEGED_JOB not in needs(bundle):
        out.append(f"{PROTECTED_BUNDLE_JOB} must list {UNPRIVILEGED_JOB} in needs")
    if not re.search(r"^    environment: release-signing\s*$", bundle, re.M):
        out.append(f"{PROTECTED_BUNDLE_JOB} must run in the release-signing environment")
    if PROTECTED_FORBIDDEN_RE.search(code_only(bundle)):
        out.append(f"{PROTECTED_BUNDLE_JOB} must only download, verify by hash and attest; no build or execution of artifact content")
    verify_at = bundle.find("build-engine-bundle.py verify")
    attest_at = bundle.find("build-engine-bundle.py provenance")
    if verify_at < 0 or attest_at < 0 or verify_at > attest_at:
        out.append(f"{PROTECTED_BUNDLE_JOB} must verify the downloaded bundle before writing provenance")
    for gate_flag in ("--gate release-gates", "--gate release-config"):
        if gate_flag not in bundle:
            out.append(f"{PROTECTED_BUNDLE_JOB} must attest the bundle with {gate_flag}")
    out += attest_problems(workflow, all_jobs, bundle)
    out += installer_problems(all_jobs)
    for name in CONFIG_JOBS:
        job = all_jobs.get(name, "")
        step = re.search(r"^ +run: " + re.escape(CONFIG_COMMAND) + r"\s*$", job, re.M)
        if not step or "vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX" not in job or "vars.RELEASE_MANIFEST_KEY_ID" not in job:
            out.append(f"{name} must run {CONFIG_COMMAND} with the release key variables")
        elif re.search(r"continue-on-error|" + re.escape(CONFIG_COMMAND) + r"\s*\|\|", job):
            out.append(f"{name} must not swallow a --config failure")
    return out


def permission_map(job: str) -> dict[str, str] | None:
    block = re.search(r"^    permissions:\s*\n((?:      [A-Za-z-]+: *\w+ *\n?)+)", job, re.M)
    if not block:
        return None
    return {k.strip(): v.strip() for k, v in (line.split(":", 1) for line in block.group(1).splitlines() if line.strip())}


def installer_problems(all_jobs: dict[str, str]) -> list[str]:
    """beta-release releases the installers only after re-verifying their attestation."""
    code = code_only(all_jobs.get("beta-release", ""))
    step = re.search(r"- name: Add the installers\n(?:        .*\n|\n)+", code)
    if not step:
        return ["beta-release must have the 'Add the installers' step"]
    body = step.group(0)
    out = []
    for needed in ("python3 packaging/install/pins.py check", 'gh attestation verify "packaging/install/$f"',
                   "--repo ${{ github.repository }}", "--signer-workflow ${{ github.repository }}/.github/workflows/release.yml",
                   "--source-digest ${{ github.sha }}", "--source-ref ${{ github.ref }}",
                   "generate-release-checksums.py --sidecars dist/install.sh dist/install.ps1"):
        if needed not in body:
            out.append(f"beta-release 'Add the installers' must contain: {needed}")
    if "||" in body or "continue-on-error" in body:
        out.append("beta-release 'Add the installers' must not swallow a failure")
    return out


def attest_problems(workflow: str, all_jobs: dict[str, str], bundle: str) -> list[str]:
    out = []
    attest = all_jobs.get(ATTEST_JOB)
    if attest is None:
        return [f"{WORKFLOW} has no {ATTEST_JOB} job"]
    code = code_only(attest)
    if UNPRIVILEGED_JOB not in needs(attest):
        out.append(f"{ATTEST_JOB} must list {UNPRIVILEGED_JOB} in needs")
    if permission_map(attest) != ATTEST_PERMISSIONS:
        out.append(f"{ATTEST_JOB} permissions must be exactly {ATTEST_PERMISSIONS}")
    if re.search(r"^    environment:", attest, re.M):
        out.append(f"{ATTEST_JOB} must not use a protected environment")
    if "secrets." in code or "vars." in code:
        out.append(f"{ATTEST_JOB} must not reference secrets or variables")
    if "ENGINE_PROVENANCE_SIGN_CMD" in code or "--sign-cmd" in code:
        out.append(f"{ATTEST_JOB} must not hold the provenance signing hook")
    if GENERATOR_RE.search(code) or PROTECTED_FORBIDDEN_RE.search(code):
        out.append(f"{ATTEST_JOB} must not build, run a generator or execute artifact content")
    if "continue-on-error" in code or re.search(r"\|\|\s*true\b", code):
        out.append(f"{ATTEST_JOB} must not swallow failures")
    if re.search(r"^\s+(run-id|repository|github-token):", code, re.M):
        out.append(f"{ATTEST_JOB} must download only this run's artifact (no run-id, repository or token input)")
    if code.count("actions/download-artifact@") != 1 or "name: engine-build-${{ matrix.target }}" not in code:
        out.append(f"{ATTEST_JOB} must download exactly the engine-build-<target> artifact")
    if len(ATTEST_ACTION_RE.findall(code)) != 1:
        out.append(f"{ATTEST_JOB} must create the attestation with actions/attest(-build-provenance) pinned by commit SHA")
    verify_at, attest_at = attest.find("build-engine-bundle.py verify"), attest.find("uses: actions/attest")
    if verify_at < 0 or attest_at < 0 or verify_at > attest_at:
        out.append(f"{ATTEST_JOB} must verify the bundle by hash before attesting it")
    if not re.search(r"subject-path: \|\n\s+engine-unverified/\*\.zip\n\s+packaging/install/install\.sh\n\s+packaging/install/install\.ps1\n", code):
        out.append(f"{ATTEST_JOB} must attest exactly the verified bundle zip and the two installers")
    pins_at = code.find("python3 packaging/install/pins.py check\n")
    if pins_at < 0 or pins_at > code.find("uses: actions/attest"):
        out.append(f"{ATTEST_JOB} must check the installer pins before attesting the installers")
    if "pins.py check --require-verifier" not in code or "if: startsWith(github.ref, 'refs/tags/v')" not in code[code.find("pins.py check --require-verifier") - 200:code.find("pins.py check --require-verifier")]:
        out.append(f"{ATTEST_JOB} must require the verifier pins on a release tag")
    for name, job in all_jobs.items():
        if name != ATTEST_JOB and IDENTITY_PERMISSION_RE.search(code_only(job)):
            out.append(f"{name} must not hold id-token, attestations or artifact-metadata; only {ATTEST_JOB} may")
    if IDENTITY_PERMISSION_RE.search(code_only(workflow[: workflow.index("\njobs:\n")])):
        out.append("workflow-level permissions must not grant id-token, attestations or artifact-metadata")
    if ATTEST_JOB not in needs(bundle):
        out.append(f"{PROTECTED_BUNDLE_JOB} must list {ATTEST_JOB} in needs")
    code_b = code_only(bundle)
    step = re.search(r"gh attestation verify[^\n\\]*(?:\\\n[^\n\\]*)*", code_b)
    if not step:
        out.append(f"{PROTECTED_BUNDLE_JOB} must run gh attestation verify")
        return out
    cmd = step.group(0)
    for needed, label in [
        ("--repo ${{ github.repository }}", "pin the repository"),
        ("--signer-workflow ${{ github.repository }}/.github/workflows/release.yml", "pin the signer workflow"),
        ("--source-digest ${{ github.sha }}", "pin the source digest"),
        ("--source-ref ${{ github.ref }}", "pin the source ref"),
    ]:
        if needed not in cmd:
            out.append(f"{PROTECTED_BUNDLE_JOB} gh attestation verify must {label}: {needed}")
    if "--format json" not in cmd:
        out.append(f"{PROTECTED_BUNDLE_JOB} gh attestation verify must write --format json for the provenance statement")
    if re.search(r"gh attestation verify[^\n]*\|\|", code_b) or "||" in cmd:
        out.append(f"{PROTECTED_BUNDLE_JOB} must not swallow a gh attestation verify failure")
    first_hash, prov_at = code_b.find("build-engine-bundle.py verify"), code_b.find("build-engine-bundle.py provenance")
    verify_att = step.start()
    if not (verify_att < first_hash < prov_at):
        out.append(f"{PROTECTED_BUNDLE_JOB} must verify the attestation before the hash check and provenance")
    lock_at = code_b.find("build-engine-bundle.py lock")
    if lock_at < prov_at or "--public-commit-sha" not in code_b[lock_at:]:
        out.append(f"{PROTECTED_BUNDLE_JOB} must write the engine.lock asset (build-engine-bundle.py lock) from the verified bundle, after provenance")
    if "--attestation-json" not in code_b or "--repository" not in code_b[prov_at:]:
        out.append(f"{PROTECTED_BUNDLE_JOB} must record the attestation identity in the provenance statement")
    return out


def config_problems(env) -> list[str]:
    key_id = env.get("YADORILINK_RELEASE_MANIFEST_KEY_ID", "").strip()
    key = env.get("YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX", "").strip()
    out = []
    if not key_id:
        out.append("YADORILINK_RELEASE_MANIFEST_KEY_ID is not set")
    if not key:
        out.append("YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX is not set")
    elif not re.fullmatch(r"[0-9a-fA-F]{64}", key):
        out.append("YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX must be exactly 64 hexadecimal characters")
    elif key.lower() == DEV_KEY:
        out.append("the release manifest public key is the known development key")
    return out


def self_test() -> int:
    assert static_problems(ROOT) == [], static_problems(ROOT)
    good_env = {"YADORILINK_RELEASE_MANIFEST_KEY_ID": "k1", "YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX": "ab" * 32}
    assert config_problems(good_env) == []
    for label, change in [
        ("dev key", {"YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX": DEV_KEY.upper()}),
        ("short key", {"YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX": "ab"}),
        ("empty key", {"YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX": ""}),
        ("empty key id", {"YADORILINK_RELEASE_MANIFEST_KEY_ID": " "}),
    ]:
        assert config_problems({**good_env, **change}), label
    assert config_problems({}), "unset config"

    mutations: list[tuple[str, str, object]] = [
        ("generator moved into the signing job", WORKFLOW, lambda t: move_generator_to_signing_job(t)),
        ("generator job gets the signing environment", WORKFLOW, lambda t: add_to_job(t, UNPRIVILEGED_JOB, "    environment: release-signing\n")),
        ("generator job gets a secret", WORKFLOW, lambda t: t.replace("GITHUB_TOKEN: ${{ github.token }}", "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}", 1)),
        ("generator job loses read-only permissions", WORKFLOW, lambda t: drop_in_job(t, UNPRIVILEGED_JOB, "    permissions:\n      contents: read\n")),
        ("generator job holds the signing hook", WORKFLOW, lambda t: add_to_job(t, UNPRIVILEGED_JOB, "    # ENGINE_PROVENANCE_SIGN_CMD\n").replace("# ENGINE_PROVENANCE_SIGN_CMD", "x: ${{ vars.ENGINE_PROVENANCE_SIGN_CMD }}")),
        ("signing job builds with cargo", WORKFLOW, lambda t: t.replace("      - name: Re-verify the bundle by hash only\n", "      - run: cargo build --release\n      - name: Re-verify the bundle by hash only\n")),
        ("signing job stops verifying", WORKFLOW, lambda t: t.replace("build-engine-bundle.py verify", "true")),
        ("signing job no longer needs the build", WORKFLOW, lambda t: drop_in_job(t, PROTECTED_BUNDLE_JOB, "      - engine-build\n")),
        ("bundle trust-root feature removed", WORKFLOW, lambda t: t.replace(FEATURE, "yadorilink-daemon/other")),
        ("bundle release-config gate removed", WORKFLOW, lambda t: t.replace("--gate release-config", "")),
        ("daemon dev key changed", MANIFEST, lambda t: t.replace(DEV_KEY, "1" * 64, 1)),
        ("gate job removed", WORKFLOW, lambda t: t.replace("\n  release-gates:\n", "\n  release-gates-renamed:\n")),
        ("gate job made conditional", WORKFLOW, lambda t: t.replace("\n  release-gates:\n", "\n  release-gates:\n    if: false\n")),
        ("gate failures swallowed", WORKFLOW, lambda t: t.replace("check-release-gates.py --self-test", "check-release-gates.py --self-test || true")),
        ("gate self-test dropped", WORKFLOW, lambda t: t.replace("check-release-gates.py --self-test", "true")),
        ("config check swallowed", WORKFLOW, lambda t: t.replace(CONFIG_COMMAND, CONFIG_COMMAND + " || true")),
        ("config check dropped", WORKFLOW, lambda t: t.replace(CONFIG_COMMAND, "true")),
        ("third-party licenses step dropped", WORKFLOW, lambda t: t.replace(NOTICE_GENERATOR, "true")),
        ("third-party licenses not passed to the bundle", WORKFLOW, lambda t: t.replace("--third-party-licenses", "--other")),
        ("third-party licenses generated in the signing job", WORKFLOW, lambda t: t.replace("      - name: Re-verify the bundle by hash only\n", "      - run: cargo about generate\n      - name: Re-verify the bundle by hash only\n")),
        ("SOURCE.txt dropped from every bundle", BUNDLE_BUILDER, lambda t: t.replace('NOTICE_FILES = ("LICENSE", "SOURCE.txt", "THIRD-PARTY-LICENSES")', 'NOTICE_FILES = ("LICENSE", "THIRD-PARTY-LICENSES")')),
        ("THIRD-PARTY-LICENSES dropped from every bundle", BUNDLE_BUILDER, lambda t: t.replace('NOTICE_FILES = ("LICENSE", "SOURCE.txt", "THIRD-PARTY-LICENSES")', 'NOTICE_FILES = ("LICENSE", "SOURCE.txt")')),
        ("notice files no longer required by verify", BUNDLE_BUILDER, lambda t: t.replace('RESERVED = (*NOTICE_FILES, ', 'RESERVED = (')),
        ("verify stops requiring reserved files", BUNDLE_BUILDER, lambda t: t.replace("for need in RESERVED:", "for need in ():")),
        ("layout doc drops SOURCE.txt", LAYOUT_DOC, lambda t: t.replace("`SOURCE.txt`", "`X`")),
        ("layout doc drops THIRD-PARTY-LICENSES", LAYOUT_DOC, lambda t: t.replace("`THIRD-PARTY-LICENSES`", "`X`")),
        ("engine-build gains id-token", WORKFLOW, lambda t: add_perm(t, UNPRIVILEGED_JOB, "      id-token: write\n")),
        ("engine-build gains attestations", WORKFLOW, lambda t: add_perm(t, UNPRIVILEGED_JOB, "      attestations: write\n")),
        ("workflow-level id-token", WORKFLOW, lambda t: t.replace("permissions:\n  contents: read\n", "permissions:\n  contents: read\n  id-token: write\n", 1)),
        ("engine-bundle gains id-token", WORKFLOW, lambda t: add_perm(t, PROTECTED_BUNDLE_JOB, "      id-token: write\n")),
        ("engine-attest job removed", WORKFLOW, lambda t: t.replace("\n  engine-attest:\n", "\n  engine-attest-renamed:\n")),
        ("engine-attest loses id-token", WORKFLOW, lambda t: drop_in_job(t, ATTEST_JOB, "      id-token: write\n")),
        ("engine-attest loses attestations", WORKFLOW, lambda t: drop_in_job(t, ATTEST_JOB, "      attestations: write\n")),
        ("engine-attest gains write-all contents", WORKFLOW, lambda t: t.replace("    permissions:\n      contents: read\n      id-token: write", "    permissions:\n      contents: write\n      id-token: write", 1)),
        ("engine-attest gains artifact-metadata", WORKFLOW, lambda t: add_perm(t, ATTEST_JOB, "      artifact-metadata: write\n")),
        ("engine-attest gets an environment", WORKFLOW, lambda t: add_to_job(t, ATTEST_JOB, "    environment: release-signing\n")),
        ("engine-attest gets a secret", WORKFLOW, lambda t: add_to_job(t, ATTEST_JOB, "    env:\n      X: ${{ secrets.GITHUB_TOKEN }}\n")),
        ("engine-attest gets a variable", WORKFLOW, lambda t: add_to_job(t, ATTEST_JOB, "    env:\n      X: ${{ vars.ENGINE_PROVENANCE_SIGN_CMD }}\n")),
        ("engine-attest runs a generator", WORKFLOW, lambda t: t.replace("      - name: Attest the bundle\n", "      - run: .github/release/generate-csharp-binding.sh\n      - name: Attest the bundle\n", 1)),
        ("engine-attest runs cargo", WORKFLOW, lambda t: t.replace("      - name: Attest the bundle\n", "      - run: cargo build --release\n      - name: Attest the bundle\n", 1)),
        ("engine-attest builds the bundle", WORKFLOW, lambda t: t.replace("      - name: Attest the bundle\n", "      - run: python3 .github/release/build-engine-bundle.py build\n      - name: Attest the bundle\n", 1)),
        ("engine-attest no longer needs engine-build", WORKFLOW, lambda t: drop_in_job(t, ATTEST_JOB, "      - engine-build\n")),
        ("engine-attest downloads another run", WORKFLOW, lambda t: t.replace("          path: engine-unverified\n\n      - name: Re-verify the bundle by hash only\n", "          path: engine-unverified\n          run-id: 1\n\n      - name: Re-verify the bundle by hash only\n", 1)),
        ("engine-attest action unpinned", WORKFLOW, lambda t: re.sub(r"actions/attest-build-provenance@[0-9a-f]{40}", "actions/attest-build-provenance@v4", t, 1)),
        ("engine-attest attests before verifying", WORKFLOW, lambda t: swap_attest_verify(t)),
        ("engine-attest attests only the bundle", WORKFLOW, lambda t: t.replace("            packaging/install/install.ps1\n", "", 1)),
        ("engine-attest skips the installer pin check", WORKFLOW, lambda t: t.replace("        run: python3 packaging/install/pins.py check\n", "        run: echo skipped\n", 1)),
        ("engine-attest drops the verifier pin requirement", WORKFLOW, lambda t: t.replace("pins.py check --require-verifier", "pins.py check", 1)),
        ("beta-release drops the installer step", WORKFLOW, lambda t: t.replace("- name: Add the installers", "- name: Add something", 1)),
        ("beta-release drops the installer attestation verify", WORKFLOW, lambda t: t.replace('gh attestation verify "packaging/install/$f"', 'true "packaging/install/$f"', 1)),
        ("beta-release drops the installer sidecars", WORKFLOW, lambda t: t.replace("--sidecars dist/install.sh dist/install.ps1", "--sidecars dist/install.sh", 1)),
        ("engine-attest swallows failures", WORKFLOW, lambda t: add_to_job(t, ATTEST_JOB, "    continue-on-error: true\n")),
        ("engine-bundle no longer needs engine-attest", WORKFLOW, lambda t: drop_in_job(t, PROTECTED_BUNDLE_JOB, "      - engine-attest\n")),
        ("engine-bundle drops the attestation verify", WORKFLOW, lambda t: t.replace("gh attestation verify", "true")),
        ("attestation verify drops the repo pin", WORKFLOW, lambda t: t.replace("            --repo ${{ github.repository }} \\\n", "")),
        ("attestation verify hard-codes the repo", WORKFLOW, lambda t: t.replace("--repo ${{ github.repository }}", "--repo o/r", 1)),
        ("attestation verify drops the signer pin", WORKFLOW, lambda t: t.replace("            --signer-workflow ${{ github.repository }}/.github/workflows/release.yml \\\n", "")),
        ("attestation verify drops the source digest pin", WORKFLOW, lambda t: t.replace("            --source-digest ${{ github.sha }} \\\n", "")),
        ("attestation verify drops the source ref pin", WORKFLOW, lambda t: t.replace("            --source-ref ${{ github.ref }} \\\n", "")),
        ("attestation verify drops the JSON output", WORKFLOW, lambda t: t.replace("            --format json > \"$RUNNER_TEMP/attestation.json\"", "            > \"$RUNNER_TEMP/attestation.json\"")),
        ("attestation verify failure swallowed", WORKFLOW, lambda t: t.replace("--format json > \"$RUNNER_TEMP/attestation.json\"", "--format json > \"$RUNNER_TEMP/attestation.json\" || true", 1)),
        ("attestation verified after provenance", WORKFLOW, lambda t: swap_bundle_steps(t)),
        ("provenance drops the attestation identity", WORKFLOW, lambda t: t.replace("            --attestation-json \"$RUNNER_TEMP/attestation.json\" \\\n", "")),
        ("engine.lock asset step dropped", WORKFLOW, lambda t: t.replace("build-engine-bundle.py lock", "true")),
        ("bundle self-test dropped", WORKFLOW, lambda t: t.replace("build-engine-bundle.py --self-test", "true")),
    ]
    for name in GATED_JOBS:
        mutations.append((
            f"{name} no longer needs the gate",
            WORKFLOW,
            lambda t, name=name: drop_need(t, name),
        ))
    for label, rel, mutate in mutations:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            for f in FILES:
                (tmp / f).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(ROOT / f, tmp / f)
            original = (tmp / rel).read_text(encoding="utf-8")
            changed = mutate(original)
            assert changed != original, f"mutation {label!r} did not change {rel}"
            (tmp / rel).write_text(changed, encoding="utf-8")
            assert static_problems(tmp), f"bypass not detected: {label}"
    print("ok")
    return 0


def job_span(workflow: str, job: str) -> tuple[int, int]:
    header = f"\n  {job}:\n"
    start = workflow.index(header)
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\s*$", workflow[start + len(header):], re.M)
    return start, start + len(header) + nxt.start() if nxt else len(workflow)


def add_to_job(workflow: str, job: str, text: str) -> str:
    """Insert a job-level line right after the job header."""
    start, _ = job_span(workflow, job)
    at = start + len(f"\n  {job}:\n")
    return workflow[:at] + text + workflow[at:]


def drop_in_job(workflow: str, job: str, text: str) -> str:
    start, end = job_span(workflow, job)
    body = workflow[start:end]
    assert text in body, text
    return workflow[:start] + body.replace(text, "", 1) + workflow[end:]


def move_generator_to_signing_job(workflow: str) -> str:
    """Take the generator step out of the unprivileged job and put it in the signing job."""
    start, end = job_span(workflow, UNPRIVILEGED_JOB)
    body = workflow[start:end]
    step = re.search(r"      - name: Generate the C# binding\n(?:        .*\n|\n)+?(?=      - name:)", body)
    assert step, "generator step not found"
    workflow = workflow[:start] + body.replace(step.group(0), "", 1) + workflow[end:]
    marker = "      - name: Re-verify the bundle by hash only\n"
    return workflow.replace(marker, step.group(0) + marker, 1)


def add_perm(workflow: str, job: str, line: str) -> str:
    """Add a permission line to a job's permissions block."""
    marker = "    permissions:\n"
    start, end = job_span(workflow, job)
    body = workflow[start:end]
    assert marker in body, job
    return workflow[:start] + body.replace(marker, marker + line, 1) + workflow[end:]


def swap_attest_verify(workflow: str) -> str:
    """Put the attest step ahead of the hash re-verification in engine-attest."""
    start, end = job_span(workflow, ATTEST_JOB)
    body = workflow[start:end]
    i, j = body.index("      - name: Re-verify the bundle by hash only\n"), body.index("      - name: Attest the bundle\n")
    return workflow[:start] + body[:i] + body[j:] + "\n" + body[i:j] + workflow[end:]


def swap_bundle_steps(workflow: str) -> str:
    """Move the attestation verify step after provenance in engine-bundle."""
    start, end = job_span(workflow, PROTECTED_BUNDLE_JOB)
    body = workflow[start:end]
    i, j = body.index("      - name: Verify the attestation\n"), body.index("      - name: Re-verify the bundle by hash only\n")
    step = body[i:j]
    body = body[:i] + body[j:]
    k = body.index("      - uses: actions/upload-artifact")
    return workflow[:start] + body[:k] + step + body[k:] + workflow[end:]


def drop_need(workflow: str, job: str) -> str:
    """Remove the release-gates entry from one job's needs."""
    header = f"\n  {job}:\n"
    start = workflow.index(header)
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\s*$", workflow[start + len(header):], re.M)
    end = start + len(header) + nxt.start() if nxt else len(workflow)
    body = workflow[start:end]
    new = re.sub(r"\n      - release-gates\b[^\n]*", "", body)
    new = re.sub(r"(needs:\s*)\[([^\]]*)\]", lambda m: m.group(1) + "[" + ", ".join(
        x.strip() for x in m.group(2).split(",") if x.strip() and x.strip() != GATE_JOB) + "]", new)
    new = re.sub(r"(needs:\s*)release-gates\s*\n", r"\1[]\n", new)
    return workflow[:start] + new + workflow[end:]


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    root = ROOT
    if "--root" in argv:
        root = Path(argv[argv.index("--root") + 1])
    found = static_problems(root)
    if "--config" in argv:
        found += config_problems(os.environ)
    for line in found:
        print(f"release gate failed: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
