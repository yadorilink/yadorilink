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
MANAGER = "crates/yadorilink-daemon/src/update/manager.rs"
CHANNEL_LEDGER = ".github/release/channel_ledger.py"
BUNDLE_BUILDER = ".github/release/build-engine-bundle.py"
LAYOUT_DOC = ".github/release/engine-bundle-layout.md"
SIGN_SCRIPT = ".github/release/macos-sign-notarize.sh"
REHEARSAL = str(Path(WORKFLOW).with_name("macos-sign-rehearsal.yml"))
FILES = (WORKFLOW, MANIFEST, MANAGER, CHANNEL_LEDGER, BUNDLE_BUILDER, LAYOUT_DOC, SIGN_SCRIPT, REHEARSAL)
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
GATED_JOBS = ("engine-build", "engine-attest", "engine-sign-macos", "engine-attest-signed", "engine-bundle", "nightly-release", "beta-release")
UNPRIVILEGED_JOB = "engine-build"
ATTEST_JOB = "engine-attest"
SIGN_JOB = "engine-sign-macos"
SIGNED_ATTEST_JOB = "engine-attest-signed"
SIGN_STEP = "Sign and notarize"
# The only places the Developer ID certificate and the notary API key may be referenced.
MACOS_SECRETS = ("MACOS_DEVELOPER_ID_APP_P12_BASE64", "MACOS_DEVELOPER_ID_APP_P12_PASSWORD", "MACOS_NOTARY_ISSUER_ID",
                 "MACOS_NOTARY_KEY_ID", "MACOS_NOTARY_KEY_P8_BASE64")
MACOS_SECRET_RE = re.compile(r"MACOS_(?:DEVELOPER_ID|NOTARY)\w*")
ATTEST_PERMISSIONS = {"contents": "read", "id-token": "write", "attestations": "write"}
ATTEST_ACTION_RE = re.compile(r"uses: actions/attest(-build-provenance)?@[0-9a-f]{40}\b")
IDENTITY_PERMISSION_RE = re.compile(r"\b(id-token|attestations|artifact-metadata)\s*:")
PROTECTED_BUNDLE_JOB = "engine-bundle"
# Anything that builds or runs the pinned third-party generators. Only the
# unprivileged job may mention these (comments are ignored).
GENERATOR_RE = re.compile(r"generate-(csharp|swift|ios)-binding|csharp-bindgen|uniffi-bindgen")
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
    "python3 .github/release/announce_trust_chain.py --self-test",
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


def freshness_problems(read) -> list[str]:
    """The manifest freshness policy (update manifest freshness policy): the publisher's
    window and skew limits are sane, and the client judges expiry and future dating before the
    replay floor can move, so a refused manifest never counts as accepted."""
    out = []
    ledger, manager, manifest = read(CHANNEL_LEDGER), read(MANAGER), read(MANIFEST)

    def number(pattern: str, text: str):
        m = re.search(pattern, text, re.M)
        return int(m.group(1)) if m else None

    validity = number(r"^VALIDITY_DAYS = (\d+)\s*$", ledger)
    reminder = number(r"^REMINDER_DAYS_LEFT = (\d+)\s*$", ledger)
    skew = number(r"^MAX_FUTURE_SKEW = timedelta\(minutes=(\d+)\)\s*$", ledger)
    if validity is None or not 14 <= validity <= 90:
        out.append(f"{CHANNEL_LEDGER} VALIDITY_DAYS must be an integer from 14 to 90 (an idle channel needs one approved refresh per window)")
    if reminder is None or validity is None or not 7 <= reminder < validity:
        out.append(f"{CHANNEL_LEDGER} REMINDER_DAYS_LEFT must be at least 7 and below VALIDITY_DAYS")
    if skew is None or not 1 <= skew <= 60:
        out.append(f"{CHANNEL_LEDGER} MAX_FUTURE_SKEW must be 1 to 60 minutes (the client allows 24 hours)")
    if "pub const MAX_FUTURE_SKEW_SECS: i64 = 24 * 60 * 60;" not in manifest:
        out.append(f"{MANIFEST} MAX_FUTURE_SKEW_SECS must stay 24 hours, above the publisher's own limit")
    order = [manager.find(c) for c in ("check_not_expired(", "check_not_future_dated(", "self.replay.accept(")]
    if min(order) < 0 or order != sorted(order):
        out.append(f"{MANAGER} must check expiry and future dating before the replay floor accepts a manifest")
    return out


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
    out += ios_problems(all_jobs, read)
    out += macos_signing_problems(all_jobs, bundle, read, root)
    out += installer_problems(all_jobs)
    out += freshness_problems(read)
    for name in CONFIG_JOBS:
        job = all_jobs.get(name, "")
        step = re.search(r"^ +run: " + re.escape(CONFIG_COMMAND) + r"\s*$", job, re.M)
        if not step or "vars.RELEASE_MANIFEST_PUBLIC_KEY_HEX" not in job or "vars.RELEASE_MANIFEST_KEY_ID" not in job:
            out.append(f"{name} must run {CONFIG_COMMAND} with the release key variables")
        elif re.search(r"continue-on-error|" + re.escape(CONFIG_COMMAND) + r"\s*\|\|", job):
            out.append(f"{name} must not swallow a --config failure")
    return out


def macos_signing_problems(all_jobs: dict[str, str], bundle: str, read, root: Path) -> list[str]:
    """The macOS executables are signed and notarized in one privileged job between two attestations."""
    out = []
    sign, attest = all_jobs.get(SIGN_JOB), all_jobs.get(SIGNED_ATTEST_JOB)
    if sign is None or attest is None:
        return [f"{WORKFLOW} must have the {SIGN_JOB} and {SIGNED_ATTEST_JOB} jobs"]
    code, acode = code_only(sign), code_only(attest)
    if needs(sign) != {GATE_JOB, UNPRIVILEGED_JOB, ATTEST_JOB}:
        out.append(f"{SIGN_JOB} must need exactly {GATE_JOB}, {UNPRIVILEGED_JOB} and {ATTEST_JOB}")
    if not re.search(r"^    environment: release-signing\s*$", sign, re.M):
        out.append(f"{SIGN_JOB} must run in the release-signing environment")
    if not re.search(r"^    runs-on: macos-", sign, re.M):
        out.append(f"{SIGN_JOB} must run on a macOS runner")
    if permission_map(sign) != {"contents": "read"}:
        out.append(f"{SIGN_JOB} permissions must be exactly contents: read")
    if "vars." in code or GENERATOR_RE.search(code) or PROTECTED_FORBIDDEN_RE.search(code):
        out.append(f"{SIGN_JOB} must not build, run a generator, run artifact content or read variables")
    if "continue-on-error" in code or re.search(r"\|\|\s*true\b", code):
        out.append(f"{SIGN_JOB} must not swallow failures")
    if re.search(r"^\s+(run-id|repository|github-token):", code, re.M) or code.count("actions/download-artifact@") != 1 \
            or "name: engine-build-macos-aarch64" not in code:
        out.append(f"{SIGN_JOB} must download only this run's engine-build-macos-aarch64 artifact")
    if re.search(r"set\s+-[a-z]*x|\bprintenv\b|ACTIONS_STEP_DEBUG|echo[^\n]*\$\{\{\s*secrets\.", code):
        out.append(f"{SIGN_JOB} must not trace the shell or print the environment or a secret")
    # Secrets: exactly the five, in the one signing step.
    step = re.search(r"      - name: " + re.escape(SIGN_STEP) + r"\n(?:        .*\n|\n)+", code)
    rest = code.replace(step.group(0), "") if step else code
    if "secrets." in rest.replace("secrets.GITHUB_TOKEN", ""):
        out.append(f"{SIGN_JOB} may reference secrets only in the {SIGN_STEP!r} step")
    if not step:
        out.append(f"{SIGN_JOB} has no {SIGN_STEP!r} step")
    else:
        if sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", step.group(0)))) != sorted(MACOS_SECRETS):
            out.append(f"{SIGN_STEP!r} must receive exactly the five MACOS_* secrets")
        if "bash .github/release/macos-sign-notarize.sh" not in step.group(0):
            out.append(f"{SIGN_STEP!r} must run macos-sign-notarize.sh")
    order = [code.find(x) for x in ("gh attestation verify", "build-engine-bundle.py extract-executables",
                                    "name: " + SIGN_STEP, "build-engine-bundle.py resign")]
    if min(order) < 0 or order != sorted(order):
        out.append(f"{SIGN_JOB} must verify the attestation, extract, sign and notarize, then write the signed bundle, in that order")
    verify = re.search(r"gh attestation verify[^\n\\]*(?:\\\n[^\n\\]*)*", code)
    for needed in ("--repo ${{ github.repository }}", "--signer-workflow ${{ github.repository }}/.github/workflows/release.yml",
                   "--source-digest ${{ github.sha }}", "--source-ref ${{ github.ref }}"):
        if not verify or needed not in verify.group(0):
            out.append(f"{SIGN_JOB} gh attestation verify must pin: {needed}")
    for needed in ("--expect-zip-sha256", "--target macos-aarch64"):
        if code.count(needed) < 2:
            out.append(f"{SIGN_JOB} must pass {needed} to both extract-executables and resign")
    if "name: engine-signed-macos-aarch64" not in code or "actions/upload-artifact@" not in code:
        out.append(f"{SIGN_JOB} must upload the signed bundle as engine-signed-macos-aarch64")

    # The attestation half for the signed bundle.
    if needs(attest) != {GATE_JOB, SIGN_JOB}:
        out.append(f"{SIGNED_ATTEST_JOB} must need exactly {GATE_JOB} and {SIGN_JOB}")
    if permission_map(attest) != ATTEST_PERMISSIONS:
        out.append(f"{SIGNED_ATTEST_JOB} permissions must be exactly {ATTEST_PERMISSIONS}")
    if re.search(r"^    environment:", attest, re.M) or "secrets." in acode or "vars." in acode or MACOS_SECRET_RE.search(acode):
        out.append(f"{SIGNED_ATTEST_JOB} must have no environment, secrets or variables")
    if GENERATOR_RE.search(acode) or PROTECTED_FORBIDDEN_RE.search(acode) or "continue-on-error" in acode or re.search(r"\|\|\s*true\b", acode):
        out.append(f"{SIGNED_ATTEST_JOB} must not build, run a generator or swallow failures")
    if re.search(r"^\s+(run-id|repository|github-token):", acode, re.M) or acode.count("actions/download-artifact@") != 1 \
            or "name: engine-signed-macos-aarch64" not in acode:
        out.append(f"{SIGNED_ATTEST_JOB} must download only this run's engine-signed-macos-aarch64 artifact")
    if len(ATTEST_ACTION_RE.findall(acode)) != 1 or not re.search(r"subject-path: engine-unverified/\*\.zip\s*$", acode, re.M):
        out.append(f"{SIGNED_ATTEST_JOB} must attest exactly the verified signed zip with a SHA-pinned action")
    v_at, a_at = attest.find("build-engine-bundle.py verify"), attest.find("uses: actions/attest")
    if v_at < 0 or a_at < 0 or v_at > a_at:
        out.append(f"{SIGNED_ATTEST_JOB} must verify the signed bundle by hash before attesting it")

    # The protected bundle job releases the signed bundle on macOS, and the provenance says so.
    code_b = code_only(bundle)
    if SIGN_JOB not in needs(bundle) or SIGNED_ATTEST_JOB not in needs(bundle):
        out.append(f"{PROTECTED_BUNDLE_JOB} must list {SIGN_JOB} and {SIGNED_ATTEST_JOB} in needs")
    if "name: ${{ matrix.target == 'macos-aarch64' && 'engine-signed' || 'engine-build' }}-${{ matrix.target }}" not in code_b:
        out.append(f"{PROTECTED_BUNDLE_JOB} must download engine-signed-macos-aarch64 for macOS and engine-build-<target> otherwise")
    if "--gate macos-notarized" not in code_b or "macos-aarch64" not in code_b[code_b.find("--gate macos-notarized") - 120:code_b.find("--gate macos-notarized")]:
        out.append(f"{PROTECTED_BUNDLE_JOB} must record --gate macos-notarized for the macOS bundle")

    for name, job in all_jobs.items():
        if name != SIGN_JOB and MACOS_SECRET_RE.search(code_only(job)):
            out.append(f"{name} must not reference the macOS signing credentials; only {SIGN_JOB} may")
    # The credentials live in the signing step and the rehearsal's signing step, nowhere else.
    return out + macos_secret_scope_problems(read, root) + signing_script_problems(read) + rehearsal_problems(read)


def macos_secret_scope_problems(read, root: Path) -> list[str]:
    out = []
    allowed = {Path(WORKFLOW).name, Path(REHEARSAL).name}
    for rel in workflow_files(root):
        name = Path(rel).name
        if name not in allowed and MACOS_SECRET_RE.search(code_only(read(rel))):
            out.append(f"{rel} must not reference the macOS signing credentials; only {', '.join(sorted(allowed))} may")
    return out


def workflow_files(root: Path) -> list[str]:
    found = []
    for d in ("oss-public/.github/workflows", ".github/workflows"):
        if (root / d).is_dir():
            found += [f"{d}/{p.name}" for p in sorted((root / d).glob("*.yml"))]
    return found


def signing_script_problems(read) -> list[str]:
    text = read(SIGN_SCRIPT)
    if text.startswith("\0"):
        return [f"{SIGN_SCRIPT} is missing"]
    code = code_only(text)
    out = []
    for needed, why in [
        ("--options runtime", "the hardened runtime"), ("--timestamp", "a secure timestamp"),
        ("codesign --verify --strict", "signature verification"), ("notarytool submit", "notarization"),
        ("--wait", "waiting for the notary service"), ('!= "Accepted"', "failing on any status but Accepted"),
        ("::add-mask::", "masking the keychain password"), ("trap cleanup EXIT", "cleanup on every exit"),
        ("security delete-keychain", "deleting the temporary keychain"), ("chmod 600", "a 0600 key file"),
        ("openssl rand", "a random keychain password"), ("set -euo pipefail", "strict mode"),
    ]:
        if needed not in code:
            out.append(f"{SIGN_SCRIPT} must keep {why} ({needed})")
    if re.search(r"set\s+-[a-z]*x|xtrace|\bprintenv\b|\benv\s*$|echo[^\n]*\$\{?MACOS_|echo(?![^\n]*add-mask)[^\n]*keychain_password|(?:^|\s)ACTIONS_STEP_DEBUG", code, re.M):
        out.append(f"{SIGN_SCRIPT} must not trace the shell or print the environment or a secret")
    return out


def rehearsal_problems(read) -> list[str]:
    text = read(REHEARSAL)
    if text.startswith("\0"):
        return [f"{REHEARSAL} is missing"]
    code = code_only(text)
    out = []
    head = code.split("\njobs:\n")[0]
    if re.findall(r"^  ([a-z_]+):", re.search(r"^on:\s*\n((?:  .*\n)+)", head, re.M).group(1), re.M) != ["workflow_dispatch"]:
        out.append(f"{Path(REHEARSAL).name} must be triggered by workflow_dispatch only")
    if not re.search(r"^permissions:\s*\n  contents: read\s*$", head, re.M):
        out.append(f"{Path(REHEARSAL).name} workflow permissions must be exactly contents: read")
    if re.search(r"id-token|attestations|contents:\s*write|packages:\s*write|gh release|actions/attest|softprops|upload-release", code):
        out.append(f"{Path(REHEARSAL).name} must publish nothing: no id-token, attestation, release or write permission")
    if "continue-on-error" in code or re.search(r"\|\|\s*true\b", code):
        out.append(f"{Path(REHEARSAL).name} must not swallow failures")
    try:
        rj = jobs(code)
    except ValueError:
        return out + [f"{Path(REHEARSAL).name} has no jobs"]
    if set(rj) != {"build-sample", "sign-sample"}:
        return out + [f"{Path(REHEARSAL).name} jobs must be exactly build-sample and sign-sample"]
    build, sign = rj["build-sample"], rj["sign-sample"]
    if re.search(r"^    environment:", build, re.M) or "secrets." in build:
        out.append("build-sample must have no environment and no secret")
    if not re.search(r"^    environment: release-signing\s*$", sign, re.M) or needs(sign) != {"build-sample"}:
        out.append("sign-sample must need build-sample and run in the release-signing environment")
    for name, job in (("build-sample", build), ("sign-sample", sign)):
        if not re.search(r"^    if: .*refs/heads/main.*refs/tags/v", job, re.M):
            out.append(f"{name} must run only on main or a release tag")
    step = re.search(r"      - name: " + re.escape(SIGN_STEP) + r"\n(?:        .*\n|\n)+", sign)
    if not step:
        return out + [f"sign-sample has no {SIGN_STEP!r} step"]
    if sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", step.group(0)))) != sorted(MACOS_SECRETS) \
            or "secrets." in sign.replace(step.group(0), ""):
        out.append(f"only the {SIGN_STEP!r} step of sign-sample may reference secrets, and exactly the five MACOS_* ones")
    if "bash .github/release/macos-sign-notarize.sh" not in step.group(0):
        out.append(f"sign-sample {SIGN_STEP!r} must run the same macos-sign-notarize.sh as the release")
    for needed in ("codesign --verify --strict", "spctl --assess --type execute"):
        if needed not in sign:
            out.append(f"sign-sample must verify the result with {needed}")
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


IOS_TARGET = "ios-aarch64"
IOS_TRIPLES = ("aarch64-apple-ios", "aarch64-apple-ios-sim")


def matrix_targets(job: str) -> set[str]:
    """The bundle targets a job builds, from `target: [a, b]` or from `target: x` matrix entries."""
    inline = re.search(r"^        target: \[([^\]]*)\]\s*$", job, re.M)
    if inline:
        return {t.strip() for t in inline.group(1).split(",") if t.strip()}
    return set(re.findall(r"^          - os: \S+\n            target: (\S+)\n", job, re.M))


def ios_problems(all_jobs: dict[str, str], read) -> list[str]:
    """The iOS engine bundle is built, attested and released like the other targets.

    Structure only: the iOS slices need macOS and Xcode, so the unprivileged engine-build job
    builds them on the same hosted macOS runner as the macOS bundle; the unchanged attest and
    protected bundle jobs only hash, attest and verify them (they never build)."""
    out = []
    build, attest, bundle = (all_jobs.get(j, "") for j in (UNPRIVILEGED_JOB, ATTEST_JOB, PROTECTED_BUNDLE_JOB))
    code = code_only(build)
    for name, job in ((UNPRIVILEGED_JOB, build), (ATTEST_JOB, attest), (PROTECTED_BUNDLE_JOB, bundle)):
        if IOS_TARGET not in matrix_targets(job):
            out.append(f"{name} must build, attest and release the {IOS_TARGET} bundle (matrix target)")
    if matrix_targets(build) != matrix_targets(attest) or matrix_targets(build) != matrix_targets(bundle):
        out.append(f"{UNPRIVILEGED_JOB}, {ATTEST_JOB} and {PROTECTED_BUNDLE_JOB} must cover the same bundle targets")
    entry = re.search(r"^          - os: (\S+)\n            target: " + IOS_TARGET + r"\n", build, re.M)
    if not entry or not entry.group(1).startswith("macos-"):
        out.append(f"the {IOS_TARGET} build must run on a macOS runner (the iOS slices need macOS and Xcode)")
    elif entry.group(1) != re.search(r"^          - os: (macos-\S+)\n            target: macos-aarch64\n", build, re.M).group(1):
        out.append(f"the {IOS_TARGET} build must use the same macOS runner as the macos-aarch64 build")
    if "runs-on: ${{ matrix.os }}" not in build:
        out.append(f"{UNPRIVILEGED_JOB} must run each target on its matrix runner")
    step = re.search(r"      - name: Build iOS static libraries and Swift binding\n((?:        .*\n|\n)+?)(?=      (?:- |#)|\Z)", build)
    if not step or "if: matrix.target == 'ios-aarch64'" not in step.group(1) \
            or '.github/release/generate-ios-binding.sh --out "$RUNNER_TEMP/swift-binding"' not in step.group(1):
        out.append(f"{UNPRIVILEGED_JOB} must run generate-ios-binding.sh for {IOS_TARGET} only")
    toolchain = re.search(r"dtolnay/rust-toolchain@[0-9a-f]{40}[^\n]*\n        with:\n((?:          .*\n)+)", build)
    if not toolchain or not all(t in toolchain.group(1) for t in IOS_TRIPLES):
        out.append(f"{UNPRIVILEGED_JOB} must install the Rust targets {' and '.join(IOS_TRIPLES)} for the iOS build")
    if not re.search(r"- os: macos-\S+\n            target: " + IOS_TARGET + r"\n(?:            \S+: .*\n)*?            features: none\n", build):
        out.append(f"the {IOS_TARGET} matrix entry must record its build settings (features: none: no updater, no trust root)")
    for needed in ('--root "device=${RUNNER_TEMP}/swift-binding/device"', '--root "simulator=${RUNNER_TEMP}/swift-binding/simulator"',
                   '--root "generated=${RUNNER_TEMP}/swift-binding/Generated"', '--root "ipc=crates/yadorilink-ipc-proto"'):
        if needed not in code:
            out.append(f"{UNPRIVILEGED_JOB} must give the bundle build the iOS root: {needed}")
    if "generate-ios-binding.sh" in code and re.search(r"\bstrip\b|STRIP|-C strip|-Cstrip|--strip", code):
        out.append(f"{UNPRIVILEGED_JOB} must ship the iOS libraries unstripped (Xcode strips on archive)")
    verify_at = code.find('if [ "$TARGET" = "ios-aarch64" ]; then exit 0; fi')
    if verify_at < 0 or verify_at > code.find("check-engine-artifact"):
        out.append(f"{UNPRIVILEGED_JOB} must stop after the hash verification for {IOS_TARGET} (no executable to run) before check-engine-artifact")
    layout_doc, builder = read(LAYOUT_DOC), read(BUNDLE_BUILDER)
    if "## ios-aarch64" not in layout_doc or "unstripped" not in layout_doc or "`slices`" not in layout_doc:
        out.append(f"{LAYOUT_DOC} must document the {IOS_TARGET} layout, its slices and that the libraries are shipped unstripped")
    if '\n    "ios-aarch64": {\n        "trust_root": False,' not in builder or '        "slices": {' not in builder:
        out.append(f"{BUNDLE_BUILDER} LAYOUTS must define {IOS_TARGET} with its slices")
    if "macOS" not in layout_doc[layout_doc.find("## ios-aarch64"):layout_doc.find("## The engine.lock release asset")] \
            or "hosted macOS runner" not in layout_doc:
        out.append(f"{LAYOUT_DOC} must state that the {IOS_TARGET} build needs the macOS runner (hosted macOS runner, Xcode)")
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
    if "pins.py check --require-verifier --require-floor" not in code:
        out.append(f"{ATTEST_JOB} must require the manifest floor pin on a release tag")
    for name, job in all_jobs.items():
        if name not in (ATTEST_JOB, SIGNED_ATTEST_JOB) and IDENTITY_PERMISSION_RE.search(code_only(job)):
            out.append(f"{name} must not hold id-token, attestations or artifact-metadata; only {ATTEST_JOB} and {SIGNED_ATTEST_JOB} may")
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
        ("engine-attest drops the manifest floor requirement", WORKFLOW, lambda t: t.replace(" --require-floor", "", 1)),
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
        ("macOS signing job removed", WORKFLOW, lambda t: t.replace("\n  engine-sign-macos:\n", "\n  engine-sign-macos-renamed:\n")),
        ("macOS signing job loses the environment", WORKFLOW, lambda t: drop_in_job(t, SIGN_JOB, "    environment: release-signing\n")),
        ("macOS signing job gains id-token", WORKFLOW, lambda t: add_perm(t, SIGN_JOB, "      id-token: write\n")),
        ("macOS signing job runs on Linux", WORKFLOW, lambda t: t.replace("    runs-on: macos-latest\n    timeout-minutes: 90", "    runs-on: ubuntu-latest\n    timeout-minutes: 90", 1)),
        ("macOS signing job gains write permission", WORKFLOW, lambda t: t.replace("    timeout-minutes: 90\n    environment: release-signing\n    permissions:\n      contents: read", "    timeout-minutes: 90\n    environment: release-signing\n    permissions:\n      contents: write", 1)),
        ("macOS signing job builds with cargo", WORKFLOW, lambda t: t.replace("      - name: Sign and notarize\n        shell: bash\n        env:\n          MACOS_DEVELOPER_ID_APP_P12_BASE64: ${{ secrets.MACOS_DEVELOPER_ID_APP_P12_BASE64 }}\n          MACOS_DEVELOPER_ID_APP_P12_PASSWORD: ${{ secrets.MACOS_DEVELOPER_ID_APP_P12_PASSWORD }}\n          MACOS_NOTARY_ISSUER_ID", "      - run: cargo build --release\n      - name: Sign and notarize\n        shell: bash\n        env:\n          MACOS_DEVELOPER_ID_APP_P12_BASE64: ${{ secrets.MACOS_DEVELOPER_ID_APP_P12_BASE64 }}\n          MACOS_DEVELOPER_ID_APP_P12_PASSWORD: ${{ secrets.MACOS_DEVELOPER_ID_APP_P12_PASSWORD }}\n          MACOS_NOTARY_ISSUER_ID", 1)),
        ("macOS signing job skips the attestation check", WORKFLOW, lambda t: t.replace('          gh attestation verify "${zips[0]}" \\\n            --repo ${{ github.repository }} \\\n            --signer-workflow ${{ github.repository }}/.github/workflows/release.yml \\\n            --source-digest ${{ github.sha }} \\\n            --source-ref ${{ github.ref }}\n', '          true\n', 1)),
        ("macOS signing job drops the source digest pin", WORKFLOW, lambda t: t.replace("            --source-digest ${{ github.sha }} \\\n            --source-ref ${{ github.ref }}\n", "            --source-ref ${{ github.ref }}\n", 1)),
        ("macOS signing job downloads another run", WORKFLOW, lambda t: t.replace("          name: engine-build-macos-aarch64\n          path: engine-unverified", "          name: engine-build-macos-aarch64\n          path: engine-unverified\n          run-id: 1", 1)),
        ("macOS signing job swallows failures", WORKFLOW, lambda t: add_to_job(t, SIGN_JOB, "    continue-on-error: true\n")),
        ("macOS signing job no longer needs the attestation", WORKFLOW, lambda t: drop_in_job(t, SIGN_JOB, "      - engine-attest\n")),
        ("macOS signing job traces the shell", WORKFLOW, lambda t: t.replace("          bash .github/release/macos-sign-notarize.sh \\\n", "          set -x\n          bash .github/release/macos-sign-notarize.sh \\\n", 1)),
        ("macOS secret leaks into another step", WORKFLOW, lambda t: t.replace("      - name: Write the bundle with the signed executables\n        shell: bash\n        env:\n", "      - name: Write the bundle with the signed executables\n        shell: bash\n        env:\n          LEAK: ${{ secrets.MACOS_NOTARY_KEY_ID }}\n", 1)),
        ("macOS signing step loses a secret", WORKFLOW, lambda t: t.replace("          MACOS_NOTARY_KEY_ID: ${{ secrets.MACOS_NOTARY_KEY_ID }}\n", "", 1)),
        ("macOS signing step skips the script", WORKFLOW, lambda t: t.replace("bash .github/release/macos-sign-notarize.sh", "echo skipped", 1)),
        ("macOS signed bundle written before signing", WORKFLOW, lambda t: swap_sign_steps(t)),
        ("macOS secret in the unprivileged build", WORKFLOW, lambda t: add_to_job(t, UNPRIVILEGED_JOB, "    env:\n      X: ${{ secrets.MACOS_NOTARY_KEY_ID }}\n")),
        ("macOS secret in the bundle job", WORKFLOW, lambda t: add_to_job(t, PROTECTED_BUNDLE_JOB, "    env:\n      X: ${{ secrets.MACOS_NOTARY_KEY_ID }}\n")),
        ("signed attestation job removed", WORKFLOW, lambda t: t.replace("\n  engine-attest-signed:\n", "\n  engine-attest-signed-renamed:\n")),
        ("signed attestation job loses id-token", WORKFLOW, lambda t: drop_in_job(t, SIGNED_ATTEST_JOB, "      id-token: write\n")),
        ("signed attestation job gets an environment", WORKFLOW, lambda t: add_to_job(t, SIGNED_ATTEST_JOB, "    environment: release-signing\n")),
        ("signed attestation job gets a secret", WORKFLOW, lambda t: add_to_job(t, SIGNED_ATTEST_JOB, "    env:\n      X: ${{ secrets.MACOS_NOTARY_KEY_ID }}\n")),
        ("signed attestation job attests the unsigned build", WORKFLOW, lambda t: drop_in_job(t, SIGNED_ATTEST_JOB, "          name: engine-signed-macos-aarch64\n").replace("      - name: Download the signed bundle\n        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n", "      - name: Download the signed bundle\n        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: engine-build-macos-aarch64\n", 1)),
        ("signed attestation job no longer needs signing", WORKFLOW, lambda t: drop_in_job(t, SIGNED_ATTEST_JOB, "      - engine-sign-macos\n")),
        ("signed attestation job attests unverified bytes", WORKFLOW, lambda t: t.replace("build-engine-bundle.py verify \"$zip\" --target macos-aarch64 --expect-zip-sha256 \"$expected\" ${release[@]+\"${release[@]}\"}\n\n      - name: Attest the signed bundle", "true\n\n      - name: Attest the signed bundle", 1)),
        ("bundle job downloads the unsigned macOS build", WORKFLOW, lambda t: t.replace("${{ matrix.target == 'macos-aarch64' && 'engine-signed' || 'engine-build' }}", "engine-build", 1)),
        ("bundle job no longer needs the signing job", WORKFLOW, lambda t: drop_in_job(t, PROTECTED_BUNDLE_JOB, "      - engine-sign-macos\n")),
        ("bundle job drops the notarized gate", WORKFLOW, lambda t: t.replace('extra_gate=(--gate macos-notarized)', 'extra_gate=()', 1)),
        ("signing script drops the hardened runtime", SIGN_SCRIPT, lambda t: t.replace("--options runtime", "")),
        ("signing script drops the timestamp", SIGN_SCRIPT, lambda t: t.replace("--timestamp", "")),
        ("signing script accepts any status", SIGN_SCRIPT, lambda t: t.replace('!= "Accepted"', '== "Nothing"')),
        ("signing script stops waiting for the notary", SIGN_SCRIPT, lambda t: t.replace("--wait", "")),
        ("signing script never deletes the keychain", SIGN_SCRIPT, lambda t: t.replace("security delete-keychain", "true")),
        ("signing script drops the cleanup trap", SIGN_SCRIPT, lambda t: t.replace("trap cleanup EXIT", "true")),
        ("signing script unmasks the keychain password", SIGN_SCRIPT, lambda t: t.replace("::add-mask::", "::debug::")),
        ("signing script traces the shell", SIGN_SCRIPT, lambda t: t.replace("set -euo pipefail", "set -euxo pipefail", 1)),
        ("signing script echoes the keychain password", SIGN_SCRIPT, lambda t: t + '\necho "$keychain_password"\n'),
        ("signing script leaves the key world-readable", SIGN_SCRIPT, lambda t: t.replace("chmod 600", "chmod 644")),
        ("rehearsal triggered by a pull request", REHEARSAL, lambda t: t.replace("on:\n  workflow_dispatch:\n", "on:\n  pull_request:\n  workflow_dispatch:\n", 1)),
        ("rehearsal triggered by push", REHEARSAL, lambda t: t.replace("on:\n  workflow_dispatch:\n", "on:\n  push:\n  workflow_dispatch:\n", 1)),
        ("rehearsal gains id-token", REHEARSAL, lambda t: t.replace("permissions:\n  contents: read\n\njobs:", "permissions:\n  contents: read\n  id-token: write\n\njobs:", 1)),
        ("rehearsal publishes a release", REHEARSAL, lambda t: t.replace("      - name: Verify the result\n", "      - run: gh release create x\n      - name: Verify the result\n", 1)),
        ("rehearsal build job gets the environment", REHEARSAL, lambda t: t.replace("    runs-on: macos-latest\n    timeout-minutes: 15\n", "    runs-on: macos-latest\n    timeout-minutes: 15\n    environment: release-signing\n", 1)),
        ("rehearsal sign job loses the environment", REHEARSAL, lambda t: t.replace("    environment: release-signing\n", "", 1)),
        ("rehearsal runs on any branch", REHEARSAL, lambda t: t.replace("    if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')\n    needs:", "    needs:", 1)),
        ("rehearsal secret outside the signing step", REHEARSAL, lambda t: t.replace("      - name: Verify the result\n        shell: bash\n", "      - name: Verify the result\n        shell: bash\n        env:\n          X: ${{ secrets.MACOS_NOTARY_KEY_ID }}\n", 1)),
        ("rehearsal stops using the shared script", REHEARSAL, lambda t: t.replace("bash .github/release/macos-sign-notarize.sh", "echo", 1)),
        ("rehearsal stops verifying", REHEARSAL, lambda t: t.replace("codesign --verify --strict", "true", 1)),
        ("iOS bundle dropped from engine-build", WORKFLOW, lambda t: t.replace("          - os: macos-latest\n            target: ios-aarch64\n", "          - os: macos-latest\n            target: ios-renamed\n", 1)),
        ("iOS bundle dropped from engine-attest", WORKFLOW, lambda t: t.replace("target: [linux-x86_64, windows-x86_64, macos-aarch64, ios-aarch64]", "target: [linux-x86_64, windows-x86_64, macos-aarch64]", 1)),
        ("iOS bundle dropped from engine-bundle", WORKFLOW, lambda t: t[::-1].replace("target: [linux-x86_64, windows-x86_64, macos-aarch64, ios-aarch64]"[::-1], "target: [linux-x86_64, windows-x86_64, macos-aarch64]"[::-1], 1)[::-1]),
        ("iOS bundle built on Linux", WORKFLOW, lambda t: t.replace("          - os: macos-latest\n            target: ios-aarch64\n", "          - os: ubuntu-latest\n            target: ios-aarch64\n", 1)),
        ("iOS bundle on another macOS runner", WORKFLOW, lambda t: t.replace("          - os: macos-latest\n            target: ios-aarch64\n", "          - os: macos-15\n            target: ios-aarch64\n", 1)),
        ("engine-build ignores the matrix runner", WORKFLOW, lambda t: t.replace("    runs-on: ${{ matrix.os }}\n    timeout-minutes: 60", "    runs-on: macos-latest\n    timeout-minutes: 60", 1)),
        ("iOS binding step dropped", WORKFLOW, lambda t: t.replace(".github/release/generate-ios-binding.sh --out", "echo skipped --out", 1)),
        ("iOS binding step runs for every target", WORKFLOW, lambda t: t.replace("        if: matrix.target == 'ios-aarch64'\n        shell: bash\n        run: |\n          set -euo pipefail\n          .github/release/generate-ios", "        shell: bash\n        run: |\n          set -euo pipefail\n          .github/release/generate-ios", 1)),
        ("iOS binding generated outside engine-build", WORKFLOW, lambda t: t.replace("      - name: Re-verify the bundle by hash only\n", "      - run: .github/release/generate-ios-binding.sh\n      - name: Re-verify the bundle by hash only\n", 1)),
        ("iOS Rust targets not installed", WORKFLOW, lambda t: t.replace("'aarch64-apple-ios,aarch64-apple-ios-sim'", "'aarch64-apple-ios'", 1)),
        ("iOS build settings not recorded", WORKFLOW, lambda t: t.replace("            features: none\n", "", 1)),
        ("iOS device root dropped", WORKFLOW, lambda t: t.replace('            --root "device=${RUNNER_TEMP}/swift-binding/device" \\\n', "", 1)),
        ("iOS simulator root dropped", WORKFLOW, lambda t: t.replace('            --root "simulator=${RUNNER_TEMP}/swift-binding/simulator" \\\n', "", 1)),
        ("iOS libraries stripped", WORKFLOW, lambda t: t.replace('generate-ios-binding.sh --out "$RUNNER_TEMP/swift-binding"\n', 'generate-ios-binding.sh --out "$RUNNER_TEMP/swift-binding"\n          strip -S "$RUNNER_TEMP"/swift-binding/*/*.a\n', 1)),
        ("iOS bundle run as an executable", WORKFLOW, lambda t: t.replace('          if [ "$TARGET" = "ios-aarch64" ]; then exit 0; fi\n', "", 1)),
        ("iOS layout missing from the builder", BUNDLE_BUILDER, lambda t: t.replace('"ios-aarch64": {', '"ios-renamed": {', 1)),
        ("iOS layout doc section dropped", LAYOUT_DOC, lambda t: t.replace("## ios-aarch64", "## ios-renamed", 1)),
        ("iOS layout doc forgets the macOS runner", LAYOUT_DOC, lambda t: t.replace("hosted macOS runner", "runner", 1)),
        ("manifest validity window shortened to days", CHANNEL_LEDGER, lambda t: t.replace("VALIDITY_DAYS = 60", "VALIDITY_DAYS = 3", 1)),
        ("manifest reminder after expiry", CHANNEL_LEDGER, lambda t: t.replace("REMINDER_DAYS_LEFT = 20", "REMINDER_DAYS_LEFT = 60", 1)),
        ("publisher future skew widened", CHANNEL_LEDGER, lambda t: t.replace("timedelta(minutes=5)", "timedelta(days=5)", 1)),
        ("client future skew changed", MANIFEST, lambda t: t.replace("MAX_FUTURE_SKEW_SECS: i64 = 24 * 60 * 60", "MAX_FUTURE_SKEW_SECS: i64 = 60", 1)),
        ("expiry checked after the replay floor", MANAGER, lambda t: t.replace("        manifest::check_not_expired(&manifest, self.now())?;\n", "", 1).replace("self.replay.accept(&policy.channel, &manifest.generated_at, &body)?;", "self.replay.accept(&policy.channel, &manifest.generated_at, &body)?;\n        manifest::check_not_expired(&manifest, self.now())?;", 1)),
        ("iOS layout doc forgets unstripped", LAYOUT_DOC, lambda t: t.replace("unstripped", "stripped")),
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
            (tmp / rel).write_text(changed, encoding="utf-8", newline="\n")
            assert static_problems(tmp), f"bypass not detected: {label}"
    # Another workflow must not reach the signing credentials.
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for f in FILES:
            (tmp / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / f, tmp / f)
        (tmp / Path(WORKFLOW).parent / "other.yml").write_text(
            "on: workflow_dispatch\njobs:\n  x:\n    runs-on: macos-latest\n    steps:\n      - run: echo ${{ secrets.MACOS_NOTARY_KEY_P8_BASE64 }}\n", encoding="utf-8", newline="\n")
        assert static_problems(tmp), "bypass not detected: another workflow uses the macOS signing credentials"
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


def swap_sign_steps(workflow: str) -> str:
    """Write the signed bundle before signing in the macOS signing job."""
    start, end = job_span(workflow, SIGN_JOB)
    body = workflow[start:end]
    i, j = body.index("      - name: Sign and notarize\n"), body.index("      - name: Write the bundle with the signed executables\n")
    k = body.index("      - uses: actions/upload-artifact")
    return workflow[:start] + body[:i] + body[j:k] + body[i:j] + body[k:] + workflow[end:]


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
