#!/usr/bin/env python3
"""Check an engine artifact against its engine identity file.

Usage: check-engine-artifact.py [--release] [--require-embedded-id] IDENTITY.json DAEMON_BINARY
       check-engine-artifact.py --self-test

Fails unless the identity is valid, the binary's SHA-256 equals
artifact_sha256, and `DAEMON_BINARY --version` reports a host api version
equal to engine_api_version and, when it reports the release identity it was built with
("(release <id>)"), that identity equals <public_commit_sha>:<build_config_digest>. --release
and --require-embedded-id also fail a binary that reports none. The binary is hashed and compared first and is
never executed when the digest does not match. --release (release and
production paths) also rejects a development engine.
"""

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("validate_engine_identity", HERE / "validate-engine-identity.py")
_validator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_validator)

API = re.compile(r"\(host api (\d+)\)")
EMBEDDED = re.compile(r"\(release ([0-9a-f]{40}:[0-9a-f]{64})\)")


def check(identity_path: Path, binary: Path, release: bool = False, require_embedded: bool = False) -> list[str]:
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    problems = _validator.validate(identity, release=release)
    if problems:
        return problems
    binary = binary.resolve()
    try:
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    except OSError as e:
        return [f"cannot read {binary}: {e}"]
    if digest != identity["artifact_sha256"]:
        # Fail closed: unverified bytes are never run.
        return [f"artifact sha256 {digest} != identity {identity['artifact_sha256']}"]
    out = []
    run = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=30, encoding="utf-8")
    match = API.search(run.stdout)
    if run.returncode != 0 or not match:
        out.append("binary did not report a host api version")
    elif int(match.group(1)) != identity["engine_api_version"]:
        out.append(f"binary host api {match.group(1)} != identity {identity['engine_api_version']}")
    embedded = EMBEDDED.search(run.stdout)
    want = f"{identity['public_commit_sha']}:{identity['build_config_digest']}"
    if embedded and embedded.group(1) != want:
        out.append(f"binary embeds release id {embedded.group(1)} != identity {want}")
    elif not embedded and (release or require_embedded):
        out.append("binary does not report the release id it was built with")
    return out


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        binary = tmp / "daemon"
        binary.write_text("#!/bin/sh\necho 'yadorilink-daemon 0.0.0 (host api 2)'\n", encoding="utf-8")
        binary.chmod(0o755)
        identity = {
            "public_commit_sha": "a" * 40,
            "engine_api_version": 2,
            "artifact_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "channel": "beta",
            "kind": "release",
            "build_config_digest": "c" * 64,
            "bundle_sha256": "d" * 64,
        }
        path = tmp / "engine-identity.json"

        def run(**change):
            path.write_text(json.dumps({**identity, **change}), encoding="utf-8")
            return check(path, binary)

        assert run() == []
        assert run(artifact_sha256="0" * 64)
        # A digest mismatch must never execute the binary.
        marker = tmp / "executed"
        probe = tmp / "probe"
        probe.write_text(f"#!/bin/sh\ntouch '{marker}'\necho 'yadorilink-daemon 0.0.0 (host api 2)'\n", encoding="utf-8")
        probe.chmod(0o755)
        path.write_text(json.dumps({**identity, "artifact_sha256": "0" * 64}), encoding="utf-8")
        found = check(path, probe)
        assert found and "sha256" in found[0], found
        assert not marker.exists(), "binary was executed despite a sha256 mismatch"
        path.write_text(json.dumps({**identity, "artifact_sha256": hashlib.sha256(probe.read_bytes()).hexdigest()}), encoding="utf-8")
        assert check(path, probe) == [] and marker.exists()
        assert check(path, tmp / "missing")
        assert run(engine_api_version=3)
        assert run(channel="nightly")
        assert run(channel="dev", kind="dev") == []
        path.write_text(json.dumps({**identity, "channel": "dev", "kind": "dev"}), encoding="utf-8")
        assert check(path, binary, release=True), "a release path accepted a development engine"
        path.write_text(json.dumps(identity), encoding="utf-8")
        rid = f"{'a' * 40}:{'c' * 64}"
        embedding = tmp / "embedding"
        embedding.write_text(f"#!/bin/sh\necho 'yadorilink-daemon 0.0.0 (host api 2) (release {rid})'\n", encoding="utf-8")
        embedding.chmod(0o755)
        digest = hashlib.sha256(embedding.read_bytes()).hexdigest()
        path.write_text(json.dumps({**identity, "artifact_sha256": digest}), encoding="utf-8")
        assert check(path, embedding, release=True, require_embedded=True) == []
        path.write_text(json.dumps({**identity, "artifact_sha256": digest, "build_config_digest": "e" * 64}), encoding="utf-8")
        assert check(path, embedding), "a binary embedding another build was accepted"
        path.write_text(json.dumps({**identity, "artifact_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}), encoding="utf-8")
        assert check(path, binary) == [] and check(path, binary, require_embedded=True), "an unembedded binary passed --require-embedded-id"
        binary.write_text("#!/bin/sh\necho 'yadorilink-daemon 0.0.0'\n", encoding="utf-8")
        assert run(artifact_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    print("ok")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    release = "--release" in argv
    require_embedded = "--require-embedded-id" in argv
    argv = [a for a in argv if a not in ("--release", "--require-embedded-id")]
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    found = check(Path(argv[0]), Path(argv[1]), release, require_embedded)
    for line in found:
        print(line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
