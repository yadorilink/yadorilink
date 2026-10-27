#!/usr/bin/env python3
"""Validate an engine identity file against engine-identity.schema.json.

Usage: validate-engine-identity.py [--require-source] [--release] IDENTITY.json
       validate-engine-identity.py --self-test

--require-source additionally demands the `source` object (repository,
release_tag, asset_name); use it for a consumer's engine.lock.

--release is for release and production build paths: it additionally rejects
a development engine (kind dev / channel dev). A development engine is
accepted everywhere else, but never by a path that signs or distributes.

Only the schema keywords the schema file uses are supported (type, required,
properties, additionalProperties, pattern, enum, minimum); an unknown keyword
is an error so the schema and this checker cannot drift apart silently.
"""

import json
import re
import sys
from pathlib import Path

SCHEMA = Path(__file__).with_name("engine-identity.schema.json")
KNOWN = {
    "$schema", "title", "description", "type", "required", "properties",
    "additionalProperties", "pattern", "enum", "minimum",
}


def errors(value, schema, path="$"):
    out = [f"{path}: unsupported schema keyword {k!r}" for k in schema if k not in KNOWN]
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            return out + [f"{path}: expected object"]
        props = schema.get("properties", {})
        out += [f"{path}: missing {k!r}" for k in schema.get("required", []) if k not in value]
        for key, item in value.items():
            if key in props:
                out += errors(item, props[key], f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                out.append(f"{path}: unexpected field {key!r}")
    elif kind == "string":
        if not isinstance(value, str):
            return out + [f"{path}: expected string"]
        if "pattern" in schema and not re.search(schema["pattern"], value):
            out.append(f"{path}: does not match {schema['pattern']}")
        if "enum" in schema and value not in schema["enum"]:
            out.append(f"{path}: must be one of {schema['enum']}")
    elif kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return out + [f"{path}: expected integer"]
        if value < schema.get("minimum", value):
            out.append(f"{path}: below minimum {schema['minimum']}")
    return out


def validate(identity, require_source: bool = False, release: bool = False) -> list[str]:
    found = errors(identity, json.loads(SCHEMA.read_text(encoding="utf-8")))
    if require_source and isinstance(identity, dict) and "source" not in identity:
        found.append("$: missing 'source'")
    if isinstance(identity, dict):
        written, oldest = identity.get("state_schema_version"), identity.get("state_schema_min_readable")
        if oldest is not None and written is None:
            found.append("$: state_schema_min_readable requires state_schema_version")
        if isinstance(written, int) and isinstance(oldest, int) and oldest > written:
            found.append("$: state_schema_min_readable is above state_schema_version")
        kind, channel = identity.get("kind"), identity.get("channel")
        # kind and channel say the same thing twice on purpose: a development
        # engine cannot be relabelled as a release (or the reverse) by editing
        # one field.
        if kind == "dev" and channel != "dev":
            found.append("$: kind dev requires channel dev")
        if kind == "release" and channel == "dev":
            found.append("$: channel dev requires kind dev")
        if release and (kind != "release" or channel not in ("stable", "beta")):
            found.append(f"$: a release or production path requires kind release on channel stable or beta, not kind {kind!r} on channel {channel!r}")
    return found


def self_test() -> int:
    good = {
        "public_commit_sha": "a" * 40,
        "engine_api_version": 1,
        "artifact_sha256": "b" * 64,
        "channel": "stable",
        "kind": "release",
        "build_config_digest": "c" * 64,
        "bundle_sha256": "d" * 64,
    }
    source = {"repository": "owner/repo", "release_tag": "v1.2.3", "asset_name": "engine-beta.zip"}
    assert validate(good) == []
    assert validate(good, require_source=True)
    assert validate({**good, "source": source}, require_source=True) == []
    for key, bad_value in [
        ("repository", "no-slash"),
        ("repository", "../repo"),
        ("repository", "owner/.."),
        ("repository", "./repo"),
        ("repository", "owner/."),
        ("repository", "owner/repo/extra"),
        ("release_tag", "../x"),
        ("asset_name", "engine.tar.gz"),
        ("asset_name", "../engine.zip"),
    ]:
        assert validate({**good, "source": {**source, key: bad_value}}), key
    assert validate({**good, "source": {"repository": "owner/repo"}})
    for ok_repo in ("a/b", "my-org/.github", "o.w/r..e", "_o/_r", "o/..x"):
        assert validate({**good, "source": {**source, "repository": ok_repo}}) == [], ok_repo
    assert validate({**good, "source": {**source, "extra": 1}})
    assert validate({k: v for k, v in good.items() if k != "bundle_sha256"})
    slices = {"aarch64-apple-ios": "e" * 64, "aarch64-apple-ios-sim": "f" * 64}
    assert validate({**good, "slices": slices}) == []
    assert validate({**good, "slices": {"aarch64-apple-ios": "e" * 64}}), "a missing slice was accepted"
    assert validate({**good, "slices": {**slices, "x86_64-apple-ios": "e" * 64}}), "an unknown slice was accepted"
    assert validate({**good, "slices": {**slices, "aarch64-apple-ios": "E" * 64}}), "a bad slice digest was accepted"
    assert validate({**good, "bundle_sha256": "D" * 64})
    for key, bad in [
        ("public_commit_sha", "abc"),
        ("engine_api_version", 0),
        ("engine_api_version", True),
        ("artifact_sha256", "B" * 64),
        ("channel", "nightly"),
        ("build_config_digest", None),
    ]:
        assert validate({**good, key: bad}), key
    assert validate({k: v for k, v in good.items() if k != "channel"})
    assert validate({k: v for k, v in good.items() if k != "kind"})
    assert validate({**good, "kind": "nightly"})
    dev = {**good, "channel": "dev", "kind": "dev"}
    assert validate(dev) == []
    assert validate(dev, require_source=True, release=False)  # only the missing source
    assert validate({**dev, "source": source}, require_source=True) == []
    # kind and channel must agree, and a release path refuses a development engine.
    assert validate({**good, "channel": "dev"}) and validate({**dev, "channel": "beta"})
    assert validate(dev, release=True)
    assert validate({**good, "channel": "dev"}, release=True)
    assert validate(good, release=True) == [] and validate({**good, "channel": "beta"}, release=True) == []
    assert validate({**good, "extra": 1})
    assert validate([])
    # The state database compatibility fields are additive and optional: identities
    # without them (older bundles) and with them are both accepted.
    assert validate({**good, "state_schema_version": 132}) == []
    assert validate({**good, "state_schema_version": 132, "state_schema_min_readable": 130}) == []
    assert validate({**good, "state_schema_min_readable": 130})
    assert validate({**good, "state_schema_version": 5, "state_schema_min_readable": 6})
    for bad_state in (0, "132", True, 1.5):
        assert validate({**good, "state_schema_version": bad_state}), bad_state
    print("ok")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    require_source = "--require-source" in argv
    release = "--release" in argv
    argv = [a for a in argv if a not in ("--require-source", "--release")]
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    found = validate(json.loads(Path(argv[0]).read_text(encoding="utf-8")), require_source, release)
    for line in found:
        print(line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
