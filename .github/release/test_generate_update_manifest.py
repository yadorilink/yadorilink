"""Tests for the cutover floor in generate-update-manifest.py.

Run: python3 -m unittest .github/release/test_generate_update_manifest.py
"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name("generate-update-manifest.py")
spec = importlib.util.spec_from_file_location("generate_update_manifest", SCRIPT)
gum = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gum)

REPO = SCRIPT.parents[2]


def make_tree(protocol=4, rpc=2, notes=""):
    """A minimal tree: just the constants the guard reads, plus CUTOVER.md."""
    guard = gum._cutover_guard()
    root = Path(tempfile.mkdtemp())
    values = {"PROTOCOL_VERSION": protocol, "RPC_VERSION": rpc, "CONTROL_PROTOCOL_VERSION": 1,
              "SCHEMA_VERSION": 1}
    for name, rel in guard.GATES.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(f"pub const {name}: u32 = {values[name]};\n", encoding="utf-8")
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs/CUTOVER.md").write_text(notes, encoding="utf-8")
    return root


def entry(version="0.3.0", minimum="0.3.0"):
    return {
        "channel": "beta", "platform": "macos", "arch": "aarch64", "install_source": "standalone",
        "version": version, "minimum_supported_version": minimum, "rollout_percentage": 100,
        "kill_switch": False, "mandatory": False, "artifact_url": "https://example.invalid/a.pkg",
        "artifact_sha256": "0" * 64, "artifact_size": 1, "artifact_publisher_identity": "",
        "release_notes_url": "",
    }


def manifest(*entries):
    return {"schema_version": gum.MANIFEST_SCHEMA_VERSION, "generated_at": "2026-10-19T00:00:00Z",
            "expires_at": "2026-12-18T00:00:00Z", "releases": list(entries)}


class SparkleBuildField(unittest.TestCase):
    def app(self, **kw):
        return {**entry(), "install_source": "app_bundle", **kw}

    def test_a_new_publication_needs_a_positive_integer_build_on_app_bundle_entries(self):
        for bad in (None, 0, "42", True, -1):
            e = self.app() if bad is None else self.app(sparkle_build=bad)
            problems = gum.validate_manifest(manifest(e), False, require_sparkle_build=True)
            self.assertTrue(any("sparkle_build" in p for p in problems), bad)
        ok = manifest(self.app(sparkle_build=42))
        self.assertEqual(gum.validate_manifest(ok, False, require_sparkle_build=True), [])

    def test_an_already_published_entry_without_a_build_still_verifies(self):
        old = manifest(self.app())
        self.assertEqual(gum.validate_manifest(old, False), [])
        self.assertEqual(gum.validate_manifest(old, False, snapshot=True), [])

    def test_a_present_build_is_always_checked_and_only_app_bundle_carries_one(self):
        problems = gum.validate_manifest(manifest(self.app(sparkle_build=0)), False)
        self.assertTrue(any("sparkle_build" in p for p in problems), problems)
        problems = gum.validate_manifest(manifest({**entry(), "sparkle_build": 42}), False)
        self.assertTrue(any("only carried by app_bundle" in p for p in problems), problems)


class ExpiryField(unittest.TestCase):
    def problems(self, **over):
        m = manifest(entry())
        m.update(over)
        return gum.validate_manifest(m, False)

    def test_a_well_formed_expiry_passes(self):
        self.assertEqual(self.problems(), [])

    def test_a_missing_expiry_is_refused(self):
        m = manifest(entry())
        del m["expires_at"]
        self.assertTrue(any("expires_at" in p for p in gum.validate_manifest(m, False)))

    def test_a_snapshot_is_accepted_with_or_without_expiry_and_never_expiry_checked(self):
        m = manifest(entry())
        del m["expires_at"]
        self.assertEqual(gum.validate_manifest(m, False, snapshot=True), [])
        m["expires_at"] = "2020-01-01T00:00:00Z"
        self.assertEqual(gum.validate_manifest(m, False, snapshot=True), [])
        self.assertEqual(gum.validate_manifest(manifest(entry()), False, snapshot=True), [])

    def test_a_live_channel_manifest_without_expiry_is_still_refused(self):
        m = manifest(entry())
        del m["expires_at"]
        self.assertTrue(any("expires_at" in p for p in gum.validate_manifest(m, False)))

    def test_a_malformed_or_non_increasing_expiry_is_refused(self):
        for bad in ("soon", None, 5, "2026-10-19T00:00:00Z", "2026-10-18T00:00:00Z"):
            self.assertTrue(any("expires_at" in p for p in self.problems(expires_at=bad)), bad)


class GenerationFloor(unittest.TestCase):
    def test_floor_is_the_first_release_recorded_for_the_current_generation(self):
        root = make_tree(notes="- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.3.0\n")
        self.assertEqual(gum.generation_floor(root), "0.3.0")

    def test_a_bump_without_a_recorded_first_release_fails_closed(self):
        notes = "- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.3.0\n"
        for protocol, rpc in ((5, 2), (4, 3)):
            root = make_tree(protocol=protocol, rpc=rpc, notes=notes)
            with self.assertRaises(gum.FloorError):
                gum.generation_floor(root)

    def test_a_missing_cutover_file_fails_closed(self):
        root = make_tree()
        (root / "docs/CUTOVER.md").unlink()
        with self.assertRaises(gum.FloorError):
            gum.generation_floor(root)

    def test_the_real_tree_records_its_current_generation(self):
        self.assertRegex(gum.generation_floor(REPO), r"^\d+\.\d+\.\d+$")


class MinimumAgainstFloor(unittest.TestCase):
    def test_a_minimum_below_the_floor_is_refused(self):
        problems = gum.validate_manifest(manifest(entry("0.3.0", "0.2.9")), False, floor="0.3.0")
        self.assertTrue(any("below 0.3.0" in p for p in problems), problems)

    def test_a_minimum_at_or_above_the_floor_is_accepted(self):
        for minimum in ("0.3.0", "0.3.1"):
            self.assertEqual(
                gum.validate_manifest(manifest(entry("0.3.1", minimum)), False, floor="0.3.0"), [],
            )

    def test_a_release_older_than_its_generations_floor_is_refused(self):
        problems = gum.validate_manifest(manifest(entry("0.2.0", "0.2.0")), False, floor="0.3.0")
        self.assertTrue(any("older than 0.3.0" in p for p in problems), problems)

    def test_a_nightly_of_the_floor_release_counts_as_that_release(self):
        self.assertEqual(
            gum.validate_manifest(manifest(entry("0.3.0-nightly.1", "0.3.0")), False, floor="0.3.0"), [],
        )


class Commands(unittest.TestCase):
    def setUp(self):
        # Never sign with a key the developer's shell happens to hold.
        saved = os.environ.pop("MANIFEST_SIGNING_KEY", None)
        if saved is not None:
            self.addCleanup(os.environ.__setitem__, "MANIFEST_SIGNING_KEY", saved)

    def run_generate(self, root, minimum, version="0.3.0"):
        out = Path(tempfile.mkdtemp()) / "m.json"
        artifacts = Path(tempfile.mkdtemp()) / "a.json"
        artifacts.write_text(json.dumps([{
            "platform": "macos", "arch": "aarch64", "install_source": "standalone",
            "artifact_url": "https://example.invalid/a.pkg", "artifact_sha256": "0" * 64,
            "artifact_size": 1,
        }]), encoding="utf-8")
        code = gum.main([
            "generate", "--channel", "beta", "--version", version, "--min-version", minimum,
            "--artifacts", str(artifacts), "--out", str(out), "--repo-root", str(root),
        ])
        return code, out

    def test_generate_refuses_a_minimum_below_the_generation_floor(self):
        root = make_tree(notes="- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.3.0\n")
        code, out = self.run_generate(root, "0.0.0")
        self.assertEqual(code, 5)
        self.assertFalse(out.exists())

    def test_generate_refuses_an_unrecorded_generation(self):
        root = make_tree(protocol=9, notes="- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.3.0\n")
        code, _ = self.run_generate(root, "0.3.0")
        self.assertEqual(code, 6)

    def test_generate_writes_a_manifest_whose_minimum_meets_the_floor(self):
        root = make_tree(notes="- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.3.0\n")
        code, out = self.run_generate(root, "0.3.0")
        self.assertEqual(code, 0)
        body = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(body["releases"][0]["minimum_supported_version"], "0.3.0")

    def test_resign_cannot_lower_the_minimum_below_the_floor(self):
        root = make_tree(notes="- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.3.0\n")
        src = Path(tempfile.mkdtemp()) / "in.json"
        src.write_text(json.dumps(manifest(entry("0.3.0", "0.3.0"))), encoding="utf-8")
        out = Path(tempfile.mkdtemp()) / "out.json"
        code = gum.main(["resign", "--input", str(src), "--min-version", "0.1.0",
                         "--out", str(out), "--repo-root", str(root)])
        self.assertEqual(code, 5)


if __name__ == "__main__":
    unittest.main()
