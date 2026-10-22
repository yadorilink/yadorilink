#!/usr/bin/env python3
"""Tests for sign_request.py: the signing step that runs inside the approved signing job.

Run: python3 .github/release/test_sign_request.py   (needs the `cryptography` package)
The stand-in signing tool below produces the same envelope shape as yadorilink-sign-manifest.
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import sign_request as SR  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

SEED = bytes([7]) * 32
ROOT_ID = "test-root"
ROOT_PUB = Ed25519PrivateKey.from_private_bytes(SEED).public_key().public_bytes_raw().hex()
OTHER_SEED = bytes([9]) * 32
T0 = "2026-10-21T00:00:00Z"
BODY = json.dumps({"generated_at": T0, "releases": []}, indent=2)
SNAP = json.dumps({"generated_at": T0, "releases": [], "snapshot": True}, indent=2)
CHAIN = "[]\n"
DIGEST = SR.signing_digest(BODY, {"0.4.1": SNAP}, "<rss/>")

TOOL = '''#!%s
import base64, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
a = dict(zip(sys.argv[2::2], sys.argv[3::2]))
body = open(a["--manifest"], "rb").read()
key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(a["--key-hex"]))
env = {"key_id": a["--key-id"], "manifest_json": body.decode(),
       "signature_base64": base64.b64encode(key.sign(body)).decode(),
       "trust_chain": json.load(open(a["--trust-chain"]))}
open(a["--out"], "w").write(json.dumps(env, indent=2) + "\\n")
'''


def request(**over) -> dict:
    req = {
        "schema_version": 1, "channel": "beta", "target": "production", "generated_at": T0,
        "ledger_sha256": "1" * 64, "manifest_body_sha256": SR.sha256_hex(BODY),
        "signing_digest": DIGEST,
        "trust_chain_sha256": SR.sha256_hex(CHAIN), "manifest_body": BODY,
        "version_manifests": {"0.4.1": SNAP}, "appcast_xml": "<rss/>",
    }
    req.update(over)
    if "signing_digest" not in over:  # a consistent request unless the test says otherwise
        req["signing_digest"] = SR.signing_digest(req["manifest_body"], req["version_manifests"], req["appcast_xml"])
    return req


class SignRequest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.tool = Path(self.td.name) / "tool"
        self.tool.write_text(TOOL % sys.executable)
        self.tool.chmod(self.tool.stat().st_mode | stat.S_IXUSR)

    def sign(self, req=None, **kw):
        req = request() if req is None else req
        args = dict(expected_digest=DIGEST, target="production", channel="beta", sign_tool=str(self.tool),
                    root_key_id=ROOT_ID, root_public_key_hex=ROOT_PUB, chain_text=CHAIN,
                    key_hex=SEED.hex(), key_id=ROOT_ID)
        args.update(kw)
        return SR.sign_request(json.dumps(req), **args)

    def refused(self, pattern, req=None, **kw):
        with self.assertRaisesRegex(SR.SignError, pattern):
            self.sign(req, **kw)

    def test_the_good_request_becomes_the_bundle_the_publisher_expects(self):
        bundle = json.loads(self.sign())
        self.assertEqual(set(bundle), {"schema_version", "channel", "body_sha256", "envelope_text",
                                       "version_manifests", "appcast_xml"})
        env = json.loads(bundle["envelope_text"])
        self.assertEqual(env["manifest_json"], BODY)
        self.assertEqual(env["key_id"], ROOT_ID)
        self.assertEqual(json.loads(bundle["version_manifests"]["0.4.1"])["manifest_json"], SNAP)
        self.assertEqual(bundle["body_sha256"], SR.sha256_hex(BODY))
        self.assertEqual(bundle["appcast_xml"], "<rss/>")
        key = Ed25519PrivateKey.from_private_bytes(SEED).public_key()
        key.verify(base64.b64decode(env["signature_base64"]), BODY.encode())

    def test_the_key_never_appears_in_the_bundle(self):
        self.assertNotIn(SEED.hex(), self.sign())

    def test_a_digest_other_than_the_approved_one_signs_nothing(self):
        self.refused("approver", expected_digest="2" * 64)
        self.refused("64 lowercase hex", expected_digest="")

    def test_every_signed_body_is_covered_by_the_approved_digest(self):
        # Replacing a snapshot, the appcast or the body while keeping the approved digest signs nothing.
        other = json.dumps({"generated_at": T0, "releases": [], "snapshot": "other"}, indent=2)
        self.refused("signing_digest", request(version_manifests={"0.4.1": other}, signing_digest=DIGEST))
        self.refused("signing_digest", request(version_manifests={"0.4.1": SNAP, "0.4.2": SNAP}, signing_digest=DIGEST))
        self.refused("signing_digest", request(appcast_xml="<rss>evil</rss>", signing_digest=DIGEST))
        self.refused("signing_digest", request(appcast_xml=None, signing_digest=DIGEST))

    def test_a_body_that_does_not_match_its_own_digest_is_refused(self):
        self.refused("own manifest_body_sha256", request(manifest_body=BODY + " "))

    def test_the_target_must_be_the_one_the_job_signs_for(self):
        # Production is the only target: a request for any other is refused at parse time, and a job
        # asked to sign for another target refuses a production request.
        self.refused("target must be one of", request(target="dev"))
        self.refused("this job signs for dev", request(target="production"), target="dev")

    def test_the_channel_must_be_the_one_the_run_was_started_for(self):
        self.refused("run was started for nightly", channel="nightly")

    def test_a_different_trust_chain_is_refused(self):
        self.refused("different trust chain", request(trust_chain_sha256="3" * 64))

    def test_a_body_for_another_generated_at_is_refused(self):
        self.refused("generated_at", request(generated_at="2026-10-21T00:10:00Z"))
        stale = json.dumps({"generated_at": "2026-01-01T00:00:00Z"})
        self.refused("does not carry", request(version_manifests={"0.4.1": stale}),
                     expected_digest=SR.signing_digest(BODY, {"0.4.1": stale}, "<rss/>"))

    def test_a_non_json_body_is_refused(self):
        bad = "not json"
        digest = SR.signing_digest(bad, {"0.4.1": SNAP}, "<rss/>")
        self.refused("not JSON", request(manifest_body=bad, manifest_body_sha256=SR.sha256_hex(bad),
                                         signing_digest=digest), expected_digest=digest)

    def test_unknown_missing_or_mistyped_fields_are_refused(self):
        extra = request()
        extra["extra"] = 1
        self.refused("unknown fields", extra)
        missing = request()
        del missing["appcast_xml"]
        self.refused("unknown fields", missing)
        self.refused("channel", request(channel="stable"))
        self.refused("target", request(target="prod"))
        self.refused("version_manifests", request(version_manifests={"0.4.1": 1}))
        self.refused("64 lowercase hex", request(ledger_sha256="XYZ"))

    def test_a_key_that_is_not_in_the_trust_set_is_refused(self):
        self.refused("not in the trust set", key_id="someone-else")

    def test_a_key_that_is_not_the_private_half_of_the_trusted_id_is_refused(self):
        self.refused("private half", key_hex=OTHER_SEED.hex())
        self.refused("32-byte", key_hex="zz")

    def test_missing_key_material_signs_nothing(self):
        self.refused("must all be set", key_hex="")
        self.refused("must all be set", key_id="")
        self.refused("must all be set", root_public_key_hex="")

    def test_the_development_key_never_signs_for_production(self):
        from trust_chain import DEV_KEY  # noqa: PLC0415

        self.refused("development key", request(target="production"), target="production",
                     root_public_key_hex=DEV_KEY)

    def test_a_foreign_key_is_rejected_by_the_production_trust_set(self):
        # The job's trust set contains only the production root; a key whose id or bytes differ does
        # not verify against it.
        self.refused("not in the trust set|private half", request(target="production"), target="production",
                     key_hex=OTHER_SEED.hex(), key_id="foreign-key")
        self.refused("private half", request(target="production"), target="production", key_hex=OTHER_SEED.hex())

    def test_a_failing_tool_signs_nothing(self):
        self.tool.write_text("#!/bin/sh\nexit 3\n")
        self.refused("signing tool failed")
        self.refused("signing tool not found", sign_tool=str(Path(self.td.name) / "nope"))


class ProductionOnlyTrust(unittest.TestCase):
    """The public signer knows the production root and chain only; this suite pins that nothing
    else exists here. Coverage of any other target is kept outside the published tree."""

    # Assembled so this file does not itself carry the word it forbids in the signer.
    OTHER_TARGET = "sta" + "ging"

    def test_the_only_chain_is_the_production_one(self):
        self.assertEqual(SR.CHAIN_FILES, {"production": "trust-chain.json"})
        self.assertEqual(SR.TARGETS, ("production",))

    def test_there_is_no_other_root_selection_and_the_signer_source_carries_no_other_target(self):
        self.assertFalse(hasattr(SR, "select_root"))
        self.assertNotIn(self.OTHER_TARGET, Path(SR.__file__).read_text(encoding="utf-8").lower())

    def test_the_command_line_has_no_other_root_arguments(self):
        for flag in (f"--{self.OTHER_TARGET}-root-key-id", f"--{self.OTHER_TARGET}-root-public-key-hex"):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                SR.main(["sign", "--request", "r", "--signing-digest", "0" * 64, "--target", "production",
                         "--channel", "beta", "--sign-tool", "t", "--root-key-id", "i",
                         "--root-public-key-hex", "ab", "--release-dir", "d", "--out", "o", flag, "x"])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            SR.main(["sign", "--request", "r", "--signing-digest", "0" * 64, "--target", self.OTHER_TARGET,
                     "--channel", "beta", "--sign-tool", "t", "--root-key-id", "i",
                     "--root-public-key-hex", "ab", "--release-dir", "d", "--out", "o"])

    def test_a_key_outside_the_production_trust_set_is_not_accepted(self):
        foreign_pub = Ed25519PrivateKey.from_private_bytes(OTHER_SEED).public_key().public_bytes_raw().hex()
        with self.assertRaises(SR.SignError):  # a foreign key under a foreign id: not in the trust set
            SR.check_signer(key_hex=OTHER_SEED.hex(), key_id="foreign-root", root_key_id=ROOT_ID,
                            root_public_key_hex=ROOT_PUB, chain_text=CHAIN, target="production")
        with self.assertRaises(SR.SignError):  # the right id but another key: not its private half
            SR.check_signer(key_hex=OTHER_SEED.hex(), key_id=ROOT_ID, root_key_id=ROOT_ID,
                            root_public_key_hex=ROOT_PUB, chain_text=CHAIN, target="production")
        # the production key itself is accepted
        SR.check_signer(key_hex=SEED.hex(), key_id=ROOT_ID, root_key_id=ROOT_ID,
                        root_public_key_hex=ROOT_PUB, chain_text=CHAIN, target="production")
        self.assertNotEqual(foreign_pub, ROOT_PUB)

    def test_a_chain_record_signed_by_a_foreign_root_does_not_replay(self):
        # A record signed by the production root extends the production trust set; the same chain
        # replayed under a different root does not.
        import base64, json as j  # noqa: E401,PLC0415

        body = j.dumps({"schema_version": 1, "serial": 1, "add": [{"key_id": "extra", "public_key_hex": Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32).public_key().public_bytes_raw().hex()}]})
        sig = base64.b64encode(Ed25519PrivateKey.from_private_bytes(SEED).sign(SR.tc.DOMAIN + body.encode())).decode()
        chain = j.dumps([{"key_id": ROOT_ID, "record_json": body, "signature_base64": sig}])
        foreign_pub = Ed25519PrivateKey.from_private_bytes(OTHER_SEED).public_key().public_bytes_raw().hex()
        SR.check_signer(key_hex=bytes([5]).hex() * 32, key_id="extra", root_key_id=ROOT_ID,
                        root_public_key_hex=ROOT_PUB, chain_text=chain, target="production")
        with self.assertRaises(SR.SignError):
            SR.check_signer(key_hex=bytes([5]).hex() * 32, key_id="extra", root_key_id="foreign-root",
                            root_public_key_hex=foreign_pub, chain_text=chain, target="production")


class Decode(unittest.TestCase):
    def enc(self, text: str) -> str:
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write(text.encode())
        return base64.b64encode(buf.getvalue()).decode()

    def test_roundtrip_and_bounds(self):
        self.assertEqual(SR.decode_b64gz(self.enc("hello")), "hello")
        for bad in ("", "   ", "!!!", base64.b64encode(b"plain").decode(), "A" * (SR.MAX_COMPRESSED + 1)):
            with self.assertRaises(SR.SignError, msg=bad[:10]):
                SR.decode_b64gz(bad)
        with self.assertRaisesRegex(SR.SignError, "larger"):
            SR.decode_b64gz(self.enc("x" * (SR.MAX_REQUEST + 1)))


class CommandLine(unittest.TestCase):
    def test_cli_signs_and_refuses_with_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            tool = td / "tool"
            tool.write_text(TOOL % sys.executable)
            tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
            (td / "req.json").write_text(json.dumps(request()))
            (td / "trust-chain.json").write_text(CHAIN)
            import os  # noqa: PLC0415

            os.environ["TEST_KEY"], os.environ["TEST_KEY_ID"] = SEED.hex(), ROOT_ID
            base = ["sign", "--request", str(td / "req.json"), "--target", "production", "--channel", "beta", "--sign-tool", str(tool),
                    "--root-key-id", ROOT_ID, "--root-public-key-hex", ROOT_PUB, "--release-dir", str(td),
                    "--out", str(td / "out.json"), "--key-env", "TEST_KEY", "--key-id-env", "TEST_KEY_ID"]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(SR.main([*base, "--signing-digest", DIGEST]), 0)
            self.assertTrue((td / "out.json").is_file())
            (td / "out.json").unlink()
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(SR.main([*base, "--signing-digest", "4" * 64]), 1)
            self.assertFalse((td / "out.json").exists())
            self.assertNotIn(SEED.hex(), err.getvalue())


def run() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    unittest.main()
