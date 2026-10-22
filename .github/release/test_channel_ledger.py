"""Tests for the channel ledger, release records and `assemble`.

Run: python3 .github/release/test_channel_ledger.py
"""

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import channel_ledger as cl  # noqa: E402

spec = importlib.util.spec_from_file_location("generate_update_manifest", HERE / "generate-update-manifest.py")
gum = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gum)

FLOOR = "0.3.0"
AT = "2026-10-19T00:00:00Z"
CHAIN = "[]\n"
H = "a" * 64


def record(version, lane="beta", gen=(4, 2), sources=("script", "app_bundle", "microsoft_store")):
    rid = f"rel-{version}"
    rec = {
        "schema_version": 1, "version": version, "tag": f"v{version}",
        "public_commit_sha": "b" * 40, "build_lane": lane, "release_id": rid,
        "engine_api_version": "1", "state_schema": "1",
        "protocol_generation": {"protocol_version": gen[0], "rpc_version": gen[1]},
    }
    if "script" in sources:
        rec["script"] = {
            f"linux-x86_64": {"asset": f"yadorilink-{version}-linux-x86_64.zip", "sha256": H, "size": 10,
                              "bundle_sha256": "c" * 64, "attestation_digest": "sha256:" + "d" * 64,
                              "github_url": "https://github.com/o/r/releases/download/x/y.zip"},
            f"macos-aarch64": {"asset": f"yadorilink-{version}-macos-aarch64.zip", "sha256": H, "size": 11,
                               "bundle_sha256": "c" * 64, "attestation_digest": "sha256:" + "d" * 64,
                               "github_url": "https://github.com/o/r/releases/download/x/z.zip"},
        }
    if "app_bundle" in sources:
        rec["app_bundle"] = {"macos-aarch64": {
            "file": f"YadoriLink-{version}.dmg", "sha256": "e" * 64, "size": 99, "sparkle_build": "42",
            "notarization_evidence_sha256": "f" * 64, "engine_release_id": rid}}
    if "microsoft_store" in sources:
        rec["microsoft_store"] = {"windows-x86_64": {
            "package_version": f"{version}.0", "submission_id": "sub1", "upload_sha256": "1" * 64,
            "upload_size": 7}}
    return rec


def ledger(versions=None, minimum="0.3.0", channel="beta", **extra):
    versions = versions or {"script": "0.4.2", "app_bundle": "0.4.2", "microsoft_store": "0.4.2"}
    led = {
        "schema_version": 1, "channel": channel, "minimum_supported_version": minimum,
        "entries": {s: {"version": v, "rollout_percentage": 100, "kill_switch": False}
                    for s, v in versions.items()},
        "reason": "test",
        "history": {s: [v] for s, v in versions.items()},
    }
    led.update(extra)
    return led


def records(*versions, **kw):
    return {v: record(v, **kw) for v in versions}


def run(led, recs, **kw):
    kw.setdefault("floor", FLOOR)
    return cl.assemble(led, recs, CHAIN, AT, **kw)


def problems_of(led, recs, **kw):
    try:
        run(led, recs, **kw)
    except cl.LedgerError as ex:
        return ex.problems
    return []


def has(tc, problems, needle):
    tc.assertTrue(any(needle in p for p in problems), problems)


class Assemble(unittest.TestCase):
    def test_builds_one_entry_per_source_platform_arch_with_own_version(self):
        led = ledger({"script": "0.4.2", "app_bundle": "0.4.2", "microsoft_store": "0.4.1"})
        led["history"]["microsoft_store"] = ["0.4.1"]
        plan = run(led, records("0.4.2", "0.4.1"))
        body = json.loads(plan["manifest_body"])
        got = [(r["install_source"], r["platform"], r["arch"], r["version"]) for r in body["releases"]]
        self.assertEqual(got, [
            ("script", "linux", "x86_64", "0.4.2"), ("script", "macos", "aarch64", "0.4.2"),
            ("app_bundle", "macos", "aarch64", "0.4.2"), ("microsoft_store", "windows", "x86_64", "0.4.1"),
        ])
        self.assertTrue(all(r["artifact_url"].startswith(cl.DL_PREFIX) for r in body["releases"]))
        self.assertEqual(body["generated_at"], AT)
        self.assertNotIn("withdrawn_versions", body)

    def test_byte_stable_for_a_fixed_generated_at(self):
        a = run(ledger(), records("0.4.2"))
        b = run(copy.deepcopy(ledger()), copy.deepcopy(records("0.4.2")))
        self.assertEqual(a, b)
        self.assertEqual(a["manifest_body_sha256"], cl.sha256_hex(a["manifest_body"]))
        c = cl.assemble(ledger(), records("0.4.2"), CHAIN, "2026-10-19T00:00:01Z", floor=FLOOR)
        self.assertNotEqual(a["manifest_body"], c["manifest_body"])

    def test_body_passes_the_generic_manifest_validation(self):
        body = json.loads(run(ledger(), records("0.4.2"))["manifest_body"])
        self.assertEqual(gum.validate_manifest(body, False, floor=FLOOR), [])

    def test_generated_at_must_be_explicit_and_well_formed(self):
        has(self, _err(lambda: cl.assemble(ledger(), records("0.4.2"), CHAIN, "yesterday", floor=FLOOR)),
            "generated_at")

    def test_trust_chain_must_be_a_json_array(self):
        has(self, _err(lambda: cl.assemble(ledger(), records("0.4.2"), "{}", AT, floor=FLOOR)),
            "JSON array")
        plan = run(ledger(), records("0.4.2"))
        self.assertEqual(plan["trust_chain_sha256"], cl.sha256_hex(CHAIN))


def _err(fn):
    try:
        fn()
    except cl.LedgerError as ex:
        return ex.problems
    return []


class LedgerRules(unittest.TestCase):
    def test_channel_allowlist(self):
        has(self, problems_of(ledger(channel="stable"), records("0.4.2")), "is not one of")

    def test_ledger_file_name_must_match_channel(self):
        has(self, problems_of(ledger(), records("0.4.2"), ledger_stem="nightly"), "does not match its file name")

    def test_unknown_install_source_and_fields_refused(self):
        led = ledger()
        led["entries"]["winget"] = {"version": "0.4.2", "rollout_percentage": 100, "kill_switch": False}
        has(self, problems_of(led, records("0.4.2")), "unknown install_source")
        led = ledger()
        led["surprise"] = 1
        has(self, problems_of(led, records("0.4.2")), "unknown fields")

    def test_minimum_below_cutover_floor(self):
        has(self, problems_of(ledger(minimum="0.2.9"), records("0.4.2")), "below 0.3.0")

    def test_minimum_compares_full_precedence_not_just_the_core(self):
        led = ledger({"script": "0.4.2-beta.1"}, minimum="0.4.2")
        has(self, problems_of(led, records("0.4.2-beta.1")), "exceeds script version")

    def test_minimum_above_a_sources_version(self):
        led = ledger({"script": "0.4.2", "app_bundle": "0.4.2", "microsoft_store": "0.4.1"}, minimum="0.4.2")
        has(self, problems_of(led, records("0.4.2", "0.4.1")), "exceeds microsoft_store version 0.4.1")

    def test_version_below_generation_floor(self):
        has(self, problems_of(ledger({"script": "0.2.0"}), records("0.2.0")), "older than 0.3.0")

    def test_minimum_above_live_version_of_previous_ledger(self):
        prev = ledger({"script": "0.4.1", "app_bundle": "0.4.1", "microsoft_store": "0.4.1"})
        led = ledger(minimum="0.4.2")
        has(self, problems_of(led, records("0.4.1", "0.4.2"), previous_ledger=prev), "already live")

    def test_minimum_the_generation_floor_demands_may_precede_live(self):
        prev = ledger({"script": "0.2.0"}, minimum="0.1.0")
        led = ledger({"script": "0.3.0"}, minimum="0.3.0")
        led["history"]["script"] = ["0.2.0", "0.3.0"]
        self.assertEqual(problems_of(led, records("0.2.0", "0.3.0"), previous_ledger=prev), [])

    def test_only_the_floor_itself_is_exempt_from_the_live_minimum_rule(self):
        prev = ledger({"script": "0.3.0-beta.2"}, minimum="0.3.0")
        led = ledger({"script": "0.3.0-beta.3"}, minimum="0.3.0-beta.3")
        led["history"]["script"] = ["0.3.0-beta.2", "0.3.0-beta.3"]
        prev["history"]["script"] = ["0.3.0-beta.2"]
        has(self, problems_of(led, records("0.3.0-beta.2", "0.3.0-beta.3"), previous_ledger=prev), "already live")

    def test_history_may_only_gain_the_version_now_served(self):
        prev = ledger({"script": "0.4.2"})
        led = ledger({"script": "0.4.3"})
        led["history"]["script"] = ["0.4.2", "0.4.1", "0.4.3"]
        has(self, problems_of(led, records("0.4.2", "0.4.3"), previous_ledger=prev), "may only gain")

    def test_history_for_an_unserved_source_cannot_be_fabricated(self):
        prev = ledger({"script": "0.4.2"})
        led = ledger({"script": "0.4.2"})
        led["history"]["app_bundle"] = ["0.4.1"]
        has(self, problems_of(led, records("0.4.2"), previous_ledger=prev), "may only gain")

    def test_minimum_above_live_appcast_version(self):
        led = ledger({"script": "0.4.2", "app_bundle": "0.4.2"}, minimum="0.4.2")
        has(self, problems_of(led, records("0.4.2"), served_appcast_version="0.4.1"), "already live for app_bundle")
        self.assertEqual(problems_of(led, records("0.4.2"), served_appcast_version="0.4.2"), [])

    def test_missing_record(self):
        has(self, problems_of(ledger(), {}), "no release record")

    def test_record_without_the_sources_artifacts(self):
        has(self, problems_of(ledger(), records("0.4.2", sources=("script",))), "has no app_bundle")

    def test_nightly_bytes_never_enter_beta(self):
        has(self, problems_of(ledger(), records("0.4.2", lane="dev")), "lane")
        self.assertEqual(problems_of(ledger(channel="nightly"), records("0.4.2", lane="dev")), [])

    def test_entries_at_different_versions_need_one_protocol_generation(self):
        led = ledger({"script": "0.4.2", "app_bundle": "0.4.1"})
        recs = {"0.4.2": record("0.4.2", gen=(5, 2)), "0.4.1": record("0.4.1", gen=(4, 2))}
        has(self, problems_of(led, recs), "different protocol generations")
        recs["0.4.1"] = record("0.4.1", gen=(5, 2))
        self.assertEqual(problems_of(led, recs), [])

    def test_version_must_be_in_history_and_not_withdrawn(self):
        led = ledger()
        led["history"]["script"] = ["0.4.0"]
        has(self, problems_of(led, records("0.4.2")), "missing from history")
        led = ledger(withdrawn_versions=["0.4.2"])
        has(self, problems_of(led, records("0.4.2")), "withdrawn_versions")

    def test_bad_rollout_and_kill_switch_types(self):
        led = ledger()
        led["entries"]["script"]["rollout_percentage"] = 101
        led["entries"]["app_bundle"]["kill_switch"] = "yes"
        p = problems_of(led, records("0.4.2"))
        has(self, p, "rollout_percentage")
        has(self, p, "kill_switch")


class Transitions(unittest.TestCase):
    def prev(self):
        return ledger({"script": "0.4.2", "app_bundle": "0.4.2"})

    def test_forward_promotion_is_fine(self):
        led = ledger({"script": "0.4.3", "app_bundle": "0.4.3"})
        led["history"] = {s: [("0.4.2"), "0.4.3"] for s in ("script", "app_bundle")}
        self.assertEqual(problems_of(led, records("0.4.2", "0.4.3"), previous_ledger=self.prev()), [])

    def test_removing_a_served_install_source_is_refused(self):
        led = ledger({"script": "0.4.2"})
        has(self, problems_of(led, records("0.4.2"), previous_ledger=self.prev()), "was removed")

    def test_promotion_may_not_drop_a_served_target(self):
        led = ledger({"script": "0.4.3"})
        led["history"]["script"] = ["0.4.2", "0.4.3"]
        recs = records("0.4.2", "0.4.3")
        del recs["0.4.3"]["script"]["macos-aarch64"]
        has(self, problems_of(led, recs, previous_ledger=ledger({"script": "0.4.2"})), "drops served target")

    def test_moving_back_without_yank_is_refused(self):
        led = ledger({"script": "0.4.1", "app_bundle": "0.4.2"})
        led["history"] = {"script": ["0.4.1"], "app_bundle": ["0.4.2"]}
        prev = self.prev()
        prev["history"]["script"] = ["0.4.1", "0.4.2"]
        led["history"]["script"] = ["0.4.1", "0.4.2"]
        has(self, problems_of(led, records("0.4.1", "0.4.2"), previous_ledger=prev), "only a ledger reason")

    def yank_fixture(self, **over):
        prev = ledger({"script": "0.4.2"})
        prev["history"]["script"] = ["0.4.1", "0.4.2"]
        led = ledger({"script": "0.4.1"}, reason="yank 0.4.2", withdrawn_versions=["0.4.2"])
        led["history"]["script"] = ["0.4.1", "0.4.2"]
        led.update(over)
        return prev, led

    def test_yank_to_a_previously_live_version_is_allowed(self):
        prev, led = self.yank_fixture()
        m = json.loads(run(led, records("0.4.1", "0.4.2"), previous_ledger=prev)["manifest_body"])
        self.assertEqual(m["withdrawn_versions"], ["0.4.2"])
        self.assertEqual(m["releases"][0]["version"], "0.4.1")

    def test_yank_must_list_the_bad_version_as_withdrawn(self):
        prev, led = self.yank_fixture()
        del led["withdrawn_versions"]
        has(self, problems_of(led, records("0.4.1", "0.4.2"), previous_ledger=prev), "must be listed in withdrawn_versions")

    def test_yank_reason_must_name_the_bad_version(self):
        prev, led = self.yank_fixture(reason="yank 0.4.9")
        has(self, problems_of(led, records("0.4.1", "0.4.2"), previous_ledger=prev), "only a ledger reason")

    def test_yank_target_must_have_been_live(self):
        prev, led = self.yank_fixture()
        prev["history"]["script"] = ["0.4.2"]
        led["history"]["script"] = ["0.4.2", "0.4.1"]
        has(self, problems_of(led, records("0.4.1", "0.4.2"), previous_ledger=prev), "never live")

    def test_yank_must_stay_in_the_bad_versions_generation(self):
        prev, led = self.yank_fixture()
        recs = {"0.4.1": record("0.4.1", gen=(4, 2)), "0.4.2": record("0.4.2", gen=(5, 2))}
        has(self, problems_of(led, recs, previous_ledger=prev), "same protocol generation")

    def test_withdrawn_and_history_are_append_only(self):
        prev = ledger({"script": "0.4.2"}, withdrawn_versions=["0.4.0"])
        led = ledger({"script": "0.4.2"})
        p = problems_of(led, records("0.4.2"), previous_ledger=prev)
        has(self, p, "may only grow")
        prev = ledger({"script": "0.4.2"})
        prev["history"]["script"] = ["0.4.1", "0.4.2"]
        has(self, problems_of(ledger({"script": "0.4.2"}), records("0.4.2"), previous_ledger=prev), "append only")


class RecordRules(unittest.TestCase):
    def bad(self, mutate, needle):
        rec = record("0.4.2")
        mutate(rec)
        has(self, problems_of(ledger(), {"0.4.2": rec}), needle)

    def test_record_shape(self):
        self.bad(lambda r: r.update(public_commit_sha="xyz"), "public_commit_sha")
        self.bad(lambda r: r.update(build_lane="stable"), "build_lane")
        self.bad(lambda r: r.update(extra=1), "unknown fields")
        self.bad(lambda r: r["script"]["linux-x86_64"].update(sha256="nothex"), "sha256")
        self.bad(lambda r: r["script"]["linux-x86_64"].update(asset="../../evil"), "asset")
        self.bad(lambda r: r["script"].update({"plan9-mips": r["script"]["linux-x86_64"]}), "target must look like")
        self.bad(lambda r: r["script"]["linux-x86_64"].update(size=0), "size")
        self.bad(lambda r: r["app_bundle"]["macos-aarch64"].pop("sparkle_build"), "missing")

    def test_app_bundle_engine_release_id_must_equal_record(self):
        self.bad(lambda r: r["app_bundle"]["macos-aarch64"].update(engine_release_id="other"), "engine_release_id")

    def test_app_bundle_is_macos_and_store_is_windows(self):
        self.bad(lambda r: r["app_bundle"].update({"linux-x86_64": r["app_bundle"]["macos-aarch64"]}), "must be macos")

    def test_file_name_must_match_version(self):
        has(self, problems_of(ledger(), {"0.4.2": record("0.4.3")}), "does not match its file name")

    def test_versions_the_client_parser_would_reject_are_refused(self):
        for bad in ("0.04.2", "0.4.2-01", "0.4.2-a..b", "v0.4.2", "0.4", "0.4.2-", "1.0.0+build.5"):
            with self.assertRaises(ValueError):
                cl.semver_key(bad)
        for ok in ("0.4.2", "0.4.2-nightly.1", "1.0.0-rc.5"):
            cl.semver_key(ok)
        self.assertLess(cl.semver_key("0.4.2-rc.1"), cl.semver_key("0.4.2"))

    def test_duplicate_json_keys_are_refused(self):
        with self.assertRaises(cl.LedgerError):
            cl.load_json('{"a": 1, "a": 2}', "x")


class UrlsAndUniqueness(unittest.TestCase):
    def test_urls_only_under_dl(self):
        base = {"channel": "beta", "install_source": "script", "platform": "linux", "arch": "x86_64"}
        for bad in ("https://evil.example/dl/x.zip", "http://yadori.link/dl/x.zip",
                    "https://yadori.link/dl/../x.zip", "https://yadori.link/dl/x.zip?a=b",
                    "https://yadori.link/dl/https://evil/x.zip", "https://yadori.link/downloads/x.zip"):
            p = cl.check_unique_and_urls([dict(base, artifact_url=bad)])
            has(self, p, "is not under")
        self.assertEqual(cl.check_unique_and_urls([dict(base, artifact_url="https://yadori.link/dl/0.4.2/x.zip")]), [])

    def test_one_entry_per_tuple(self):
        e = {"channel": "beta", "install_source": "script", "platform": "linux", "arch": "x86_64",
             "artifact_url": "https://yadori.link/dl/0.4.2/x.zip"}
        has(self, cl.check_unique_and_urls([e, dict(e)]), "duplicates")


class AppcastGate(unittest.TestCase):
    def setUp(self):
        self.plan = run(ledger(), records("0.4.2"))
        self.manifest = json.loads(self.plan["manifest_body"])

    def test_appcast_is_built_from_the_app_bundle_entry_alone(self):
        items = self.plan["appcast"]["items"]
        self.assertEqual([(i["platform"], i["arch"], i["version"]) for i in items], [("macos", "aarch64", "0.4.2")])
        self.assertEqual(cl.check_appcast_covered(self.plan["appcast"], self.manifest), [])

    def test_item_without_a_covering_manifest_entry(self):
        ap = copy.deepcopy(self.plan["appcast"])
        ap["items"][0]["arch"] = "x86_64"
        has(self, cl.check_appcast_covered(ap, self.manifest), "no app_bundle entry")

    def test_item_ahead_of_the_manifest(self):
        ap = copy.deepcopy(self.plan["appcast"])
        ap["items"][0]["version"] = "0.4.3"
        has(self, cl.check_appcast_covered(ap, self.manifest), "not the manifest's app_bundle version")

    def test_item_for_a_kill_switched_entry(self):
        m = copy.deepcopy(self.manifest)
        for r in m["releases"]:
            if r["install_source"] == "app_bundle":
                r["kill_switch"] = True
        has(self, cl.check_appcast_covered(self.plan["appcast"], m), "kill-switches")

    def test_item_whose_dmg_facts_differ(self):
        ap = copy.deepcopy(self.plan["appcast"])
        ap["items"][0]["sha256"] = "0" * 64
        has(self, cl.check_appcast_covered(ap, self.manifest), "do not match")

    def test_kill_switched_entry_generates_no_item(self):
        led = ledger()
        led["entries"]["app_bundle"]["kill_switch"] = True
        plan = run(led, records("0.4.2"))
        self.assertEqual(plan["appcast"]["items"], [])

    def test_zero_rollout_offers_nothing_and_partial_rollout_is_carried(self):
        led = ledger()
        led["entries"]["app_bundle"]["rollout_percentage"] = 0
        self.assertEqual(run(led, records("0.4.2"))["appcast"]["items"], [])
        led["entries"]["app_bundle"]["rollout_percentage"] = 25
        self.assertEqual(run(led, records("0.4.2"))["appcast"]["items"][0]["rollout_percentage"], 25)
        ap = copy.deepcopy(self.plan["appcast"])
        ap["items"][0]["rollout_percentage"] = 50
        has(self, cl.check_appcast_covered(ap, self.manifest), "do not match")

    def test_malformed_served_appcast_version_is_an_error(self):
        has(self, problems_of(ledger(), records("0.4.2"), served_appcast_version="v0.4.1"), "served appcast version")

    def test_no_app_bundle_entry_means_no_appcast_items(self):
        plan = run(ledger({"script": "0.4.2"}), records("0.4.2"))
        self.assertEqual(plan["appcast"]["items"], [])


class RecordImmutability(unittest.TestCase):
    def test_cli_ignores_the_placeholder_file(self):
        import subprocess
        root = Path(tempfile.mkdtemp())
        rel = root / ".github" / "channels" / "releases"
        rel.mkdir(parents=True)
        (rel / ".gitkeep").write_text("")
        (rel / "0.4.1.json").write_text("{}")
        for cmd in (["init", "-q"], ["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"]):
            subprocess.run(["git", "-C", str(root), *cmd], check=True)
        args = ["check-records-immutable", "--base-ref", "HEAD", "--repo-root", str(root)]
        self.assertEqual(gum.main(args), 0)
        (rel / "0.4.1.json").write_text("{ }")
        self.assertEqual(gum.main(args), 5)

    def test_edit_and_delete_are_refused_addition_is_fine(self):
        base = {"0.4.1.json": b"a"}
        has(self, cl.check_records_immutable(base, {"0.4.1.json": b"b"}), "edited")
        has(self, cl.check_records_immutable(base, {}), "deleted")
        self.assertEqual(cl.check_records_immutable(base, {"0.4.1.json": b"a", "0.4.2.json": b"c"}), [])


class Cli(unittest.TestCase):
    def tree(self, led, recs):
        root = Path(tempfile.mkdtemp())
        (root / "releases").mkdir()
        (root / "beta.json").write_text(json.dumps(led))
        for v, r in recs.items():
            (root / "releases" / f"{v}.json").write_text(json.dumps(r))
        (root / "chain.json").write_text(CHAIN)
        cut = gum._cutover_guard()
        values = {"PROTOCOL_VERSION": 4, "RPC_VERSION": 2, "CONTROL_PROTOCOL_VERSION": 1, "SCHEMA_VERSION": 1}
        for name, rel in cut.GATES.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(f"pub const {name}: u32 = {values[name]};\n")
        (root / "docs").mkdir(exist_ok=True)
        (root / "docs/CUTOVER.md").write_text(
            "- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.3.0\n")
        return root

    def run_cli(self, root, extra=()):
        out = root / "body.json"
        code = gum.main(["assemble", "--ledger", str(root / "beta.json"), "--records-dir",
                         str(root / "releases"), "--trust-chain", str(root / "chain.json"),
                         "--generated-at", AT, "--out-body", str(out), "--out-appcast", str(root / "ap.json"),
                         "--repo-root", str(root), *extra])
        return code, out

    def test_assemble_writes_identical_bytes_twice(self):
        root = self.tree(ledger(), records("0.4.2"))
        c1, out = self.run_cli(root)
        first = out.read_bytes()
        c2, _ = self.run_cli(root)
        self.assertEqual((c1, c2), (0, 0))
        self.assertEqual(first, out.read_bytes())
        self.assertEqual(json.loads(first)["generated_at"], AT)

    def test_assemble_refuses_a_bad_ledger_without_writing(self):
        root = self.tree(ledger(minimum="0.1.0"), records("0.4.2"))
        code, out = self.run_cli(root)
        self.assertEqual(code, 5)
        self.assertFalse(out.exists())

    def test_existing_generate_command_still_works(self):
        root = self.tree(ledger(), records("0.4.2"))
        arts = root / "a.json"
        arts.write_text(json.dumps([{"platform": "macos", "arch": "aarch64", "install_source": "standalone",
                                     "artifact_url": "https://example.invalid/a.pkg",
                                     "artifact_sha256": "0" * 64, "artifact_size": 1}]))
        out = root / "m.json"
        self.assertEqual(gum.main(["generate", "--channel", "beta", "--version", "0.3.0", "--min-version",
                                   "0.3.0", "--artifacts", str(arts), "--out", str(out),
                                   "--repo-root", str(root), "--generated-at", AT]), 0)
        self.assertEqual(out.read_text(), cl.render_body(json.loads(out.read_text())))


class SchemasMatchValidator(unittest.TestCase):
    """The JSON schemas are documentation; keep their field sets equal to the validator's."""

    def schema(self, name):
        return json.loads((HERE / "channel-schema" / name).read_text())

    def test_ledger_schema(self):
        s = self.schema("ledger.schema.json")
        self.assertEqual(set(s["properties"]), cl.LEDGER_FIELDS)
        self.assertEqual(set(s["properties"]["entries"]["additionalProperties"]["properties"]), cl.ENTRY_FIELDS)
        self.assertEqual(tuple(s["properties"]["channel"]["enum"]), cl.CHANNELS)

    def test_record_schema(self):
        s = self.schema("release-record.schema.json")
        self.assertEqual(set(s["properties"]), cl.RECORD_FIELDS)
        for source, fields in cl.TARGET_FIELDS.items():
            t = s["properties"][source]["additionalProperties"]
            self.assertEqual(set(t["properties"]) - cl.OPTIONAL_TARGET_FIELDS, fields)
            self.assertEqual(set(t["required"]), fields)


if __name__ == "__main__":
    unittest.main()
