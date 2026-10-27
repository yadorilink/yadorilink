"""Tests for the channel ledger, release records and `assemble`.

Run: python3 .github/release/test_channel_ledger.py
"""

import copy
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import channel_ledger as cl  # noqa: E402

spec = importlib.util.spec_from_file_location("generate_update_manifest", HERE / "generate-update-manifest.py")
gum = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gum)

FLOOR = "0.3.0"
AT = "2026-10-19T00:00:00Z"
FRESH = "2026-10-18T12:00:00Z"  # inside the stamp lag before AT
FULL = {"max_rollout_percentage": 100, "kill_switched": False}
CHAIN = "[]\n"
H = "a" * 64


def build_for(version):
    """A Sparkle build that rises with the version (0.4.2 -> 42), as real releases must."""
    core = version.split("-")[0].split(".")
    pre = int(version.rsplit(".", 1)[1]) if "-" in version else 0
    return 1000 * int(core[0]) + 10 * int(core[1]) + int(core[2]) + pre


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
            "file": f"YadoriLink-{version}.dmg", "sha256": "e" * 64, "size": 99,
            "sparkle_build": str(build_for(version)),
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
        "rollout_history": {s: {v: {"max_rollout_percentage": 100, "kill_switched": False}}
                            for s, v in versions.items()},
    }
    led.update(extra)
    return led


def records(*versions, **kw):
    return {v: record(v, **kw) for v in versions}


def settle_rollouts(led, prev=None):
    """Make `led`'s rollout_history truthful for the history and entries the test built by hand:
    keep recorded values, take a version's record from `prev`, else assume it was served at 100%."""
    roll = led.setdefault("rollout_history", {})
    for src, versions in led.get("history", {}).items():
        per = roll.setdefault(src, {})
        for v in versions:
            old = ((prev or {}).get("rollout_history") or {}).get(src, {}).get(v)
            per.setdefault(v, dict(old) if old else {"max_rollout_percentage": 100, "kill_switched": False})
        e = led.get("entries", {}).get(src)
        if e and e["version"] in per:
            r = per[e["version"]]
            r["max_rollout_percentage"] = max(r["max_rollout_percentage"], e["rollout_percentage"])
            r["kill_switched"] = r["kill_switched"] or e["kill_switch"] is True


def run(led, recs, **kw):
    kw.setdefault("floor", FLOOR)
    if isinstance(led, dict) and "rollout_history" in led and isinstance(led.get("history"), dict) \
            and isinstance(led.get("entries"), dict):
        settle_rollouts(led, kw.get("previous_ledger"))
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
        self.assertEqual(body["expires_at"], "2026-12-18T00:00:00Z")
        self.assertEqual(body["expires_at"], cl.expires_at_for(AT))

    def test_every_entry_declares_the_engines_state_version(self):
        recs = records("0.4.2")
        recs["0.4.2"]["state_schema"] = "132"
        body = json.loads(run(ledger(), recs)["manifest_body"])
        self.assertTrue(body["releases"])
        for r in body["releases"]:
            self.assertEqual((r["state_schema_version"], r["state_schema_min_readable"]), (132, 132))

    def test_only_the_app_bundle_entry_carries_the_sparkle_build_as_an_integer(self):
        body = json.loads(run(ledger(), records("0.4.2"))["manifest_body"])
        for r in body["releases"]:
            if r["install_source"] == "app_bundle":
                self.assertEqual(r["sparkle_build"], 42)
            else:
                self.assertNotIn("sparkle_build", r)

    def test_a_record_without_a_usable_state_version_is_refused_not_published_undeclared(self):
        for bad in ("", "abc", "0", "-1", "1.5"):
            recs = records("0.4.2")
            recs["0.4.2"]["state_schema"] = bad
            self.assertTrue(problems_of(ledger(), recs), bad)

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

    def test_expiry_is_sixty_days_after_generation_across_month_and_year_ends(self):
        self.assertEqual(cl.VALIDITY_DAYS, 60)
        self.assertEqual(cl.expires_at_for("2026-12-31T23:59:59Z"), "2027-03-01T23:59:59Z")
        self.assertEqual(cl.expires_at_for("2028-01-01T00:00:00Z"), "2028-03-01T00:00:00Z")
        self.assertRaises(cl.LedgerError, cl.expires_at_for, "yesterday")

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
        has(self, problems_of(ledger(channel="gamma"), records("0.4.2")), "is not one of")

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
        led["rollout_history"] = {s: {"0.4.2": dict(FULL), "0.4.3": dict(FULL)} for s in ("script", "app_bundle")}
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
        prev["rollout_history"]["script"]["0.4.1"] = dict(FULL)
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

    def test_the_ios_engine_target_is_script_only(self):
        def with_ios(r):
            r["script"]["ios-aarch64"] = {**r["script"]["linux-x86_64"], "asset": "yadorilink-engine-dev-ios-aarch64.zip"}
        rec = record("0.4.2")
        with_ios(rec)
        self.assertEqual(problems_of(ledger(), {"0.4.2": rec}), [])
        self.bad(lambda r: r["app_bundle"].update({"ios-aarch64": r["app_bundle"]["macos-aarch64"]}), "must be macos")
        self.bad(lambda r: r["microsoft_store"].update({"ios-aarch64": r["microsoft_store"]["windows-x86_64"]}), "must be windows")

    def test_the_ios_engine_target_is_served_in_the_manifest_for_script_only(self):
        rec = record("0.4.2")
        rec["script"]["ios-aarch64"] = {**rec["script"]["linux-x86_64"], "asset": "yadorilink-engine-dev-ios-aarch64.zip"}
        entries = cl.build_entries(ledger({"script": "0.4.2"}), {"0.4.2": rec})
        ios = [e for e in entries if e["platform"] == "ios"]
        self.assertEqual([(e["arch"], e["install_source"]) for e in ios], [("aarch64", "script")])
        self.assertEqual(ios[0]["artifact_url"], "https://yadori.link/dl/0.4.2/yadorilink-engine-dev-ios-aarch64.zip")
        self.assertEqual(cl.check_unique_and_urls(entries), [])

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

    def test_item_whose_build_differs(self):
        ap = copy.deepcopy(self.plan["appcast"])
        ap["items"][0]["sparkle_build"] = "43"
        has(self, cl.check_appcast_covered(ap, self.manifest), "build")

    def test_kill_switched_entry_generates_no_item(self):
        led = ledger()
        led["entries"]["app_bundle"]["kill_switch"] = True
        led["app_build_tombstones"] = [{"version": led["entries"]["app_bundle"]["version"], "sparkle_build": 42}]
        plan = run(led, records("0.4.2"))
        self.assertEqual(plan["appcast"]["items"], [])

    def test_zero_rollout_offers_nothing_and_partial_rollout_is_carried(self):
        led = ledger()
        led["entries"]["app_bundle"]["rollout_percentage"] = 0
        led["app_build_tombstones"] = [{"version": "0.4.2", "sparkle_build": 42}]
        led["rollout_history"]["app_bundle"]["0.4.2"]["kill_switched"] = True
        self.assertEqual(run(led, records("0.4.2"))["appcast"]["items"], [])
        led["entries"]["app_bundle"]["rollout_percentage"] = 25
        del led["app_build_tombstones"]
        self.assertEqual(run(led, records("0.4.2"))["appcast"]["items"][0]["rollout_percentage"], 25)
        ap = copy.deepcopy(self.plan["appcast"])
        ap["items"][0]["rollout_percentage"] = 50
        has(self, cl.check_appcast_covered(ap, self.manifest), "do not match")

    def test_malformed_served_appcast_version_is_an_error(self):
        has(self, problems_of(ledger(), records("0.4.2"), served_appcast_version="v0.4.1"), "served appcast version")

    def test_no_app_bundle_entry_means_no_appcast_items(self):
        plan = run(ledger({"script": "0.4.2"}), records("0.4.2"))
        self.assertEqual(plan["appcast"]["items"], [])


class AppBuildTombstones(unittest.TestCase):
    TOMB = {"version": "0.4.2", "sparkle_build": 42}

    def test_a_kill_switched_app_bundle_must_be_tombstoned(self):
        led = ledger()
        led["entries"]["app_bundle"]["kill_switch"] = True
        has(self, problems_of(led, records("0.4.2")), "app_build_tombstones must list")
        led["app_build_tombstones"] = [self.TOMB]
        self.assertEqual(problems_of(led, records("0.4.2")), [])

    def test_a_yanked_app_bundle_that_was_served_must_be_tombstoned(self):
        prev = ledger({"app_bundle": "0.4.2"})
        prev["history"]["app_bundle"] = ["0.4.1", "0.4.2"]
        prev["rollout_history"]["app_bundle"]["0.4.1"] = dict(FULL)
        led = ledger({"app_bundle": "0.4.1"}, reason="yank 0.4.2", withdrawn_versions=["0.4.2"])
        led["history"]["app_bundle"] = ["0.4.1", "0.4.2"]
        recs = records("0.4.1", "0.4.2")
        recs["0.4.1"]["app_bundle"]["macos-aarch64"]["sparkle_build"] = "41"
        has(self, problems_of(led, recs, previous_ledger=prev), "app_build_tombstones must list")
        led["app_build_tombstones"] = [self.TOMB]
        self.assertEqual(problems_of(led, recs, previous_ledger=prev), [])

    def test_a_tombstoned_build_cannot_be_reused_by_another_version(self):
        led = ledger({"app_bundle": "0.4.3"})
        led["history"]["app_bundle"] = ["0.4.2", "0.4.3"]
        led["app_build_tombstones"] = [self.TOMB]
        recs = records("0.4.2", "0.4.3")
        recs["0.4.3"]["app_bundle"]["macos-aarch64"]["sparkle_build"] = "42"
        has(self, problems_of(led, recs), "reuses sparkle_build 42")

    def test_a_build_that_does_not_rise_with_the_version_is_refused(self):
        led = ledger({"app_bundle": "0.4.3"})
        led["history"]["app_bundle"] = ["0.4.2", "0.4.3"]
        recs = records("0.4.2", "0.4.3")
        self.assertEqual(problems_of(led, recs), [])
        recs["0.4.3"]["app_bundle"]["macos-aarch64"]["sparkle_build"] = "42"
        has(self, problems_of(led, recs), "sparkle_build must increase with version")
        recs["0.4.3"]["app_bundle"]["macos-aarch64"]["sparkle_build"] = "41"
        has(self, problems_of(led, recs), "0.4.3 has 41 but 0.4.2 has 42")

    def test_a_tombstoned_version_cannot_change_its_build(self):
        led = ledger()
        led["app_build_tombstones"] = [{"version": "0.4.2", "sparkle_build": 41}]
        has(self, problems_of(led, records("0.4.2")), "tombstoned as 41")

    def test_shape(self):
        for bad in ([{"version": "0.4.2"}], [{"version": "x", "sparkle_build": 1}],
                    [{"version": "0.4.2", "sparkle_build": 0}], [{"version": "0.4.2", "sparkle_build": True}],
                    "no", [self.TOMB, {"version": "0.4.3", "sparkle_build": 42}]):
            led = ledger()
            led["app_build_tombstones"] = bad
            self.assertTrue(problems_of(led, records("0.4.2")), bad)

    def test_append_only(self):
        prev = ledger()
        prev["app_build_tombstones"] = [self.TOMB]
        has(self, problems_of(ledger(), records("0.4.2"), previous_ledger=prev), "app_build_tombstones may only grow")
        cur = ledger()
        cur["app_build_tombstones"] = [self.TOMB, {"version": "0.4.1", "sparkle_build": 41}]
        self.assertFalse([m for m in problems_of(cur, records("0.4.2"), previous_ledger=prev)
                          if "may only grow" in m])


class RecordImmutability(unittest.TestCase):
    def test_cli_ignores_the_placeholder_file(self):
        import subprocess
        root = Path(tempfile.mkdtemp())
        rel = root / ".github" / "channels" / "releases"
        rel.mkdir(parents=True)
        (rel / ".gitkeep").write_text("", encoding="utf-8")
        (rel / "0.4.1.json").write_text("{}", encoding="utf-8")
        for cmd in (["init", "-q"], ["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"]):
            subprocess.run(["git", "-C", str(root), *cmd], check=True)
        args = ["check-records-immutable", "--base-ref", "HEAD", "--repo-root", str(root)]
        self.assertEqual(gum.main(args), 0)
        (rel / "0.4.1.json").write_text("{ }", encoding="utf-8")
        self.assertEqual(gum.main(args), 5)

    def test_edit_and_delete_are_refused_addition_is_fine(self):
        base = {"0.4.1.json": b"a"}
        has(self, cl.check_records_immutable(base, {"0.4.1.json": b"b"}), "edited")
        has(self, cl.check_records_immutable(base, {}), "deleted")
        self.assertEqual(cl.check_records_immutable(base, {"0.4.1.json": b"a", "0.4.2.json": b"c"}), [])


class AdditiveStore(unittest.TestCase):
    """A merged record may gain exactly one new microsoft_store target (Windows) and nothing else."""

    @staticmethod
    def enc(rec):
        return (json.dumps(rec, indent=2, sort_keys=True) + "\n").encode("utf-8")

    def setUp(self):
        self.rec = record("0.4.1", sources=("script",))
        self.base = {"0.4.1.json": self.enc(self.rec)}
        self.store = record("0.4.1")["microsoft_store"]["windows-x86_64"]

    def head(self, mutate):
        r = copy.deepcopy(self.rec)
        mutate(r)
        return {"0.4.1.json": self.enc(r)}

    def refused(self, mutate, needle="immutable"):
        has(self, cl.check_records_immutable(self.base, self.head(mutate)), needle)

    def test_one_new_store_target_is_accepted(self):
        out = cl.check_records_immutable(self.base, self.head(lambda r: r.update(microsoft_store={"windows-x86_64": self.store})))
        self.assertEqual(out, [])

    def test_store_next_to_an_existing_dmg_is_accepted(self):
        rec = record("0.4.1", sources=("script", "app_bundle"))
        base = {"0.4.1.json": self.enc(rec)}
        rec["microsoft_store"] = {"windows-x86_64": self.store}
        self.assertEqual(cl.check_records_immutable(base, {"0.4.1.json": self.enc(rec)}), [])

    def test_dmg_and_store_in_one_edit_are_refused(self):
        dmg = record("0.4.1")["app_bundle"]
        self.refused(lambda r: r.update(microsoft_store={"windows-x86_64": self.store}, app_bundle=dmg))

    def test_two_store_targets_are_refused(self):
        self.refused(lambda r: r.update(microsoft_store={"windows-x86_64": self.store, "windows-aarch64": dict(self.store)}))

    def test_non_windows_store_target_is_refused(self):
        self.refused(lambda r: r.update(microsoft_store={"linux-x86_64": self.store}))

    def test_macos_target_in_the_store_section_is_refused(self):
        self.refused(lambda r: r.update(microsoft_store={"macos-aarch64": self.store}))

    def test_windows_target_in_the_dmg_section_is_refused(self):
        self.refused(lambda r: r.update(app_bundle={"windows-x86_64": record("0.4.1")["app_bundle"]["macos-aarch64"]}))

    def test_existing_store_target_replaced_or_removed_is_refused(self):
        rec = record("0.4.1")
        base = {"0.4.1.json": self.enc(rec)}
        changed = copy.deepcopy(rec)
        changed["microsoft_store"]["windows-x86_64"]["submission_id"] = "other"
        has(self, cl.check_records_immutable(base, {"0.4.1.json": self.enc(changed)}), "immutable")
        both = copy.deepcopy(changed)   # an existing target changed while one is added: still refused
        both["microsoft_store"]["windows-aarch64"] = dict(self.store)
        has(self, cl.check_records_immutable(base, {"0.4.1.json": self.enc(both)}), "immutable")
        gone = copy.deepcopy(rec)
        gone["microsoft_store"] = {"windows-aarch64": dict(self.store)}
        has(self, cl.check_records_immutable(base, {"0.4.1.json": self.enc(gone)}), "immutable")

    def test_other_field_edited_alongside_is_refused(self):
        def m(r):
            r["microsoft_store"] = {"windows-x86_64": self.store}
            r["tag"] = "v9.9.9"
        self.refused(m)

    def test_script_edited_alongside_is_refused(self):
        def m(r):
            r["microsoft_store"] = {"windows-x86_64": self.store}
            r["script"]["linux-x86_64"]["sha256"] = "9" * 64
        self.refused(m)

    def test_malformed_store_entry_is_refused(self):
        for bad in ({**self.store, "upload_sha256": "zz"}, {**self.store, "x": "y"}, {k: v for k, v in self.store.items() if k != "submission_id"}):
            self.refused(lambda r, bad=bad: r.update(microsoft_store={"windows-x86_64": bad}))

    def test_empty_store_section_is_refused(self):
        self.refused(lambda r: r.update(microsoft_store={}))

    def test_non_canonical_bytes_are_refused(self):
        r = copy.deepcopy(self.rec)
        r["microsoft_store"] = {"windows-x86_64": self.store}
        has(self, cl.check_records_immutable(self.base, {"0.4.1.json": json.dumps(r).encode()}), "immutable")

    def test_null_sections_count_as_absent(self):
        dmg = record("0.4.1")["app_bundle"]
        self.assertEqual(cl.check_records_immutable(self.base, self.head(
            lambda r: r.update(app_bundle=None, microsoft_store={"windows-x86_64": self.store}))), [])
        self.assertEqual(cl.check_records_immutable(self.base, self.head(
            lambda r: r.update(microsoft_store=None, app_bundle=dmg))), [])
        self.refused(lambda r: r.update(app_bundle=None, microsoft_store=None))

    def test_record_version_must_match_its_file_name(self):
        r = copy.deepcopy(self.rec)
        r["version"] = "0.4.2"
        base = {"0.4.2.json": self.enc(r)}
        r["microsoft_store"] = {"windows-x86_64": self.store}
        has(self, cl.check_records_immutable({"0.4.1.json": base["0.4.2.json"]}, {"0.4.1.json": self.enc(r)}), "immutable")

    def test_ledger_serving_the_added_store_entry_assembles(self):
        rec = copy.deepcopy(self.rec)
        rec["microsoft_store"] = {"windows-x86_64": self.store}
        led = ledger({"script": "0.4.1", "microsoft_store": "0.4.1"})
        body = json.loads(run(led, {"0.4.1": rec})["manifest_body"])
        self.assertIn(("microsoft_store", "windows"), {(r["install_source"], r["platform"]) for r in body["releases"]})


class AdditiveDmg(unittest.TestCase):
    """A merged record may gain exactly one new app_bundle target and nothing else."""

    @staticmethod
    def enc(rec):
        return (json.dumps(rec, indent=2, sort_keys=True) + "\n").encode("utf-8")

    def setUp(self):
        self.rec = record("0.4.1", sources=("script",))
        self.base = {"0.4.1.json": self.enc(self.rec)}
        self.dmg = record("0.4.1")["app_bundle"]["macos-aarch64"]

    def head(self, mutate):
        r = copy.deepcopy(self.rec)
        mutate(r)
        return {"0.4.1.json": self.enc(r)}

    def refused(self, mutate):
        has(self, cl.check_records_immutable(self.base, self.head(mutate)), "immutable")

    def test_one_new_target_is_accepted(self):
        out = cl.check_records_immutable(self.base, self.head(lambda r: r.update(app_bundle={"macos-aarch64": self.dmg})))
        self.assertEqual(out, [])

    def test_second_target_next_to_an_existing_one_is_accepted(self):
        rec = record("0.4.1")
        base = {"0.4.1.json": self.enc(rec)}
        rec["app_bundle"]["macos-x86_64"] = dict(self.dmg)
        self.assertEqual(cl.check_records_immutable(base, {"0.4.1.json": self.enc(rec)}), [])

    def test_other_field_edited_alongside_is_refused(self):
        def m(r):
            r["app_bundle"] = {"macos-aarch64": self.dmg}
            r["tag"] = "v9.9.9"
        self.refused(m)

    def test_script_edited_alongside_is_refused(self):
        def m(r):
            r["app_bundle"] = {"macos-aarch64": self.dmg}
            r["script"]["linux-x86_64"]["sha256"] = "9" * 64
        self.refused(m)

    def test_field_removed_is_refused(self):
        self.refused(lambda r: r.pop("tag"))

    def test_edit_without_app_bundle_is_refused(self):
        self.refused(lambda r: r.update(state_schema="2"))

    def test_existing_target_replaced_is_refused(self):
        rec = record("0.4.1")
        base = {"0.4.1.json": self.enc(rec)}
        rec["app_bundle"]["macos-aarch64"]["sha256"] = "9" * 64
        has(self, cl.check_records_immutable(base, {"0.4.1.json": self.enc(rec)}), "immutable")

    def test_existing_target_removed_is_refused(self):
        rec = record("0.4.1")
        base = {"0.4.1.json": self.enc(rec)}
        del rec["app_bundle"]["macos-aarch64"]
        rec["app_bundle"]["macos-x86_64"] = dict(self.dmg)
        has(self, cl.check_records_immutable(base, {"0.4.1.json": self.enc(rec)}), "immutable")

    def test_two_new_targets_are_refused(self):
        self.refused(lambda r: r.update(app_bundle={"macos-aarch64": self.dmg, "macos-x86_64": dict(self.dmg)}))

    def test_non_macos_target_is_refused(self):
        self.refused(lambda r: r.update(app_bundle={"linux-x86_64": self.dmg}))

    def test_foreign_engine_release_id_is_refused(self):
        self.refused(lambda r: r.update(app_bundle={"macos-aarch64": {**self.dmg, "engine_release_id": "other"}}))

    def test_extra_entry_field_is_refused(self):
        self.refused(lambda r: r.update(app_bundle={"macos-aarch64": {**self.dmg, "x": "y"}}))

    def test_malformed_entry_is_refused(self):
        self.refused(lambda r: r.update(app_bundle={"macos-aarch64": {**self.dmg, "sha256": "zz"}}))

    def test_non_canonical_bytes_are_refused(self):
        r = copy.deepcopy(self.rec)
        r["app_bundle"] = {"macos-aarch64": self.dmg}
        has(self, cl.check_records_immutable(self.base, {"0.4.1.json": json.dumps(r).encode()}), "immutable")

    def test_duplicate_keys_and_garbage_are_refused(self):
        dup = self.enc(self.rec).replace(b'  "tag"', b'  "tag": "v0.4.1",\n  "tag"', 1)
        self.assertEqual(json.loads(dup), self.rec)
        has(self, cl.check_records_immutable(self.base, {"0.4.1.json": dup}), "immutable")
        has(self, cl.check_records_immutable(self.base, {"0.4.1.json": b"\xff"}), "immutable")

    def test_scalar_type_change_in_other_field_is_refused(self):
        for v in (True, 1.0):
            self.refused(lambda r, v=v: r.update(schema_version=v, app_bundle={"macos-aarch64": self.dmg}))

    def test_non_canonical_merged_base_is_refused(self):
        base = {"0.4.1.json": json.dumps(self.rec, indent=4, sort_keys=True).encode() + b"\n"}
        r = copy.deepcopy(self.rec)
        r["app_bundle"] = {"macos-aarch64": self.dmg}
        has(self, cl.check_records_immutable(base, {"0.4.1.json": self.enc(r)}), "immutable")

    def test_empty_app_bundle_in_base_is_refused(self):
        r = copy.deepcopy(self.rec)
        r["app_bundle"] = {}
        base = {"0.4.1.json": self.enc(r)}
        r["app_bundle"] = {"macos-aarch64": self.dmg}
        has(self, cl.check_records_immutable(base, {"0.4.1.json": self.enc(r)}), "immutable")

    def test_unusable_sparkle_build_is_refused(self):
        for b in ("abc", "0", "01", str(2**64)):
            self.refused(lambda r, b=b: r.update(app_bundle={"macos-aarch64": {**self.dmg, "sparkle_build": b}}))

    def test_file_name_not_ending_in_dmg_is_refused(self):
        for f in ("manifest.json", "x.dmg.sha256", "yadorilink-0.4.1-linux-x86_64.zip"):
            self.refused(lambda r, f=f: r.update(app_bundle={"macos-aarch64": {**self.dmg, "file": f}}))

    def test_second_arch_reusing_a_file_name_with_other_bytes_is_refused(self):
        rec = record("0.4.1")
        base = {"0.4.1.json": self.enc(rec)}
        rec["app_bundle"]["macos-x86_64"] = {**self.dmg, "sha256": "9" * 64}
        has(self, cl.check_records_immutable(base, {"0.4.1.json": self.enc(rec)}), "immutable")

    def test_deleting_the_record_is_still_refused(self):
        has(self, cl.check_records_immutable(self.base, {}), "deleted")

    def test_ledger_serving_the_added_dmg_assembles(self):
        recs = {"0.4.1": self.rec}
        led = ledger({"script": "0.4.1"})
        self.assertEqual(run(led, recs)["appcast"]["items"], [])
        self.rec["app_bundle"] = {"macos-aarch64": self.dmg}
        led2 = ledger({"script": "0.4.1", "app_bundle": "0.4.1"})
        led2["history"]["script"] = ["0.4.1"]
        out = run(led2, recs, previous_ledger=led)
        self.assertEqual(len(out["appcast"]["items"]), 1)


class Cli(unittest.TestCase):
    def tree(self, led, recs):
        root = Path(tempfile.mkdtemp())
        (root / "releases").mkdir()
        (root / "beta.json").write_text(json.dumps(led), encoding="utf-8")
        for v, r in recs.items():
            (root / "releases" / f"{v}.json").write_text(json.dumps(r), encoding="utf-8")
        (root / "chain.json").write_text(CHAIN, encoding="utf-8")
        cut = gum._cutover_guard()
        values = {"PROTOCOL_VERSION": 4, "RPC_VERSION": 2, "CONTROL_PROTOCOL_VERSION": 1, "SCHEMA_VERSION": 1}
        for name, rel in cut.GATES.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(f"pub const {name}: u32 = {values[name]};\n", encoding="utf-8")
        (root / "docs").mkdir(exist_ok=True)
        (root / "docs/CUTOVER.md").write_text(
            "- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.3.0\n", encoding="utf-8")
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
                                     "artifact_sha256": "0" * 64, "artifact_size": 1}]), encoding="utf-8")
        out = root / "m.json"
        self.assertEqual(gum.main(["generate", "--channel", "beta", "--version", "0.3.0", "--min-version",
                                   "0.3.0", "--artifacts", str(arts), "--out", str(out),
                                   "--repo-root", str(root), "--generated-at", AT]), 0)
        self.assertEqual(out.read_text(encoding="utf-8"), cl.render_body(json.loads(out.read_text(encoding="utf-8"))))


class SchemasMatchValidator(unittest.TestCase):
    """The JSON schemas are documentation; keep their field sets equal to the validator's."""

    def schema(self, name):
        return json.loads((HERE / "channel-schema" / name).read_text(encoding="utf-8"))

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


class SchemaVersionIsAnInteger(unittest.TestCase):
    """`True == 1` and `1.0 == 1` in Python, so an equality check alone accepts them."""

    def test_record_and_ledger_refuse_true_and_float_versions(self):
        for bad in (True, 1.0):
            rec = record("0.4.2")
            rec["schema_version"] = bad
            has(self, cl.validate_record(rec, "0.4.2"), "schema_version")
            led = ledger()
            led["schema_version"] = bad
            has(self, cl.validate_ledger(led, {}, floor="0.3.0"), "schema_version")

    def test_manifest_validator_refuses_true_and_float_versions(self):
        for bad in (True, 2.0):
            has(self, gum.validate_manifest({"schema_version": bad}, False), "schema_version")


class StrictIdentifiers(unittest.TestCase):
    """Identifiers become file names, URLs and upload keys, so `$` (which accepts a trailing
    newline) must never be the end anchor of a validator."""

    GOOD = {"SHA256_RE": "a" * 64, "COMMIT_RE": "b" * 40, "TARGET_RE": "macos-aarch64", "FILE_RE": "a.dmg",
            "SEMVER_RE": "1.2.3-rc.1", "STATE_SCHEMA_RE": "12", "GENERATED_AT_RE": AT}

    def test_compiled_validators_reject_a_trailing_newline_and_non_ascii_digits(self):
        for name, good in self.GOOD.items():
            rx = getattr(cl, name)
            self.assertTrue(rx.fullmatch(good), name)
            self.assertIsNone(rx.fullmatch(good + "\n"), name)
        self.assertIsNone(cl.GENERATED_AT_RE.fullmatch("\u0662\u0660\u0662\u0666" + AT[4:]))
        self.assertIsNone(cl.SEMVER_RE.fullmatch("\u0661.2.3"))

    def test_a_record_filename_or_hash_with_a_trailing_newline_is_refused(self):
        rec = record("0.4.2")
        rec["app_bundle"]["macos-aarch64"]["file"] += "\n"
        has(self, cl.validate_record(rec, "0.4.2"), "file")
        rec = record("0.4.2")
        rec["script"]["linux-x86_64"]["asset"] += "\n"
        has(self, cl.validate_record(rec, "0.4.2"), "asset")
        rec = record("0.4.2")
        rec["script"]["linux-x86_64"]["attestation_digest"] += "\n"
        has(self, cl.validate_record(rec, "0.4.2"), "attestation_digest")
        rec = record("0.4.2")
        rec["public_commit_sha"] += "\n"
        has(self, cl.validate_record(rec, "0.4.2"), "public_commit_sha")

    def test_the_manifest_validator_refuses_a_trailing_newline(self):
        self.assertEqual(gum.parse_semver("1.2.3"), gum.parse_semver("v1.2.3"))
        with self.assertRaises(ValueError):
            gum.parse_semver("1.2.3\n")
        with self.assertRaises(ValueError):
            gum.parse_semver("\u0661.2.3")

    # Genuine non-identifier uses of an anchored inline re.match/re.search (single-line workflow
    # text parsers where a trailing newline cannot occur), keyed by (file, pattern) with the reason.
    INLINE_ALLOWED = {
        ("check-signing-workflow.py", r"^(\s*)(?:- )?run:"): "one workflow line, no newline in it",
        ("check-signing-workflow.py", r"^\s+(?:[A-Z][A-Z0-9_]*|group"): "one workflow line, prefix test",
    }

    # Anchored compiled patterns that are deliberately a prefix match / suffix search, with the reason.
    PATTERN_ALLOWED = {
        ("channel_ledger.py", "YANK_RE"): "prefix match of a free-text reason (`yank <version>` then anything)",
        ("generate-update-manifest.py", "GENERATION_LINE"): "prefix match of one CUTOVER.md line (not an identifier)",
        ("verifier_mirror.py", "TAG_RE"): "search for the tag suffix of a URL, anchored with \\Z",
    }

    def test_identifier_patterns_are_only_used_with_fullmatch(self):
        """Sweep (AST): no `.match`/`.search` on a compiled validator (same-module name or another
        module's attribute such as `cl.TARGET_RE.match`), and no anchored inline `re.match` /
        `re.search` without re.M. Patterns are written `\\A...\\Z` and used with fullmatch."""
        import ast
        root = HERE.parent.parent
        dirs = [root / ".github/release", root / ".github/staging-signer", root / "scripts" / "release-publish",
                root / "packaging/install"]
        files = [p for d in dirs if d.is_dir() for p in sorted(d.glob("*.py")) if not p.name.startswith("test_")]
        files += [p for p in (root / "scripts" / "dev-engine.py", root / "scripts" / "check-dev-engine-pin.py") if p.exists()]
        trees = {p: ast.parse(p.read_text(encoding="utf-8")) for p in files}
        def literal(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.JoinedStr):
                return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
            return None

        compiled = set()
        for tree in trees.values():
            for node in ast.walk(tree):
                if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                        and ast.unparse(node.value.func) == "re.compile" and node.value.args):
                    pat = literal(node.value.args[0])
                    if pat is not None and pat.startswith(("^", "\\A")) or pat is not None and pat.endswith(("$", "\\Z")):
                        compiled |= {t.id for t in node.targets if isinstance(t, ast.Name)}

        offenders = []
        for path, tree in trees.items():
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("match", "search")):
                    continue
                recv = node.func.value
                where = f"{path.name}:{node.lineno}"
                if isinstance(recv, ast.Name) and recv.id == "re":
                    pat = literal(node.args[0]) if node.args else None
                    multiline = any("M" in ast.unparse(a) for a in node.args[2:]) or node.keywords
                    anchored = pat is not None and (pat.startswith(("^", "\\A")) or pat.endswith(("$", "\\Z")))
                    if anchored and not multiline:
                        if not any(path.name == f and pat.startswith(p) for f, p in self.INLINE_ALLOWED):
                            offenders.append(where)
                else:
                    name = recv.id if isinstance(recv, ast.Name) else getattr(recv, "attr", None)
                    if name in compiled and (path.name, name) not in self.PATTERN_ALLOWED:
                        offenders.append(where)
        self.maxDiff = None
        self.assertEqual(offenders, [])


class Channels(unittest.TestCase):
    """One channel definition (channels.json); stable promotes identical beta bytes."""

    def test_channel_list_and_lanes(self):
        self.assertEqual(cl.CHANNELS, ("nightly", "beta", "stable"))
        self.assertEqual(cl.CHANNEL_LANE, {"nightly": "dev", "beta": "beta", "stable": "beta"})

    def test_no_tool_keeps_its_own_channel_list(self):
        root = HERE.parent.parent
        offenders = []
        for path in [*(root / ".github").rglob("*.py"), *(root / "scripts").rglob("*.py")]:
            if re.search(r'\(\s*"nightly"\s*,\s*"beta"', path.read_text(encoding="utf-8")) \
                    and path.name != Path(__file__).name:
                offenders.append(str(path.relative_to(root)))
        self.assertEqual(offenders, [], "read the list from release_channels instead")

    def test_every_tool_uses_the_shared_list(self):
        import importlib.util
        import release_channels as rc
        import sign_request as sr
        spec = importlib.util.spec_from_file_location("gum_channels", HERE / "generate-update-manifest.py")
        gum_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gum_mod)
        mods = [cl, sr, gum_mod]
        # .github/staging-signer is private-only: the projected public tree does not carry it.
        staging_path = HERE.parent / "staging-signer" / "sign_request.py"
        if staging_path.is_file():
            spec = importlib.util.spec_from_file_location("staging_sr", staging_path)
            staging = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(staging)
            mods.append(staging)
        for mod in mods:
            self.assertEqual(tuple(mod.CHANNELS), rc.CHANNELS, mod.__name__)

    def assemble_cli(self, tree, channel, *extra):
        from unittest import mock
        chain = Path(tree) / "chain.json"
        chain.write_text(CHAIN, encoding="utf-8")
        with mock.patch.object(gum, "generation_floor", lambda root: FLOOR), \
                mock.patch("sys.stderr"), mock.patch("sys.stdout"):
            return gum.main(["assemble", "--ledger", str(Path(tree) / f"{channel}.json"),
                             "--records-dir", str(Path(tree) / "releases"), "--trust-chain", str(chain),
                             "--generated-at", AT, "--out-body", str(Path(tree) / "out.json"), *extra])

    def ledger_tree(self, with_beta=True):
        tree = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tree, ignore_errors=True)
        (tree / "releases").mkdir()
        (tree / "releases" / "0.4.2.json").write_text(json.dumps(record("0.4.2", sources=("script",))), encoding="utf-8")
        (tree / "stable.json").write_text(json.dumps(self.stable()), encoding="utf-8")
        if with_beta:
            (tree / "beta.json").write_text(json.dumps(self.beta("0.4.2")), encoding="utf-8")
        return tree

    def test_assemble_cli_needs_the_served_promotion_source_for_stable(self):
        """The repository beta file carries no stamps and cannot show a soak: the CLI no longer
        picks it up; the stamped snapshot beta serves is passed explicitly (the publisher reads it
        from storage)."""
        tree = self.ledger_tree()
        self.assertEqual(self.assemble_cli(tree, "stable"), 5)
        self.assertEqual(self.assemble_cli(tree, "stable", "--promotion-source-ledger", str(tree / "beta.json")), 0)

    def test_workflows_and_cli_list_the_shared_channels(self):
        """Every channel list in a workflow or the CLI is the shared one, or the shared one without
        `stable` in a place that keeps stable off until the owner enables it."""
        import release_channels as rc
        root = HERE.parent.parent
        everything = set(rc.CHANNELS)
        stable_off = everything - {"stable"}
        # Where stable is intentionally not enabled yet (publish, signing, self-update).
        owner_switch = {
            ".github/workflows/channel-plan.yml", ".github/workflows/channel-publish.yml",
            ".github/workflows/sign-staging.yml", "oss-public/.github/workflows/sign-manifest.yml",
            # The same signer after projection: .github/ is replaced by the oss-public overlay.
            ".github/workflows/sign-manifest.yml",
            "crates/yadorilink-cli/src/commands/update.rs",
        }
        patterns = [r"options:\s*\[([^\]]*)\]", r"channel:\s*\[([^\]]*)\]",
                    r'case "\$INPUT_CHANNEL" in ([a-z|]+)\)', r'matches!\(channel, ((?:"[a-z]+"\s*\|?\s*)+)\)']
        found = {}
        # Some source layouts carry extra workflow directories that others lack, so a file or
        # directory that exists only in some layouts is checked when present and never required.
        files = [*(root / ".github/workflows").glob("*.yml"),
                 *(root / "oss-public/.github/workflows").glob("*.yml"),
                 root / "crates/yadorilink-cli/src/commands/update.rs"]
        private_only = {".github/workflows/channel-monitor.yml"}
        for path in files:
            text = path.read_text(encoding="utf-8")
            for pat in patterns:
                for m in re.finditer(pat, text):
                    names = set(re.findall(r"[a-z]+", m.group(1)))
                    if names & {"nightly", "stable"}:  # build-lane lists (beta, dev) are not channel lists
                        found.setdefault(str(path.relative_to(root)), []).append(names)
        self.assertIn("crates/yadorilink-cli/src/commands/update.rs", found)
        for rel in private_only:
            if (root / rel).exists():
                self.assertIn(rel, found)
        for rel, sets in found.items():
            for names in sets:
                want = stable_off if rel in owner_switch else everything
                self.assertEqual(names, want, f"{rel} lists {sorted(names)}, expected {sorted(want)}")

    def stable(self, version="0.4.2"):
        led = ledger(channel="stable", versions={"script": version})
        return led

    def beta(self, *versions, withdrawn=(), published="2026-10-01T00:00:00Z"):
        led = ledger(channel="beta", versions={"script": versions[-1]})
        led["history"] = {"script": list(versions)}
        led["published_at"] = {"script": {v: published for v in versions}}
        led["full_rollout_at"] = {"script": {v: published for v in versions}}
        led["rollout_history"] = {"script": {v: {"max_rollout_percentage": 100, "kill_switched": False}
                                             for v in versions}}
        if withdrawn:
            led["withdrawn_versions"] = list(withdrawn)
        return led

    def test_stable_serves_a_beta_build_promoted_from_beta(self):
        out = run(self.stable(), records("0.4.2", sources=("script",)), promotion_source=self.beta("0.4.2"))
        self.assertTrue(json.loads(out["manifest_body"])["releases"])

    def test_stable_refuses_a_dev_build(self):
        recs = {"0.4.2": record("0.4.2", lane="dev", sources=("script",))}
        has(self, problems_of(self.stable(), recs, promotion_source=self.beta("0.4.2")), "lane 'dev'")

    def test_stable_needs_the_beta_ledger(self):
        has(self, problems_of(self.stable(), records("0.4.2", sources=("script",))), "ledger is required")

    def test_stable_refuses_a_version_never_live_on_beta(self):
        has(self, problems_of(self.stable("0.4.2"), records("0.4.1", "0.4.2", sources=("script",)),
                              promotion_source=self.beta("0.4.1")), "not in the beta history")

    def test_stable_refuses_a_version_withdrawn_on_beta(self):
        has(self, problems_of(self.stable("0.4.2"), records("0.4.2", "0.4.3", sources=("script",)),
                              promotion_source=self.beta("0.4.2", "0.4.3", withdrawn=["0.4.2"])),
            "withdrawn on beta")

    def test_stable_refuses_a_prerelease_version(self):
        has(self, problems_of(self.stable("0.4.2-beta.1"), records("0.4.2-beta.1", sources=("script",)),
                              promotion_source=self.beta("0.4.2-beta.1")), "pre-release")

    def test_stable_refuses_a_version_beta_never_fully_rolled_out_or_ever_switched_off(self):
        recs = records("0.4.2", "0.4.3", sources=("script",))
        for current, record in (("0.4.2", {"max_rollout_percentage": 50, "kill_switched": False}),
                                ("0.4.2", {"max_rollout_percentage": 0, "kill_switched": False}),
                                ("0.4.2", {"max_rollout_percentage": 100, "kill_switched": True}),
                                # beta has moved on: 0.4.2 is no longer the current entry
                                ("0.4.3", {"max_rollout_percentage": 0, "kill_switched": False}),
                                ("0.4.3", {"max_rollout_percentage": 100, "kill_switched": True})):
            src = self.beta("0.4.2", "0.4.3") if current == "0.4.3" else self.beta("0.4.2")
            src["rollout_history"]["script"]["0.4.2"] = record
            if record["max_rollout_percentage"] != 100:
                del src["full_rollout_at"]["script"]["0.4.2"]
            if current == "0.4.2":
                src["entries"]["script"].update(rollout_percentage=record["max_rollout_percentage"],
                                                kill_switch=record["kill_switched"])
            has(self, problems_of(self.stable(), recs, promotion_source=src), "not cleanly fully offered on beta")

    def test_stable_refuses_a_version_with_no_recorded_rollout(self):
        src = self.beta("0.4.2")
        del src["rollout_history"], src["full_rollout_at"]
        has(self, problems_of(self.stable(), records("0.4.2", sources=("script",)), promotion_source=src),
            "no recorded rollout_history")

    def test_rollout_history_is_validated_and_append_only(self):
        led = ledger({"script": "0.4.2"})

        def shape_problems(l):
            return cl.validate_ledger(l, records("0.4.2"), floor=FLOOR)
        good = {"max_rollout_percentage": 100, "kill_switched": False}
        for bad in ({"max_rollout_percentage": 101, "kill_switched": False}, {"max_rollout_percentage": 5},
                    {"max_rollout_percentage": 100, "kill_switched": "no"}):
            led["rollout_history"] = {"script": {"0.4.2": bad}}
            has(self, shape_problems(led), "rollout_history[script][0.4.2] must be exactly")
        led["rollout_history"] = {"script": {"0.9.9": good}}
        has(self, shape_problems(led), "not in history")
        led["rollout_history"] = {"script": {"0.4.2": {"max_rollout_percentage": 50, "kill_switched": False}}}
        has(self, shape_problems(led), "below the current rollout_percentage")
        # transitions, called directly (run() settles hand-built records)
        prev = ledger({"script": "0.4.2"}, rollout_history={"script": {"0.4.2": {
            "max_rollout_percentage": 100, "kill_switched": True}}})
        cur = ledger({"script": "0.4.2"})
        found = cl.validate_transition(prev, cur, records("0.4.2"), floor=FLOOR, generated_at=AT)
        has(self, found, "must keep its record")
        cur["rollout_history"] = {"script": {}}
        has(self, cl.validate_transition(prev, cur, records("0.4.2"), floor=FLOOR, generated_at=AT), "must record the rollout of 0.4.2")

    def test_stable_accepts_a_version_beta_has_moved_past(self):
        src = self.beta("0.4.2", "0.4.3")
        self.assertEqual(problems_of(self.stable("0.4.2"), records("0.4.2", "0.4.3", sources=("script",)),
                                     promotion_source=src), [])

    def test_a_malformed_beta_ledger_fails_closed(self):
        recs = records("0.4.2", sources=("script",))
        for bad in ("0.4.2", ["0.4.2"], {"script": "0.4.2"}, None):
            src = self.beta("0.4.2")
            src["history"] = bad
            if bad is None:
                del src["history"]
            has(self, problems_of(self.stable(), recs, promotion_source=src), "beta ledger")
        src = self.beta("0.4.2")
        src["entries"] = "x"
        has(self, problems_of(self.stable(), recs, promotion_source=src), "beta ledger")

    def test_stable_refuses_a_version_younger_than_the_soak_period(self):
        recs = records("0.4.2", sources=("script",))
        fresh = cl.TIME_FORMAT
        for age, ok in ((cl.SOAK_DAYS * 86400 - 1, False), (cl.SOAK_DAYS * 86400, True)):
            at = (datetime.strptime(AT, fresh) - timedelta(seconds=age)).strftime(fresh)
            probs = problems_of(self.stable(), recs, promotion_source=self.beta("0.4.2", published=at))
            if ok:
                self.assertEqual(probs, [])
            else:
                has(self, probs, "days before")

    def test_stable_refuses_a_version_with_no_recorded_publish_time(self):
        src = self.beta("0.4.2")
        del src["full_rollout_at"]
        has(self, problems_of(self.stable(), records("0.4.2", sources=("script",)), promotion_source=src),
            "no recorded full_rollout_at")

    def test_soak_uses_the_time_recorded_for_the_version_not_the_current_one(self):
        src = self.beta("0.4.2", "0.4.3")
        src["full_rollout_at"]["script"]["0.4.3"] = "2026-10-18T00:00:00Z"
        self.assertEqual(problems_of(self.stable("0.4.2"), records("0.4.2", "0.4.3", sources=("script",)),
                                     promotion_source=src), [])

    def test_a_typed_stamp_is_refused(self):
        """#1383: the stamps come from the publisher's clock; a ledger file may not carry them."""
        recs = records("0.4.2", sources=("script",))
        for name in ("published_at", "full_rollout_at"):
            led = ledger({"script": "0.4.2"})
            led[name] = {"script": {"0.4.2": FRESH}}
            has(self, problems_of(led, recs), f"{name} is stamped by the publisher")

    def test_the_publisher_stamps_new_versions_with_its_own_clock(self):
        recs = records("0.4.2", "0.4.3", sources=("script",))
        prev = cl.stamp_ledger(ledger({"script": "0.4.2"}), None, "2026-10-01T00:00:00Z")
        self.assertEqual(prev["published_at"], {"script": {"0.4.2": "2026-10-01T00:00:00Z"}})
        led = ledger({"script": "0.4.3"})
        led["history"]["script"] = ["0.4.2", "0.4.3"]
        led["rollout_history"]["script"]["0.4.2"] = dict(FULL)
        out = run(led, recs, previous_ledger=prev)
        stamped = json.loads(out["ledger_text"])
        # the recorded time is carried, the new version gets generated_at (AT), nothing is typed
        self.assertEqual(stamped["published_at"], {"script": {"0.4.2": "2026-10-01T00:00:00Z", "0.4.3": AT}})
        self.assertEqual(stamped["full_rollout_at"], {"script": {"0.4.2": "2026-10-01T00:00:00Z", "0.4.3": AT}})
        self.assertEqual(out["ledger_text"], run(led, recs, previous_ledger=prev)["ledger_text"])  # pure
        self.assertNotIn("published_at", led)  # the reviewed ledger is not changed

    def test_a_ramping_version_gets_full_rollout_only_when_it_reaches_100(self):
        recs = records("0.4.2", sources=("script",))
        led = ledger({"script": "0.4.2"})
        led["entries"]["script"]["rollout_percentage"] = 50
        led["rollout_history"]["script"]["0.4.2"]["max_rollout_percentage"] = 50
        first = json.loads(run(led, recs)["ledger_text"])
        self.assertEqual(first["published_at"], {"script": {"0.4.2": AT}})
        self.assertNotIn("full_rollout_at", first)
        led2 = ledger({"script": "0.4.2"})
        later = "2026-10-20T00:00:00Z"
        second = json.loads(cl.assemble(led2, recs, CHAIN, later, floor=FLOOR, previous_ledger=first)["ledger_text"])
        self.assertEqual(second["published_at"], {"script": {"0.4.2": AT}})
        self.assertEqual(second["full_rollout_at"], {"script": {"0.4.2": later}})
        # and a later publish keeps it
        third = json.loads(cl.assemble(led2, recs, CHAIN, "2026-10-21T00:00:00Z", floor=FLOOR,
                                       previous_ledger=second)["ledger_text"])
        self.assertEqual(third["full_rollout_at"], {"script": {"0.4.2": later}})

    def test_recorded_stamps_are_validated_and_append_only(self):
        """The published snapshot is read back by the promotion and the next publish: its stamps
        are still validated, and a recorded time is never changed."""
        recs = records("0.4.2", "0.4.3", sources=("script",))
        snap = cl.stamp_ledger(ledger({"script": "0.4.3"}, ), None, AT)
        snap["history"]["script"] = ["0.4.2", "0.4.3"]
        snap["rollout_history"]["script"]["0.4.2"] = dict(FULL)
        snap["published_at"] = {"script": {"0.4.2": "yesterday"}}
        has(self, cl.validate_ledger(snap, recs, floor=FLOOR), "must be YYYY-MM-DDTHH:MM:SSZ")
        snap["published_at"] = {"script": {"0.9.9": "2026-10-01T00:00:00Z"}}
        has(self, cl.validate_ledger(snap, recs, floor=FLOOR), "not in history")
        snap["published_at"] = {"script": {"0.4.2": "2026-10-18T11:00:00Z", "0.4.3": "2026-10-18T10:00:00Z"}}
        has(self, cl.validate_ledger(snap, recs, floor=FLOOR), "may not go backwards")
        # a later publish never rewrites a recorded time: the stamps are carried from the served ledger
        prev = cl.stamp_ledger(ledger({"script": "0.4.2"}), None, "2026-10-01T00:00:00Z")
        edited = json.loads(json.dumps(prev))
        edited["published_at"]["script"]["0.4.2"] = "2026-10-02T00:00:00Z"
        has(self, cl.validate_transition(prev, edited, recs, floor=FLOOR, generated_at=AT), "keep every recorded time")

    def test_a_stamp_the_publisher_clock_would_not_allow_is_refused(self):
        """The bounds stay: nothing in the archived ledger lies after generated_at, and a
        recorded time is within MAX_STAMP_LAG of it when first recorded."""
        recs = records("0.4.2", sources=("script",))
        led = cl.stamp_ledger(ledger({"script": "0.4.2"}), None, "2026-10-19T01:00:00Z")
        has(self, cl._future_published_problems(led, AT), "is after generated_at")
        prev = ledger({"script": "0.4.2"})
        old = cl.stamp_ledger(ledger({"script": "0.4.3"}), prev, "2026-10-01T00:00:00Z")
        has(self, cl.validate_transition(prev, old, recs, floor=FLOOR, generated_at=AT), "more than 1 day before")

    def test_full_rollout_is_recorded_only_for_a_version_that_reached_100(self):
        recs = records("0.4.2", sources=("script",))
        led = ledger({"script": "0.4.2"})
        led["rollout_history"]["script"]["0.4.2"]["max_rollout_percentage"] = 50
        led["entries"]["script"]["rollout_percentage"] = 50
        led["full_rollout_at"] = {"script": {"0.4.2": FRESH}}
        has(self, problems_of(led, recs), "does not show at 100%")
        led["rollout_history"]["script"]["0.4.2"]["max_rollout_percentage"] = 100
        led["published_at"] = {"script": {"0.4.2": "2026-10-18T13:00:00Z"}}
        has(self, problems_of(led, recs), "before its published_at")

    def test_soak_runs_from_reaching_100_not_from_first_publish(self):
        """Published long ago but only fully rolled out yesterday is not soaked."""
        src = self.beta("0.4.2", published="2026-09-01T00:00:00Z")
        src["full_rollout_at"]["script"]["0.4.2"] = "2026-10-18T00:00:00Z"
        has(self, problems_of(self.stable(), records("0.4.2", sources=("script",)), promotion_source=src),
            "reached 100%")
        src["full_rollout_at"]["script"]["0.4.2"] = "2026-10-12T00:00:00Z"
        self.assertEqual(problems_of(self.stable(), records("0.4.2", sources=("script",)),
                                     promotion_source=src), [])

    def test_a_version_dropped_to_zero_is_withdrawn_and_not_promotable(self):
        """0% after being served is a withdrawal, by the same predicate the build
        tombstones use."""
        recs = records("0.4.2", "0.4.3", sources=("script",))
        self.assertTrue(cl.is_withdrawn_entry({"rollout_percentage": 0, "kill_switch": False}))
        self.assertTrue(cl.is_withdrawn_entry({"rollout_percentage": 100, "kill_switch": True}))
        self.assertFalse(cl.is_withdrawn_entry({"rollout_percentage": 1, "kill_switch": False}))
        led = ledger({"script": "0.4.2"})
        led["entries"]["script"]["rollout_percentage"] = 0
        has(self, problems_of(led, recs), "kill_switched must be true")
        led["rollout_history"]["script"]["0.4.2"]["kill_switched"] = True
        self.assertEqual(problems_of(led, recs), [])
        # a version only ever dark at 0% has not been served and may still ramp
        dark = ledger({"script": "0.4.2"})
        dark["entries"]["script"]["rollout_percentage"] = 0
        dark["rollout_history"]["script"]["0.4.2"]["max_rollout_percentage"] = 0
        self.assertEqual(problems_of(dark, recs), [])
        # the recorded withdrawal is never forgotten, so the version stays unpromotable
        src = self.beta("0.4.2", "0.4.3")
        src["rollout_history"]["script"]["0.4.2"]["kill_switched"] = True
        has(self, problems_of(self.stable("0.4.2"), recs, promotion_source=src), "not cleanly fully offered")
        back = ledger({"script": "0.4.2"})
        prev = ledger({"script": "0.4.2"}, rollout_history={"script": {"0.4.2": {
            "max_rollout_percentage": 100, "kill_switched": True}}})
        has(self, problems_of(back, recs, previous_ledger=prev), "must keep its record")

    def test_beta_and_nightly_ignore_promotion(self):
        self.assertEqual(problems_of(ledger(), records("0.4.2")), [])
        self.assertEqual(problems_of(ledger(channel="nightly"), records("0.4.2", lane="dev")), [])


if __name__ == "__main__":
    unittest.main()


class LandingChannelCheck(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("check_landing_channels", HERE / "check-landing-channels.py")
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def landing(self, names):
        root = Path(tempfile.mkdtemp())
        (root / "src").mkdir()
        listed = ", ".join(f'"{n}"' for n in names)
        (root / "src" / "dl.mjs").write_text(f"const CHANNELS = new Set([{listed}]);\n", encoding="utf-8")
        return str(root)

    def test_equal_lists_pass_and_differing_lists_fail(self):
        self.assertEqual(self.mod.main([self.landing(cl.CHANNELS)]), 0)
        self.assertEqual(self.mod.main([self.landing(cl.CHANNELS[:-1])]), 1)
        self.assertEqual(self.mod.main([self.landing([*cl.CHANNELS, "extra"])]), 1)

    def test_absent_landing_is_skipped_and_unparsable_fails(self):
        self.assertEqual(self.mod.main([]), 0)
        self.assertEqual(self.mod.main(["/nonexistent-landing-path"]), 0)
        root = Path(self.landing(cl.CHANNELS))
        (root / "src" / "dl.mjs").write_text("nothing\n", encoding="utf-8")
        self.assertEqual(self.mod.main([str(root)]), 2)
