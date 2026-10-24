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

    def assemble_cli(self, tree, channel):
        from unittest import mock
        chain = Path(tree) / "chain.json"
        chain.write_text(CHAIN, encoding="utf-8")
        with mock.patch.object(gum, "generation_floor", lambda root: FLOOR), \
                mock.patch("sys.stderr"), mock.patch("sys.stdout"):
            return gum.main(["assemble", "--ledger", str(Path(tree) / f"{channel}.json"),
                             "--records-dir", str(Path(tree) / "releases"), "--trust-chain", str(chain),
                             "--generated-at", AT, "--out-body", str(Path(tree) / "out.json")])

    def ledger_tree(self, with_beta=True):
        tree = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tree, ignore_errors=True)
        (tree / "releases").mkdir()
        (tree / "releases" / "0.4.2.json").write_text(json.dumps(record("0.4.2", sources=("script",))), encoding="utf-8")
        (tree / "stable.json").write_text(json.dumps(self.stable()), encoding="utf-8")
        if with_beta:
            (tree / "beta.json").write_text(json.dumps(self.beta("0.4.2")), encoding="utf-8")
        return tree

    def test_assemble_cli_reads_the_promotion_source_itself(self):
        """The CI dry run passes no --promotion-source-ledger: assemble must find the sibling beta
        ledger for stable (as the publisher does), and still refuse when it is absent."""
        self.assertEqual(self.assemble_cli(self.ledger_tree(), "stable"), 0)
        self.assertEqual(self.assemble_cli(self.ledger_tree(with_beta=False), "stable"), 5)

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

    def beta(self, *versions, withdrawn=()):
        led = ledger(channel="beta", versions={"script": versions[-1]})
        led["history"] = {"script": list(versions)}
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

    def test_stable_refuses_a_version_beta_has_switched_off_or_not_fully_rolled_out(self):
        for field, value in (("kill_switch", True), ("rollout_percentage", 0), ("rollout_percentage", 50)):
            src = self.beta("0.4.2")
            src["entries"]["script"][field] = value
            has(self, problems_of(self.stable(), records("0.4.2", sources=("script",)), promotion_source=src),
                "not fully offered on beta")

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

    def test_beta_and_nightly_ignore_promotion(self):
        self.assertEqual(problems_of(ledger(), records("0.4.2")), [])
        self.assertEqual(problems_of(ledger(channel="nightly"), records("0.4.2", lane="dev")), [])


if __name__ == "__main__":
    unittest.main()
