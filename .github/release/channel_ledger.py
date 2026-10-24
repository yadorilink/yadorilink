"""Channel ledger, immutable release records, and the pure `assemble` function.

A channel's state is a reviewed file (`.github/channels/<channel>.json`, the ledger) plus one
immutable record per released version (`.github/channels/releases/<version>.json`). The unsigned
manifest body and the appcast body data are a pure function of (ledger, records, trust chain,
generated_at): nothing here reads the clock, the network or a key, and the same inputs always
yield the same bytes.

Every rule below fails closed by raising `LedgerError` with all problems found, so a ledger
change is rejected before anything is signed. No signing key is ever read here.

Rules enforced:
  - channel allowlist; ledger file name matches its channel;
  - one entry per (install_source, platform, arch); duplicate JSON keys are refused;
  - artifact URLs are built only under https://yadori.link/dl/ from validated file names;
  - minimum_supported_version >= the protocol-generation floor, <= the version of every
    install_source entry, and <= what is already live (previous ledger; served appcast version);
  - a version only moves forward, except a yank back to a previously live version of the same
    protocol generation, which records the bad version in withdrawn_versions;
  - entries of different versions must belong to the same protocol generation;
  - a record's build lane matches the channel (nightly bytes never enter beta);
  - an app bundle's engine release id equals its record's release id;
  - merged release records are never edited;
  - a promoting channel (`stable`, see channels.json) serves only release versions (no
    pre-release suffix) that are in its source channel's history, not withdrawn there and, if
    the source still serves them, fully rolled out and not kill-switched (promotion_problems);
  - an appcast item exists only for the app_bundle entry the manifest serves (none while it is
    kill-switched or at 0% rollout; partial rollout is carried on the item).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Appended, not prepended: a caller that put another sign_request.py first keeps it.
sys.path.append(str(Path(__file__).resolve().parent))
import release_channels  # noqa: E402

LEDGER_SCHEMA_VERSION = 1
RECORD_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 2
CHANNELS = release_channels.CHANNELS
CHANNEL_LANE = release_channels.CHANNEL_LANE
SOURCES = ("script", "app_bundle", "microsoft_store")
SOURCE_PLATFORM = {"app_bundle": "macos", "microsoft_store": "windows"}
DL_PREFIX = "https://yadori.link/dl/"

SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"\A[0-9a-f]{40}\Z")
TARGET_RE = re.compile(r"\A(linux|macos|windows|ios)-(x86_64|aarch64)\Z")
# `ios` is an engine-bundle platform only (the `script` source): app_bundle and microsoft_store
# are pinned to macos and windows by SOURCE_PLATFORM.
FILE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
GENERATED_AT_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
# How long a signed manifest stays valid, and how many days before expiry the channel monitor
# starts reminding the operator to republish. Clients treat `expires_at` as the end of validity.
VALIDITY_DAYS = 60
REMINDER_DAYS_LEFT = 20
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
# A publish may not stamp a manifest later than the publisher's own clock plus this. Clients keep
# the newest generated_at they ever accepted and never expire it, so a manifest stamped far ahead
# would make every later, correctly stamped one look older to them.
MAX_FUTURE_SKEW = timedelta(minutes=5)


def future_dated_problem(generated_at: str, now: datetime) -> str | None:
    """Why `generated_at` is too far ahead of `now` (an aware or naive UTC time), or None."""
    stamped = datetime.strptime(generated_at, TIME_FORMAT)
    if stamped > now.replace(tzinfo=None) + MAX_FUTURE_SKEW:
        return (f"generated_at {generated_at} is more than {int(MAX_FUTURE_SKEW.total_seconds() // 60)} "
                "minutes ahead of the publisher's clock; clients would keep it as their replay floor")
    return None


def expires_at_for(generated_at: str) -> str:
    """The `expires_at` of a manifest stamped `generated_at`: derived, never typed, so the same
    inputs always produce the same bytes."""
    if not GENERATED_AT_RE.fullmatch(generated_at or ""):
        raise LedgerError([f"generated_at {generated_at!r} must be YYYY-MM-DDTHH:MM:SSZ"])
    start = datetime.strptime(generated_at, TIME_FORMAT)
    return (start + timedelta(days=VALIDITY_DAYS)).strftime(TIME_FORMAT)
_NUM = r"(?:0|[1-9]\d*)"
_PRE_ID = r"(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
# semver.org strict grammar without build metadata (versions are also file and URL names).
SEMVER_RE = re.compile(
    rf"\A({_NUM})\.({_NUM})\.({_NUM})(?:-({_PRE_ID}(?:\.{_PRE_ID})*))?\Z",
    re.ASCII,
)
# The state database version the engine stamps; every manifest entry declares it so a client
# can refuse a release whose engine cannot read the data it has.
STATE_SCHEMA_RE = re.compile(r"\A[1-9][0-9]{0,9}\Z")
YANK_RE = re.compile(r"^yank (\S+)")

LEDGER_FIELDS = {
    "schema_version", "channel", "minimum_supported_version", "entries", "reason",
    "history", "withdrawn_versions",
}
ENTRY_FIELDS = {"version", "rollout_percentage", "kill_switch"}
RECORD_FIELDS = {
    "schema_version", "version", "tag", "public_commit_sha", "build_lane", "release_id",
    "engine_api_version", "state_schema", "protocol_generation", "script", "app_bundle",
    "microsoft_store", "verifier", "installers",
}
TARGET_FIELDS = {
    "script": {"asset", "sha256", "size", "bundle_sha256", "attestation_digest", "github_url"},
    "app_bundle": {"file", "sha256", "size", "sparkle_build", "notarization_evidence_sha256",
                   "engine_release_id"},
    "microsoft_store": {"package_version", "submission_id", "upload_sha256", "upload_size"},
}
OPTIONAL_TARGET_FIELDS = {"publisher_identity"}


class LedgerError(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


# --------------------------------------------------------------------------- loading


def _no_duplicate_keys(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON key {k!r}")
        out[k] = v
    return out


def load_json(text: str, what: str):
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except ValueError as ex:
        raise LedgerError([f"{what}: {ex}"]) from ex


def semver_key(raw: str):
    """Total order on strict semver (no leading v: ledger versions are also file and URL names)."""
    m = SEMVER_RE.fullmatch(raw) if isinstance(raw, str) else None
    if not m:
        raise ValueError(f"not strict semver: {raw!r}")
    core = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    pre = m.group(4)
    if pre is None:
        return core, (1,)
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return core, (0, parts)


def _core(raw: str):
    return semver_key(raw)[0]


# --------------------------------------------------------------------------- records


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_str(v) -> bool:
    return isinstance(v, str) and v != ""


def validate_record(rec, expected_version: str | None = None) -> list[str]:
    p: list[str] = []
    if not isinstance(rec, dict):
        return ["record must be an object"]
    unknown = set(rec) - RECORD_FIELDS
    if unknown:
        p.append(f"record has unknown fields {sorted(unknown)}")
    if rec.get("schema_version") != RECORD_SCHEMA_VERSION:
        p.append(f"record schema_version must be {RECORD_SCHEMA_VERSION}")
    ver = rec.get("version")
    try:
        semver_key(ver)
    except ValueError:
        p.append(f"record version {ver!r} is not strict semver")
    if expected_version is not None and ver != expected_version:
        p.append(f"record version {ver!r} does not match its file name {expected_version!r}")
    for f in ("tag", "release_id", "engine_api_version", "state_schema"):
        if not _is_str(rec.get(f)):
            p.append(f"record.{f} must be a non-empty string")
    if _is_str(rec.get("state_schema")) and not STATE_SCHEMA_RE.fullmatch(rec["state_schema"]):
        p.append("record.state_schema must be the state database version, a positive integer")
    if not (isinstance(rec.get("public_commit_sha"), str) and COMMIT_RE.fullmatch(rec["public_commit_sha"])):
        p.append("record.public_commit_sha must be 40 lowercase hex chars")
    if rec.get("build_lane") not in set(CHANNEL_LANE.values()):
        p.append(f"record.build_lane must be one of {sorted(set(CHANNEL_LANE.values()))}")
    gen = rec.get("protocol_generation")
    if not (isinstance(gen, dict) and set(gen) == {"protocol_version", "rpc_version"}
            and all(_is_int(v) for v in gen.values())):
        p.append("record.protocol_generation must be {protocol_version, rpc_version} integers")
    sections = 0
    for source in SOURCES:
        sec = rec.get(source)
        if sec is None:
            continue
        sections += 1
        if not isinstance(sec, dict) or not sec:
            p.append(f"record.{source} must be a non-empty object of targets")
            continue
        for tname, t in sec.items():
            where = f"record.{source}[{tname}]"
            m = TARGET_RE.fullmatch(tname)
            if not m:
                p.append(f"{where}: target must look like <platform>-<arch>")
            elif source in SOURCE_PLATFORM and m.group(1) != SOURCE_PLATFORM[source]:
                p.append(f"{where}: {source} targets must be {SOURCE_PLATFORM[source]}")
            p.extend(_validate_target(source, where, t))
            if source == "app_bundle" and isinstance(t, dict) \
                    and t.get("engine_release_id") != rec.get("release_id"):
                p.append(f"{where}.engine_release_id must equal the record's release_id")
    if sections == 0:
        p.append("record must carry at least one of script, app_bundle, microsoft_store")
    for aux in ("verifier", "installers"):
        v = rec.get(aux)
        if v is None:
            continue
        items = v if aux == "installers" else {aux: v}
        if not isinstance(items, dict):
            p.append(f"record.{aux} must be an object")
            continue
        for name, a in items.items():
            if not (isinstance(a, dict) and set(a) == {"asset", "sha256"}
                    and isinstance(a["asset"], str) and FILE_RE.fullmatch(a["asset"])
                    and isinstance(a["sha256"], str) and SHA256_RE.fullmatch(a["sha256"])):
                p.append(f"record.{aux}[{name}] must be {{asset, sha256}}")
    return p


def _validate_target(source: str, where: str, t) -> list[str]:
    p: list[str] = []
    if not isinstance(t, dict):
        return [f"{where} must be an object"]
    want = TARGET_FIELDS[source]
    missing = want - set(t)
    unknown = set(t) - want - OPTIONAL_TARGET_FIELDS
    if missing:
        p.append(f"{where} is missing {sorted(missing)}")
    if unknown:
        p.append(f"{where} has unknown fields {sorted(unknown)}")
    for f in want | OPTIONAL_TARGET_FIELDS:
        if f not in t:
            continue
        v = t[f]
        if f.endswith("sha256") or f == "attestation_digest":
            ok = isinstance(v, str) and (SHA256_RE.fullmatch(v) or
                                         (f == "attestation_digest" and re.fullmatch(r"sha256:[0-9a-f]{64}", v)))
        elif f in ("size", "upload_size"):
            ok = _is_int(v) and v > 0
        elif f in ("asset", "file"):
            ok = isinstance(v, str) and FILE_RE.fullmatch(v) and ".." not in v
        elif f == "github_url":
            ok = isinstance(v, str) and v.startswith("https://github.com/")
        elif f == "publisher_identity":
            ok = isinstance(v, str)
        else:
            ok = _is_str(v)
        if not ok:
            p.append(f"{where}.{f} is invalid")
    return p


# --------------------------------------------------------------------------- ledger


def validate_ledger(ledger, records: dict[str, dict], *, floor: str,
                    file_stem: str | None = None) -> list[str]:
    """Rules that need only this ledger, the records and the generation floor."""
    p: list[str] = []
    if not isinstance(ledger, dict):
        return ["ledger must be an object"]
    unknown = set(ledger) - LEDGER_FIELDS
    if unknown:
        p.append(f"ledger has unknown fields {sorted(unknown)}")
    if ledger.get("schema_version") != LEDGER_SCHEMA_VERSION:
        p.append(f"ledger schema_version must be {LEDGER_SCHEMA_VERSION}")
    channel = ledger.get("channel")
    if channel not in CHANNELS:
        p.append(f"channel {channel!r} is not one of {CHANNELS}")
    if file_stem is not None and channel != file_stem:
        p.append(f"ledger channel {channel!r} does not match its file name {file_stem!r}")
    if not _is_str(ledger.get("reason")):
        p.append("ledger.reason must be a non-empty string")

    minimum = ledger.get("minimum_supported_version")
    try:
        semver_key(minimum)
    except ValueError:
        p.append(f"minimum_supported_version {minimum!r} is not strict semver")
        minimum = None

    entries = ledger.get("entries")
    if not isinstance(entries, dict) or not entries:
        p.append("entries must be a non-empty object")
        return p
    unknown_src = set(entries) - set(SOURCES)
    if unknown_src:
        p.append(f"entries has unknown install_source {sorted(unknown_src)}")
    history = ledger.get("history", {})
    if not (isinstance(history, dict) and set(history) <= set(SOURCES)
            and all(isinstance(v, list) and all(isinstance(x, str) for x in v) for v in history.values())):
        p.append("history must map install_source to a list of version strings")
        history = {}
    withdrawn = ledger.get("withdrawn_versions", [])
    if not (isinstance(withdrawn, list) and all(isinstance(x, str) for x in withdrawn)):
        p.append("withdrawn_versions must be a list of version strings")
        withdrawn = []
    for w in withdrawn:
        try:
            semver_key(w)
        except ValueError:
            p.append(f"withdrawn_versions entry {w!r} is not strict semver")
    if len(set(withdrawn)) != len(withdrawn):
        p.append("withdrawn_versions contains duplicates")

    generations = {}
    for source, e in entries.items():
        if source not in SOURCES:
            continue
        where = f"entries[{source}]"
        if not (isinstance(e, dict) and set(e) == ENTRY_FIELDS):
            p.append(f"{where} must have exactly {sorted(ENTRY_FIELDS)}")
            continue
        roll = e["rollout_percentage"]
        if not _is_int(roll) or not 0 <= roll <= 100:
            p.append(f"{where}.rollout_percentage must be an int in 0..100")
        if not isinstance(e["kill_switch"], bool):
            p.append(f"{where}.kill_switch must be a boolean")
        ver = e["version"]
        try:
            semver_key(ver)
        except ValueError:
            p.append(f"{where}.version {ver!r} is not strict semver")
            continue
        if ver in withdrawn:
            p.append(f"{where}.version {ver} is listed in withdrawn_versions")
        if source in history and ver not in history[source]:
            p.append(f"{where}.version {ver} is missing from history[{source}]")
        elif source not in history:
            p.append(f"{where}: history[{source}] must list every version ever served")
        if minimum is not None:
            try:
                if semver_key(minimum) > semver_key(ver):
                    p.append(f"minimum_supported_version {minimum} exceeds {source} version {ver}")
                if _core(floor) > _core(ver):
                    p.append(f"{where}.version {ver} is older than {floor}, the first release of "
                             "the protocol generation this tree carries")
            except ValueError as ex:
                p.append(str(ex))
        rec = records.get(ver)
        if rec is None:
            p.append(f"{where}: no release record for version {ver}")
            continue
        if rec.get("build_lane") != CHANNEL_LANE.get(channel):
            p.append(f"{where}: version {ver} was built in lane {rec.get('build_lane')!r}, "
                     f"which may not be served on {channel!r}")
        if not rec.get(source):
            p.append(f"{where}: record {ver} has no {source} artifacts")
        if channel in release_channels.PROMOTES_FROM and SEMVER_RE.fullmatch(ver) \
                and SEMVER_RE.fullmatch(ver).group(4) is not None:
            p.append(f"{where}: pre-release version {ver} may not be served on {channel!r}")
        generations[source] = (ver, json.dumps(rec.get("protocol_generation"), sort_keys=True))
    if minimum is not None:
        try:
            if _core(floor) > _core(minimum):
                p.append(f"minimum_supported_version {minimum} is below {floor}, the first release of "
                         "this protocol generation; older builds must be told an update is required")
        except ValueError as ex:
            p.append(str(ex))
    # Entries at different versions must share one protocol generation.
    items = list(generations.values())
    for i, (va, ga) in enumerate(items):
        for vb, gb in items[i + 1:]:
            if va != vb and ga != gb:
                p.append(f"entries at {va} and {vb} are in different protocol generations; promote "
                         "a generation change for every install_source or for none")
    return p


def promotion_problems(ledger: dict, source_ledger: dict | None, records: dict[str, dict], *,
                       floor: str) -> list[str]:
    """A promoting channel serves only what its source channel has served. Checked, for every
    entry of the promoting ledger and the same install_source in the source ledger (itself
    validated first, so a malformed source fails closed):
      - the version is in the source's history and not in its withdrawn_versions;
      - if the source currently serves that version, it is not kill-switched and its rollout is
        100 (a version still ramping or switched off on the source is not promoted).
    Not checked: how long the version has been live (history has no publish times) and whether
    the source ledger gained the version in the same change as this one (the ledger alone cannot
    tell; the reviewer of the change must)."""
    channel = ledger.get("channel")
    source_channel = release_channels.PROMOTES_FROM.get(channel)
    if source_channel is None:
        return []
    if not isinstance(source_ledger, dict) or source_ledger.get("channel") != source_channel:
        return [f"{channel!r} promotes from {source_channel!r}: the {source_channel} ledger is required"]
    found = validate_ledger(source_ledger, records, floor=floor, file_stem=source_channel)
    if found:
        return [f"the {source_channel} ledger this promotion reads is invalid: {x}" for x in found]
    p = []
    history = source_ledger["history"]
    withdrawn = source_ledger.get("withdrawn_versions", [])
    for source, e in (ledger.get("entries") or {}).items():
        ver = e.get("version") if isinstance(e, dict) else None
        if ver not in history.get(source, []):
            p.append(f"entries[{source}].version {ver} is not in the {source_channel} history")
        elif ver in withdrawn:
            p.append(f"entries[{source}].version {ver} is withdrawn on {source_channel}")
        else:
            now = source_ledger["entries"].get(source)
            if now and now["version"] == ver and (now["kill_switch"] or now["rollout_percentage"] != 100):
                p.append(f"entries[{source}].version {ver} is not fully offered on {source_channel} "
                         "(kill-switched or rollout below 100)")
    return p


def validate_transition(prev, cur, records: dict[str, dict], *, floor: str,
                        served_appcast_version: str | None = None) -> list[str]:
    """Rules that compare a ledger with the ledger it replaces and with what is live."""
    p: list[str] = []
    if prev is None:
        prev_entries, prev_hist, prev_withdrawn = {}, {}, []
    else:
        prev_entries = prev.get("entries", {})
        prev_hist = prev.get("history", {})
        prev_withdrawn = prev.get("withdrawn_versions", [])
    minimum = cur.get("minimum_supported_version")
    withdrawn = cur.get("withdrawn_versions", [])
    history = cur.get("history", {})
    missing_w = set(prev_withdrawn) - set(withdrawn)
    if missing_w:
        p.append(f"withdrawn_versions may only grow; dropped {sorted(missing_w)}")
    for source, ph in prev_hist.items():
        if history.get(source, [])[:len(ph)] != ph:
            p.append(f"history[{source}] must keep the previous history as a prefix (append only)")
    if prev is not None:
        # Only the version being served now may be added; otherwise a fabricated history entry
        # could later serve as a yank target.
        for source in history:
            served = (cur.get("entries", {}).get(source) or {}).get("version")
            added = history[source][len(prev_hist.get(source, [])):]
            if any(v != served for v in added) or len(added) > 1:
                p.append(f"history[{source}] may only gain the version now served ({served})")

    for source in prev_entries:
        if source not in cur.get("entries", {}):
            p.append(f"entries[{source}] was removed; a served install_source is kept (use its "
                     "kill_switch to withdraw it)")

    for source, e in cur.get("entries", {}).items():
        before = prev_entries.get(source)
        old_rec = records.get(before["version"]) if isinstance(before, dict) else None
        new_rec = records.get(e.get("version")) if isinstance(e, dict) else None
        if old_rec and new_rec and old_rec.get(source) and new_rec.get(source):
            for tname in sorted(set(old_rec[source]) - set(new_rec[source])):
                p.append(f"entries[{source}] drops served target {tname}; clients on it would "
                         "see no entry")

    reason = cur.get("reason") or ""
    yank = YANK_RE.match(reason)
    for source, e in cur.get("entries", {}).items():
        before = prev_entries.get(source)
        if not before or not isinstance(e, dict):
            continue
        try:
            new_k, old_k = semver_key(e["version"]), semver_key(before["version"])
        except (ValueError, KeyError):
            continue
        if new_k >= old_k:
            continue
        where = f"entries[{source}]"
        bad, target = before["version"], e["version"]
        if not yank or yank.group(1) != bad:
            p.append(f"{where} moves back from {bad} to {target}; only a ledger reason "
                     f"starting `yank {bad}` may do that")
            continue
        if target not in prev_hist.get(source, []):
            p.append(f"{where}: yank target {target} was never live on this channel")
        if bad not in withdrawn:
            p.append(f"{where}: yanked version {bad} must be listed in withdrawn_versions")
        gt = (records.get(target) or {}).get("protocol_generation")
        gb = (records.get(bad) or {}).get("protocol_generation")
        if gt is None or gb is None or gt != gb:
            p.append(f"{where}: yank target {target} must be in the same protocol generation as {bad}")

    # A minimum is never raised past what is already live, so a run never requires an item it
    # is the first to publish.
    live = {s: e["version"] for s, e in prev_entries.items()}
    if served_appcast_version is not None:
        try:
            semver_key(served_appcast_version)
        except ValueError:
            p.append(f"served appcast version {served_appcast_version!r} is not strict semver")
            return p
        live["app_bundle"] = served_appcast_version
    for s, v in live.items():
        # A minimum the generation floor demands (first release of a new protocol generation)
        # cannot wait for the version to be live.
        if s in cur.get("entries", {}) and semver_key(minimum) > semver_key(v) \
                and semver_key(minimum) != semver_key(floor):
            p.append(f"minimum_supported_version {minimum} is above {v}, the version already "
                     f"live for {s}; publish the version first, raise the minimum afterwards")
    return p


def check_records_immutable(base: dict[str, bytes], head: dict[str, bytes]) -> list[str]:
    """`base`/`head` map record file name -> bytes. A record present in base may not change or
    disappear."""
    p = []
    for name, data in sorted(base.items()):
        if name not in head:
            p.append(f"release record {name} was deleted")
        elif head[name] != data:
            p.append(f"release record {name} was edited; merged records are immutable")
    return p


# --------------------------------------------------------------------------- assemble


def _url(version: str, name: str) -> str:
    return f"{DL_PREFIX}{version}/{name}"


def build_entries(ledger: dict, records: dict[str, dict]) -> list[dict]:
    channel, minimum = ledger["channel"], ledger["minimum_supported_version"]
    out = []
    for source in SOURCES:
        e = ledger["entries"].get(source)
        if e is None:
            continue
        rec = records[e["version"]]
        for tname in sorted(rec[source]):
            t = rec[source][tname]
            platform, arch = TARGET_RE.fullmatch(tname).groups()
            if source == "script":
                name, sha, size = t["asset"], t["sha256"], t["size"]
            elif source == "app_bundle":
                name, sha, size = t["file"], t["sha256"], t["size"]
            else:
                # The client never downloads for a store install; the URL is a page under /dl/.
                name, sha, size = "microsoft-store", t["upload_sha256"], t["upload_size"]
            out.append({
                "channel": channel,
                "platform": platform,
                "arch": arch,
                "install_source": source,
                "version": e["version"],
                "minimum_supported_version": minimum,
                "rollout_percentage": e["rollout_percentage"],
                "kill_switch": e["kill_switch"],
                "mandatory": False,
                "artifact_url": _url(e["version"], name),
                "artifact_sha256": sha,
                "artifact_size": size,
                "artifact_publisher_identity": t.get("publisher_identity", ""),
                "release_notes_url": "",
                "state_schema_version": int(rec["state_schema"]),
                "state_schema_min_readable": int(rec["state_schema"]),
                **({"sparkle_build": int(t["sparkle_build"])} if source == "app_bundle" else {}),
            })
    return out


def check_unique_and_urls(releases: list[dict]) -> list[str]:
    p, seen = [], set()
    for i, r in enumerate(releases):
        key = (r["channel"], r["install_source"], r["platform"], r["arch"])
        if key in seen:
            p.append(f"releases[{i}] duplicates the entry for {key}")
        seen.add(key)
        url = r["artifact_url"]
        rest = url[len(DL_PREFIX):]
        if not url.startswith(DL_PREFIX) or any(c in rest for c in "?#\\") or ".." in rest \
                or "//" in rest or not re.fullmatch(r"[A-Za-z0-9._/-]+", rest):
            p.append(f"releases[{i}].artifact_url {url!r} is not under {DL_PREFIX}")
    return p


def build_appcast(ledger: dict, records: dict[str, dict]) -> dict:
    """Appcast body data, derived from the app_bundle entry alone. A kill-switched entry offers
    nothing."""
    items = []
    e = ledger["entries"].get("app_bundle")
    if e is not None and not e["kill_switch"] and e["rollout_percentage"] > 0:
        rec = records[e["version"]]
        for tname in sorted(rec["app_bundle"]):
            t = rec["app_bundle"][tname]
            platform, arch = TARGET_RE.fullmatch(tname).groups()
            items.append({
                "platform": platform,
                "arch": arch,
                "version": e["version"],
                "sparkle_build": t["sparkle_build"],
                "url": _url(e["version"], t["file"]),
                "sha256": t["sha256"],
                "size": t["size"],
                "rollout_percentage": e["rollout_percentage"],
            })
    return {"channel": ledger["channel"], "items": items}


def check_appcast_covered(appcast: dict, manifest: dict) -> list[str]:
    """Every appcast item must be exactly what the manifest's app_bundle entry serves, and that
    entry must not be kill-switched."""
    p = []
    entries = {
        (r["platform"], r["arch"]): r for r in manifest.get("releases", [])
        if r.get("install_source") == "app_bundle" and r.get("channel") == appcast.get("channel")
    }
    for i, it in enumerate(appcast.get("items", [])):
        r = entries.get((it.get("platform"), it.get("arch")))
        where = f"appcast.items[{i}]"
        if r is None:
            p.append(f"{where}: the manifest has no app_bundle entry for {it.get('platform')}-"
                     f"{it.get('arch')}")
        elif r["kill_switch"]:
            p.append(f"{where}: the manifest kill-switches app_bundle {r['version']}")
        elif r["version"] != it.get("version"):
            p.append(f"{where}: version {it.get('version')} is not the manifest's app_bundle "
                     f"version {r['version']}")
        elif (r["artifact_url"], r["artifact_sha256"], r["artifact_size"], r["rollout_percentage"],
              str(r.get("sparkle_build"))) != \
                (it.get("url"), it.get("sha256"), it.get("size"), it.get("rollout_percentage"),
                 str(it.get("sparkle_build"))):
            p.append(f"{where}: url/sha256/size/rollout/build do not match the manifest's "
                     "app_bundle entry")
    return p


def render_body(manifest: dict) -> str:
    """The exact bytes that get signed (also used by generate-update-manifest.py)."""
    return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def assemble(ledger: dict, records: dict[str, dict], trust_chain_text: str, generated_at: str, *,
             floor: str, previous_ledger: dict | None = None,
             served_appcast_version: str | None = None,
             ledger_stem: str | None = None, promotion_source: dict | None = None) -> dict:
    """Pure: build the unsigned manifest body and appcast body data, or raise LedgerError.

    Returns {manifest_body, manifest_body_sha256, appcast, trust_chain_sha256}. The trust chain
    rides on the signed envelope rather than the body, so only its digest is reported (it must be
    a JSON array)."""
    problems: list[str] = []
    if not GENERATED_AT_RE.fullmatch(generated_at or ""):
        problems.append(f"generated_at {generated_at!r} must be YYYY-MM-DDTHH:MM:SSZ")
    chain = load_json(trust_chain_text, "trust-chain.json")
    if not isinstance(chain, list):
        problems.append("trust-chain.json must be a JSON array")
    for ver, rec in sorted(records.items()):
        problems += [f"records/{ver}: {x}" for x in validate_record(rec, ver)]
    if problems:
        raise LedgerError(problems)
    problems += validate_ledger(ledger, records, floor=floor, file_stem=ledger_stem)
    if problems:
        raise LedgerError(problems)
    problems += validate_transition(previous_ledger, ledger, records, floor=floor,
                                    served_appcast_version=served_appcast_version)
    problems += promotion_problems(ledger, promotion_source, records, floor=floor)
    releases = build_entries(ledger, records)
    problems += check_unique_and_urls(releases)
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": generated_at,
        "expires_at": expires_at_for(generated_at),
        "releases": releases,
    }
    withdrawn = sorted(set(ledger.get("withdrawn_versions", [])), key=semver_key)
    if withdrawn:
        # Unknown to older clients, which ignore it (the client does not deny unknown fields).
        manifest["withdrawn_versions"] = withdrawn
    appcast = build_appcast(ledger, records)
    problems += check_appcast_covered(appcast, manifest)
    if problems:
        raise LedgerError(problems)
    body = render_body(manifest)
    return {
        "manifest_body": body,
        "manifest_body_sha256": sha256_hex(body),
        "appcast": appcast,
        "trust_chain_sha256": sha256_hex(trust_chain_text),
    }


def load_records(directory: Path) -> dict[str, dict]:
    records = {}
    problems = []
    for path in sorted(directory.glob("*.json")):
        try:
            records[path.stem] = load_json(path.read_text(encoding="utf-8"), str(path))
        except LedgerError as ex:
            problems += ex.problems
    if problems:
        raise LedgerError(problems)
    return records
