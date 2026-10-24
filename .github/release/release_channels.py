"""The one definition of the update channels: `channels.json` next to this file.

Every release tool (ledger validator, manifest generator, signing request) reads its channel list
from here, and the landing site's channel list is kept equal to it by a check in that repository.
A channel serves builds from one build lane. A channel with `promotes_from` serves only builds
that were already live on that channel (promotion republishes identical bytes).
"""

from __future__ import annotations

import json
from pathlib import Path

_DEFINITION = Path(__file__).resolve().parent / "channels.json"


def _load() -> list[dict]:
    channels = json.loads(_DEFINITION.read_text(encoding="utf-8"))["channels"]
    names = [c["name"] for c in channels]
    if len(set(names)) != len(names):
        raise ValueError(f"{_DEFINITION.name}: duplicate channel name")
    for c in channels:
        if set(c) - {"name", "lane", "promotes_from"} or not {"name", "lane"} <= set(c):
            raise ValueError(f"{_DEFINITION.name}: channel {c.get('name')!r} has wrong fields")
        if c.get("promotes_from", names[0]) not in names:
            raise ValueError(f"{_DEFINITION.name}: {c['name']} promotes from an unknown channel")
    return channels


_CHANNELS = _load()
CHANNELS = tuple(c["name"] for c in _CHANNELS)
# Which build lane may be served on which channel.
CHANNEL_LANE = {c["name"]: c["lane"] for c in _CHANNELS}
# Channels that only republish what another channel already served.
PROMOTES_FROM = {c["name"]: c["promotes_from"] for c in _CHANNELS if "promotes_from" in c}
