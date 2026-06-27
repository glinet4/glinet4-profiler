"""Structural + data-safety smoke for the registry browser site."""
# pylint: disable=missing-function-docstring

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
DATA = ROOT / "src" / "glinet_profiler" / "data"


def test_index_has_controls():
    html = (SITE / "index.html").read_text(encoding="utf-8")
    for needle in (
        'id="device"',
        'id="search"',
        'id="available-only"',
        'id="not-wrapped"',
        'id="results"',
        "app.js",
        "style.css",
    ):
        assert needle in html, needle


def test_app_js_fetches_relative_data_paths():
    js = (SITE / "app.js").read_text(encoding="utf-8")
    assert "data/index.json" in js
    assert "data/devices/" in js


def test_registry_data_present_and_sanitized():
    manifest = json.loads((DATA / "index.json").read_text(encoding="utf-8"))
    assert manifest["devices"], "expected committed registry data"
    mac_re = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    for entry in manifest["devices"]:
        dev = json.loads((DATA / "devices" / f"{entry['id']}.json").read_text(encoding="utf-8"))
        assert "mac" not in dev and "sn" not in dev and "sn_bak" not in dev
        for service in dev["services"].values():
            for rec in service.values():
                assert "value" not in rec
        assert not mac_re.search(json.dumps(dev))
