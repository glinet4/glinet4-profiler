"""Registry lookup tests."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import json
from pathlib import Path

from glinet_profiler.registry import build_manifest, load_manifest, lookup, rebuild

MANIFEST = {
    "devices": [
        {"id": "mt6000_4.9.0", "model": "mt6000", "firmware_version": "4.9.0"},
        {"id": "ax1800_4.0.0", "model": "ax1800", "firmware_version": "4.0.0"},
    ]
}


def test_lookup_match():
    entry = lookup("mt6000", "4.9.0", MANIFEST)
    assert entry is not None and entry["id"] == "mt6000_4.9.0"


def test_lookup_miss():
    assert lookup("mt6000", "9.9.9", MANIFEST) is None
    assert lookup("nope", "4.9.0", MANIFEST) is None


def test_load_manifest_reads_bundled_seed():
    manifest = load_manifest()
    ids = [d["id"] for d in manifest["devices"]]
    assert "mt6000_4.9.0" in ids


def test_build_manifest_counts():
    profile = {
        "id": "mt6000_4.9.0",
        "model": "mt6000",
        "firmware_version": "4.9.0",
        "services": {
            "system": {"get_info": {"status": "available", "covered_by": "router_info"}},
            "firewall": {
                "get_rule_list": {"status": "available", "covered_by": None},
                "set_rule": {"status": "absent", "covered_by": None},
            },
        },
    }
    entry = build_manifest([profile])["devices"][0]
    assert entry["available_count"] == 2
    assert entry["service_count"] == 2
    assert entry["not_wrapped_count"] == 1


def test_build_manifest_needs_params_is_present():
    profile = {
        "id": "x_1",
        "model": "x",
        "firmware_version": "1",
        "services": {"svc": {"m": {"status": "needs_params", "covered_by": None}}},
    }
    entry = build_manifest([profile])["devices"][0]
    assert entry["available_count"] == 1
    assert entry["not_wrapped_count"] == 1


def test_build_manifest_empty():
    assert build_manifest([]) == {"devices": []}


def test_rebuild_writes_index(tmp_path):
    devices = tmp_path / "devices"
    devices.mkdir()
    (devices / "x_1.json").write_text(
        json.dumps(
            {
                "id": "x_1",
                "model": "x",
                "firmware_version": "1",
                "services": {"svc": {"m": {"status": "available", "covered_by": None}}},
            }
        ),
        encoding="utf-8",
    )
    count = rebuild(tmp_path)
    assert count == 1
    manifest = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert manifest["devices"][0]["id"] == "x_1"
    assert manifest["devices"][0]["available_count"] == 1
    assert manifest["devices"][0]["service_count"] == 1
    assert manifest["devices"][0]["not_wrapped_count"] == 1


def test_rebuild_missing_devices_dir(tmp_path):
    count = rebuild(tmp_path)  # no devices/ subdir
    assert count == 0
    assert json.loads((tmp_path / "index.json").read_text(encoding="utf-8")) == {"devices": []}


def test_build_manifest_sorts_by_model_then_firmware():
    profiles = [
        {"id": "b_1", "model": "b", "firmware_version": "1", "services": {}},
        {"id": "a_2", "model": "a", "firmware_version": "2", "services": {}},
        {"id": "a_1", "model": "a", "firmware_version": "1", "services": {}},
    ]
    ids = [d["id"] for d in build_manifest(profiles)["devices"]]
    assert ids == ["a_1", "a_2", "b_1"]


def test_committed_manifest_matches_devices():
    data = Path(__file__).resolve().parent.parent / "src" / "glinet_profiler" / "data"
    profiles = [
        json.loads(p.read_text(encoding="utf-8")) for p in sorted((data / "devices").glob("*.json"))
    ]
    committed = json.loads((data / "index.json").read_text(encoding="utf-8"))
    assert committed == build_manifest(profiles)
