"""Tests for fixtures.py: sanitized raw-response fixture emission."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import json
from datetime import datetime, timezone
from importlib.metadata import version as pkg_version

from glinet4_profiler.fixtures import (
    build_fixture_set,
    profiler_version,
    select_fixture_methods,
    write_fixture_set,
)

# Shaped like enumerator.report.to_json's output (see tests/test_capture.py's RAW for the
# minimal version): device + services -> method -> {status, error_code, risk, discovered_by,
# covered_by, params, signature, value}.
RAW = {
    "device": {
        "model": "mt6000",
        "firmware_version": "4.9.0",
        "mac": "94:83:C4:AA:BB:CC",
        "sn": "SN0001234",
    },
    "services": {
        "system": {
            "get_info": {
                "status": "available",
                "error_code": None,
                "risk": "read",
                "discovered_by": "catalog",
                "covered_by": "router_info",
                "params": None,
                "signature": {"mac": "<mac>"},
                "value": {"mac": "94:83:C4:AA:BB:CC", "model": "mt6000"},
            },
            "reboot": {  # dangerous; even though "available" here, must never yield a fixture
                "status": "available",
                "error_code": None,
                "risk": "dangerous",
                "discovered_by": "ssh",
                "covered_by": None,
                "params": None,
                "signature": None,
                "value": {"ok": True},
            },
        },
        "clients": {
            "get_list": {
                "status": "available",
                "error_code": None,
                "risk": "read",
                "discovered_by": "catalog",
                "covered_by": "list_all_clients",
                "params": None,
                "signature": {},
                "value": {
                    "94:83:C4:AA:BB:01": {"mac": "94:83:C4:AA:BB:01", "name": "Shaunes-iPhone"},
                },
            },
            "block_client": {  # write method: recorded as "discovered", never HTTP-called
                "status": "discovered",
                "error_code": None,
                "risk": "write",
                "discovered_by": "ssh",
                "covered_by": None,
                "params": None,
                "signature": None,
                "value": None,
            },
        },
        "lan": {
            "get_static_bind_list": {
                "status": "available",
                "error_code": None,
                "risk": "read",
                "discovered_by": "catalog",
                "covered_by": "list_static_clients",
                "params": None,
                "signature": [],
                # same real MAC as clients.get_list — proves cross-payload identity survives
                "value": [{"mac": "94:83:C4:AA:BB:01", "ip": "192.168.8.50"}],
            },
        },
        "wifi": {
            "get_config": {  # errored probe: no meaningful value, must not emit a fixture
                "status": "error",
                "error_code": -32603,
                "risk": "read",
                "discovered_by": "catalog",
                "covered_by": "wifi_ifaces_get",
                "params": None,
                "signature": None,
                "value": None,
            },
        },
    },
}


def test_select_fixture_methods_only_successful_reads():
    selected = select_fixture_methods(RAW)
    names = [(s, m) for s, m, _ in selected]
    assert names == [
        ("clients", "get_list"),
        ("lan", "get_static_bind_list"),
        ("system", "get_info"),
    ]
    # excluded: reboot (dangerous, despite "available"), block_client (discovered/no value),
    # wifi.get_config (errored/no value)
    assert ("system", "reboot") not in names
    assert ("clients", "block_client") not in names
    assert ("wifi", "get_config") not in names


def test_build_fixture_set_names_files_and_sanitizes():
    fixture_id, files, _manifest = build_fixture_set(RAW)
    assert fixture_id == "mt6000_4.9.0"
    assert set(files.keys()) == {
        "system.get_info.json",
        "clients.get_list.json",
        "lan.get_static_bind_list.json",
    }
    sysinfo = files["system.get_info.json"]
    assert sysinfo["mac"] != "94:83:C4:AA:BB:CC"  # pseudonymized, not the real device MAC


def test_build_fixture_set_pseudonymizes_macs_consistently_across_methods():
    _fixture_id, files, _manifest = build_fixture_set(RAW)
    clients = files["clients.get_list.json"]
    static = files["lan.get_static_bind_list.json"]
    fake_mac = next(iter(clients.keys()))
    assert clients[fake_mac]["mac"] == fake_mac
    # the SAME real MAC appears in clients.get_list (dict key) and lan.get_static_bind_list (list
    # item) — one sanitizer instance per fixture set means they land on the same fake MAC
    assert static[0]["mac"] == fake_mac
    assert static[0]["ip"] == "192.168.8.50"  # LAN IP: topology info, kept verbatim


def test_build_fixture_set_manifest_has_provenance_fields():
    when = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
    _fixture_id, _files, manifest = build_fixture_set(RAW, captured_at=when)
    assert manifest["id"] == "mt6000_4.9.0"
    assert manifest["model"] == "mt6000"
    assert manifest["firmware_version"] == "4.9.0"
    assert manifest["captured_at"] == when.isoformat()
    assert manifest["profiler_version"] == pkg_version("glinet4-profiler")
    assert isinstance(manifest["sanitizer_version"], int)
    assert isinstance(manifest["ruleset_hash"], str) and manifest["ruleset_hash"]
    assert manifest["methods"] == [
        "clients.get_list",
        "lan.get_static_bind_list",
        "system.get_info",
    ]


def test_write_fixture_set_writes_files_and_manifest(tmp_path):
    when = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
    target = write_fixture_set(RAW, tmp_path, captured_at=when)
    assert target == tmp_path / "mt6000_4.9.0"
    assert (target / "system.get_info.json").exists()
    assert (target / "clients.get_list.json").exists()
    assert (target / "lan.get_static_bind_list.json").exists()
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["id"] == "mt6000_4.9.0"
    assert manifest["captured_at"] == when.isoformat()
    # zero real identifiers survive anywhere on disk
    blob = "\n".join(p.read_text(encoding="utf-8") for p in target.glob("*.json"))
    assert "94:83:C4" not in blob
    assert "Shaunes-iPhone" not in blob
    assert "SN0001234" not in blob  # device-level secret never even reaches the fixture set
    assert "192.168.8.50" in blob  # LAN topology info: this IS the fixture's value


def test_profiler_version_matches_installed_distribution():
    assert profiler_version() == pkg_version("glinet4-profiler")
