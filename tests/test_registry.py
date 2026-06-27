"""Registry lookup tests."""
# pylint: disable=missing-function-docstring,redefined-outer-name

from glinet_profiler.registry import load_manifest, lookup

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
