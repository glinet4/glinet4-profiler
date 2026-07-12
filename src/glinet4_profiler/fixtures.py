"""Emit sanitized raw-response fixtures for the glinet4 library's golden tests.

``capture.capture_raw`` enumerates read-only methods and returns the RAW per-device report —
response values un-redacted, the same shape ``capture.capture`` builds internally but caught
*before* ``sanitize.project_report`` strips every value out. This module is the seam's other
half: it selects every successfully-probed READ method's raw value, runs each through one shared
``sanitize.FixtureSanitizer`` instance (so MAC/IP/SSID/hostname pseudonymization is consistent
*across* every method's payload in the set — cross-payload identity, e.g. a client MAC appearing
in both ``clients.get_list`` and ``lan.get_static_bind_list``, survives sanitization), and writes
one JSON file per (service, method) plus a ``manifest.json`` recording provenance: model,
firmware, capture date, profiler version, and the sanitizer's version/ruleset hash — so a
consumer (the library's ``tests/fixtures/``) can assert the fixture set's origin and freshness.

The values handed to ``FixtureSanitizer`` here are genuinely raw. Nothing in this module is
publishable or safe to persist until it has gone through ``sanitize.FixtureSanitizer`` — every
call site below does that before anything touches disk.
"""

import json
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

from .enumerator.probe import device_id
from .sanitize import FIXTURE_SANITIZER_VERSION, FixtureSanitizer, ruleset_hash

_PACKAGE_NAME = "glinet4-profiler"


def profiler_version() -> str:
    """Installed ``glinet4-profiler`` distribution version (``0+unknown`` if not installed)."""
    try:
        return _pkg_version(_PACKAGE_NAME)
    except PackageNotFoundError:
        return "0+unknown"


def select_fixture_methods(raw: dict[str, Any]) -> list[tuple[str, str, Any]]:
    """Every successfully-probed READ method's raw value, as ``(service, method, value)`` triples.

    Sorted by ``(service, method)`` for deterministic file emission. Read-only discipline is
    already enforced upstream — ``capture.capture_raw`` never HTTP-calls a non-read method (see
    ``enumerator.catalog.is_read_method``) — this filter is defense-in-depth: it additionally
    requires ``status == "available"``, ``risk == "read"``, and a non-null ``value`` (matching the
    field names ``enumerator.report.to_json`` writes), so a WRITE/DANGEROUS method that somehow
    carries a stray value (e.g. an SSH-discovered write recorded without an HTTP call) can never
    produce a fixture file.
    """
    out: list[tuple[str, str, Any]] = []
    for service, methods in sorted(raw.get("services", {}).items()):
        for method, rec in sorted(methods.items()):
            if (
                rec.get("status") == "available"
                and rec.get("risk") == "read"
                and rec.get("value") is not None
            ):
                out.append((service, method, rec["value"]))
    return out


def build_fixture_set(
    raw: dict[str, Any], *, captured_at: datetime | None = None
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Sanitize a raw capture report into ``(fixture_id, {filename: sanitized_json}, manifest)``.

    One ``FixtureSanitizer`` instance is shared across every method in the set, so the same real
    MAC/IP/SSID/hostname anywhere in the capture maps to the same fake value everywhere it
    appears — the property the library's golden tests rely on for cross-payload identity.
    """
    device = raw.get("device", {})
    fixture_id = device_id(device)
    sanitizer = FixtureSanitizer()
    methods = select_fixture_methods(raw)
    files = {
        f"{service}.{method}.json": sanitizer.sanitize(value) for service, method, value in methods
    }
    manifest = {
        "id": fixture_id,
        "model": device.get("model"),
        "firmware_version": device.get("firmware_version"),
        "captured_at": (captured_at or datetime.now(timezone.utc)).isoformat(),
        "profiler_version": profiler_version(),
        "sanitizer_version": FIXTURE_SANITIZER_VERSION,
        "ruleset_hash": ruleset_hash(),
        "methods": [f"{service}.{method}" for service, method, _value in methods],
    }
    return fixture_id, files, manifest


def write_fixture_set(
    raw: dict[str, Any], out_dir: Path, *, captured_at: datetime | None = None
) -> Path:
    """Write a sanitized fixture set — one JSON per method plus ``manifest.json`` — under
    ``out_dir/<model>_<firmware>/`` and return that directory.
    """
    fixture_id, files, manifest = build_fixture_set(raw, captured_at=captured_at)
    target = out_dir / fixture_id
    target.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        _dump(target / name, data)
    _dump(target / "manifest.json", manifest)
    return target


def _dump(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
