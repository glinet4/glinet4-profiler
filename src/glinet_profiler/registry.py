"""Registry lookup + manifest building over the bundled device profiles."""

import json
from importlib import resources
from pathlib import Path
from typing import Any

_PRESENT = ("available", "needs_params")


def load_manifest() -> dict[str, Any]:
    """Load the bundled registry manifest (data/index.json)."""
    text = (resources.files("glinet_profiler") / "data" / "index.json").read_text(encoding="utf-8")
    parsed: dict[str, Any] = json.loads(text)
    return parsed


def lookup(
    model: str, firmware: str, manifest: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    """Return the manifest entry matching (model, firmware_version), or None."""
    source = manifest if manifest is not None else load_manifest()
    devices: list[dict[str, Any]] = source.get("devices", [])
    for entry in devices:
        if entry.get("model") == model and entry.get("firmware_version") == firmware:
            return entry
    return None


def build_manifest(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the manifest (per-device id/model/firmware + present-method counts)."""
    entries: list[dict[str, Any]] = []
    for dev in profiles:
        present = [
            rec
            for methods in dev["services"].values()
            for rec in methods.values()
            if rec.get("status") in _PRESENT
        ]
        service_count = sum(
            1
            for methods in dev["services"].values()
            if any(rec.get("status") in _PRESENT for rec in methods.values())
        )
        entries.append(
            {
                "id": dev["id"],
                "model": dev.get("model", "unknown"),
                "firmware_version": dev.get("firmware_version", "unknown"),
                "service_count": service_count,
                "available_count": len(present),
                "not_wrapped_count": sum(1 for rec in present if rec.get("covered_by") is None),
            }
        )
    entries.sort(key=lambda entry: (entry["model"], entry["firmware_version"]))
    return {"devices": entries}


def rebuild(data_dir: Path) -> int:
    """Rebuild ``data_dir/index.json`` from ``data_dir/devices/*.json``; return device count."""
    devices_dir = data_dir / "devices"
    paths = sorted(devices_dir.glob("*.json")) if devices_dir.exists() else []
    profiles = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    (data_dir / "index.json").write_text(
        json.dumps(build_manifest(profiles), indent=2, sort_keys=True), encoding="utf-8"
    )
    return len(profiles)
