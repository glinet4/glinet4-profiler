"""Registry lookup: load the bundled manifest and match (model, firmware)."""

import json
from importlib import resources
from typing import Any


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
