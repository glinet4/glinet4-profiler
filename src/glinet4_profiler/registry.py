"""Runtime fetch client for the live registry manifest."""

import json
from typing import Any

import aiohttp

DEFAULT_REGISTRY_URL = "https://glinet4.github.io/glinet4-registry/data/index.json"


async def fetch_manifest(
    url: str = DEFAULT_REGISTRY_URL, *, timeout: float = 5.0
) -> dict[str, Any] | None:
    """Fetch the live registry manifest; return None on any failure (offline-friendly)."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return None
                payload = await resp.json(content_type=None)
                return payload if isinstance(payload, dict) else None
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError):
        return None


def lookup(model: str, firmware: str, manifest: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the manifest entry matching (model, firmware_version), or None."""
    if manifest is None:
        return None
    devices: list[dict[str, Any]] = manifest.get("devices", [])
    for entry in devices:
        if entry.get("model") == model and entry.get("firmware_version") == firmware:
            return entry
    return None
