"""Build a prefilled GitHub issue URL for submitting a captured profile."""

import urllib.parse
from typing import Any

# The registry repo that receives profile submissions (update on extraction).
REGISTRY_REPO = "shauneccles/glinet-profiler"
_PRESENT = ("available", "needs_params")


def prefilled_issue_url(profile: dict[str, Any], *, repo: str = REGISTRY_REPO) -> str:
    """Construct a prefilled 'submit profile' GitHub issue URL (asks the user to attach the file)."""
    model = profile.get("model", "unknown")
    firmware = profile.get("firmware_version", "unknown")
    services = profile.get("services", {})
    available = sum(
        1
        for methods in services.values()
        for rec in methods.values()
        if rec.get("status") in _PRESENT
    )
    title = f"Add profile: {model} ({firmware})"
    body = (
        "Device API profile submission.\n\n"
        f"- Model: `{model}`\n"
        f"- Firmware: `{firmware}`\n"
        f"- Available methods: {available}\n\n"
        f"Please **attach the downloaded `{profile.get('id', 'profile')}.json`** to this issue.\n"
    )
    query = urllib.parse.urlencode({"title": title, "body": body, "labels": "profile-submission"})
    return f"https://github.com/{repo}/issues/new?{query}"
