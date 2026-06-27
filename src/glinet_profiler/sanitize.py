"""Sanitizing projection: a raw enumerator report -> publishable profile.

Drops device identifiers (mac/sn/sn_bak) and every method response value;
keeps model+firmware plus the per-method API shape (status/risk/coverage/params/schema).
The schema is kept intact: its keys are type-erased API field-names (documentation),
not device values.
"""

from typing import Any

_DEVICE_FIELDS = ("model", "firmware_version", "vendor", "device_type", "hardware_version")
_METHOD_FIELDS = ("status", "error_code", "risk", "discovered_by", "covered_by", "params", "schema")


def project_report(raw: dict[str, Any], device_id_str: str) -> dict[str, Any]:
    """Project a raw enumerator report to the sanitized, publishable profile."""
    device = raw.get("device", {})
    out: dict[str, Any] = {"id": device_id_str}
    for field in _DEVICE_FIELDS:
        if field in device:
            out[field] = device[field]
    out["services"] = {
        service: {
            method: {field: rec.get(field) for field in _METHOD_FIELDS}
            for method, rec in methods.items()
        }
        for service, methods in raw.get("services", {}).items()
    }
    return out
