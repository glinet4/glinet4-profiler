"""Distill a probed response value into a publishable signature.

Balanced labeling (see docs/superpowers/specs/2026-06-29-rich-schema-design.md §4.2): numbers,
booleans, null, and short enum-like strings are kept verbatim (the API contract); identifiers and
personal/free-text strings are replaced with a format label so a developer learns the type/format
without the submitter's data. Runs at sanitize time on the user's machine; raw values are never
published — only this distilled result.
"""

import re

from .redact import key_is_secret  # shared secret-key matcher (renamed export, Task 1 Step 3a)

_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HEXCOLON = re.compile(r"^[0-9A-Fa-f:]+$")
_TIME = re.compile(r"^\d{1,2}:\d{2}(:\d{2})?$")  # HH:MM(:SS) time-of-day, checked before IPv6
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}")  # ISO-8601 date or datetime
# No ':' in the enum charset — colon-bearing tokens (ip:port, "08:30:00") fall through to <string>
# rather than being kept as an "enum".
_ENUM = re.compile(r"^[A-Za-z0-9._-]{1,24}$")
_PERSONAL = (
    "ssid",
    "name",
    "hostname",
    "host",
    "comment",
    "description",
    "desc",
    "note",
    "label",
    "path",
    "url",
    "email",
    "domain",
    "ddns",
    "user",
    "username",
    "server",
    "endpoint",
    "peer",
    "address",
    "addr",
)


def _key_is_personal(key: str) -> bool:
    low = key.lower()
    return any(low == t or low.endswith("_" + t) or low.startswith(t + "_") for t in _PERSONAL)


def _label_str(value: str, key: str | None) -> str:  # pylint: disable=too-many-return-statements
    if key is not None and key_is_secret(key):
        return "<secret>"
    if _MAC.match(value):
        return "<mac>"
    if _IPV4.match(value):
        return "<ipv4>"
    if _TIME.match(value):
        return "<datetime>"  # HH:MM(:SS) is a time-of-day, not an IPv6 address
    if value.count(":") >= 2 and _HEXCOLON.match(value):
        return "<ipv6>"
    if _DATETIME.match(value) or (value.isdigit() and len(value) in (10, 13)):
        return "<datetime>"  # ISO-8601, or a 10/13-digit unix timestamp (could leak activity times)
    if key is not None and _key_is_personal(key):
        return "<string>"
    if _ENUM.match(value):
        return value  # enum-like / mode / version — kept as the API contract
    return "<string>"


def signature_of(value: object, _key: str | None = None) -> object:
    """Distill ``value`` into a publishable signature: structure + formats + safe example scalars."""
    if isinstance(value, dict):
        return {k: signature_of(v, _key=k) for k, v in value.items()}
    if isinstance(value, list):
        # propagate the key: a personal/secret key holding a LIST of strings must still be labeled
        # by key (e.g. {"domain": ["host.example"]}), not just by value pattern.
        return [signature_of(value[0], _key=_key)] if value else []
    if isinstance(value, str):
        return _label_str(value, _key)
    return value  # int / float / bool / None kept verbatim
