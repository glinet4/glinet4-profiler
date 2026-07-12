"""Sanitizing projection: a raw enumerator report -> publishable profile.

Drops device identifiers (mac/sn/sn_bak) and every method response value;
keeps model+firmware plus the per-method API shape (status/risk/coverage/params/signature).
The signature is kept intact: it carries safe format labels and example scalars (the
published API shape), never raw device values.

Also keeps a small ``capabilities`` block from ``system get_info`` — the regulatory
``country_code`` and the ``software_feature``/``hardware_feature`` capability maps. These are
non-identifying (booleans + hardware descriptors, no mac/sn) and explain *why* a method works
or errors on a given variant (e.g. no modem hardware -> the modem.* methods error).
"""

import hashlib
import ipaddress
import json
import re
from typing import Any

from .enumerator.redact import OPAQUE_BLOB, key_is_secret
from .enumerator.signature import PERSONAL_FIELDS

_DEVICE_FIELDS = ("model", "firmware_version", "vendor", "device_type", "hardware_version")
# Allowlist of non-identifying capability fields lifted from system.get_info. Strict allowlist:
# mac/sn/sn_bak and everything else in get_info are dropped.
_CAPABILITY_FIELDS = ("country_code", "software_feature", "hardware_feature")
_METHOD_FIELDS = (
    "status",
    "error_code",
    "risk",
    "discovered_by",
    "covered_by",
    "params",
    "signature",
)


def project_report(
    raw: dict[str, Any], device_id_str: str, *, keep_data: bool = False
) -> dict[str, Any]:
    """Project a raw enumerator report to the sanitized, publishable profile.

    ``keep_data`` additionally keeps each method's response ``value`` (already secret-redacted by
    the enumerator: password/key/serial/token/... scrubbed). This is for LOCAL signature analysis
    only — the result is *not* a publishable profile (it carries response data, so the registry's
    validator rejects it).
    """
    device = raw.get("device", {})
    out: dict[str, Any] = {"id": device_id_str}
    for field in _DEVICE_FIELDS:
        if field in device:
            out[field] = device[field]
    capabilities = {field: device[field] for field in _CAPABILITY_FIELDS if field in device}
    if capabilities:
        out["capabilities"] = capabilities
    method_fields = (*_METHOD_FIELDS, "value") if keep_data else _METHOD_FIELDS
    out["services"] = {
        service: {
            method: {field: rec.get(field) for field in method_fields}
            for method, rec in methods.items()
        }
        for service, methods in raw.get("services", {}).items()
    }
    return out


# ── Fixture sanitization: raw-response fixtures for the library's golden tests ─────────────
#
# project_report() above drops every response VALUE outright — the safe floor for registry
# submissions. Raw-response fixtures need the values (that's the point: real API response
# shapes for the library's golden tests), so this is a materially stricter, different policy:
# every value is walked and scrubbed *in place* rather than dropped. It reuses ``key_is_secret``
# (the registry's own floor) for one rule; the MAC/IP/SSID/hostname handling below is new — raw
# response bodies carry things (client MACs, SSIDs, WAN IPs, DHCP hostnames) the value-stripped
# registry flow never had to consider.

FIXTURE_SANITIZER_VERSION = 4  # bump on any behavioral change to a rule below

# ── The free-text class ───────────────────────────────────────────────────────────────────────
# Every rule below except this one is ANCHORED: it inspects a whole value (or its key) and
# either replaces it or passes it through verbatim. That design has one structural blind spot —
# free text. A hosts file, an inline .ovpn config, a log dump, or an AT-command transcript
# carries MACs/IPs/hostnames/PEM material MID-LINE, where no whole-value rule can see them, so
# the whole blob passes untouched. Three rounds of security review each found new INSTANCES of
# this class (logread, then dns.get_host, then populated ovpn/parental-control configs), so the
# rule is now stated at the level of the class instead: a newline means free text, and free text
# is nulled. No key-name exceptions — an exception list would be exactly the "trust the key"
# pattern that produced the blind spot in the first place.
#
# Cost on the real mt6000/4.9.0 capture: exactly two strings, neither of any golden-test value
# (the glinet4 library references neither: `grep -rn 'amnezia\|get_host'` finds nothing).
#   * dns.get_host.content       — localhost boilerplate on the tested device (a customized
#                                  hosts file on an untested one is the leak this closes).
#   * wg-server.get_config.amnezia — machine-generated AmneziaWG tuning params (Jc/S1/H1..H4).
# Both keys survive with a `None` value, so the response SHAPE is preserved either way.
_MULTILINE = "\n"

# Unanchored identifier scrub (parity with ``enumerator.redact._MAC_VALUE``, which is
# deliberately unanchored — "device identifier; scrub anywhere"). Anchored full-value matching
# was a regression against the registry flow's own floor: a MAC or public IP embedded in a
# single-line string (an error message, a status line, a route description) passed verbatim.
# Substitution runs through the SAME pseudonym maps as the standalone rules, so a MAC seen both
# standalone and mid-string lands on ONE fake MAC — cross-payload identity is preserved, not
# broken, by scrubbing mid-string.
_MAC_TEXT = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
_IPV4_TEXT = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
# Loose candidate shape (hex + colons, at least one colon); every match is validated by
# ``ipaddress`` before substitution, so MAC-shaped runs (6 groups — including the 02:00:00:*
# fakes the MAC pass just wrote) and HH:MM:SS times fail to parse and are left untouched.
_IPV6_TEXT = re.compile(r"(?<![\w:.])(?=[0-9A-Fa-f]*:)[0-9A-Fa-f:]{2,45}(?![\w:.])")
# Locally-administered, unicast prefix (U/L bit set on the first octet — 0x02) — by construction
# this can never collide with a real IEEE-assigned OUI, unlike a vendor-looking prefix.
_MAC_FAKE_PREFIX = "02:00:00"
# RFC 5737 documentation ranges, used in order (254 usable host addresses each: .1-.254).
_IPV4_DOC_RANGES: tuple[tuple[str, int], ...] = (
    ("192.0.2", 254),
    ("198.51.100", 254),
    ("203.0.113", 254),
)
_SSID_KEYS = ("ssid",)
# Identity-bearing personal fields: same real value recurring under different keys/methods must
# land on the same fake token (e.g. a WireGuard peer's "name" and a client's "name" share the
# host-token space; see test_hostname_and_name_fields_share_the_host_token_space). "alias" isn't
# part of enumerator.signature.PERSONAL_FIELDS but was already handled here; the rest of this
# tuple is exactly the "tokenize" half of that shared vocabulary — see
# test_personal_field_vocabulary_is_fully_covered_by_a_rule for the completeness guarantee.
_HOST_KEYS = (
    "hostname",
    "host",
    "name",
    "alias",
    "label",
    "user",
    "username",
    "server",
    "peer",
    "address",
    "addr",
    "domain",
    "ddns",
    "email",
    # "endpoint" tokenizes (not nulls): a bare-domain endpoint with no ":port" — WireGuard's
    # real "end_point" spelling included, which never boundary-matches "endpoint" — keeps
    # cross-payload identity like every other host field; ":port" compounds keep the port via
    # _sanitize_host_port, which runs first.
    "endpoint",
    "end_point",
)
# Free-text/content-free personal fields: no cross-payload identity worth preserving, so nulling
# is simplest and safest (the rest of enumerator.signature.PERSONAL_FIELDS).
_PERSONAL_NULL_KEYS = ("comment", "description", "desc", "note", "path", "url")
# Location-revealing keys (system.get_timezone_config): an IANA zone name ("Australia/Sydney")
# is city-level location, and the POSIX TZ string ("AEST-10AEDT,...") encodes the same zone by
# its abbreviations. Nulled anywhere — siblings (offsets, booleans) survive, so shape is kept.
_LOCATION_NULL_KEYS = ("zonename", "timezone")
_UNCOVERED_PERSONAL_FIELDS = set(PERSONAL_FIELDS) - (
    set(_SSID_KEYS) | set(_HOST_KEYS) | set(_PERSONAL_NULL_KEYS)
)
if _UNCOVERED_PERSONAL_FIELDS:
    # A real raise, not `assert` (which is stripped under `python -O`): a PERSONAL_FIELDS entry
    # with no sanitizer rule is a silent leak, so importing this module must fail loudly.
    raise RuntimeError(
        "enumerator.signature.PERSONAL_FIELDS grew keys sanitize.py doesn't handle yet: "
        f"{sorted(_UNCOVERED_PERSONAL_FIELDS)}"
    )

# Cellular/SMS surface (Critical fix 3): the highest-risk service in the catalog — real
# subscriber/hardware identifiers and message content, not just network topology.
_CELLULAR_ID_KEYS = ("imei", "iccid", "imsi", "msisdn")
_SMS_CONTENT_KEYS = ("content", "message", "text")
# Substring hints (not boundary-matched — service names are whole catalog keys, not
# underscore-joined) for which services carry cellular/SMS data at all: "modem" (the RPC
# service) and "sms-forward" (SMS-forwarding rules, which carry a forward-to phone number —
# typically in NATIONAL format, no '+', which the E.164 _PHONE value-shape rule can never
# match). Every hinted service gets the full wholesale-null strict mode below.
_CELLULAR_SERVICE_HINTS = ("modem", "sms")
# Fields safe to keep verbatim even under the cellular surface's wholesale-null strict mode:
# structural/enum-like values that describe capability/state or the API's error contract, not
# subscriber, hardware, or location identity. Kept deliberately short — "safer default for the
# highest-risk service" per the security review. NOTE: never add "id"/"code" here — "cell_id" /
# "location_area_code"-class keys would boundary-match them and geolocate the device.
_CELLULAR_STRICT_WHITELIST = (
    "status",
    "type",
    "net_type",
    "network_type",
    "mode",
    "state",
    "band",
    "index",  # list position: structural, not identity
    "err_code",  # the error contract is a fixture's whole value for capability-gated methods
)
# E.164-shaped phone number ('+', no leading 0, 7-15 total digits) — conservative on purpose
# (requires the leading '+') so it doesn't collide with bare numeric IDs/serials elsewhere.
_PHONE = re.compile(r"^\+[1-9]\d{6,14}$")

# host:port / [v6]:port compound strings (Critical fix 2 — WireGuard's end_point format). The
# plain form requires the host part to contain no ':' at all, so a bare IPv6 address (multiple
# colons, no brackets) never matches it; a HH:MM(:SS) time-of-day matches syntactically but its
# host part is all-digits, so _sanitize_host_part below leaves it untouched.
_HOST_PORT_BRACKET = re.compile(r"^\[(?P<host>[^\[\]]+)\]:(?P<port>\d{1,5})$")
_HOST_PORT_PLAIN = re.compile(r"^(?P<host>[^:\s\[\]]+):(?P<port>\d{1,5})$")


def _split_host_port(value: str) -> tuple[str, str, bool] | None:
    """Split ``host:port`` / ``[v6]:port`` into ``(host, port, was_bracketed)``, else ``None``."""
    bracket_match = _HOST_PORT_BRACKET.match(value)
    if bracket_match:
        return bracket_match["host"], bracket_match["port"], True
    plain_match = _HOST_PORT_PLAIN.match(value)
    if plain_match:
        return plain_match["host"], plain_match["port"], False
    return None


def _is_cellular_service(service: str | None) -> bool:
    return service is not None and any(hint in service for hint in _CELLULAR_SERVICE_HINTS)


def _cellular_strict_nulls(key: str | None, service: str | None) -> bool:
    """True when the cellular strict mode nulls this value: a non-whitelisted key under any
    cellular-hint service (``modem``, ``sms-forward``, ...). The short whitelist is the only
    escape — strings and numbers alike default to ``None`` on this surface (cell-tower integers
    like ``lac``/``cid`` geolocate a device as surely as a WAN IP does).
    """
    if not _is_cellular_service(service):
        return False
    return key is None or not _key_matches(key, _CELLULAR_STRICT_WHITELIST)


def _dict_key_forces_null(key: str, service: str | None) -> bool:
    """True if *key*'s entire value must be replaced with ``None``, regardless of its shape."""
    if key_is_secret(key):
        return True
    if _key_matches(key, _PERSONAL_NULL_KEYS):
        return True
    if _key_matches(key, _LOCATION_NULL_KEYS):
        return True
    if _key_matches(key, _CELLULAR_ID_KEYS):
        return True
    if _is_cellular_service(service) and _key_matches(key, _SMS_CONTENT_KEYS):
        return True
    return False


def _key_matches(key: str, tokens: tuple[str, ...]) -> bool:
    """Boundary match like ``key_is_secret``: exact, or on a ``_`` boundary — never a bare
    substring. A trailing plural (``aliases``, ``hostnames``, ``usernames``) also matches its
    singular token, so a list-shaped key isn't missed just because the API pluralizes it.
    """
    low = key.lower()
    candidates = {low}
    if low.endswith("es"):
        candidates.add(low[:-2])
    if low.endswith("s") and not low.endswith("ss"):
        candidates.add(low[:-1])
    return any(
        cand == tok or cand.endswith("_" + tok) or cand.startswith(tok + "_")
        for cand in candidates
        for tok in tokens
    )


def _fake_mac(index: int) -> str:
    """Deterministic fake MAC for the *index*-th (1-based) distinct real MAC seen."""
    page, rem = divmod(index - 1, 256 * 256)
    hi, lo = divmod(rem, 256)
    return f"{_MAC_FAKE_PREFIX}:{page:02x}:{hi:02x}:{lo:02x}"


def _fake_ipv4(index: int) -> str:
    """Deterministic fake IPv4 in an RFC 5737 documentation range for the *index*-th real IP."""
    remaining = index - 1
    for prefix, size in _IPV4_DOC_RANGES:
        if remaining < size:
            return f"{prefix}.{remaining + 1}"
        remaining -= size
    raise ValueError("exhausted RFC 5737 documentation address space for fixture pseudonymization")


def _fake_ipv6(index: int) -> str:
    """Deterministic fake IPv6 in the RFC 3849 documentation range for the *index*-th real IP."""
    return f"2001:db8::{index:x}"


class FixtureSanitizer:
    """Stateful, deterministic sanitizer for one fixture set (one model+firmware capture).

    Consistent pseudonymization *within an instance*: the same real MAC/IP/SSID/hostname always
    maps to the same fake value everywhere it appears, across every method's payload — so
    cross-payload identity (e.g. a client's MAC in both ``clients.get_list`` and
    ``lan.get_static_bind_list``) survives sanitization, which is exactly the property the
    library's golden tests need. Create one instance per fixture set; never reuse across
    devices/captures — that would leak cross-capture correlation into fixtures that are supposed
    to be independent of each other.
    """

    def __init__(self) -> None:
        self._macs: dict[str, str] = {}
        self._ipv4: dict[str, str] = {}
        self._ipv6: dict[str, str] = {}
        self._ssids: dict[str, str] = {}
        self._hosts: dict[str, str] = {}

    def sanitize(self, value: Any, key: str | None = None, service: str | None = None) -> Any:
        """Return a deep-sanitized copy of *value* (a raw JSON-RPC ``result``).

        *service* is the owning catalog service name (e.g. ``"modem"``), when known — it gates
        the cellular/SMS-only rules (SMS body nulling, the cellular wholesale-null strict mode)
        so they never fire outside that surface. Omit it for value-shape rules that apply
        everywhere regardless of context (MAC/IP/host:port/phone/opaque-blob).
        """
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for k, v in value.items():
                new_key = self._mac(k) if _MAC_TEXT.fullmatch(k) else k
                out[new_key] = (
                    None if _dict_key_forces_null(k, service) else self.sanitize(v, k, service)
                )
            return out
        if isinstance(value, list):
            return [self.sanitize(v, key, service) for v in value]
        if isinstance(value, str):
            return self._sanitize_str(value, key, service)
        if isinstance(value, bool):
            return value  # a capability/state bit is never identifying on its own
        if isinstance(value, (int, float)) and _cellular_strict_nulls(key, service):
            # Strict mode covers non-whitelisted NUMBERS too: cell-tower integers (mcc/mnc/
            # lac/cid/pci) resolve to coordinates via public tower databases — a strings-only
            # strict mode would pass them verbatim.
            return None
        return value

    def _sanitize_str(self, value: str, key: str | None, service: str | None) -> str | None:
        # pylint: disable=too-many-return-statements
        if _MULTILINE in value:
            return None  # free-text class: no anchored rule can see inside a blob — null it
        if _MAC_TEXT.fullmatch(value):
            return self._mac(value)
        ip_out = self._sanitize_ip(value)
        if ip_out is not None:
            return ip_out
        host_port_out = self._sanitize_host_port(value)
        if host_port_out is not None:
            return host_port_out
        if _PHONE.match(value):
            return None  # phone-number-shaped: null anywhere, key-agnostic
        if value and _cellular_strict_nulls(key, service):
            # Strict mode takes precedence over the softer tokenize rules below: "cellular
            # strings nulled wholesale unless whitelisted" must mean exactly that (null, not a
            # token) for the highest-risk surface — it must not be softened by a key that also
            # happens to end in e.g. "_name".
            return None
        if key is not None and value:
            if _key_matches(key, _SSID_KEYS):
                return self._token(value, self._ssids, "ssid")
            if _key_matches(key, _HOST_KEYS):
                return self._token(value, self._hosts, "host")
        if len(value) >= 64 and OPAQUE_BLOB.match(value):
            return None  # high-entropy blob backstop, regardless of key name
        # Everything above matched a whole value. What's left is a single-line string that no
        # anchored rule claimed — which is exactly where an embedded MAC/public IP hides.
        return self._scrub_identifiers(value)

    def _scrub_identifiers(self, value: str) -> str:
        """Substitute MACs and public IPs *inside* a free-form string, through the shared maps.

        Order matters: MACs are replaced first, so the ``02:00:00:*`` fakes they leave behind are
        present when the IPv6 pass runs — and are rejected by it (6 hex groups, no ``::``, so
        ``ipaddress`` refuses them), rather than being mangled a second time.
        """
        if ":" not in value and "." not in value:
            return value  # no separator: cannot contain a MAC or an IP
        out = _MAC_TEXT.sub(lambda m: self._mac(m.group()), value)
        out = _IPV4_TEXT.sub(self._scrub_ip_match, out)
        return _IPV6_TEXT.sub(self._scrub_ip_match, out)

    def _scrub_ip_match(self, match: re.Match[str]) -> str:
        """Replace one regex hit if it really is a public IP; leave every other candidate alone."""
        return self._sanitize_ip(match.group()) or match.group()

    def _sanitize_host_port(self, value: str) -> str | None:
        """Sanitize a ``host:port`` / ``[v6]:port`` compound (e.g. WireGuard ``end_point``).

        Returns ``None`` if *value* isn't that shape at all, so the caller falls through to its
        other rules. The IP half is sanitized like any bare IP (public -> doc range, private
        kept); a non-IP host that contains a letter (a real hostname/domain, not a bare number
        like a HH:MM time-of-day) is pseudonymized into the same host-token space as any other
        identity field, so the port survives without the real domain leaking.
        """
        split = _split_host_port(value)
        if split is None:
            return None
        host, port, bracketed = split
        ip_host = self._sanitize_ip(host)
        if ip_host is not None:
            sanitized_host = ip_host
        elif any(c.isalpha() for c in host):
            sanitized_host = self._token(host, self._hosts, "host")
        else:
            return None  # not IP-shaped and not hostname-shaped (e.g. "8:30") -- leave untouched
        return f"[{sanitized_host}]:{port}" if bracketed else f"{sanitized_host}:{port}"

    def _sanitize_ip(self, value: str) -> str | None:
        """Return a sanitized IP string if *value* parses as one, else ``None`` (not an IP)."""
        addr_part, sep, suffix = value.partition("/")
        try:
            addr = ipaddress.ip_address(addr_part)
        except ValueError:
            return None
        # Private (RFC1918/ULA/...), link-local, loopback, multicast, and unspecified addresses
        # are not globally-identifying — they're topology info, the fixture's actual value.
        if addr.is_private or addr.is_multicast or addr.is_unspecified:
            return value
        fake = self._ip(addr)
        return f"{fake}{sep}{suffix}" if sep else fake

    def _mac(self, value: str) -> str:
        # Keyed case-insensitively (and separator-insensitively): a real capture spells the same
        # MAC both ways — upper in ``system.get_info``, lower in the ``clients.get_list`` keys —
        # and one physical device must never become two fake devices, which is precisely the
        # cross-payload identity the shared map exists to preserve.
        real = value.lower().replace("-", ":")
        if real not in self._macs:
            self._macs[real] = _fake_mac(len(self._macs) + 1)
        return self._macs[real]

    def _ip(self, addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        mapping = self._ipv4 if isinstance(addr, ipaddress.IPv4Address) else self._ipv6
        real = str(addr)
        if real not in mapping:
            index = len(mapping) + 1
            fake = (
                _fake_ipv4(index) if isinstance(addr, ipaddress.IPv4Address) else _fake_ipv6(index)
            )
            mapping[real] = fake
        return mapping[real]

    @staticmethod
    def _token(value: str, mapping: dict[str, str], prefix: str) -> str:
        if value not in mapping:
            mapping[value] = f"{prefix}-{len(mapping) + 1}"
        return mapping[value]


def ruleset_hash() -> str:
    """Stable content hash of the active fixture sanitization ruleset.

    Changes automatically whenever a rule's *definition* changes (key sets, MAC/IP formats),
    independent of ``FIXTURE_SANITIZER_VERSION`` (a human-readable bump for changelogs). Fixture
    manifests record both so a consumer can detect drift and ask for a fixture set to be
    regenerated. Does not hash the secret-key token list owned by ``enumerator.redact`` — bump
    ``FIXTURE_SANITIZER_VERSION`` by hand if that list changes.
    """
    payload = json.dumps(
        {
            "version": FIXTURE_SANITIZER_VERSION,
            "ssid_keys": _SSID_KEYS,
            "host_keys": _HOST_KEYS,
            "personal_null_keys": _PERSONAL_NULL_KEYS,
            "location_null_keys": _LOCATION_NULL_KEYS,
            "cellular_id_keys": _CELLULAR_ID_KEYS,
            "sms_content_keys": _SMS_CONTENT_KEYS,
            "cellular_service_hints": _CELLULAR_SERVICE_HINTS,
            "cellular_strict_whitelist": _CELLULAR_STRICT_WHITELIST,
            "mac_fake_prefix": _MAC_FAKE_PREFIX,
            "ipv4_doc_ranges": _IPV4_DOC_RANGES,
            # Policy markers, not key lists: flipping either rule must change the hash even if
            # no key set moved (both are key-agnostic by design — that is the point of them).
            "multiline_strings": "null",
            "identifier_scrub": "mid_string",
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
