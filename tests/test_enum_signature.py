"""Tests for the Balanced rich-schema distiller."""
# pylint: disable=missing-function-docstring

from glinet4_profiler.enumerator.signature import PERSONAL_FIELDS, signature_of


def test_keeps_numbers_bools_null():
    src = {"period_seconds": 86400, "enable": False, "x": None}
    assert signature_of(src) == {"period_seconds": 86400, "enable": False, "x": None}


def test_keeps_enum_like_strings():
    src = {"band": "5g", "mode": "ap", "state": "connected", "ver": "1.2.3"}
    assert signature_of(src) == src  # short, no-space tokens are the API contract


def test_labels_identifiers():
    src = {"mac": "94:83:C4:AA:BB:CC", "ip": "192.168.8.1", "created": "2026-06-29T10:00:00"}
    assert signature_of(src) == {"mac": "<mac>", "ip": "<ipv4>", "created": "<datetime>"}


def test_labels_secret_and_personal_and_freetext():
    src = {"password": "hunter2", "ssid": "MyWifi", "blurb": "hello there world"}
    assert signature_of(src) == {"password": "<secret>", "ssid": "<string>", "blurb": "<string>"}


def test_personal_key_beats_enum():
    # "Router-AP" looks enum-like but sits under a personal key -> labeled
    assert signature_of({"name": "Router-AP"}) == {"name": "<string>"}


def test_nested_dict_and_list():
    src = {"clients": [{"mac": "94:83:C4:AA:BB:CC", "band": "5g", "name": "Phone"}]}
    assert signature_of(src) == {"clients": [{"mac": "<mac>", "band": "5g", "name": "<string>"}]}


def test_empty_list_and_top_level_scalar():
    assert signature_of({"items": []}) == {"items": []}
    assert signature_of("5g") == "5g"
    assert signature_of(42) == 42


def test_personal_or_secret_key_holding_a_list_is_labeled():
    # regression: the list branch must propagate the key, or a personal-keyed list of strings
    # (e.g. DDNS hostnames) would be published verbatim — a real PII leak.
    assert signature_of({"domain": ["host.example.com"]}) == {"domain": ["<string>"]}
    assert signature_of({"ssid": ["MyHomeWifi"]}) == {"ssid": ["<string>"]}
    assert signature_of({"psk": ["s3cr3t"]}) == {"psk": ["<secret>"]}


def test_labels_ddns_and_unix_ts_and_ip_port():
    assert signature_of({"ddns": "rh370e3"}) == {"ddns": "<string>"}  # DDNS subdomain is a locator
    assert signature_of({"updated": "1780618374"}) == {"updated": "<datetime>"}  # unix ts string
    # ip:port must not survive as an "enum" just because the colon used to be allowed
    assert signature_of({"upstream": "192.168.8.1:8080"}) == {"upstream": "<string>"}


def test_time_of_day_is_datetime_not_ipv6():
    # a HH:MM(:SS) schedule time was being mislabeled <ipv6> (harmless but wrong)
    assert signature_of({"reboot_at": "08:30:00"}) == {"reboot_at": "<datetime>"}
    assert signature_of({"t": "8:30"}) == {"t": "<datetime>"}
    # a genuine IPv6 (hex / ::) is still labeled correctly
    assert signature_of({"v6": "fe80::1"}) == {"v6": "<ipv6>"}


def test_personal_fields_is_publicly_exported_for_reuse():
    # sanitize.FixtureSanitizer imports this tuple rather than copying it — single source of
    # truth for "which keys are personal/free-text" across the enumerator and the fixture
    # sanitizer (see docs/superpowers/sdd/task-1-report.md "Fix: sanitizer gaps").
    assert "ssid" in PERSONAL_FIELDS
    assert "endpoint" in PERSONAL_FIELDS
    assert "peer" in PERSONAL_FIELDS
    assert "addr" in PERSONAL_FIELDS
