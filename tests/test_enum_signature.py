"""Tests for the Balanced rich-schema distiller."""
# pylint: disable=missing-function-docstring

from glinet_profiler.enumerator.signature import signature_of


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
