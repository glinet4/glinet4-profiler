"""Tests for the sanitizing projection."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import importlib
import json
import re

import pytest

from glinet4_profiler.sanitize import FixtureSanitizer, project_report, ruleset_hash

RAW = {
    "device": {
        "model": "mt6000",
        "firmware_version": "4.9.0",
        "vendor": "GL.iNet",
        "device_type": "router",
        "hardware_version": "1.0",
        "mac": "94:83:C4:AA:BB:CC",
        "sn": "SECRET123",
        "sn_bak": "SECRET456",
        "country_code": "US",
        "software_feature": {"adguard": True, "vpn": True, "cellular_ref": "1.0"},
        "hardware_feature": {"usb3": "2-1", "simo": False},
    },
    "services": {
        "system": {
            "get_info": {
                "status": "available",
                "error_code": None,
                "risk": "read",
                "discovered_by": "catalog",
                "covered_by": "router_info",
                "params": None,
                "signature": {"model": "mt6000", "mac": "<mac>"},
                "value": {"mac": "94:83:C4:AA:BB:CC", "sn": "SECRET123"},
            },
        },
    },
}


def test_keeps_allowlist_and_method_fields():
    out = project_report(RAW, "mt6000_4.9.0")
    assert out["id"] == "mt6000_4.9.0"
    assert out["model"] == "mt6000" and out["firmware_version"] == "4.9.0"
    assert out["vendor"] == "GL.iNet"
    m = out["services"]["system"]["get_info"]
    assert m["status"] == "available" and m["covered_by"] == "router_info"
    # signature is kept intact (formats + safe examples are the published API shape)
    assert m["signature"] == {"model": "mt6000", "mac": "<mac>"}
    assert "schema" not in m


def test_keeps_non_identifying_capabilities():
    out = project_report(RAW, "mt6000_4.9.0")
    caps = out["capabilities"]
    assert caps["country_code"] == "US"
    assert caps["software_feature"]["vpn"] is True
    assert caps["hardware_feature"]["simo"] is False  # explains why modem.* would error


def test_keep_data_keeps_method_value():
    kept = project_report(RAW, "mt6000_4.9.0", keep_data=True)
    dropped = project_report(RAW, "mt6000_4.9.0")
    assert "value" not in dropped["services"]["system"]["get_info"]  # default still drops it
    # keep_data is a pure projection toggle: it keeps whatever value the enumerator already redacted
    raw_value = RAW["services"]["system"]["get_info"]["value"]
    assert kept["services"]["system"]["get_info"]["value"] == raw_value


def test_drops_identifiers_and_values():
    out = project_report(RAW, "mt6000_4.9.0")
    for k in ("mac", "sn", "sn_bak"):  # identifiers dropped from the top level
        assert k not in out
    assert "capabilities" in out  # ...but the non-identifying capability block is kept
    # method-level response value is dropped
    assert "value" not in out["services"]["system"]["get_info"]
    # no actual identifier VALUE survives (the real MAC / serials)
    blob = json.dumps(out)
    assert "SECRET123" not in blob and "SECRET456" not in blob
    assert not re.search(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", blob)


# ── FixtureSanitizer: raw-response fixtures for the library's golden tests ─────────────────
# Unlike project_report() (which drops every response value), fixtures keep the response
# VALUES — that's the point — so each rule below is exercised with a realistic payload shape
# taken from real GL.iNet RPC responses (clients.get_list is keyed by client MAC; wifi.get_config
# carries ssid/key; system.get_info nests board_info.hostname; wan status carries a public IP).

CLIENTS_RAW = {
    "94:83:C4:AA:BB:01": {
        "mac": "94:83:C4:AA:BB:01",
        "name": "Shaunes-iPhone",
        "ip": "192.168.8.101",
        "online": True,
    },
    "94:83:C4:AA:BB:02": {
        "mac": "94:83:C4:AA:BB:02",
        "name": "",
        "ip": "192.168.8.102",
        "online": False,
    },
}

WIFI_RAW = {
    "2g": {
        "ssid": "The Cclles Household",
        "key": "sup3rSecretPass!",
        "enabled": True,
        "encryption": "psk2",
    },
}

SYSINFO_RAW = {
    "mac": "94:83:C4:AA:BB:CC",
    "sn": "SN0001234",
    "board_info": {"hostname": "GL-MT6000-abcd"},
    "wifi_password": "hunter2",
}

WAN_RAW = {
    "ipv4": {
        "ip": "51.68.44.10/21",
        "gateway": "51.68.44.1",
        "dns": ["8.8.8.8", "8.8.4.4"],
    },
}

# ── Real-shape payloads for the sanitizer-gaps fixes ────────────────────────────────────────
# Field names/shapes below are taken from a real captured GL-MT6000/4.9.0 device report
# (gli4py/docs/devices/mt6000_4.9.0.json, services["wg-server"]["get_peer_list"] and
# services["wg-client"]["get_group_list"]) — the same schema the security review confirmed the
# holes against. The real capture's "end_point" was an empty string (peer never connected); a
# populated value is used here to exercise the host:port rule the review flagged as missing.
WG_SERVER_PEER_LIST_RAW = {
    "peers": [
        {
            "peer_id": 7089,
            "name": "Shauns Pixel 10",
            "end_point": "51.68.44.10:51820",
            "allowed_ips": "0.0.0.0/0",
            "client_ip": "10.0.0.2/24",
            "dns": "10.0.0.1",
            "enabled": True,
            "mtu": 1420,
            "persistent_keepalive": 25,
            "presharedkey_enable": False,
            "private_key": "yAnRealPrivateKeyBase64==",
            "public_key": "yAnRealPublicKeyBase64==",
        },
    ],
}

WG_CLIENT_GROUP_LIST_RAW = {
    "groups": [
        {
            "group_id": 6666,
            "group_name": "AzireVPN",
            "group_type": 1,
            "auth_type": 1,
            "username": "shaun@example.com",
            "password": "hunter2",
            "peer_count": 0,
            "procedure": 0,
            "show": False,
        },
    ],
}

# modem.get_sms_list-class shape: an SMS inbox entry carries a sender phone number and a free-text
# body — the highest-risk surface in the catalog (real subscriber identity + message content).
MODEM_SMS_LIST_RAW = {
    "sms": [
        {
            "index": 1,
            "number": "+15551234567",
            "content": "Your verification code is 482913",
            "date": "24/01/15,10:22:31+32",
            "unread": True,
        },
    ],
}

MODEM_INFO_RAW = {
    "imei": "354864102345678",
    "iccid": "8991101200003204514",
    "imsi": "310150123456789",
    "msisdn": "+15551234567",
    "modem_name": "Quectel EC25",
    "manufacturer": "Quectel",
    "status": "registered",
}

# modem.get_cells_info-class shape: serving/neighbour cell records. The mcc/mnc/lac/cid/pci
# INTEGERS uniquely identify a physical cell tower — public tower databases resolve them to
# coordinates, geolocating the router as surely as a WAN IP does.
MODEM_CELLS_INFO_RAW = {
    "cells": [
        {
            "index": 0,
            "mcc": 505,
            "mnc": 3,
            "lac": 12345,
            "cid": 67890123,
            "pci": 218,
            "arfcn": 9410,
            "rsrp": -95,
            "rsrq": -10.5,
            "net_type": "LTE",
            "band": "B3",
            "registered": True,
        },
    ],
}

# sms-forward.get_rule_list-class shape: a forward-to number is typically entered in NATIONAL
# format (no leading '+'), so the E.164 _PHONE value-shape rule never matches it — only the
# service-scoped strict mode can catch it.
SMS_FORWARD_RULE_LIST_RAW = {
    "rules": [
        {"rule_id": 1, "number": "0412345678", "enable": True},
    ],
}

# system.get_timezone_config — real captured mt6000/4.9.0 shape. An IANA zone name is
# city-level location; the POSIX TZ string encodes the same zone by its abbreviations.
TIMEZONE_CONFIG_RAW = {
    "autotimezone_enabled": True,
    "localtime": 1782522425,
    "timestamp": 1782486425,
    "timezone": "AEST-10AEDT,M10.1.0,M4.1.0/3",
    "tzoffset": "+1000",
    "zonename": "Australia/Sydney",
}


def test_pseudonymizes_macs_consistently_within_a_set():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(CLIENTS_RAW)
    fake_keys = list(clean.keys())
    assert set(fake_keys).isdisjoint({"94:83:C4:AA:BB:01", "94:83:C4:AA:BB:02"})
    assert len(set(fake_keys)) == 2  # two distinct real MACs -> two distinct fake MACs
    # the dict KEY (clients.get_list is keyed by MAC) and the nested "mac" FIELD are the same
    # real MAC, so they must land on the same fake MAC (cross-field identity within one payload)
    for fake_key, rec in clean.items():
        assert rec["mac"] == fake_key


def test_mac_pseudonym_is_stable_across_separate_payloads():
    sanitizer = FixtureSanitizer()
    a = sanitizer.sanitize({"mac": "94:83:C4:AA:BB:01"})
    b = sanitizer.sanitize({"lan_mac": "94:83:C4:AA:BB:01"})
    assert a["mac"] == b["lan_mac"]  # same real MAC, two different methods -> same fake MAC
    c = sanitizer.sanitize({"mac": "94:83:C4:AA:BB:02"})
    assert c["mac"] != a["mac"]


def test_fake_mac_is_locally_administered_and_never_the_real_value():
    sanitizer = FixtureSanitizer()
    fake = sanitizer.sanitize({"mac": "94:83:C4:AA:BB:CC"})["mac"]
    assert re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", fake)
    assert fake != "94:83:C4:AA:BB:CC"
    first_octet = int(fake.split(":")[0], 16)
    assert first_octet & 0b10 == 0b10  # U/L bit set: guaranteed not a real assigned OUI


def test_ssid_tokenized_consistently():
    sanitizer = FixtureSanitizer()
    a = sanitizer.sanitize({"ssid": "The Cclles Household"})
    b = sanitizer.sanitize({"ssid": "The Cclles Household"})  # same SSID again -> same token
    c = sanitizer.sanitize({"ssid": "Guest WiFi"})
    assert a["ssid"] == b["ssid"]
    assert re.match(r"^ssid-\d+$", a["ssid"])
    assert a["ssid"] != c["ssid"]
    assert "Cclles" not in json.dumps(a)


def test_hostname_and_name_fields_share_the_host_token_space():
    sanitizer = FixtureSanitizer()
    board = sanitizer.sanitize({"board_info": {"hostname": "GL-MT6000-abcd"}})
    client = sanitizer.sanitize({"name": "GL-MT6000-abcd"})  # same value, sibling key -> same token
    assert board["board_info"]["hostname"] == client["name"]
    assert re.match(r"^host-\d+$", client["name"])
    assert "GL-MT6000-abcd" not in json.dumps([board, client])


def test_empty_name_is_left_alone_not_tokenized():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"name": ""})
    assert clean == {"name": ""}


def test_secret_keyed_fields_are_nulled_not_stringified():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(
        {
            "sn": "SN0001234",
            "wifi_password": "hunter2",
            "key": "abc",
            "token": "xyz",
            "nonce": "n1",
            "salt": "s1",
        }
    )
    assert clean == {
        "sn": None,
        "wifi_password": None,
        "key": None,
        "token": None,
        "nonce": None,
        "salt": None,
    }


def test_secret_key_nulls_nested_values_too():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"peers": [{"name": "p", "preshared_key": "x"}]})
    assert clean["peers"][0]["name"] != "p"  # "name" is a host-token key, not left verbatim either
    assert clean["peers"][0]["preshared_key"] is None


def test_public_ipv4_replaced_with_documentation_range_consistently():
    sanitizer = FixtureSanitizer()
    a = sanitizer.sanitize({"gateway": "51.68.44.1"})
    b = sanitizer.sanitize({"dns": ["51.68.44.1", "8.8.8.8"]})
    assert a["gateway"] == b["dns"][0]  # same real public IP everywhere -> same fake IP
    assert a["gateway"].startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    assert b["dns"][1] != "8.8.8.8"


def test_ipv4_cidr_suffix_is_preserved():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"ip": "51.68.44.10/21"})
    addr, sep, suffix = clean["ip"].partition("/")
    assert sep == "/" and suffix == "21"
    assert addr != "51.68.44.10"


def test_lan_ipv4_kept_verbatim():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"ip": "192.168.8.101", "gw": "10.0.0.1", "vpn": "172.16.5.5"})
    assert clean == {"ip": "192.168.8.101", "gw": "10.0.0.1", "vpn": "172.16.5.5"}


def test_ipv6_public_replaced_private_kept():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(
        {"wan6": "2606:4700:4700::1111", "lan6": "fc00::1", "ll6": "fe80::1"}
    )
    assert clean["wan6"].startswith("2001:db8:")
    assert clean["wan6"] != "2606:4700:4700::1111"
    assert clean["lan6"] == "fc00::1"
    assert clean["ll6"] == "fe80::1"


@pytest.mark.parametrize("value", [3, True, False, None, "ap", "psk2", 0.5], ids=repr)
def test_scalars_and_enum_strings_pass_through_unchanged(value):
    sanitizer = FixtureSanitizer()
    assert sanitizer.sanitize({"field": value}) == {"field": value}


def test_realistic_multi_method_capture_leaks_nothing_but_keeps_topology():
    sanitizer = FixtureSanitizer()
    clean_clients = sanitizer.sanitize(CLIENTS_RAW)
    clean_wifi = sanitizer.sanitize(WIFI_RAW)
    clean_sysinfo = sanitizer.sanitize(SYSINFO_RAW)
    clean_wan = sanitizer.sanitize(WAN_RAW)
    blob = json.dumps([clean_clients, clean_wifi, clean_sysinfo, clean_wan])
    for secret in (
        "94:83:C4",
        "sup3rSecretPass",
        "hunter2",
        "SN0001234",
        "GL-MT6000-abcd",
        "51.68.44.10",
        "8.8.8.8",
        "Cclles",
    ):
        assert secret not in blob
    # LAN topology and categorical/structural fields are the fixture's actual value — kept
    assert "192.168.8.101" in blob
    assert "psk2" in blob
    assert json.loads(blob)[1]["2g"]["enabled"] is True


def test_sanitize_does_not_mutate_input():
    sanitizer = FixtureSanitizer()
    src = {"ssid": "Home"}
    sanitizer.sanitize(src)
    assert src == {"ssid": "Home"}


def test_ruleset_hash_is_deterministic_and_short():
    first = ruleset_hash()
    second = ruleset_hash()
    assert first == second
    assert re.match(r"^[0-9a-f]{16}$", first)


# ── Critical fix 1: the sanitizer must incorporate enumerator.signature's personal-field
# vocabulary (single source of truth) instead of hand-rolling its own smaller key list ─────────


def test_personal_field_vocabulary_is_fully_covered_by_a_rule():
    # regression guard: every key in enumerator.signature.PERSONAL_FIELDS must be handled by
    # *some* sanitizer rule (tokenize or null) — this fails loudly if a future addition to the
    # shared vocabulary is forgotten here, instead of silently leaking.
    from glinet4_profiler import sanitize as sanitize_module
    from glinet4_profiler.enumerator.signature import PERSONAL_FIELDS

    covered = (
        set(sanitize_module._SSID_KEYS)  # pylint: disable=protected-access
        | set(sanitize_module._HOST_KEYS)  # pylint: disable=protected-access
        | set(sanitize_module._PERSONAL_NULL_KEYS)  # pylint: disable=protected-access
    )
    missing = set(PERSONAL_FIELDS) - covered
    assert not missing, f"PERSONAL_FIELDS entries with no sanitizer rule: {missing}"


def test_alias_field_tokenized_as_host_token():
    sanitizer = FixtureSanitizer()
    a = sanitizer.sanitize({"alias": "Shaunes-Laptop"})
    b = sanitizer.sanitize({"alias": "Shaunes-Laptop"})
    assert a["alias"] == b["alias"]
    assert re.match(r"^host-\d+$", a["alias"])
    assert "Shaunes-Laptop" not in json.dumps(a)


@pytest.mark.parametrize("key", ["username", "user", "label", "peer", "server", "domain", "email"])
def test_new_personal_vocabulary_keys_tokenize_consistently(key):
    sanitizer = FixtureSanitizer()
    a = sanitizer.sanitize({key: "shaun@example.com"})
    b = sanitizer.sanitize({key: "shaun@example.com"})
    assert a[key] == b[key]
    assert re.match(r"^host-\d+$", a[key])
    assert "shaun@example.com" not in json.dumps(a)


@pytest.mark.parametrize("key", ["comment", "description", "desc", "note", "path", "url"])
def test_free_text_personal_vocabulary_keys_are_nulled(key):
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({key: "some free-text value nobody needs pseudonymized"})
    assert clean[key] is None


def test_wg_client_group_list_username_and_password_sanitized():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(WG_CLIENT_GROUP_LIST_RAW)
    group = clean["groups"][0]
    assert group["password"] is None  # secret key -> nulled
    assert group["username"] != "shaun@example.com"
    assert re.match(r"^host-\d+$", group["username"])
    # "group_name" ends on the "_name" boundary -> tokenized too (pre-existing rule, not new
    # here): a VPN group name can be identifying (e.g. "My Home Office"), unlike categorical
    # fields such as "group_type"/"auth_type" (ints, untouched) which stay verbatim.
    assert group["group_name"] != "AzireVPN"
    assert re.match(r"^host-\d+$", group["group_name"])
    assert group["auth_type"] == 1
    blob = json.dumps(clean)
    assert "hunter2" not in blob and "shaun@example.com" not in blob


# ── Critical fix 2: host:port compound strings (WireGuard end_point format) ────────────────


def test_public_ip_port_endpoint_sanitized_ip_kept_port():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"end_point": "51.68.44.10:51820"})
    addr, _, port = clean["end_point"].partition(":")
    assert port == "51820"
    assert addr != "51.68.44.10"
    assert addr.startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_private_ip_port_endpoint_kept_verbatim():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"end_point": "192.168.8.1:51820"})
    assert clean["end_point"] == "192.168.8.1:51820"  # LAN topology info


def test_ipv6_bracket_port_endpoint_sanitized():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"end_point": "[2606:4700:4700::1111]:51820"})
    assert clean["end_point"].startswith("[2001:db8:")
    assert clean["end_point"].endswith("]:51820")
    assert "2606:4700:4700::1111" not in clean["end_point"]


def test_empty_endpoint_left_alone():
    # matches the real captured mt6000 wg-server.get_peer_list value for a never-connected peer
    sanitizer = FixtureSanitizer()
    assert sanitizer.sanitize({"end_point": ""}) == {"end_point": ""}


def test_domain_port_endpoint_tokenizes_host_keeps_port():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"end_point": "myhouse.duckdns.org:51820"})
    host, _, port = clean["end_point"].partition(":")
    assert port == "51820"
    assert host != "myhouse.duckdns.org"
    assert re.match(r"^host-\d+$", host)


def test_time_of_day_shaped_value_is_not_mistaken_for_host_port():
    sanitizer = FixtureSanitizer()
    assert sanitizer.sanitize({"t": "8:30"}) == {"t": "8:30"}


def test_host_port_ip_shares_pseudonym_with_bare_ip_elsewhere():
    sanitizer = FixtureSanitizer()
    bare = sanitizer.sanitize({"gateway": "51.68.44.10"})
    compound = sanitizer.sanitize({"end_point": "51.68.44.10:51820"})
    addr, _, _port = compound["end_point"].partition(":")
    assert addr == bare["gateway"]  # same real public IP -> same fake IP, in or out of a compound


def test_wg_server_peer_list_realistic_capture_leaks_nothing():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(WG_SERVER_PEER_LIST_RAW)
    peer = clean["peers"][0]
    assert peer["private_key"] is None and peer["public_key"] is None
    assert peer["name"] != "Shauns Pixel 10"
    addr, _, port = peer["end_point"].partition(":")
    assert port == "51820" and addr != "51.68.44.10"
    assert peer["client_ip"] == "10.0.0.2/24"  # VPN-internal address: topology, kept
    blob = json.dumps(clean)
    for secret in (
        "Shauns Pixel 10",
        "51.68.44.10",
        "yAnRealPrivateKeyBase64",
        "yAnRealPublicKeyBase64",
    ):
        assert secret not in blob


# ── Critical fix 3: cellular/SMS surface ─────────────────────────────────────────────────────


@pytest.mark.parametrize("key", ["imei", "iccid", "imsi", "msisdn"])
def test_cellular_identifier_keys_nulled_anywhere(key):
    # general, service-agnostic rule: these are sensitive hardware/subscriber identifiers no
    # matter which service happens to carry them.
    sanitizer = FixtureSanitizer()
    assert sanitizer.sanitize({key: "354864102345678"}) == {key: None}


def test_phone_number_shaped_value_nulled_key_agnostic():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"contact": "+15557654321"})
    assert clean["contact"] is None


def test_modem_sms_list_number_and_content_nulled():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(MODEM_SMS_LIST_RAW, service="modem")
    entry = clean["sms"][0]
    assert entry["number"] is None
    assert entry["content"] is None
    assert entry["index"] == 1  # structural field kept
    assert entry["unread"] is True
    blob = json.dumps(clean)
    assert "+15551234567" not in blob
    assert "482913" not in blob


@pytest.mark.parametrize("key", ["content", "message", "text"])
def test_sms_body_keys_nulled_only_under_cellular_service(key):
    sanitizer = FixtureSanitizer()
    modem_scoped = sanitizer.sanitize({key: "hello"}, service="modem")
    unscoped = sanitizer.sanitize({key: "hello"})
    assert modem_scoped[key] is None
    assert unscoped[key] == "hello"  # same key, no cellular service context -> not touched


def test_modem_service_strict_mode_nulls_wholesale_unless_whitelisted():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(MODEM_INFO_RAW, service="modem")
    assert clean["imei"] is None
    assert clean["iccid"] is None
    assert clean["imsi"] is None
    assert clean["msisdn"] is None
    assert clean["modem_name"] is None  # not whitelisted -> nulled even though not "personal"
    assert clean["manufacturer"] is None  # ditto
    assert clean["status"] == "registered"  # whitelisted structural/enum field -> kept


def test_non_modem_service_keeps_unrelated_string_fields():
    # the strict wholesale-null mode is scoped to service == "modem" — it must not leak into
    # every other service's fixtures.
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"manufacturer": "Quectel"}, service="wg-server")
    assert clean["manufacturer"] == "Quectel"


# ── Important fix 4: OPAQUE_BLOB value-level backstop (key-name-agnostic) ──────────────────


def test_opaque_blob_backstop_nulls_high_entropy_value_under_any_key():
    sanitizer = FixtureSanitizer()
    blob = "A1b2" * 20  # 80 chars, base64-ish — same shape enumerator.redact treats as opaque
    clean = sanitizer.sanitize({"config_blob": blob})
    assert clean["config_blob"] is None


def test_short_string_under_generic_key_is_not_touched_by_opaque_backstop():
    sanitizer = FixtureSanitizer()
    assert sanitizer.sanitize({"config_blob": "short"}) == {"config_blob": "short"}


# ── Important fix 5: plural/variant key names match the singular token ─────────────────────


@pytest.mark.parametrize(
    ("key", "expected_prefix"),
    [("aliases", "host"), ("hostnames", "host"), ("usernames", "host"), ("ssids", "ssid")],
)
def test_plural_key_names_match_singular_token(key, expected_prefix):
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({key: "some-value"})
    assert re.match(rf"^{expected_prefix}-\d+$", clean[key])


def test_plural_of_address_is_not_mangled_by_the_s_stripper():
    # "address" already ends in "ss" — the plural stripper must not turn it into "addres"
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"address": "some-value"})
    assert re.match(r"^host-\d+$", clean["address"])


# ── Round 2, Important fix 2: cellular strict mode nulls non-whitelisted SCALARS too ────────
# Cell-tower integers (mcc/mnc/lac/cid/pci) pass a strings-only strict mode verbatim and
# geolocate the device via public tower databases.


def test_modem_cell_tower_integers_nulled_under_strict_mode():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"lac": 12345, "cid": 67890123}, service="modem")
    assert clean == {"lac": None, "cid": None}


def test_modem_cells_info_realistic_capture_nulls_geolocating_scalars():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(MODEM_CELLS_INFO_RAW, service="modem")
    cell = clean["cells"][0]
    for key in ("mcc", "mnc", "lac", "cid", "pci", "arfcn", "rsrp", "rsrq"):
        assert cell[key] is None, key
    assert cell["index"] == 0  # structural whitelist covers ints too
    assert cell["net_type"] == "LTE" and cell["band"] == "B3"  # enum-ish whitelist still works
    assert cell["registered"] is True  # bools are capability/state bits, kept
    blob = json.dumps(clean)
    assert "67890123" not in blob and "12345" not in blob


def test_float_scalar_nulled_under_cellular_strict_mode():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"longitude": 151.2094}, service="modem")
    assert clean["longitude"] is None


def test_modem_error_shape_keeps_err_code():
    # real captured shape (modem.get_sms_list on a modem-less mt6000): the error contract IS
    # the fixture's value — err_code must survive strict mode; err_msg (free text) must not.
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(
        {"err_code": 20002001, "err_msg": "Parameter not found"}, service="modem"
    )
    assert clean == {"err_code": 20002001, "err_msg": None}


def test_non_cellular_service_keeps_numeric_fields():
    # the scalar-null strict mode is scoped to cellular services — a numeric field under any
    # other service (uptime, counters, ids) is the fixture's actual value.
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"lac": 12345, "uptime": 99.5}, service="wan")
    assert clean == {"lac": 12345, "uptime": 99.5}


# ── Round 2, Important fix 3: strict mode covers every cellular-hint service, not just
# service == "modem" — sms-forward carries national-format phone numbers _PHONE can't match ──


def test_sms_forward_national_format_number_nulled():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(SMS_FORWARD_RULE_LIST_RAW, service="sms-forward")
    rule = clean["rules"][0]
    assert rule["number"] is None  # national format, no '+': only strict mode catches it
    assert rule["rule_id"] is None  # non-whitelisted scalar on the cellular surface: safer null
    assert rule["enable"] is True
    assert "0412345678" not in json.dumps(clean)


def test_sms_forward_config_strings_strict_nulled():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(
        {"forward_number": "0412345678", "enable": True, "mode": "all"}, service="sms-forward"
    )
    assert clean["forward_number"] is None
    assert clean["enable"] is True
    assert clean["mode"] == "all"  # enum-ish whitelist applies across the whole cellular surface


# ── Round 2, Important fix 4: zonename/timezone leak city-level location ────────────────────


def test_timezone_and_zonename_nulled_shape_survives():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(TIMEZONE_CONFIG_RAW)
    assert clean["zonename"] is None  # "Australia/Sydney" is city-level location
    assert clean["timezone"] is None  # the POSIX TZ string encodes the same zone
    assert clean["autotimezone_enabled"] is True  # shape survives: siblings untouched
    assert clean["localtime"] == 1782522425  # scalar outside cellular strict mode: kept
    blob = json.dumps(clean)
    assert "Australia" not in blob and "AEST" not in blob


# ── Round 2, Minor: bare-domain end_point (no ":port") + endpoint underscore variant ────────


def test_bare_domain_end_point_without_port_tokenized():
    # a real end_point can be a bare DDNS domain with no ":port" — the host:port compound rule
    # never fires, so the key itself must be in the host-token set (underscore variant included).
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"end_point": "myhouse.duckdns.org"})
    assert re.match(r"^host-\d+$", clean["end_point"])
    assert "duckdns" not in json.dumps(clean)


def test_endpoint_key_tokenizes_instead_of_nulling():
    # "endpoint" moved from the null set to the host-token set: a bare-domain endpoint keeps
    # cross-payload identity like every other host field, and both spellings share one token.
    sanitizer = FixtureSanitizer()
    a = sanitizer.sanitize({"endpoint": "vpn.example.com"})
    b = sanitizer.sanitize({"end_point": "vpn.example.com"})
    assert re.match(r"^host-\d+$", a["endpoint"])
    assert a["endpoint"] == b["end_point"]


def test_end_point_with_port_still_keeps_port():
    # the compound rule still wins for host:port shapes — the port must survive tokenization
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"endpoint": "myhouse.duckdns.org:51820"})
    host, _, port = clean["endpoint"].partition(":")
    assert port == "51820"
    assert re.match(r"^host-\d+$", host)


# ── Round 2, Minor: the PERSONAL_FIELDS completeness guard must be a real raise, not an
# `assert` (stripped under python -O) ────────────────────────────────────────────────────────


# ── Round 3: the free-text CLASS — anchored (full-value) rules pass free text through ───────
# The previous two rounds patched INSTANCES (logread); a third review proved the same class
# leaks on device configurations nobody has captured yet: a populated OpenVPN client config
# (inline PEM + provider hostname), a parental-control blocklist, a custom hosts file. The
# general rule: any string containing a newline is nulled, anywhere.

# dns.get_host — real captured shape ({"content": "<hosts-file text>"}). On the tested device
# this is localhost boilerplate; a user who added their own entries gets IP+hostname pairs that
# every anchored rule passes verbatim (the leak is MID-LINE, exactly like logread's).
DNS_HOST_CUSTOM_RAW = {
    "content": (
        "127.0.0.1 localhost\n"
        "192.168.8.42 nas.smith-family.lan\n"
        "192.168.8.43 hass.smith-family.lan\n"
    )
}

# ovpn-client.get_config-class shape: an OpenVPN client config is uploaded whole and handed
# back as one inline blob — the provider's real hostname plus inline PEM material.
OVPN_CLIENT_CONFIG_RAW = {
    "group_id": 3,
    "ovpn_file": (
        "client\n"
        "dev tun\n"
        "remote vpn-provider.example.net 1194 udp\n"
        "<ca>\n"
        "-----BEGIN CERTIFICATE-----\n"
        "MIIB0jCCAXigAwIBAgIJAKm3S5Ry8pEyMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT\n"
        "-----END CERTIFICATE-----\n"
        "</ca>\n"
        "<key>\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2Zk9zRealKeyBytes\n"
        "-----END PRIVATE KEY-----\n"
        "</key>\n"
    ),
    "enabled": True,
}

# parental-control / black_white_list-class shape: blocked domains entered as a free-text
# block. The domains are a household's browsing policy — and no anchored rule sees them.
BLOCKLIST_CONFIG_RAW = {
    "mode": 1,
    "enable": True,
    "domain_list": "casino-example.com\nsmith-family-intranet.lan\nsome-dating-site.example\n",
}

# wg-server.get_config.amnezia — real captured shape: a machine-generated AmneziaWG tuning
# block (Jc/Jmin/Jmax/S1/S2/H1..H4 numeric params), 11 lines. Nulled by the general rule; the
# library never reads it (grep: zero references in gli4py), so nulling costs golden tests
# nothing and the key itself survives, preserving the response shape.
WG_SERVER_CONFIG_RAW = {
    "enable": True,
    "port": 51820,
    "amnezia": "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 62\nH1 = 1234567890\nH2 = 987654321\n",
}


def test_multiline_string_is_nulled_under_any_key():
    # the general rule: a newline means free text, and free text defeats every anchored rule
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"whatever": "line one\nline two"})
    assert clean == {"whatever": None}


def test_single_line_values_are_untouched_by_the_multiline_rule():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"mode": "psk2", "banner": "one line only", "n": 7})
    assert clean == {"mode": "psk2", "banner": "one line only", "n": 7}


def test_custom_hosts_file_content_nulled():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(DNS_HOST_CUSTOM_RAW, service="dns")
    assert clean == {"content": None}
    blob = json.dumps(clean)
    assert "smith-family" not in blob and "192.168.8.42" not in blob


def test_inline_ovpn_config_with_pem_nulled_shape_survives():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(OVPN_CLIENT_CONFIG_RAW, service="ovpn-client")
    assert clean["ovpn_file"] is None
    assert clean["group_id"] == 3 and clean["enabled"] is True  # shape survives
    blob = json.dumps(clean)
    for secret in ("vpn-provider.example.net", "BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "MIIB"):
        assert secret not in blob


def test_blocklist_free_text_domains_nulled():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(BLOCKLIST_CONFIG_RAW, service="parental-control")
    assert clean["domain_list"] is None
    assert clean["mode"] == 1 and clean["enable"] is True
    assert "casino-example.com" not in json.dumps(clean)


def test_amnezia_tuning_block_nulled_key_survives():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize(WG_SERVER_CONFIG_RAW, service="wg-server")
    assert "amnezia" in clean and clean["amnezia"] is None  # key kept: response shape intact
    assert clean["port"] == 51820


def test_multiline_rule_covers_log_blobs_even_without_the_service_exclusion():
    # belt-and-braces: fixtures.py still excludes logread outright, but a log blob reaching the
    # sanitizer by any other route (a "log" field on a non-log service, diag output, AT dumps)
    # is nulled by the general rule rather than passing verbatim.
    sanitizer = FixtureSanitizer()
    log = (
        "[   12.345678] ra0: STA 94:83:c4:aa:bb:01 IEEE 802.11: associated\n"
        "[   99.000001] dnsmasq-dhcp: DHCPACK(br-lan) 192.168.8.101 Shaunes-iPhone\n"
    )
    clean = sanitizer.sanitize({"log": log}, service="ovpn-server")
    assert clean == {"log": None}
    assert "94:83:c4" not in json.dumps(clean)


# ── Round 3, Fix 2: identifiers are scrubbed MID-STRING (parity with enumerator.redact) ─────
# redact._MAC_VALUE is deliberately unanchored ("device identifier; scrub anywhere") and
# substitutes mid-string; FixtureSanitizer's full-value match was a regression against it.


def test_mid_string_mac_and_public_ip_are_scrubbed():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"info": "client 94:83:c4:11:22:33 joined from 8.8.8.8"})
    assert "94:83:c4:11:22:33" not in clean["info"]
    assert "8.8.8.8" not in clean["info"]
    assert "02:00:00:" in clean["info"]  # pseudonymized, not blanked: the shape stays readable
    assert re.search(r"(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)\d+", clean["info"])
    assert clean["info"].startswith("client ") and "joined from" in clean["info"]


def test_mid_string_mac_shares_the_pseudonym_of_the_standalone_mac():
    sanitizer = FixtureSanitizer()
    standalone = sanitizer.sanitize({"mac": "94:83:c4:11:22:33"})
    mid = sanitizer.sanitize({"info": "client 94:83:c4:11:22:33 joined"})
    assert standalone["mac"] in mid["info"]  # SAME fake MAC: one shared pseudonym map


def test_mid_string_public_ip_shares_the_pseudonym_of_the_standalone_ip():
    sanitizer = FixtureSanitizer()
    standalone = sanitizer.sanitize({"gateway": "51.68.44.10"})
    mid = sanitizer.sanitize({"info": "route via 51.68.44.10 dev wan"})
    assert standalone["gateway"] in mid["info"]


def test_mac_pseudonym_is_case_insensitive():
    # a real capture spells the same MAC both ways (upper in system.get_info, lower in the
    # clients dict); two spellings of ONE physical device must not become two fake devices.
    sanitizer = FixtureSanitizer()
    upper = sanitizer.sanitize({"mac": "94:83:C4:AA:BB:01"})
    lower = sanitizer.sanitize({"mac": "94:83:c4:aa:bb:01"})
    assert upper["mac"] == lower["mac"]


def test_mid_string_private_ip_and_lan_topology_kept():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"info": "lease 192.168.8.101 from 192.168.8.1"})
    assert clean["info"] == "lease 192.168.8.101 from 192.168.8.1"


def test_mid_string_public_ipv6_scrubbed_fake_mac_not_mistaken_for_one():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"info": "peer 94:83:c4:11:22:33 via 2606:4700:4700::1111"})
    assert "2606:4700:4700::1111" not in clean["info"]
    assert "2001:db8:" in clean["info"]
    assert "02:00:00:" in clean["info"]  # the substituted fake MAC survives the IPv6 pass intact


def test_version_and_time_strings_are_not_mangled_by_the_mid_string_scrub():
    sanitizer = FixtureSanitizer()
    clean = sanitizer.sanitize({"fw": "GL-MT6000 v4.9.0", "at": "10:22:31", "t": "8:30"})
    assert clean == {"fw": "GL-MT6000 v4.9.0", "at": "10:22:31", "t": "8:30"}


def test_personal_field_guard_raises_on_uncovered_key():
    from glinet4_profiler import sanitize as sanitize_module
    from glinet4_profiler.enumerator import signature

    original = signature.PERSONAL_FIELDS
    try:
        signature.PERSONAL_FIELDS = (*original, "shoe_size")
        with pytest.raises(RuntimeError, match="shoe_size"):
            importlib.reload(sanitize_module)
    finally:
        signature.PERSONAL_FIELDS = original
        importlib.reload(sanitize_module)


def test_sanitize_module_has_no_module_level_assert():
    # the completeness guard must survive `python -O`: no bare `assert` at module scope
    import ast
    import inspect

    from glinet4_profiler import sanitize as sanitize_module

    tree = ast.parse(inspect.getsource(sanitize_module))
    module_level_asserts = [n for n in tree.body if isinstance(n, ast.Assert)]
    assert not module_level_asserts
