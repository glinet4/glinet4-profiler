"""Tests for the stock-OpenWrt /ubus probe (schema + UCI config-state)."""
# pylint: disable=missing-function-docstring,redefined-outer-name,protected-access,unused-argument

import json

import pytest

from glinet4_profiler import ubus
from glinet4_profiler.sanitize import sanitize_ubus


class _FakeResp:
    """Serves a queued payload as text. A dict is JSON-encoded; a str is returned raw (to
    simulate the router's malformed bodies); an Exception is raised (to simulate a dead port).
    """

    def __init__(self, payload):
        self._payload = payload
        self.headers = {"Content-Type": "application/json"}

    async def __aenter__(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self

    async def __aexit__(self, *_a):
        return False

    async def text(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload if isinstance(self._payload, str) else json.dumps(self._payload)


class _FakeSession:
    """Queued-response aiohttp stand-in. `post` pops the next response (or exception)."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.posted = []
        self.closed = False

    def post(self, url, json=None, timeout=None, ssl=None):  # noqa: A002, ARG002
        self.posted.append((url, json))
        nxt = self._responses.pop(0)
        return _FakeResp(nxt)

    async def close(self):
        self.closed = True


def _ok(result):
    return {"jsonrpc": "2.0", "id": 1, "result": result}


# ── list_schema ────────────────────────────────────────────────────────────────


async def test_list_schema_returns_object_map():
    schema = {"system": {"board": {}}, "cellular.cm": {"cm_start_dial": {"bus": "string"}}}
    sess = _FakeSession([_ok(schema)])
    out = await ubus.list_schema(sess, "http://r/ubus")
    assert out == schema


async def test_list_schema_rejects_non_object_result():
    sess = _FakeSession([_ok([0, {}])])  # a call-shaped result, not a schema map
    with pytest.raises(ubus.UbusUnavailable):
        await ubus.list_schema(sess, "http://r/ubus")


def test_repair_ubus_json_drops_stray_unknown_token():
    # The MT6000's `ubus list *` emits a bare `"unknown"` for unknown-type args, producing
    # invalid JSON (a value where a key:value pair belongs). The repair drops it, no valid key lost.
    bad = '{"result":{"cellular.cm":{"cm_get_status":{"bus":"string","unknown","slot":"number"}}}}'
    fixed = ubus._repair_ubus_json(bad)
    obj = json.loads(fixed)
    assert obj["result"]["cellular.cm"]["cm_get_status"] == {"bus": "string", "slot": "number"}


def test_repair_ubus_json_keeps_legitimate_unknown_values():
    # A properly-KEYED "unknown" (a real arg whose type is literally "unknown") must survive.
    good = '{"result":{"o":{"m":{"arg":"unknown"}}}}'
    assert json.loads(ubus._repair_ubus_json(good))["result"]["o"]["m"] == {"arg": "unknown"}


async def test_list_schema_tolerates_router_malformed_unknown():
    body = '{"jsonrpc":"2.0","id":1,"result":{"sys":{"board":{"x":"string","unknown"}}}}'
    sess = _FakeSession([body])
    out = await ubus.list_schema(sess, "http://r/ubus")
    assert out == {"sys": {"board": {"x": "string"}}}


# ── discover ───────────────────────────────────────────────────────────────────


async def test_discover_returns_url_and_schema_from_one_probe():
    schema = {"system": {"board": {}}}
    sess = _FakeSession([_ok(schema)])
    url, got = await ubus.discover(sess, "192.168.1.1")
    assert url == "http://192.168.1.1:8080/ubus"
    assert got == schema  # the probe's schema is returned, not re-fetched


async def test_discover_falls_through_to_https():
    # 8080 errors (connection refused), 8443 answers
    sess = _FakeSession([ConnectionError("refused"), _ok({"system": {}})])
    url, _schema = await ubus.discover(sess, "192.168.1.1")
    assert url == "https://192.168.1.1:8443/ubus"


async def test_discover_returns_none_when_all_fail():
    sess = _FakeSession([ConnectionError("x"), ConnectionError("y")])
    assert await ubus.discover(sess, "192.168.1.1") is None


# ── login ──────────────────────────────────────────────────────────────────────


async def test_login_returns_session_id():
    sess = _FakeSession([_ok([0, {"ubus_rpc_session": "deadbeef", "acls": {}}])])
    sid = await ubus.login(sess, "http://r/ubus", "root", "pw")
    assert sid == "deadbeef"


async def test_login_raises_on_denied():
    # rpcd returns a JSON-RPC error object on bad credentials
    sess = _FakeSession([{"jsonrpc": "2.0", "id": 1, "error": {"code": -32002}}])
    with pytest.raises(ubus.UbusUnavailable):
        await ubus.login(sess, "http://r/ubus", "root", "bad")


# ── uci_get ────────────────────────────────────────────────────────────────────


async def test_uci_get_returns_values():
    values = {"wifi2g": {".type": "wifi-iface", "ssid": "Home", "key": "hunter2"}}
    sess = _FakeSession([_ok([0, {"values": values}])])
    out = await ubus.uci_get(sess, "http://r/ubus", "sid", "wireless")
    assert out == values


async def test_uci_get_returns_none_on_access_denied():
    sess = _FakeSession([_ok([6])])  # ubus rc 6 = permission denied
    assert await ubus.uci_get(sess, "http://r/ubus", "sid", "wireless") is None


# ── capture_ubus orchestration ───────────────────────────────────────────────────


async def test_capture_ubus_assembles_schema_and_uci():
    schema = {"system": {"board": {}}}
    sess = _FakeSession(
        [
            _ok(schema),  # discover -> list *
            _ok([0, {"ubus_rpc_session": "s1"}]),  # login
            _ok([0, {"values": {"a": {"ssid": "Home"}}}]),  # uci get network
            _ok([0, {"values": {"b": {"key": "sekret"}}}]),  # uci get wireless
        ]
    )
    out = await ubus.capture_ubus(
        "192.168.1.1", "root", "pw", configs=("network", "wireless"), session=sess
    )
    assert out["endpoint"] == "http:8080"
    assert out["schema"] == schema
    assert out["uci"]["network"] == {"a": {"ssid": "Home"}}
    assert out["uci"]["wireless"] == {"b": {"key": "sekret"}}


async def test_capture_ubus_returns_none_when_unreachable():
    sess = _FakeSession([ConnectionError("x"), ConnectionError("y")])
    out = await ubus.capture_ubus("192.168.1.1", "root", "pw", session=sess)
    assert out is None


async def test_capture_ubus_survives_missing_config():
    # login ok, first config denied (rc6), second returns data
    sess = _FakeSession(
        [
            _ok({"system": {}}),
            _ok([0, {"ubus_rpc_session": "s1"}]),
            _ok([6]),
            _ok([0, {"values": {"b": {}}}]),
        ]
    )
    out = await ubus.capture_ubus(
        "192.168.1.1", "root", "pw", configs=("network", "wireless"), session=sess
    )
    assert "network" not in out["uci"]
    assert out["uci"]["wireless"] == {"b": {}}


# ── sanitize_ubus ────────────────────────────────────────────────────────────────


def test_sanitize_ubus_keeps_schema_verbatim():
    raw = {"endpoint": "http:8080", "schema": {"system": {"board": {}}}, "uci": {}}
    out = sanitize_ubus(raw)
    assert out["schema"] == {"system": {"board": {}}}
    assert out["endpoint"] == "http:8080"


def test_sanitize_ubus_nulls_wifi_psk():
    raw = {
        "endpoint": "http:8080",
        "schema": {},
        "uci": {
            "wireless": {"wifi2g": {".type": "wifi-iface", "ssid": "MyHome", "key": "hunter2pw"}}
        },
    }
    out = sanitize_ubus(raw)
    iface = out["uci"]["wireless"]["wifi2g"]
    assert iface["key"] is None  # PSK nulled (key_is_secret)
    assert iface["ssid"] != "MyHome"  # SSID pseudonymized, not verbatim
    assert iface[".type"] == "wifi-iface"  # structural field kept


def test_sanitize_ubus_pseudonymizes_identifiers_consistently():
    raw = {
        "endpoint": "http:8080",
        "schema": {},
        "uci": {
            "network": {
                "lan": {"macaddr": "aa:bb:cc:dd:ee:ff", "ipaddr": "8.8.8.8"},
                "wan": {"macaddr": "aa:bb:cc:dd:ee:ff"},
            }
        },
    }
    out = sanitize_ubus(raw)
    lan = out["uci"]["network"]["lan"]
    wan = out["uci"]["network"]["wan"]
    assert lan["macaddr"] != "aa:bb:cc:dd:ee:ff"
    assert lan["macaddr"] == wan["macaddr"]  # same real MAC -> same fake, within the block
    assert lan["ipaddr"] not in ("8.8.8.8",)  # public IP pseudonymized
