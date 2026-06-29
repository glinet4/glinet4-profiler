"""Pure SSH-parser tests (fixtures from live recon)."""
# pylint: disable=missing-function-docstring,redefined-outer-name

from glinet_profiler.enumerator.ssh import (
    merge_surface,
    parse_account_acl,
    parse_fcgi_workers,
    parse_handlers,
    parse_validators,
)

LUA_TOR = """
local M = {}
function M.get_config() end
function M.set_config() end
function M.get_status() end
return M
"""

# `strings` dump from a .so (real method names + internal-helper noise)
SO_WG = "\n".join(
    [
        "get_all_config_list",
        "add_config",
        "set_config",
        "set_proxy",
        "check_string_length",
        "get_peer_key",
        "xyzzy_internal",
    ]
)


def test_parse_handlers_lua_and_so_with_dedup():
    listing = ["tor", "wg-client.so", "wg_client", "flow_statistics"]
    sources = {
        "tor": LUA_TOR,
        "wg-client.so": SO_WG,
        "wg_client": "",
        "flow_statistics": "get_flow_statistics\nset_flow_statistics\n",
    }
    out, untrusted = parse_handlers(listing, sources)
    assert out["tor"] == sorted(["get_config", "set_config", "get_status"])
    # hyphenated .so keeps its hyphenated name; empty underscore shim is dropped
    assert "wg-client" in out
    assert "wg_client" not in out and "wg-client.so" not in out
    assert "get_all_config_list" in out["wg-client"]
    assert "set_config" in out["wg-client"]
    # obvious noise filtered (not a known verb prefix)
    assert "xyzzy_internal" not in out["wg-client"]
    # underscore-named services preserve their wire name (no _ -> - mangling)
    assert "flow_statistics" in out
    assert "flow-statistics" not in out
    assert "get_flow_statistics" in out["flow_statistics"]
    # services parsed from strings (no `function M.x`) are flagged untrusted; real Lua is not
    assert "wg-client" in untrusted
    assert "tor" not in untrusted


def test_parse_validators_reads_compiled_bytecode():
    # compiled validators are Lua bytecode; method names survive as strings, no params
    blob = "LuaQ\x00\x19\x93\rrequire\x00gl.validator\x00set_group\x00group_name\x00add_config\x00name\x00"
    out = parse_validators({"wg-client": blob})
    assert "set_group" in out["wg-client"] and "add_config" in out["wg-client"]
    assert out["wg-client"]["set_group"] == []  # params unrecoverable from bytecode
    assert "group_name" not in out["wg-client"] and "require" not in out["wg-client"]  # params/stdlib excluded


def test_merge_surface_drops_unverified_so_writes():
    handlers = {"wg-client": ["get_status", "set_proxy", "add_config"]}  # from .so strings
    untrusted = {"wg-client"}
    validators = {"wg-client": {"add_config": []}}  # validator confirms add_config only
    merged = merge_surface(handlers, untrusted, validators)
    assert "get_status" in merged["wg-client"]  # read kept (probe will filter if bogus)
    assert "add_config" in merged["wg-client"]  # validator-confirmed write kept
    assert "set_proxy" not in merged["wg-client"]  # unverified .so write dropped as noise


def test_parse_validators_extracts_methods_and_params():
    validators = {
        "tor": 'local M = { ["set_config"] = { "enable", "manual" }, ["get_config"] = {} }\nreturn M',
    }
    out = parse_validators(validators)
    assert "set_config" in out["tor"]
    assert out["tor"]["set_config"] == ["enable", "manual"]
    assert out["tor"]["get_config"] == []


def test_parse_validators_preserves_underscore_service_name():
    validators = {
        "flow_statistics": 'local M = { ["get_statistics_rule"] = { "period" } }\nreturn M',
    }
    out = parse_validators(validators)
    assert "flow_statistics" in out
    assert "flow-statistics" not in out
    assert out["flow_statistics"]["get_statistics_rule"] == ["period"]


def test_parse_fcgi_workers():
    # from `ps w` (running process) and from the init script — both carry `-c N`
    assert parse_fcgi_workers("4325 root /usr/bin/fcgiwrap -c 4 -s unix:/var/run/fcgiwrap.socket") == 4
    assert parse_fcgi_workers("    procd_set_param command $PROG -c 8 -s unix:...") == 8
    assert parse_fcgi_workers("no fcgiwrap here") is None
    assert parse_fcgi_workers("") is None


def test_parse_account_acl_root_full():
    accounts, root_full = parse_account_acl([("root", "root"), ("guest", "limited")])
    assert {"username": "root", "acl": "root"} in accounts
    assert root_full is True
