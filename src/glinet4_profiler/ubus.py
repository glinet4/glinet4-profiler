"""Stock-OpenWrt ubus-over-HTTP probe (port 8080/8443) — schema + UCI config-state.

This is the standard OpenWrt ``rpcd`` + ``uhttpd-mod-ubus`` endpoint, **not** GL.iNet's
``/rpc``. It is gated by rpcd ACLs that only cover stock LuCI groups, so it reaches *none*
of GL.iNet's proprietary objects (cellular/SMS/DPI/clients/repeater) — it is **not** a
capability transport, and nothing here should be mistaken for one. See
``GLINET4-TRANSPORTS.md`` for the reconnaissance behind that conclusion.

Its only value to the profiler is read-only enrichment:

* ``list *`` — the **authoritative ubus schema** (object + method + arg-type signatures),
  returned unauthenticated. Value-free (names and type strings only), so it is kept verbatim.
* ``uci get`` — a **config-state** dump (network/wireless/firewall/dhcp/glconfig), reachable
  because the root rpcd session carries ``allow-full-uci-access``. This carries real values
  (PSKs, SSIDs, MACs, IPs), so the caller MUST run the ``uci`` block through
  :func:`glinet4_profiler.sanitize.sanitize_ubus` before persisting or publishing it.

Everything here is read-only. ``uci get`` never writes; no other method is called.
"""

import contextlib
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp

# http first (the common case); https as a fallback for units that only expose the TLS port.
_UBUS_ENDPOINTS: tuple[tuple[str, int], ...] = (("http", 8080), ("https", 8443))
# The stock configs worth capturing. `glconfig` is GL.iNet's own UCI namespace (device/UI
# settings); the rest are stock OpenWrt. All read-only via `uci get`.
DEFAULT_UCI_CONFIGS: tuple[str, ...] = ("network", "wireless", "firewall", "dhcp", "glconfig")
_NULL_SESSION = "0" * 32  # rpcd's anonymous session id, used to call `session login`
_TIMEOUT = 6.0  # seconds; a LAN ubus call is sub-second — a slow one means the port isn't really it

ProgressFn = Callable[[dict[str, Any]], Awaitable[None]]


class UbusUnavailable(Exception):
    """The /ubus endpoint didn't answer as a working ubus JSON-RPC server."""


def _payload(method: str, params: list[Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}


# The MT6000's ubus serializer emits a bare ``"unknown"`` (no key) for arguments whose blobmsg
# type it can't name — e.g. ``{"bus":"string","unknown","slot":"number"}`` — which is invalid
# JSON, so ``json.loads`` on a ``list *`` body throws. A real key is *always* followed by ``:``;
# this stray token sits in key position (after ``{`` or ``,``) followed by ``,`` or ``}``, so it
# is unambiguous to drop without touching any legitimately-keyed ``"...":"unknown"`` value.
_STRAY_UNKNOWN = re.compile(r'([{,])"unknown"(?=[,}])')


def _repair_ubus_json(text: str) -> str:
    """Drop the router's stray bare ``"unknown"`` arg tokens, yielding parseable JSON."""
    fixed = _STRAY_UNKNOWN.sub(r"\1", text)
    # dropping a leading/trailing stray can leave `{,` / `,}` / `,,` — normalize those.
    fixed = fixed.replace("{,", "{").replace(",}", "}")
    while ",," in fixed:
        fixed = fixed.replace(",,", ",")
    return fixed


def _loads_lenient(text: str) -> dict[str, Any]:
    """Parse a ubus JSON body, repairing the firmware's stray-``"unknown"`` malformation first."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = json.loads(_repair_ubus_json(text))
    if not isinstance(data, dict):
        raise UbusUnavailable("ubus response was not a JSON object")
    return data


async def _post(
    session: aiohttp.ClientSession, url: str, payload: dict[str, Any]
) -> dict[str, Any]:
    async with session.post(
        url, json=payload, timeout=aiohttp.ClientTimeout(total=_TIMEOUT), ssl=False
    ) as resp:
        return _loads_lenient(await resp.text())


async def list_schema(session: aiohttp.ClientSession, url: str) -> dict[str, Any]:
    """Return the unauthenticated ``list *`` schema: ``{object: {method: {arg: type}}}``.

    Raises :class:`UbusUnavailable` if the endpoint doesn't answer with a schema map (a
    non-ubus server, or a redirect/error page).
    """
    data = await _post(session, url, _payload("list", ["*"]))
    result = data.get("result")
    if not isinstance(result, dict):
        raise UbusUnavailable(f"{url}: not a ubus list response")
    return result


async def discover(session: aiohttp.ClientSession, host: str) -> tuple[str, dict[str, Any]] | None:
    """Probe *host* for a working ``/ubus`` (http:8080, then https:8443).

    Returns ``(url, schema)`` from the single ``list *`` probe that succeeded — the schema is
    carried back so the caller needn't fetch it again — or None if neither port answers.
    """
    for scheme, port in _UBUS_ENDPOINTS:
        url = f"{scheme}://{host}:{port}/ubus"
        try:
            schema = await list_schema(session, url)
            return url, schema
        except Exception:  # pylint: disable=broad-except  # any failure = "not here, try next"
            continue
    return None


async def login(session: aiohttp.ClientSession, url: str, username: str, password: str) -> str:
    """Run the stock rpcd ``session login`` and return the ``ubus_rpc_session`` token.

    This is rpcd's own auth (separate from GL.iNet's ``gl-session``); the password is the same
    admin/root password the ``/rpc`` login already uses. Raises :class:`UbusUnavailable` on any
    non-success (wrong password → a JSON-RPC error object; rpcd absent → no session id).
    """
    data = await _post(
        session,
        url,
        _payload(
            "call",
            [_NULL_SESSION, "session", "login", {"username": username, "password": password}],
        ),
    )
    result = data.get("result")
    if not (isinstance(result, list) and len(result) == 2 and result[0] == 0):
        raise UbusUnavailable("ubus session login failed (wrong password or rpcd unavailable)")
    sid = result[1].get("ubus_rpc_session")
    if not sid:
        raise UbusUnavailable("ubus login returned no session id")
    return str(sid)


async def uci_get(
    session: aiohttp.ClientSession, url: str, sid: str, config: str
) -> dict[str, Any] | None:
    """Return the ``{section: {...}}`` values of a UCI *config*, or None if denied/absent.

    A ubus call result is ``[rc, payload]``: rc 0 = ok, rc 6 = access denied, rc 2 = not found.
    Anything other than rc 0 (or a missing ``values`` key) yields None so a config the session
    can't read simply doesn't appear in the dump.
    """
    data = await _post(session, url, _payload("call", [sid, "uci", "get", {"config": config}]))
    result = data.get("result")
    if not (isinstance(result, list) and result and result[0] == 0):
        return None
    payload = result[1] if len(result) > 1 and isinstance(result[1], dict) else {}
    values = payload.get("values")
    return values if isinstance(values, dict) else None


def _endpoint_label(url: str) -> str:
    """`http://host:8080/ubus` -> `http:8080` (records the transport, never the host/IP)."""
    scheme, _, rest = url.partition("://")
    port = rest.split(":", 1)[1].split("/", 1)[0] if ":" in rest else ""
    return f"{scheme}:{port}"


async def capture_ubus(  # pylint: disable=too-many-arguments
    host: str,
    username: str,
    password: str,
    *,
    configs: tuple[str, ...] = DEFAULT_UCI_CONFIGS,
    session: aiohttp.ClientSession | None = None,
    on_progress: ProgressFn | None = None,
) -> dict[str, Any] | None:
    """Probe ``/ubus`` and return a RAW ``{endpoint, schema, uci}`` block, or None if unreachable.

    The returned ``uci`` block carries **unsanitized** config values — the caller MUST pass the
    result through :func:`glinet4_profiler.sanitize.sanitize_ubus` before persisting it. The
    ``schema`` is value-free and safe as-is. Never raises for an absent endpoint (returns None);
    a missing admin session or an ACL-denied config just yields a smaller ``uci`` block.
    """
    own_session = session is None
    session = session or aiohttp.ClientSession()
    try:
        found = await discover(session, host)
        if found is None:
            return None
        url, schema = found
        if on_progress:
            await on_progress(
                {
                    "event": "progress",
                    "phase": "ubus",
                    "message": f"ubus reachable at {_endpoint_label(url)} — capturing schema.",
                }
            )
        uci: dict[str, Any] = {}
        sid: str | None = None
        with contextlib.suppress(UbusUnavailable):
            sid = await login(session, url, username, password)
        if sid is not None:
            for config in configs:
                values = await uci_get(session, url, sid, config)
                if values is not None:
                    uci[config] = values
            if on_progress:
                await on_progress(
                    {
                        "event": "progress",
                        "phase": "ubus",
                        "message": f"ubus UCI captured ({len(uci)} configs).",
                    }
                )
        return {"endpoint": _endpoint_label(url), "schema": schema, "uci": uci}
    finally:
        if own_session:
            await session.close()
