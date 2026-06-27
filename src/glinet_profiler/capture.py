"""Server-side capture: enumerate a device read-only and return a sanitized profile."""

import json
from typing import Any

from gli4py.enumerator.probe import device_id

from .sanitize import project_report


async def _enumerate(  # pylint: disable=too-many-locals
    host: str, username: str, password: str, *, ssh: bool
) -> dict[str, Any]:
    """Run gli4py's read-only enumeration and return the raw report dict (performs I/O)."""
    import aiohttp  # pylint: disable=import-outside-toplevel  # noqa: PLC0415  (kept local so tests can patch _enumerate without the I/O stack)
    from gli4py.enumerator.probe import (  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
        enumerate_device,
    )
    from gli4py.enumerator.report import (  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
        to_json,
    )
    from gli4py.enumerator.ssh import (  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
        SshUnavailable,
        ssh_discover,
    )
    from gli4py.glinet import GLinet  # pylint: disable=import-outside-toplevel  # noqa: PLC0415
    from uplink import AiohttpClient  # pylint: disable=import-outside-toplevel  # noqa: PLC0415

    base = host.rstrip("/")
    rpc_url = f"{base}/rpc"
    host_only = base.replace("https://", "").replace("http://", "").split("/")[0]

    surface = None
    if ssh:
        try:
            surface = await ssh_discover(host_only, username="root", password=password)
        except SshUnavailable:
            surface = None

    async with aiohttp.ClientSession() as session:
        glinet = GLinet(base_url=rpc_url, client=AiohttpClient(session=session))
        await glinet.login(username, password)
        sid = glinet.sid or ""

        async def caller(service: str, method: str, args: dict[str, Any] | None) -> dict[str, Any]:
            params: list[Any] = [sid, service, method]
            if args is not None:
                params.append(args)
            payload = {"jsonrpc": "2.0", "id": 0, "method": "call", "params": params}
            async with session.post(rpc_url, json=payload) as resp:
                data: dict[str, Any] = await resp.json(content_type=None)
                return data

        info_env = await caller("system", "get_info", None)
        info = info_env.get("result")
        device_info = info if isinstance(info, dict) else {}
        report = await enumerate_device(caller, device_info=device_info, ssh_surface=surface)
        raw: dict[str, Any] = json.loads(to_json(report))
        return raw


async def capture(host: str, username: str, password: str, *, ssh: bool = False) -> dict[str, Any]:
    """Enumerate (read-only) and return the sanitized, publishable profile."""
    raw = await _enumerate(host, username, password, ssh=ssh)
    return project_report(raw, device_id(raw.get("device", {})))
