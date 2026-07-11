# glinet-profiler launcher (Phase 1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `uvx`-runnable local launcher (`gli4py-web`) that enumerates a GL.iNet device read-only (server-side, no CORS), sanitizes the result to a publishable profile, looks it up against a bundled registry, and offers download + a prefilled GitHub issue.

**Architecture:** A new self-contained package `glinet-profiler` in `webapp/` (own pyproject, depends on gli4py via an editable path-source for dev, extracts cleanly to a new repo). An aiohttp server bound to `127.0.0.1` with a session token serves a vanilla web UI and a `/api/enumerate` endpoint that runs gli4py's existing enumerator + a sanitizing projection. The password only travels browser → localhost → the user's router.

**Tech Stack:** Python ≥3.11, aiohttp (server + router I/O, already a gli4py dep), gli4py (enumerator engine), stdlib `argparse`/`secrets`/`importlib.resources`/`socket`, vanilla HTML/CSS/JS, pytest + pytest-asyncio + pytest-aiohttp, ruff, pylint, hatchling, uv.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-27-glinet-profiler-design.md`. Phase 1 = the launcher only (no browsing site; no gli4py change).
- New package `glinet-profiler` lives in `webapp/` with its **own** `pyproject.toml`; package import name `glinet_profiler`; console command `gli4py-web`; license `GPL-3.0-or-later`; `requires-python >=3.11`. For dev it depends on the parent gli4py via `[tool.uv.sources] gli4py = { path = "..", editable = true }`.
- **Publish-safety (hard):** the sanitizer keeps device allowlist `{model, firmware_version, vendor, device_type, hardware_version}` and per-method `{status, error_code, risk, discovered_by, covered_by, params, schema}`; it **drops `mac`/`sn`/`sn_bak` and every method `value`**; `schema` is kept intact (type-erased field-names are API docs, not values). No `mac`/`sn`/`sn_bak` device value and no method-level `value` key survive projection.
- **Server security:** bind `127.0.0.1` only (never `0.0.0.0`); `/api/*` requires the session token header `X-Profiler-Token` and a request host of `127.0.0.1`/`localhost`. The password is read from the POST body, used only to log into the router from the local process, and is **never persisted, logged, or sent remotely**.
- Enumeration is **read-only** (gli4py catalog tier + optional SSH read tier; never `--dangerous`).
- "Present" = status in `{available, needs_params}`.
- `webapp/**/*.py` must be **ruff** clean and **pylint** clean (the gli4py repo CI runs `ruff check .` and pylint over `git ls-files '*.py'`, which include `webapp/`). gli4py's `mypy --strict` targets `gli4py` only and does not check `webapp/`, but the package is fully type-annotated.
- Run the package's tests with `uv run --directory webapp pytest`. New test files start with `# pylint: disable=missing-function-docstring,redefined-outer-name`.
- **No change to gli4py** — reuse its public `enumerate_device`, `report.to_json`, `probe.device_id`, `GLinet`.

## File Structure

| File | Responsibility |
|---|---|
| `webapp/pyproject.toml` | Package metadata, deps (`gli4py`, `aiohttp`), `ssh` extra (`paramiko`), console `gli4py-web`, dev deps, uv path-source to gli4py. |
| `webapp/README.md` | Short usage note. |
| `webapp/src/glinet_profiler/__init__.py` | Package docstring. |
| `webapp/src/glinet_profiler/sanitize.py` | `project_report()` — raw report → sanitized profile. |
| `webapp/src/glinet_profiler/registry.py` | `load_manifest()`, `lookup(model, firmware, manifest=None)`. |
| `webapp/src/glinet_profiler/submit.py` | `prefilled_issue_url(profile, *, repo=...)`. |
| `webapp/src/glinet_profiler/capture.py` | `async capture(host, username, password, *, ssh)` + `_enumerate(...)` (I/O). |
| `webapp/src/glinet_profiler/server.py` | `make_app(token, *, registry_url=None)`, `serve(...)` (aiohttp, localhost, token). |
| `webapp/src/glinet_profiler/cli.py` | `main(argv=None)` console entry. |
| `webapp/src/glinet_profiler/web/{index.html,app.js,style.css}` | The launcher UI. |
| `webapp/src/glinet_profiler/data/{index.json,devices/<id>.json}` | Bundled registry seed (sanitized). |
| `webapp/tests/test_*.py` | Unit/integration tests (no hardware). |

---

### Task 1: Scaffold + sanitizer

**Files:**
- Create: `webapp/pyproject.toml`, `webapp/README.md`, `webapp/src/glinet_profiler/__init__.py`, `webapp/src/glinet_profiler/sanitize.py`
- Test: `webapp/tests/test_sanitize.py`

**Interfaces:**
- Produces: `project_report(raw: dict, device_id_str: str) -> dict`.

- [ ] **Step 1: Write the failing test**

Create `webapp/tests/test_sanitize.py`:

```python
"""Tests for the sanitizing projection."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import json
import re

from glinet_profiler.sanitize import project_report

RAW = {
    "device": {
        "model": "mt6000", "firmware_version": "4.9.0", "vendor": "GL.iNet",
        "device_type": "router", "hardware_version": "1.0",
        "mac": "94:83:C4:AA:BB:CC", "sn": "SECRET123", "sn_bak": "SECRET456",
        "country_code": "US",
    },
    "services": {
        "system": {
            "get_info": {
                "status": "available", "error_code": None, "risk": "read",
                "discovered_by": "catalog", "covered_by": "router_info",
                "params": None, "schema": {"model": "str", "mac": "str"},
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
    # schema is kept intact (type-erased field-names, incl. "mac", are API docs)
    assert m["schema"] == {"model": "str", "mac": "str"}


def test_drops_identifiers_and_values():
    out = project_report(RAW, "mt6000_4.9.0")
    for k in ("mac", "sn", "sn_bak", "country_code"):
        assert k not in out
    # method-level response value is dropped
    assert "value" not in out["services"]["system"]["get_info"]
    # no actual identifier VALUE survives (the real MAC / serials)
    blob = json.dumps(out)
    assert "SECRET123" not in blob and "SECRET456" not in blob
    assert not re.search(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", blob)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run --directory webapp pytest tests/test_sanitize.py -v`
Expected: `ModuleNotFoundError: No module named 'glinet_profiler'`.

- [ ] **Step 3: Create the scaffold + sanitizer**

Create `webapp/pyproject.toml`:

```toml
[project]
name = "glinet-profiler"
version = "0.1.0"
description = "Local capture launcher + registry for GL.iNet device API profiles (uses gli4py)."
readme = "README.md"
license = "GPL-3.0-or-later"
requires-python = ">=3.11"
dependencies = ["gli4py", "aiohttp>=3.8.4"]

[project.optional-dependencies]
ssh = ["paramiko>=3"]

[project.scripts]
gli4py-web = "glinet_profiler.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/glinet_profiler"]

[tool.uv.sources]
gli4py = { path = "..", editable = true }

[dependency-groups]
dev = ["pytest>=7.2", "pytest-asyncio>=0.21", "pytest-aiohttp>=1.0"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
```

Create `webapp/README.md`:

```markdown
# glinet-profiler

Local launcher that captures a GL.iNet device's API surface (read-only),
sanitizes it to a shareable profile, and helps you contribute it to the
registry. Run with `uvx glinet-profiler` (or `uv run --directory webapp gli4py-web`).
Your password only ever goes from your browser to localhost to your own router.

Depends on [gli4py](https://github.com/shauneccles/gli4py) for the enumeration engine.
```

Create `webapp/src/glinet_profiler/__init__.py`:

```python
"""glinet-profiler: local capture launcher + registry for GL.iNet API profiles."""
```

Create `webapp/src/glinet_profiler/sanitize.py`:

```python
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
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run --directory webapp pytest tests/test_sanitize.py -v`
Expected: PASS (2 passed). (First run also syncs the env: installs gli4py editable from `..`, aiohttp, pytest.)

- [ ] **Step 5: Lint and commit**

Run: `uv run ruff check webapp && uv run ruff format webapp && uv run --with pylint pylint --disable=import-error,fixme,line-too-long,invalid-name,too-many-public-methods,abstract-method,overridden-final-method,too-many-instance-attributes,too-many-public-methods,too-few-public-methods,too-many-branches webapp/src/glinet_profiler/sanitize.py webapp/src/glinet_profiler/__init__.py webapp/tests/test_sanitize.py`
Expected: ruff clean; pylint `10.00`.
```bash
git add webapp/pyproject.toml webapp/README.md webapp/src/glinet_profiler/__init__.py webapp/src/glinet_profiler/sanitize.py webapp/tests/test_sanitize.py
git commit -m "feat(profiler): scaffold glinet-profiler package + sanitizer"
```

---

### Task 2: Registry lookup + submit URL + bundled seed

**Files:**
- Create: `webapp/src/glinet_profiler/registry.py`, `webapp/src/glinet_profiler/submit.py`, `webapp/src/glinet_profiler/data/index.json`, `webapp/src/glinet_profiler/data/devices/mt6000_4.9.0.json`
- Test: `webapp/tests/test_registry.py`, `webapp/tests/test_submit.py`

**Interfaces:**
- Produces:
  - `load_manifest() -> dict` (reads bundled `data/index.json`).
  - `lookup(model: str, firmware: str, manifest: dict | None = None) -> dict | None`.
  - `prefilled_issue_url(profile: dict, *, repo: str = "glinet4/glinet4-profiler") -> str`.

- [ ] **Step 1: Write the failing tests**

Create `webapp/tests/test_registry.py`:

```python
"""Registry lookup tests."""
# pylint: disable=missing-function-docstring,redefined-outer-name

from glinet_profiler.registry import load_manifest, lookup

MANIFEST = {"devices": [
    {"id": "mt6000_4.9.0", "model": "mt6000", "firmware_version": "4.9.0"},
    {"id": "ax1800_4.0.0", "model": "ax1800", "firmware_version": "4.0.0"},
]}


def test_lookup_match():
    entry = lookup("mt6000", "4.9.0", MANIFEST)
    assert entry is not None and entry["id"] == "mt6000_4.9.0"


def test_lookup_miss():
    assert lookup("mt6000", "9.9.9", MANIFEST) is None
    assert lookup("nope", "4.9.0", MANIFEST) is None


def test_load_manifest_reads_bundled_seed():
    manifest = load_manifest()
    ids = [d["id"] for d in manifest["devices"]]
    assert "mt6000_4.9.0" in ids
```

Create `webapp/tests/test_submit.py`:

```python
"""Submit-URL tests."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import urllib.parse

from glinet_profiler.submit import prefilled_issue_url

PROFILE = {
    "id": "mt6000_4.9.0", "model": "mt6000", "firmware_version": "4.9.0",
    "services": {"system": {"get_info": {"status": "available", "covered_by": "router_info"}}},
}


def test_prefilled_issue_url():
    url = prefilled_issue_url(PROFILE, repo="owner/repo")
    assert url.startswith("https://github.com/owner/repo/issues/new?")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert "mt6000" in query["title"][0] and "4.9.0" in query["title"][0]
    assert "mt6000_4.9.0.json" in query["body"][0]
    assert query["labels"][0] == "profile-submission"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run --directory webapp pytest tests/test_registry.py tests/test_submit.py -v`
Expected: `ModuleNotFoundError` for `glinet_profiler.registry` / `.submit`.

- [ ] **Step 3: Seed the bundled registry data**

Copy the sanitized sample from the api-browser (present in this tree) into the package data dir:
```bash
mkdir -p webapp/src/glinet_profiler/data/devices
cp site/data/index.json webapp/src/glinet_profiler/data/index.json
cp site/data/devices/mt6000_4.9.0.json webapp/src/glinet_profiler/data/devices/mt6000_4.9.0.json
```
(The api-browser's `index.json` entries already carry `{id, model, firmware_version, ...}` — exactly what `lookup` needs.)

- [ ] **Step 4: Implement registry + submit**

Create `webapp/src/glinet_profiler/registry.py`:

```python
"""Registry lookup: load the bundled manifest and match (model, firmware)."""

import json
from importlib import resources
from typing import Any


def load_manifest() -> dict[str, Any]:
    """Load the bundled registry manifest (data/index.json)."""
    text = (resources.files("glinet_profiler") / "data" / "index.json").read_text(encoding="utf-8")
    parsed: dict[str, Any] = json.loads(text)
    return parsed


def lookup(model: str, firmware: str, manifest: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Return the manifest entry matching (model, firmware_version), or None."""
    devices = (manifest if manifest is not None else load_manifest()).get("devices", [])
    for entry in devices:
        if entry.get("model") == model and entry.get("firmware_version") == firmware:
            return entry
    return None
```

Create `webapp/src/glinet_profiler/submit.py`:

```python
"""Build a prefilled GitHub issue URL for submitting a captured profile."""

import urllib.parse
from typing import Any

# The registry repo that receives profile submissions (update on extraction).
REGISTRY_REPO = "glinet4/glinet4-profiler"
_PRESENT = ("available", "needs_params")


def prefilled_issue_url(profile: dict[str, Any], *, repo: str = REGISTRY_REPO) -> str:
    """Construct a prefilled 'submit profile' GitHub issue URL (asks the user to attach the file)."""
    model = profile.get("model", "unknown")
    firmware = profile.get("firmware_version", "unknown")
    services = profile.get("services", {})
    available = sum(
        1
        for methods in services.values()
        for rec in methods.values()
        if rec.get("status") in _PRESENT
    )
    title = f"Add profile: {model} ({firmware})"
    body = (
        "Device API profile submission.\n\n"
        f"- Model: `{model}`\n"
        f"- Firmware: `{firmware}`\n"
        f"- Available methods: {available}\n\n"
        f"Please **attach the downloaded `{profile.get('id', 'profile')}.json`** to this issue.\n"
    )
    query = urllib.parse.urlencode({"title": title, "body": body, "labels": "profile-submission"})
    return f"https://github.com/{repo}/issues/new?{query}"
```

- [ ] **Step 5: Run to verify pass**

Run: `uv run --directory webapp pytest tests/test_registry.py tests/test_submit.py -v`
Expected: PASS (4 passed) — `test_load_manifest_reads_bundled_seed` confirms the copied seed is packaged.

- [ ] **Step 6: Lint and commit**

Run: `uv run ruff check webapp && uv run --with pylint pylint --disable=import-error,fixme,line-too-long,invalid-name,too-many-public-methods,abstract-method,overridden-final-method,too-many-instance-attributes,too-many-public-methods,too-few-public-methods,too-many-branches webapp/src/glinet_profiler/registry.py webapp/src/glinet_profiler/submit.py webapp/tests/test_registry.py webapp/tests/test_submit.py`
Expected: clean / `10.00`.
```bash
git add webapp/src/glinet_profiler/registry.py webapp/src/glinet_profiler/submit.py webapp/src/glinet_profiler/data webapp/tests/test_registry.py webapp/tests/test_submit.py
git commit -m "feat(profiler): registry lookup + submit-issue URL + bundled seed"
```

---

### Task 3: Capture (server-side enumeration, mocked-tested)

**Files:**
- Create: `webapp/src/glinet_profiler/capture.py`
- Test: `webapp/tests/test_capture.py`

**Interfaces:**
- Consumes: `sanitize.project_report` (Task 1); gli4py `GLinet`, `enumerator.probe.{enumerate_device, device_id}`, `enumerator.report.to_json`, `enumerator.ssh.{ssh_discover, SshUnavailable}`.
- Produces:
  - `async _enumerate(host: str, username: str, password: str, *, ssh: bool) -> dict` (the I/O; patched in tests).
  - `async capture(host: str, username: str, password: str, *, ssh: bool = False) -> dict` (sanitized profile).

- [ ] **Step 1: Write the failing test**

Create `webapp/tests/test_capture.py`:

```python
"""capture() tests against a mocked enumeration (no router)."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import json

import glinet_profiler.capture as capture_mod
from glinet_profiler.capture import capture

RAW = {
    "device": {"model": "mt6000", "firmware_version": "4.9.0",
               "mac": "94:83:C4:AA:BB:CC", "sn": "SECRET123"},
    "services": {"system": {"get_info": {
        "status": "available", "error_code": None, "risk": "read",
        "discovered_by": "catalog", "covered_by": "router_info",
        "params": None, "schema": {"model": "str"},
        "value": {"mac": "94:83:C4:AA:BB:CC"},
    }}},
}


async def test_capture_returns_sanitized_profile(monkeypatch):
    async def fake_enumerate(host, username, password, *, ssh):  # noqa: ARG001
        return RAW

    monkeypatch.setattr(capture_mod, "_enumerate", fake_enumerate)
    profile = await capture("http://192.168.8.1", "root", "pw")
    assert profile["id"] == "mt6000_4.9.0"
    assert profile["model"] == "mt6000"
    assert "mac" not in profile and "sn" not in profile
    assert "value" not in profile["services"]["system"]["get_info"]
    blob = json.dumps(profile)
    assert "SECRET123" not in blob and "94:83:C4" not in blob


async def test_capture_passes_ssh_flag(monkeypatch):
    seen = {}

    async def fake_enumerate(host, username, password, *, ssh):  # noqa: ARG001
        seen["ssh"] = ssh
        return RAW

    monkeypatch.setattr(capture_mod, "_enumerate", fake_enumerate)
    await capture("http://x", "root", "pw", ssh=True)
    assert seen["ssh"] is True
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run --directory webapp pytest tests/test_capture.py -v`
Expected: `ModuleNotFoundError: No module named 'glinet_profiler.capture'`.

- [ ] **Step 3: Implement capture**

Create `webapp/src/glinet_profiler/capture.py`:

```python
"""Server-side capture: enumerate a device read-only and return a sanitized profile."""

import json
from typing import Any

from gli4py.enumerator.probe import device_id

from .sanitize import project_report


async def _enumerate(host: str, username: str, password: str, *, ssh: bool) -> dict[str, Any]:
    """Run gli4py's read-only enumeration and return the raw report dict (performs I/O)."""
    import aiohttp  # noqa: PLC0415  (kept local so tests can patch _enumerate without the I/O stack)
    from uplink import AiohttpClient  # noqa: PLC0415
    from gli4py.enumerator.probe import enumerate_device  # noqa: PLC0415
    from gli4py.enumerator.report import to_json  # noqa: PLC0415
    from gli4py.enumerator.ssh import SshUnavailable, ssh_discover  # noqa: PLC0415
    from gli4py.glinet import GLinet  # noqa: PLC0415

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
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run --directory webapp pytest tests/test_capture.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Lint and commit**

Run: `uv run ruff check webapp && uv run --with pylint pylint --disable=import-error,fixme,line-too-long,invalid-name,too-many-public-methods,abstract-method,overridden-final-method,too-many-instance-attributes,too-many-public-methods,too-few-public-methods,too-many-branches webapp/src/glinet_profiler/capture.py webapp/tests/test_capture.py`
Expected: clean / `10.00`. (If pylint flags `import-outside-toplevel` on the lazy imports in `_enumerate`, add `# pylint: disable=import-outside-toplevel` on those lines — they are intentional so tests can patch `_enumerate`.)
```bash
git add webapp/src/glinet_profiler/capture.py webapp/tests/test_capture.py
git commit -m "feat(profiler): server-side read-only capture -> sanitized profile"
```

---

### Task 4: Web UI

**Files:**
- Create: `webapp/src/glinet_profiler/web/index.html`, `webapp/src/glinet_profiler/web/style.css`, `webapp/src/glinet_profiler/web/app.js`
- Test: `webapp/tests/test_web.py`

**Interfaces:**
- Consumes: the server's `POST /api/enumerate` (Task 5) returning `{profile, lookup, submit_url}`.

- [ ] **Step 1: Write the failing structural test**

Create `webapp/tests/test_web.py`:

```python
"""Structural smoke checks for the launcher UI."""
# pylint: disable=missing-function-docstring

from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "src" / "glinet_profiler" / "web"


def test_index_has_form_controls():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    for needle in ('id="form"', 'id="host"', 'id="username"', 'id="password"',
                   'id="ssh"', 'id="status"', 'id="result"', 'id="banner"',
                   'id="actions"', 'id="download"', 'id="submit"', "app.js", "style.css"):
        assert needle in html, needle


def test_app_js_uses_token_and_endpoint():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert "api/enumerate" in js
    assert "X-Profiler-Token" in js
    assert "submit_url" in js  # opens the server-built prefilled issue URL
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run --directory webapp pytest tests/test_web.py -v`
Expected: FAIL (web/index.html missing).

- [ ] **Step 3: Create `web/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>glinet-profiler</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header>
    <h1>glinet-profiler</h1>
    <p class="sub">Capture your GL.iNet device's API surface — read-only, your password stays on this machine.</p>
  </header>
  <form id="form">
    <label>Router URL <input id="host" type="text" value="http://192.168.8.1" required></label>
    <label>Username <input id="username" type="text" value="root"></label>
    <label>Password <input id="password" type="password" required></label>
    <label class="chk"><input id="ssh" type="checkbox"> try SSH ground-truth (needs SSH access)</label>
    <button type="submit">Capture</button>
  </form>
  <p id="status" class="status"></p>
  <div id="banner"></div>
  <div id="actions" hidden>
    <button id="download">Download profile</button>
    <button id="submit">Submit to registry</button>
  </div>
  <main id="result"></main>
  <footer><p>Read-only. No identifiers or response values are included in the profile. Nothing is uploaded unless you click Submit.</p></footer>
  <script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 4: Create `web/style.css`**

```css
:root { --bg:#0f1419; --panel:#1a212b; --fg:#e6e9ef; --muted:#9aa6b2; --line:#2a3340;
  --green:#2ea043; --amber:#d29922; --red:#da3633; --blue:#2f81f7; }
* { box-sizing: border-box; }
body { margin:0; font:14px/1.5 system-ui,sans-serif; background:var(--bg); color:var(--fg); }
header, form, #banner, #actions, main, footer { max-width:900px; margin:0 auto; padding:0 16px; }
header { padding-top:24px; } h1 { margin:0 0 4px; } .sub, footer { color:var(--muted); font-size:13px; }
code { background:var(--panel); padding:1px 5px; border-radius:4px; }
form { display:flex; flex-direction:column; gap:10px; margin:18px auto; }
form label { display:flex; gap:8px; align-items:center; justify-content:space-between; }
form input[type=text], form input[type=password] { flex:1; background:var(--panel); color:var(--fg);
  border:1px solid var(--line); border-radius:6px; padding:7px 9px; font:inherit; }
.chk { justify-content:flex-start !important; color:var(--muted); }
button { background:var(--panel); color:var(--fg); border:1px solid var(--line); border-radius:6px;
  padding:8px 14px; font:inherit; cursor:pointer; }
button[type=submit], button.primary { background:var(--blue); border-color:var(--blue); color:#fff; }
#actions { display:flex; gap:10px; margin:10px auto; }
.status { color:var(--muted); } .error { color:var(--red); }
#banner .known { color:var(--green); } #banner .new { color:var(--amber); font-weight:600; }
#banner > div { padding:10px 12px; border:1px solid var(--line); border-radius:8px; margin:10px auto; }
.service { border:1px solid var(--line); border-radius:8px; margin:10px 0; overflow:hidden; }
.service h3 { margin:0; padding:8px 12px; font-size:14px; background:var(--panel); }
.method { padding:6px 12px; border-top:1px solid var(--line); display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.badge { font-size:11px; padding:1px 7px; border-radius:10px; }
.rk-read{background:rgba(46,160,67,.15);color:var(--green);} .rk-write,.rk-active{background:rgba(210,153,34,.15);color:var(--amber);}
.rk-dangerous{background:rgba(218,54,51,.15);color:var(--red);}
.st-available{background:rgba(46,160,67,.15);color:var(--green);} .st-needs_params{background:rgba(210,153,34,.15);color:var(--amber);}
.st-absent,.st-unreachable,.st-other,.st-auth_error,.st-token_error{background:var(--panel);color:var(--muted);}
.cov-yes{background:rgba(47,129,247,.15);color:var(--blue);} .cov-no{background:rgba(210,153,34,.12);color:var(--amber);}
```

- [ ] **Step 5: Create `web/app.js`**

```javascript
"use strict";
const token = new URLSearchParams(location.search).get("t") || "";
const $ = (id) => document.getElementById(id);
const PRESENT = new Set(["available", "needs_params"]);
let profile = null;
let submitUrl = "";

function escapeHtml(s) { return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
function badge(t, c) { return `<span class="badge ${c}">${escapeHtml(t)}</span>`; }

function renderProfile(p) {
  const parts = [];
  for (const service of Object.keys(p.services).sort()) {
    const methods = p.services[service];
    const rows = [];
    for (const m of Object.keys(methods).sort()) {
      const rec = methods[m];
      let cov = "";
      if (rec.covered_by) cov = badge(`gli4py: ${rec.covered_by}`, "cov-yes");
      else if (PRESENT.has(rec.status)) cov = badge("not yet wrapped", "cov-no");
      rows.push(`<div class="method"><code>${escapeHtml(m)}</code>${badge(rec.status, "st-" + rec.status)}${badge(rec.risk, "rk-" + rec.risk)}${cov}</div>`);
    }
    parts.push(`<section class="service"><h3>${escapeHtml(service)}</h3>${rows.join("")}</section>`);
  }
  return parts.join("");
}

async function onCapture(e) {
  e.preventDefault();
  $("status").textContent = "Enumerating… this can take a moment.";
  $("result").innerHTML = ""; $("banner").innerHTML = ""; $("actions").hidden = true;
  try {
    const res = await fetch("api/enumerate", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Profiler-Token": token },
      body: JSON.stringify({
        host: $("host").value.trim(),
        username: $("username").value.trim() || "root",
        password: $("password").value,
        ssh: $("ssh").checked,
      }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    const data = await res.json();
    profile = data.profile; submitUrl = data.submit_url || "";
    $("status").textContent = "";
    $("banner").innerHTML = data.lookup
      ? `<div class="known">✅ <b>${escapeHtml(profile.model)}</b> (${escapeHtml(profile.firmware_version)}) is already in the registry.</div>`
      : `<div class="new">🆕 <b>${escapeHtml(profile.model)}</b> (${escapeHtml(profile.firmware_version)}) is new — please contribute it!</div>`;
    $("result").innerHTML = renderProfile(profile);
    $("actions").hidden = false;
    $("submit").classList.toggle("primary", !data.lookup);
  } catch (err) {
    $("status").textContent = "";
    $("result").innerHTML = `<p class="error">${escapeHtml(err.message || err)}</p>`;
  }
}

function onDownload() {
  const blob = new Blob([JSON.stringify(profile, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = `${profile.id}.json`; a.click();
  URL.revokeObjectURL(a.href);
}

function onSubmit() { if (submitUrl) window.open(submitUrl, "_blank", "noopener"); }

$("form").addEventListener("submit", onCapture);
$("download").addEventListener("click", onDownload);
$("submit").addEventListener("click", onSubmit);
```

- [ ] **Step 6: Run to verify pass**

Run: `uv run --directory webapp pytest tests/test_web.py -v`
Expected: PASS (2 passed).

- [ ] **Step 7: Lint and commit**

Run: `uv run ruff check webapp` (HTML/CSS/JS aren't linted by ruff/pylint; only confirm no Python regressions)
```bash
git add webapp/src/glinet_profiler/web
git commit -m "feat(profiler): launcher web UI (capture form + profile render + actions)"
```

---

### Task 5: Server + CLI

**Files:**
- Create: `webapp/src/glinet_profiler/server.py`, `webapp/src/glinet_profiler/cli.py`
- Test: `webapp/tests/test_server.py`

**Interfaces:**
- Consumes: `capture.capture` (Task 3), `registry.{load_manifest, lookup}` (Task 2), `submit.prefilled_issue_url` (Task 2), the `web/` assets (Task 4).
- Produces:
  - `make_app(token: str, *, registry_url: str | None = None) -> aiohttp.web.Application`.
  - `serve(*, port: int = 0, open_browser: bool = True, registry_url: str | None = None) -> None`.
  - `cli.main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1: Write the failing test**

Create `webapp/tests/test_server.py`:

```python
"""Server API tests (aiohttp test client; no router)."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import pytest

import glinet_profiler.capture as capture_mod
from glinet_profiler.server import make_app

TOKEN = "test-token"
PROFILE = {
    "id": "mt6000_4.9.0", "model": "mt6000", "firmware_version": "4.9.0",
    "services": {"system": {"get_info": {
        "status": "available", "error_code": None, "risk": "read",
        "discovered_by": "catalog", "covered_by": "router_info", "params": None, "schema": {}}}},
}


@pytest.fixture
async def client(aiohttp_client, monkeypatch):
    async def fake_capture(host, username, password, *, ssh=False):  # noqa: ARG001
        return PROFILE
    monkeypatch.setattr(capture_mod, "capture", fake_capture)
    return await aiohttp_client(make_app(TOKEN))


async def test_enumerate_requires_token(client):
    resp = await client.post("/api/enumerate", json={"host": "http://x", "password": "p"})
    assert resp.status == 401


async def test_enumerate_with_token_returns_profile_lookup_submit(client):
    resp = await client.post(
        "/api/enumerate",
        headers={"X-Profiler-Token": TOKEN},
        json={"host": "http://x", "username": "root", "password": "p", "ssh": False},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["profile"]["model"] == "mt6000"
    assert data["lookup"] is not None           # mt6000_4.9.0 is in the bundled registry
    assert "issues/new" in data["submit_url"]


async def test_index_is_served(client):
    resp = await client.get("/")
    assert resp.status == 200
    assert "glinet-profiler" in await resp.text()
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run --directory webapp pytest tests/test_server.py -v`
Expected: `ModuleNotFoundError: No module named 'glinet_profiler.server'`.

- [ ] **Step 3: Implement server + cli**

Create `webapp/src/glinet_profiler/server.py`:

```python
"""The local launcher web server (aiohttp, 127.0.0.1, token-guarded API)."""

import asyncio
import secrets
import socket
import webbrowser
from importlib import resources
from pathlib import Path

from aiohttp import web

from . import capture as capture_mod
from . import registry as registry_mod
from . import submit as submit_mod

_WEB = resources.files("glinet_profiler") / "web"
_ALLOWED_HOSTS = ("127.0.0.1", "localhost")


def _guard(request: web.Request, token: str) -> None:
    if request.headers.get("X-Profiler-Token") != token:
        raise web.HTTPUnauthorized(text="missing or invalid token")
    if (request.host or "").split(":")[0] not in _ALLOWED_HOSTS:
        raise web.HTTPForbidden(text="local access only")


def make_app(token: str, *, registry_url: str | None = None) -> web.Application:
    """Build the aiohttp application. `registry_url` is reserved for a live registry (unused in v1)."""
    _ = registry_url  # v1 uses the bundled registry
    app = web.Application()

    async def index(_request: web.Request) -> web.StreamResponse:
        return web.FileResponse(str(_WEB / "index.html"))

    async def asset(request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        path = Path(str(_WEB / name))
        if name not in ("app.js", "style.css") or not path.is_file():
            raise web.HTTPNotFound()
        return web.FileResponse(str(path))

    async def api_enumerate(request: web.Request) -> web.Response:
        _guard(request, token)
        body = await request.json()
        profile = await capture_mod.capture(
            body["host"],
            body.get("username") or "root",
            body.get("password", ""),
            ssh=bool(body.get("ssh")),
        )
        match = registry_mod.lookup(profile.get("model", ""), profile.get("firmware_version", ""))
        return web.json_response(
            {"profile": profile, "lookup": match, "submit_url": submit_mod.prefilled_issue_url(profile)}
        )

    async def api_registry(request: web.Request) -> web.Response:
        _guard(request, token)
        return web.json_response(registry_mod.load_manifest())

    app.router.add_get("/", index)
    app.router.add_post("/api/enumerate", api_enumerate)
    app.router.add_get("/api/registry", api_registry)
    app.router.add_get("/{name}", asset)
    return app


def serve(*, port: int = 0, open_browser: bool = True, registry_url: str | None = None) -> None:
    """Start the launcher on 127.0.0.1 (ephemeral port by default) and optionally open the browser."""
    token = secrets.token_urlsafe(16)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    actual_port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{actual_port}/?t={token}"

    async def _run() -> None:
        runner = web.AppRunner(make_app(token, registry_url=registry_url))
        await runner.setup()
        await web.SockSite(runner, sock).start()
        print(f"glinet-profiler is running at:\n  {url}\nPress Ctrl+C to stop.")
        if open_browser:
            webbrowser.open(url)
        await asyncio.Event().wait()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        print("\nstopped.")
```

Create `webapp/src/glinet_profiler/cli.py`:

```python
"""gli4py-web console entry point."""

import argparse

from .server import serve


def main(argv: list[str] | None = None) -> int:
    """Start the glinet-profiler launcher."""
    parser = argparse.ArgumentParser(
        prog="gli4py-web", description="Local GL.iNet API profile capture launcher."
    )
    parser.add_argument("--port", type=int, default=0, help="port (default: ephemeral)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser")
    parser.add_argument("--registry-url", help="override the bundled registry (reserved)")
    args = parser.parse_args(argv)
    serve(port=args.port, open_browser=not args.no_browser, registry_url=args.registry_url)
    return 0
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run --directory webapp pytest tests/test_server.py -v`
Expected: PASS (3 passed).

- [ ] **Step 5: Local smoke (the launcher actually starts + serves)**

Run:
```bash
( uv run --directory webapp gli4py-web --no-browser --port 8765 & echo $! > /tmp/gp.pid ; sleep 3 )
curl -s -o /dev/null -w "index %{http_code}\n" http://127.0.0.1:8765/
curl -s -o /dev/null -w "no-token-401 %{http_code}\n" -X POST http://127.0.0.1:8765/api/enumerate -H 'Content-Type: application/json' -d '{"host":"http://x","password":"p"}'
kill "$(cat /tmp/gp.pid)" 2>/dev/null
```
Expected: `index 200` and `no-token-401 401`. (A full capture needs a real router + the controller's visual check.)

- [ ] **Step 6: Lint + full package tests + commit**

Run:
```bash
uv run ruff check webapp && uv run ruff format webapp
uv run --directory webapp pytest -q
uv run --with pylint pylint --disable=import-error,fixme,line-too-long,invalid-name,too-many-public-methods,abstract-method,overridden-final-method,too-many-instance-attributes,too-many-public-methods,too-few-public-methods,too-many-branches webapp/src/glinet_profiler/server.py webapp/src/glinet_profiler/cli.py webapp/tests/test_server.py
```
Expected: ruff clean; all package tests pass; pylint `10.00` (add the standard `# pylint: disable=...` header to any test file that trips missing-docstring/redefined-outer-name; `serve()` may need `# pylint: disable=...` if flagged for locals — keep it small).
```bash
git add webapp/src/glinet_profiler/server.py webapp/src/glinet_profiler/cli.py webapp/tests/test_server.py
git commit -m "feat(profiler): aiohttp launcher server + gli4py-web CLI"
```

---

## Self-Review

**1. Spec coverage**

| Spec requirement | Task |
|---|---|
| Sanitizer (drop mac/sn/sn_bak + values; keep allowlist+schema) | 1 |
| Publish-safety (no identifier value / no `value` key survives) | 1 (tests) |
| Registry lookup by (model, firmware) | 2 |
| Bundled registry seed | 2 |
| Submission = prefilled GitHub issue | 2 (url), 4 (button), 5 (embed in response) |
| Capture (server-side, read-only catalog + optional SSH) reusing gli4py | 3 |
| Local launcher (127.0.0.1, token, Origin/host check) | 5 |
| Password local-only, never persisted/sent | 3 (capture local) + 5 (localhost bind) |
| Web UI (form → progress → profile → lookup banner → download/submit) | 4 |
| `uvx`/console `gli4py-web` | 1 (scripts), 5 (cli) |
| Own pyproject, depends on gli4py, extracts cleanly | 1 |
| No gli4py change | all (reuse only) |
| ruff/pylint clean; tests hardware-free | each task's lint/test steps |

No uncovered Phase-1 requirements. The browsing site + automated PR are Phase 2 (spec §2), out of scope here.

**2. Placeholder scan:** No TBD/TODO. The UI's visual rendering is verified by the controller running the launcher (no JS test tooling — the structural test + the 200/401 smoke are the automated gate). The `registry_url` param is implemented as reserved (bundled registry in v1), explicitly documented — not a placeholder.

**3. Type consistency:** `project_report(raw, device_id_str)`, `load_manifest()`, `lookup(model, firmware, manifest=None)`, `prefilled_issue_url(profile, *, repo)`, `_enumerate(host, username, password, *, ssh)`, `capture(host, username, password, *, ssh=False)`, `make_app(token, *, registry_url=None)`, `serve(*, port, open_browser, registry_url)`, `cli.main(argv)` are used with identical signatures across tasks. The `/api/enumerate` response shape `{profile, lookup, submit_url}` matches between `server.py` (Task 5) and `app.js` (Task 4, reads `data.profile`/`data.lookup`/`data.submit_url`). The HTML element ids (`form`, `host`, `username`, `password`, `ssh`, `status`, `result`, `banner`, `actions`, `download`, `submit`) match between `index.html`, `app.js`, and `test_web.py`.

---

## Execution Handoff

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks (`superpowers:subagent-driven-development`).
2. **Inline Execution** — work the tasks in this session with checkpoints (`superpowers:executing-plans`).
