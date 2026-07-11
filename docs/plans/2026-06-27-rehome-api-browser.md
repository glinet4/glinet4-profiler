# Re-home the API browser (Phase 2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the GL.iNet API browser into glinet-profiler — a public, filterable per-model site that renders the one canonical registry — plus a manifest builder and a Pages deploy.

**Architecture:** The registry at `src/glinet_profiler/data/` stays the single source of truth (the launcher reads it; the site renders it). A small manifest builder keeps `index.json` in sync with `devices/*.json`. A vanilla static site (ported from the gli4py api-browser) fetches relative `data/`; a Pages workflow assembles the artifact by copying the canonical data dir alongside the static assets — no duplicated data.

**Tech Stack:** Python 3.11 stdlib (manifest builder), vanilla HTML/CSS/JS, pytest, ruff, mypy, pylint, GitHub Actions Pages, uv.

## Global Constraints

- Spec: `docs/specs/2026-06-27-rehome-api-browser-design.md`.
- Repo: **glinet-profiler**. All commands via uv: `uv run pytest`, `uv run ruff check .`, `uv run mypy src`, `uv run pylint <files>`. Gates: ruff, ruff-format, `mypy --strict` (config `files=["src"]` — does NOT check `scripts/`), pylint (over `git ls-files '*.py'`), pytest.
- **One canonical registry:** `src/glinet_profiler/data/` (`index.json` + `devices/<id>.json`). No second copy; the Pages deploy copies it into the published artifact.
- **"Present"** = `status` in `{"available", "needs_params"}`. `available_count` = present methods; `service_count` = services with ≥1 present method; `not_wrapped_count` = present methods with `covered_by is None`. Manifest entries sorted by `(model, firmware_version)`.
- The site is **vanilla HTML/CSS/JS** (no framework/bundler) and fetches **relative** `data/...`.
- **Publish-safety:** the committed registry data has no `mac`/`sn`/`sn_bak` and no method-level `value` key (verified by a test).
- The repo's pylint config (in `pyproject.toml`) disables `import-outside-toplevel`, `too-many-locals`, `duplicate-code`, etc., but **keeps `missing-function-docstring`** — so new/modified test files start with `# pylint: disable=missing-function-docstring,redefined-outer-name`. Source functions need docstrings.
- No gli4py change.

## File Structure

| File | Responsibility |
|---|---|
| `src/glinet_profiler/registry.py` | + `build_manifest(profiles)` and `rebuild(data_dir)` (alongside `load_manifest`/`lookup`). |
| `scripts/build_registry.py` | Thin CLI: rebuild `data/index.json` from `data/devices/*.json`. |
| `site/index.html`, `site/app.js`, `site/style.css` | The public browser (ported, copy adapted, escaping hardened). |
| `.github/workflows/pages.yml` | Pages deploy: assemble `site/` assets + a copy of `data/`. |
| `tests/test_registry.py` | + `build_manifest` / `rebuild` tests. |
| `tests/test_site_static.py` | Browser structural + registry-data-sanitized smoke. |

---

### Task 1: Manifest builder (`registry.build_manifest` + `rebuild` + CLI)

**Files:**
- Modify: `src/glinet_profiler/registry.py`
- Create: `scripts/build_registry.py`
- Test: `tests/test_registry.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `build_manifest(profiles: list[dict]) -> dict` — `{"devices": [{id, model, firmware_version, service_count, available_count, not_wrapped_count}]}`.
  - `rebuild(data_dir: Path) -> int` — read `data_dir/devices/*.json`, write `data_dir/index.json`, return count.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_registry.py`)

```python
import json
from pathlib import Path

from glinet_profiler.registry import build_manifest, rebuild


def test_build_manifest_counts():
    profile = {
        "id": "mt6000_4.9.0", "model": "mt6000", "firmware_version": "4.9.0",
        "services": {
            "system": {"get_info": {"status": "available", "covered_by": "router_info"}},
            "firewall": {
                "get_rule_list": {"status": "available", "covered_by": None},
                "set_rule": {"status": "absent", "covered_by": None},
            },
        },
    }
    entry = build_manifest([profile])["devices"][0]
    assert entry["available_count"] == 2
    assert entry["service_count"] == 2
    assert entry["not_wrapped_count"] == 1


def test_build_manifest_needs_params_is_present():
    profile = {
        "id": "x_1", "model": "x", "firmware_version": "1",
        "services": {"svc": {"m": {"status": "needs_params", "covered_by": None}}},
    }
    entry = build_manifest([profile])["devices"][0]
    assert entry["available_count"] == 1
    assert entry["not_wrapped_count"] == 1


def test_build_manifest_empty():
    assert build_manifest([]) == {"devices": []}


def test_rebuild_writes_index(tmp_path):
    devices = tmp_path / "devices"
    devices.mkdir()
    (devices / "x_1.json").write_text(
        json.dumps({
            "id": "x_1", "model": "x", "firmware_version": "1",
            "services": {"svc": {"m": {"status": "available", "covered_by": None}}},
        }),
        encoding="utf-8",
    )
    count = rebuild(tmp_path)
    assert count == 1
    manifest = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert manifest["devices"][0]["id"] == "x_1"
    assert manifest["devices"][0]["available_count"] == 1
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_registry.py -k "build_manifest or rebuild" -v`
Expected: `ImportError: cannot import name 'build_manifest'`.

- [ ] **Step 3: Implement `build_manifest` + `rebuild`** (edit `src/glinet_profiler/registry.py`)

Change the imports at the top to add `json` and `Path`:

```python
"""Registry lookup + manifest building over the bundled device profiles."""

import json
from importlib import resources
from pathlib import Path
from typing import Any

_PRESENT = ("available", "needs_params")
```

(Keep the existing `load_manifest` and `lookup` unchanged.) Append these two functions:

```python
def build_manifest(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the manifest (per-device id/model/firmware + present-method counts)."""
    entries: list[dict[str, Any]] = []
    for dev in profiles:
        present = [
            rec
            for methods in dev["services"].values()
            for rec in methods.values()
            if rec.get("status") in _PRESENT
        ]
        service_count = sum(
            1
            for methods in dev["services"].values()
            if any(rec.get("status") in _PRESENT for rec in methods.values())
        )
        entries.append(
            {
                "id": dev["id"],
                "model": dev.get("model", "unknown"),
                "firmware_version": dev.get("firmware_version", "unknown"),
                "service_count": service_count,
                "available_count": len(present),
                "not_wrapped_count": sum(1 for rec in present if rec.get("covered_by") is None),
            }
        )
    entries.sort(key=lambda entry: (entry["model"], entry["firmware_version"]))
    return {"devices": entries}


def rebuild(data_dir: Path) -> int:
    """Rebuild ``data_dir/index.json`` from ``data_dir/devices/*.json``; return device count."""
    devices_dir = data_dir / "devices"
    paths = sorted(devices_dir.glob("*.json")) if devices_dir.exists() else []
    profiles = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    (data_dir / "index.json").write_text(
        json.dumps(build_manifest(profiles), indent=2, sort_keys=True), encoding="utf-8"
    )
    return len(profiles)
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_registry.py -v`
Expected: PASS (all registry tests, incl. the four new ones).

- [ ] **Step 5: Create the CLI** `scripts/build_registry.py`

```python
"""CLI: rebuild the registry manifest (data/index.json) from data/devices/*.json."""

import sys
from pathlib import Path

from glinet_profiler.registry import rebuild

_DATA = Path(__file__).resolve().parent.parent / "src" / "glinet_profiler" / "data"


def main() -> int:
    """Rebuild the bundled registry manifest."""
    count = rebuild(_DATA)
    print(f"Wrote {count} device(s) to {_DATA / 'index.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Verify the CLI reproduces the committed manifest**

Run: `uv run python scripts/build_registry.py && git diff --stat src/glinet_profiler/data/index.json`
Expected: prints `Wrote 1 device(s) to …`; `git diff` shows **no change** (the committed `index.json` already matches `build_manifest` of the one device — confirms the builder is consistent with the existing data).

- [ ] **Step 7: Lint, type, commit**

Run: `uv run ruff check . && uv run ruff format . && uv run mypy src && uv run pylint src/glinet_profiler/registry.py scripts/build_registry.py tests/test_registry.py`
Expected: ruff clean; mypy clean; pylint `10.00`.
```bash
git add src/glinet_profiler/registry.py scripts/build_registry.py tests/test_registry.py
git commit -m "feat: registry manifest builder (build_manifest + rebuild + CLI)"
```

---

### Task 2: The public browser (`site/`) + structural test

**Files:**
- Create: `site/index.html`, `site/style.css`, `site/app.js`
- Test: `tests/test_site_static.py`

**Interfaces:**
- Consumes: the registry at `src/glinet_profiler/data/` (rendered via relative `data/` fetches once the Pages artifact is assembled in Task 3; the test reads the data dir directly).

- [ ] **Step 1: Write the failing structural test** `tests/test_site_static.py`

```python
"""Structural + data-safety smoke for the registry browser site."""
# pylint: disable=missing-function-docstring

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
DATA = ROOT / "src" / "glinet_profiler" / "data"


def test_index_has_controls():
    html = (SITE / "index.html").read_text(encoding="utf-8")
    for needle in (
        'id="device"', 'id="search"', 'id="available-only"',
        'id="not-wrapped"', 'id="results"', "app.js", "style.css",
    ):
        assert needle in html, needle


def test_app_js_fetches_relative_data_paths():
    js = (SITE / "app.js").read_text(encoding="utf-8")
    assert "data/index.json" in js
    assert "data/devices/" in js


def test_registry_data_present_and_sanitized():
    manifest = json.loads((DATA / "index.json").read_text(encoding="utf-8"))
    assert manifest["devices"], "expected committed registry data"
    mac_re = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    for entry in manifest["devices"]:
        dev = json.loads((DATA / "devices" / f"{entry['id']}.json").read_text(encoding="utf-8"))
        assert "mac" not in dev and "sn" not in dev and "sn_bak" not in dev
        for service in dev["services"].values():
            for rec in service.values():
                assert "value" not in rec
        assert not mac_re.search(json.dumps(dev))
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_site_static.py -v`
Expected: FAIL (`site/index.html` does not exist).

- [ ] **Step 3: Create `site/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GL.iNet API registry</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header>
    <h1>GL.iNet API registry</h1>
    <p class="sub">Discovered RPC surface per device — collected with <code>glinet-profiler</code>.</p>
  </header>
  <div class="controls">
    <label class="field">Model
      <select id="device"></select>
    </label>
    <input id="search" type="search" placeholder="filter service / method…">
    <label class="chk"><input type="checkbox" id="available-only"> available only</label>
    <label class="chk"><input type="checkbox" id="not-wrapped"> not yet wrapped</label>
    <span id="count" class="count"></span>
  </div>
  <main id="results"></main>
  <footer>
    <p>Sanitized profiles — no device identifiers or response values are published.</p>
  </footer>
  <script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 4: Create `site/style.css`**

```css
:root {
  --bg: #0f1419; --panel: #1a212b; --fg: #e6e9ef; --muted: #9aa6b2; --line: #2a3340;
  --green: #2ea043; --amber: #d29922; --red: #da3633; --blue: #2f81f7;
}
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.5 system-ui, sans-serif; background: var(--bg); color: var(--fg); }
header, .controls, main, footer { max-width: 1000px; margin: 0 auto; padding: 0 16px; }
header { padding-top: 24px; }
h1 { margin: 0 0 4px; font-size: 22px; }
.sub, footer { color: var(--muted); font-size: 13px; }
code { background: var(--panel); padding: 1px 5px; border-radius: 4px; }
.controls { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin: 18px auto; }
.field { display: flex; gap: 6px; align-items: center; }
select, #search { background: var(--panel); color: var(--fg); border: 1px solid var(--line);
  border-radius: 6px; padding: 6px 8px; font: inherit; }
#search { flex: 1; min-width: 180px; }
.chk { color: var(--muted); display: flex; gap: 4px; align-items: center; }
.count { color: var(--muted); margin-left: auto; }
.service { border: 1px solid var(--line); border-radius: 8px; margin: 12px 0; overflow: hidden; }
.service h2 { margin: 0; padding: 8px 12px; font-size: 14px; background: var(--panel); }
.method { padding: 7px 12px; border-top: 1px solid var(--line); cursor: pointer; }
.mhead { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.badge { font-size: 11px; padding: 1px 7px; border-radius: 10px; border: 1px solid transparent; }
.rk-read { background: rgba(46,160,67,.15); color: var(--green); }
.rk-write, .rk-active { background: rgba(210,153,34,.15); color: var(--amber); }
.rk-dangerous { background: rgba(218,54,51,.15); color: var(--red); }
.st-available { background: rgba(46,160,67,.15); color: var(--green); }
.st-needs_params { background: rgba(210,153,34,.15); color: var(--amber); }
.st-absent, .st-unreachable, .st-other, .st-auth_error, .st-token_error {
  background: var(--panel); color: var(--muted); }
.cov-yes { background: rgba(47,129,247,.15); color: var(--blue); }
.cov-no { background: rgba(210,153,34,.12); color: var(--amber); }
.detail { display: none; margin: 8px 0 2px; background: #0b0f14; border: 1px solid var(--line);
  border-radius: 6px; padding: 8px; font-size: 12px; overflow-x: auto; white-space: pre; }
.method.open .detail { display: block; }
.empty { color: var(--muted); padding: 24px 0; }
```

- [ ] **Step 5: Create `site/app.js`** (ported; `escapeHtml` covers quotes and `badge` escapes its class — the hardening already applied to the launcher UI)

```javascript
"use strict";

const els = {
  device: document.getElementById("device"),
  search: document.getElementById("search"),
  availableOnly: document.getElementById("available-only"),
  notWrapped: document.getElementById("not-wrapped"),
  count: document.getElementById("count"),
  results: document.getElementById("results"),
};

const PRESENT = new Set(["available", "needs_params"]);
let current = null;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function badge(text, cls) {
  return `<span class="badge ${escapeHtml(cls)}">${escapeHtml(text)}</span>`;
}

function methodRow(service, method, rec) {
  const present = PRESENT.has(rec.status);
  let cov = "";
  if (rec.covered_by) cov = badge(`gli4py: ${rec.covered_by}`, "cov-yes");
  else if (present) cov = badge("not yet wrapped", "cov-no");
  let detail = "";
  if (rec.params || rec.schema) {
    const body = JSON.stringify({ params: rec.params, schema: rec.schema }, null, 2);
    detail = `<pre class="detail">${escapeHtml(body)}</pre>`;
  }
  return `<div class="method">
    <div class="mhead">
      <code>${escapeHtml(method)}</code>
      ${badge(rec.status, "st-" + rec.status)}
      ${badge(rec.risk, "rk-" + rec.risk)}
      ${cov}
    </div>${detail}</div>`;
}

function render() {
  if (!current) return;
  const q = els.search.value.trim().toLowerCase();
  const availOnly = els.availableOnly.checked;
  const nw = els.notWrapped.checked;
  let shown = 0;
  const parts = [];
  for (const service of Object.keys(current.services).sort()) {
    const methods = current.services[service];
    const rows = [];
    for (const method of Object.keys(methods).sort()) {
      const rec = methods[method];
      const present = PRESENT.has(rec.status);
      if (availOnly && !present) continue;
      if (nw && !(present && rec.covered_by == null)) continue;
      if (q && !`${service}.${method}`.toLowerCase().includes(q)) continue;
      rows.push(methodRow(service, method, rec));
      shown += 1;
    }
    if (rows.length) parts.push(`<section class="service"><h2>${escapeHtml(service)}</h2>${rows.join("")}</section>`);
  }
  els.results.innerHTML = parts.join("") || "<p class='empty'>No methods match.</p>";
  els.count.textContent = `${shown} method${shown === 1 ? "" : "s"}`;
}

async function loadDevice(id) {
  try {
    const res = await fetch(`data/devices/${id}.json`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    current = await res.json();
    render();
  } catch (err) {
    els.results.innerHTML = "<p class='empty'>Could not load this device's data.</p>";
  }
}

async function loadManifest() {
  let manifest;
  try {
    manifest = await (await fetch("data/index.json")).json();
  } catch (err) {
    els.results.innerHTML = "<p class='empty'>Could not load data/index.json.</p>";
    return;
  }
  if (!manifest.devices || !manifest.devices.length) {
    els.results.innerHTML = "<p class='empty'>No device data yet. Capture one with <code>glinet-profiler</code>.</p>";
    return;
  }
  for (const d of manifest.devices) {
    const opt = document.createElement("option");
    opt.value = d.id;
    opt.textContent = `${d.model} (${d.firmware_version}) — ${d.available_count} available`;
    els.device.appendChild(opt);
  }
  await loadDevice(manifest.devices[0].id);
}

els.device.addEventListener("change", (e) => loadDevice(e.target.value));
for (const el of [els.search, els.availableOnly, els.notWrapped]) {
  el.addEventListener("input", render);
}
els.results.addEventListener("click", (e) => {
  const m = e.target.closest(".method");
  if (m) m.classList.toggle("open");
});

loadManifest();
```

- [ ] **Step 6: Run the structural test + local preview**

Run: `uv run pytest tests/test_site_static.py -v`
Expected: PASS (3 passed).

Local visual check (assemble the artifact the way Pages will, then serve):
```bash
mkdir -p _site && cp site/index.html site/app.js site/style.css _site/ && cp -r src/glinet_profiler/data _site/data
( python -m http.server 8139 -d _site >/dev/null 2>&1 & echo $! > /tmp/reg.pid ) ; sleep 1
curl -s -o /dev/null -w "index %{http_code}\n" http://localhost:8139/
curl -s -o /dev/null -w "data %{http_code}\n" http://localhost:8139/data/index.json
kill "$(cat /tmp/reg.pid)" 2>/dev/null ; rm -rf _site
```
Expected: both `200`. (The dropdown/filters render is confirmed by the controller opening it.)

- [ ] **Step 7: Lint + commit**

Run: `uv run ruff check . && uv run pylint tests/test_site_static.py`
Expected: clean / `10.00`.
```bash
git add site/index.html site/style.css site/app.js tests/test_site_static.py
git commit -m "feat: public registry browser site (ported, hardened escaping)"
```

---

### Task 3: GitHub Pages deploy

**Files:**
- Create: `.github/workflows/pages.yml`

**Interfaces:**
- Consumes: `site/` (Task 2) + `src/glinet_profiler/data/` (the registry).

- [ ] **Step 1: Create the workflow** `.github/workflows/pages.yml`

```yaml
name: Pages
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  pages: write
  id-token: write
  contents: read
concurrency:
  group: pages
  cancel-in-progress: false
jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deploy.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Assemble site (static assets + canonical registry data)
        run: |
          mkdir -p _site
          cp site/index.html site/app.js site/style.css _site/
          cp -r src/glinet_profiler/data _site/data
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: _site
      - id: deploy
        uses: actions/deploy-pages@v4
```

- [ ] **Step 2: Validate the YAML**

Run: `uv run python -c "import yaml; yaml.safe_load(open('.github/workflows/pages.yml')); print('ok')"`
Expected: `ok`. (If PyYAML isn't in the env, `uv run --with pyyaml python -c "..."`.)

> The workflow publishes only the assembled `_site` (the static browser + a copy of the canonical `src/glinet_profiler/data/`). It does not run the manifest builder — `index.json` is committed pre-built. Enable Pages once with source = "GitHub Actions" (`gh api -X POST repos/glinet4/glinet4-profiler/pages -f build_type=workflow`, or Settings → Pages). The existing `ci.yml` is untouched.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/pages.yml
git commit -m "ci: deploy the registry browser to GitHub Pages"
```

---

## After implementation (out-of-repo)

- **Close gli4py PR #13** (the api-browser is now here) with a note pointing to glinet-profiler — gli4py stays pure implementation. This is a GitHub action on the gli4py repo, not a change in this repo.

## Self-Review

**1. Spec coverage**

| Spec section | Task |
|---|---|
| §2 one canonical registry (`src/glinet_profiler/data/`) | 1 (rebuild writes there), 3 (deploy copies it) |
| §3 `build_manifest` + `scripts/build_registry.py` | 1 |
| §4 public browser (ported, own page) | 2 |
| §4 structural + data-sanitized test | 2 |
| §5 Pages deploy (assembles data copy, no duplicate) | 3 |
| §6 launcher unchanged | n/a (not touched) |
| §7 close gli4py PR #13 | After-implementation note |
| §8 testing (manifest counts, rebuild, site smoke) | 1, 2 |

No uncovered in-repo requirements. (Spec §9 listed a separate `test_build_registry.py`; consolidated into `tests/test_registry.py` since `rebuild` is a registry function — same coverage, one fewer file.)

**2. Placeholder scan:** No TBD/TODO. The browser's visual rendering is verified by the controller's local preview (no JS test tooling — YAGNI); the structural test + 200 checks are the automated gate. Not a placeholder.

**3. Type consistency:** `build_manifest(profiles) -> dict`, `rebuild(data_dir: Path) -> int`, `load_manifest()`, `lookup(...)` are used consistently across `registry.py`, `scripts/build_registry.py`, and the tests. The manifest entry keys (`id`, `model`, `firmware_version`, `service_count`, `available_count`, `not_wrapped_count`) match what `app.js` reads (`d.id`, `d.model`, `d.firmware_version`, `d.available_count`). The site element ids (`device`, `search`, `available-only`, `not-wrapped`, `results`, `count`) match across `index.html`, `app.js`, and `test_site_static.py`. The site fetches `data/index.json` + `data/devices/<id>.json`, which the Pages workflow provides by copying the canonical data dir.

---

## Execution Handoff

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks (`superpowers:subagent-driven-development`).
2. **Inline Execution** — work the tasks in this session with checkpoints (`superpowers:executing-plans`).
