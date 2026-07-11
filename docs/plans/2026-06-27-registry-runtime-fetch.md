# Split the registry into its own repo (runtime fetch) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Move the registry (data + submission bot + browse site) into a new `glinet-registry` repo; make `glinet-profiler` fetch the live manifest at runtime and ship no data.

**Architecture:** `glinet-registry` is a dependency-free, data-focused repo (profiles + self-contained stdlib tooling + the issue→PR bot + the Pages browse site). `glinet-profiler` becomes pure code whose `registry.py` is an aiohttp fetch client with graceful offline degradation.

**Tech Stack:** Python 3.11 stdlib (registry tooling), aiohttp (package fetch), GitHub Actions (Pages + bot + CI), uv, ruff/mypy/pylint/zizmor. Source for the moves is on disk in `/home/shaunes/dev/oss/glinet-profiler`.

## Global Constraints
- Spec: `docs/specs/2026-06-27-registry-runtime-fetch-design.md`.
- **`glinet-registry`** (new, at `/home/shaunes/dev/oss/glinet-registry`) has **no dependency on `glinet-profiler`** — its tooling (`tools/registry_lib.py`) is self-contained stdlib.
- **`glinet-profiler`** ships no registry data; `registry.py` becomes `fetch_manifest`/`lookup`; `lookup` requires a passed manifest; offline (`fetch_manifest` → `None`) degrades to "couldn't check — submit anyway".
- Publish-safety unchanged: `validate_profile` (no `mac`/`sn`/`sn_bak`, no method `value`, no MAC-hex) gates both the launcher's output and the registry's contributions.
- All workflows SHA-pin actions (zizmor-clean) + `persist-credentials: false` on checkouts.
- The slug regex is `_SLUG = re.compile(r"[^a-z0-9.]+")`; manifest "present" = status in `{available, needs_params}`.

---

### Task 1: `glinet-registry` — data + self-contained tooling + CI

**Files (in `/home/shaunes/dev/oss/glinet-registry`):**
- Create: `tools/registry_lib.py`, `scripts/build_manifest.py`, `scripts/ingest.py`, `registry/index.json`, `registry/devices/mt6000_4.9.0.json`, `tests/test_registry_lib.py`, `.github/workflows/ci.yml`, `.github/dependabot.yml`, `README.md`, `LICENSE`, `.gitignore`, `ruff.toml`

- [ ] **Step 1: Scaffold + migrate the data**
```bash
NEW=/home/shaunes/dev/oss/glinet-registry
SRC=/home/shaunes/dev/oss/glinet-profiler
mkdir -p "$NEW"/{tools,scripts,registry/devices,tests,.github/workflows,.github/ISSUE_TEMPLATE}
cp "$SRC"/src/glinet_profiler/data/index.json "$NEW"/registry/index.json
cp "$SRC"/src/glinet_profiler/data/devices/mt6000_4.9.0.json "$NEW"/registry/devices/mt6000_4.9.0.json
cp "$SRC"/LICENSE "$NEW"/LICENSE
```

- [ ] **Step 2: `tools/registry_lib.py`** (self-contained — no glinet-profiler dep)
```python
"""Self-contained registry helpers (stdlib only): id slug, validation, manifest."""

import json
import re
from typing import Any

_SLUG = re.compile(r"[^a-z0-9.]+")
_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_PRESENT = ("available", "needs_params")
_REQUIRED = ("model", "firmware_version", "services")
_IDENTIFIERS = ("mac", "sn", "sn_bak")


def device_id(model: str, firmware: str) -> str:
    """Slug `model_firmware`."""
    model_slug = _SLUG.sub("-", model.lower()).strip("-")
    firmware_slug = _SLUG.sub("-", firmware.lower()).strip("-")
    return f"{model_slug}_{firmware_slug}"


def validate_profile(data: Any) -> str | None:  # pylint: disable=too-many-return-statements
    """Return an error message if `data` is not a clean sanitized profile, else None."""
    if not isinstance(data, dict):
        return "submission is not a JSON object"
    for key in _REQUIRED:
        if key not in data:
            return f"missing required key: {key}"
    for key in ("model", "firmware_version"):
        if not isinstance(data[key], str) or not data[key].strip():
            return f"'{key}' must be a non-empty string"
    if not isinstance(data["services"], dict):
        return "'services' must be an object"
    for ident in _IDENTIFIERS:
        if ident in data:
            return f"profile contains a device identifier ({ident}); submit a sanitized profile, not a raw report"
    for service, methods in data["services"].items():
        if not isinstance(methods, dict):
            return f"service '{service}' must be an object"
        for method, rec in methods.items():
            if not isinstance(rec, dict):
                return f"method '{service}.{method}' must be an object"
            if "value" in rec:
                return f"method '{service}.{method}' contains a response value; submit a sanitized profile"
    if _MAC_RE.search(json.dumps(data)):
        return "profile contains a MAC-address-like value; submit a sanitized profile"
    return None


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
```

- [ ] **Step 3: `scripts/build_manifest.py`** (rebuild + `--check`)
```python
"""Rebuild registry/index.json from registry/devices/*.json (or --check it's in sync)."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.registry_lib import build_manifest  # noqa: E402

_REG = Path(__file__).resolve().parent.parent / "registry"


def main(argv: list[str] | None = None) -> int:
    """Rebuild or --check the manifest."""
    parser = argparse.ArgumentParser(description="Build/check the registry manifest.")
    parser.add_argument("--check", action="store_true", help="fail if index.json is out of date")
    args = parser.parse_args(argv)
    profiles = [
        json.loads(p.read_text(encoding="utf-8")) for p in sorted((_REG / "devices").glob("*.json"))
    ]
    manifest = json.dumps(build_manifest(profiles), indent=2, sort_keys=True) + "\n"
    index = _REG / "index.json"
    if args.check:
        if index.read_text(encoding="utf-8") != manifest:
            print("index.json is out of date — run scripts/build_manifest.py", file=sys.stderr)
            return 1
        return 0
    index.write_text(manifest, encoding="utf-8")
    print(f"wrote {len(profiles)} device(s) to {index}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```
Note: write `index.json` with a trailing newline; **the migrated `registry/index.json` must match this format** — run `python scripts/build_manifest.py` once after Step 1 to normalize it.

- [ ] **Step 4: `scripts/ingest.py`** (validate a submission → write → rebuild)
```python
"""Validate a submitted profile, write registry/devices/<id>.json, rebuild the manifest."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.registry_lib import build_manifest, device_id, validate_profile  # noqa: E402

_REG = Path(__file__).resolve().parent.parent / "registry"


def main(argv: list[str] | None = None) -> int:
    """Ingest the given submission file; print the id (ok) or the error (fail)."""
    if not argv:
        argv = sys.argv[1:]
    data = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    error = validate_profile(data)
    if error:
        print(error, file=sys.stderr)
        return 1
    new_id = device_id(data["model"], data["firmware_version"])
    data["id"] = new_id
    (_REG / "devices").mkdir(parents=True, exist_ok=True)
    (_REG / "devices" / f"{new_id}.json").write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
    )
    profiles = [
        json.loads(p.read_text(encoding="utf-8")) for p in sorted((_REG / "devices").glob("*.json"))
    ]
    (_REG / "index.json").write_text(
        json.dumps(build_manifest(profiles), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(new_id)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: `tests/test_registry_lib.py`**
```python
"""Tests for the self-contained registry tooling."""
# pylint: disable=missing-function-docstring

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.registry_lib import build_manifest, device_id, validate_profile  # noqa: E402

CLEAN = {
    "id": "x", "model": "mt6000", "firmware_version": "4.9.0",
    "services": {"system": {"get_info": {"status": "available", "covered_by": "router_info"}}},
}


def test_device_id_slug():
    assert device_id("MT6000", "4.9.0") == "mt6000_4.9.0"


def test_validate_clean_and_rejections():
    assert validate_profile(CLEAN) is None
    assert "identifier" in validate_profile({**CLEAN, "mac": "94:83:C4:AA:BB:CC"})
    bad = {**CLEAN, "services": {"s": {"m": {"status": "available", "value": {"x": 1}}}}}
    assert "response value" in validate_profile(bad)
    assert "MAC" in validate_profile({**CLEAN, "services": {"s": {"m": {"schema": {"a": "94:83:C4:AA:BB:CC"}}}}})


def test_build_manifest_counts():
    entry = build_manifest([{**CLEAN, "id": "mt6000_4.9.0"}])["devices"][0]
    assert entry["available_count"] == 1 and entry["service_count"] == 1


def test_committed_index_matches_devices():
    reg = Path(__file__).resolve().parent.parent / "registry"
    profiles = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((reg / "devices").glob("*.json"))]
    committed = json.loads((reg / "index.json").read_text(encoding="utf-8"))
    assert committed == build_manifest(profiles)
    mac = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
    for p in (reg / "devices").glob("*.json"):
        assert validate_profile(json.loads(p.read_text(encoding="utf-8"))) is None
        assert not mac.search(p.read_text(encoding="utf-8"))
```

- [ ] **Step 6: `ruff.toml`, `.gitignore`, `dependabot.yml`, `README.md`, CI**

`ruff.toml`:
```toml
line-length = 100
target-version = "py311"
[lint]
select = ["E", "F", "I", "UP", "B"]
ignore = ["E501"]
```
`.gitignore`: `__pycache__/`, `*.py[cod]`, `.ruff_cache/`, `.pytest_cache/`, `_site/`
`.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```
`.github/workflows/ci.yml`:
```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          persist-credentials: false
      - uses: astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78 # v7
        with:
          python-version: "3.11"
      - run: uvx ruff check .
      - run: python scripts/build_manifest.py --check
      - run: uvx pytest -q
```
`README.md`: short — what the registry is, how to contribute (the launcher or the issue form), that `scripts/build_manifest.py` keeps `index.json` in sync.

- [ ] **Step 7: Verify + commit**
```bash
cd /home/shaunes/dev/oss/glinet-registry
python scripts/build_manifest.py            # normalize the migrated index.json
uvx ruff check . && uvx pytest -q           # tooling clean + tests pass
python scripts/build_manifest.py --check    # in sync
git init -q -b main && git add -A
git -c user.name=shauneccles -c user.email=shauneccles@gmail.com commit -q -m "feat: registry data + self-contained tooling + CI"
```

---

### Task 2: `glinet-registry` — browse site + submission bot + Pages

**Files (in `/home/shaunes/dev/oss/glinet-registry`):**
- Create: `site/{index.html,app.js,style.css}`, `.github/ISSUE_TEMPLATE/profile-submission.yml`, `.github/workflows/{pages.yml,submit-profile.yml}`

- [ ] **Step 1: Move the browse site** (from glinet-profiler, unchanged — it fetches relative `data/`)
```bash
SRC=/home/shaunes/dev/oss/glinet-profiler
cp "$SRC"/site/index.html "$SRC"/site/app.js "$SRC"/site/style.css site/
cp "$SRC"/.github/ISSUE_TEMPLATE/profile-submission.yml .github/ISSUE_TEMPLATE/profile-submission.yml
```

- [ ] **Step 2: `pages.yml`** (serves `site/` + `registry/` as `data/`)
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
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          persist-credentials: false
      - name: Assemble site (browser + registry data)
        run: |
          mkdir -p _site
          cp site/index.html site/app.js site/style.css _site/
          cp -r registry _site/data
      - uses: actions/configure-pages@45bfe0192ca1faeb007ade9deae92b16b8254a0d # v6
      - uses: actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9 # v5
        with:
          path: _site
      - id: deploy
        uses: actions/deploy-pages@cd2ce8fcbc39b97be8ca5fce6e763baed58fa128 # v5
```

- [ ] **Step 3: `submit-profile.yml`** (issue → download → `scripts/ingest.py` → PR). Adapt the glinet-profiler version: drop `setup-uv`/`uv sync` (no deps), run `python scripts/ingest.py submission.json`. Resolve the create-pull-request SHA:
```bash
git ls-remote https://github.com/peter-evans/create-pull-request refs/tags/v7 | cut -f1
```
Then:
```yaml
name: Profile submission
on:
  issues:
    types: [opened, labeled]
permissions:
  contents: write
  pull-requests: write
  issues: write
jobs:
  ingest:
    if: contains(github.event.issue.labels.*.name, 'profile-submission')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          persist-credentials: false
      - name: Extract attachment URL
        id: url
        env:
          BODY: ${{ github.event.issue.body }}
        run: |
          URL=$(printf '%s' "$BODY" | grep -oiE 'https://github\.com/[^)" ]*/files/[0-9]+/[^)" ]+\.json' | head -1)
          echo "url=$URL" >> "$GITHUB_OUTPUT"
      - name: Download + ingest
        id: ingest
        if: steps.url.outputs.url != ''
        env:
          ATT_URL: ${{ steps.url.outputs.url }}
        run: |
          curl -sL -A glinet-registry-bot "$ATT_URL" -o submission.json
          if ID=$(python scripts/ingest.py submission.json 2>err.txt); then
            echo "id=$ID" >> "$GITHUB_OUTPUT"
            echo "ok=true" >> "$GITHUB_OUTPUT"
          else
            DELIM="ERR_$(openssl rand -hex 8)"
            { echo "error<<$DELIM"; cat err.txt; echo "$DELIM"; } >> "$GITHUB_OUTPUT"
            echo "ok=false" >> "$GITHUB_OUTPUT"
          fi
      - name: Open pull request
        if: steps.ingest.outputs.ok == 'true'
        uses: peter-evans/create-pull-request@PIN_SHA_HERE # v7
        with:
          add-paths: registry
          branch: submit/${{ steps.ingest.outputs.id }}
          delete-branch: true
          title: "Add profile: ${{ steps.ingest.outputs.id }}"
          commit-message: "feat(registry): add ${{ steps.ingest.outputs.id }}"
          body: |
            Automated profile submission from #${{ github.event.issue.number }}.
      - name: Comment result on the issue
        if: always()
        uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7
        env:
          FOUND_URL: ${{ steps.url.outputs.url }}
          OK: ${{ steps.ingest.outputs.ok }}
          DEV_ID: ${{ steps.ingest.outputs.id }}
          ERR: ${{ steps.ingest.outputs.error }}
        with:
          script: |
            let body;
            if (!process.env.FOUND_URL) {
              body = "I couldn't find a `.json` attachment. Please edit the issue and drag-and-drop the file you downloaded from the launcher.";
            } else if (process.env.OK === 'true') {
              body = "✅ Validated `" + process.env.DEV_ID + "` and opened a pull request. Thanks for contributing!";
            } else {
              body = "❌ Your submission couldn't be validated:\n\n```\n" + (process.env.ERR || "unknown error") + "\n```";
            }
            await github.rest.issues.createComment({
              owner: context.repo.owner, repo: context.repo.repo,
              issue_number: context.issue.number, body,
            });
```

- [ ] **Step 4: Validate + commit**
```bash
cd /home/shaunes/dev/oss/glinet-registry
uvx --from pyyaml python -c "import yaml,glob; [yaml.safe_load(open(f)) for f in glob.glob('.github/**/*.yml',recursive=True)]; print('yaml ok')"
uvx zizmor .github/    # must be clean (SHA pins + minimal perms); grep PIN_SHA_HERE must be empty
git add -A && git -c user.name=shauneccles -c user.email=shauneccles@gmail.com commit -q -m "feat: browse site + submission bot + Pages deploy"
```

---

### Task 3: `glinet-profiler` — fetch client + repoint to the registry repo

**Files (in `/home/shaunes/dev/oss/glinet-profiler`):**
- Rewrite: `src/glinet_profiler/registry.py`
- Modify: `src/glinet_profiler/{server.py,cli.py,submit.py}`, `src/glinet_profiler/web/{app.js,index.html}`, `pyproject.toml`
- Remove: `src/glinet_profiler/data/`, `src/glinet_profiler/ingest.py`, `site/`, `scripts/build_registry.py`, `scripts/ingest_submission.py`, `.github/ISSUE_TEMPLATE/profile-submission.yml`, `.github/workflows/{submit-profile.yml,pages.yml}`, `tests/{test_site_static.py,test_ingest_submission.py}`
- Modify tests: `tests/test_registry.py`, `tests/test_capture.py`, `tests/test_server.py`, `tests/test_cli.py`, `tests/test_submit.py`

- [ ] **Step 1: Rewrite `src/glinet_profiler/registry.py`** as the fetch client
```python
"""Runtime fetch client for the live registry manifest."""

import asyncio
import json
from typing import Any

import aiohttp

DEFAULT_REGISTRY_URL = "https://glinet4.github.io/glinet4-registry/data/index.json"


async def fetch_manifest(
    url: str = DEFAULT_REGISTRY_URL, *, timeout: float = 5.0
) -> dict[str, Any] | None:
    """Fetch the live registry manifest; return None on any failure (offline-friendly)."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return None
                data: dict[str, Any] = await resp.json(content_type=None)
                return data
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
        return None


def lookup(model: str, firmware: str, manifest: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the manifest entry matching (model, firmware_version), or None."""
    if manifest is None:
        return None
    for entry in manifest.get("devices", []):
        if entry.get("model") == model and entry.get("firmware_version") == firmware:
            return entry
    return None
```

- [ ] **Step 2: `submit.py`** → `REGISTRY_REPO = "glinet4/glinet4-registry"` (one line).

- [ ] **Step 3: `server.py`** — `make_app(token, *, registry_url=registry_mod.DEFAULT_REGISTRY_URL)`; in `api_enumerate`, after producing `profile`:
```python
            manifest = await registry_mod.fetch_manifest(registry_url)
            match = registry_mod.lookup(
                profile.get("model", ""), profile.get("firmware_version", ""), manifest
            )
            await emit(
                {
                    "event": "result",
                    "profile": profile,
                    "lookup": match,
                    "registry_reachable": manifest is not None,
                    "submit_url": submit_mod.prefilled_issue_url(profile),
                }
            )
```
Thread `registry_url` through `serve(*, port=0, open_browser=True, registry_url=registry_mod.DEFAULT_REGISTRY_URL)` → `make_app(token, registry_url=registry_url)`.

- [ ] **Step 4: `cli.py`** — restore `--registry-url` (default `registry_mod.DEFAULT_REGISTRY_URL`); in `_capture_cli`:
```python
    manifest = await fetch_manifest(args.registry_url)
    known = lookup(profile.get("model", ""), profile.get("firmware_version", ""), manifest)
    print(f"\nProfile: {profile['model']} ({profile['firmware_version']}) -> {out}")
    if manifest is None:
        print("Status:  couldn't reach the registry — submit anyway (the bot dedups on the PR):")
        print(f"  open:   {prefilled_issue_url(profile)}")
        print(f"  attach: {out}  (drag it into the issue)")
    elif known:
        print("Status:  already in the registry — nothing to submit.")
    else:
        print("Status:  NEW — contribute it:")
        print(f"  open:   {prefilled_issue_url(profile)}")
        print(f"  attach: {out}  (drag it into the issue)")
```
(Import `fetch_manifest`, `lookup`; pass `--registry-url` to `serve` in the web-mode branch.)

- [ ] **Step 5: `web/app.js`** — in the result handler, branch on `registry_reachable`:
```javascript
    if (result.registry_reachable === false) {
      $("banner").innerHTML = `<div class="new">⚠️ Couldn't reach the registry — submit anyway; the bot will dedup.</div>`;
    } else {
      $("banner").innerHTML = result.lookup
        ? `<div class="known">✅ <b>${escapeHtml(profile.model)}</b> (${escapeHtml(profile.firmware_version)}) is already in the registry.</div>`
        : `<div class="new">🆕 <b>${escapeHtml(profile.model)}</b> (${escapeHtml(profile.firmware_version)}) is new — please contribute it!</div>`;
    }
    $("submit").classList.toggle("primary", !result.lookup);
```

- [ ] **Step 6: Remove the moved/dead files**
```bash
cd /home/shaunes/dev/oss/glinet-profiler
git rm -r src/glinet_profiler/data site scripts/build_registry.py scripts/ingest_submission.py \
  src/glinet_profiler/ingest.py .github/ISSUE_TEMPLATE/profile-submission.yml \
  .github/workflows/submit-profile.yml .github/workflows/pages.yml \
  tests/test_site_static.py tests/test_ingest_submission.py
rmdir scripts 2>/dev/null || true
```

- [ ] **Step 7: Fix the tests**
- `tests/test_registry.py`: drop the `build_manifest`/`rebuild`/`load_manifest` tests; keep/replace with a `lookup` test (pass a manifest dict) + a `fetch_manifest` test using a mocked aiohttp (or `aioresponses`-free: monkeypatch `aiohttp.ClientSession.get`). Minimal:
```python
from glinet_profiler.registry import lookup

MAN = {"devices": [{"id": "mt6000_4.9.0", "model": "mt6000", "firmware_version": "4.9.0"}]}
def test_lookup_match_miss_and_none():
    assert lookup("mt6000", "4.9.0", MAN)["id"] == "mt6000_4.9.0"
    assert lookup("mt6000", "9.9.9", MAN) is None
    assert lookup("mt6000", "4.9.0", None) is None
```
- `tests/test_capture.py`: unaffected by registry (it patches `_enumerate`); keep.
- `tests/test_server.py`: the fixture/test must monkeypatch `registry_mod.fetch_manifest` to return a manifest (so `lookup` works) — add `async def fake_fetch(url, *, timeout=5.0): return MAN` and `monkeypatch.setattr(registry_mod, "fetch_manifest", fake_fetch)`; assert the result event has `registry_reachable` and `lookup`.
- `tests/test_cli.py`: monkeypatch `cli_mod.fetch_manifest` (return None or a manifest) so the CLI prints the right status; assert the link + the NEW/couldn't-reach text.
- `tests/test_submit.py`: assert the URL targets `glinet4/glinet4-registry`.

- [ ] **Step 8: `pyproject.toml`** — nothing ships data now; confirm `[tool.hatch.build.targets.wheel] packages = ["src/glinet_profiler"]` no longer pulls a `data/` dir (it's deleted). No dep change (`aiohttp` already present).

- [ ] **Step 9: Verify + commit**
```bash
cd /home/shaunes/dev/oss/glinet-profiler
grep -rn "load_manifest\|build_manifest\|rebuild\|ingest\|/api/registry\|glinet_profiler/data\|glinet-profiler/issues" src/ && echo "RESIDUE" || echo "clean"
uv run ruff check . && uv run ruff format --check . && uv run mypy src
uv run pylint $(git ls-files '*.py') && uv run zizmor .github/ && uv run pytest -q
git add -A
git commit -m "feat: fetch the live registry at runtime; drop bundled data/site/bot (own repo)"
```
Expected: no residue; all gates green; the wheel (`uv build`) contains no `registry`/`data` JSON.

---

### Task 4: Publish `glinet-registry` + enable Pages

- [ ] **Step 1: Create the GitHub repo + push** (PAUSE for the user's go-ahead — public repo creation)
```bash
cd /home/shaunes/dev/oss/glinet-registry
gh repo create glinet4/glinet4-registry --public --source=. --remote=origin --push \
  --description="Community registry of GL.iNet device API profiles (data + browse + submission bot)."
```
- [ ] **Step 2: Enable Pages** (source = GitHub Actions) + trigger
```bash
gh api --method POST repos/glinet4/glinet4-registry/pages -f build_type=workflow
gh workflow run pages.yml --repo glinet4/glinet4-registry
```
- [ ] **Step 3: Confirm the live manifest** the package fetches
```bash
sleep 25
curl -s -o /dev/null -w "%{http_code}\n" https://glinet4.github.io/glinet4-registry/data/index.json   # 200
```
- [ ] **Step 4:** Enable "Allow GitHub Actions to create and approve pull requests" on `glinet-registry` (Settings → Actions) so the submission bot can open PRs.

---

## Self-Review

**Spec coverage:** registry repo (data+tooling Task 1; site+bot+pages Task 2); package fetch client + repoint + removals + frontend Task 3; publish Task 4. The `registry_reachable` degraded state is wired in server (Step 3), cli (Step 4), app.js (Step 5), and asserted in the tests (Step 7). Self-contained tooling (no package dep) in Task 1. No uncovered spec items.

**Placeholders:** `PIN_SHA_HERE` is resolved in Task 2 Step 3 (the validate step fails if it remains). No TBD.

**Type/interface consistency:** `fetch_manifest(url, *, timeout) -> dict | None` and `lookup(model, firmware, manifest) -> dict | None` are used consistently in `registry.py`, `server.py`, `cli.py`, and the tests. `device_id(model, firmware)` (registry repo) takes two strings — matching the call in `scripts/ingest.py` — distinct from the package's `device_id(device_dict)` (they are now separate codebases sharing only the JSON contract). The result event keys (`profile`, `lookup`, `registry_reachable`, `submit_url`) match between `server.py` and `app.js`. `REGISTRY_REPO` is `glinet4/glinet4-registry` in `submit.py` and asserted in `test_submit.py`.

---

## Execution Handoff
1. **Subagent-Driven (recommended)** — fresh subagent per task (`superpowers:subagent-driven-development`).
2. **Inline Execution** — checkpoints (`superpowers:executing-plans`).
