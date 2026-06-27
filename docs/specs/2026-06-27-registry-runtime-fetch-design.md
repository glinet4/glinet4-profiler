# Design: split the registry into its own repo; package fetches at runtime

- **Date:** 2026-06-27
- **Status:** Approved (design); pending plan
- **Repos:** `glinet-profiler` (code; this repo) + **`glinet-registry`** (new — data + collection + browse)

## Goal

Decouple the **registry data** (community-populated, grows continuously) from the **package** (stable code), so adding profiles never forces a package release. The launcher fetches the live registry manifest at capture time; the registry lives in its own repo with the submission bot + browse site.

## `glinet-registry` (new repo)

```
registry/
  index.json                 # manifest [{id, model, firmware_version, counts}]
  devices/<id>.json          # sanitized profiles (migrated; seeded with mt6000_4.9.0)
site/{index.html,app.js,style.css}   # the browse site (moved from glinet-profiler)
tools/registry_lib.py        # SELF-CONTAINED stdlib helpers (no glinet-profiler dependency):
                             #   device_id(model, firmware) -> slug   (ported)
                             #   validate_profile(data) -> str | None (ported from ingest)
                             #   build_manifest(profiles) -> dict      (ported)
scripts/build_manifest.py    # rebuild registry/index.json from registry/devices/*.json (+ --check)
scripts/ingest.py            # validate a submitted profile, write it, rebuild the manifest
.github/
  ISSUE_TEMPLATE/profile-submission.yml   # the form (auto-labels profile-submission)
  workflows/pages.yml         # deploy: assemble site/ + a copy of registry/ as data/
  workflows/submit-profile.yml # issue -> download attachment -> ingest -> PR (SHA-pinned create-pull-request)
  workflows/ci.yml            # ruff on tools+scripts; assert build_manifest(--check) is clean; validate every device file
  dependabot.yml              # github-actions
README.md, LICENSE (GPL-3.0), .gitignore
```

- **Self-contained tooling (the sub-decision, approved):** `tools/registry_lib.py` ports `device_id` (the slug), `validate_profile`, and `build_manifest` as ~60 lines of stdlib — the registry repo has **no dependency on the `glinet-profiler` package** (no PyPI chicken-and-egg; data maintenance never needs the launcher). The launcher and the registry repo share only the *profile JSON contract*, not code.
- **Pages** serves `site/` + `registry/` copied to `data/` → `https://shauneccles.github.io/glinet-registry/data/index.json` is the live manifest URL.
- **CI** keeps the committed `index.json` honest (rebuild-and-diff) and rejects any device file that fails `validate_profile` (identifiers/values/MAC) — a server-side publish-safety gate on contributions.

## `glinet-profiler` changes (becomes pure code)

- **`registry.py` → a fetch client:**
  - `DEFAULT_REGISTRY_URL = "https://shauneccles.github.io/glinet-registry/data/index.json"`.
  - `async fetch_manifest(url=DEFAULT_REGISTRY_URL, *, timeout=5.0) -> dict | None` — aiohttp GET; returns `None` on any failure (non-200, `ClientError`, timeout, bad JSON).
  - `lookup(model, firmware, manifest) -> dict | None` — match against the passed manifest; `manifest is None` → `None`.
  - **Removed:** `load_manifest`, `build_manifest`, `rebuild` (registry-maintenance, now in the registry repo).
- **Launcher fetches at capture time + degrades offline.** `server.api_enumerate` and `cli._capture_cli` call `fetch_manifest(registry_url)` once, then `lookup(...)`. The result/output gains **`registry_reachable: manifest is not None`** so the UI/CLI can say:
  - unreachable → "couldn't reach the registry — capture saved; submit anyway (the bot dedups on the PR)";
  - reachable + match → "already in the registry";
  - reachable + no match → "NEW — contribute it" + the submit link.
- **`--registry-url` returns** (default `DEFAULT_REGISTRY_URL`, override for testing) — threaded `cli → serve → make_app`.
- **`submit.py`** → `REGISTRY_REPO = "shauneccles/glinet-registry"`.
- **Removed from the package:** `src/glinet_profiler/data/`, `site/`, `scripts/{build_registry,ingest_submission}.py`, `src/glinet_profiler/ingest.py`, `.github/ISSUE_TEMPLATE/profile-submission.yml`, `.github/workflows/{submit-profile,pages}.yml`, and their tests (`test_site_static`, `test_ingest_submission`, the build/rebuild tests in `test_registry`). The wheel no longer ships any registry data. **Kept:** `src/glinet_profiler/web/` (the *launcher* UI), `sanitize.py`, `enumerator/`, `glinet_login.py`.
- **Tests** mock `fetch_manifest` (no network in CI): a reachable manifest → known/new; `None` → degraded. capture/cli tests updated for the manifest arg + `registry_reachable`.

## Frontend (`web/app.js`, `index.html`)

The result handler reads `registry_reachable`: false → an amber "couldn't reach the registry; submit anyway" banner with the submit action shown; true → the existing known/new banner. (Progress streaming, the rest of the UI, unchanged.)

## Ordering / migration

1. Build `glinet-registry` locally (data migrated, tooling, site, bot, CI); create the GitHub repo (user-confirmed) + push + enable Pages → the live manifest URL exists.
2. Repoint `glinet-profiler`: fetch client, drop the data/site/bot/tooling, `submit` → registry repo, update tests.
3. The launcher degrades gracefully if the registry Pages isn't live yet, so step 2 is safe even before step 1's Pages finishes building.

## Testing

Both repos hardware-free. Package: ruff/mypy --strict/pylint/zizmor + mocked-fetch tests. Registry repo: ruff on tools+scripts + the manifest-consistency + per-device validation checks in CI; the bot/pages YAML parse + zizmor-clean (SHA pins).
