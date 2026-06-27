# Design: re-home the API browser into glinet-profiler (Phase 2)

- **Date:** 2026-06-27
- **Status:** Approved (design); pending implementation plan
- **Repo:** glinet-profiler (this repo)
- **Boundary:** gli4py = *implementation* (the enumerator engine + `gli4py-enumerate` CLI). glinet-profiler = *discovery + collection*: the local capture launcher (Phase 1, done) **plus** the public registry **browsing site** (this phase), both over one registry.

## 1. Scope

In scope: bring the GL.iNet API browser (currently gli4py PR #13) into this repo as the public site that renders the registry, deployed via GitHub Pages, plus a small manifest builder so the registry stays current as profiles are added.

Out of scope: changing the launcher's capture/lookup behaviour; unifying the launcher's inline renderer with the browser (a future refactor); automated PR submission; a cross-model comparison matrix. No gli4py code change.

## 2. One canonical registry

`src/glinet_profiler/data/` (`index.json` + `devices/<id>.json`) remains the **single source of truth**:

- the **launcher** reads it for lookup (already, via `registry.load_manifest`);
- the **public site** renders it (the site fetches relative `data/index.json` + `data/devices/<id>.json`);
- a new profile is added as `data/devices/<id>.json`, then the manifest is rebuilt (§3).

There is no second copy of the data. The Pages deploy (§5) copies this one directory into the published artifact.

## 3. Manifest builder (`scripts/build_registry.py` + `registry.build_manifest`)

The per-device API shape is already sanitized at capture time (`sanitize.project_report`); the registry just needs its **manifest** kept in sync with the device files.

- Add a pure function `registry.build_manifest(profiles: list[dict]) -> dict` →
  `{"devices": [{id, model, firmware_version, service_count, available_count, not_wrapped_count}]}`, where:
  - `available_count` = methods with `status` in `{available, needs_params}` (the "present" set);
  - `service_count` = services with ≥1 present method;
  - `not_wrapped_count` = present methods with `covered_by is None`.
  Entries sorted by `(model, firmware_version)`. Empty input → `{"devices": []}`.
- Add `scripts/build_registry.py`: a CLI (`python scripts/build_registry.py`, or `uv run`) that reads every `src/glinet_profiler/data/devices/*.json`, calls `build_manifest`, and writes `src/glinet_profiler/data/index.json`. Run when a profile is added; commit the result.

This is the api-browser's `build_manifest`, owned here; the sanitizing projection (`project_report`) is reused, not duplicated.

## 4. The public browser (`site/`)

Port the gli4py api-browser's `site/{index.html, app.js, style.css}` **verbatim** (they already fetch relative `data/...`):

- a **model select** (`<select id="device">`) labelled `"{model} ({firmware}) — {available} available"`;
- a filter bar (`search`, `available-only`, `not-wrapped`) composing client-side;
- services→methods rendered with **status / risk / coverage** badges; a row expands to show `params` + `schema`;
- empty/error states.

It stays its **own page**, distinct from the launcher's inline renderer (different views: multi-model browse vs single-capture result). A structural smoke test (`tests/test_site_static.py`) ports too: required element ids present, `app.js` fetches relative `data/...`, and the committed registry data is sanitized (no `mac`/`sn`/`sn_bak`, no method `value` key).

## 5. Pages deploy (`.github/workflows/pages.yml`)

A GitHub Actions Pages workflow assembles the publish artifact so the **one** canonical data dir is copied in (no committed `site/data/` duplicate):

```yaml
name: Pages
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions: { pages: write, id-token: write, contents: read }
concurrency: { group: pages, cancel-in-progress: false }
jobs:
  deploy:
    environment: { name: github-pages, url: "${{ steps.deploy.outputs.page_url }}" }
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          mkdir -p _site
          cp site/index.html site/app.js site/style.css _site/
          cp -r src/glinet_profiler/data _site/data
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with: { path: _site }
      - id: deploy
        uses: actions/deploy-pages@v4
```

Enabling Pages with source = "GitHub Actions" is a one-time repo setting (`gh api -X POST repos/<owner>/<repo>/pages -f build_type=workflow`, or Settings → Pages). Local preview: `mkdir -p _site && cp site/*.{html,js,css} _site/ && cp -r src/glinet_profiler/data _site/data && python -m http.server -d _site`.

## 6. Launcher ↔ live registry

Unchanged: the launcher's lookup uses the **bundled** registry (offline-friendly). The existing `--registry-url` flag stays the hook to point it at the deployed Pages URL later; the default is not changed now.

## 7. gli4py supersession (out-of-repo follow-up)

This phase makes gli4py **PR #13 redundant** — the api-browser now lives here. PR #13 will be **closed** (not merged) with a note pointing to glinet-profiler, so gli4py stays pure implementation. This is a GitHub action on the gli4py repo, not a change in this repo.

## 8. Testing

Hardware-free pytest (`uv run pytest`), plus the existing gates (ruff, ruff-format, mypy --strict, pylint, all already green):
- `registry.build_manifest` — counts (incl. `needs_params` present, covered excluded from not-wrapped) and the empty case.
- `scripts/build_registry.py` — writes `index.json` from a temp `devices/` dir; round-trips.
- `tests/test_site_static.py` — required ids in `index.html`; `app.js` fetches relative `data/...`; committed registry data is sanitized.
The browser's visual rendering is verified by local preview (no JS test tooling — YAGNI).

## 9. File structure (new/changed in this repo)

| File | Responsibility |
|---|---|
| `src/glinet_profiler/registry.py` | + `build_manifest(profiles)` (alongside `load_manifest`/`lookup`). |
| `scripts/build_registry.py` | CLI: rebuild `data/index.json` from `data/devices/*.json`. |
| `site/index.html`, `site/app.js`, `site/style.css` | The public browser (ported). |
| `.github/workflows/pages.yml` | Pages deploy (assembles `site/` + a copy of `data/`). |
| `tests/test_registry.py` | + `build_manifest` tests. |
| `tests/test_build_registry.py` | `build_registry` CLI test. |
| `tests/test_site_static.py` | Browser structural + data-sanitized smoke. |
