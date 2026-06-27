# Design: glinet-profiler — local capture launcher (Phase 1)

- **Date:** 2026-06-27
- **Status:** Approved (design); pending implementation plan
- **Branch:** `feat/glinet-profiler` (off `feat/api-browser` @ `4fa2e39`)
- **Relationship to gli4py:** glinet-profiler is a **new, separate project** that **depends on** gli4py. gli4py stays "implementation/execution" (the enumerator engine + `gli4py-enumerate` CLI). glinet-profiler is the product: a local capture launcher, a public registry, and a browsing/contribution site. It is developed now in a self-contained `webapp/` subdir of the gli4py repo and is structured for clean extraction to its own repo.

## 1. Why this shape (verified constraint)

A public browser page **cannot** enumerate a user's local router: the GL.iNet RPC sends **no CORS headers** (`OPTIONS` preflight → 403; `POST` response has no `Access-Control-Allow-*`), verified against a live device. CORS is browser-only, so the **native-Python** path works. Therefore capture happens in a **local launcher** (`uvx glinet-profiler`) that runs gli4py server-side and serves a local web UI. The user's password only ever travels browser → localhost → their own router; nothing is sent to any remote server.

## 2. Scope

**Phase 1 (this spec):** the **launcher** — enter credentials → read-only enumeration (server-side) → sanitized profile → lookup against the registry → **download** + **submit via prefilled GitHub PR**.

**Phase 2 (separate spec, deferred):** the public **registry browsing site** — re-home the api-browser (currently gli4py PR #13) into glinet-profiler as the Pages app that renders the registry; automated PR submission via GitHub API. **Consequence to confirm:** since the browsing site moves here, gli4py **PR #13 is superseded** (closed, not merged) rather than landing the site in gli4py.

Out of scope (both phases): any mutating/`--dangerous` enumeration; sending the password or raw report anywhere remote; a hosted backend (the launcher is local-only).

## 3. Project structure (`webapp/`, extracts to the new repo)

```
webapp/
  pyproject.toml                 # package "glinet-profiler"; deps: gli4py, aiohttp; console: gli4py-web
  README.md
  src/glinet_profiler/
    __init__.py
    cli.py                       # main(): parse args, start server, open browser
    server.py                    # aiohttp app: routes, 127.0.0.1 bind, session token
    capture.py                   # async capture(host, user, pw, *, ssh) -> dict (profile)
    sanitize.py                  # project_report(): raw report -> sanitized profile (publish-safety)
    registry.py                  # load_manifest(); lookup(model, firmware) -> Match | None
    submit.py                    # prefilled_pr_url(profile) -> str
    web/{index.html, app.js, style.css}   # the launcher UI (self-contained renderer)
    data/{index.json, devices/<id>.json}  # bundled registry seed (sanitized profiles)
  tests/{test_sanitize.py, test_registry.py, test_submit.py, test_capture.py, test_server.py}
```

Develop with the subdir as its own uv project (`uv run --project webapp ...`); its `.py` files also pass the gli4py repo-wide `ruff` + `pylint` gates. `mypy --strict` (gli4py-only target) does not check `webapp/`, but the package is fully type-annotated.

## 4. The launcher (`gli4py-web`)

`gli4py-web` (run via `uvx glinet-profiler` once published, or `uv run --project webapp gli4py-web` in dev): starts an **aiohttp** server bound to **`127.0.0.1`** on an ephemeral port, mints a random **session token**, opens the browser to `http://127.0.0.1:<port>/?t=<token>`, and serves the UI. Flags: `--port`, `--no-browser`, `--registry-url` (override the bundled registry with a live one). Ctrl-C exits.

**Routes:**
- `GET /` → `index.html`; `GET /app.js`, `/style.css` → static assets.
- `POST /api/enumerate` → body `{host, username, password, ssh}`. **Requires** the session token (header `X-Profiler-Token`) and an `Origin`/`Host` of `127.0.0.1` (anti-CSRF / DNS-rebinding). Runs capture, returns `{profile, lookup}`.
- `GET /api/registry` → the registry manifest (bundled, or fetched from `--registry-url`) so the page can render the lookup without any cross-origin fetch.

## 5. Capture (`capture.py`, server-side, read-only)

`async capture(host, username, password, *, ssh=False) -> dict`:
1. Build an `aiohttp` caller (POST JSON-RPC to `http(s)://<host>/rpc`) and reuse `gli4py.enumerator.probe.enumerate_device` at the **read-only catalog tier** (and the SSH tier if `ssh` and creds work — paramiko optional). Auth via `gli4py`'s `GLinet.login()` for the sid (websession-injected, like the CLI).
2. Serialize the `DeviceReport` with `gli4py.enumerator.report.to_json` → parse to the raw dict (device get_info + per-method records, values already redacted by the enumerator).
3. Compute `device_id` via `gli4py.enumerator.probe.device_id(raw["device"])`.
4. **Sanitize** with `sanitize.project_report(raw, device_id_str)` → the publishable profile.

Returns only the sanitized profile (the raw report with `mac`/`sn`/values never leaves the function). All of this runs in the user's local process.

## 6. Sanitizer (`sanitize.py`) — publish-safety

`project_report(raw, device_id_str)` (the same projection the api-browser uses, owned here as product logic): keep device allowlist `{model, firmware_version, vendor, device_type, hardware_version}` and per-method `{status, error_code, risk, discovered_by, covered_by, params, schema}`; **drop `mac`/`sn`/`sn_bak` and every method `value`**; keep `schema` intact (type-erased API shape). Invariant (tested): no `mac`/`sn`/`sn_bak` device value and no method-level `value` key survive.

## 7. The UI (`web/`, vanilla)

One page:
1. **Form** — host (e.g. `http://192.168.8.1`), username (default `root`), password, "try SSH (ground-truth, needs SSH access)" checkbox, **Capture** button.
2. **Progress** — a spinner/status while `POST /api/enumerate` runs.
3. **Result** — the sanitized profile rendered as services→methods with status/risk/coverage badges (a self-contained renderer for Phase 1; Phase 2 unifies it with the browsing site).
4. **Lookup banner** — from the response: "**`<model>` / `<fw>` is already in the registry** ✅ (no need to submit)" or "**New device/firmware** — please contribute!".
5. **Actions** — **Download profile** (`<id>.json`) always available; **Submit** → opens the prefilled GitHub issue (§9), shown prominently when the device is **new** (still available when already known, in case of additions).

Errors (unreachable host, bad password, paramiko missing for SSH) surface as a clear message; the form stays usable.

## 8. Lookup (`registry.py`)

`load_manifest()` reads the bundled `data/index.json` (a list of `{id, model, firmware_version, ...}`) — or, if `--registry-url` is set, the live registry's manifest. `lookup(model, firmware) -> Match | None` matches on `(model, firmware_version)`. The capture response embeds the lookup so the page renders the banner without a second round-trip.

## 9. Submission (`submit.py`) — download + prefilled issue

Primary action is **Download** the sanitized `<id>.json`. **Submit** opens a **prefilled GitHub issue** on the registry repo: `https://github.com/<owner>/<repo>/issues/new?title=<t>&body=<b>&labels=profile-submission`, where the title is `Add profile: <model> (<fw>)` and the body is a template that includes the device summary (model, firmware, available/not-wrapped counts) and **instructs the user to attach the downloaded `<id>.json`**. (An issue is used, not a prefilled file/PR URL, because sanitized profiles can exceed GitHub's ~8 KB URL-length limit; the maintainer turns the attached profile into a registry PR. **Automated PR via the GitHub API with the user's token is Phase 2.**) `submit.py` only constructs the URL — the launcher never uploads anything; the user submits deliberately in their browser.

## 10. Security & privacy

- **Bind `127.0.0.1` only** (never `0.0.0.0`/LAN). Ephemeral port.
- **Session token** required on `/api/*` + `Origin`/`Host` checked = `127.0.0.1`, to stop other web pages / DNS-rebinding from driving the local API.
- Password is read from the POST body, used only to log into the router from the local process, and is **never persisted, logged, or sent remotely**.
- Enumeration is **read-only** (catalog + SSH read tiers; no `--dangerous`).
- Output is **sanitized** (no identifiers/values). The raw report never leaves `capture()`.
- The only outbound network from the launcher is to the user's router; the only remote action is the user's deliberate Download (local) / Submit (opens GitHub in their browser).

## 11. Testing

Pure/mockable units get pytest tests (no hardware), via `uv run --project webapp pytest`:
- `sanitize.project_report` — drops `mac`/`sn`/`sn_bak` + method `value`s; keeps allowlist + method fields + schema; a publish-safety guard (no identifier value / no `value` key survives a fixture report).
- `registry.lookup` — known `(model, fw)` → Match; unknown → None; bundled manifest loads.
- `submit.prefilled_pr_url` — produces a valid GitHub URL with the encoded profile/template.
- `capture` — against a **mocked** enumerate/caller (no router): returns a sanitized profile + correct `device_id`; raw identifiers absent from the result.
- `server` — `aiohttp` test client: `/` serves the UI; `/api/enumerate` rejects a missing/wrong token and a non-localhost Origin (401/403); with a patched `capture`, returns `{profile, lookup}`.
The UI is verified by running the launcher locally.

## 12. New-repo extraction & gli4py boundary

`webapp/` is self-contained (own `pyproject.toml`, package `glinet_profiler`, console `gli4py-web`, bundled registry seed). Extraction = move `webapp/` to a new repo root; it keeps depending on published `gli4py`. gli4py is touched **only** if a small shared helper is wanted (e.g. exposing the report→dict path); Phase 1 reuses gli4py's existing public surface (`enumerate_device`, `to_json`, `device_id`) and needs **no gli4py change**. Phase 2 re-homes the browsing site and supersedes gli4py PR #13.

## 13. Naming

Project: **glinet-profiler**. Console command: **`gli4py-web`**. Python package: `glinet_profiler`. (All changeable.)
