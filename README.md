<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/glinet4/branding/main/assets/dark_logo.png">
    <img alt="glinet4" src="https://raw.githubusercontent.com/glinet4/branding/main/assets/logo.png" width="300">
  </picture>
</p>

# glinet4-profiler

[![PyPI](https://img.shields.io/pypi/v/glinet4-profiler)](https://pypi.org/project/glinet4-profiler/)

A small **local** web launcher that captures a GL.iNet router's API surface
(read-only), sanitizes it into a shareable **profile**, checks whether that
device + firmware is already in the registry, and lets you download it or open
a prefilled submission.

Your **password never leaves your machine**: it goes from your browser to a
local server (`127.0.0.1`) to your own router. Nothing is uploaded unless you
deliberately submit.

> **Built with AI assistance.** Most of this code was written by Claude — human-directed,
> reviewed change by change, and verified against real hardware. It's open source; read it
> and judge for yourself. The read-only-by-default behaviour and the sanitization are the
> parts to scrutinise.

> **Why a local launcher and not a public site?** GL.iNet's RPC sends no CORS
> headers, so a public browser page cannot talk to your local router. The
> enumeration therefore runs server-side in this launcher (native Python,
> which is not subject to CORS), and the UI is served locally.

## Quick start

Once published you'll be able to run it with no install:

```bash
uvx glinet4-profiler
```

From a source checkout:

```bash
uv run glinet4-profiler            # starts the launcher, opens your browser
uv run glinet4-profiler --no-browser --port 8765
```

Then enter your router URL (e.g. `http://192.168.8.1`), username (`root`), and
password, and click **Capture**. You'll get a sanitized profile, a
"already-known / new" banner, and **Download** / **Submit** actions.

## What's in the profile (and what isn't)

The published profile keeps the device **model + firmware**, non-identifying
**capability flags** (regulatory region + the software/hardware feature map), and
the **per-method API shape**: status, risk, [glinet4](https://github.com/glinet4/glinet4)
coverage, params, and a response **signature**.

The **signature** is distilled from a real response — on your machine, before
anything is written. Field **structure** and *safe* example values (numbers,
booleans, and short enum-like strings such as `"5g"` / `"ap"`) are kept because
they're the API contract; **anything that could identify you or your network is
replaced with a format label, never a real value**:

| kept verbatim | replaced with a format label |
| --- | --- |
| numbers, booleans, enums (`"5g"`) | MAC → `<mac>` · IPv4 / IPv6 → `<ipv4>` / `<ipv6>` |
| field names + nesting | timestamps → `<datetime>` |
| | passwords / keys / tokens / serials → `<secret>` |
| | SSIDs / hostnames / domains / free text → `<string>` |

**Dropped entirely:** device identifiers (`mac`, `sn`, `sn_bak`), credentials, and
every raw response body. Your real IPs, hostnames, SSIDs, MACs, and secrets are
**never published — only their format.** (`--keep-data` keeps the redacted values
*locally* for your own analysis; that output is not registry-publishable, and the
registry's validator independently rejects any MAC, serial, or raw value.)

Enumeration is strictly **read-only** (a built-in catalog tier, plus an optional
SSH read tier if you tick the box and have SSH access).

## Security

- The launcher binds **`127.0.0.1` only** and guards its API with a per-run
  session token plus a localhost host check (so no other web page can drive it).
- The password is used only to log into your router from the local process and
  is never persisted, logged, or sent anywhere remote.

## How it fits with gli4py and the registry

This package is the **capture launcher** only. The enumeration **engine** lives
inside it (`glinet_profiler/enumerator/`, originally developed in the gli4py
project) — there is **no runtime dependency on gli4py** (deps are just
`aiohttp`, `paramiko`, `libpass`).

- **[glinet4](https://github.com/glinet4/glinet4)** — the typed GL.iNet Python
  **client library**. Each captured profile records, per method, whether the
  gli4py client already wraps it ("coverage") — a lens for Python developers.
- **[glinet-registry](https://github.com/glinet4/glinet4-registry)** — the
  public, community registry of device profiles (browse site + submission bot).
  The launcher fetches its manifest to tell you whether a device is already
  known, and **Submit** opens its issue form. It releases independently of this
  package.

## Development

```bash
uv sync --all-extras --dev
uv run pytest -q
uvx prek run --all-files   # ruff, mypy, pylint, workflow lint/security (actionlint, zizmor) + hygiene hooks
```

Lint hooks are managed by [prek](https://github.com/j178/prek) (a drop-in
replacement for pre-commit) via `.pre-commit-config.yaml`; run
`uvx prek install` once to have them run automatically on every commit.

## The three repos

- **glinet4-profiler** (this repo) — the capture launcher + enumeration engine.
- **[glinet-registry](https://github.com/glinet4/glinet4-registry)** — the
  device-profile data, browse site, and submission bot.
- **[glinet4](https://github.com/glinet4/glinet4)** — the GL.iNet Python client
  library (the "coverage" lens shown in each profile).

## License

GPL-3.0-or-later.

---

Part of the **[glinet4](https://github.com/glinet4)** project — [glinet4](https://github.com/glinet4/glinet4) (Python library) · [glinet4-ha](https://github.com/glinet4/glinet4-ha) (Home Assistant) · [glinet4-profiler](https://github.com/glinet4/glinet4-profiler) · [glinet4-registry](https://github.com/glinet4/glinet4-registry)
