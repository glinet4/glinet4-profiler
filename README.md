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

Run it with no install:

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
- **[glinet4-registry](https://github.com/glinet4/glinet4-registry)** — the
  public, community registry of device profiles (browse site + submission bot).
  The launcher fetches its manifest to tell you whether a device is already
  known, and **Submit** opens its issue form. It releases independently of this
  package.

## Contributing fixtures for the library's golden tests

Beyond a publishable profile, you can capture a **fixture set**: real (but
sanitized) raw RPC responses, one JSON file per `service.method`, for the
[glinet4](https://github.com/glinet4/glinet4) library's golden tests.

```bash
uv run glinet4-profiler 192.168.8.1 --fixtures-out ./fixtures
```

This is a separate, always-read-only capture (it never HTTP-calls a
write/dangerous endpoint, regardless of `--dangerous`) that writes
`./fixtures/<model>_<firmware>/<service>.<method>.json` — the sanitized raw
`result` for every successfully-probed read method — plus a `manifest.json`
recording provenance: model, firmware, capture date, profiler version, and
the sanitizer's version + ruleset hash.

Sanitization here is **stricter, and different**, from the profile flow
above — raw response *values* survive on purpose (the library's tests need
real API shapes to assert against):

- MAC addresses are pseudonymized **consistently**: the same real MAC always
  maps to the same fake MAC everywhere in the set, so cross-payload identity
  (e.g. a client's MAC in both `clients.get_list` and
  `lan.get_static_bind_list`) survives.
- SSIDs and hostnames become `ssid-N` / `host-N` tokens (also consistent
  within the set).
- Any field whose key looks like a secret (`password`, `key`, `token`,
  `secret`, `nonce`, `salt`, ...) is nulled out.
- Public IPs are replaced with documentation-range addresses (`192.0.2.0/24`,
  `2001:db8::/32`); your **LAN** addresses (e.g. `192.168.x.x`) are kept
  verbatim — the local topology is the fixture's actual test value.
- `host:port` / `[ipv6]:port` compounds (e.g. a WireGuard peer's `end_point`)
  are parsed: the address half follows the MAC/IP rules above, the port is
  kept. A bare-domain `endpoint`/`end_point` with no `:port` is tokenized
  like any other host field.
- The personal-field vocabulary (`ssid`, `name`, `hostname`, `user`,
  `email`, `domain`, ...) is shared with the profile flow's signature
  labeler, so a key personal there is never missed here — either
  pseudonymized to a stable token or nulled, whichever leaves nothing to
  re-identify.
- Blocklist keys (`blacklist`, `whitelist`, `black_white_list`, `block_list`,
  `allow_list`, `deny_list`, `website`/`site` and their plurals) are in the
  same host-token vocabulary, so a **JSON array of bare domains** under one
  of them — e.g. GL.iNet's own `black_white_list` service — is tokenized
  element-by-element. `whitelist` is included even though
  `firewall.get_wan_access.whitelist` is a real list of *IPs*, not domains:
  the IP rule runs before this one, so an IP-shaped element is claimed there
  first and is never mistaken for a hostname.
- `zonename`/`timezone` (`system.get_timezone_config`) are nulled — an IANA
  zone name like `Australia/Sydney` is city-level location. Siblings
  (offsets, booleans) survive, so the response shape is kept.
- Cellular services (`modem.*`, `sms-forward.*`) — SMS bodies,
  IMEI/ICCID/IMSI/MSISDN, phone numbers (national-format ones included), and
  cell-tower identifiers (MCC/MNC/LAC/CID/PCI, which geolocate the device via
  public tower databases) — get the strictest treatment: every string **and
  numeric** value is nulled unless explicitly whitelisted as a safe
  structural/status field. It's the highest-risk surface in the catalog, so
  it defaults to nothing surviving rather than relying on a rule catching
  every field GL.iNet's firmware might expose.
- **Any string containing a newline is nulled**, whatever its key. Free text —
  a custom hosts file, an inline `.ovpn` config with its PEM blocks and
  provider hostname, a log dump, an AT-command transcript — carries MACs, IPs,
  hostnames and key material *mid-line*, where a whole-value rule cannot see
  them. Rather than keep patching the instances, the rule is stated at the
  level of the class: a newline means free text, and free text is nulled. The
  key survives with a `null` value, so the response shape is kept. On the
  reference mt6000/4.9.0 capture this costs exactly two strings
  (`dns.get_host.content`, `wg-server.get_config.amnezia`), neither of which
  the library reads.
- MACs and public IPs are also scrubbed **mid-string**, through the same
  pseudonym maps as standalone values — so a MAC in a status line and the same
  MAC in a `clients.get_list` key land on the *same* fake MAC.
- The `logread` service is **excluded from emission entirely** — its methods
  (`get_system_log`, `get_kernel_log`, ...) return raw free-text log dumps with
  no golden-test value. The multi-line rule above would null them anyway; the
  exclusion is kept as defence in depth (it fails differently: this one is
  keyed on the service, that one on the value). No `logread.*.json` file is
  ever written.

Every rule above is unit-tested (`tests/test_sanitize.py`), but **review the
output before committing it anywhere** — you know your own network better
than an automated tool does. Once you're happy with it, open a PR against the
library's `tests/fixtures/` with the new `<model>_<firmware>/` directory.

### What a fixture set still tells someone about you

Sanitization removes credentials and identifiers; it does not make the set
anonymous. A fixture set is **your device's configuration**, and you are
attributable — the PR that contributes it has your name on it. Specifically:

- **Port-forwarding rules keep their real ports and LAN targets.** A
  `firewall.get_port_forward_list` fixture emits the actual external port,
  protocol and internal destination of every rule you have (the rule's `name`
  is tokenized, the LAN IP is kept as topology). `32400 → 192.168.8.x` says
  you run Plex; `22`, `3389` or `8006` say rather more. This is deliberate —
  the rule shape *is* the golden-test value — but it is a statement about your
  network, published under your name. **Read the port-forward fixture before
  you open the PR**, and delete it from the set if you would rather not say.
- **Dict keys that aren't MACs are not pseudonymized.** MAC-keyed dicts (e.g.
  `clients.get_list`) have their keys pseudonymized like any other MAC, but a
  response keyed by *hostname* or *IP* would keep those keys verbatim — only
  values are tokenized. No GL.iNet method in the reference capture is shaped
  that way (0 instances), so this is a latent gap rather than a live one; if a
  future firmware returns a hostname-keyed map, its keys will leak until a
  rule covers them.
- **`tzoffset` is kept on purpose.** `zonename`/`timezone` are nulled (a zone
  name is city-level location), but the numeric UTC offset stays: it is
  already derivable from the `localtime - timestamp` pair in the same
  response, which the fixture keeps, so nulling it would cost shape and buy
  nothing. It narrows you to a longitude band, not a city.
- **Single-line free text under an unrecognized key still passes through
  verbatim.** The multi-line rule only fires on a newline; the key-vocabulary
  rules (SSID/host/blocklist tokens, secret/personal/cellular nulling) only
  fire on a key the sanitizer knows. An array — or a single-line,
  comma/space-joined list — of bare domains or URLs under a key outside both
  vocabularies is neither shape, so nothing claims it and it is emitted
  as-is. **Read the emitted files before opening a PR**, and eyeball
  services whose whole purpose is a domain list, e.g. `parental-control`,
  `black_white_list`, `adguardhome` — anything under an unfamiliar key that
  looks like a household's browsing policy rather than router state.
- **Public IPs inside a vendor-shipped catalog get doc-range-substituted
  like any other public IP** (`dns.get_info`'s built-in DoH/DoT resolver
  list is the real example — Control D's, NextDNS's, etc. server
  addresses). That's not a leak — it's not your data — but don't be
  surprised to see Cloudflare's public resolver address read back as
  `192.0.2.7`: the sanitizer can't tell "vendor constant" apart from "your
  address" by shape alone, so it treats both the same way.

**Caveat on MAC/IP/token pseudonym numbering:** the `-N` suffix each fake
MAC/IP/SSID/token gets is assigned **positionally** — in the order that real
value is first *encountered* while walking the capture (methods sorted by
`(service, method)`, then each payload's own key order). Two captures of the
same physical device can walk fields in a different order (the router's own
JSON key order isn't guaranteed stable across firmware/API calls), so the
same real MAC/SSID/etc. can land on a *different* fake index between two
regenerations of "the same" fixture set. A diff between two fixture sets can
therefore look noisier than the underlying device state actually changed —
don't read positional-index churn alone as a meaningful change.

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
- **[glinet4-registry](https://github.com/glinet4/glinet4-registry)** — the
  device-profile data, browse site, and submission bot.
- **[glinet4](https://github.com/glinet4/glinet4)** — the GL.iNet Python client
  library (the "coverage" lens shown in each profile).

## License

GPL-3.0-or-later.

---

Part of the **[glinet4](https://github.com/glinet4)** project — [glinet4](https://github.com/glinet4/glinet4) (Python library) · [glinet4-ha](https://github.com/glinet4/glinet4-ha) (Home Assistant) · [glinet4-profiler](https://github.com/glinet4/glinet4-profiler) · [glinet4-registry](https://github.com/glinet4/glinet4-registry)
