# Reddit launch copy — recruit GL.iNet profile submissions

> All commands/links are live (`glinet-profiler` 0.1.0 on PyPI; registry public).
> Best subs: **r/GLinet** (primary), then r/homeassistant, r/selfhosted, r/homelab, r/openwrt.
> Check each sub's self-promo rules, lead with the value, and engage in the comments.
> Every technical claim below is verified against the real MT6000 capture + the code.

---

## Primary post — r/GLinet

**Title:** GL.iNet took down the 4.x API docs, so I wrote a tool that reads your router's own files to rebuild the JSON-RPC API map — open registry, looking for more models

**Body:**

GL.iNet's firmware 4.x dropped the old REST API for a **JSON-RPC** one (everything is a `POST /rpc`). The problem: the official 4.x API reference (`dev.gl-inet.com/router-4.x-api`) has been **offline for the better part of a year**, and there's no complete English documentation. So if you're scripting your router, building the Home Assistant integration, or using a client library, you're reverse-engineering an undocumented surface that's *different on every model and firmware*, by hand.

I got tired of that, so I built two things: a tool that **discovers** the actual API surface on your specific router, and an open registry that collects the (sanitized) results so we can document it as a community.

**How the discovery actually works — this is the interesting bit.**
Most attempts at this just *guess*: throw method names at `/rpc` and see what doesn't 404. That only ever finds reads, and it's noisy. This goes to the source instead — it SSHes in (read-only) and reads the router's **own** files:

- It lists the RPC handler directory (`/usr/lib/oui-httpd/rpc/`) and recovers each service's method names — `cat` for the plain-Lua handlers, `strings`/bytecode parsing for the compiled `.so` and Lua-bytecode ones.
- It parses the parameter validators in `/usr/share/gl-validator.d/` (which ship as compiled Lua bytecode) to recover each method's params.

That's **ground truth from the firmware itself** — crucially, it surfaces the **write** methods (`set_*`, `add_*`, `remove_*`) that you can *never* find by probing reads.

Then it logs in over the real RPC — the GL.iNet challenge-response: the router hands you a salt, you hash your admin password with crypt **locally**, you get a session id — and for the **read** methods only, it calls them to confirm they respond and to capture the *shape* of the response. **Write methods are recorded as "discovered" from the files and are never called**, so the scan won't touch your config. (There's an opt-in `--dangerous` flag for folks with a spare router who want to actually exercise the writes and capture their schemas — but the default never pulls that trigger.)

Everything is then **sanitized on your machine**. What gets published is the API shape — method, params, and a response *signature*: the field structure with **safe** example values kept (numbers, booleans, short enums like `"5g"`), but every MAC, IP, hostname, SSID, serial and secret replaced by a format label (`<mac>`, `<ipv4>`, `<string>`), **never a real value**. Your identifiers and raw response bodies are dropped entirely.

**What I've found so far** — one router, GL-MT6000 on firmware 4.9.0:
**63 services, 128 confirmed read methods, 300 write methods discovered straight from the firmware, plus ~230 more that exist but error out unless the feature is configured — north of 600 methods, basically none of them publicly documented.** A taste of the undocumented stuff that's just… sitting there:

- **Cellular / SMS / SIM:** `modem.set_sms`, `modem.remove_sms`, `modem.set_sim_config`, `modem.set_operator_config`, `modem.set_cell_tower`
- **WireGuard server peer management:** `wg-server.add_peer`, `wg-server.generate_publickey`, `wg-server.set_peer`
- **Firewall:** `firewall.add_port_forward`, `firewall.set_dmz`, `firewall.add_acl_rule`
- **QoS:** `qos.set_bandwidth_config`, `qos.set_packet_priority`, `qos.set_speed_limit_rule`
- **System / misc:** `system.set_password`, `system.set_airplane_mode`, `system.set_usb_config`, `timer.set_reboot` (scheduled reboot), plus AdGuard Home, Tailscale, ZeroTier, site-to-site VPN, NAS shares, multipath tunnels…

You can browse all of it — with the JSON-Schema response shapes and an **OpenRPC export** (point it at codegen for a typed client) — here: https://glinet4.github.io/glinet4-registry/

**Where you come in:** it only has my MT6000. Every model + firmware exposes a different surface, and the registry is only useful once it covers more. If you've got a GL.iNet router, adding it is ~2 minutes and **read-only**:

```
uvx glinet-profiler              # local web UI: enter IP + admin password, hit Capture, Submit
uvx glinet-profiler 192.168.8.1  # headless; prints a submission link
```

*(`uvx` ships with [uv](https://docs.astral.sh/uv/) — grab that first if you don't have it. Prefer pipx? `pipx run glinet-profiler` works too.)*

A bot validates your file and opens a pull request automatically.

**On safety — you should be skeptical of running anything against your router with your admin password, so here's exactly what it does:**
- **Read-only by default.** It reads the device's files over SSH and calls only read methods. It never calls a write/set endpoint or changes config.
- **Your password never leaves your machine.** It's used locally for the SSH read and the RPC login; nothing is uploaded unless you click submit.
- **What you submit is sanitized** — the API shape only: method names, statuses, and a response signature where every MAC / IP / hostname / SSID / serial / secret is a format label (`<mac>`, `<ipv4>`, `<string>`), never a real value. No identifiers, no raw response bodies. The registry's validator independently rejects any submission that still contains one.
- **It's open source** — read it before you run it.

Links: tool + source → https://github.com/glinet4/glinet4-profiler · browse the registry → https://glinet4.github.io/glinet4-registry/ · contribute / how it works → https://github.com/glinet4/glinet4-registry

These are my projects — happy to go deeper on the SSH parsing or the JSON-RPC quirks in the comments (e.g. the RPC backend is `fcgiwrap` with only ~4 CGI workers, so naive concurrent scanning will DoS your own router's UI — the tool reads the worker count over SSH and tunes its scan concurrency to stay one under it).

Full disclosure: most of the code was written by AI (Claude). I scoped each piece, reviewed every change, and verified it all against a real router — but the bulk is AI-generated. It's open source, so read it and judge for yourself; the reverse-engineering and the safety boundaries are the parts I cared most about getting right.

---

## Short cross-post — r/homeassistant / r/selfhosted / r/homelab / r/openwrt

**Title:** GL.iNet's 4.x JSON-RPC API is undocumented (the official docs went offline) — I built a read-only tool to map it + an open registry of what each model exposes

**Body:**

GL.iNet firmware 4.x speaks JSON-RPC over `POST /rpc`, but the official API reference has been down for ~a year, so anyone automating these routers (Home Assistant, scripts, client libs) is reverse-engineering it by hand.

My tool SSHes into the router **read-only** and reads its *own* RPC handler files + parameter validators to recover the full method list — including the `set_*`/`add_*` **write** endpoints you can't find by guessing (it discovers them from the files; it never calls them). Reads get probed to capture response **signatures** (the field structure + safe example values like enums, with identifiers/IPs/hostnames/secrets replaced by format labels — never real values); identifiers and raw response bodies are dropped before anything is published.

So far on a GL-MT6000/4.9.0: 63 services, 128 reads, **300 write methods** found in the firmware — `modem.set_sms`, `wg-server.add_peer`, `firewall.set_dmz`, `system.set_password`, none of it in any public doc.

It needs more devices. ~2 min, read-only: `uvx glinet-profiler` → Capture → Submit (a bot opens the PR).

- Browse: https://glinet4.github.io/glinet4-registry/
- Tool/source: https://github.com/glinet4/glinet4-profiler

(My projects — mostly AI-built with Claude, reviewed and hardware-tested. Open source; happy to answer anything.)

---

## One-liner (comments / Discord / forum replies)

GL.iNet 4.x's JSON-RPC API is undocumented since they pulled the official reference — `uvx glinet-profiler` SSHes in read-only, reads the router's own handler/validator files to recover the full method list (incl. the `set_*` writes, which it discovers but never calls), sanitizes it, and submits to an open registry: https://glinet4.github.io/glinet4-registry/
