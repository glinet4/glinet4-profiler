# Rich-Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each registry method entry carries a rich `signature` (structure + formats + safe example values) and, for writes, an inferred request shape — so a developer can write a gli4py wrapper from one entry with high confidence it will work.

**Architecture:** A Balanced distiller (`signature_of`) runs in the **launcher at sanitize time**, turning each probed response value into a PII-safe `signature` published in place of the type-erased `schema`. The registry's OpenRPC export and browse site consume `signature` (falling back to legacy `schema` for old profiles) and pair each `set_*` write to its `get_*` sibling to infer the request shape.

**Tech Stack:** Python 3.11+ (launcher: asyncio/aiohttp; registry tooling: stdlib only), pytest, ruff, mypy --strict, pylint, vanilla JS browse site.

**Design spec:** `glinet-profiler/docs/superpowers/specs/2026-06-29-rich-schema-design.md` (read §4.2 for the labeling rules).

## Global Constraints

- **glinet-profiler gates (all must stay green):** `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src` (strict), `uv run pylint $(git ls-files '*.py')` = **10.00/10**, `uv run pytest -q`.
- **glinet-registry gates:** `uvx ruff check .`, `uvx pytest -q`, and `python scripts/build_manifest.py --check` (committed artifacts in sync).
- **Privacy (non-negotiable):** the distiller runs on the user's machine at sanitize time; **raw response values are never published** — only the distilled `signature`.
- **Balanced labeling** (spec §4.2). Sentinels, exact strings: `<secret>` `<mac>` `<ipv4>` `<ipv6>` `<datetime>` `<string>`.
- **Numbers, booleans, and `null` are always kept verbatim.** Short enum-like strings (`^[A-Za-z0-9._:-]{1,24}$`, no spaces) are kept; identifiers and personal-keyed/free-text strings are labeled.
- **Published `signature` replaces type-erased `schema`.** The registry reads `signature`, falling back to `schema` for legacy profiles (transitional).
- Commit messages end with the repo's existing trailer style; one task = one commit.

## File Structure

**glinet-profiler**
- `src/glinet_profiler/enumerator/signature.py` — NEW: `signature_of` + format/key helpers.
- `src/glinet_profiler/enumerator/models.py` — `MethodReport.schema` → `signature`.
- `src/glinet_profiler/enumerator/probe.py` — `_report`/`_discovered` produce `signature`.
- `src/glinet_profiler/enumerator/redact.py` — remove now-unused `schema_of`.
- `src/glinet_profiler/sanitize.py` — `_METHOD_FIELDS`: `schema` → `signature`.
- `tests/` — NEW `test_enum_signature.py`; update `test_sanitize.py`, `test_enum_probe.py`, `test_enum_redact.py`, `test_enum_report.py` (any `schema` refs → `signature`).

**glinet-registry**
- `tools/registry_lib.py` — `to_openrpc`: `_signature_to_schema` + `examples`; `_pair_write` (get/set, `x-inferred-from`).
- `site/app.js`, `site/style.css` — render `signature` + inferred request block.
- `tests/test_registry_lib.py` — signature schema, examples, pairing.
- `registry/devices/mt6000_4.9.0.json` + artifacts — re-captured (Task 6).

---

## Task 1: `signature_of` distiller

**Files:**
- Create: `glinet-profiler/src/glinet_profiler/enumerator/signature.py`
- Test: `glinet-profiler/tests/test_enum_signature.py`

**Interfaces:**
- Produces: `signature_of(value: object) -> object` — deep-distills a value to a publishable signature. Consumed by `probe._report` (Task 2) and exercised by the registry (Tasks 3-5).

- [ ] **Step 1: Write the failing tests**

`glinet-profiler/tests/test_enum_signature.py`:
```python
"""Tests for the Balanced rich-schema distiller."""
# pylint: disable=missing-function-docstring

from glinet_profiler.enumerator.signature import signature_of


def test_keeps_numbers_bools_null():
    src = {"period_seconds": 86400, "enable": False, "x": None}
    assert signature_of(src) == {"period_seconds": 86400, "enable": False, "x": None}


def test_keeps_enum_like_strings():
    src = {"band": "5g", "mode": "ap", "state": "connected", "ver": "1.2.3"}
    assert signature_of(src) == src  # short, no-space tokens are the API contract


def test_labels_identifiers():
    src = {"mac": "94:83:C4:AA:BB:CC", "ip": "192.168.8.1", "created": "2026-06-29T10:00:00"}
    assert signature_of(src) == {"mac": "<mac>", "ip": "<ipv4>", "created": "<datetime>"}


def test_labels_secret_and_personal_and_freetext():
    src = {"password": "hunter2", "ssid": "MyWifi", "blurb": "hello there world"}
    assert signature_of(src) == {"password": "<secret>", "ssid": "<string>", "blurb": "<string>"}


def test_personal_key_beats_enum():
    # "Router-AP" looks enum-like but sits under a personal key -> labeled
    assert signature_of({"name": "Router-AP"}) == {"name": "<string>"}


def test_nested_dict_and_list():
    src = {"clients": [{"mac": "94:83:C4:AA:BB:CC", "band": "5g", "name": "Phone"}]}
    assert signature_of(src) == {"clients": [{"mac": "<mac>", "band": "5g", "name": "<string>"}]}


def test_empty_list_and_top_level_scalar():
    assert signature_of({"items": []}) == {"items": []}
    assert signature_of("5g") == "5g"
    assert signature_of(42) == 42
```

- [ ] **Step 2: Run the tests, verify they fail**

Run: `cd glinet-profiler && uv run pytest tests/test_enum_signature.py -q`
Expected: FAIL — `ModuleNotFoundError: ...enumerator.signature`.

- [ ] **Step 3: Implement `signature.py`**

`glinet-profiler/src/glinet_profiler/enumerator/signature.py`:
```python
"""Distill a probed response value into a publishable signature.

Balanced labeling (see docs/superpowers/specs/2026-06-29-rich-schema-design.md §4.2): numbers,
booleans, null, and short enum-like strings are kept verbatim (the API contract); identifiers and
personal/free-text strings are replaced with a format label so a developer learns the type/format
without the submitter's data. Runs at sanitize time on the user's machine; raw values are never
published — only this distilled result.
"""

import re

from .redact import key_is_secret  # shared secret-key matcher (renamed export, Task 1 Step 3a)

_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HEXCOLON = re.compile(r"^[0-9A-Fa-f:]+$")
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}")  # ISO-8601 date or datetime
_ENUM = re.compile(r"^[A-Za-z0-9._:-]{1,24}$")
_PERSONAL = (
    "ssid", "name", "hostname", "host", "comment", "description", "desc", "note", "label",
    "path", "url", "email", "domain", "user", "username", "server", "endpoint", "peer",
    "address", "addr",
)


def _key_is_personal(key: str) -> bool:
    low = key.lower()
    return any(low == t or low.endswith("_" + t) or low.startswith(t + "_") for t in _PERSONAL)


def _label_str(value: str, key: str | None) -> str:
    if key is not None and key_is_secret(key):
        return "<secret>"
    if _MAC.match(value):
        return "<mac>"
    if _IPV4.match(value):
        return "<ipv4>"
    if value.count(":") >= 2 and _HEXCOLON.match(value):
        return "<ipv6>"
    if _DATETIME.match(value):
        return "<datetime>"
    if key is not None and _key_is_personal(key):
        return "<string>"
    if _ENUM.match(value):
        return value  # enum-like / mode / version — kept as the API contract
    return "<string>"


def signature_of(value: object, _key: str | None = None) -> object:
    """Distill ``value`` into a publishable signature: structure + formats + safe example scalars."""
    if isinstance(value, dict):
        return {k: signature_of(v, _key=k) for k, v in value.items()}
    if isinstance(value, list):
        return [signature_of(value[0])] if value else []
    if isinstance(value, str):
        return _label_str(value, _key)
    return value  # int / float / bool / None kept verbatim
```

- [ ] **Step 3a: Export `key_is_secret` from `redact.py`**

In `glinet-profiler/src/glinet_profiler/enumerator/redact.py`, rename the private helper to a public one so both modules share it. Change `def _key_is_secret(key: str)` → `def key_is_secret(key: str)`, and update its one caller in `_redact_str` (`if key is not None and _key_is_secret(key):` → `key_is_secret(key)`).

- [ ] **Step 4: Run the tests, verify they pass**

Run: `cd glinet-profiler && uv run pytest tests/test_enum_signature.py tests/test_enum_redact.py -q`
Expected: PASS (signature tests + redact tests still green after the rename).

- [ ] **Step 5: Gates + commit**

Run: `uv run ruff check . && uv run ruff format . && uv run mypy src && uv run pylint $(git ls-files '*.py') | grep rated`
```bash
git add src/glinet_profiler/enumerator/signature.py src/glinet_profiler/enumerator/redact.py tests/test_enum_signature.py
git commit -m "feat(enum): Balanced rich-schema distiller (signature_of)"
```

---

## Task 2: Publish `signature` in place of `schema`

**Files:**
- Modify: `glinet-profiler/src/glinet_profiler/enumerator/models.py`, `probe.py`, `redact.py`, `sanitize.py`
- Test: update `glinet-profiler/tests/test_sanitize.py`, `test_enum_probe.py`, `test_enum_redact.py`

**Interfaces:**
- Consumes: `signature_of` (Task 1).
- Produces: published profile method records carry `signature` (object|None), no `schema`. `MethodReport.signature` replaces `MethodReport.schema`.

- [ ] **Step 1: Write/adjust the failing test (sanitize publishes signature)**

In `glinet-profiler/tests/test_sanitize.py`, change the `RAW` fixture's `get_info` method record key `"schema": {"model": "str", "mac": "str"}` → `"signature": {"model": "mt6000", "mac": "<mac>"}`, and update `test_keeps_allowlist_and_method_fields`:
```python
    # signature is kept intact (formats + safe examples are the published API shape)
    assert m["signature"] == {"model": "mt6000", "mac": "<mac>"}
    assert "schema" not in m
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd glinet-profiler && uv run pytest tests/test_sanitize.py -q`
Expected: FAIL — `signature` not in the projected fields (still `schema`).

- [ ] **Step 3: Rename the field end-to-end**

`models.py` — in `MethodReport`, change `schema: object | None = None` to `signature: object | None = None` (keep the same position/ordering; remove the old `schema` field).

`probe.py` — in `_report`, replace:
```python
            schema=schema_of(value) if value is not None else None,
```
with:
```python
            signature=signature_of(value) if value is not None else None,
```
and in `_discovered`, change `schema=None,` → `signature=None,`. Update the import: drop `schema_of` from the `.redact` import, add `from .signature import signature_of`.

`redact.py` — remove the now-unused `schema_of` function.

`sanitize.py` — in `_METHOD_FIELDS`, change `"schema"` → `"signature"`. Update the module docstring line that says "status/risk/coverage/params/schema" → "…/params/signature".

- [ ] **Step 4: Sweep remaining `schema` references in the launcher**

Run: `cd glinet-profiler && grep -rn "schema_of\|\.schema\|\"schema\"\|'schema'" src tests`
For each hit in `tests/test_enum_probe.py`, `test_enum_redact.py`, `test_enum_report.py`: replace `schema` assertions with `signature` equivalents (e.g. `m.schema` → `m.signature`; remove the two `schema_of` tests from `test_enum_redact.py`). The OpenRPC/registry `schema` lives in the *other* repo — ignore those.

- [ ] **Step 5: Run all gates, verify green**

Run: `uv run pytest -q && uv run ruff check . && uv run ruff format . && uv run mypy src && uv run pylint $(git ls-files '*.py') | grep rated`
Expected: all pass, pylint 10.00.

- [ ] **Step 6: Commit**
```bash
git add -A
git commit -m "feat(sanitize): publish rich signature in place of type-erased schema"
```

---

## Task 3: OpenRPC consumes `signature` (schema + examples)

**Files:**
- Modify: `glinet-registry/tools/registry_lib.py`
- Test: `glinet-registry/tests/test_registry_lib.py`

**Interfaces:**
- Consumes: profile method records with `signature` (Task 2) or legacy `schema`.
- Produces: OpenRPC method `result.schema` (JSON Schema with `format`/`examples`) derived from `signature`.

- [ ] **Step 1: Write the failing test**

In `glinet-registry/tests/test_registry_lib.py`, add:
```python
def test_to_openrpc_uses_signature_for_schema_and_examples():
    profile = {
        "id": "x_1", "model": "x", "firmware_version": "1",
        "services": {"wifi": {"get_status": {
            "status": "available", "risk": "read", "discovered_by": "catalog",
            "covered_by": None, "params": None,
            "signature": {"band": "5g", "channel": 36, "gateway": "<ipv4>"},
        }}},
    }
    m = {x["name"]: x for x in to_openrpc(profile)["methods"]}["wifi.get_status"]
    schema = m["result"]["schema"]
    assert schema["type"] == "object"
    assert schema["properties"]["channel"] == {"type": "integer", "examples": [36]}
    assert schema["properties"]["band"] == {"type": "string", "examples": ["5g"]}
    assert schema["properties"]["gateway"] == {"type": "string", "format": "ipv4"}
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd glinet-registry && uvx pytest tests/test_registry_lib.py::test_to_openrpc_uses_signature_for_schema_and_examples -q`
Expected: FAIL (still using `_to_json_schema` on `schema`).

- [ ] **Step 3: Implement `_signature_to_schema` and use it**

In `glinet-registry/tools/registry_lib.py`, add:
```python
_LABEL_FORMAT = {
    "<ipv4>": "ipv4", "<ipv6>": "ipv6", "<mac>": "mac", "<datetime>": "date-time",
}


def _signature_to_schema(sig: Any) -> dict[str, Any]:
    """Convert a distilled signature node into a JSON Schema fragment (with format/examples)."""
    if isinstance(sig, dict):
        return {"type": "object", "properties": {k: _signature_to_schema(v) for k, v in sig.items()}}
    if isinstance(sig, list):
        return {"type": "array", "items": _signature_to_schema(sig[0]) if sig else {}}
    if isinstance(sig, bool):
        return {"type": "boolean", "examples": [sig]}
    if isinstance(sig, int):
        return {"type": "integer", "examples": [sig]}
    if isinstance(sig, float):
        return {"type": "number", "examples": [sig]}
    if sig is None:
        return {}
    if isinstance(sig, str):
        if sig in _LABEL_FORMAT:
            return {"type": "string", "format": _LABEL_FORMAT[sig]}
        if sig in ("<secret>", "<string>"):
            return {"type": "string"}
        return {"type": "string", "examples": [sig]}  # kept enum value
    return {}
```
Then in `to_openrpc`, replace the result-schema line:
```python
            schema = rec.get("schema")
            ...
                "result": {"name": "result", "schema": _to_json_schema(schema) if schema else {}},
```
with signature-preferred, schema-fallback:
```python
            sig = rec.get("signature")
            if sig is not None:
                result_schema = _signature_to_schema(sig)
            else:  # legacy profile: fall back to the type-erased schema
                schema = rec.get("schema")
                result_schema = _to_json_schema(schema) if schema else {}
            ...
                "result": {"name": "result", "schema": result_schema},
```

- [ ] **Step 4: Run tests, verify green**

Run: `cd glinet-registry && uvx pytest tests/test_registry_lib.py -q`
Expected: PASS (new test + existing schema-fallback test still pass).

- [ ] **Step 5: Gates + commit**
```bash
uvx ruff check . && uvx pytest -q
git add tools/registry_lib.py tests/test_registry_lib.py
git commit -m "feat(openrpc): build result schema + examples from signature"
```

---

## Task 4: get/set pairing infers the write request shape

**Files:**
- Modify: `glinet-registry/tools/registry_lib.py`
- Test: `glinet-registry/tests/test_registry_lib.py`

**Interfaces:**
- Consumes: a profile's services (to find a write's `get_*` sibling).
- Produces: OpenRPC write methods carry `params` derived from the sibling read's signature, tagged `x-inferred-from`.

- [ ] **Step 1: Write the failing test**
```python
def test_to_openrpc_pairs_write_request_shape_from_get_sibling():
    profile = {
        "id": "x_1", "model": "x", "firmware_version": "1",
        "services": {"tor": {
            "get_config": {"status": "available", "risk": "read", "covered_by": None,
                           "signature": {"enable": False, "manual": True}},
            "set_config": {"status": "discovered", "risk": "write", "covered_by": None,
                           "params": [], "signature": None},
        }},
    }
    m = {x["name"]: x for x in to_openrpc(profile)["methods"]}["tor.set_config"]
    names = {p["name"] for p in m["params"]}
    assert names == {"enable", "manual"}
    assert m["x-inferred-from"] == "tor.get_config"
    assert m["params"][0]["schema"]  # has a JSON-schema fragment from the read
```

- [ ] **Step 2: Run it, verify it fails**

Run: `cd glinet-registry && uvx pytest tests/test_registry_lib.py::test_to_openrpc_pairs_write_request_shape_from_get_sibling -q`
Expected: FAIL (`set_config` params come from `rec["params"]` = `[]`, no `x-inferred-from`).

- [ ] **Step 3: Implement pairing**

In `registry_lib.py`, add:
```python
_WRITE_VERBS = ("set", "add", "update", "create", "del", "remove", "clear")


def _paired_read(service_methods: dict[str, Any], method: str) -> tuple[str, Any] | None:
    """For a write `<verb>_<noun>`, return (read_name, read_signature) of its get_* sibling, if any."""
    verb, _, noun = method.partition("_")
    if verb not in _WRITE_VERBS or not noun:
        return None
    for cand in (f"get_{noun}", f"get_{noun}_list", f"get_{noun}_config", f"get_{noun}_info"):
        rec = service_methods.get(cand)
        if rec and isinstance(rec.get("signature"), dict):
            return cand, rec["signature"]
    return None
```
In `to_openrpc`'s method loop, after computing the base `entry`, add (the loop already has `service` and `method` in scope; pass `profile["services"][service]`):
```python
            if rec.get("risk") == "write" and not entry["params"]:
                pair = _paired_read(profile["services"][service], method)
                if pair:
                    read_name, read_sig = pair
                    entry["params"] = [
                        {"name": k, "schema": _signature_to_schema(v)} for k, v in read_sig.items()
                    ]
                    entry["x-inferred-from"] = f"{service}.{read_name}"
```

- [ ] **Step 4: Run tests, verify green**

Run: `cd glinet-registry && uvx pytest tests/test_registry_lib.py -q`

- [ ] **Step 5: Gates + commit**
```bash
uvx ruff check . && uvx pytest -q
git add tools/registry_lib.py tests/test_registry_lib.py
git commit -m "feat(openrpc): infer write request shape from the get_* sibling"
```

---

## Task 5: Browse site renders signatures + inferred request

**Files:**
- Modify: `glinet-registry/site/app.js`, `glinet-registry/site/style.css`

**Interfaces:**
- Consumes: a device profile's method records (`signature`, `risk`); the device's service map (to find a write's `get_*` sibling, mirroring Task 4's heuristic in JS).

- [ ] **Step 1: Render the signature in the method detail**

In `site/app.js`, `methodRow(service, method, rec)`, replace the detail block that serializes `{params, schema}`:
```javascript
  if (rec.params || rec.schema) {
    const body = JSON.stringify({ params: rec.params, schema: rec.schema }, null, 2);
    detail = `<pre class="detail">${escapeHtml(body)}</pre>`;
  }
```
with a signature-aware version that also shows the inferred request shape for writes:
```javascript
  const parts = [];
  if (rec.signature != null) parts.push("// response signature\n" + JSON.stringify(rec.signature, null, 2));
  const inferred = rec.risk === "write" ? inferredRequest(service, method) : null;
  if (inferred) parts.push(`// request shape (inferred from ${inferred.from})\n` + JSON.stringify(inferred.shape, null, 2));
  else if (rec.params && rec.params.length) parts.push("// params\n" + JSON.stringify(rec.params, null, 2));
  if (parts.length) detail = `<pre class="detail">${escapeHtml(parts.join("\n\n"))}</pre>`;
```

- [ ] **Step 2: Add the `inferredRequest` helper (mirror Task 4's heuristic)**

Near the top of `site/app.js` (after `escapeHtml`):
```javascript
const WRITE_VERBS = new Set(["set", "add", "update", "create", "del", "remove", "clear"]);

function inferredRequest(service, method) {
  const us = method.indexOf("_");
  if (us < 0) return null;
  const verb = method.slice(0, us), noun = method.slice(us + 1);
  if (!WRITE_VERBS.has(verb) || !noun) return null;
  const methods = current.services[service] || {};
  for (const cand of [`get_${noun}`, `get_${noun}_list`, `get_${noun}_config`, `get_${noun}_info`]) {
    const r = methods[cand];
    if (r && r.signature && typeof r.signature === "object") return { from: `${service}.${cand}`, shape: r.signature };
  }
  return null;
}
```

- [ ] **Step 3: Verify in a browser (manual smoke)**

Run a local static server in `site/` against a re-captured device (Task 6) or a hand-made fixture with a `signature`; confirm: response signature renders, and a `set_*` whose `get_*` exists shows "request shape (inferred from …)". No JS errors in the console.

- [ ] **Step 4: Commit**
```bash
git add site/app.js site/style.css
git commit -m "feat(site): show response signature + inferred write request shape"
```

---

## Task 6: Re-capture the MT6000 and regenerate artifacts (requires hardware)

**Files:**
- Modify: `glinet-registry/registry/devices/mt6000_4.9.0.json`, `registry/index.json`, `registry/openrpc/mt6000_4.9.0.openrpc.json`

**Interfaces:**
- Consumes: a live GL.iNet device reachable via `.env` (the MT6000) + the Task 1-2 launcher.

- [ ] **Step 1: Capture with the new launcher**

From `glinet-profiler` with `.env` loaded:
```bash
GLINET_PASSWORD="$GLI_ROUTER_PASSWORD" uv run glinet-profiler "$GLI_ROUTER_IP" \
  --username "$GLI_ROUTER_USERNAME" -o /tmp/mt6000_sig.json
```
Verify the profile now carries `signature` (not `schema`) and is PII-free:
```bash
python3 -c "import json,re; r=open('/tmp/mt6000_sig.json').read(); d=json.loads(r); \
  m=d['services']['system']['get_info']; \
  print('has signature:', 'signature' in m, '| has schema:', 'schema' in m); \
  print('no ipv4:', not re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r)); \
  print('no mac:', not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', r))"
```
Expected: `has signature: True | has schema: False`, `no ipv4: True`, `no mac: True`.

- [ ] **Step 2: Ingest + regenerate**

From `glinet-registry`:
```bash
python scripts/ingest.py /tmp/mt6000_sig.json
python scripts/build_manifest.py --check && echo "in sync"
uvx pytest -q
```
Expected: ingest OK, in sync, tests green. Spot-check `registry/openrpc/mt6000_4.9.0.openrpc.json` — methods now have `examples`/`format`, and a `set_*` carries `x-inferred-from`.

- [ ] **Step 3: Commit**
```bash
git add registry/
git commit -m "data: re-capture mt6000 with rich signatures"
```

---

## Self-Review

- **Spec coverage:** §4 distiller → Tasks 1-2; §4.4 data model → Task 2; §5 pairing → Task 4; §5.2 OpenRPC examples → Task 3, browse → Task 5; §3 privacy boundary (distiller in launcher) → Task 1-2; §7 deferred items not built (correct). ✓
- **Type consistency:** `signature_of` (Task 1) → `MethodReport.signature` (Task 2) → profile `signature` field → `_signature_to_schema` / `_paired_read` (Tasks 3-4) → `inferredRequest` (Task 5). Names consistent across tasks. ✓
- **Transition safety:** registry reads `signature` else legacy `schema` (Task 3) so the build stays green before Task 6's re-capture. ✓
- **Placeholder scan:** every code step carries full code; no TBD/TODO. ✓
