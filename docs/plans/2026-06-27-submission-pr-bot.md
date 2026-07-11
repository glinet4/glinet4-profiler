# Automated profile-submission PR bot — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let contributors submit a captured profile via a GitHub issue form; a workflow validates the attached file and opens a reviewed PR adding it to the registry.

**Architecture:** Testable validate/ingest logic lives in the package (`glinet_profiler.ingest`), wrapped by a thin `scripts/ingest_submission.py` CLI (mirrors the `rebuild` pattern). A GitHub Actions workflow downloads the issue's `.json` attachment, runs the CLI, and opens a PR via `peter-evans/create-pull-request` (SHA-pinned). The launcher's Submit points at the issue form.

**Tech Stack:** Python 3.11 (+ gli4py `device_id`), pytest, ruff, mypy, pylint, GitHub Actions (issue form + workflow), uv.

## Global Constraints

- Spec: `docs/specs/2026-06-27-submission-pr-bot-design.md`.
- Repo: **glinet-profiler**. Commands via uv (`uv run pytest`, `uv run ruff check .`, `uv run mypy src`, `uv run pylint <files>`). Gates: ruff, ruff-format, `mypy --strict` (`files=["src"]` — checks `src/`, not `scripts/`), pylint (over `git ls-files '*.py'`), pytest.
- **Testable logic in the package** (`src/glinet_profiler/ingest.py`); `scripts/ingest_submission.py` is a thin CLI (so tests import the package, not `scripts/`). (Spec §3 named the script; the logic is in the package per the established `rebuild` pattern — same coverage.)
- **Publish-safety / validation:** a submission is rejected if it has a device identifier key (`mac`/`sn`/`sn_bak`), any method-level `value` key, or a MAC-hex value (`(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}`). The registry filename is the **recomputed** slug `device_id({"model":…, "firmware_version":…})` — never submitted free text (no path traversal).
- **"Present"** counts unchanged; the manifest is rebuilt via `registry.rebuild`.
- The repo's pylint config disables `import-outside-toplevel`/`too-many-locals`/`duplicate-code` but keeps `missing-function-docstring`; new test files start with `# pylint: disable=missing-function-docstring,redefined-outer-name`.
- Workflows use the bumped majors (`actions/checkout@v7`, `astral-sh/setup-uv@v7`); third-party `peter-evans/create-pull-request` is **pinned to a commit SHA**.

## File Structure

| File | Responsibility |
|---|---|
| `src/glinet_profiler/ingest.py` | `validate_profile` + `ingest` (validate, write, rebuild). |
| `scripts/ingest_submission.py` | Thin CLI over `ingest`. |
| `src/glinet_profiler/submit.py` | Point Submit at the issue form. |
| `.github/ISSUE_TEMPLATE/profile-submission.yml` | The submission form (auto-label + attachment field). |
| `.github/workflows/submit-profile.yml` | Issue→PR bot. |
| `tests/test_ingest_submission.py` | Validation + ingest tests. |
| `tests/test_submit.py` | Updated for the form URL. |

---

### Task 1: Validate + ingest (`glinet_profiler.ingest` + CLI)

**Files:**
- Create: `src/glinet_profiler/ingest.py`, `scripts/ingest_submission.py`
- Test: `tests/test_ingest_submission.py`

**Interfaces:**
- Consumes: `glinet_profiler.registry.rebuild` (exists); `gli4py.enumerator.probe.device_id`.
- Produces:
  - `validate_profile(data) -> str | None` (error message or None).
  - `ingest(submission: Path, data_dir: Path) -> str` (validate→write→rebuild→return id; raises `ValueError`).

- [ ] **Step 1: Write the failing tests** `tests/test_ingest_submission.py`

```python
"""Tests for submission validation + ingest."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import json
from pathlib import Path

import pytest

from glinet_profiler.ingest import ingest, validate_profile

CLEAN = {
    "id": "ignored", "model": "mt6000", "firmware_version": "4.9.0",
    "services": {"system": {"get_info": {"status": "available", "covered_by": "router_info"}}},
}


def test_validate_accepts_clean():
    assert validate_profile(CLEAN) is None


def test_validate_missing_key():
    assert "missing required key" in validate_profile({"model": "x", "services": {}})


def test_validate_rejects_identifier():
    assert "identifier" in validate_profile({**CLEAN, "mac": "94:83:C4:AA:BB:CC"})


def test_validate_rejects_method_value():
    bad = {**CLEAN, "services": {"s": {"m": {"status": "available", "value": {"x": 1}}}}}
    assert "response value" in validate_profile(bad)


def test_validate_rejects_mac_hex():
    bad = {**CLEAN, "services": {"s": {"m": {"status": "available", "schema": {"a": "94:83:C4:AA:BB:CC"}}}}}
    assert "MAC" in validate_profile(bad)


def test_ingest_writes_and_normalizes_id(tmp_path):
    sub = tmp_path / "submission.json"
    sub.write_text(json.dumps(CLEAN), encoding="utf-8")
    new_id = ingest(sub, tmp_path)
    assert new_id == "mt6000_4.9.0"  # recomputed from model+firmware, not the submitted "ignored"
    written = json.loads((tmp_path / "devices" / "mt6000_4.9.0.json").read_text(encoding="utf-8"))
    assert written["id"] == "mt6000_4.9.0"
    manifest = json.loads((tmp_path / "index.json").read_text(encoding="utf-8"))
    assert manifest["devices"][0]["id"] == "mt6000_4.9.0"


def test_ingest_raises_on_invalid(tmp_path):
    sub = tmp_path / "submission.json"
    sub.write_text(json.dumps({**CLEAN, "sn": "SECRET"}), encoding="utf-8")
    with pytest.raises(ValueError):
        ingest(sub, tmp_path)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_ingest_submission.py -v`
Expected: `ModuleNotFoundError: No module named 'glinet_profiler.ingest'`.

- [ ] **Step 3: Create `src/glinet_profiler/ingest.py`**

```python
"""Validate + ingest a submitted device profile into the registry."""

import json
import re
from pathlib import Path
from typing import Any

from gli4py.enumerator.probe import device_id

from .registry import rebuild

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")
_REQUIRED = ("model", "firmware_version", "services")
_IDENTIFIERS = ("mac", "sn", "sn_bak")


def validate_profile(data: Any) -> str | None:
    """Return an error message if `data` is not a clean sanitized profile, else None."""
    if not isinstance(data, dict):
        return "submission is not a JSON object"
    for key in _REQUIRED:
        if key not in data:
            return f"missing required key: {key}"
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


def ingest(submission: Path, data_dir: Path) -> str:
    """Validate `submission`, write devices/<id>.json, rebuild the manifest; return the id."""
    data = json.loads(submission.read_text(encoding="utf-8"))
    error = validate_profile(data)
    if error:
        raise ValueError(error)
    new_id = device_id({"model": data["model"], "firmware_version": data["firmware_version"]})
    if not _ID_RE.fullmatch(new_id):
        raise ValueError(f"could not derive a safe id from model/firmware (got {new_id!r})")
    data["id"] = new_id
    devices_dir = data_dir / "devices"
    devices_dir.mkdir(parents=True, exist_ok=True)
    (devices_dir / f"{new_id}.json").write_text(
        json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
    )
    rebuild(data_dir)
    return new_id
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_ingest_submission.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Create `scripts/ingest_submission.py`**

```python
"""CLI: validate + ingest a submitted profile into the registry (prints the id, or the error)."""

import argparse
import json
import sys
from pathlib import Path

from glinet_profiler.ingest import ingest

_DATA = Path(__file__).resolve().parent.parent / "src" / "glinet_profiler" / "data"


def main(argv: list[str] | None = None) -> int:
    """Ingest the given submission file. On success print the id (exit 0); on failure print to stderr (exit 1)."""
    parser = argparse.ArgumentParser(description="Ingest a submitted device profile.")
    parser.add_argument("submission")
    args = parser.parse_args(argv)
    try:
        print(ingest(Path(args.submission), _DATA))
    except (ValueError, json.JSONDecodeError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 6: Lint, type, commit**

Run: `uv run ruff check . && uv run ruff format . && uv run mypy src && uv run pylint src/glinet_profiler/ingest.py scripts/ingest_submission.py tests/test_ingest_submission.py`
Expected: ruff clean; mypy clean; pylint `10.00`.
```bash
git add src/glinet_profiler/ingest.py scripts/ingest_submission.py tests/test_ingest_submission.py
git commit -m "feat: validate + ingest submitted profiles (glinet_profiler.ingest + CLI)"
```

---

### Task 2: Launcher Submit → the issue form

**Files:**
- Modify: `src/glinet_profiler/submit.py`
- Test: `tests/test_submit.py`

**Interfaces:**
- Produces: `prefilled_issue_url(profile, *, repo=REGISTRY_REPO) -> str` (now returns the issue-form URL with a prefilled title). Signature unchanged, so `server.py`'s call site is unaffected.

- [ ] **Step 1: Update the test** `tests/test_submit.py`

Replace the body of `test_prefilled_issue_url` (keep the module's existing header + `PROFILE` fixture and imports):

```python
def test_prefilled_issue_url_points_at_form():
    url = prefilled_issue_url(PROFILE, repo="owner/repo")
    assert url.startswith("https://github.com/owner/repo/issues/new?")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert query["template"][0] == "profile-submission.yml"
    assert "mt6000" in query["title"][0] and "4.9.0" in query["title"][0]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_submit.py -v`
Expected: FAIL (the current URL has no `template` param).

- [ ] **Step 3: Update `src/glinet_profiler/submit.py`**

Replace the whole file with:

```python
"""Build the 'submit a profile' URL pointing at the registry's issue form."""

import urllib.parse
from typing import Any

# The registry repo that receives profile submissions (update on extraction).
REGISTRY_REPO = "glinet4/glinet4-profiler"


def prefilled_issue_url(profile: dict[str, Any], *, repo: str = REGISTRY_REPO) -> str:
    """Return the issue-form URL (auto-labels + has the attachment field); prefills the title."""
    model = profile.get("model", "unknown")
    firmware = profile.get("firmware_version", "unknown")
    query = urllib.parse.urlencode(
        {"template": "profile-submission.yml", "title": f"Add profile: {model} ({firmware})"}
    )
    return f"https://github.com/{repo}/issues/new?{query}"
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_submit.py tests/test_server.py -v`
Expected: PASS (the submit test + the server test, which calls `prefilled_issue_url` and asserts `issues/new` in `submit_url` — still true).

- [ ] **Step 5: Lint, type, commit**

Run: `uv run ruff check . && uv run mypy src && uv run pylint src/glinet_profiler/submit.py tests/test_submit.py`
Expected: clean / `10.00`.
```bash
git add src/glinet_profiler/submit.py tests/test_submit.py
git commit -m "feat: point launcher Submit at the issue form (auto-label submission)"
```

---

### Task 3: Issue form + workflow

**Files:**
- Create: `.github/ISSUE_TEMPLATE/profile-submission.yml`, `.github/workflows/submit-profile.yml`

**Interfaces:**
- Consumes: `scripts/ingest_submission.py` (Task 1); the `profile-submission` label (set by the form).

- [ ] **Step 1: Create the issue form** `.github/ISSUE_TEMPLATE/profile-submission.yml`

```yaml
name: Submit a device profile
description: Contribute a captured GL.iNet API profile to the registry.
title: "Add profile: "
labels: [profile-submission]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for contributing! **Attach the `<id>.json` you downloaded from the
        glinet-profiler launcher** in the field below — drag-and-drop the file,
        don't paste its contents. A bot validates it and opens a pull request.
  - type: textarea
    id: profile
    attributes:
      label: Profile file
      description: Drag-and-drop your downloaded `<id>.json` here.
      placeholder: Drop the .json file here…
    validations:
      required: true
  - type: input
    id: notes
    attributes:
      label: Notes (optional)
      description: Anything else we should know.
```

- [ ] **Step 2: Resolve the pinned SHA for create-pull-request**

Run:
```bash
git ls-remote https://github.com/peter-evans/create-pull-request 'refs/tags/v7^{}' | cut -f1
```
Expected: a 40-char commit SHA (the dereferenced `v7` tag). Use it in Step 3 as `peter-evans/create-pull-request@<SHA>`. (If the deref form is empty, use `refs/tags/v7` without `^{}`.)

- [ ] **Step 3: Create the workflow** `.github/workflows/submit-profile.yml`

(Replace `PIN_SHA_HERE` with the SHA from Step 2.)

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
      - uses: actions/checkout@v7
      - uses: astral-sh/setup-uv@v7
        with:
          python-version: "3.11"
      - run: uv sync --all-extras --dev
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
        run: |
          curl -sL -A glinet-profiler-bot "${{ steps.url.outputs.url }}" -o submission.json
          if ID=$(uv run python scripts/ingest_submission.py submission.json 2>err.txt); then
            echo "id=$ID" >> "$GITHUB_OUTPUT"
            echo "ok=true" >> "$GITHUB_OUTPUT"
          else
            { echo "error<<ERR_EOF"; cat err.txt; echo "ERR_EOF"; } >> "$GITHUB_OUTPUT"
            echo "ok=false" >> "$GITHUB_OUTPUT"
          fi
      - name: Open pull request
        if: steps.ingest.outputs.ok == 'true'
        uses: peter-evans/create-pull-request@PIN_SHA_HERE  # v7
        with:
          add-paths: src/glinet_profiler/data
          branch: submit/${{ steps.ingest.outputs.id }}
          delete-branch: true
          title: "Add profile: ${{ steps.ingest.outputs.id }}"
          commit-message: "feat(registry): add ${{ steps.ingest.outputs.id }}"
          body: |
            Automated profile submission from #${{ github.event.issue.number }}.
      - name: Comment result on the issue
        if: always()
        uses: actions/github-script@v7
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

- [ ] **Step 4: Validate the YAML**

Run:
```bash
uv run --with pyyaml python -c "import yaml; yaml.safe_load(open('.github/ISSUE_TEMPLATE/profile-submission.yml')); yaml.safe_load(open('.github/workflows/submit-profile.yml')); print('ok')"
grep -q 'create-pull-request@PIN_SHA_HERE' .github/workflows/submit-profile.yml && echo 'ERROR: SHA not pinned' || echo 'SHA pinned'
```
Expected: `ok`; `SHA pinned`.

- [ ] **Step 5: Commit**

```bash
git add .github/ISSUE_TEMPLATE/profile-submission.yml .github/workflows/submit-profile.yml
git commit -m "ci: issue form + bot that opens a PR from a submitted profile"
```

> **Live verification (after merge to main):** open a test issue via the form, attach a known-good `<id>.json`, and confirm the bot comments + opens a PR; then attach a deliberately-bad file (e.g. one with a `mac` key) and confirm it's rejected with a comment. The workflow can't be exercised by `issues` events locally.

---

## Self-Review

**1. Spec coverage**

| Spec section | Task |
|---|---|
| §2 issue form (auto-label + attachment field) | 3 |
| §3 validate + ingest (identifiers/value/MAC rejected; recomputed slug id) | 1 |
| §4 workflow (extract → download → ingest → PR → comment) | 3 |
| §5 launcher Submit → form | 2 |
| §6 security (PR-only; no traversal; SHA pin; env-passed comment to avoid injection) | 1 (slug), 3 (pin + env vars) |
| §7 testing | 1, 2 (unit); 3 (YAML parse + live note) |

No uncovered requirements.

**2. Placeholder scan:** `PIN_SHA_HERE` is replaced in Task 3 Step 3 from the value resolved in Step 2 (Step 4 fails the build if it isn't) — not a leftover placeholder. No TBD/TODO. The workflow's live behavior is verified by a real submission post-merge (documented) — `issues` events can't be triggered locally.

**3. Type consistency:** `validate_profile(data) -> str | None`, `ingest(submission, data_dir) -> str`, `rebuild(data_dir) -> int`, `device_id(dict) -> str`, `prefilled_issue_url(profile, *, repo) -> str` are used consistently across `ingest.py`, `scripts/ingest_submission.py`, `submit.py`, and the tests. The CLI prints the id on success / error on stderr — exactly what the workflow's `Download + ingest` step consumes (`ID=$(...)` + `err.txt`). The workflow's `profile-submission` label matches the form's `labels:` and the job `if`. `add-paths: src/glinet_profiler/data` matches where `ingest` writes.

---

## Execution Handoff

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks (`superpowers:subagent-driven-development`).
2. **Inline Execution** — work the tasks in this session with checkpoints (`superpowers:executing-plans`).
