# Design: automated profile-submission PR bot (glinet-profiler)

- **Date:** 2026-06-27
- **Status:** Approved (design); pending implementation plan
- **Repo:** glinet-profiler

## 1. Goal & flow

Let contributors get their captured profile into the registry **without manual PR work**:

```
launcher → Submit → GitHub issue FORM (auto-labels profile-submission)
        → contributor drag-drops the downloaded <id>.json into the form
        → GitHub Actions: download attachment → validate → write into the registry → rebuild manifest
        → open a PR (branch submit/<id>) linked to the issue, comment the link
        → maintainer reviews + merges
```

The bot **only ever opens a reviewed PR** — it never auto-merges and never executes the submitted content (JSON data). Profiles are ~100 KB (too large for an issue body), so the file rides as an issue **attachment**, not pasted text.

## 2. Issue form — `.github/ISSUE_TEMPLATE/profile-submission.yml`

A "Submit a device profile" form that **auto-applies the `profile-submission` label** (forms set labels regardless of the submitter's permissions, which is how the bot triggers reliably for external contributors). It has a required `textarea` field "Profile file" whose markdown editor accepts the drag-dropped `<id>.json` (the attachment link lands in the issue body, where the workflow finds it), and an optional notes field. The markdown instructs: attach the file you downloaded from the launcher; do not paste the contents.

## 3. Ingest + validation — `scripts/ingest_submission.py` (+ tests)

The only new Python. Given a downloaded JSON file and the registry `data_dir`:

- **Parse + shape:** require keys `model`, `firmware_version`, `services` (services an object of objects). Reject on missing/wrong shape with a clear message.
- **Canonical id (no path traversal):** recompute `id = gli4py.enumerator.probe.device_id({"model": ..., "firmware_version": ...})` — a slug — and write to `devices/<id>.json`. The filename is never taken from submitted free text, so traversal is impossible by construction; set `data["id"] = id`.
- **Publish-safety:** reject if the file contains a device identifier (`mac`/`sn`/`sn_bak` keys), any method-level `value` key, or a MAC-address-like value (`(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}`) — i.e. someone submitting a raw/unsanitized report is rejected, not published.
- **Write + rebuild:** write the pretty-printed profile to `src/glinet_profiler/data/devices/<id>.json` and call `registry.rebuild(data_dir)` to refresh `index.json`.

Interface:
- `validate_profile(data: dict) -> str | None` — error message, or None if clean.
- `ingest(submission: Path, data_dir: Path) -> str` — validate (raise `ValueError` on bad), write, rebuild, return the id.
- `main(argv=None) -> int` — CLI: on success print the id (exit 0); on failure print the error (exit 1) — the workflow captures both.

Unit-tested: a clean profile is ingested (file written, manifest rebuilt, id returned); raw-report/identifier/`value`/MAC-hex submissions are each rejected with a message; a profile whose `id` disagrees with `model_firmware` is normalized to the recomputed slug.

## 4. Workflow — `.github/workflows/submit-profile.yml`

Trigger: `issues` `[opened, labeled]`, gated `if contains(github.event.issue.labels.*.name, 'profile-submission')`. Permissions: `contents: write`, `pull-requests: write`, `issues: write`. Steps:
1. checkout + setup-uv + `uv sync --all-extras --dev`.
2. Extract the attachment URL from `github.event.issue.body` (regex for a GitHub file-attachment link ending `.json`); if none, comment a "please attach the file" message and stop.
3. `curl -sL` the attachment → `submission.json`.
4. Run `uv run python scripts/ingest_submission.py submission.json`, capturing stdout + exit code.
5. **On success:** open a PR with `peter-evans/create-pull-request` (pinned to a commit SHA) — branch `submit/<id>`, only `src/glinet_profiler/data/` staged, title `Add profile: <id>`, body referencing the issue — then comment the PR link on the issue (`actions/github-script`).
6. **On failure:** comment the validation error on the issue.

Uses the bumped action majors (checkout@v7, setup-uv@v7). The third-party `peter-evans/create-pull-request` is pinned to a SHA for supply-chain safety.

## 5. Launcher Submit → the form — `submit.py` (+ test)

`prefilled_issue_url(profile, *, repo)` now returns the **issue-form** URL: `https://github.com/<repo>/issues/new?template=profile-submission.yml&title=<encoded "Add profile: <model> (<fw>)">`. The form supplies the body fields + the label; the launcher just prefills the title and opens it. The launcher's `/api/enumerate` response and the UI's Submit button are unchanged (they already open `submit_url`). The test asserts the URL targets the form template + carries the encoded title.

## 6. Security

- The workflow runs on **untrusted issue input** but only opens a **reviewed PR** — no auto-merge, no execution of submitted content.
- Validation blocks **identifier leaks** (mac/sn/sn_bak/value/MAC-hex) and **path traversal** (filename is a recomputed slug, never submitted text).
- `peter-evans/create-pull-request` pinned to a SHA; least-privilege `GITHUB_TOKEN` scopes; PR-only bounds abuse to reviewable spam.

## 7. Testing

`uv run pytest` (hardware-free) plus the existing gates (ruff, ruff-format, mypy --strict on `src`, pylint, all green):
- `scripts/ingest_submission.py` validation + ingest (clean accepted; raw/identifier/value/MAC-hex rejected; id normalized). `scripts/` is not mypy-checked (`files=["src"]`) but is ruff + pylint clean and type-annotated.
- `submit.py` updated test (form-template URL + encoded title).
- The workflow + issue form are validated by YAML parse; the end-to-end submission is verified by a real test issue after merge (no local trigger for `issues` events).

## 8. File structure (new/changed)

| File | Responsibility |
|---|---|
| `.github/ISSUE_TEMPLATE/profile-submission.yml` | Submission form (auto-label + attachment field). |
| `scripts/ingest_submission.py` | Validate + ingest a submitted profile; rebuild the manifest. |
| `.github/workflows/submit-profile.yml` | Issue→PR bot (download, ingest, open PR, comment). |
| `src/glinet_profiler/submit.py` | Point Submit at the issue form. |
| `tests/test_ingest_submission.py` | Validation + ingest tests. |
| `tests/test_submit.py` | Updated for the form URL. |
