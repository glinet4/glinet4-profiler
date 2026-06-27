"""Structural smoke checks for the launcher UI."""
# pylint: disable=missing-function-docstring

from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "src" / "glinet_profiler" / "web"


def test_index_has_form_controls():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    for needle in (
        'id="form"',
        'id="host"',
        'id="username"',
        'id="password"',
        'id="ssh"',
        'id="status"',
        'id="result"',
        'id="banner"',
        'id="actions"',
        'id="download"',
        'id="submit"',
        "app.js",
        "style.css",
    ):
        assert needle in html, needle


def test_app_js_uses_token_and_endpoint():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert "api/enumerate" in js
    assert "X-Profiler-Token" in js
    assert "submit_url" in js  # opens the server-built prefilled issue URL
