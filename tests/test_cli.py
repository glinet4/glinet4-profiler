"""CLI tests for glinet-profiler (capture mode + server-mode dispatch)."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument

import glinet_profiler.cli as cli_mod

PROFILE = {
    "id": "zz1300_9.9.9",
    "model": "zz1300",
    "firmware_version": "9.9.9",
    "services": {"system": {"get_info": {"status": "available", "covered_by": None}}},
}


def test_capture_mode_writes_profile_and_submit_link(monkeypatch, tmp_path, capsys):
    async def fake_capture(ip, username, password, *, ssh=True, on_progress=None):  # noqa: ARG001
        return PROFILE

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh"])
    assert rc == 0
    out = tmp_path / "zz1300_9.9.9.json"
    assert out.exists()
    stdout = capsys.readouterr().out
    assert "issues/new" in stdout  # NEW device (not in the bundled registry) → submission link
    assert "zz1300_9.9.9.json" in stdout


def test_no_ip_starts_web_server(monkeypatch):
    called = {}
    monkeypatch.setattr(cli_mod, "serve", lambda **kwargs: called.update(kwargs))
    rc = cli_mod.main(["--port", "9999", "--no-browser"])
    assert rc == 0
    assert called["port"] == 9999
    assert called["open_browser"] is False
