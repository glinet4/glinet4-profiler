"""CLI tests for glinet4-profiler (capture mode + server-mode dispatch)."""
# pylint: disable=missing-function-docstring,redefined-outer-name,unused-argument

import glinet4_profiler.cli as cli_mod

PROFILE = {
    "id": "zz1300_9.9.9",
    "model": "zz1300",
    "firmware_version": "9.9.9",
    "services": {"system": {"get_info": {"status": "available", "covered_by": None}}},
}

MAN = {"devices": [{"id": "mt6000_4.9.0", "model": "mt6000", "firmware_version": "4.9.0"}]}


def test_capture_mode_new_device_submit_link(monkeypatch, tmp_path, capsys):
    """A device not in the manifest → NEW status + submission link."""

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        return PROFILE

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        return MAN  # manifest reachable but zz1300 not in it

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh"])
    assert rc == 0
    out = tmp_path / "zz1300_9.9.9.json"
    assert out.exists()
    stdout = capsys.readouterr().out
    assert "issues/new" in stdout
    assert "zz1300_9.9.9.json" in stdout
    assert "NEW" in stdout


def test_capture_mode_offline_submit_link(monkeypatch, tmp_path, capsys):
    """When fetch_manifest returns None → offline message + submission link."""

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        return PROFILE

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        return None  # offline

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh"])
    assert rc == 0
    stdout = capsys.readouterr().out
    assert "couldn't reach the registry" in stdout
    assert "issues/new" in stdout


def test_capture_mode_include_destructive_implies_dangerous(monkeypatch, tmp_path):
    seen = {}

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        seen["dangerous"] = dangerous
        seen["include_destructive"] = include_destructive
        return PROFILE

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        return None

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh", "--include-destructive"])
    assert rc == 0
    assert seen == {"dangerous": True, "include_destructive": True}


def test_capture_mode_keep_data_is_local_only(monkeypatch, tmp_path, capsys):
    """--keep-data passes keep_data through, prints LOCAL-ONLY, and skips the submission flow."""
    seen = {}
    fetched = {"called": False}

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        seen["keep_data"] = keep_data
        return PROFILE

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        fetched["called"] = True
        return MAN

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh", "--keep-data"])
    assert rc == 0
    assert seen["keep_data"] is True
    assert fetched["called"] is False  # local-only: no registry lookup / submission
    assert "LOCAL-ONLY" in capsys.readouterr().out


def test_fixtures_out_writes_fixture_set_and_skips_profile_flow(monkeypatch, tmp_path, capsys):
    """--fixtures-out captures raw + writes fixtures; never touches capture()/the registry."""
    seen = {}
    capture_called = {"called": False}
    fetch_called = {"called": False}

    async def fake_capture_raw(ip, username, password, *, ssh=True, on_progress=None):  # noqa: ARG001
        seen["ssh"] = ssh
        return {"device": {"model": "mt6000", "firmware_version": "4.9.0"}, "services": {}}

    async def fake_capture(*args, **kwargs):  # noqa: ARG001
        capture_called["called"] = True
        raise AssertionError("capture() must not run when --fixtures-out is given")

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        fetch_called["called"] = True
        return None

    def fake_write_fixture_set(raw, out_dir, **kwargs):  # noqa: ARG001
        seen["raw"] = raw
        seen["out_dir"] = out_dir
        target = out_dir / "mt6000_4.9.0"
        target.mkdir(parents=True)
        (target / "system.get_info.json").write_text("{}", encoding="utf-8")
        (target / "manifest.json").write_text("{}", encoding="utf-8")
        return target

    monkeypatch.setattr(cli_mod, "capture_raw", fake_capture_raw)
    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.setattr(cli_mod, "write_fixture_set", fake_write_fixture_set)

    out_dir = tmp_path / "fixtures"
    rc = cli_mod.main(
        ["192.168.8.1", "--password", "x", "--no-ssh", "--fixtures-out", str(out_dir)]
    )
    assert rc == 0
    assert seen["ssh"] is False
    assert seen["out_dir"] == out_dir
    assert not capture_called["called"]  # the profile-shape capture never ran
    assert not fetch_called["called"]  # no registry lookup for a fixture-only run
    stdout = capsys.readouterr().out
    assert "Fixtures (1 methods)" in stdout
    assert str(out_dir / "mt6000_4.9.0") in stdout


def test_fixtures_out_reports_failure(monkeypatch, tmp_path, capsys):
    async def fake_capture_raw(ip, username, password, *, ssh=True, on_progress=None):  # noqa: ARG001
        raise RuntimeError("router unreachable")

    monkeypatch.setattr(cli_mod, "capture_raw", fake_capture_raw)
    rc = cli_mod.main(
        [
            "192.168.8.1",
            "--password",
            "x",
            "--no-ssh",
            "--fixtures-out",
            str(tmp_path / "fixtures"),
        ]
    )
    assert rc == 1
    assert "fixture capture failed" in capsys.readouterr().err


def test_no_ip_starts_web_server(monkeypatch):
    called = {}
    monkeypatch.setattr(cli_mod, "serve", lambda **kwargs: called.update(kwargs))
    rc = cli_mod.main(["--port", "9999", "--no-browser", "--registry-url", "http://x/i.json"])
    assert rc == 0
    assert called["port"] == 9999
    assert called["open_browser"] is False
    assert called["registry_url"] == "http://x/i.json"


def test_capture_mode_known_device(monkeypatch, tmp_path, capsys):
    """A device already in the manifest → display 'already in the registry' message."""

    async def fake_capture(
        ip,
        username,
        password,
        *,
        ssh=True,
        dangerous=False,
        include_destructive=False,
        keep_data=False,
        on_progress=None,
    ):  # noqa: ARG001
        return {**PROFILE, "model": "mt6000", "firmware_version": "4.9.0", "id": "mt6000_4.9.0"}

    async def fake_fetch(url, *, timeout=5.0):  # noqa: ARG001
        return MAN  # contains mt6000_4.9.0

    monkeypatch.setattr(cli_mod, "capture", fake_capture)
    monkeypatch.setattr(cli_mod, "fetch_manifest", fake_fetch)
    monkeypatch.chdir(tmp_path)
    rc = cli_mod.main(["192.168.8.1", "--password", "x", "--no-ssh"])
    assert rc == 0
    assert "already in the registry" in capsys.readouterr().out
