import asyncio
from pathlib import Path

import pytest

from osintmaster.config import Config
from osintmaster.core.models import FindingStatus
from osintmaster.plugins.manager import external_providers
from osintmaster.providers.external import is_profile_url
from osintmaster.providers.maigret import MaigretProvider
from osintmaster.providers.sherlock import SherlockProvider


class FakeProcess:
    returncode = 0

    def __init__(self, output):
        self.output = output

    async def communicate(self):
        return self.output, b""


@pytest.mark.asyncio
async def test_enabled_but_missing_external_tools_report_errors(monkeypatch):
    monkeypatch.setattr("osintmaster.providers.sherlock.shutil.which", lambda _: None)
    monkeypatch.setattr("osintmaster.providers.maigret.shutil.which", lambda _: None)
    providers = external_providers(Config(sherlock=True, maigret=True))
    findings = [item for provider in providers for item in await provider.scan("alex", 2)]
    assert [item.provider for item in findings] == ["Sherlock", "Maigret"]
    assert all(item.status == FindingStatus.ERROR for item in findings)
    assert all("not installed" in item.error for item in findings)


@pytest.mark.asyncio
async def test_sherlock_parses_only_found_urls(monkeypatch):
    monkeypatch.setattr("osintmaster.providers.sherlock.shutil.which", lambda _: "sherlock")

    async def fake_process(*args, **kwargs):
        assert "--site" not in args
        output = Path(args[args.index("--output") + 1])
        output.write_text(
            "GitHub: https://github.com/alex\n"
            "Example: https://example.org/user/alex\n"
            "Visit: https://osintsearch.org/go/sherlock\n",
            encoding="utf-8",
        )
        return FakeProcess(b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_process)
    findings = await SherlockProvider().scan("alex", 2)
    assert len(findings) == 2
    assert all(item.status == FindingStatus.POSSIBLE for item in findings)
    assert {item.url for item in findings} == {
        "https://github.com/alex",
        "https://example.org/user/alex",
    }


@pytest.mark.asyncio
async def test_maigret_parses_ndjson(monkeypatch):
    monkeypatch.setattr("osintmaster.providers.maigret.shutil.which", lambda _: "maigret")

    async def fake_process(*args, **kwargs):
        assert "--site" not in args
        folder = Path(args[args.index("--folderoutput") + 1])
        (folder / "report_alex_ndjson.json").write_text(
            '{"url_user":"https://github.com/alex","status":{"status":"Claimed","username":"alex"}}\n',
            encoding="utf-8",
        )
        return FakeProcess(b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_process)
    findings = await MaigretProvider().scan("alex", 2)
    assert [item.url for item in findings] == ["https://github.com/alex"]


@pytest.mark.asyncio
async def test_maigret_reports_malformed_records_alongside_valid_findings(monkeypatch):
    monkeypatch.setattr("osintmaster.providers.maigret.shutil.which", lambda _: "maigret")

    async def fake_process(*args, **kwargs):
        folder = Path(args[args.index("--folderoutput") + 1])
        (folder / "report_alex_ndjson.json").write_text(
            '{"url_user":"https://github.com/alex","status":{"status":"Claimed","username":"alex"}}\n{bad json\n',
            encoding="utf-8",
        )
        return FakeProcess(b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_process)
    findings = await MaigretProvider().scan("alex", 2)
    assert [item.status for item in findings] == [FindingStatus.POSSIBLE, FindingStatus.ERROR]
    assert findings[1].error == "Maigret report contained 1 invalid or unverified record(s)"


@pytest.mark.asyncio
async def test_maigret_rejects_nonclaimed_similar_or_other_username(monkeypatch):
    monkeypatch.setattr("osintmaster.providers.maigret.shutil.which", lambda _: "maigret")

    async def fake_process(*args, **kwargs):
        folder = Path(args[args.index("--folderoutput") + 1])
        (folder / "report_alex_ndjson.json").write_text(
            '{"url_user":"https://github.com/alex","status":{"status":"Available","username":"alex"}}\n'
            '{"url_user":"https://gitlab.com/alex","status":{"status":"Claimed","username":"other"}}\n'
            '{"url_user":"https://codeberg.org/alex","status":{"status":"Claimed","username":"alex"},"is_similar":true}\n',
            encoding="utf-8",
        )
        return FakeProcess(b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_process)
    findings = await MaigretProvider().scan("alex", 2)
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.ERROR
    assert "2 invalid or unverified" in findings[0].error


def test_external_urls_must_be_exact_profile_paths():
    assert is_profile_url("https://github.com/alex", "alex")
    assert is_profile_url("https://example.org/users/alex", "alex")
    assert is_profile_url("https://alex.itch.io/", "alex")
    assert not is_profile_url("https://github.com/other/alex", "alex")
    assert not is_profile_url("https://www.reddit.com/user/alex", "alex")
    assert not is_profile_url("https://127.0.0.1/user/alex", "alex")
    assert not is_profile_url("https://github.com/alex?tab=repositories", "alex")
