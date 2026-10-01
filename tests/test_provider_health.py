import json

import httpx
import pytest
from typer.testing import CliRunner

from osintmaster.cli import app
from osintmaster.config import Config
from osintmaster.providers.health import load_canaries, run_canaries


def test_canary_fixture_rejects_ambiguous_or_unknown_cases(tmp_path):
    fixture = tmp_path / "canaries.json"
    fixture.write_text(
        json.dumps(
            {
                "cases": [
                    {"site": "GitHub", "username": "Sample", "expected": "CONFIRMED"},
                    {"site": "GitHub", "username": "sample", "expected": "NOT_FOUND"},
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicates"):
        load_canaries(fixture)
    fixture.write_text(
        json.dumps({"cases": [{"site": "Unknown", "username": "sample", "expected": "CONFIRMED"}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown built-in site"):
        load_canaries(fixture)


@pytest.mark.asyncio
async def test_live_canaries_distinguish_regression_from_unresolved(tmp_path):
    fixture = tmp_path / "canaries.json"
    fixture.write_text(
        json.dumps(
            {
                "cases": [
                    {"site": "GitHub", "username": "owned", "expected": "CONFIRMED"},
                    {"site": "GitHub", "username": "missing", "expected": "NOT_FOUND"},
                    {"site": "GitHub", "username": "regressed", "expected": "CONFIRMED"},
                    {"site": "Hacker News", "username": "MixedCase", "expected": "CONFIRMED"},
                    {"site": "Telegram", "username": "unresolved", "expected": "NOT_FOUND"},
                    {"site": "GitHub", "username": "blocked", "expected": "CONFIRMED"},
                ]
            }
        ),
        encoding="utf-8",
    )

    def respond(request):
        url = str(request.url)
        if url.endswith("/users/owned"):
            return httpx.Response(200, json={"login": "owned"})
        if url.endswith("/users/missing") or url.endswith("/users/regressed"):
            return httpx.Response(404)
        if url.endswith("/user/MixedCase.json"):
            return httpx.Response(200, json={"id": "MixedCase"})
        if url.endswith("/unresolved"):
            return httpx.Response(200, text="<title>Telegram: Contact @unresolved</title>")
        if url.endswith("/users/blocked"):
            return httpx.Response(403)
        raise AssertionError(f"Unexpected URL: {url}")

    result = await run_canaries(
        load_canaries(fixture),
        Config(reports_dir=tmp_path, host_interval=0),
        transport=httpx.MockTransport(respond),
    )
    assert [case["outcome"] for case in result["cases"]] == [
        "PASS",
        "PASS",
        "FAIL",
        "PASS",
        "INCONCLUSIVE",
        "INCONCLUSIVE",
    ]
    assert result["summary"] == {"pass": 3, "fail": 1, "inconclusive": 2}
    assert result["cases"][3]["actual"] == "CONFIRMED"
    assert result["cases"][4]["error"] == "Public preview did not verify requested account"
    assert result["cases"][5]["actual"] == "BLOCKED"
    assert result["timestamp"].endswith("+00:00")


def test_cli_health_json_and_dated_save(monkeypatch, tmp_path):
    fixture = tmp_path / "canaries.json"
    fixture.write_text(
        json.dumps({"cases": [{"site": "GitHub", "username": "owned", "expected": "CONFIRMED"}]}),
        encoding="utf-8",
    )

    async def fake_run(cases, config):
        assert cases[0].username == "owned"
        return {
            "timestamp": "2026-10-01T12:00:00+00:00",
            "version": "0.3.0",
            "summary": {"pass": 0, "fail": 0, "inconclusive": 1},
            "cases": [
                {
                    "site": "GitHub",
                    "username": "owned",
                    "expected": "CONFIRMED",
                    "actual": "RATE_LIMITED",
                    "outcome": "INCONCLUSIVE",
                    "http_status": 429,
                    "error": None,
                    "duration_ms": 1,
                }
            ],
        }

    monkeypatch.setattr("osintmaster.cli.run_canaries", fake_run)
    saved = tmp_path / "health.json"
    result = CliRunner().invoke(app, ["health", str(fixture), "--json", "--save", str(saved)])
    assert result.exit_code == 3, result.output
    assert json.loads(result.stdout) == json.loads(saved.read_text(encoding="utf-8"))
