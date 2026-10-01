import json
import sqlite3
from time import monotonic

import httpx
import pytest
from typer.testing import CliRunner

from osintmaster.cli import app
from osintmaster.config import Config
from osintmaster.core.budget import RequestBudget
from osintmaster.core.models import FindingStatus
from osintmaster.investigation.engine import HuntEngine, HuntLimits
from osintmaster.investigation.models import EdgeType, EventType
from osintmaster.investigation.providers import (
    Observation,
    ProviderActivity,
    ProviderContext,
    ProviderCost,
    ProviderRegistry,
)
from osintmaster.investigation.store import InvestigationStore, compare_investigations
from osintmaster.providers.username import RegistryUsernameProvider, Site, load_sites
from osintmaster.reports.json_report import save_jsonl


@pytest.mark.asyncio
async def test_sqlite_history_keeps_both_runs_and_diff_labels_missing_as_unobserved(tmp_path):
    config = Config(reports_dir=tmp_path, host_interval=0)
    site = Site(
        "Example", "https://example.org/{username}", "social", (200,), (404,), ("profile-card",)
    )

    def first(request):
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=(
                '<link rel="canonical" href="https://example.org/alex">'
                '<meta property="og:title" content="Alex">'
                '<div class="profile-card"></div>'
            ),
        )

    report1 = await HuntEngine(config, sites=[site], transport=httpx.MockTransport(first)).hunt(
        "alex", limits=HuntLimits(depth=0)
    )
    report2 = await HuntEngine(
        config, sites=[site], transport=httpx.MockTransport(lambda request: httpx.Response(404))
    ).hunt("alex", limits=HuntLimits(depth=0))
    store = InvestigationStore(tmp_path)
    store.save(report1)
    store.save(report2)
    assert len(store.list(target="alex")) == 2
    assert store.load(report1.investigation_id[:12])["findings"][0]["status"] == "CONFIRMED"
    assert store.load(report2.investigation_id[:12])["findings"][0]["status"] == "NOT_FOUND"
    difference = compare_investigations(report1.to_dict(), report2.to_dict())
    assert difference["status_changes"][0]["after"] == "NOT_FOUND"
    assert any(item["type"] == "PROFILE" for item in difference["not_observed_entities"])
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM investigations").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(
            report1.events
        ) + len(report2.events)
        assert connection.execute("SELECT COUNT(*) FROM relationships").fetchone()[0] >= 1
    records = [
        json.loads(line)
        for line in save_jsonl(report1, tmp_path).read_text(encoding="utf-8").splitlines()
    ]
    assert records[0]["record"] == "investigation"
    assert any(item["record"] == "relationship" for item in records)


def test_run_diff_preserves_case_sensitive_hacker_news_profiles_and_usernames():
    old = {
        "target": "Forgeties79",
        "target_type": "USERNAME",
        "findings": [
            {"provider": "Hacker News", "username": "Forgeties79", "status": "CONFIRMED"},
            {"provider": "Hacker News", "username": "forgeties79", "status": "NOT_FOUND"},
        ],
        "graph": {
            "nodes": [
                {"type": "USERNAME", "value": "Forgeties79"},
                {"type": "USERNAME", "value": "forgeties79"},
            ]
        },
    }
    new = {
        **old,
        "findings": [old["findings"][0]],
        "graph": {"nodes": [old["graph"]["nodes"][0]]},
    }
    difference = compare_investigations(old, new)
    assert difference["status_changes"] == []
    assert difference["not_observed_profiles"] == [old["findings"][1]]
    assert difference["not_observed_entities"] == [old["graph"]["nodes"][1]]


@pytest.mark.asyncio
async def test_event_provider_uses_shared_budget_and_emits_graph_observation(tmp_path):
    class PageTitleProvider:
        name = "Page title"
        accepts = frozenset({EventType.URL})
        produces = frozenset({EventType.METADATA})
        cost = ProviderCost.FREE_PUBLIC
        activity = ProviderActivity.PASSIVE

        async def run(self, event, context):
            response = await context.get("https://api.example.org/title")
            return [
                Observation(
                    EventType.METADATA,
                    response.text,
                    EdgeType.DISCOVERED_FROM,
                    0.8,
                    str(response.url),
                    depth_increment=0,
                )
            ]

    config = Config(reports_dir=tmp_path, host_interval=0)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="Example page"))
    report = await HuntEngine(
        config, sites=[], transport=transport, event_providers=[PageTitleProvider()]
    ).hunt("https://example.org", limits=HuntLimits(depth=0, max_requests=1))
    assert report.limits["requests_used"] == 1
    assert any(node["value"] == "Example page" for node in report.graph["nodes"])
    assert any(edge["provider"] == "Page title" for edge in report.graph["edges"])
    assert not report.errors

    exhausted = await HuntEngine(
        config, sites=[], transport=transport, event_providers=[PageTitleProvider()]
    ).hunt("https://example.org", limits=HuntLimits(depth=0, max_requests=0))
    assert any("Request limit" in error for error in exhausted.errors)
    assert exhausted.limits["requests_used"] == 0

    registry = ProviderRegistry()
    registry.register(PageTitleProvider())
    with pytest.raises(ValueError):
        registry.register(PageTitleProvider())

    class PaidProvider(PageTitleProvider):
        name = "Paid page title"
        cost = ProviderCost.PAID

    skipped = await HuntEngine(
        config, sites=[], transport=transport, event_providers=[PaidProvider()]
    ).hunt("https://example.org", limits=HuntLimits(depth=0, max_requests=0))
    assert skipped.limits["requests_used"] == 0
    assert not any(run["provider"] == "Paid page title" for run in skipped.provider_runs)


@pytest.mark.asyncio
async def test_event_provider_context_rejects_private_hosts_and_bounds_streams():
    class LargeStream(httpx.AsyncByteStream):
        def __init__(self):
            self.chunks_sent = 0

        async def __aiter__(self):
            for _ in range(10):
                self.chunks_sent += 1
                yield b"x" * 400_000

    stream = LargeStream()
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    budget = RequestBudget(1)
    async with httpx.AsyncClient(transport=transport) as client:
        context = ProviderContext(budget, client, monotonic() + 5, 5)
        with pytest.raises(ValueError, match="Private IP"):
            await context.get("https://127.0.0.1/private")
        assert budget.used == 0
        with pytest.raises(ValueError, match="exceeded 1 MB"):
            await context.get("https://api.example.org/huge")
    assert budget.used == 1
    assert stream.chunks_sent == 3


@pytest.mark.asyncio
async def test_telegram_preview_requires_exact_public_profile_not_generic_200():
    site = Site(
        "Telegram", "https://t.me/{username}", "social", (200,), (404,), page_kind="telegram"
    )
    present = (
        "<title>Telegram: View @exampleuser</title>"
        '<meta property="og:title" content="Example Channel">'
        '<div class="tgme_page_title">Example Channel</div>'
        '<div class="tgme_page_extra">42 subscribers</div>'
        '<div class="tgme_page_description">Public bio '
        '<a href="https://example.org">website</a></div>'
    )
    missing = (
        "<title>Telegram: Contact @exampleuser</title>"
        '<meta property="og:title" content="Telegram: Contact @exampleuser">'
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text=present))
    ) as client:
        result = await RegistryUsernameProvider(site).check("exampleuser", client)
    assert result.status == FindingStatus.CONFIRMED
    assert result.profile.account_type == "CHANNEL"
    assert result.profile.links == ["https://example.org"]
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text=missing))
    ) as client:
        result = await RegistryUsernameProvider(site).check("exampleuser", client)
    assert result.status == FindingStatus.UNKNOWN


def test_cli_history_and_diff_work_offline(tmp_path):
    runner = CliRunner()
    options = ["hunt", "alex@example.test", "--depth", "0", "--output", str(tmp_path), "--json"]
    first = runner.invoke(app, options)
    second = runner.invoke(app, options)
    assert first.exit_code == second.exit_code == 0
    old_id = json.loads(first.stdout)["investigation_id"]
    new_id = json.loads(second.stdout)["investigation_id"]
    history = runner.invoke(app, ["investigations", "--output", str(tmp_path), "--json"])
    assert history.exit_code == 0
    assert len(json.loads(history.stdout)) == 2
    shown = runner.invoke(app, ["show", old_id[:12], "--output", str(tmp_path), "--json"])
    assert shown.exit_code == 0
    assert json.loads(shown.stdout)["investigation_id"] == old_id
    changed = runner.invoke(app, ["diff", old_id, new_id, "--output", str(tmp_path), "--json"])
    assert changed.exit_code == 0
    assert json.loads(changed.stdout)["status_changes"] == []


def test_builtin_catalog_excludes_unverified_reddit_and_includes_telegram():
    names = {site.name for site in load_sites()}
    assert names == {
        "GitHub",
        "GitLab",
        "Codeberg",
        "DEV Community",
        "Hacker News",
        "Bluesky",
        "Telegram",
    }
