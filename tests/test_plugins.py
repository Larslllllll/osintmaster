import json

import httpx
import pytest
from typer.testing import CliRunner

from osintmaster.cli import app
from osintmaster.config import Config
from osintmaster.core.engine import ScanEngine
from osintmaster.core.models import Finding, FindingStatus, SearchResult
from osintmaster.investigation.engine import HuntEngine, HuntLimits
from osintmaster.investigation.models import EdgeType, EventType
from osintmaster.investigation.providers import Observation, ProviderActivity, ProviderCost
from osintmaster.plugins.manager import load_event_plugins, load_plugins
from osintmaster.providers.base import SearchProvider, UsernameProvider


class PublicProfile(UsernameProvider):
    name = "PublicProfile"
    host = "example.org"

    async def check(self, username, client):
        response = await client.get(f"https://example.org/{username}")
        return Finding(self.name, username, str(response.url), FindingStatus.CONFIRMED)


class ApiSearch(SearchProvider):
    name = "ApiSearch"

    async def search(self, query):
        return [SearchResult("Result", "https://example.org/result", query, self.name)]


class MaliciousSearch(SearchProvider):
    name = "[red]Source[/red]"

    async def search(self, query):
        return [
            SearchResult(
                "\x1b[2J[bold]Fake alert[/bold]\u202e",
                "https://example.org/result",
                query,
                self.name,
            )
        ]


class FakeEntryPoint:
    def __init__(self, name, provider):
        self.name = name
        self.provider = provider

    def load(self):
        return self.provider


@pytest.mark.asyncio
async def test_enabled_username_plugin_runs_with_shared_client(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "osintmaster.plugins.manager.installed_plugins",
        lambda: [FakeEntryPoint("profile", PublicProfile)],
    )
    config = Config(reports_dir=tmp_path, host_interval=0, plugin_names=("profile",))
    usernames, searches, errors = load_plugins(config)
    assert searches == [] and errors == []
    engine = ScanEngine(
        config,
        sites=[],
        plugins=usernames,
        transport=httpx.MockTransport(lambda request: httpx.Response(200)),
    )
    report = await engine.scan("alex")
    assert report.findings[0].status == FindingStatus.CONFIRMED
    assert report.providers_used == ["PublicProfile"]


def test_missing_plugin_is_reported_without_loading_others(monkeypatch):
    monkeypatch.setattr(
        "osintmaster.plugins.manager.installed_plugins",
        lambda: [FakeEntryPoint("profile", PublicProfile)],
    )
    usernames, searches, errors = load_plugins(Config(plugin_names=("missing",)))
    assert usernames == searches == []
    assert errors == ["Plugin missing: not installed"]


@pytest.mark.asyncio
async def test_enabled_event_plugin_runs_in_hunt(monkeypatch, tmp_path):
    class PhoneLabel:
        name = "Phone label"
        accepts = frozenset({EventType.PHONE})
        produces = frozenset({EventType.METADATA})
        cost = ProviderCost.FREE_OFFLINE
        activity = ProviderActivity.LOCAL

        async def run(self, event, context):
            return [
                Observation(
                    EventType.METADATA,
                    "test label",
                    EdgeType.DISCOVERED_FROM,
                    0.8,
                    depth_increment=0,
                )
            ]

    monkeypatch.setattr(
        "osintmaster.plugins.manager.installed_plugins",
        lambda: [FakeEntryPoint("phone_label", PhoneLabel)],
    )
    config = Config(reports_dir=tmp_path, plugin_names=("phone_label",))
    providers, errors = load_event_plugins(config)
    assert errors == []
    report = await HuntEngine(config, sites=[], event_providers=providers).hunt(
        "+41791234567", limits=HuntLimits(depth=0, max_requests=0)
    )
    assert any(node["value"] == "test label" for node in report.graph["nodes"])
    assert report.limits["requests_used"] == 0


def test_dorks_search_calls_configured_provider_once(monkeypatch):
    monkeypatch.setattr("osintmaster.cli.load_config", lambda: Config(plugin_names=("search",)))
    monkeypatch.setattr(
        "osintmaster.plugins.manager.installed_plugins",
        lambda: [FakeEntryPoint("search", ApiSearch)],
    )
    result = CliRunner().invoke(app, ["dorks", "alex", "--search", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["results"][0]["provider"] == "ApiSearch"
    assert data["queries"][0] == '"alex"'


def test_search_result_cannot_inject_terminal_controls_or_rich_markup(monkeypatch):
    monkeypatch.setattr("osintmaster.cli.load_config", lambda: Config(plugin_names=("bad",)))
    monkeypatch.setattr(
        "osintmaster.plugins.manager.installed_plugins",
        lambda: [FakeEntryPoint("bad", MaliciousSearch)],
    )
    result = CliRunner().invoke(app, ["dorks", "alex", "--search"])
    assert result.exit_code == 0, result.output
    assert "[red]Source[/red]" in result.stdout
    assert "[bold]Fake alert[/bold]" in result.stdout
    assert "\x1b" not in result.stdout
    assert "\u202e" not in result.stdout
