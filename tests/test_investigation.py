import json
import threading

import httpx
import pytest
from typer.testing import CliRunner

from osintmaster.cli import app
from osintmaster.config import Config
from osintmaster.core.engine import ScanEngine
from osintmaster.core.models import FindingStatus
from osintmaster.investigation.engine import HuntEngine, HuntLimits
from osintmaster.investigation.models import EventType
from osintmaster.investigation.targets import classify_target, match_profile_url
from osintmaster.providers.username import Site, load_sites
from osintmaster.reports.dashboard import make_dashboard_server
from osintmaster.reports.html_report import render_html
from osintmaster.reports.json_report import load_report, report_directory, save_graph, save_json

A = Site("A", "https://a.example/{username}", "social", (200,), (404,), ("profile-card",))
B = Site("B", "https://b.example/{username}", "social", (200,), (404,), ("profile-card",))


def response_for(request):
    if request.url.host == "a.example" and request.url.path == "/alice":
        return httpx.Response(
            200,
            text=(
                '<link rel="canonical" href="https://a.example/alice">'
                '<meta property="og:title" content="Alice Example">'
                '<meta property="og:description" content="Contact alice@example.test">'
                '<a rel="me" href="https://b.example/bob">other profile</a>'
                '<div class="profile-card"></div>'
            ),
            headers={"content-type": "text/html"},
        )
    if request.url.host == "b.example" and request.url.path == "/bob":
        return httpx.Response(
            200,
            text=(
                '<link rel="canonical" href="https://b.example/bob">'
                '<meta property="og:title" content="Alice Example">'
                '<a rel="me" href="https://a.example/alice">first profile</a>'
                '<div class="profile-card"></div>'
            ),
            headers={"content-type": "text/html"},
        )
    return httpx.Response(404)


def test_target_detection_and_profile_matching():
    assert classify_target("demo@example.test")[0] == EventType.EMAIL
    assert classify_target("example.org")[0] == EventType.DOMAIN
    assert classify_target("https://example.org/x")[0] == EventType.URL
    assert classify_target("alex.smith", EventType.USERNAME) == (EventType.USERNAME, "alex.smith")
    assert match_profile_url("https://b.example/bob", [A, B]) == (B, "bob")
    assert match_profile_url("https://b.example/bob/repo", [A, B]) is None
    with pytest.raises(ValueError):
        classify_target("../private", EventType.USERNAME)


@pytest.mark.asyncio
async def test_case_has_two_seed_entities_and_shared_budget(tmp_path):
    report = await HuntEngine(Config(reports_dir=tmp_path), sites=[]).hunt_many(
        "sample", ["+41791234567", "+41791234568"], limits=HuntLimits(depth=0)
    )
    assert report.target == "case-sample"
    assert report.target_type == "CASE"
    assert report.graph is not None
    assert len(report.graph["investigation"]["seed_entities"]) == 2
    assert report.limits["requests_used"] == 0
    with pytest.raises(ValueError, match="at least two distinct"):
        await HuntEngine(Config(reports_dir=tmp_path), sites=[]).hunt_many(
            "sample", ["+41791234567", "+41791234567"]
        )


@pytest.mark.asyncio
async def test_case_reports_provider_cap_instead_of_silently_skipping_seed(tmp_path):
    report = await HuntEngine(
        Config(reports_dir=tmp_path, host_interval=0),
        sites=[A],
        transport=httpx.MockTransport(lambda request: httpx.Response(404)),
    ).hunt_many(
        "capped",
        ["alice", "bob"],
        limits=HuntLimits(depth=0, max_requests=2, max_per_provider=1),
    )
    assert report.limits["requests_used"] == 1
    assert "Provider check limit reached: A" in report.errors


def test_case_cli_writes_a_saved_report(tmp_path):
    result = CliRunner().invoke(
        app,
        [
            "case",
            "sample",
            "+41791234567",
            "+41791234568",
            "--depth",
            "0",
            "--output",
            str(tmp_path),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["target_type"] == "CASE"
    assert (tmp_path / "case-sample" / "graph.json").exists()


@pytest.mark.asyncio
async def test_hacker_news_preserves_case_sensitive_username_in_scan_and_hunt(tmp_path):
    site = next(item for item in load_sites() if item.name == "Hacker News")

    def response_for_case(request):
        if request.url.path.endswith("/Forgeties79.json"):
            return httpx.Response(200, json={"id": "Forgeties79"})
        return httpx.Response(200, content=b"null")

    transport = httpx.MockTransport(response_for_case)
    config = Config(reports_dir=tmp_path, host_interval=0)
    mixed = await ScanEngine(config, sites=[site], transport=transport).scan("Forgeties79")
    lower = await ScanEngine(config, sites=[site], transport=transport).scan("forgeties79")
    assert mixed.findings[0].status == FindingStatus.CONFIRMED
    assert mixed.findings[0].username == "Forgeties79"
    assert lower.findings[0].status == FindingStatus.NOT_FOUND
    assert report_directory(tmp_path, mixed.target) != report_directory(tmp_path, lower.target)

    hunt = await HuntEngine(config, sites=[site], transport=transport).hunt(
        "Forgeties79", limits=HuntLimits(depth=0)
    )
    assert hunt.findings[0].status == FindingStatus.CONFIRMED
    assert hunt.events[0]["value"] == "Forgeties79"
    assert hunt.graph is not None
    assert (
        next(node for node in hunt.graph["nodes"] if node["type"] == "PROFILE")["attributes"][
            "platform_id"
        ]
        == "Forgeties79"
    )
    assert match_profile_url("https://news.ycombinator.com/user?id=Forgeties79", [site]) == (
        site,
        "Forgeties79",
    )


@pytest.mark.asyncio
async def test_hunt_pivots_with_provenance_and_stops_cycles(tmp_path):
    config = Config(reports_dir=tmp_path, host_interval=0)
    engine = HuntEngine(config, sites=[A, B], transport=httpx.MockTransport(response_for))
    report = await engine.hunt("alice", limits=HuntLimits(depth=2))
    assert [(item.provider, item.username) for item in report.findings] == [
        ("A", "alice"),
        ("B", "alice"),
        ("B", "bob"),
    ]
    assert report.limits["requests_used"] == 3
    assert report.graph is not None
    nodes = report.graph["nodes"]
    edges = report.graph["edges"]
    assert any(item["type"] == "USERNAME" and item["value"] == "bob" for item in nodes)
    assert any(item["type"] == "EMAIL" and item["value"] == "alice@example.test" for item in nodes)
    assert any(item["type"] == "USES_USERNAME" and item["provider"] == "B" for item in edges)
    assert all(item["source_url"] is not None for item in edges)
    assert len({(item["type"], item["value"]) for item in nodes}) == len(nodes)
    graph_path = save_graph(report, tmp_path)
    save_json(report, tmp_path)
    assert len(json.loads(graph_path.read_text(encoding="utf-8"))["edges"]) == len(edges)


@pytest.mark.asyncio
async def test_hunt_depth_and_request_limits(tmp_path):
    config = Config(reports_dir=tmp_path, host_interval=0)
    transport = httpx.MockTransport(response_for)
    shallow = await HuntEngine(config, sites=[A, B], transport=transport).hunt(
        "alice", limits=HuntLimits(depth=0)
    )
    assert len(shallow.findings) == 2
    assert not any(item.username == "bob" for item in shallow.findings)
    bounded = await HuntEngine(config, sites=[A, B], transport=transport).hunt(
        "alice", limits=HuntLimits(depth=2, max_requests=2)
    )
    assert bounded.limits["requests_used"] == 2
    assert len(bounded.findings) == 2
    assert any("Request limit" in item for item in bounded.errors)


@pytest.mark.asyncio
async def test_domain_dns_pivot_obeys_shared_request_budget(monkeypatch, tmp_path):
    async def fake_resolve(name, record_type, *, lifetime):
        assert name == "example.org"
        assert lifetime > 0
        return ["203.0.113.10"] if record_type == "A" else ["2001:db8::10"]

    monkeypatch.setattr("osintmaster.investigation.engine.dns.asyncresolver.resolve", fake_resolve)
    config = Config(reports_dir=tmp_path, host_interval=0)
    full = await HuntEngine(config, sites=[]).hunt(
        "example.org", limits=HuntLimits(depth=0, max_requests=2)
    )
    assert full.limits["requests_used"] == 2
    assert {item["value"] for item in full.graph["nodes"] if item["type"] == "IP_ADDRESS"} == {
        "203.0.113.10",
        "2001:db8::10",
    }
    bounded = await HuntEngine(config, sites=[]).hunt(
        "example.org", limits=HuntLimits(depth=0, max_requests=1)
    )
    assert bounded.limits["requests_used"] == 1
    assert any("Request limit" in error for error in bounded.errors)


def test_dashboard_is_local_and_graph_content_is_escaped(tmp_path):
    report = {
        "target": "alice",
        "version": "0.2.0",
        "findings": [],
        "correlations": [],
        "errors": [],
        "rate_limits": [],
        "graph": {
            "nodes": [
                {
                    "id": "n",
                    "type": "USERNAME",
                    "value": "</script><script>alert(1)</script>",
                    "confidence": 1.0,
                    "observations": 1,
                }
            ],
            "edges": [],
        },
    }
    html = render_html(report)
    assert "</script><script>alert(1)</script>" not in html
    assert "\\u003c/script\\u003e" in html
    server = make_dashboard_server(report)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        assert httpx.get(base + "/").status_code == 200
        assert httpx.get(base + "/report.json").json()["target"] == "alice"
        assert httpx.get(base + "/../../secret").status_code == 404
        assert httpx.get(base + "/", headers={"Host": "evil.example"}).status_code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_hunt_cli_exports_non_username_targets_without_network(tmp_path):
    result = CliRunner().invoke(
        app, ["hunt", "demo@example.test", "--depth", "0", "--json", "--output", str(tmp_path)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["target_type"] == "EMAIL"
    assert data["graph"]["nodes"][0]["type"] == "EMAIL"
    assert load_report(tmp_path, "demo@example.test")["target"] == "demo@example.test"
    assert (report_directory(tmp_path, "demo@example.test") / "graph.json").is_file()
    assert report_directory(tmp_path, "2001:db8::1").name.startswith("target-")
