import sqlite3
from uuid import UUID

import httpx
import pytest
from typer.testing import CliRunner

from osintmaster.cli import app
from osintmaster.config import Config
from osintmaster.core.models import Report
from osintmaster.graph.canonicalize import canonicalize
from osintmaster.graph.models import InvestigationGraph
from osintmaster.investigation.engine import HuntEngine, HuntLimits
from osintmaster.investigation.models import EdgeType, Event, EventType
from osintmaster.investigation.store import InvestigationStore, compare_investigations
from osintmaster.providers.username import Site, load_sites


def test_canonical_keys_preserve_meaningful_case_and_history():
    assert canonicalize("EMAIL", "Alice@TÄST.CH") == "Alice@xn--tst-qla.ch"
    assert canonicalize("DOMAIN", "TÄST.CH.") == "xn--tst-qla.ch"
    assert canonicalize("URL", "HTTPS://TÄST.CH:443/#old") == "https://xn--tst-qla.ch"
    assert canonicalize("USERNAME", "Forgeties79", platform="hackernews") == "Forgeties79"
    assert canonicalize("USERNAME", "OctoCat", platform="github") == "octocat"
    assert canonicalize("PHONE", "+41 (79) 123-45-67") == "+41791234567"
    assert canonicalize("IP_ADDRESS", "2001:0db8::1") == "2001:db8::1"
    with pytest.raises(ValueError):
        canonicalize("PHONE", "0791234567")

    graph = InvestigationGraph()
    first = graph.add_entity("DOMAIN", "TÄST.CH")
    second = graph.add_entity("DOMAIN", "xn--tst-qla.ch.")
    assert first.id == second.id
    assert UUID(first.id)
    assert first.aliases == ["xn--tst-qla.ch."]


def test_event_provenance_and_graph_queries():
    graph = InvestigationGraph()
    seed = Event(EventType.USERNAME, "alice", "input", None, None, 1, 0)
    profile = Event(
        EventType.PROFILE,
        "https://example.org/alice",
        "Example",
        "https://example.org/alice",
        seed.id,
        0.95,
        0,
    )
    root = graph.add(seed)
    found = graph.add(profile, EdgeType.DISCOVERED_FROM)
    assert root.id != found.id
    assert graph.path(root.id, found.id) == [root.id, found.id]
    assert graph.provenance(found.id)[0]["source"] == root.id
    assert graph.neighbors(root.id)[0].id == found.id
    assert graph.observations[-1].evidence_ids
    assert graph.evidence[-1].source_url == "https://example.org/alice"
    assert graph.edges[0].evidence_ids == graph.observations[-1].evidence_ids


def test_repeated_relation_keeps_both_evidence_records():
    graph = InvestigationGraph()
    left = graph.add_entity("PROFILE", "https://a.example/alice")
    right = graph.add_entity("URL", "https://example.org/about")
    first = graph.add_evidence("A", method="PUBLIC_HTML", excerpt="first")
    second = graph.add_evidence("A", method="PUBLIC_HTML", excerpt="second")
    graph.add_relation(left.id, right.id, "LINKS_TO", provider="A", evidence_ids=[first.id])
    graph.add_relation(left.id, right.id, "LINKS_TO", provider="A", evidence_ids=[second.id])
    assert len(graph.edges) == 1
    assert graph.edges[0].evidence_ids == [first.id, second.id]


@pytest.mark.asyncio
async def test_negative_checks_and_provider_trace_survive_sqlite(tmp_path):
    site = Site("Example", "https://example.org/{username}", "social", (200,), (404,), ())
    engine = HuntEngine(
        Config(reports_dir=tmp_path, host_interval=0),
        sites=[site],
        transport=httpx.MockTransport(lambda request: httpx.Response(404)),
    )
    report = await engine.hunt("alice", limits=HuntLimits(depth=0))
    assert report.graph is not None
    graph = report.graph
    assert not any(node["type"] == "PROFILE" for node in graph["nodes"])
    checks = [item for item in graph["observations"] if item["property"] == "profile_check:Example"]
    assert len(checks) == 1 and checks[0]["state"] == "NOT_FOUND"
    assert checks[0]["provider_run_id"] == graph["provider_runs"][0]["id"]
    assert graph["provider_runs"][0]["requests_made"] == 1
    assert graph["evidence"][-1]["source_url"] == "https://example.org/alice"

    store = InvestigationStore(tmp_path)
    store.save(report)
    assert store.load(report.investigation_id)["graph"]["observations"] == graph["observations"]
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert (
            connection.execute(
                "SELECT state FROM graph_observations WHERE property = ?",
                ("profile_check:Example",),
            ).fetchone()[0]
            == "NOT_FOUND"
        )
        for table in (
            "graph_entity_details",
            "graph_evidence",
            "graph_observations",
            "graph_relation_details",
            "graph_pivot_candidates",
            "graph_provider_runs",
        ):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("PRAGMA user_version = 1")
    older = store.load(report.investigation_id)
    next_run = Report(
        "alice", [], [], [], ["alice"], target_type="USERNAME", graph={"nodes": [], "edges": []}
    )
    store.save(next_run)
    assert store.load(report.investigation_id) == older
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3


def test_graph_diff_keeps_missing_claims_uncertain():
    older = InvestigationGraph()
    newer = InvestigationGraph()
    old_profile = older.add_entity("PROFILE", "https://example.org/alice")
    older.add_observation(old_profile.id, "bio", "old", provider="Example")
    new_profile = newer.add_entity("PROFILE", "https://example.org/alice")
    newer.add_observation(new_profile.id, "bio", "new", provider="Example")
    change = older.diff(newer)
    assert change["added_entities"] == []
    assert change["not_observed_entities"] == []
    assert len(change["added_observations"]) == 1
    assert len(change["not_observed_observations"]) == 1

    old_report = Report("alice", [], [], [], [], target_type="USERNAME", graph=older.to_dict())
    new_report = Report("alice", [], [], [], [], target_type="USERNAME", graph=newer.to_dict())
    persisted_change = compare_investigations(old_report.to_dict(), new_report.to_dict())
    assert len(persisted_change["added_observations"]) == 1
    assert len(persisted_change["not_observed_observations"]) == 1


def test_phone_seed_cli_is_recorded_without_network(tmp_path):
    result = CliRunner().invoke(
        app,
        ["hunt", "+41 (79) 123-45-67", "--depth", "0", "--json", "--output", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    import json

    data = json.loads(result.stdout)
    assert data["target_type"] == "PHONE"
    assert data["graph"]["nodes"][0]["canonical_value"] == "+41791234567"
    assert data["graph"]["investigation"]["id"] == data["investigation_id"]


@pytest.mark.asyncio
async def test_public_avatar_is_a_sourced_image_entity_without_download(tmp_path):
    site = next(item for item in load_sites() if item.name == "GitHub")
    requests = []

    def respond(request):
        requests.append(str(request.url))
        return httpx.Response(
            200,
            json={"login": "alice", "id": 123, "avatar_url": "https://images.example/alice.png"},
        )

    report = await HuntEngine(
        Config(reports_dir=tmp_path, host_interval=0),
        sites=[site],
        transport=httpx.MockTransport(respond),
    ).hunt("alice", limits=HuntLimits(depth=1))
    assert report.graph is not None
    assert len(requests) == 1
    assert any(node["type"] == "IMAGE" for node in report.graph["nodes"])
    assert any(edge["type"] == "USES_IMAGE" for edge in report.graph["edges"])
    assert all(run["provider"] != "Local image" for run in report.graph["provider_runs"])
