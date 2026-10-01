import json
import re
import threading

import httpx
from typer.testing import CliRunner

from osintmaster.cli import app
from osintmaster.core.models import Finding, FindingStatus, Report
from osintmaster.investigation.store import InvestigationStore
from osintmaster.reports.dashboard import make_dashboard_server


def _saved_run(
    store, target, timestamp, *, status=None, entity=None, partial=False, target_type="USERNAME"
):
    report = Report(target, [], [], [], [target], timestamp=timestamp, target_type=target_type)
    if status is not None:
        report.findings = [
            Finding("GitHub", target, f"https://github.com/{target}", FindingStatus(status))
        ]
    nodes = (
        [
            {
                "id": "n1",
                "type": "DOMAIN",
                "value": entity,
                "confidence": 0.5,
                "observations": 1,
            }
        ]
        if entity is not None
        else []
    )
    report.graph = {"nodes": nodes, "edges": []}
    if partial:
        report.errors = ["Example provider unavailable"]
    store.save(report)
    return report


def test_dashboard_browses_old_runs_only_for_current_target(tmp_path):
    store = InvestigationStore(tmp_path)
    older = _saved_run(store, "alice", "2026-09-30T10:00:00+00:00")
    current = _saved_run(store, "alice", "2026-10-01T10:00:00+00:00")
    other = _saved_run(store, "bob", "2026-10-01T11:00:00+00:00")
    other_type = _saved_run(store, "alice", "2026-10-01T12:00:00+00:00", target_type="DOMAIN")
    assert store.list(target="alice", target_type="USERNAME", limit=1)[0]["id"] == (
        current.investigation_id
    )
    server = make_dashboard_server(current.to_dict(), store=store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with httpx.Client() as client:
            assert "Browse saved runs" in client.get(base + "/").text
            history = client.get(base + "/history")
            assert history.status_code == 200
            assert older.investigation_id in history.text
            assert current.investigation_id in history.text
            assert other.investigation_id not in history.text
            assert other_type.investigation_id not in history.text
            old_page = client.get(base + f"/run/{older.investigation_id}")
            assert old_page.status_code == 200
            assert older.investigation_id in old_page.text
            old_json = client.get(base + f"/run/{older.investigation_id}/report.json")
            assert old_json.json()["investigation_id"] == older.investigation_id
            assert client.get(base + f"/run/{other.investigation_id}").status_code == 404
            assert client.get(base + "/run/../../secret").status_code == 404
            assert (
                client.get(base + "/history", headers={"Host": "evil.example"}).status_code == 403
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_dashboard_cli_opens_run_id(monkeypatch, tmp_path):
    store = InvestigationStore(tmp_path)
    older = _saved_run(store, "alice", "2026-09-30T10:00:00+00:00")
    _saved_run(store, "alice", "2026-10-01T10:00:00+00:00")
    opened = {}

    class FakeServer:
        server_port = 1234

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def serve_forever(self, **_kwargs):
            raise KeyboardInterrupt

    def fake_server(data, port, *, store):
        opened.update(json.loads(json.dumps(data)))
        return FakeServer()

    monkeypatch.setattr("osintmaster.cli.make_dashboard_server", fake_server)
    result = CliRunner().invoke(
        app,
        ["dashboard", "--run", older.investigation_id[:12], "--no-open", "--output", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    assert opened["investigation_id"] == older.investigation_id


def test_dashboard_compare_shows_changes_without_calling_missing_items_removed(tmp_path):
    store = InvestigationStore(tmp_path)
    older = _saved_run(
        store,
        "alice",
        "2026-09-30T10:00:00+00:00",
        status="CONFIRMED",
        entity="old.example",
    )
    newer = _saved_run(
        store,
        "alice",
        "2026-10-01T10:00:00+00:00",
        status="NOT_FOUND",
        entity="<script>alert(1)</script>",
        partial=True,
    )
    other = _saved_run(store, "bob", "2026-10-01T11:00:00+00:00")
    server = make_dashboard_server(newer.to_dict(), store=store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        route = f"/compare/{older.investigation_id}/{newer.investigation_id}"
        with httpx.Client() as client:
            history = client.get(base + "/history").text
            assert route in history
            assert "2026-09-30 10:00 UTC" in history
            page = client.get(base + route)
            assert page.status_code == 200
            assert "2026-09-30 10:00 UTC → 2026-10-01 10:00 UTC" in page.text
            assert "CONFIRMED → NOT_FOUND" in page.text
            assert "Profiles not observed in later run" in page.text
            assert "does not prove an account or entity was removed" in page.text
            assert "At least one run was partial" in page.text
            assert "<script>alert(1)</script>" not in page.text
            assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text
            difference = client.get(base + route + "/diff.json").json()
            assert difference["status_changes"][0]["after"] == "NOT_FOUND"
            assert difference["partial"] is True
            assert difference["not_observed_entities"][0]["value"] == "old.example"
            assert (
                client.get(
                    base + f"/compare/{older.investigation_id}/{other.investigation_id}"
                ).status_code
                == 404
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_local_review_persists_decision_and_rejects_cross_origin(tmp_path):
    store = InvestigationStore(tmp_path)
    report = _saved_run(store, "alice", "2026-10-01T10:00:00+00:00")
    # The review store only accepts IDs found on a hypothesis in the immutable snapshot.
    relation_id = "a" * 32
    report.graph = {
        "nodes": [
            {
                "id": "b" * 32,
                "type": "PROFILE",
                "value": "Alice A",
                "confidence": 1,
                "observations": 1,
            },
            {
                "id": "c" * 32,
                "type": "PROFILE",
                "value": "Alice B",
                "confidence": 1,
                "observations": 1,
            },
        ],
        "edges": [
            {
                "id": relation_id,
                "source": "b" * 32,
                "target": "c" * 32,
                "type": "POSSIBLY_SAME_AS",
                "provider": "correlation",
                "strength": "hypothesis",
                "score": 42,
                "confidence": 0.42,
                "evidence": [],
                "timestamp": "2026-10-01T10:00:00+00:00",
            }
        ],
    }
    # Save a fresh run so the snapshot contains the reviewable relation.
    report.investigation_id = "d" * 32
    store.save(report)
    server = make_dashboard_server(report.to_dict(), store=store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        route = f"/review/{report.investigation_id}"
        with httpx.Client(follow_redirects=False) as client:
            page = client.get(base + route)
            assert page.status_code == 200
            token = re.search(r'name="token" value="([^"]+)"', page.text).group(1)
            form = {
                "token": token,
                "relation_id": relation_id,
                "decision": "REJECTED",
                "note": "<script>alert(1)</script>",
            }
            assert (
                client.post(
                    base + route, data=form, headers={"Origin": "http://evil.example"}
                ).status_code
                == 403
            )
            assert client.post(base + route, data=form, headers={"Origin": base}).status_code == 303
            saved = store.reviews(report.investigation_id)[relation_id]
            assert saved["decision"] == "REJECTED"
            assert saved["note"] == "<script>alert(1)</script>"
            assert (
                client.get(base + route + "/reviews.json").json()[relation_id]["decision"]
                == "REJECTED"
            )
            reviewed = client.get(base + route).text
            assert "&lt;script&gt;alert(1)&lt;/script&gt;" in reviewed
            assert "<script>alert(1)</script>" not in reviewed
            invalid = {**form, "relation_id": "e" * 32}
            assert (
                client.post(base + route, data=invalid, headers={"Origin": base}).status_code == 400
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
