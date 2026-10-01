"""Local, transactional history of investigation runs and their evidence."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from osintmaster.core.models import Report

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    version TEXT NOT NULL,
    requests_used INTEGER NOT NULL,
    entity_count INTEGER NOT NULL,
    edge_count INTEGER NOT NULL,
    report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS investigations_target_time
    ON investigations(target, created_at DESC);
CREATE TABLE IF NOT EXISTS events (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    provider TEXT NOT NULL,
    source_url TEXT,
    parent_id TEXT,
    depth INTEGER NOT NULL,
    confidence REAL NOT NULL,
    retrieved_at TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY (investigation_id, id)
);
CREATE INDEX IF NOT EXISTS events_type_value ON events(type, value);
CREATE TABLE IF NOT EXISTS entities (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence REAL NOT NULL,
    observations INTEGER NOT NULL,
    PRIMARY KEY (investigation_id, id)
);
CREATE TABLE IF NOT EXISTS relationships (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    type TEXT NOT NULL,
    provider TEXT NOT NULL,
    source_url TEXT,
    confidence REAL NOT NULL,
    evidence_json TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (investigation_id, ordinal)
);
CREATE TABLE IF NOT EXISTS findings (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    provider TEXT NOT NULL,
    username TEXT NOT NULL,
    url TEXT NOT NULL,
    status TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY (investigation_id, ordinal)
);
CREATE TABLE IF NOT EXISTS provider_runs (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    provider TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    cost TEXT NOT NULL,
    activity TEXT NOT NULL,
    status TEXT NOT NULL,
    requests_used INTEGER NOT NULL,
    events_emitted INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    PRIMARY KEY (investigation_id, ordinal)
);
CREATE TABLE IF NOT EXISTS graph_entity_details (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    canonical_value TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    aliases_json TEXT NOT NULL,
    state TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (investigation_id, entity_id)
);
CREATE INDEX IF NOT EXISTS graph_entity_canonical
    ON graph_entity_details(canonical_value);
CREATE TABLE IF NOT EXISTS graph_evidence (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    provider TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    method TEXT NOT NULL,
    source_url TEXT,
    data_json TEXT NOT NULL,
    PRIMARY KEY (investigation_id, id)
);
CREATE TABLE IF NOT EXISTS graph_observations (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    property TEXT NOT NULL,
    state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    provider TEXT NOT NULL,
    value_json TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    provider_run_id TEXT,
    PRIMARY KEY (investigation_id, id)
);
CREATE INDEX IF NOT EXISTS graph_observations_entity_time
    ON graph_observations(investigation_id, entity_id, observed_at);
CREATE TABLE IF NOT EXISTS graph_relation_details (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    relation_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    strength TEXT NOT NULL,
    score INTEGER,
    features_json TEXT NOT NULL,
    contradictions_json TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    PRIMARY KEY (investigation_id, relation_id)
);
CREATE TABLE IF NOT EXISTS graph_pivot_candidates (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    priority REAL NOT NULL,
    data_json TEXT NOT NULL,
    PRIMARY KEY (investigation_id, entity_id)
);
CREATE TABLE IF NOT EXISTS graph_provider_runs (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    provider TEXT NOT NULL,
    input_entity_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    data_json TEXT NOT NULL,
    PRIMARY KEY (investigation_id, id)
);
CREATE TABLE IF NOT EXISTS relation_reviews (
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    relation_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('NEEDS_REVIEW', 'SUPPORTED', 'REJECTED')),
    note TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (investigation_id, relation_id)
);
"""


class InvestigationStore:
    """SQLite index plus full report snapshots; no network or shared service."""

    def __init__(self, root: Path) -> None:
        self.path = root / "investigations.sqlite3"

    @contextmanager
    def _connect(self, *, create: bool = False) -> Iterator[sqlite3.Connection]:
        if not create and not self.path.is_file():
            raise FileNotFoundError("No saved investigations found")
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            if create:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version > 3:
                    raise ValueError("Investigation database is from a newer OSINTMaster version")
                connection.executescript(SCHEMA)
                connection.execute("PRAGMA user_version = 3")
            with connection:
                yield connection
        finally:
            connection.close()

    def save(self, report: Report) -> str:
        if report.graph is None:
            raise ValueError("Only graph investigations can be saved in history")
        data = report.to_dict()
        nodes = report.graph.get("nodes", [])
        edges = report.graph.get("edges", [])
        with self._connect(create=True) as connection:
            connection.execute(
                "INSERT INTO investigations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    report.investigation_id,
                    report.target,
                    report.target_type or "UNKNOWN",
                    report.timestamp,
                    report.version,
                    int(report.limits.get("requests_used", 0)),
                    len(nodes),
                    len(edges),
                    json.dumps(data, ensure_ascii=False),
                ),
            )
            connection.executemany(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        event["id"],
                        event["type"],
                        event["value"],
                        event["source_provider"],
                        event.get("source_url"),
                        event.get("parent_id"),
                        event["depth"],
                        event["confidence"],
                        event["retrieved_at"],
                        json.dumps(event.get("evidence", []), ensure_ascii=False),
                    )
                    for event in report.events
                ),
            )
            connection.executemany(
                "INSERT INTO entities VALUES (?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        node["id"],
                        node["type"],
                        node["value"],
                        node["confidence"],
                        node["observations"],
                    )
                    for node in nodes
                ),
            )
            connection.executemany(
                "INSERT INTO relationships VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        ordinal,
                        edge["source"],
                        edge["target"],
                        edge["type"],
                        edge["provider"],
                        edge.get("source_url"),
                        edge["confidence"],
                        json.dumps(edge.get("evidence", []), ensure_ascii=False),
                        edge["timestamp"],
                    )
                    for ordinal, edge in enumerate(edges)
                ),
            )
            connection.executemany(
                "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        ordinal,
                        finding["provider"],
                        finding["username"],
                        finding["url"],
                        finding["status"],
                        json.dumps(finding["profile"], ensure_ascii=False),
                        json.dumps(finding["evidence"], ensure_ascii=False),
                    )
                    for ordinal, finding in enumerate(data["findings"])
                ),
            )
            connection.executemany(
                "INSERT INTO provider_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        ordinal,
                        run["provider"],
                        run["event_id"],
                        run["event_type"],
                        run["cost"],
                        run["activity"],
                        run["status"],
                        run["requests_used"],
                        run["events_emitted"],
                        run["duration_ms"],
                    )
                    for ordinal, run in enumerate(report.provider_runs)
                ),
            )
            connection.executemany(
                "INSERT INTO graph_entity_details VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        node["id"],
                        node.get("canonical_value", node["value"]),
                        json.dumps(node.get("attributes", {}), ensure_ascii=False),
                        json.dumps(node.get("aliases", []), ensure_ascii=False),
                        node.get("state", "observed"),
                        node.get("first_seen", report.timestamp),
                        node.get("last_seen", report.timestamp),
                    )
                    for node in nodes
                ),
            )
            connection.executemany(
                "INSERT INTO graph_evidence VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        item["id"],
                        item["provider"],
                        item["collected_at"],
                        item["method"],
                        item.get("source_url"),
                        json.dumps(item, ensure_ascii=False),
                    )
                    for item in report.graph.get("evidence", [])
                ),
            )
            connection.executemany(
                "INSERT INTO graph_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        item["id"],
                        item["entity_id"],
                        item["property"],
                        item["state"],
                        item["observed_at"],
                        item["provider"],
                        json.dumps(item.get("value"), ensure_ascii=False),
                        json.dumps(item.get("evidence_ids", []), ensure_ascii=False),
                        item.get("provider_run_id"),
                    )
                    for item in report.graph.get("observations", [])
                ),
            )
            connection.executemany(
                "INSERT INTO graph_relation_details VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        edge["id"],
                        ordinal,
                        edge.get("strength", "direct"),
                        edge.get("score"),
                        json.dumps(edge.get("features", {}), ensure_ascii=False),
                        json.dumps(edge.get("contradictions", []), ensure_ascii=False),
                        json.dumps(edge.get("evidence_ids", []), ensure_ascii=False),
                    )
                    for ordinal, edge in enumerate(edges)
                    if "id" in edge
                ),
            )
            connection.executemany(
                "INSERT INTO graph_pivot_candidates VALUES (?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        item["entity_id"],
                        item["priority"],
                        json.dumps(item, ensure_ascii=False),
                    )
                    for item in report.graph.get("pivot_candidates", [])
                ),
            )
            connection.executemany(
                "INSERT INTO graph_provider_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        report.investigation_id,
                        item["id"],
                        item["provider"],
                        item["input_entity_id"],
                        item["status"],
                        item["started_at"],
                        item["finished_at"],
                        json.dumps(item, ensure_ascii=False),
                    )
                    for item in report.graph.get("provider_runs", [])
                ),
            )
        return report.investigation_id

    def list(
        self,
        *,
        target: str | None = None,
        target_type: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        if not 1 <= limit <= 1000:
            raise ValueError("List limit must be between 1 and 1000")
        filters = []
        parameters: list[str | int] = []
        if target is not None:
            filters.append("target = ?")
            parameters.append(target)
        if target_type is not None:
            filters.append("target_type = ?")
            parameters.append(target_type)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        parameters.append(limit)
        query = (
            "SELECT id, target, target_type, created_at, version, requests_used, "
            "entity_count, edge_count FROM investigations"
            + where
            + " ORDER BY created_at DESC, id DESC LIMIT ?"
        )
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def load(self, id_prefix: str) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{8,32}", id_prefix):
            raise ValueError("Use at least eight hexadecimal characters from an investigation ID")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT report_json FROM investigations WHERE id GLOB ? LIMIT 2",
                (id_prefix + "*",),
            ).fetchall()
        if not rows:
            raise FileNotFoundError("Investigation ID not found")
        if len(rows) > 1:
            raise ValueError("Investigation ID prefix is ambiguous")
        data: dict[str, Any] = json.loads(rows[0][0])
        return data

    def reviews(self, investigation_id: str) -> dict[str, dict[str, str]]:
        """Return analyst decisions separately from the immutable scan snapshot."""
        if not re.fullmatch(r"[0-9a-f]{32}", investigation_id):
            raise ValueError("Invalid investigation ID")
        with self._connect(create=True) as connection:
            rows = connection.execute(
                "SELECT relation_id, decision, note, updated_at FROM relation_reviews "
                "WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchall()
        return {str(row["relation_id"]): dict(row) for row in rows}

    def save_review(
        self, investigation_id: str, relation_id: str, decision: str, note: str
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{32}", investigation_id):
            raise ValueError("Invalid investigation ID")
        if not re.fullmatch(r"[0-9a-f]{32}", relation_id):
            raise ValueError("Invalid relation ID")
        if decision not in {"NEEDS_REVIEW", "SUPPORTED", "REJECTED"}:
            raise ValueError("Invalid review decision")
        if len(note) > 2000:
            raise ValueError("Review note must be at most 2000 characters")
        with self._connect(create=True) as connection:
            row = connection.execute(
                "SELECT report_json FROM investigations WHERE id = ?", (investigation_id,)
            ).fetchone()
            if row is None:
                raise ValueError("Investigation not found")
            report = json.loads(row[0])
            edges = (report.get("graph") or {}).get("edges", [])
            if not any(
                edge.get("id") == relation_id and edge.get("strength") == "hypothesis"
                for edge in edges
                if isinstance(edge, dict)
            ):
                raise ValueError("Relation is not a reviewable hypothesis")
            connection.execute(
                "INSERT INTO relation_reviews VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(investigation_id, relation_id) DO UPDATE SET "
                "decision=excluded.decision, note=excluded.note, updated_at=excluded.updated_at",
                (
                    investigation_id,
                    relation_id,
                    decision,
                    note,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )


def compare_investigations(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Compare observations; absence in one run never proves a profile vanished."""
    if old.get("target") != new.get("target") or old.get("target_type") != new.get("target_type"):
        raise ValueError("Investigations must have the same target and target type")

    def entity_map(report: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
        graph = report.get("graph") or {}
        return {
            (
                str(item["type"]),
                str(item.get("canonical_value"))
                if item.get("canonical_value") is not None
                else (
                    str(item["value"])
                    if str(item["type"]) == "USERNAME"
                    else str(item["value"]).casefold()
                ),
            ): item
            for item in graph.get("nodes", [])
        }

    def observation_map(
        report: dict[str, Any],
    ) -> dict[tuple[str, str, str, str, str, str], dict[str, Any]]:
        graph = report.get("graph") or {}
        nodes = {str(item["id"]): item for item in graph.get("nodes", []) if "id" in item}
        result = {}
        for item in graph.get("observations", []):
            node = nodes.get(str(item.get("entity_id")))
            if node is None:
                continue
            key = (
                str(node["type"]),
                str(node.get("canonical_value", node["value"])),
                str(item["property"]),
                json.dumps(item.get("value"), sort_keys=True, ensure_ascii=False),
                str(item["state"]),
                str(item["provider"]),
            )
            result[key] = {**item, "entity_type": node["type"], "entity_value": node["value"]}
        return result

    def profile_map(report: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
        return {
            (
                str(item["provider"]),
                str(item["username"])
                if str(item["provider"]) == "Hacker News"
                else str(item["username"]).casefold(),
            ): item
            for item in report.get("findings", [])
        }

    old_entities, new_entities = entity_map(old), entity_map(new)
    old_observations, new_observations = observation_map(old), observation_map(new)
    old_profiles, new_profiles = profile_map(old), profile_map(new)
    changes = [
        {
            "provider": new_profiles[key]["provider"],
            "username": new_profiles[key]["username"],
            "before": old_profiles[key]["status"],
            "after": new_profiles[key]["status"],
        }
        for key in old_profiles.keys() & new_profiles.keys()
        if old_profiles[key]["status"] != new_profiles[key]["status"]
    ]
    return {
        "target": new["target"],
        "old_id": old.get("investigation_id"),
        "new_id": new.get("investigation_id"),
        "added_entities": [
            new_entities[key] for key in sorted(new_entities.keys() - old_entities.keys())
        ],
        "not_observed_entities": [
            old_entities[key] for key in sorted(old_entities.keys() - new_entities.keys())
        ],
        "added_observations": [
            new_observations[key]
            for key in sorted(new_observations.keys() - old_observations.keys())
        ],
        "not_observed_observations": [
            old_observations[key]
            for key in sorted(old_observations.keys() - new_observations.keys())
        ],
        "added_profiles": [
            new_profiles[key] for key in sorted(new_profiles.keys() - old_profiles.keys())
        ],
        "not_observed_profiles": [
            old_profiles[key] for key in sorted(old_profiles.keys() - new_profiles.keys())
        ],
        "status_changes": sorted(changes, key=lambda item: (item["provider"], item["username"])),
        "partial": bool(
            old.get("errors")
            or new.get("errors")
            or old.get("rate_limits")
            or new.get("rate_limits")
        ),
    }
