"""JSON report serialization and safe local destination."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from osintmaster.core.models import Report
from osintmaster.core.normalization import normalize_url, validated_username


def report_directory(root: Path, target: str) -> Path:
    try:
        handle = validated_username(target)
        folded = handle.casefold()
        if handle == folded:
            return root / folded
        digest = hashlib.sha256(handle.encode("utf-8")).hexdigest()[:8]
        return root / f"{folded}-{digest}"
    except ValueError:
        if target.startswith(("https://", "http://")):
            canonical = normalize_url(target)
        elif re.fullmatch(r"[^\s@]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", target):
            canonical = target.casefold()
        elif re.fullmatch(r"\+[1-9][0-9]{7,14}", target):
            canonical = target
        elif Path(target).is_absolute() and Path(target).suffix.lower() in {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".tif",
            ".tiff",
        }:
            canonical = str(Path(target).resolve())
        else:
            try:
                canonical = str(ipaddress.ip_address(target))
            except ValueError as exc:
                raise ValueError("Invalid report target") from exc
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]
        kind = "url" if urlsplit(canonical).scheme in {"http", "https"} else "target"
        return root / f"{kind}-{digest}"


def render_json(report: Report | dict[str, Any], *, ascii_only: bool = False) -> str:
    data = report.to_dict() if isinstance(report, Report) else report
    return json.dumps(data, ensure_ascii=ascii_only, indent=2) + "\n"


def save_json(report: Report, root: Path) -> Path:
    directory = report_directory(root, report.target)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "report.json"
    temporary = directory / "report.json.tmp"
    temporary.write_text(render_json(report), encoding="utf-8")
    temporary.replace(destination)
    return destination


def save_graph(report: Report, root: Path) -> Path:
    if report.graph is None:
        raise ValueError("Report does not contain an investigation graph")
    directory = report_directory(root, report.target)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "graph.json"
    temporary = directory / "graph.json.tmp"
    temporary.write_text(
        json.dumps(report.graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(destination)
    return destination


def save_jsonl(report: Report, root: Path) -> Path:
    """Write a streaming-friendly snapshot with one typed observation per line."""
    directory = report_directory(root, report.target)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "events.jsonl"
    temporary = directory / "events.jsonl.tmp"
    rows: list[dict[str, Any]] = [
        {
            "record": "investigation",
            "id": report.investigation_id,
            "target": report.target,
            "target_type": report.target_type,
            "timestamp": report.timestamp,
            "version": report.version,
            "limits": report.limits,
        }
    ]
    rows.extend({"record": "event", **event} for event in report.events)
    if report.graph:
        rows.extend({"record": "entity", **node} for node in report.graph.get("nodes", []))
        rows.extend({"record": "relationship", **edge} for edge in report.graph.get("edges", []))
        rows.extend(
            {"record": "observation", **item} for item in report.graph.get("observations", [])
        )
        rows.extend({"record": "evidence", **item} for item in report.graph.get("evidence", []))
        rows.extend(
            {"record": "pivot_candidate", **item}
            for item in report.graph.get("pivot_candidates", [])
        )
        rows.extend(
            {"record": "graph_provider_run", **item}
            for item in report.graph.get("provider_runs", [])
        )
    rows.extend({"record": "finding", **item} for item in report.to_dict()["findings"])
    rows.extend({"record": "provider_run", **item} for item in report.provider_runs)
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    temporary.replace(destination)
    return destination


def load_report(root: Path, target: str) -> dict[str, Any]:
    path = report_directory(root, target) / "report.json"
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if (
        not isinstance(data, dict)
        or report_directory(root, str(data.get("target", ""))) != path.parent
    ):
        raise ValueError("Invalid saved report")
    return data
