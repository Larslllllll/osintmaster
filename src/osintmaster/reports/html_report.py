"""Self-contained, interactive HTML dashboard for saved public observations."""

from __future__ import annotations

import json
from collections import Counter
from enum import Enum
from html import escape
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from osintmaster.core.models import Report
from osintmaster.reports.json_report import report_directory


def _cell(value: Any) -> str:
    if isinstance(value, Enum):
        value = value.value
    return escape(str(value if value is not None else ""), quote=True)


def _link(url: Any, label: str | None = None) -> str:
    if not isinstance(url, str):
        return _cell(label or url)
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
            return _cell(label or url)
    except ValueError:
        return _cell(label or url)
    return (
        f'<a href="{_cell(url)}" target="_blank" rel="noopener noreferrer">'
        f"{_cell(label or url)}</a>"
    )


def _finding(item: dict[str, Any]) -> str:
    profile = item.get("profile") or {}
    status = _cell(item.get("status"))
    name = _cell(item.get("provider"))
    handle = _cell(item.get("username"))
    fields = []
    for label, key in (
        ("Account type", "account_type"),
        ("Display name", "display_name"),
        ("Location claim", "location"),
        ("Bio", "bio"),
    ):
        if profile.get(key):
            fields.append(
                f'<div class="profile-field"><span>{label}</span><p>{_cell(profile[key])}</p></div>'
            )
    links = "".join(
        f"<li>{_link(url)}</li>" for url in profile.get("links", []) if isinstance(url, str)
    )
    if links:
        fields.append(f'<div class="profile-field"><span>Public links</span><ul>{links}</ul></div>')
    evidence = "".join(
        "<li><b>"
        + _cell(proof.get("type", "")).replace("_", " ")
        + "</b> · "
        + _cell(proof.get("value", ""))
        + " · "
        + _link(proof.get("source", ""), "source")
        + "</li>"
        for proof in item.get("evidence", [])
    )
    if evidence:
        fields.append(f'<div class="profile-field"><span>Evidence</span><ul>{evidence}</ul></div>')
    if item.get("error"):
        fields.append(
            f'<div class="profile-field"><span>Why unresolved</span><p>{_cell(item["error"])}</p></div>'
        )
    if item.get("http_status"):
        fields.append(
            f'<div class="profile-field"><span>HTTP status</span><p>{_cell(item["http_status"])}</p></div>'
        )
    detail = "".join(fields) or '<p class="muted">No additional public profile data returned.</p>'
    opened = " open" if status == "CONFIRMED" else ""
    return (
        f'<details class="result-card" data-status="{status}"{opened}>'
        f'<summary><span class="source">{name}</span><span class="handle">@{handle}</span>'
        f'<span class="badge badge-{status.lower()}">{status}</span></summary>'
        f'<div class="result-body"><div class="profile-field"><span>Public profile</span>'
        f"<p>{_link(item.get('url'))}</p></div>{detail}</div></details>"
    )


def _correlation(item: dict[str, Any]) -> str:
    reasons = "".join(
        f"<li>+{_cell(proof.get('weight'))} {_cell(proof.get('type')).replace('_', ' ')}"
        f" · {_cell(proof.get('value'))}</li>"
        for proof in item.get("evidence", [])
    )
    return (
        '<article class="relation"><div class="relation-head">'
        f"<strong>{_cell(item.get('score'))}/100</strong>"
        f"<span>{_cell(item.get('label'))}</span></div>"
        f"<p>{_link(item.get('left_url'))} ↔ {_link(item.get('right_url'))}</p>"
        f"<ul>{reasons}</ul></article>"
    )


def _event_card(item: dict[str, Any], parents: dict[str, dict[str, Any]]) -> str:
    parent = parents.get(str(item.get("parent_id")), {})
    origin = (
        f"<div><span>Discovered from</span><p>{_cell(parent.get('type', ''))} "
        f"{_cell(parent.get('value', ''))}</p></div>"
        if parent
        else ""
    )
    evidence = "".join(
        f"<li>{_cell(proof.get('type', '')).replace('_', ' ')}: "
        f"{_cell(proof.get('value', ''))}</li>"
        for proof in item.get("evidence", [])
    )
    proof_row = f"<div><span>Evidence</span><ul>{evidence}</ul></div>" if evidence else ""
    return (
        '<details class="trail-event"><summary>'
        f'<span class="trail-depth">D{_cell(item.get("depth", 0))}</span>'
        f'<span class="trail-type">{_cell(item.get("type", "")).replace("_", " ")}</span>'
        f'<span class="trail-value">{_cell(item.get("value", ""))}</span>'
        f'<span class="trail-provider">{_cell(item.get("source_provider", ""))}</span>'
        '</summary><div class="trail-detail">'
        f"{origin}<div><span>Source</span><p>{_link(item.get('source_url'))}</p></div>"
        f"<div><span>Retrieved</span><p>{_cell(item.get('retrieved_at', ''))}</p></div>"
        f"{proof_row}</div></details>"
    )


def render_html(report: Report | dict[str, Any], *, show_history: bool = False) -> str:
    data = report.to_dict() if isinstance(report, Report) else report
    findings = [item for item in data.get("findings", []) if isinstance(item, dict)]
    priority = {
        "CONFIRMED": 0,
        "PROBABLE": 1,
        "POSSIBLE": 2,
        "UNKNOWN": 3,
        "BLOCKED": 4,
        "AUTH_REQUIRED": 4,
        "RATE_LIMITED": 5,
        "ERROR": 6,
        "NOT_FOUND": 7,
    }
    findings.sort(key=lambda item: priority.get(_cell(item.get("status")), 7))
    counts = Counter(_cell(item.get("status")) for item in findings)
    confirmed = counts["CONFIRMED"]
    leads = counts["PROBABLE"] + counts["POSSIBLE"]
    unresolved = (
        counts["UNKNOWN"]
        + counts["BLOCKED"]
        + counts["AUTH_REQUIRED"]
        + counts["RATE_LIMITED"]
        + counts["ERROR"]
    )
    cards = "".join(_finding(item) for item in findings)
    correlations = sorted(
        (item for item in data.get("correlations", []) if item.get("score", 0) >= 30),
        key=lambda item: item.get("score", 0),
        reverse=True,
    )
    relation_cards = "".join(_correlation(item) for item in correlations[:20])
    pivot_sources: dict[str, list[str]] = {}
    for item in findings:
        if _cell(item.get("status")) not in {"CONFIRMED", "PROBABLE", "POSSIBLE"}:
            continue
        for url in (item.get("profile") or {}).get("links", []):
            if isinstance(url, str):
                try:
                    valid = urlsplit(url).scheme in {"http", "https"}
                except ValueError:
                    valid = False
                if valid:
                    pivot_sources.setdefault(url, []).append(str(item.get("provider", "")))
    pivots = "".join(
        f"<li>{_link(url)}<small>{_cell(', '.join(dict.fromkeys(sources)))}</small></li>"
        for url, sources in list(pivot_sources.items())[:50]
    )
    issues = "".join(
        f"<li>{_cell(message)}</li>"
        for message in [*data.get("errors", []), *data.get("rate_limits", [])]
    )
    activity: dict[str, dict[str, Any]] = {}
    for run in data.get("provider_runs", []):
        name = str(run.get("provider", "Unknown"))
        item = activity.setdefault(
            name,
            {"calls": 0, "requests": 0, "events": 0, "errors": 0, "cost": run.get("cost", "")},
        )
        item["calls"] += 1
        item["requests"] += int(run.get("requests_used", 0))
        item["events"] += int(run.get("events_emitted", 0))
        item["errors"] += int(run.get("status") != "OK")
    activity_items = "".join(
        "<li><strong>"
        + _cell(name)
        + "</strong><small>"
        + _cell(item["cost"])
        + " · "
        + _cell(item["calls"])
        + " calls · "
        + _cell(item["requests"])
        + " requests · "
        + _cell(item["events"])
        + " events"
        + (" · " + _cell(item["errors"]) + " errors" if item["errors"] else "")
        + "</small></li>"
        for name, item in activity.items()
    )
    events = [item for item in data.get("events", []) if isinstance(item, dict)]
    parent_events = {str(item.get("id")): item for item in events}
    trail_cards = "".join(_event_card(item, parent_events) for item in events[:150])
    trail_section = ""
    if events:
        truncated = (
            f'<p class="graph-note">Showing the first 150 of {len(events)} events. '
            "The complete trail is in report.json and events.jsonl.</p>"
            if len(events) > 150
            else ""
        )
        trail_section = (
            '<section class="section"><div class="section-head"><div><p class="eyebrow">03 / EVIDENCE TRAIL</p>'
            "<h2>How this graph was built</h2></div>"
            f'<span class="section-count">{len(events)} observations</span></div>'
            f'<div class="trail">{trail_cards}</div>{truncated}</section>'
        )
    css = files("osintmaster.data").joinpath("dashboard.css").read_text(encoding="utf-8")
    js = files("osintmaster.data").joinpath("dashboard.js").read_text(encoding="utf-8")
    graph = data.get("graph")
    graph_blob = ""
    graph_section = ""
    timeline_section = ""
    recommended_pivots = ""
    if isinstance(graph, dict):
        observations = sorted(
            (item for item in graph.get("observations", []) if isinstance(item, dict)),
            key=lambda item: str(item.get("observed_at", "")),
            reverse=True,
        )
        timeline_items = "".join(
            "<li><strong>"
            + _cell(item.get("property"))
            + "</strong><small>"
            + _cell(item.get("state"))
            + " · "
            + _cell(item.get("provider"))
            + " · "
            + _cell(item.get("observed_at"))
            + "</small></li>"
            for item in observations[:50]
        )
        if observations:
            timeline_section = (
                '<section class="section"><div class="section-head"><div><p class="eyebrow">TIMELINE</p>'
                "<h2>Recent observations</h2></div>"
                f'<span class="section-count">{len(observations)} recorded</span></div>'
                f'<ul class="provider-list">{timeline_items}</ul></section>'
            )
        recommended_pivots = "".join(
            "<li><strong>"
            + _cell(
                next(
                    (
                        node.get("value")
                        for node in graph.get("nodes", [])
                        if node.get("id") == item.get("entity_id")
                    ),
                    "",
                )
            )
            + "</strong><small>Priority "
            + _cell(item.get("priority"))
            + " · "
            + _cell(item.get("status"))
            + " · "
            + _cell(item.get("reason"))
            + "</small></li>"
            for item in graph.get("pivot_candidates", [])[:15]
            if isinstance(item, dict)
        )
        graph_blob = (
            json.dumps(graph, ensure_ascii=False)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )
        graph_section = f"""<section class="section graph-section"><div class="section-head"><div><p class="eyebrow">02 / ENTITY GRAPH</p><h2>Investigation graph</h2></div><span class="section-count">{len(graph.get("nodes", []))} entities · {len(graph.get("edges", []))} links</span></div>
<div class="graph-toolbar"><input id="graph-query" type="search" placeholder="Find an entity..." aria-label="Find an entity"><select id="graph-type" aria-label="Filter entity type"><option value="all">All entity types</option></select></div>
<div class="graph-legend"><span><i class="legend-username"></i> Username</span><span><i class="legend-profile"></i> Profile</span><span><i class="legend-url"></i> URL</span><span><i class="legend-domain"></i> Domain</span><span><i class="legend-email"></i> Email</span></div>
<div class="graph-wrap"><svg id="graph-svg" viewBox="0 0 1000 620" role="img" aria-label="Interactive investigation graph"></svg></div><div id="graph-detail" class="graph-detail">Select a node to inspect its provenance and evidence.</div>
<p class="graph-note">Lines show observed or claimed relationships. They do not prove shared ownership.</p></section>"""
    run_navigation = (
        '<nav class="run-nav"><a href="/history">Browse saved runs →</a>'
        f'<a href="/review/{_cell(data.get("investigation_id"))}">Review hypotheses →</a></nav>'
        if show_history
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src https: data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>OSINTMaster / {_cell(data.get("target"))}</title><style>{css}</style></head>
<body><div class="shell">
<header class="masthead"><div class="brand"><span class="brand-mark">◎</span><span>OSINT<span class="accent">MASTER</span></span></div>
<div class="header-side">PUBLIC SOURCE INTELLIGENCE <span>·</span> v{_cell(data.get("version"))}</div></header>
{run_navigation}
<main>
<section class="hero"><div><p class="eyebrow">INVESTIGATION / {_cell(data.get("target_type") or "USERNAME")}</p>
<h1>{_cell(data.get("target"))}</h1><p class="hero-sub">Public account signals, cross-profile clues, and source evidence in one place.</p></div>
<div class="hero-meta"><span>SCAN TIMESTAMP</span><strong>{_cell(data.get("timestamp"))}</strong>
<span>RUN ID</span><strong>{_cell(data.get("investigation_id", ""))}</strong>
<span>REPORT STATUS</span><strong>{len(findings)} checks · {_cell((data.get("limits") or {}).get("requests_used", 0))} requests</strong></div></section>
<section class="metrics" aria-label="Scan summary">
<div class="metric"><span>CONFIRMED PROFILES</span><strong class="green">{confirmed}</strong><small>Exact public API match or verified profile page</small></div>
<div class="metric"><span>LEADS TO REVIEW</span><strong class="amber">{leads}</strong><small>Public pages without enough proof</small></div>
<div class="metric"><span>NOT FOUND</span><strong>{counts["NOT_FOUND"]}</strong><small>Source reported no matching account</small></div>
<div class="metric"><span>UNRESOLVED</span><strong class="rose">{unresolved}</strong><small>Blocked, timed out, or ambiguous</small></div></section>
<div class="content-grid"><div class="main-column">
<section class="section"><div class="section-head"><div><p class="eyebrow">01 / SOURCE COVERAGE</p><h2>Profile map</h2></div><span class="section-count">{len(findings)} sources</span></div>
<div class="toolbar"><label class="sr-only" for="query">Search findings</label><input id="query" type="search" placeholder="Search source, username, bio, URL...">
<label class="sr-only" for="status-filter">Filter status</label><select id="status-filter"><option value="active">Signals and issues</option><option value="all">All statuses</option><option value="CONFIRMED">Confirmed</option><option value="POSSIBLE">Possible</option><option value="NOT_FOUND">Not found</option><option value="unresolved">Unresolved</option></select></div>
<p id="visible-count" class="result-count" aria-live="polite"></p><div id="findings">{cards}</div>
<p id="empty-results" class="empty" hidden>No findings match this filter.</p></section>
{graph_section}
{timeline_section}
{trail_section}
<section class="section"><div class="section-head"><div><p class="eyebrow">04 / CROSS-PROFILE</p><h2>Relationships</h2></div><span class="section-count">{len(correlations)} supported links</span></div>
{relation_cards or '<p class="empty">No cross-profile link has enough independent evidence yet. Matching usernames alone are weak evidence.</p>'}</section>
</div><aside class="side-column"><section class="section"><p class="eyebrow">05 / PIVOT POINTS</p><h2>Public links</h2>
<p class="section-sub">Links published on matched profiles. Open and review manually.</p><ul class="pivot-list">{pivots or '<li class="muted">No public links found.</li>'}</ul></section>
<section class="section"><p class="eyebrow">PIVOT PRIORITY</p><h2>Next leads</h2>
<p class="section-sub">Estimated information gain divided by collection cost. Processed leads remain visible.</p>
<ul class="provider-list">{recommended_pivots or '<li class="muted">No pivots recorded.</li>'}</ul></section>
<section class="section"><p class="eyebrow">06 / SCAN NOTES</p><h2>Unresolved checks</h2>
<ul class="issue-list">{issues or '<li class="muted">No errors or rate limits recorded.</li>'}</ul></section>
<section class="section"><p class="eyebrow">07 / PROVIDER ACTIVITY</p><h2>Run log</h2>
<ul class="provider-list">{activity_items or '<li class="muted">No event providers ran.</li>'}</ul></section>
<div class="notice"><strong>Evidence ≠ identity</strong><p>A matching handle or profile page does not prove who owns an account. Review each claim and source before drawing conclusions.</p></div>
</aside></div></main><footer>OSINTMASTER · LOCAL REPORT · NO TRACKING OR EXTERNAL SCRIPTS</footer>
</div><script id="graph-data" type="application/json">{graph_blob}</script><script type="text/javascript">{js}</script></body></html>"""


def save_html(report: Report, root: Path) -> Path:
    directory = report_directory(root, report.target)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "report.html"
    temporary = directory / "report.html.tmp"
    temporary.write_text(render_html(report), encoding="utf-8")
    temporary.replace(destination)
    return destination
