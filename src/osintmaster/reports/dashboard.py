"""Read-only local dashboard server for saved investigations of one target."""

from __future__ import annotations

import re
import secrets
import sqlite3
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any, cast
from urllib.parse import parse_qs

from osintmaster.investigation.store import InvestigationStore, compare_investigations
from osintmaster.reports.html_report import render_html
from osintmaster.reports.json_report import render_json


def _display_time(value: Any) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    if parsed.tzinfo is None:
        return str(value)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _history_card(run: dict[str, Any], older: dict[str, Any] | None, current_id: str) -> str:
    run_id = escape(str(run["id"]), quote=True)
    compare_link = (
        '<a class="history-compare" href="/compare/'
        + escape(str(older["id"]), quote=True)
        + "/"
        + run_id
        + '">Compare with previous run →</a>'
        if older is not None
        else '<span class="history-compare muted">First saved run</span>'
    )
    return (
        '<article class="history-card"><a class="history-run" href="/run/'
        + run_id
        + '"><span class="history-time">'
        + escape(_display_time(run["created_at"]))
        + "</span><strong>"
        + escape(str(run["entity_count"]))
        + " entities · "
        + escape(str(run["edge_count"]))
        + " links</strong><small>"
        + run_id
        + (" · opened" if run["id"] == current_id else "")
        + "</small></a>"
        + compare_link
        + "</article>"
    )


def _history_page(data: dict[str, Any], runs: list[dict[str, Any]]) -> bytes:
    css = files("osintmaster.data").joinpath("dashboard.css").read_text(encoding="utf-8")
    current_id = str(data.get("investigation_id", ""))
    cards = "".join(
        _history_card(run, runs[index + 1] if index + 1 < len(runs) else None, current_id)
        for index, run in enumerate(runs)
    )
    title = escape(str(data.get("target", "")))
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>OSINTMaster / History / {title}</title><style>{css}
.history-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}}
.history-card{{display:flex;flex-direction:column;justify-content:space-between;gap:16px;padding:20px;border:1px solid var(--line);border-radius:14px;background:rgba(255,255,255,.03);overflow-wrap:anywhere}}
.history-card:hover{{border-color:var(--cyan)}}.history-run{{display:flex;flex-direction:column;gap:10px;color:inherit;text-decoration:none}}.history-run:hover strong{{color:var(--cyan)}}.history-card small,.history-time{{color:var(--muted)}}
.history-compare{{border-top:1px solid var(--line);padding-top:13px;color:var(--cyan);font-size:12px;font-weight:750;text-decoration:none}}.history-compare:hover{{text-decoration:underline}}
</style></head><body><div class="shell"><header class="masthead"><div class="brand"><span class="brand-mark">◎</span><span>OSINT<span class="accent">MASTER</span></span></div></header>
<nav class="run-nav"><a href="/">← Opened dashboard</a></nav><main>
<section class="hero"><div><p class="eyebrow">SAVED INVESTIGATIONS</p><h1>{title}</h1>
<p class="hero-sub">Open a previous run to inspect its recorded evidence.</p></div></section>
<section class="section"><div class="section-head"><h2>Run history</h2><span class="section-count">{len(runs)} shown</span></div>
<div class="history-grid">{cards or '<p class="muted">No saved runs for this target.</p>'}</div></section>
</main></div></body></html>"""
    return html.encode("utf-8")


def _diff_section(title: str, rows: list[str], total: int) -> str:
    content = "".join(f"<li>{row}</li>" for row in rows) or '<li class="muted">None recorded.</li>'
    note = (
        f'<p class="graph-note">Showing the first {len(rows)} of {total} items.</p>'
        if total > len(rows)
        else ""
    )
    return (
        '<section class="section compare-section"><div class="section-head"><h2>'
        + title
        + f'</h2><span class="section-count">{total}</span></div>'
        + f'<ul class="compare-list">{content}</ul>{note}</section>'
    )


def _comparison_page(result: dict[str, Any], old: dict[str, Any], new: dict[str, Any]) -> bytes:
    css = files("osintmaster.data").joinpath("dashboard.css").read_text(encoding="utf-8")
    old_id = escape(str(old["investigation_id"]), quote=True)
    new_id = escape(str(new["investigation_id"]), quote=True)
    title = escape(str(result["target"]))
    changes = result["status_changes"]
    added_profiles = result["added_profiles"]
    added_entities = result["added_entities"]
    added_observations = result.get("added_observations", [])
    missing_profiles = result["not_observed_profiles"]
    missing_entities = result["not_observed_entities"]
    missing_observations = result.get("not_observed_observations", [])
    status_rows = [
        "<strong>"
        + escape(str(item["provider"]))
        + " @"
        + escape(str(item["username"]))
        + "</strong><span>"
        + escape(str(item["before"]))
        + " → "
        + escape(str(item["after"]))
        + "</span>"
        for item in changes[:100]
    ]
    profile_rows = [
        "<strong>"
        + escape(str(item["provider"]))
        + " @"
        + escape(str(item["username"]))
        + "</strong><span>"
        + escape(str(item["status"]))
        + "</span>"
        for item in added_profiles[:100]
    ]
    missing_profile_rows = [
        "<strong>"
        + escape(str(item["provider"]))
        + " @"
        + escape(str(item["username"]))
        + "</strong><span>Last seen as "
        + escape(str(item["status"]))
        + "</span>"
        for item in missing_profiles[:100]
    ]
    entity_rows = [
        "<strong>"
        + escape(str(item["type"]))
        + "</strong><span>"
        + escape(str(item["value"]))
        + "</span>"
        for item in added_entities[:100]
    ]
    missing_entity_rows = [
        "<strong>"
        + escape(str(item["type"]))
        + "</strong><span>"
        + escape(str(item["value"]))
        + "</span>"
        for item in missing_entities[:100]
    ]

    def observation_rows(items: list[dict[str, Any]]) -> list[str]:
        return [
            "<strong>"
            + escape(str(item["entity_value"]))
            + " · "
            + escape(str(item["property"]))
            + "</strong><span>"
            + escape(str(item.get("value", "")))
            + " · "
            + escape(str(item["state"]))
            + "</span>"
            for item in items[:100]
        ]

    sections = "".join(
        (
            _diff_section("Profile status changes", status_rows, len(changes)),
            _diff_section("Newly observed profiles", profile_rows, len(added_profiles)),
            _diff_section("Newly observed entities", entity_rows, len(added_entities)),
            _diff_section(
                "New observations", observation_rows(added_observations), len(added_observations)
            ),
            _diff_section(
                "Profiles not observed in later run", missing_profile_rows, len(missing_profiles)
            ),
            _diff_section(
                "Entities not observed in later run", missing_entity_rows, len(missing_entities)
            ),
            _diff_section(
                "Observations not seen in later run",
                observation_rows(missing_observations),
                len(missing_observations),
            ),
        )
    )
    partial = (
        '<div class="compare-warning">At least one run was partial. Missing observations may reflect provider errors, blocked access or limits.</div>'
        if result["partial"]
        else ""
    )
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>OSINTMaster / Compare / {title}</title><style>{css}
.compare-links{{display:flex;flex-wrap:wrap;gap:18px;justify-content:flex-end;padding:14px 0 0}}.compare-links a{{color:var(--cyan);font-size:12px;font-weight:750;text-decoration:none}}.compare-links a:hover{{text-decoration:underline}}
.compare-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}}.compare-section{{margin:0}}.compare-section:first-child{{grid-column:1/-1}}
.compare-list{{list-style:none;padding:0;margin:0;display:grid;gap:10px}}.compare-list li{{display:flex;justify-content:space-between;gap:16px;overflow-wrap:anywhere;border-top:1px solid var(--line);padding:12px 0}}.compare-list li span{{color:var(--muted);text-align:right}}
.compare-context{{font-size:14px;color:var(--muted);margin:0 0 18px}}
.compare-warning{{border:1px solid var(--amber);border-radius:12px;padding:16px 20px;margin:0 0 20px;color:var(--amber)}}
@media(max-width:760px){{.compare-grid{{grid-template-columns:1fr}}.compare-section:first-child{{grid-column:auto}}.compare-list li{{display:block}}.compare-list li span{{display:block;text-align:left;margin-top:5px}}}}
</style></head><body><div class="shell"><header class="masthead"><div class="brand"><span class="brand-mark">◎</span><span>OSINT<span class="accent">MASTER</span></span></div></header>
<nav class="compare-links"><a href="/history">← Run history</a><a href="/run/{old_id}">Earlier run</a><a href="/run/{new_id}">Later run</a><a href="/compare/{old_id}/{new_id}/diff.json">View diff JSON</a></nav>
<main><section class="hero"><div><p class="eyebrow">INVESTIGATION COMPARISON</p><h1>{title}</h1>
<p class="hero-sub">{escape(_display_time(old.get("timestamp", "")))} → {escape(_display_time(new.get("timestamp", "")))}</p></div></section>
<p class="compare-context">A missing observation in the later run does not prove an account or entity was removed.</p>
{partial}<div class="compare-grid">{sections}</div></main></div></body></html>"""
    return html.encode("utf-8")


def _review_page(data: dict[str, Any], reviews: dict[str, dict[str, str]], token: str) -> bytes:
    """Render a local analyst workbench for scored, hypothetical relationships."""
    css = files("osintmaster.data").joinpath("dashboard.css").read_text(encoding="utf-8")
    graph = data.get("graph") or {}
    nodes = {node["id"]: node for node in graph.get("nodes", []) if isinstance(node, dict)}
    run_id = escape(str(data.get("investigation_id", "")), quote=True)
    cards = []
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict) or edge.get("strength") != "hypothesis":
            continue
        relation_id = str(edge.get("id", ""))
        review = reviews.get(relation_id, {})
        source = nodes.get(edge.get("source"), {})
        target = nodes.get(edge.get("target"), {})
        options = "".join(
            f'<option value="{choice}"'
            + (" selected" if review.get("decision", "NEEDS_REVIEW") == choice else "")
            + f">{label}</option>"
            for choice, label in (
                ("NEEDS_REVIEW", "Needs review"),
                ("SUPPORTED", "Supported by evidence"),
                ("REJECTED", "Rejected"),
            )
        )
        cards.append(
            '<article class="review-card"><h2>'
            + escape(str(source.get("value", "?")))
            + " ↔ "
            + escape(str(target.get("value", "?")))
            + '</h2><p class="muted">Heuristic support: '
            + escape(str(edge.get("score", "?")))
            + '/100 · Source hypothesis</p><form method="post" action="/review/'
            + run_id
            + '"><input type="hidden" name="token" value="'
            + escape(token, quote=True)
            + '"><input type="hidden" name="relation_id" value="'
            + escape(relation_id, quote=True)
            + '"><label>Decision <select name="decision">'
            + options
            + '</select></label><label>Analyst note <textarea name="note" maxlength="2000" rows="3">'
            + escape(review.get("note", ""))
            + '</textarea></label><button type="submit">Save decision</button></form>'
            + (
                '<small class="muted">Updated ' + escape(review["updated_at"]) + "</small>"
                if review.get("updated_at")
                else ""
            )
            + "</article>"
        )
    title = escape(str(data.get("target", "")))
    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'">
<title>OSINTMaster / Review / {title}</title><style>{css}
.review-list{{display:grid;gap:18px}}.review-card{{padding:20px;border:1px solid var(--line);border-radius:14px;background:rgba(255,255,255,.03);overflow-wrap:anywhere}}.review-card h2{{font-size:17px;margin:0 0 10px}}.review-card form{{display:grid;gap:12px;margin:14px 0}}.review-card label{{display:grid;gap:6px;color:var(--muted)}}.review-card select,.review-card textarea{{width:100%;padding:10px;color:var(--text);background:#182335;border:1px solid var(--line);border-radius:8px}}.review-card button{{justify-self:start;padding:9px 15px;color:#0b1821;background:var(--cyan);border:0;border-radius:8px;font-weight:800;cursor:pointer}}
</style></head><body><div class="shell"><header class="masthead"><div class="brand"><span class="brand-mark">◎</span><span>OSINT<span class="accent">MASTER</span></span></div></header>
<nav class="run-nav"><a href="/run/{run_id}">← Investigation graph</a><a href="/history">Run history</a><a href="/review/{run_id}/reviews.json">Review JSON</a></nav>
<main><section class="hero"><div><p class="eyebrow">ANALYST REVIEW</p><h1>{title}</h1><p class="hero-sub">Decisions are local notes about evidence, not proof of real-world identity. The scan snapshot stays unchanged.</p></div></section>
<section class="section"><div class="section-head"><h2>Hypothetical links</h2><span class="section-count">{len(cards)}</span></div><div class="review-list">{"".join(cards) or '<p class="muted">No scored hypotheses in this run.</p>'}</div></section></main></div></body></html>"""
    return html.encode("utf-8")


def make_dashboard_server(
    data: dict[str, Any], port: int = 0, *, store: InvestigationStore | None = None
) -> ThreadingHTTPServer:
    if not 0 <= port <= 65535:
        raise ValueError("Port must be between 0 and 65535")
    html = render_html(data, show_history=store is not None).encode("utf-8")
    json_bytes = render_json(data).encode("utf-8")
    target = data.get("target")
    target_type = data.get("target_type")
    review_token = secrets.token_urlsafe(32)

    def load_saved(run_id: str) -> dict[str, Any] | None:
        if store is None:
            return None
        try:
            saved = store.load(run_id)
        except (OSError, sqlite3.Error, ValueError, FileNotFoundError):
            return None
        if saved.get("target") != target or saved.get("target_type") != target_type:
            return None
        return saved

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            server = cast(ThreadingHTTPServer, self.server)
            expected_hosts = {
                f"127.0.0.1:{server.server_port}",
                f"localhost:{server.server_port}",
            }
            if self.headers.get("Host") not in expected_hosts:
                self.send_error(403, "Localhost only")
                return
            if self.path == "/":
                body, content_type = html, "text/html; charset=utf-8"
            elif self.path == "/report.json":
                body, content_type = json_bytes, "application/json; charset=utf-8"
            elif self.path == "/history" and store is not None:
                try:
                    rows = store.list(
                        target=str(target),
                        target_type=str(target_type) if target_type is not None else None,
                        limit=100,
                    )
                    if target_type is None:
                        rows = [row for row in rows if row["target_type"] is None]
                except (OSError, sqlite3.Error, ValueError):
                    self.send_error(500, "History unavailable")
                    return
                body, content_type = _history_page(data, rows), "text/html; charset=utf-8"
            elif store is not None and (
                review_match := re.fullmatch(r"/review/([0-9a-f]{32})(/reviews\.json)?", self.path)
            ):
                saved = load_saved(review_match.group(1))
                if saved is None:
                    self.send_error(404, "Run not found")
                    return
                try:
                    reviews = store.reviews(review_match.group(1))
                except (OSError, sqlite3.Error, ValueError):
                    self.send_error(500, "Reviews unavailable")
                    return
                if review_match.group(2):
                    body = render_json(reviews).encode("utf-8")
                    content_type = "application/json; charset=utf-8"
                else:
                    body = _review_page(saved, reviews, review_token)
                    content_type = "text/html; charset=utf-8"
            elif store is not None and (
                match := re.fullmatch(r"/run/([0-9a-f]{32})(/report\.json)?", self.path)
            ):
                saved = load_saved(match.group(1))
                if saved is None:
                    self.send_error(404, "Run not found")
                    return
                if match.group(2):
                    body = render_json(saved).encode("utf-8")
                    content_type = "application/json; charset=utf-8"
                else:
                    body = render_html(saved, show_history=True).encode("utf-8")
                    content_type = "text/html; charset=utf-8"
            elif store is not None and (
                pair := re.fullmatch(
                    r"/compare/([0-9a-f]{32})/([0-9a-f]{32})(/diff\.json)?", self.path
                )
            ):
                older = load_saved(pair.group(1))
                newer = load_saved(pair.group(2))
                if older is None or newer is None:
                    self.send_error(404, "Run not found")
                    return
                try:
                    difference = compare_investigations(older, newer)
                except (KeyError, TypeError, ValueError):
                    self.send_error(500, "Comparison unavailable")
                    return
                if pair.group(3):
                    body = render_json(difference).encode("utf-8")
                    content_type = "application/json; charset=utf-8"
                else:
                    body = _comparison_page(difference, older, newer)
                    content_type = "text/html; charset=utf-8"
            else:
                self.send_error(404, "Not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            server = cast(ThreadingHTTPServer, self.server)
            host = self.headers.get("Host")
            if host not in {f"127.0.0.1:{server.server_port}", f"localhost:{server.server_port}"}:
                self.send_error(403, "Localhost only")
                return
            match = re.fullmatch(r"/review/([0-9a-f]{32})", self.path)
            if store is None or match is None or load_saved(match.group(1)) is None:
                self.send_error(404, "Run not found")
                return
            if self.headers.get("Origin") != f"http://{host}":
                self.send_error(403, "Invalid origin")
                return
            if self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
                self.send_error(415, "Form encoding required")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 4096:
                    raise ValueError("Invalid form size")
                form = parse_qs(
                    self.rfile.read(length).decode("utf-8"),
                    keep_blank_values=True,
                    strict_parsing=True,
                    max_num_fields=4,
                )
                if set(form) != {"token", "relation_id", "decision", "note"} or any(
                    len(values) != 1 for values in form.values()
                ):
                    raise ValueError("Invalid form fields")
                if not secrets.compare_digest(form["token"][0], review_token):
                    self.send_error(403, "Invalid form token")
                    return
                store.save_review(
                    match.group(1),
                    form["relation_id"][0],
                    form["decision"][0],
                    form["note"][0],
                )
            except (UnicodeError, ValueError, OSError, sqlite3.Error):
                self.send_error(400, "Invalid review")
                return
            self.send_response(303)
            self.send_header("Location", self.path)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
