"""Loopback-only workspace for starting and browsing bounded investigations."""

from __future__ import annotations

import asyncio
import re
import secrets
import sqlite3
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any, cast
from urllib.parse import parse_qs

from osintmaster.config import Config
from osintmaster.core.normalization import validated_username
from osintmaster.investigation.engine import HuntEngine, HuntLimits
from osintmaster.investigation.store import InvestigationStore
from osintmaster.investigation.targets import classify_target
from osintmaster.plugins.manager import load_event_plugins
from osintmaster.providers.username import load_sites
from osintmaster.reports.html_report import render_html, save_html
from osintmaster.reports.json_report import render_json, save_graph, save_json, save_jsonl


def _page(title: str, content: str, *, refresh: bool = False) -> bytes:
    css = files("osintmaster.data").joinpath("dashboard.css").read_text(encoding="utf-8")
    meta = '<meta http-equiv="refresh" content="2">' if refresh else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{meta}
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'">
<title>OSINTMaster / {escape(title)}</title><style>{css}
.work-form{{display:grid;gap:12px;max-width:680px}}.work-form label{{display:grid;gap:6px;color:var(--muted)}}.work-form input,.work-form textarea,.work-form select{{padding:10px;border:1px solid var(--line);border-radius:8px;color:var(--text);background:#182335}}.work-form button{{justify-self:start;padding:10px 18px;border:0;border-radius:8px;color:#0b1821;background:var(--cyan);font-weight:800;cursor:pointer}}.work-list{{list-style:none;padding:0;display:grid;gap:10px}}.work-list li{{padding:12px;border:1px solid var(--line);border-radius:8px;overflow-wrap:anywhere}}.work-list a{{color:var(--cyan)}}
</style></head><body><div class="shell"><header class="masthead"><div class="brand"><span class="brand-mark">◎</span><span>OSINT<span class="accent">MASTER</span></span></div></header>
<nav class="run-nav"><a href="/">Workspace</a></nav><main>{content}</main></div></body></html>""".encode()


def make_workspace_server(config: Config, port: int = 0) -> ThreadingHTTPServer:
    """Serve a single-user local workspace; every scan uses the normal CLI budgets."""
    config.validate()
    if not 0 <= port <= 65535:
        raise ValueError("Port must be between 0 and 65535")
    store = InvestigationStore(config.reports_dir)
    token = secrets.token_urlsafe(32)
    jobs: dict[str, dict[str, str]] = {}
    lock = threading.Lock()

    def scan(job_id: str, targets: list[str], name: str, limits: HuntLimits, wide: bool) -> None:
        try:
            plugins, plugin_errors = load_event_plugins(config)
            engine = HuntEngine(
                config,
                sites=load_sites(wide=wide),
                event_providers=plugins,
                plugin_errors=plugin_errors,
            )
            report = asyncio.run(
                engine.hunt(targets[0], limits=limits)
                if len(targets) == 1
                else engine.hunt_many(name, targets, limits=limits)
            )
            save_json(report, config.reports_dir)
            save_html(report, config.reports_dir)
            save_graph(report, config.reports_dir)
            save_jsonl(report, config.reports_dir)
            store.save(report)
            with lock:
                jobs[job_id] = {
                    "status": "partial" if report.errors or report.rate_limits else "complete",
                    "investigation_id": report.investigation_id,
                }
        except Exception:
            with lock:
                jobs[job_id] = {"status": "error", "message": "Investigation failed"}

    class Handler(BaseHTTPRequestHandler):
        def _local_host(self) -> str | None:
            server = cast(ThreadingHTTPServer, self.server)
            host = self.headers.get("Host")
            return (
                host
                if host in {f"127.0.0.1:{server.server_port}", f"localhost:{server.server_port}"}
                else None
            )

        def _reply(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self._local_host() is None:
                self.send_error(403, "Localhost only")
                return
            if self.path == "/":
                try:
                    rows = store.list(limit=100)
                except (OSError, sqlite3.Error, ValueError):
                    self.send_error(500, "History unavailable")
                    return
                items = "".join(
                    '<li><a href="/runs/'
                    + escape(str(row["id"]), quote=True)
                    + '">'
                    + escape(str(row["target"]))
                    + "</a> · "
                    + escape(str(row["target_type"]))
                    + " · "
                    + escape(str(row["created_at"]))
                    + "</li>"
                    for row in rows
                )
                content = (
                    '<section class="hero"><div><p class="eyebrow">LOCAL WORKSPACE</p><h1>Investigations</h1>'
                    '<p class="hero-sub">Start one target or a case with 2–20 seeds. The browser stays on this computer.</p></div></section>'
                    '<section class="section"><h2>New investigation</h2><form class="work-form" method="post" action="/runs">'
                    '<input type="hidden" name="token" value="' + escape(token, quote=True) + '">'
                    '<label>Targets, one per line<textarea name="targets" required rows="4" maxlength="4000"></textarea></label>'
                    '<label>Case name (required for multiple targets)<input name="name" maxlength="64"></label>'
                    '<label>Pivot depth<select name="depth"><option value="0">0</option><option value="1" selected>1</option><option value="2">2</option><option value="3">3</option></select></label>'
                    '<label>Maximum requests<input name="max_requests" type="number" min="0" max="1000" value="50"></label>'
                    '<label><input name="wide" type="checkbox" value="yes"> Include extended source catalogue</label>'
                    '<button type="submit">Start investigation</button></form></section>'
                    '<section class="section"><h2>Saved runs</h2><ul class="work-list">'
                    + (items or '<li class="muted">No saved investigations yet.</li>')
                    + "</ul></section>"
                )
                self._reply(200, _page("Workspace", content), "text/html; charset=utf-8")
                return
            job = re.fullmatch(r"/jobs/([0-9a-f]{16})(\.json)?", self.path)
            if job:
                with lock:
                    status = jobs.get(job.group(1))
                if status is None:
                    self.send_error(404, "Job not found")
                    return
                if job.group(2):
                    self._reply(
                        200, render_json(status).encode("utf-8"), "application/json; charset=utf-8"
                    )
                else:
                    link = (
                        '<p><a href="/runs/'
                        + escape(status["investigation_id"])
                        + '">Open report →</a></p>'
                        if "investigation_id" in status
                        else ""
                    )
                    content = (
                        '<section class="hero"><div><p class="eyebrow">SCAN JOB</p><h1>'
                        + escape(status["status"].title())
                        + "</h1>"
                        + link
                        + "</div></section>"
                    )
                    self._reply(
                        200,
                        _page("Job", content, refresh=status["status"] == "running"),
                        "text/html; charset=utf-8",
                    )
                return
            run = re.fullmatch(r"/runs/([0-9a-f]{32})(/report\.json)?", self.path)
            if run:
                try:
                    report = store.load(run.group(1))
                except (OSError, sqlite3.Error, ValueError, FileNotFoundError):
                    self.send_error(404, "Run not found")
                    return
                if run.group(2):
                    self._reply(
                        200, render_json(report).encode("utf-8"), "application/json; charset=utf-8"
                    )
                else:
                    self._reply(
                        200, render_html(report).encode("utf-8"), "text/html; charset=utf-8"
                    )
                return
            self.send_error(404, "Not found")

        def do_POST(self) -> None:
            host = self._local_host()
            if host is None or self.headers.get("Origin") != f"http://{host}":
                self.send_error(403, "Local origin required")
                return
            if self.path != "/runs":
                self.send_error(404, "Not found")
                return
            if self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
                self.send_error(415, "Form encoding required")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 5000:
                    raise ValueError("Invalid form size")
                form = parse_qs(
                    self.rfile.read(length).decode("utf-8"),
                    keep_blank_values=True,
                    strict_parsing=True,
                    max_num_fields=6,
                )
                if set(form) not in (
                    {"token", "targets", "name", "depth", "max_requests"},
                    {"token", "targets", "name", "depth", "max_requests", "wide"},
                ) or any(len(values) != 1 for values in form.values()):
                    raise ValueError("Invalid form fields")
                if not secrets.compare_digest(form["token"][0], token):
                    self.send_error(403, "Invalid form token")
                    return
                targets = [item.strip() for item in form["targets"][0].splitlines() if item.strip()]
                if not 1 <= len(targets) <= 20:
                    raise ValueError("Use 1 to 20 targets")
                name = form["name"][0].strip()
                if len(targets) > 1 and not name:
                    raise ValueError("Cases require a name")
                if len(targets) > 1:
                    validated_username(name)
                if len(set(classify_target(item) for item in targets)) != len(targets):
                    raise ValueError("Targets must be distinct")
                depth = int(form["depth"][0])
                requests = int(form["max_requests"][0])
                limits = HuntLimits(depth=depth, max_requests=requests)
                limits.validate()
                wide = form.get("wide", [""])[0] == "yes"
            except (UnicodeError, ValueError):
                self.send_error(400, "Invalid investigation form")
                return
            with lock:
                if any(item["status"] == "running" for item in jobs.values()):
                    self.send_error(409, "Another investigation is running")
                    return
                job_id = secrets.token_hex(8)
                jobs[job_id] = {"status": "running"}
            threading.Thread(target=scan, args=(job_id, targets, name, limits, wide)).start()
            self.send_response(303)
            self.send_header("Location", f"/jobs/{job_id}")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
