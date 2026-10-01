"""Command-line interface."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import unicodedata
import webbrowser
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from osintmaster import __version__
from osintmaster.config import Config, load_config
from osintmaster.constants import EXIT_ERROR, EXIT_INVALID, EXIT_PARTIAL
from osintmaster.core.engine import ScanEngine
from osintmaster.core.models import FindingStatus, Report
from osintmaster.doctor import doctor_checks
from osintmaster.investigation.engine import HuntEngine, HuntLimits
from osintmaster.investigation.models import EventType
from osintmaster.investigation.store import InvestigationStore, compare_investigations
from osintmaster.metadata.exif import analyze_metadata
from osintmaster.metadata.image import analyze_image, compare_images
from osintmaster.plugins.manager import (
    external_providers,
    load_event_plugins,
    load_plugins,
    plugin_status,
)
from osintmaster.providers.brave import BraveSearchProvider
from osintmaster.providers.health import (
    catalog_canaries,
    load_canaries,
    run_canaries,
    summarize_catalog_health,
)
from osintmaster.providers.search import generate_dorks
from osintmaster.providers.username import load_sites
from osintmaster.reports.dashboard import make_dashboard_server
from osintmaster.reports.html_report import render_html, save_html
from osintmaster.reports.json_report import (
    load_report,
    render_json,
    report_directory,
    save_graph,
    save_json,
    save_jsonl,
)
from osintmaster.reports.workspace import make_workspace_server

app = typer.Typer(help="Public-profile OSINT with explainable evidence.", no_args_is_help=True)


@dataclass
class Options:
    verbose: bool = False
    quiet: bool = False
    json_output: bool = False
    no_color: bool = False
    timeout: float | None = None
    output: Path | None = None


@app.callback()
def main(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", help="Show extra status."),
    quiet: bool = typer.Option(False, "--quiet", help="Only show essential output."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output."),
    timeout: float | None = typer.Option(None, "--timeout", help="Request timeout in seconds."),
    output: Path | None = typer.Option(None, "--output", help="Report root directory."),
) -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    ctx.obj = Options(verbose, quiet, json_output, no_color, timeout, output)


def _options(ctx: typer.Context) -> Options:
    return ctx.obj if isinstance(ctx.obj, Options) else Options()


def _console(ctx: typer.Context, *, stderr: bool = False) -> Console:
    return Console(stderr=stderr, no_color=_options(ctx).no_color)


def _terminal_text(value: Any) -> str:
    """Keep untrusted source text from controlling terminal display."""
    return "".join(
        " " if unicodedata.category(char) == "Cc" else char
        for char in str(value)
        if unicodedata.category(char) != "Cf"
    )


def _fail(ctx: typer.Context, message: str, code: int = EXIT_ERROR) -> None:
    _console(ctx, stderr=True).print(Text("Error: " + _terminal_text(message)))
    raise typer.Exit(code)


def _config(ctx: typer.Context) -> Config:
    try:
        config = load_config()
        options = _options(ctx)
        if options.timeout is not None:
            config.timeout = options.timeout
        if options.output is not None:
            config.reports_dir = options.output
        config.validate()
        return config
    except (ValueError, OSError) as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    raise AssertionError("unreachable")


def _print_json(data: Any) -> None:
    typer.echo(json.dumps(data, ensure_ascii=True, indent=2))


@app.command()
def username(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Public username to check."),
    json_output: bool = typer.Option(False, "--json", help="Print report as JSON."),
    html: bool = typer.Option(False, "--html", help="Print the HTML report path."),
    output: Path | None = typer.Option(None, "--output", help="Report root directory."),
    timeout: float | None = typer.Option(None, "--timeout", help="Request timeout in seconds."),
    max_concurrency: int | None = typer.Option(
        None, "--max-concurrency", help="Maximum simultaneous requests (1-20)."
    ),
    no_external: bool = typer.Option(
        False, "--no-external", help="Disable optional external tools."
    ),
    variants: bool = typer.Option(
        False, "--variants", help="Also check generated username candidates."
    ),
    wide: bool = typer.Option(
        False, "--wide", help="Check the dated, canary-tested extended catalogue."
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Show extra status."),
    quiet: bool = typer.Option(False, "--quiet", help="Only show essential output."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colors."),
) -> None:
    options = _options(ctx)
    options.no_color |= no_color
    config = _config(ctx)
    if output is not None:
        config.reports_dir = output
    if timeout is not None:
        config.timeout = timeout
    if max_concurrency is not None:
        config.max_concurrency = max_concurrency
    try:
        config.validate()
        providers = [] if no_external else external_providers(config)
        plugins, _searches, plugin_errors = ([], [], []) if no_external else load_plugins(config)
        report = asyncio.run(
            ScanEngine(
                config, sites=load_sites(wide=wide), external=providers, plugins=plugins
            ).scan(target, variants=variants)
        )
        report.errors.extend(plugin_errors)
        json_path = save_json(report, config.reports_dir)
        html_path = save_html(report, config.reports_dir)
    except ValueError as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    except OSError:
        _fail(ctx, "Could not read or write a report", EXIT_ERROR)
    if json_output or options.json_output:
        typer.echo(render_json(report, ascii_only=True), nl=False)
    elif not (quiet or options.quiet):
        _show_report(ctx, report, verbose=verbose or options.verbose)
        _console(ctx).print(Text(_terminal_text(f"Reports: {json_path} · {html_path}")))
    elif html:
        _console(ctx).print(Text(_terminal_text(html_path)))
    if report.errors or report.rate_limits:
        raise typer.Exit(EXIT_PARTIAL)


@app.command()
def hunt(
    ctx: typer.Context,
    target: str = typer.Argument(
        ..., help="Username, email, domain, IP, URL, E.164 phone, or local image."
    ),
    target_type: str | None = typer.Option(None, "--type", help="Override auto detection."),
    depth: int = typer.Option(1, "--depth", help="Pivot depth (0-3)."),
    max_events: int = typer.Option(300, "--max-events"),
    max_requests: int = typer.Option(50, "--max-requests"),
    max_runtime: float = typer.Option(90.0, "--max-runtime"),
    max_per_provider: int = typer.Option(10, "--max-per-provider"),
    max_provider_runs: int = typer.Option(300, "--max-provider-runs"),
    wide: bool = typer.Option(
        False, "--wide", help="Use the extended catalogue for username pivots."
    ),
    output: Path | None = typer.Option(None, "--output", help="Report root directory."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    open_browser: bool = typer.Option(False, "--open", help="Open the offline HTML dashboard."),
    quiet: bool = typer.Option(False, "--quiet"),
    verbose: bool = typer.Option(False, "--verbose"),
    no_color: bool = typer.Option(False, "--no-color"),
) -> None:
    """Investigate one target and build a bounded, explainable entity graph."""
    options = _options(ctx)
    options.no_color |= no_color
    config = _config(ctx)
    if output is not None:
        config.reports_dir = output
    aliases = {"ip": "IP_ADDRESS"}
    try:
        kind = (
            EventType[aliases.get(target_type.lower(), target_type.upper())]
            if target_type
            else None
        )
        if kind not in {
            None,
            EventType.USERNAME,
            EventType.EMAIL,
            EventType.DOMAIN,
            EventType.IP_ADDRESS,
            EventType.URL,
            EventType.IMAGE,
            EventType.PHONE,
        }:
            raise ValueError("Unsupported target type")
        limits = HuntLimits(
            depth, max_events, max_requests, max_runtime, max_per_provider, max_provider_runs
        )
        event_plugins, plugin_errors = load_event_plugins(config)
        report = asyncio.run(
            HuntEngine(
                config,
                sites=load_sites(wide=wide),
                event_providers=event_plugins,
                plugin_errors=plugin_errors,
            ).hunt(target, target_type=kind, limits=limits)
        )
        json_path = save_json(report, config.reports_dir)
        html_path = save_html(report, config.reports_dir)
        graph_path = save_graph(report, config.reports_dir)
        jsonl_path = save_jsonl(report, config.reports_dir)
        InvestigationStore(config.reports_dir).save(report)
    except KeyError:
        _fail(ctx, "Unknown target type", EXIT_INVALID)
    except ValueError as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    except (OSError, sqlite3.Error):
        _fail(ctx, "Could not read or write investigation", EXIT_ERROR)
    if json_output or options.json_output:
        typer.echo(render_json(report, ascii_only=True), nl=False)
    elif not (quiet or options.quiet):
        _show_report(ctx, report, verbose=verbose or options.verbose)
        _console(ctx).print(f"Investigation: {report.investigation_id[:12]}")
        _console(ctx).print(
            Text(
                _terminal_text(f"Reports: {json_path} · {html_path} · {graph_path} · {jsonl_path}")
            )
        )
        _console(ctx).print(
            Text(_terminal_text(f"Open locally: osintmaster dashboard {report.target}"))
        )
    if open_browser:
        webbrowser.open(html_path.resolve().as_uri())
    if report.errors or report.rate_limits:
        raise typer.Exit(EXIT_PARTIAL)


@app.command()
def case(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Short local case name."),
    targets: list[str] = typer.Argument(..., help="Two or more seed targets."),
    depth: int = typer.Option(1, "--depth"),
    max_events: int = typer.Option(300, "--max-events"),
    max_requests: int = typer.Option(50, "--max-requests"),
    max_runtime: float = typer.Option(90.0, "--max-runtime"),
    max_per_provider: int = typer.Option(10, "--max-per-provider"),
    max_provider_runs: int = typer.Option(300, "--max-provider-runs"),
    wide: bool = typer.Option(False, "--wide"),
    output: Path | None = typer.Option(None, "--output"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Investigate 2–20 seeds together with one graph and request budget."""
    config = _config(ctx)
    if output is not None:
        config.reports_dir = output
    try:
        limits = HuntLimits(
            depth=depth,
            max_events=max_events,
            max_requests=max_requests,
            max_runtime=max_runtime,
            max_per_provider=max_per_provider,
            max_provider_runs=max_provider_runs,
        )
        event_plugins, plugin_errors = load_event_plugins(config)
        report = asyncio.run(
            HuntEngine(
                config,
                sites=load_sites(wide=wide),
                event_providers=event_plugins,
                plugin_errors=plugin_errors,
            ).hunt_many(name, targets, limits=limits)
        )
        json_path = save_json(report, config.reports_dir)
        html_path = save_html(report, config.reports_dir)
        save_graph(report, config.reports_dir)
        save_jsonl(report, config.reports_dir)
        InvestigationStore(config.reports_dir).save(report)
    except ValueError as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    except (OSError, sqlite3.Error):
        _fail(ctx, "Could not read or write case", EXIT_ERROR)
    if json_output or _options(ctx).json_output:
        typer.echo(render_json(report, ascii_only=True), nl=False)
    elif not _options(ctx).quiet:
        _show_report(ctx, report)
        _console(ctx).print(f"Case: {report.investigation_id[:12]}")
        _console(ctx).print(Text(_terminal_text(f"Reports: {json_path} · {html_path}")))
    if report.errors or report.rate_limits:
        raise typer.Exit(EXIT_PARTIAL)


def _show_report(ctx: typer.Context, report: Report, *, verbose: bool = False) -> None:
    console = _console(ctx)
    counts = {
        status: sum(item.status == status for item in report.findings) for status in FindingStatus
    }
    header = Text.assemble(
        ("OSINT", "bold cyan"),
        ("MASTER", "bold white"),
        (f"  v{report.version}\n", "dim"),
        (
            f"{report.target_type} INVESTIGATION"
            if report.target_type
            else "PUBLIC PROFILE INVESTIGATION",
            "bold white",
        ),
        (f"  /  {_terminal_text(report.target)}", "cyan"),
    )
    console.print(Panel(header, border_style="cyan", expand=True))
    summary = Table.grid(expand=True, padding=(0, 2))
    summary.add_column(justify="center", ratio=1)
    summary.add_column(justify="center", ratio=1)
    summary.add_column(justify="center", ratio=1)
    summary.add_column(justify="center", ratio=1)
    summary.add_row(
        f"[bold green]{counts[FindingStatus.CONFIRMED]}[/] confirmed",
        f"[bold yellow]{counts[FindingStatus.POSSIBLE] + counts[FindingStatus.PROBABLE]}[/] leads",
        f"[bold dim]{counts[FindingStatus.NOT_FOUND]}[/] absent",
        f"[bold red]{counts[FindingStatus.ERROR] + counts[FindingStatus.BLOCKED] + counts[FindingStatus.AUTH_REQUIRED] + counts[FindingStatus.UNKNOWN] + counts[FindingStatus.RATE_LIMITED]}[/] unresolved",
    )
    console.print(
        Panel(summary, title=f"Coverage · {len(report.findings)} checks", border_style="blue")
    )

    status_style = {
        FindingStatus.CONFIRMED: "green",
        FindingStatus.PROBABLE: "yellow",
        FindingStatus.POSSIBLE: "yellow",
        FindingStatus.NOT_FOUND: "dim",
        FindingStatus.ERROR: "red",
        FindingStatus.BLOCKED: "red",
        FindingStatus.AUTH_REQUIRED: "red",
        FindingStatus.RATE_LIMITED: "red",
        FindingStatus.UNKNOWN: "magenta",
    }
    visible = [
        item for item in report.findings if verbose or item.status != FindingStatus.NOT_FOUND
    ]
    table = Table(title="PROFILE MAP", header_style="bold cyan", expand=True, show_lines=False)
    table.add_column("Source", style="bold", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Public profile", overflow="fold")
    for finding in visible:
        table.add_row(
            Text(_terminal_text(finding.provider)),
            Text(finding.status.value, style=status_style[finding.status]),
            Text(_terminal_text(finding.url or "—")),
        )
    if visible:
        console.print(table)
    else:
        console.print(
            "[dim]This target produced no public profile leads. Review its graph entities below.[/]"
            if report.graph
            else "[dim]No public profiles or leads were returned. Use --verbose for all checks.[/]"
        )

    if report.graph:
        nodes = report.graph.get("nodes", [])
        edges = report.graph.get("edges", [])
        console.print(
            Panel(
                f"[bold cyan]{len(nodes)}[/] entities   [bold cyan]{len(edges)}[/] links   "
                f"[bold cyan]{report.limits.get('requests_used', 0)}[/] requests",
                title="INVESTIGATION GRAPH",
                border_style="cyan",
            )
        )

    enriched = [
        item
        for item in report.findings
        if item.status in {FindingStatus.CONFIRMED, FindingStatus.PROBABLE, FindingStatus.POSSIBLE}
        and any(
            (item.profile.display_name, item.profile.bio, item.profile.location, item.profile.links)
        )
    ]
    if enriched:
        details = Table(title="PUBLIC PROFILE CLUES", header_style="bold cyan", expand=True)
        details.add_column("Source", no_wrap=True)
        details.add_column("Public details", overflow="fold")
        for item in enriched[:10]:
            parts = [
                _terminal_text(value)
                for value in (
                    item.profile.account_type,
                    item.profile.display_name,
                    item.profile.location,
                    (item.profile.bio or "")[:180],
                )
                if value
            ]
            parts.extend(_terminal_text(link) for link in item.profile.links[:3])
            details.add_row(Text(_terminal_text(item.provider)), Text("\n".join(parts)))
        console.print(details)

    supported = sorted(
        (item for item in report.correlations if item.score >= 30),
        key=lambda item: item.score,
        reverse=True,
    )
    if supported:
        correlations = Table(title="CROSS-PROFILE LINKS · review manually", expand=True)
        correlations.add_column("Score", no_wrap=True)
        correlations.add_column("Profiles and evidence", overflow="fold")
        for relation in supported[:10]:
            reasons = ", ".join(evidence.type.replace("_", " ") for evidence in relation.evidence)
            correlations.add_row(
                Text(f"{relation.score}/100", style="bold yellow"),
                Text(_terminal_text(f"{relation.left_url} ↔ {relation.right_url}\n{reasons}")),
            )
        console.print(correlations)
    else:
        console.print(
            "[dim]No strong cross-profile link found. Matching handles alone are weak evidence.[/]"
        )
    if report.errors or report.rate_limits:
        console.print(
            f"[yellow]Unresolved: {len(report.errors)} errors/blocked/unknown, "
            f"{len(report.rate_limits)} rate limits. Details are in the saved report.[/]"
        )
    console.print("[dim]A confirmed profile page does not confirm who owns the account.[/]")


@app.command()
def sites(ctx: typer.Context, wide: bool = typer.Option(False, "--wide")) -> None:
    """List the built-in public profile sources and verification method."""
    catalog = load_sites(wide=wide)
    table = Table(title=f"BUILT-IN SOURCES · {len(catalog)}", header_style="bold cyan")
    table.add_column("Source")
    table.add_column("Category")
    table.add_column("Verification")
    table.add_column("Health")
    for site in catalog:
        verification = (
            "Public API"
            if site.api_kind
            else "Dated marker canary"
            if site.page_kind == "catalog"
            else "Exact public preview"
            if site.page_kind == "telegram"
            else "Profile page"
        )
        table.add_row(
            site.name,
            site.category,
            verification,
            f"{site.health} · {site.last_tested[:10]}"
            if site.health and site.last_tested
            else "Unverified",
        )
    _console(ctx).print(table)


@app.command()
def health(
    ctx: typer.Context,
    fixture: Path = typer.Argument(..., help="JSON file with controlled provider canaries."),
    json_output: bool = typer.Option(False, "--json"),
    save: Path | None = typer.Option(None, "--save", help="Save the dated result as JSON."),
    wide: bool = typer.Option(False, "--wide", help="Include extended catalogue rules."),
) -> None:
    """Check built-in providers against known present and absent handles."""
    try:
        cases = load_canaries(fixture, load_sites(wide=wide))
        result = asyncio.run(run_canaries(cases, _config(ctx)))
        if save is not None:
            save.parent.mkdir(parents=True, exist_ok=True)
            save.write_text(
                json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
            )
    except (ValueError, OSError) as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    if json_output or _options(ctx).json_output:
        _print_json(result)
    else:
        table = Table(title="PROVIDER HEALTH", header_style="bold cyan")
        for column in ("Source", "Handle", "Expected", "Actual", "HTTP", "Result"):
            table.add_column(column)
        for item in result["cases"]:
            table.add_row(
                Text(_terminal_text(item["site"])),
                Text(_terminal_text(item["username"])),
                item["expected"],
                item["actual"],
                str(item["http_status"] or "—"),
                item["outcome"],
            )
        console = _console(ctx)
        console.print(table)
        summary = result["summary"]
        console.print(
            f"{summary['pass']} passed · {summary['fail']} failed · "
            f"{summary['inconclusive']} inconclusive"
        )
        if save is not None:
            console.print(Text(f"Saved: {save}"))
    if result["summary"]["fail"] or result["summary"]["inconclusive"]:
        raise typer.Exit(EXIT_PARTIAL)


@app.command("health-catalog")
def health_catalog(
    ctx: typer.Context,
    start: int = typer.Option(0, "--start", help="First extended source, zero based."),
    limit: int = typer.Option(20, "--limit", help="Number of sources to recheck."),
    save: Path | None = typer.Option(None, "--save", help="Save dated canary results."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Recheck extended sources with fresh positive and negative controls."""
    try:
        cases = catalog_canaries(start=start, limit=limit)
        result = asyncio.run(run_canaries(cases, _config(ctx)))
        result["site_health"] = summarize_catalog_health(result)
        if save is not None:
            save.parent.mkdir(parents=True, exist_ok=True)
            save.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
    except (ValueError, OSError) as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    if json_output or _options(ctx).json_output:
        _print_json(result)
    else:
        table = Table(title="EXTENDED CATALOGUE HEALTH", header_style="bold cyan")
        table.add_column("Source")
        table.add_column("Health")
        for item in result["site_health"]:
            table.add_row(Text(_terminal_text(item["site"])), item["health"])
        _console(ctx).print(table)
    if any(item["health"] != "HEALTHY" for item in result["site_health"]):
        raise typer.Exit(EXIT_PARTIAL)


@app.command()
def investigations(
    ctx: typer.Context,
    target: str | None = typer.Option(None, "--target", help="Filter by exact target."),
    limit: int = typer.Option(20, "--limit", help="Maximum rows (1-1000)."),
    output: Path | None = typer.Option(None, "--output", help="Report root directory."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """List locally saved investigation runs."""
    config = _config(ctx)
    if output is not None:
        config.reports_dir = output
    try:
        rows = InvestigationStore(config.reports_dir).list(target=target, limit=limit)
    except (ValueError, OSError, sqlite3.Error) as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    if json_output or _options(ctx).json_output:
        _print_json(rows)
        return
    table = Table(title=f"INVESTIGATION HISTORY · {len(rows)} runs", header_style="bold cyan")
    for heading in ("ID", "Target", "Type", "Time (UTC)", "Nodes", "Edges", "Requests"):
        table.add_column(heading)
    for row in rows:
        table.add_row(
            row["id"][:12],
            Text(_terminal_text(row["target"])),
            row["target_type"],
            row["created_at"][:19],
            str(row["entity_count"]),
            str(row["edge_count"]),
            str(row["requests_used"]),
        )
    _console(ctx).print(table)


@app.command()
def show(
    ctx: typer.Context,
    investigation_id: str = typer.Argument(..., help="Investigation ID or unique prefix."),
    output: Path | None = typer.Option(None, "--output", help="Report root directory."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Show a saved run by ID, even when a newer run has replaced its report files."""
    config = _config(ctx)
    if output is not None:
        config.reports_dir = output
    try:
        data = InvestigationStore(config.reports_dir).load(investigation_id)
    except (ValueError, FileNotFoundError, OSError, sqlite3.Error) as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    if json_output or _options(ctx).json_output:
        typer.echo(render_json(data, ascii_only=True), nl=False)
        return
    graph = data.get("graph") or {}
    _console(ctx).print(
        Panel(
            Text.assemble(
                _terminal_text(f"{data['target']} · {data.get('target_type', 'UNKNOWN')}"),
                "\n",
                _terminal_text(f"ID: {data['investigation_id']}"),
                "\n",
                _terminal_text(
                    f"{len(graph.get('nodes', []))} entities · {len(graph.get('edges', []))} links · "
                    f"{data.get('limits', {}).get('requests_used', 0)} requests"
                ),
            ),
            title="SAVED INVESTIGATION",
            border_style="cyan",
        )
    )
    table = Table("Source", "State", "Public URL", title="PROFILE MAP")
    for finding in data.get("findings", []):
        table.add_row(
            Text(_terminal_text(finding["provider"])),
            Text(_terminal_text(finding["status"])),
            Text(_terminal_text(finding["url"])),
        )
    if data.get("findings"):
        _console(ctx).print(table)


@app.command()
def diff(
    ctx: typer.Context,
    old_id: str = typer.Argument(..., help="Earlier investigation ID."),
    new_id: str = typer.Argument(..., help="Later investigation ID."),
    output: Path | None = typer.Option(None, "--output", help="Report root directory."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Compare two runs without treating missed checks as vanished accounts."""
    config = _config(ctx)
    if output is not None:
        config.reports_dir = output
    try:
        store = InvestigationStore(config.reports_dir)
        result = compare_investigations(store.load(old_id), store.load(new_id))
    except (ValueError, FileNotFoundError, OSError, sqlite3.Error) as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    if json_output or _options(ctx).json_output:
        _print_json(result)
        return
    console = _console(ctx)
    console.print(
        Panel(
            Text.assemble(
                _terminal_text(result["target"]),
                "\n",
                _terminal_text(
                    f"+ {len(result['added_entities'])} newly observed entities · "
                    f"+ {len(result['added_observations'])} new observations · "
                    f"{len(result['status_changes'])} status changes · "
                    f"{len(result['not_observed_entities'])} entities and "
                    f"{len(result['not_observed_observations'])} observations not seen this run"
                ),
            ),
            title="INVESTIGATION DIFF",
            border_style="cyan",
        )
    )
    changes = Table("Source", "Handle", "Before", "After", title="STATUS CHANGES")
    for item in result["status_changes"]:
        changes.add_row(
            *(
                Text(_terminal_text(item[key]))
                for key in ("provider", "username", "before", "after")
            )
        )
    if result["status_changes"]:
        console.print(changes)
    console.print(
        "[dim]Not observed means this run did not record it; it does not prove removal.[/]"
    )
    if result["partial"]:
        console.print("[yellow]One or both runs were partial; compare their errors and limits.[/]")


@app.command()
def dashboard(
    ctx: typer.Context,
    target: str | None = typer.Argument(None, help="Saved report target to open."),
    output: Path | None = typer.Option(None, "--output", help="Report root directory."),
    run: str | None = typer.Option(None, "--run", help="Open a saved investigation ID."),
    port: int = typer.Option(0, "--port", help="Local port (0 chooses a free port)."),
    no_open: bool = typer.Option(False, "--no-open", help="Do not open a browser automatically."),
) -> None:
    """Open a saved investigation and local analyst review dashboard."""
    config = _config(ctx)
    if output is not None:
        config.reports_dir = output
    if (target is None) == (run is None):
        _fail(ctx, "Provide a target or --run ID", EXIT_INVALID)
    try:
        store = InvestigationStore(config.reports_dir)
        if run is not None:
            data = store.load(run)
        else:
            assert target is not None
            data = load_report(config.reports_dir, target)
        server = make_dashboard_server(data, port, store=store if store.path.is_file() else None)
    except (ValueError, FileNotFoundError) as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    except (OSError, sqlite3.Error) as exc:
        _fail(ctx, f"Could not start dashboard: {exc}")
    url = f"http://127.0.0.1:{server.server_port}/"
    _console(ctx).print(f"Dashboard: {url} · Press Ctrl+C to stop")
    if not no_open:
        webbrowser.open(url)
    try:
        with server:
            server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        _console(ctx).print("Dashboard stopped.")


@app.command()
def web(
    ctx: typer.Context,
    output: Path | None = typer.Option(None, "--output", help="Report root directory."),
    port: int = typer.Option(0, "--port", help="Local port (0 chooses a free port)."),
    no_open: bool = typer.Option(False, "--no-open", help="Do not open a browser automatically."),
) -> None:
    """Start a local workspace to launch and browse investigations in a browser."""
    config = _config(ctx)
    if output is not None:
        config.reports_dir = output
    try:
        server = make_workspace_server(config, port)
    except ValueError as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    except OSError as exc:
        _fail(ctx, f"Could not start workspace: {exc}")
    url = f"http://127.0.0.1:{server.server_port}/"
    _console(ctx).print(f"Workspace: {url} · Press Ctrl+C to stop")
    if not no_open:
        webbrowser.open(url)
    try:
        with server:
            server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        _console(ctx).print("Workspace stopped.")


@app.command()
def metadata(
    ctx: typer.Context,
    file: Path = typer.Argument(..., help="Local image file."),
    json_output: bool = typer.Option(False, "--json"),
    no_exiftool: bool = typer.Option(False, "--no-exiftool"),
) -> None:
    try:
        result = analyze_metadata(file, use_exiftool=not no_exiftool)
    except ValueError as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    if json_output or _options(ctx).json_output:
        _print_json(result)
    else:
        _console(ctx).print_json(data=result)


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": False})
def image(
    ctx: typer.Context,
    args: list[str] = typer.Argument(..., help="FILE or compare FILE_A FILE_B"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        if len(args) == 3 and args[0] == "compare":
            result = compare_images(Path(args[1]), Path(args[2]))
        elif len(args) == 1:
            result = analyze_image(Path(args[0]))
        else:
            _fail(ctx, "Use 'image FILE' or 'image compare FILE_A FILE_B'", EXIT_INVALID)
    except ValueError as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    if json_output or _options(ctx).json_output:
        _print_json(result)
    else:
        _console(ctx).print_json(data=result)


@app.command()
def dorks(
    ctx: typer.Context,
    query: str = typer.Argument(...),
    json_output: bool = typer.Option(False, "--json"),
    search: bool = typer.Option(False, "--search", help="Query configured search plugins once."),
) -> None:
    try:
        queries = generate_dorks(query)
    except ValueError as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    if search:
        config = _config(ctx)
        _usernames, providers, errors = load_plugins(config)
        brave_key = os.getenv("OSINTMASTER_BRAVE_API_KEY")
        if brave_key:
            providers.append(BraveSearchProvider(brave_key, timeout=config.timeout))
        if not providers:
            _fail(ctx, "No search provider is configured", EXIT_INVALID)

        async def run_search() -> list[dict[str, Any]]:
            async def one(provider: Any) -> list[dict[str, Any]]:
                try:
                    found = await asyncio.wait_for(provider.search(query), timeout=config.timeout)
                    return [asdict(item) for item in found[:20]]
                except Exception:
                    errors.append(f"Search plugin {provider.name}: request failed")
                    return []

            batches = await asyncio.gather(*(one(provider) for provider in providers))
            return [item for batch in batches for item in batch]

        search_results = asyncio.run(run_search())
        result = {"queries": queries, "results": search_results, "errors": errors}
        if json_output or _options(ctx).json_output:
            _print_json(result)
        else:
            for item in queries:
                typer.echo(_terminal_text(item))
            for search_item in search_results:
                _console(ctx).print(
                    Text(
                        _terminal_text(
                            f"{search_item['provider']}: {search_item['title']} — {search_item['url']}"
                        )
                    )
                )
        if errors:
            raise typer.Exit(EXIT_PARTIAL)
    elif json_output or _options(ctx).json_output:
        _print_json(queries)
    else:
        for item in queries:
            typer.echo(_terminal_text(item))


@app.command()
def report(
    ctx: typer.Context,
    target: str = typer.Argument(...),
    json_output: bool = typer.Option(False, "--json"),
    html: bool = typer.Option(False, "--html"),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    config = _config(ctx)
    if output is not None:
        config.reports_dir = output
    try:
        data = load_report(config.reports_dir, target)
        if html:
            destination = report_directory(config.reports_dir, target) / "report.html"
            destination.write_text(render_html(data), encoding="utf-8")
            if not (json_output or _options(ctx).json_output):
                typer.echo(str(destination))
        if json_output or _options(ctx).json_output:
            typer.echo(render_json(data, ascii_only=True), nl=False)
        elif not html:
            console = _console(ctx)
            console.print(
                Panel(
                    Text.assemble(
                        ("OSINTMASTER", "bold cyan"),
                        (f"  /  {_terminal_text(data.get('target', ''))}", "white"),
                        (
                            f"\nSaved investigation · {_terminal_text(data.get('timestamp', ''))}",
                            "dim",
                        ),
                    ),
                    border_style="cyan",
                )
            )
            table = Table("Source", "Handle", "State", "Public URL", title="PROFILE MAP")
            for finding in data.get("findings", []):
                table.add_row(
                    Text(_terminal_text(finding.get("provider", ""))),
                    Text(_terminal_text(finding.get("username", ""))),
                    Text(_terminal_text(finding.get("status", ""))),
                    Text(_terminal_text(finding.get("url", ""))),
                )
            if data.get("findings"):
                console.print(table)
            graph = data.get("graph")
            if isinstance(graph, dict):
                console.print(
                    f"Graph: {len(graph.get('nodes', []))} entities · "
                    f"{len(graph.get('edges', []))} links"
                )
            console.print(Text(_terminal_text(f"Dashboard: osintmaster dashboard {target}")))
    except (ValueError, FileNotFoundError) as exc:
        _fail(ctx, str(exc), EXIT_INVALID)
    except OSError:
        _fail(ctx, "Could not read or write the report", EXIT_ERROR)


@app.command()
def doctor(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
    checks = doctor_checks(_config(ctx))
    if json_output or _options(ctx).json_output:
        _print_json(
            [{"check": name, "detail": detail, "status": status} for name, detail, status in checks]
        )
    else:
        table = Table("Check", "Detail", "Status", title="OSINTMaster Doctor")
        for row in checks:
            table.add_row(*row)
        _console(ctx).print(table)


@app.command()
def plugins(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
    status = plugin_status(_config(ctx))
    if json_output or _options(ctx).json_output:
        _print_json([{"name": name, "status": state} for name, state in status])
    else:
        table = Table("Plugin", "Status")
        for row in status:
            table.add_row(*row)
        _console(ctx).print(table)


@app.command()
def version() -> None:
    typer.echo(__version__)


if __name__ == "__main__":
    app()
