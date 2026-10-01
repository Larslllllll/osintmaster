"""Opt-in live canary checks for the built-in public profile providers."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

import httpx

from osintmaster import __version__
from osintmaster.config import Config
from osintmaster.core.engine import ScanEngine
from osintmaster.core.models import FindingStatus
from osintmaster.core.normalization import validated_username
from osintmaster.providers.username import Site, load_sites

EXPECTED = {FindingStatus.CONFIRMED, FindingStatus.PROBABLE, FindingStatus.NOT_FOUND}
UNRESOLVED = {
    FindingStatus.ERROR,
    FindingStatus.BLOCKED,
    FindingStatus.AUTH_REQUIRED,
    FindingStatus.RATE_LIMITED,
    FindingStatus.UNKNOWN,
    FindingStatus.POSSIBLE,
}


@dataclass(frozen=True)
class Canary:
    site: Site
    username: str
    expected: FindingStatus


def load_canaries(path: Path, sites: list[Site] | None = None) -> list[Canary]:
    """Read a small, explicit set of live test cases; never infer expected status."""
    if path.stat().st_size > 64_000:
        raise ValueError("Canary fixture must be at most 64 KB")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Canary fixture must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {"cases"}:
        raise ValueError("Canary fixture must contain only a cases list")
    raw = payload["cases"]
    if not isinstance(raw, list) or not 1 <= len(raw) <= 50:
        raise ValueError("Canary fixture must contain 1 to 50 cases")
    catalog = {site.name: site for site in (load_sites() if sites is None else sites)}
    cases: list[Canary] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(raw, 1):
        if not isinstance(item, dict) or set(item) != {"site", "username", "expected"}:
            raise ValueError(f"Canary case {index} requires site, username and expected")
        name, username, expected = item["site"], item["username"], item["expected"]
        if not isinstance(name, str) or name not in catalog:
            raise ValueError(f"Canary case {index} names an unknown built-in site")
        if not isinstance(username, str):
            raise ValueError(f"Canary case {index} has an invalid username")
        username = validated_username(username)
        if not isinstance(expected, str) or expected not in {status.value for status in EXPECTED}:
            raise ValueError(f"Canary case {index} must expect CONFIRMED, PROBABLE or NOT_FOUND")
        key = (name, username if catalog[name].api_kind == "hackernews" else username.casefold())
        if key in seen:
            raise ValueError(f"Canary case {index} duplicates a site and username")
        seen.add(key)
        cases.append(Canary(catalog[name], username, FindingStatus(expected)))
    return cases


async def run_canaries(
    cases: list[Canary],
    config: Config,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Run cases serially so the ordinary scanner's host spacing remains effective."""
    config.validate()
    engines: dict[str, ScanEngine] = {}
    results: list[dict[str, Any]] = []
    for case in cases:
        if case.site.name not in engines:
            engines[case.site.name] = ScanEngine(config, [case.site], transport=transport)
        engine = engines[case.site.name]
        started = perf_counter()
        finding = (await engine.scan(case.username)).findings[0]
        if finding.status == case.expected:
            outcome = "PASS"
        elif finding.status in UNRESOLVED:
            outcome = "INCONCLUSIVE"
        else:
            outcome = "FAIL"
        results.append(
            {
                "site": case.site.name,
                "username": case.username,
                "expected": case.expected.value,
                "actual": finding.status.value,
                "outcome": outcome,
                "http_status": finding.http_status,
                "error": finding.error,
                "evidence_types": [item.type for item in finding.evidence],
                "duration_ms": round((perf_counter() - started) * 1000),
            }
        )
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": __version__,
        "summary": {
            state.lower(): sum(item["outcome"] == state for item in results)
            for state in ("PASS", "FAIL", "INCONCLUSIVE")
        },
        "cases": results,
    }


def catalog_canaries(*, start: int = 0, limit: int = 20) -> list[Canary]:
    """Create fresh positive and absent-handle controls for selected catalogue sites."""
    catalog = [site for site in load_sites(wide=True) if site.page_kind == "catalog"]
    if start < 0 or limit < 1 or start + limit > len(catalog):
        raise ValueError(f"Catalogue range must fit within {len(catalog)} sites")
    cases = []
    for site in catalog[start : start + limit]:
        if not site.known_positive:
            raise ValueError(f"Catalogue site {site.name} lacks a positive control")
        cases.append(
            Canary(site, validated_username(site.known_positive[0]), FindingStatus.PROBABLE)
        )
        cases.append(Canary(site, "osintmaster" + secrets.token_hex(8), FindingStatus.NOT_FOUND))
    return cases


def summarize_catalog_health(result: dict[str, Any]) -> list[dict[str, str]]:
    """Status is a dated probe outcome, not a standing guarantee."""
    checks: dict[str, list[dict[str, Any]]] = {}
    for item in result["cases"]:
        checks.setdefault(str(item["site"]), []).append(item)
    summary = []
    for site, items in checks.items():
        if all(item["outcome"] == "PASS" for item in items):
            health = "HEALTHY"
        elif any(item["actual"] in {"BLOCKED", "AUTH_REQUIRED", "RATE_LIMITED"} for item in items):
            health = "BLOCKED"
        elif any(item["outcome"] == "FAIL" for item in items):
            health = "BROKEN"
        elif any(item["outcome"] == "INCONCLUSIVE" for item in items):
            health = "DEGRADED"
        else:
            health = "UNKNOWN"
        summary.append({"site": site, "health": health, "last_tested": str(result["timestamp"])})
    return summary
