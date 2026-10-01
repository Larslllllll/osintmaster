"""Run dated positive and negative controls against the built-in providers.

This is deliberately an opt-in live check. It never runs in the normal test suite.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from osintmaster.config import Config
from osintmaster.core.models import FindingStatus
from osintmaster.providers.health import Canary
from osintmaster.providers.health import run_canaries as run_fixture_canaries
from osintmaster.providers.username import load_sites

POSITIVE_CONTROLS = {
    "GitHub": "octocat",
    "GitLab": "gitlab",
    "Codeberg": "forgejo",
    "DEV Community": "ben",
    "Hacker News": "pg",
    "Bluesky": "octocat",
    "Telegram": "telegram",
}


async def run_canaries(rounds: int, timeout: float, host_interval: float) -> dict[str, Any]:
    sites = load_sites()
    names = {site.name for site in sites}
    if names != set(POSITIVE_CONTROLS):
        raise ValueError(
            f"Provider controls need updating: {sorted(names ^ set(POSITIVE_CONTROLS))}"
        )
    config = Config(
        timeout=timeout,
        max_concurrency=1,
        per_host_concurrency=1,
        host_interval=host_interval,
    )
    config.validate()
    cases: list[Canary] = []
    probes: list[tuple[int, str]] = []
    for number in range(1, rounds + 1):
        for site in sites:
            negative = "osintmaster" + secrets.token_hex(8)
            for probe, username, expected in (
                ("positive", POSITIVE_CONTROLS[site.name], FindingStatus.CONFIRMED),
                ("random_negative", negative, FindingStatus.NOT_FOUND),
            ):
                cases.append(Canary(site, username, expected))
                probes.append((number, probe))
    checked = await run_fixture_canaries(cases, config)
    records: list[dict[str, Any]] = []
    for (number, probe), item in zip(probes, checked["cases"], strict=True):
        records.append(
            {
                "round": number,
                "provider": item["site"],
                "probe": probe,
                "username": item["username"],
                "expected": item["expected"],
                "observed": item["actual"],
                "verdict": {
                    "PASS": "PASS",
                    "INCONCLUSIVE": "UNVERIFIED",
                    "FAIL": "MISMATCH",
                }[item["outcome"]],
                "http_status": item["http_status"],
                "error": item["error"],
                "evidence_types": item["evidence_types"],
                "elapsed_ms": item["duration_ms"],
            }
        )
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": "Public positive control plus fresh random negative control per provider and round",
        "caveat": "A passing control is a point-in-time check, not proof of future provider reliability.",
        "rounds": rounds,
        "host_interval_seconds": host_interval,
        "timeout_seconds": timeout,
        "summary": {
            verdict: sum(item["verdict"] == verdict for item in records)
            for verdict in ("PASS", "UNVERIFIED", "MISMATCH")
        },
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=1, help="Runs per provider (1-3)")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    parser.add_argument(
        "--host-interval",
        type=float,
        default=1.0,
        help="Minimum seconds between same-host requests",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON evidence file")
    args = parser.parse_args()
    if not 1 <= args.rounds <= 3:
        parser.error("--rounds must be between 1 and 3")
    if not 0.5 <= args.timeout <= 120:
        parser.error("--timeout must be between 0.5 and 120 seconds")
    if not 0.5 <= args.host_interval <= 60:
        parser.error("--host-interval must be between 0.5 and 60 seconds")
    result = asyncio.run(run_canaries(args.rounds, args.timeout, args.host_interval))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"output": str(args.output), "summary": result["summary"]}))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["summary"]["MISMATCH"]:
        return 1
    return 2 if result["summary"]["UNVERIFIED"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
