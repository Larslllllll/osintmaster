"""Generate a fully offline example investigation with controlled profiles."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx

from osintmaster.config import Config
from osintmaster.investigation.engine import HuntEngine, HuntLimits
from osintmaster.investigation.store import InvestigationStore
from osintmaster.providers.username import Site
from osintmaster.reports.html_report import save_html
from osintmaster.reports.json_report import save_graph, save_json, save_jsonl

SITES = [
    Site(
        "Forge",
        "https://forge.example.test/{username}",
        "development",
        (200,),
        (404,),
        ("profile-card",),
    ),
    Site(
        "Studio",
        "https://studio.example.test/{username}",
        "creative",
        (200,),
        (404,),
        ("profile-card",),
    ),
    Site(
        "Community",
        "https://community.example.test/{username}",
        "social",
        (200,),
        (404,),
        ("profile-card",),
    ),
]


def profile(site: str, handle: str, links: list[str]) -> httpx.Response:
    anchors = "".join(f'<a rel="me" href="{link}">published link</a>' for link in links)
    return httpx.Response(
        200,
        text=(
            f'<link rel="canonical" href="https://{site}.example.test/{handle}">'
            '<meta property="og:title" content="Sample Researcher">'
            '<meta property="og:description" content="Public research notes. Contact demo@example.test">'
            f'<div class="profile-card">{anchors}</div>'
        ),
        headers={"content-type": "text/html"},
    )


def respond(request: httpx.Request) -> httpx.Response:
    host, handle = request.url.host, request.url.path.lstrip("/")
    if host == "forge.example.test" and handle == "sample_user":
        return profile(
            "forge",
            handle,
            [
                "https://portfolio.example.test/about",
                "https://community.example.test/alias_user",
            ],
        )
    if host == "studio.example.test" and handle == "sample_user":
        return profile("studio", handle, ["https://portfolio.example.test/about"])
    if host == "community.example.test" and handle == "alias_user":
        return profile("community", handle, ["https://forge.example.test/sample_user"])
    return httpx.Response(404)


async def main() -> None:
    root = Path(__file__).parent / "demo-output"
    config = Config(reports_dir=root, host_interval=0)
    report = await HuntEngine(config, sites=SITES, transport=httpx.MockTransport(respond)).hunt(
        "sample_user", limits=HuntLimits(depth=2)
    )
    save_json(report, root)
    save_graph(report, root)
    save_jsonl(report, root)
    InvestigationStore(root).save(report)
    path = save_html(report, root)
    print(f"Offline demo: {path}")


if __name__ == "__main__":
    asyncio.run(main())
