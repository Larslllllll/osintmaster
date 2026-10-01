import httpx
import pytest

from osintmaster.config import Config
from osintmaster.core.engine import ScanEngine
from osintmaster.core.models import FindingStatus
from osintmaster.investigation.engine import HuntEngine, HuntLimits
from osintmaster.providers.health import (
    Canary,
    catalog_canaries,
    run_canaries,
    summarize_catalog_health,
)
from osintmaster.providers.username import Site, load_sites

CATALOG_SITE = Site.from_dict(
    {
        "name": "Canary example",
        "url": "https://example.org/u/{username}",
        "check_url": "https://example.org/api/{username}",
        "category": "test",
        "page_kind": "catalog",
        "expected_status": [200],
        "not_found_status": [404],
        "positive_code": 200,
        "negative_code": 404,
        "positive_marker": "account-unique-marker",
        "negative_marker": "missing-account-marker",
        "known_positive": ["alice"],
        "health": "HEALTHY",
        "last_tested": "2026-10-01T00:00:00+00:00",
    }
)


@pytest.mark.asyncio
async def test_extended_marker_rule_requires_positive_and_negative_controls(tmp_path):
    def respond(request):
        if request.url.path.endswith("/alice"):
            return httpx.Response(200, text="account-unique-marker")
        if request.url.path.endswith("/missing"):
            return httpx.Response(404, text="missing-account-marker")
        return httpx.Response(200, text="generic page")

    engine = ScanEngine(
        Config(reports_dir=tmp_path, host_interval=0),
        sites=[CATALOG_SITE],
        transport=httpx.MockTransport(respond),
    )
    assert (await engine.scan("alice")).findings[0].status == FindingStatus.PROBABLE
    assert (await engine.scan("missing")).findings[0].status == FindingStatus.NOT_FOUND
    assert (await engine.scan("generic")).findings[0].status == FindingStatus.UNKNOWN


@pytest.mark.asyncio
async def test_wide_hunt_keeps_shared_request_budget(tmp_path):
    sites = load_sites(wide=True)
    assert len(sites) == 146
    assert len({site.name for site in sites}) == len(sites)
    assert all(site.health == "HEALTHY" and site.last_tested for site in sites[7:])
    report = await HuntEngine(
        Config(reports_dir=tmp_path, host_interval=0),
        sites=sites,
        transport=httpx.MockTransport(lambda request: httpx.Response(404)),
    ).hunt("alice", limits=HuntLimits(depth=0, max_requests=5))
    assert report.limits["requests_used"] == 5
    assert len(report.findings) == 5


@pytest.mark.asyncio
async def test_verified_http_404_can_be_negative_without_body_marker(tmp_path):
    site = next(item for item in load_sites(wide=True) if item.name == "Bandlab")
    assert site.negative_marker == ""
    engine = ScanEngine(
        Config(reports_dir=tmp_path, host_interval=0),
        sites=[site],
        transport=httpx.MockTransport(lambda request: httpx.Response(404, text="missing")),
    )
    finding = (await engine.scan("absenthandle")).findings[0]
    assert finding.status == FindingStatus.NOT_FOUND
    assert finding.evidence[0].type == "catalog_http_not_found"


@pytest.mark.asyncio
async def test_negative_catalog_canary_fails_on_false_positive(tmp_path):
    result = await run_canaries(
        [Canary(CATALOG_SITE, "missing", FindingStatus.NOT_FOUND)],
        Config(reports_dir=tmp_path, host_interval=0),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, text="account-unique-marker")
        ),
    )
    assert result["cases"][0]["actual"] == "PROBABLE"
    assert result["cases"][0]["outcome"] == "FAIL"


def test_catalog_canaries_have_fresh_negative_identifiers():
    first = catalog_canaries(start=0, limit=1)
    second = catalog_canaries(start=0, limit=1)
    assert first[0].username == second[0].username
    assert first[1].username != second[1].username
    result = {
        "timestamp": "2026-10-01T00:00:00+00:00",
        "cases": [
            {"site": first[0].site.name, "outcome": "PASS", "actual": "PROBABLE"},
            {"site": first[1].site.name, "outcome": "PASS", "actual": "NOT_FOUND"},
        ],
    }
    assert summarize_catalog_health(result)[0]["health"] == "HEALTHY"
