import httpx
import pytest

from osintmaster.config import Config
from osintmaster.core.engine import ScanEngine
from osintmaster.core.models import FindingStatus
from osintmaster.providers.username import (
    RegistryUsernameProvider,
    Site,
    detect_status,
    extract_profile,
    load_sites,
)
from osintmaster.reports.html_report import render_html

SITE = Site(
    "Example",
    "https://example.org/{username}",
    "social",
    (200,),
    (404,),
    ("profile-card",),
    ("No user here",),
)


def test_status_detection_and_profile_extraction():
    assert detect_status(SITE, 200, "<div class=profile-card></div>") == FindingStatus.CONFIRMED
    assert detect_status(SITE, 200, "generic page") == FindingStatus.UNKNOWN
    assert detect_status(SITE, 200, "No user here profile-card") == FindingStatus.NOT_FOUND
    assert detect_status(SITE, 404, "") == FindingStatus.NOT_FOUND
    assert detect_status(SITE, 429, "") == FindingStatus.RATE_LIMITED
    assert detect_status(SITE, 403, "") == FindingStatus.BLOCKED
    assert detect_status(SITE, 503, "") == FindingStatus.ERROR
    profile = extract_profile(
        '<meta property="og:title" content="Alex">'
        '<a rel="me" href="https://portfolio.example/alex">portfolio</a>',
        "https://example.org/alex",
    )
    assert profile.display_name == "Alex"
    assert profile.links == ["https://portfolio.example/alex"]


def test_unverified_reddit_check_is_not_in_default_registry():
    assert "Reddit" not in {site.name for site in load_sites()}


@pytest.mark.asyncio
async def test_engine_retries_server_error_then_recovers(tmp_path):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503)
        return httpx.Response(
            200,
            text='<link rel="canonical" href="https://example.org/alex"><div>profile-card</div>',
            headers={"content-type": "text/html"},
        )

    config = Config(reports_dir=tmp_path, host_interval=0)
    report = await ScanEngine(config, [SITE], transport=httpx.MockTransport(handler)).scan("alex")
    assert calls == 2
    assert report.findings[0].status == FindingStatus.CONFIRMED
    assert report.errors == []


@pytest.mark.asyncio
async def test_engine_stops_on_rate_limit(tmp_path):
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(429)

    config = Config(reports_dir=tmp_path, host_interval=0)
    report = await ScanEngine(config, [SITE], transport=httpx.MockTransport(handler)).scan("alex")
    assert calls == 1
    assert report.findings[0].status == FindingStatus.RATE_LIMITED
    assert report.rate_limits == ["Example"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [401, 403, 451])
async def test_access_denial_is_unresolved_not_absence(tmp_path, status_code):
    calls = 0
    chunks_read = 0

    class DeniedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            nonlocal chunks_read
            chunks_read += 1
            yield b"x" * 1_000_001

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(status_code, stream=DeniedStream())

    report = await ScanEngine(
        Config(reports_dir=tmp_path, host_interval=0),
        [SITE],
        transport=httpx.MockTransport(handler),
    ).scan("alex")
    finding = report.findings[0]
    assert calls == 1
    assert chunks_read == 0
    assert finding.status == (
        FindingStatus.AUTH_REQUIRED if status_code == 401 else FindingStatus.BLOCKED
    )
    assert finding.http_status == status_code
    assert finding.evidence[0].type == "http_access_denied"
    assert "account state unverified" in finding.error
    assert report.errors
    assert report.correlations == []
    assert '<span>UNRESOLVED</span><strong class="rose">1</strong>' in render_html(report)


@pytest.mark.asyncio
async def test_engine_keeps_other_results_when_provider_fails(tmp_path):
    second = Site("Second", "https://second.example/{username}", "social", (200,), (404,))

    def handler(request):
        if request.url.host == "example.org":
            raise httpx.ConnectError("connection failed")
        return httpx.Response(404)

    config = Config(reports_dir=tmp_path, host_interval=0)
    report = await ScanEngine(config, [SITE, second], transport=httpx.MockTransport(handler)).scan(
        "alex"
    )
    assert [item.status for item in report.findings] == [
        FindingStatus.ERROR,
        FindingStatus.NOT_FOUND,
    ]
    assert len(report.errors) == 1


@pytest.mark.asyncio
async def test_engine_handles_timeout_and_malformed_page(tmp_path):
    def handler(request):
        if request.url.host == "example.org":
            raise httpx.ReadTimeout("timeout")
        return httpx.Response(200, content=b"x" * 1_000_001)

    second = Site("Second", "https://second.example/{username}", "social", (200,), (404,))
    config = Config(reports_dir=tmp_path, host_interval=0)
    report = await ScanEngine(config, [SITE, second], transport=httpx.MockTransport(handler)).scan(
        "alex"
    )
    assert report.findings[0].status == FindingStatus.ERROR
    assert report.findings[1].status == FindingStatus.UNKNOWN
    assert len(report.errors) == 2


@pytest.mark.asyncio
async def test_large_response_stops_streaming_before_full_download(tmp_path):
    class LargeStream(httpx.AsyncByteStream):
        def __init__(self):
            self.chunks_sent = 0

        async def __aiter__(self):
            for _ in range(10):
                self.chunks_sent += 1
                yield b"x" * 400_000

    stream = LargeStream()
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    report = await ScanEngine(
        Config(reports_dir=tmp_path, host_interval=0), [SITE], transport=transport
    ).scan("alex")
    assert report.findings[0].status == FindingStatus.UNKNOWN
    assert report.findings[0].error == "Page too large"
    assert stream.chunks_sent == 3

    announced_stream = LargeStream()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200, headers={"content-length": "4000000"}, stream=announced_stream
        )
    )
    report = await ScanEngine(
        Config(reports_dir=tmp_path, host_interval=0), [SITE], transport=transport
    ).scan("alex")
    assert report.findings[0].status == FindingStatus.UNKNOWN
    assert announced_stream.chunks_sent == 0


@pytest.mark.asyncio
async def test_public_api_requires_exact_username_and_keeps_profile_details():
    site = Site.from_dict(
        {
            "name": "GitHub",
            "url": "https://github.com/{username}",
            "category": "development",
            "api_url": "https://api.github.com/users/{username}",
            "api_kind": "github",
        }
    )

    def handler(request):
        username = request.url.path.rsplit("/", 1)[-1]
        if username == "missing":
            return httpx.Response(404)
        if username == "limited":
            return httpx.Response(403, headers={"x-ratelimit-remaining": "0"})
        if username == "wrong":
            return httpx.Response(200, json={"login": "someone_else"})
        return httpx.Response(
            200,
            json={
                "login": username,
                "name": "Example User",
                "bio": "Public bio",
                "blog": "example.org",
                "location": "Berlin",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = RegistryUsernameProvider(site)
        assert (await provider.check("wrong", client)).status == FindingStatus.UNKNOWN
        missing = await provider.check("missing", client)
        assert missing.status == FindingStatus.NOT_FOUND
        assert missing.evidence[0].type == "api_not_found"
        assert (await provider.check("limited", client)).status == FindingStatus.RATE_LIMITED
        exact = await provider.check("sample", client)
    assert exact.status == FindingStatus.CONFIRMED
    assert exact.profile.links == ["https://example.org"]
    assert exact.profile.location == "Berlin"
    assert exact.evidence[0].source == "https://api.github.com/users/sample"


@pytest.mark.asyncio
async def test_bluesky_only_treats_explicit_profile_absence_as_not_found(tmp_path):
    bluesky = next(site for site in load_sites() if site.name == "Bluesky")

    def handler(request):
        if "missing" in str(request.url):
            return httpx.Response(
                400, json={"error": "InvalidRequest", "message": "Profile not found"}
            )
        return httpx.Response(
            400,
            json={"error": "InvalidRequest", "message": "Invalid AT identifier"},
        )

    scanner = ScanEngine(
        Config(reports_dir=tmp_path, host_interval=0),
        [bluesky],
        transport=httpx.MockTransport(handler),
    )
    missing = (await scanner.scan("missing")).findings[0]
    malformed = (await scanner.scan("foo_bar")).findings[0]
    assert missing.status == FindingStatus.NOT_FOUND
    assert missing.evidence[0].source == bluesky.request_url("missing")
    assert malformed.status == FindingStatus.UNKNOWN


@pytest.mark.asyncio
async def test_html_redirect_and_unrelated_canonical_are_not_confirmed(tmp_path):
    def handler(request):
        if request.url.path == "/redirect":
            return httpx.Response(302, headers={"location": "https://login.example.org/"})
        return httpx.Response(
            200,
            text='<link rel="canonical" href="https://example.org/another">'
            '<div class="profile-card"></div>',
            headers={"content-type": "text/html"},
        )

    config = Config(reports_dir=tmp_path, host_interval=0)
    report = await ScanEngine(config, [SITE], transport=httpx.MockTransport(handler)).scan(
        "redirect"
    )
    assert report.findings[0].status == FindingStatus.UNKNOWN
    second = await ScanEngine(config, [SITE], transport=httpx.MockTransport(handler)).scan("alex")
    assert second.findings[0].status == FindingStatus.UNKNOWN


@pytest.mark.asyncio
async def test_generic_reddit_page_is_not_an_active_profile(tmp_path):
    reddit = Site(
        "Reddit",
        "https://www.reddit.com/user/{username}/",
        "social",
        (200,),
        (404,),
        negative_markers=("Sorry, nobody on Reddit goes by that name",),
    )

    def handler(request):
        return httpx.Response(
            200,
            text="<html><head><title>Reddit</title></head><body>Generic page</body></html>",
            headers={"content-type": "text/html"},
        )

    report = await ScanEngine(
        Config(reports_dir=tmp_path, host_interval=0),
        [reddit],
        transport=httpx.MockTransport(handler),
    ).scan("osintmaster_random_nonexistent_name")
    assert report.findings[0].status == FindingStatus.UNKNOWN
    assert report.correlations == []
