import httpx
import pytest

from osintmaster.providers.brave import BraveSearchProvider


@pytest.mark.asyncio
async def test_brave_search_uses_header_and_returns_transient_results():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "web": {
                    "results": [
                        {
                            "title": "Profile",
                            "url": "https://example.org/alex",
                            "description": "Public page",
                        }
                    ]
                }
            },
        )

    provider = BraveSearchProvider("test-secret", transport=httpx.MockTransport(handler))
    results = await provider.search("alex")
    assert len(requests) == 1
    assert requests[0].headers["X-Subscription-Token"] == "test-secret"
    assert requests[0].url.params["q"] == "alex"
    assert results[0].url == "https://example.org/alex"
    assert "test-secret" not in repr(results)


@pytest.mark.asyncio
async def test_brave_search_handles_missing_web_results():
    provider = BraveSearchProvider(
        "test-secret", transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}))
    )
    assert await provider.search("alex") == []
