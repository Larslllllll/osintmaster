"""Optional, one-request Brave Search API adapter."""

from __future__ import annotations

from typing import Any

import httpx

from osintmaster.core.models import SearchResult
from osintmaster.providers.base import SearchProvider

BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"


class BraveSearchProvider(SearchProvider):
    name = "Brave Search"

    def __init__(
        self, api_key: str, timeout: float = 10, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        if not api_key:
            raise ValueError("Brave Search API key is missing")
        self._api_key = api_key
        self.timeout = timeout
        self.transport = transport

    async def search(self, query: str) -> list[SearchResult]:
        if not query.strip() or len(query) > 600:
            raise ValueError("Search query must contain 1-600 characters")
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            response = await client.get(
                BRAVE_SEARCH_URL,
                params={"q": query, "count": 10, "result_filter": "web"},
                headers={"Accept": "application/json", "X-Subscription-Token": self._api_key},
            )
            response.raise_for_status()
            data: Any = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("web"), dict):
            return []
        results = data["web"].get("results", [])
        if not isinstance(results, list):
            return []
        found = []
        for item in results[:10]:
            if isinstance(item, dict) and isinstance(item.get("url"), str):
                found.append(
                    SearchResult(
                        title=str(item.get("title") or ""),
                        url=item["url"],
                        snippet=str(item.get("description") or ""),
                        provider=self.name,
                    )
                )
        return found
