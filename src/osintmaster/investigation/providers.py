"""Event-provider contract and bounded network context for investigations."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from time import monotonic
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from osintmaster.core.budget import RequestBudget
from osintmaster.core.models import Evidence
from osintmaster.investigation.models import EdgeType, Event, EventType


class ProviderCost(str, Enum):
    FREE_OFFLINE = "FREE_OFFLINE"
    FREE_PUBLIC = "FREE_PUBLIC"
    FREE_API = "FREE_API"
    FREE_TIER = "FREE_TIER"
    PAID = "PAID"


class ProviderActivity(str, Enum):
    LOCAL = "LOCAL"
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"


@dataclass(frozen=True)
class Observation:
    type: EventType
    value: str
    relation: EdgeType
    confidence: float
    source_url: str | None = None
    depth_increment: int = 1
    evidence: tuple[Evidence, ...] = ()
    tags: tuple[str, ...] = ()


@dataclass
class ProviderContext:
    """The supported network path for event providers; shares the hunt budget."""

    budget: RequestBudget
    client: httpx.AsyncClient
    deadline: float
    timeout: float

    async def get(self, url: str) -> httpx.Response:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Event providers may request only public HTTPS URLs")
        if parsed.port not in {None, 443}:
            raise ValueError("Event providers may request only HTTPS on port 443")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:
            if parsed.hostname == "localhost" or parsed.hostname.endswith(
                (".local", ".localhost", ".internal")
            ):
                raise ValueError("Local hosts are not valid public provider endpoints") from exc
        else:
            if not address.is_global:
                raise ValueError("Private IP addresses are not valid provider endpoints")
        remaining = self.deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("Investigation runtime limit reached")
        if not await self.budget.acquire():
            raise RuntimeError("Request limit reached")

        async def read_bounded() -> httpx.Response:
            async with self.client.stream("GET", url, follow_redirects=False) as response:
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > 1_000_000:
                        raise ValueError("Provider response exceeded 1 MB")
                    chunks.append(chunk)
                return httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    content=b"".join(chunks),
                    request=response.request,
                    extensions=response.extensions,
                )

        return await asyncio.wait_for(read_bounded(), timeout=min(self.timeout, remaining))


class EventProvider(Protocol):
    name: str
    accepts: frozenset[EventType]
    produces: frozenset[EventType]
    cost: ProviderCost
    activity: ProviderActivity

    async def run(self, event: Event, context: ProviderContext) -> list[Observation]: ...


@dataclass
class ProviderRegistry:
    providers: list[EventProvider] = field(default_factory=list)

    def register(self, provider: EventProvider) -> None:
        if not provider.name or any(item.name == provider.name for item in self.providers):
            raise ValueError(f"Duplicate or empty event provider name: {provider.name}")
        if (
            not isinstance(provider.accepts, frozenset)
            or not provider.accepts
            or any(not isinstance(item, EventType) for item in provider.accepts)
            or not isinstance(provider.produces, frozenset)
            or not provider.produces
            or any(not isinstance(item, EventType) for item in provider.produces)
            or not isinstance(provider.cost, ProviderCost)
            or not isinstance(provider.activity, ProviderActivity)
            or not callable(provider.run)
        ):
            raise ValueError(f"Provider {provider.name} needs accepted and produced event types")
        self.providers.append(provider)

    def for_event(self, kind: EventType) -> list[EventProvider]:
        return [
            provider
            for provider in self.providers
            if kind in provider.accepts
            and provider.cost
            in {ProviderCost.FREE_OFFLINE, ProviderCost.FREE_PUBLIC, ProviderCost.FREE_API}
            and provider.activity in {ProviderActivity.LOCAL, ProviderActivity.PASSIVE}
        ]
