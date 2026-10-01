"""Provider interfaces for separately installed extensions."""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from osintmaster.core.models import Finding, SearchResult


class BaseProvider(ABC):
    name: str


class UsernameProvider(BaseProvider):
    @abstractmethod
    async def check(self, username: str, client: httpx.AsyncClient) -> Finding:
        """Check one public username and return a standard finding."""


class SearchProvider(BaseProvider):
    @abstractmethod
    async def search(self, query: str) -> list[SearchResult]:
        """Search via an explicitly configured API."""


class ExternalToolProvider(BaseProvider):
    @abstractmethod
    async def scan(self, username: str, timeout: float) -> list[Finding]:
        """Run an optional locally installed tool."""
