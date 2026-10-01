"""Async scan engine with bounded requests and isolated provider failures."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from urllib.parse import urlsplit

import httpx

from osintmaster.config import Config
from osintmaster.constants import USER_AGENT
from osintmaster.core.budget import RequestBudget
from osintmaster.core.correlation import correlate_findings
from osintmaster.core.models import Finding, FindingStatus, Report
from osintmaster.core.normalization import username_variants, validated_username
from osintmaster.core.rate_limit import HostRateLimiter
from osintmaster.providers.base import ExternalToolProvider, UsernameProvider
from osintmaster.providers.username import RegistryUsernameProvider, Site, load_sites


class ScanEngine:
    def __init__(
        self,
        config: Config,
        sites: list[Site] | None = None,
        external: list[ExternalToolProvider] | None = None,
        plugins: list[UsernameProvider] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        request_budget: RequestBudget | None = None,
    ) -> None:
        config.validate()
        self.config = config
        self.sites = load_sites() if sites is None else sites
        self.external = external or []
        self.plugins = plugins or []
        self.transport = transport
        self.request_budget = request_budget
        self._global = asyncio.Semaphore(config.max_concurrency)
        self._hosts: defaultdict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(config.per_host_concurrency)
        )
        self._rate = HostRateLimiter(config.host_interval)

    async def _check(
        self, provider: RegistryUsernameProvider, username: str, client: httpx.AsyncClient
    ) -> Finding:
        url = provider.site.profile_url(username)
        host = urlsplit(url).hostname or ""
        for attempt in range(3):
            if self.request_budget is not None and not await self.request_budget.acquire():
                return Finding(
                    provider.name,
                    username,
                    url,
                    FindingStatus.UNKNOWN,
                    error="Request budget exhausted",
                )
            try:
                async with self._global, self._hosts[host]:
                    await self._rate.wait(host)
                    finding = await provider.check(username, client)
            except asyncio.CancelledError:
                raise
            except Exception:
                finding = Finding(
                    provider.name,
                    username,
                    url,
                    FindingStatus.ERROR,
                    error="Provider failed unexpectedly",
                )
            if finding.status != FindingStatus.ERROR:
                return finding
            if attempt < 2:
                await asyncio.sleep(0.5 * (2**attempt))
        return finding

    async def _external_scan(self, provider: ExternalToolProvider, username: str) -> list[Finding]:
        try:
            return await provider.scan(username, self.config.timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            return [
                Finding(
                    provider.name,
                    username,
                    "",
                    FindingStatus.ERROR,
                    error="External provider failed unexpectedly",
                )
            ]

    async def _plugin_check(
        self, provider: UsernameProvider, username: str, client: httpx.AsyncClient
    ) -> Finding:
        key = getattr(provider, "host", provider.name)
        try:
            async with self._global, self._hosts[key]:
                await self._rate.wait(key)
                finding = await asyncio.wait_for(
                    provider.check(username, client), timeout=self.config.timeout
                )
            if not isinstance(finding, Finding):
                raise TypeError("Invalid plugin result")
            return finding
        except asyncio.CancelledError:
            raise
        except Exception:
            return Finding(
                provider.name,
                username,
                "",
                FindingStatus.ERROR,
                error="Plugin request failed or timed out",
            )

    async def scan(self, username: str, *, variants: bool = False) -> Report:
        target = validated_username(username)
        folded = target.casefold()
        candidates = username_variants(folded) if variants else [folded]
        candidates[0] = target
        timeout = httpx.Timeout(self.config.timeout)
        limits = httpx.Limits(
            max_connections=self.config.max_concurrency,
            max_keepalive_connections=self.config.max_concurrency,
        )
        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            transport=self.transport,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        ) as client:
            checks = [
                self._check(
                    RegistryUsernameProvider(site),
                    candidate if site.api_kind == "hackernews" else candidate.casefold(),
                    client,
                )
                for site in self.sites
                for candidate in candidates
            ]
            checks.extend(
                self._plugin_check(plugin, candidate, client)
                for plugin in self.plugins
                for candidate in candidates
            )
            findings = list(await asyncio.gather(*checks))
        if self.external:
            batches = await asyncio.gather(
                *(self._external_scan(item, target) for item in self.external)
            )
            findings.extend(finding for batch in batches for finding in batch)
        errors = [
            f"{item.provider}: {item.error or item.status.value}"
            for item in findings
            if item.status
            in {
                FindingStatus.ERROR,
                FindingStatus.BLOCKED,
                FindingStatus.AUTH_REQUIRED,
                FindingStatus.UNKNOWN,
            }
        ]
        limited = [item.provider for item in findings if item.status == FindingStatus.RATE_LIMITED]
        return Report(
            target,
            findings,
            correlate_findings(findings),
            list(dict.fromkeys(item.provider for item in findings)),
            candidates,
            errors=errors,
            rate_limits=limited,
        )
