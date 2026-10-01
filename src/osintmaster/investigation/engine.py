"""Bounded recursive investigation over public profile links and domains."""

from __future__ import annotations

import asyncio
import ipaddress
import re
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import httpx

from osintmaster.config import Config
from osintmaster.constants import USER_AGENT
from osintmaster.core.budget import RequestBudget
from osintmaster.core.correlation import correlate_findings
from osintmaster.core.engine import ScanEngine
from osintmaster.core.models import Evidence, Finding, FindingStatus, Report
from osintmaster.core.normalization import validated_username
from osintmaster.graph.models import ProviderRun, evidence_method, new_id
from osintmaster.investigation.models import EdgeType, Event, EventType, InvestigationGraph
from osintmaster.investigation.providers import (
    EventProvider,
    Observation,
    ProviderActivity,
    ProviderContext,
    ProviderCost,
    ProviderRegistry,
)
from osintmaster.investigation.targets import (
    classify_target,
    domain_from_url,
    match_profile_url,
    public_dns_domain,
)
from osintmaster.metadata.image import analyze_image
from osintmaster.providers.username import Site, load_sites

PUBLIC_EMAIL = re.compile(r"(?<![\w.-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
ACTIVE = {FindingStatus.CONFIRMED, FindingStatus.PROBABLE, FindingStatus.POSSIBLE}


@dataclass(frozen=True)
class HuntLimits:
    depth: int = 1
    max_events: int = 300
    max_requests: int = 50
    max_runtime: float = 90.0
    max_per_provider: int = 10
    max_provider_runs: int = 300

    def validate(self) -> None:
        if not 0 <= self.depth <= 3:
            raise ValueError("Depth must be between 0 and 3")
        if not 1 <= self.max_events <= 5000:
            raise ValueError("max_events must be between 1 and 5000")
        if not 0 <= self.max_requests <= 1000:
            raise ValueError("max_requests must be between 0 and 1000")
        if not 1 <= self.max_runtime <= 3600:
            raise ValueError("max_runtime must be between 1 and 3600 seconds")
        if not 1 <= self.max_per_provider <= 100:
            raise ValueError("max_per_provider must be between 1 and 100")
        if not 1 <= self.max_provider_runs <= 5000:
            raise ValueError("max_provider_runs must be between 1 and 5000")


@dataclass
class BuiltinEventProvider:
    name: str
    accepts: frozenset[EventType]
    produces: frozenset[EventType]
    cost: ProviderCost
    activity: ProviderActivity
    handler: Callable[[Event], Awaitable[None]]

    async def run(self, event: Event, context: ProviderContext) -> list[Observation]:
        await self.handler(event)
        return []


class HuntEngine:
    def __init__(
        self,
        config: Config,
        *,
        sites: list[Site] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        event_providers: list[EventProvider] | None = None,
        plugin_errors: list[str] | None = None,
    ) -> None:
        config.validate()
        self.config = config
        self.sites = load_sites() if sites is None else sites
        self.transport = transport
        self.event_providers = event_providers or []
        self.plugin_errors = plugin_errors or []

    def _registry(self) -> ProviderRegistry:
        registry = ProviderRegistry()
        specs = (
            (
                "Username scanner",
                EventType.USERNAME,
                frozenset(
                    {
                        EventType.PROFILE,
                        EventType.PERSON_NAME,
                        EventType.LOCATION,
                        EventType.URL,
                        EventType.EMAIL,
                    }
                ),
                ProviderCost.FREE_PUBLIC,
                ProviderActivity.PASSIVE,
                self._scan_username_event,
            ),
            (
                "Known URL pivot",
                EventType.URL,
                frozenset({EventType.USERNAME, EventType.DOMAIN}),
                ProviderCost.FREE_PUBLIC,
                ProviderActivity.PASSIVE,
                self._process_url,
            ),
            (
                "Email domain",
                EventType.EMAIL,
                frozenset({EventType.DOMAIN}),
                ProviderCost.FREE_OFFLINE,
                ProviderActivity.LOCAL,
                self._process_email,
            ),
            (
                "DNS",
                EventType.DOMAIN,
                frozenset({EventType.IP_ADDRESS}),
                ProviderCost.FREE_PUBLIC,
                ProviderActivity.PASSIVE,
                self._resolve_domain,
            ),
            (
                "reverse DNS",
                EventType.IP_ADDRESS,
                frozenset({EventType.HOSTNAME}),
                ProviderCost.FREE_PUBLIC,
                ProviderActivity.PASSIVE,
                self._reverse_ip,
            ),
            (
                "Local image",
                EventType.IMAGE,
                frozenset({EventType.IMAGE_HASH, EventType.METADATA}),
                ProviderCost.FREE_OFFLINE,
                ProviderActivity.LOCAL,
                self._inspect_image,
            ),
        )
        for name, accepts, produces, cost, activity, handler in specs:
            registry.register(
                BuiltinEventProvider(name, frozenset({accepts}), produces, cost, activity, handler)
            )
        for provider in self.event_providers:
            registry.register(provider)
        return registry

    async def hunt(
        self,
        target: str,
        *,
        target_type: EventType | None = None,
        limits: HuntLimits = HuntLimits(),
    ) -> Report:
        kind, value = classify_target(target, target_type)
        return await self._hunt_seeds([(kind, value)], value, kind.value, limits)

    async def hunt_many(
        self, name: str, targets: list[str], *, limits: HuntLimits = HuntLimits()
    ) -> Report:
        """Investigate several explicit seeds with one graph and one shared budget."""
        if not 2 <= len(targets) <= 20:
            raise ValueError("A case requires 2 to 20 targets")
        case_name = validated_username(name)
        seeds = list(dict.fromkeys(classify_target(target) for target in targets))
        if len(seeds) < 2:
            raise ValueError("A case requires at least two distinct targets")
        return await self._hunt_seeds(seeds, f"case-{case_name}", "CASE", limits)

    async def _hunt_seeds(
        self,
        seeds: list[tuple[EventType, str]],
        report_target: str,
        report_type: str,
        limits: HuntLimits,
    ) -> Report:
        limits.validate()
        self.limits = limits
        self.budget = RequestBudget(limits.max_requests)
        self.deadline = monotonic() + limits.max_runtime
        investigation_id = new_id()
        self.graph = InvestigationGraph(
            investigation_id,
            name=report_target,
            budgets={
                "max_depth": limits.depth,
                "max_entities": limits.max_events,
                "max_network_requests": limits.max_requests,
                "max_runtime": limits.max_runtime,
                "max_per_provider": limits.max_per_provider,
                "max_provider_runs": limits.max_provider_runs,
            },
        )
        self.events: list[Event] = []
        self.queue: deque[Event] = deque()
        self._observed: set[tuple[EventType, str, str, str | None]] = set()
        self._checked: set[tuple[str, str]] = set()
        self._per_provider: defaultdict[str, int] = defaultdict(int)
        self.findings: list[Finding] = []
        self.errors: list[str] = list(self.plugin_errors)
        self.rate_limits: list[str] = []
        self.provider_runs: list[dict[str, Any]] = []
        self._event_limit_hit = False
        registry = self._registry()
        for kind, value in seeds:
            root = self._emit(kind, value, "input", None, None, 1.0, 0)
            if root is None:
                raise AssertionError("Root event was not created")
        async with httpx.AsyncClient(
            transport=self.transport,
            timeout=self.config.timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            context = ProviderContext(self.budget, client, self.deadline, self.config.timeout)
            while self.queue:
                if len(self.provider_runs) >= limits.max_provider_runs:
                    self.errors.append("Provider run limit reached")
                    break
                if monotonic() >= self.deadline:
                    self.errors.append("Investigation runtime limit reached")
                    break
                event = self.queue.popleft()
                if event.depth > limits.depth:
                    continue
                pivot_entity = self.graph.event_entity(event.id)
                pivot = self.graph.pivot_candidates.get(pivot_entity.id) if pivot_entity else None
                if pivot is not None:
                    pivot.status = "processed"
                for provider in registry.for_event(event.type):
                    if provider.name == "Local image" and event.source_provider != "input":
                        continue
                    if len(self.provider_runs) >= limits.max_provider_runs:
                        self.errors.append("Provider run limit reached")
                        break
                    if not isinstance(provider, BuiltinEventProvider):
                        if self._per_provider[provider.name] >= limits.max_per_provider:
                            continue
                        self._per_provider[provider.name] += 1
                    started = monotonic()
                    started_at = datetime.now(timezone.utc).isoformat()
                    run_id = new_id()
                    requests_before = self.budget.used
                    events_before = len(self.events)
                    entities_before = len(self.graph.nodes)
                    observations_before = len(self.graph.observations)
                    relations_before = len(self.graph.edges)
                    evidence_before = len(self.graph.evidence)
                    errors_before = len(self.errors)
                    limits_before = len(self.rate_limits)
                    status = "OK"
                    error_message: str | None = None
                    try:
                        observations = await asyncio.wait_for(
                            provider.run(event, context), timeout=self._remaining()
                        )
                        for observation in observations:
                            if observation.type not in provider.produces:
                                raise ValueError("Provider emitted an undeclared event type")
                            if (
                                observation.depth_increment not in {0, 1}
                                or not 0 <= observation.confidence <= 1
                            ):
                                raise ValueError("Provider emitted invalid depth or confidence")
                            self._emit(
                                observation.type,
                                observation.value,
                                provider.name,
                                observation.source_url,
                                event,
                                observation.confidence,
                                event.depth + observation.depth_increment,
                                observation.relation,
                                evidence=list(observation.evidence),
                                tags=list(observation.tags),
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        status = "ERROR"
                        error_message = f"{type(exc).__name__}: {exc}"
                        self.errors.append(f"{provider.name}: {error_message}")
                    finally:
                        if status == "OK" and (
                            len(self.errors) > errors_before
                            or len(self.rate_limits) > limits_before
                        ):
                            status = "PARTIAL"
                            error_message = "; ".join(self.errors[errors_before:]) or None
                        for observation_record in self.graph.observations[observations_before:]:
                            observation_record.provider_run_id = run_id
                        for evidence_record in self.graph.evidence[evidence_before:]:
                            evidence_record.provider_run_id = run_id
                        for relation_record in self.graph.edges[relations_before:]:
                            relation_record.provider_run_id = run_id
                        input_entity = self.graph.event_entity(event.id)
                        if input_entity is not None:
                            self.graph.add_provider_run(
                                ProviderRun(
                                    run_id,
                                    provider.name,
                                    input_entity.id,
                                    started_at,
                                    datetime.now(timezone.utc).isoformat(),
                                    status,
                                    self.budget.used - requests_before,
                                    len(self.graph.nodes) - entities_before,
                                    len(self.graph.observations) - observations_before,
                                    len(self.graph.edges) - relations_before,
                                    error_message,
                                    self.rate_limits[limits_before:],
                                )
                            )
                        self.provider_runs.append(
                            {
                                "provider": provider.name,
                                "event_id": event.id,
                                "event_type": event.type.value,
                                "cost": provider.cost.value,
                                "activity": provider.activity.value,
                                "status": status,
                                "requests_used": self.budget.used - requests_before,
                                "events_emitted": len(self.events) - events_before,
                                "duration_ms": round((monotonic() - started) * 1000),
                            }
                        )
        if self._event_limit_hit:
            self.errors.append("Event limit reached; additional pivots were omitted")
        self.graph.investigation.status = (
            "partial" if self.errors or self.rate_limits else "complete"
        )
        self.graph.investigation.updated_at = datetime.now(timezone.utc).isoformat()
        correlations = correlate_findings(self.findings)
        self.graph.correlate(correlations)
        return Report(
            report_target,
            self.findings,
            correlations,
            list(dict.fromkeys(item.provider for item in self.findings)),
            list(
                dict.fromkeys(item.value for item in self.events if item.type == EventType.USERNAME)
            ),
            errors=list(dict.fromkeys(self.errors)),
            rate_limits=list(dict.fromkeys(self.rate_limits)),
            target_type=report_type,
            events=[item.to_dict() for item in self.events],
            graph=self.graph.to_dict(),
            limits={
                "depth": limits.depth,
                "max_events": limits.max_events,
                "max_requests": limits.max_requests,
                "requests_used": self.budget.used,
                "max_runtime": limits.max_runtime,
                "max_per_provider": limits.max_per_provider,
                "max_provider_runs": limits.max_provider_runs,
            },
            provider_runs=self.provider_runs,
            investigation_id=investigation_id,
        )

    async def _scan_username_event(self, event: Event) -> None:
        if "alias_candidate" not in event.tags:
            await self._scan_username(event)

    async def _process_email(self, event: Event) -> None:
        domain = event.value.rpartition("@")[2]
        self._emit(
            EventType.DOMAIN,
            domain,
            "email domain",
            event.value,
            event,
            0.95,
            event.depth + 1,
            EdgeType.BELONGS_TO_DOMAIN,
        )

    def _emit(
        self,
        kind: EventType,
        value: str,
        provider: str,
        source_url: str | None,
        parent: Event | None,
        confidence: float,
        depth: int,
        relation: EdgeType | None = None,
        *,
        evidence: list[Evidence] | None = None,
        tags: list[str] | None = None,
    ) -> Event | None:
        key = (
            kind,
            value if kind == EventType.USERNAME else value.casefold(),
            provider,
            parent.id if parent else None,
        )
        if key in self._observed:
            return None
        if len(self.events) >= self.limits.max_events:
            self._event_limit_hit = True
            return None
        event = Event(
            kind,
            value,
            provider,
            source_url,
            parent.id if parent else None,
            confidence,
            depth,
            tags or [],
            evidence or [],
        )
        self._observed.add(key)
        self.events.append(event)
        self.graph.add(event, relation)
        if depth <= self.limits.depth:
            self.queue.append(event)
        return event

    def _remaining(self) -> float:
        return max(0.01, self.deadline - monotonic())

    async def _scan_username(self, event: Event, site: Site | None = None) -> None:
        selected: list[Site] = []
        for candidate in [site] if site is not None else self.sites:
            key = (
                candidate.name,
                event.value if candidate.api_kind == "hackernews" else event.value.casefold(),
            )
            if key in self._checked:
                continue
            if self._per_provider[candidate.name] >= self.limits.max_per_provider:
                self.errors.append(f"Provider check limit reached: {candidate.name}")
                continue
            if self.budget.used + len(selected) >= self.budget.limit:
                self.errors.append("Request limit reached")
                break
            self._checked.add(key)
            self._per_provider[candidate.name] += 1
            selected.append(candidate)
        if not selected:
            return
        scanner = ScanEngine(
            self.config,
            sites=selected,
            transport=self.transport,
            request_budget=self.budget,
        )
        try:
            result = await asyncio.wait_for(scanner.scan(event.value), timeout=self._remaining())
        except asyncio.TimeoutError:
            self.errors.append("Profile scan exceeded investigation runtime")
            return
        self.findings.extend(result.findings)
        self.errors.extend(result.errors)
        self.rate_limits.extend(result.rate_limits)
        for finding in result.findings:
            self._record_finding(event, finding)

    def _record_finding(self, parent: Event, finding: Finding) -> None:
        seed = self.graph.event_entity(parent.id)
        if seed is not None:
            proof = [
                self.graph.add_evidence(
                    finding.provider,
                    method=evidence_method(item.type, finding.provider),
                    source_url=item.source or finding.url,
                    excerpt=item.value,
                    raw_reference=item.type,
                )
                for item in finding.evidence
            ]
            if not proof:
                proof = [
                    self.graph.add_evidence(
                        finding.provider, method="PUBLIC_METADATA", source_url=finding.url
                    )
                ]
            self.graph.add_observation(
                seed.id,
                f"profile_check:{finding.provider}",
                {
                    "username": finding.username,
                    "url": finding.url,
                    "http_status": finding.http_status,
                    "error": finding.error,
                },
                provider=finding.provider,
                state=finding.status.value,
                evidence_ids=[item.id for item in proof],
            )
        if finding.status not in ACTIVE:
            return
        confidence = 0.95 if finding.status == FindingStatus.CONFIRMED else 0.45
        profile = self._emit(
            EventType.PROFILE,
            finding.url,
            finding.provider,
            finding.url,
            parent,
            confidence,
            parent.depth,
            EdgeType.DISCOVERED_FROM,
            evidence=finding.evidence,
            tags=[
                finding.status.value,
                *([finding.profile.account_type] if finding.profile.account_type else []),
            ],
        )
        if profile is None or finding.status != FindingStatus.CONFIRMED:
            return
        profile_entity = self.graph.event_entity(profile.id)
        if profile_entity is not None and seed is not None:
            profile_entity.attributes["platform"] = finding.provider
            profile_entity.attributes["username"] = finding.username
            if finding.profile.platform_id:
                profile_entity.attributes["platform_id"] = finding.profile.platform_id
            self.graph.add_relation(
                profile_entity.id,
                seed.id,
                "USES_USERNAME",
                provider=finding.provider,
                source_url=finding.url,
                evidence_ids=[item.id for item in proof],
            )
        public = finding.profile
        if profile_entity is not None:
            for property_name in ("bio", "display_name", "location", "image_url", "image_hash"):
                claim = getattr(public, property_name)
                if claim:
                    self.graph.add_observation(
                        profile_entity.id,
                        property_name,
                        claim,
                        provider=finding.provider,
                        evidence_ids=[item.id for item in proof],
                    )
        if public.display_name:
            self._emit(
                EventType.PERSON_NAME,
                public.display_name,
                finding.provider,
                finding.url,
                profile,
                0.5,
                parent.depth,
                EdgeType.CLAIMS_NAME,
                evidence=[Evidence("public_display_name", public.display_name, 0, finding.url)],
            )
        if public.location:
            self._emit(
                EventType.LOCATION,
                public.location,
                finding.provider,
                finding.url,
                profile,
                0.4,
                parent.depth,
                EdgeType.CLAIMS_LOCATION,
                evidence=[Evidence("public_location", public.location, 0, finding.url)],
            )
        if public.image_url:
            try:
                scheme = urlsplit(public.image_url).scheme
            except ValueError:
                scheme = ""
            if scheme in {"http", "https"}:
                image = self._emit(
                    EventType.IMAGE,
                    public.image_url,
                    finding.provider,
                    finding.url,
                    profile,
                    0.7,
                    parent.depth + 1,
                    EdgeType.USES_IMAGE,
                    evidence=[Evidence("public_image_url", public.image_url, 0, finding.url)],
                )
                image_entity = self.graph.event_entity(image.id) if image else None
                if image_entity is not None and public.image_hash:
                    self.graph.add_observation(
                        image_entity.id,
                        "externally_supplied_hash",
                        public.image_hash,
                        provider=finding.provider,
                        evidence_ids=[item.id for item in proof],
                    )
        for link in public.links[:10]:
            try:
                scheme = urlsplit(link).scheme
            except ValueError:
                continue
            if scheme in {"http", "https"}:
                self._emit(
                    EventType.URL,
                    link,
                    finding.provider,
                    finding.url,
                    profile,
                    0.7,
                    parent.depth + 1,
                    EdgeType.LINKS_TO,
                    evidence=[Evidence("published_link", link, 0, finding.url)],
                )
        for email in dict.fromkeys(PUBLIC_EMAIL.findall(public.bio or "")):
            self._emit(
                EventType.EMAIL,
                email.casefold(),
                finding.provider,
                finding.url,
                profile,
                0.5,
                parent.depth + 1,
                EdgeType.EXPOSES_EMAIL,
                evidence=[Evidence("public_bio_email", email, 0, finding.url)],
            )

    async def _process_url(self, event: Event) -> None:
        match = match_profile_url(event.value, self.sites)
        if match:
            site, username = match
            alias = self._emit(
                EventType.USERNAME,
                username,
                site.name,
                event.value,
                event,
                0.6,
                event.depth,
                EdgeType.USES_USERNAME,
                tags=["alias_candidate"],
            )
            if alias is not None:
                await self._scan_username(alias, site)
            return
        domain = domain_from_url(event.value)
        if domain:
            self._emit(
                EventType.DOMAIN,
                domain,
                "URL hostname",
                event.value,
                event,
                0.95,
                event.depth + 1,
                EdgeType.BELONGS_TO_DOMAIN,
                evidence=[Evidence("url_hostname", domain, 0, event.value)],
            )

    async def _resolve_domain(self, event: Event) -> None:
        if not public_dns_domain(event.value):
            return
        ips: set[str] = set()
        limited = False
        for record_type in ("A", "AAAA"):
            if self._per_provider["DNS"] >= self.limits.max_per_provider:
                limited = True
                break
            if not await self.budget.acquire():
                self.errors.append("Request limit reached")
                limited = True
                break
            self._per_provider["DNS"] += 1
            timeout = min(self.config.timeout, self._remaining())
            try:
                answer = await asyncio.wait_for(
                    dns.asyncresolver.resolve(event.value, record_type, lifetime=timeout),
                    timeout=timeout,
                )
                ips.update(str(ipaddress.ip_address(str(item))) for item in answer)
            except (dns.exception.DNSException, asyncio.TimeoutError):
                continue
        if not ips:
            if not limited:
                self.errors.append(f"DNS: no A/AAAA result for {event.value}")
            return
        for address in sorted(ips)[:8]:
            self._emit(
                EventType.IP_ADDRESS,
                address,
                "DNS",
                event.value,
                event,
                0.8,
                event.depth + 1,
                EdgeType.RESOLVES_TO,
                evidence=[Evidence("dns_resolution", event.value, 0, event.value)],
            )

    async def _reverse_ip(self, event: Event) -> None:
        ip = ipaddress.ip_address(event.value)
        if not ip.is_global or self._per_provider["reverse DNS"] >= self.limits.max_per_provider:
            return
        if not await self.budget.acquire():
            self.errors.append("Request limit reached")
            return
        self._per_provider["reverse DNS"] += 1
        timeout = min(self.config.timeout, self._remaining())
        try:
            answer = await asyncio.wait_for(
                dns.asyncresolver.resolve_address(event.value, lifetime=timeout),
                timeout=timeout,
            )
            hostname = str(answer[0]).rstrip(".")
        except (dns.exception.DNSException, asyncio.TimeoutError, IndexError):
            return
        self._emit(
            EventType.HOSTNAME,
            hostname.casefold(),
            "reverse DNS",
            event.value,
            event,
            0.65,
            event.depth + 1,
            EdgeType.RESOLVES_TO,
        )

    async def _inspect_image(self, event: Event) -> None:
        if event.source_provider != "input":
            return
        try:
            result: dict[str, Any] = await asyncio.wait_for(
                asyncio.to_thread(analyze_image, Path(event.value)),
                timeout=self._remaining(),
            )
        except (ValueError, OSError, asyncio.TimeoutError):
            self.errors.append("Could not analyze local image")
            return
        digest = result.get("sha256")
        if isinstance(digest, str):
            self._emit(
                EventType.IMAGE_HASH,
                digest,
                "local image",
                event.value,
                event,
                1.0,
                event.depth,
                EdgeType.DISCOVERED_FROM,
            )
        dimensions = result.get("dimensions")
        if dimensions:
            self._emit(
                EventType.METADATA,
                f"dimensions: {dimensions}",
                "local image",
                event.value,
                event,
                1.0,
                event.depth,
                EdgeType.DISCOVERED_FROM,
            )
