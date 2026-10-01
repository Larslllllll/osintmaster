"""Stable, serializable result models for providers and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from osintmaster import __version__


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    NOT_FOUND = "NOT_FOUND"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    RATE_LIMITED = "RATE_LIMITED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Evidence:
    type: str
    value: str
    weight: int
    source: str


@dataclass
class Profile:
    display_name: str | None = None
    bio: str | None = None
    links: list[str] = field(default_factory=list)
    image_url: str | None = None
    image_hash: str | None = None
    location: str | None = None
    account_type: str | None = None
    platform_id: str | None = None


@dataclass
class Finding:
    provider: str
    username: str
    url: str
    status: FindingStatus
    profile: Profile = field(default_factory=Profile)
    evidence: list[Evidence] = field(default_factory=list)
    error: str | None = None
    http_status: int | None = None


@dataclass
class Identity:
    target: str
    candidates: list[str]
    profiles: list[Finding]


@dataclass
class Correlation:
    left_url: str
    right_url: str
    score: int
    label: str
    evidence: list[Evidence]
    explanation: str = "Technical profile correlation only; real-world identity is unverified."


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str
    provider: str


@dataclass
class Report:
    target: str
    findings: list[Finding]
    correlations: list[Correlation]
    providers_used: list[str]
    variants: list[str]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = __version__
    errors: list[str] = field(default_factory=list)
    rate_limits: list[str] = field(default_factory=list)
    target_type: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    graph: dict[str, Any] | None = None
    limits: dict[str, Any] = field(default_factory=dict)
    investigation_id: str = field(default_factory=lambda: uuid4().hex)
    provider_runs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
