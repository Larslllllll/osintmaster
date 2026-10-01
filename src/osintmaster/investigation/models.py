"""Typed observations and a provenance-preserving investigation graph."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from osintmaster.core.models import Evidence


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventType(str, Enum):
    USERNAME = "USERNAME"
    PROFILE = "PROFILE"
    EMAIL = "EMAIL"
    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"
    IMAGE = "IMAGE"
    IMAGE_HASH = "IMAGE_HASH"
    PHONE = "PHONE"
    LOCATION = "LOCATION"
    PERSON_NAME = "PERSON_NAME"
    ORGANIZATION = "ORGANIZATION"
    SOCIAL_PROFILE = "SOCIAL_PROFILE"
    REPOSITORY = "REPOSITORY"
    DNS_RECORD = "DNS_RECORD"
    CERTIFICATE = "CERTIFICATE"
    METADATA = "METADATA"
    TECHNOLOGY = "TECHNOLOGY"
    DOCUMENT = "DOCUMENT"
    FINDING = "FINDING"


class EdgeType(str, Enum):
    DISCOVERED_FROM = "DISCOVERED_FROM"
    USES_USERNAME = "USES_USERNAME"
    LINKS_TO = "LINKS_TO"
    CLAIMS_WEBSITE = "CLAIMS_WEBSITE"
    CLAIMS_NAME = "CLAIMS_NAME"
    CLAIMS_LOCATION = "CLAIMS_LOCATION"
    SAME_AVATAR = "SAME_AVATAR"
    USES_IMAGE = "USES_IMAGE"
    SAME_EMAIL = "SAME_EMAIL"
    SIMILAR_PROFILE = "SIMILAR_PROFILE"
    RESOLVES_TO = "RESOLVES_TO"
    BELONGS_TO_DOMAIN = "BELONGS_TO_DOMAIN"
    EXPOSES_EMAIL = "EXPOSES_EMAIL"


@dataclass
class Event:
    type: EventType
    value: str
    source_provider: str
    source_url: str | None
    parent_id: str | None
    confidence: float
    depth: int
    tags: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid4().hex)
    retrieved_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


from osintmaster.graph.models import InvestigationGraph as InvestigationGraph  # noqa: E402
