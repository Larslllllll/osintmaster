"""Target classification and known-profile URL matching."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from osintmaster.core.normalization import normalize_url, validated_username
from osintmaster.graph.canonicalize import canonicalize
from osintmaster.investigation.models import EventType
from osintmaster.providers.username import Site

EMAIL_RE = re.compile(r"^[^\s@]+@([^\s@]+\.[^\s@]+)$")
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
PHONE_RE = re.compile(r"^\+[1-9][0-9\s().-]{7,20}$")
SPECIAL_SUFFIXES = (".local", ".localhost", ".internal", ".test", ".invalid", ".example")


def _domain(value: str) -> str | None:
    try:
        normalized = canonicalize("DOMAIN", value)
    except (UnicodeError, ValueError):
        return None
    return normalized if DOMAIN_RE.fullmatch(normalized) else None


def classify_target(value: str, forced: EventType | None = None) -> tuple[EventType, str]:
    text = value.strip()
    if not text:
        raise ValueError("Target cannot be empty")
    if forced is None:
        if text.startswith(("https://", "http://")):
            kind = EventType.URL
        elif EMAIL_RE.fullmatch(text):
            kind = EventType.EMAIL
        elif PHONE_RE.fullmatch(text):
            kind = EventType.PHONE
        else:
            try:
                ipaddress.ip_address(text)
                kind = EventType.IP_ADDRESS
            except ValueError:
                if Path(text).is_file():
                    kind = EventType.IMAGE
                elif _domain(text):
                    kind = EventType.DOMAIN
                else:
                    kind = EventType.USERNAME
    else:
        kind = forced
    if kind == EventType.USERNAME:
        return kind, validated_username(text)
    if kind == EventType.URL:
        return kind, normalize_url(text)
    if kind == EventType.EMAIL:
        if not EMAIL_RE.fullmatch(text):
            raise ValueError("Invalid email address")
        domain = _domain(text.rpartition("@")[2])
        if domain is None:
            raise ValueError("Invalid email domain")
        return kind, canonicalize("EMAIL", text)
    if kind == EventType.DOMAIN:
        domain = _domain(text)
        if domain is None:
            raise ValueError("Invalid domain")
        return kind, domain
    if kind == EventType.IP_ADDRESS:
        return kind, str(ipaddress.ip_address(text))
    if kind == EventType.IMAGE:
        image = Path(text).expanduser().resolve()
        if not image.is_file():
            raise ValueError("Local image does not exist")
        return kind, str(image)
    if kind == EventType.PHONE:
        return kind, canonicalize("PHONE", text)
    raise ValueError(f"Unsupported target type: {kind}")


def domain_from_url(value: str) -> str | None:
    try:
        hostname = urlsplit(value).hostname
    except ValueError:
        return None
    return _domain(hostname) if hostname else None


def public_dns_domain(value: str) -> bool:
    return bool(_domain(value)) and not value.endswith(SPECIAL_SUFFIXES)


def match_profile_url(value: str, sites: list[Site]) -> tuple[Site, str] | None:
    for site in sites:
        pattern = (
            "^"
            + re.escape(site.url)
            .replace(re.escape("{username}"), r"(?P<username>[^/?#]+)")
            .rstrip("/")
            + "/?$"
        )
        match = re.fullmatch(pattern, value, flags=re.IGNORECASE)
        if match:
            try:
                return site, validated_username(unquote(match.group("username")))
            except ValueError:
                return None
    return None
