"""Canonical keys for deduplication; display values remain untouched."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit


def canonicalize(kind: str, value: str, *, platform: str | None = None) -> str:
    kind = kind.upper()
    value = unicodedata.normalize("NFKC", value.strip())
    if not value:
        raise ValueError("Entity value cannot be empty")
    if kind in {"DOMAIN", "HOSTNAME"}:
        return value.rstrip(".").encode("idna").decode("ascii").lower()
    if kind == "EMAIL":
        local, separator, domain = value.rpartition("@")
        if not separator or not local or not domain:
            raise ValueError("Invalid email address")
        return local + "@" + canonicalize("DOMAIN", domain)
    if kind == "IP_ADDRESS" or kind == "IP":
        return str(ipaddress.ip_address(value))
    if kind == "IMAGE" and value.lower().startswith(("http://", "https://")):
        return canonicalize("URL", value)
    if kind in {"URL", "PROFILE", "SOCIAL_PROFILE"}:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Invalid HTTP URL")
        if parsed.username or parsed.password:
            raise ValueError("URLs with credentials are not supported")
        scheme = parsed.scheme.lower()
        host = (
            canonicalize("DOMAIN", parsed.hostname)
            if ":" not in parsed.hostname
            else str(ipaddress.ip_address(parsed.hostname))
        )
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        authority = host + (
            f":{port}" if port and port != {"http": 80, "https": 443}[scheme] else ""
        )
        path = parsed.path or "/"
        if path == "/":
            path = ""
        return urlunsplit((scheme, authority, path, parsed.query, ""))
    if kind == "PHONE":
        compact = re.sub(r"[\s().-]", "", value)
        if not re.fullmatch(r"\+[1-9][0-9]{7,14}", compact):
            raise ValueError("Phone number must be in international E.164 form")
        return compact
    if kind == "USERNAME":
        # Preserve case unless a known platform explicitly defines case-insensitive IDs.
        if platform and platform.lower() in {"github", "gitlab", "codeberg", "bluesky"}:
            return value.casefold()
        return value
    if kind in {"IMAGE_HASH", "CRYPTO_ADDRESS"}:
        return value.lower() if kind == "IMAGE_HASH" else value
    return " ".join(value.split())
