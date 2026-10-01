"""Validation of optional external-tool profile URLs."""

from __future__ import annotations

import ipaddress
from urllib.parse import unquote, urlsplit

UNRELIABLE_HOSTS = {"reddit.com", "www.reddit.com"}
PROFILE_PREFIXES = {"u", "user", "users", "member", "members", "profile", "profiles"}


def is_profile_url(url: str, username: str) -> bool:
    try:
        parsed = urlsplit(url)
        parts = [unquote(part) for part in parsed.path.split("/") if part]
        host = parsed.hostname
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username
            or parsed.password
            or parsed.port not in {None, 443}
            or parsed.query
            or parsed.fragment
            or host in UNRELIABLE_HOSTS
            or host in {"localhost", "localhost.localdomain"}
            or host.endswith((".local", ".localhost", ".internal"))
        ):
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not address.is_global:
                return False
        if len(parts) == 1:
            return parts[0].lstrip("@~").casefold() == username.casefold()
        if len(parts) == 2 and parts[0].casefold() in PROFILE_PREFIXES:
            return parts[1].lstrip("@~").casefold() == username.casefold()
        if not parts and len(host.split(".")) >= 3:
            return host.split(".")[0].casefold() == username.casefold()
        return False
    except ValueError:
        return False
