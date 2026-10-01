"""Search query generation and a plugin-facing search interface."""

from __future__ import annotations

from osintmaster.providers.base import SearchProvider

DOMAINS = ("github.com", "reddit.com", "instagram.com", "tiktok.com", "youtube.com")


def generate_dorks(query: str) -> list[str]:
    clean = " ".join(query.strip().split())
    if not clean or len(clean) > 200:
        raise ValueError("Query must contain 1-200 characters")
    quoted = '"' + clean.replace('"', "") + '"'
    result = [quoted]
    result.extend(f"site:{domain} {quoted}" for domain in DOMAINS)
    result.extend(f"{quoted} {domain.split('.')[0]}" for domain in DOMAINS[:3])
    return result


__all__ = ["SearchProvider", "generate_dorks"]
