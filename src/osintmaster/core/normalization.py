"""Conservative normalization of public text and URLs."""

from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

TRACKING_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid", "igshid"}


def normalize_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def validated_username(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip()
    if (
        not normalized
        or len(normalized) > 64
        or not re.fullmatch(r"[\w.\-]+", normalized, re.UNICODE)
    ):
        raise ValueError(
            "Username must contain 1-64 letters, numbers, dots, underscores or hyphens"
        )
    if normalized in {".", ".."}:
        raise ValueError("Invalid username")
    return normalized


def normalize_username(value: str) -> str:
    return validated_username(value).casefold()


def username_variants(value: str) -> list[str]:
    base = normalize_username(value)
    parts = [part for part in re.split(r"[._-]+", base) if part]
    result = [base]
    if len(parts) == 2 and all(len(part) >= 2 for part in parts):
        first, last = parts
        result.extend(
            [
                first + last,
                first + "_" + last,
                first + "." + last,
                first + "-" + last,
                first[0] + last,
                last + first,
            ]
        )
    return list(dict.fromkeys(result))[:7]


def normalize_url(value: str) -> str:
    value = value.strip()
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs can be normalized")
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    port = parsed.port
    if (
        port
        and not (parsed.scheme == "http" and port == 80)
        and not (parsed.scheme == "https" and port == 443)
    ):
        hostname += f":{port}"
    path = quote(parsed.path.rstrip("/") or "/", safe="/%:@-._~")
    query = urlencode(
        sorted(
            (key, val)
            for key, val in parse_qsl(parsed.query, keep_blank_values=True)
            if not key.lower().startswith("utm_") and key.lower() not in TRACKING_KEYS
        )
    )
    return urlunsplit((parsed.scheme.lower(), hostname, path, query, ""))


def similarity(left: str, right: str) -> float:
    a, b = normalize_text(left), normalize_text(right)
    return SequenceMatcher(None, a, b).ratio() if a and b else 0.0
