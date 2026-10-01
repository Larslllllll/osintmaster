"""Registry-driven public profile checks and minimal HTML metadata parsing."""

from __future__ import annotations

import json
from dataclasses import dataclass
from html.parser import HTMLParser
from importlib.resources import files
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import httpx

from osintmaster.core.models import Evidence, Finding, FindingStatus, Profile
from osintmaster.core.normalization import normalize_text
from osintmaster.providers.base import UsernameProvider


@dataclass(frozen=True)
class Site:
    name: str
    url: str
    category: str
    expected_status: tuple[int, ...]
    not_found_status: tuple[int, ...]
    positive_markers: tuple[str, ...] = ()
    negative_markers: tuple[str, ...] = ()
    api_url: str | None = None
    api_kind: str | None = None
    page_kind: str | None = None
    check_url: str | None = None
    positive_code: int | None = None
    negative_code: int | None = None
    positive_marker: str | None = None
    negative_marker: str | None = None
    known_positive: tuple[str, ...] = ()
    health: str | None = None
    last_tested: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Site:
        url = str(data["url"])
        if url.count("{username}") != 1 or urlsplit(url).scheme != "https":
            raise ValueError("Site URL must be HTTPS and contain one username placeholder")
        api_url = data.get("api_url")
        api_kind = data.get("api_kind")
        if api_url is not None and (
            not isinstance(api_url, str)
            or api_url.count("{username}") != 1
            or urlsplit(api_url).scheme != "https"
        ):
            raise ValueError("API URL must be HTTPS and contain one username placeholder")
        if (api_url is None) != (api_kind is None) or api_kind not in {
            None,
            "github",
            "gitlab",
            "codeberg",
            "devto",
            "hackernews",
            "bluesky",
        }:
            raise ValueError("Site API kind is invalid")
        page_kind = data.get("page_kind")
        if page_kind not in {None, "telegram", "catalog"} or (page_kind and api_kind):
            raise ValueError("Site page kind is invalid")
        check_url = data.get("check_url")
        if page_kind == "catalog":
            if (
                not isinstance(check_url, str)
                or check_url.count("{username}") != 1
                or urlsplit(check_url).scheme != "https"
                or not isinstance(data.get("positive_marker"), str)
                or not data["positive_marker"]
                or not isinstance(data.get("negative_marker"), str)
                or not isinstance(data.get("positive_code"), int)
                or not isinstance(data.get("negative_code"), int)
                or data.get("health") not in {"HEALTHY", "DEGRADED", "BROKEN", "BLOCKED", "UNKNOWN"}
            ):
                raise ValueError("Catalog site rule is invalid")
        elif check_url is not None:
            raise ValueError("Only catalog sites may define a check URL")
        return cls(
            name=str(data["name"]),
            url=url,
            category=str(data["category"]),
            expected_status=tuple(data.get("expected_status", [200])),
            not_found_status=tuple(data.get("not_found_status", [404])),
            positive_markers=tuple(data.get("positive_markers", [])),
            negative_markers=tuple(data.get("negative_markers", [])),
            api_url=api_url,
            api_kind=api_kind,
            page_kind=page_kind,
            check_url=check_url,
            positive_code=data.get("positive_code"),
            negative_code=data.get("negative_code"),
            positive_marker=data.get("positive_marker"),
            negative_marker=data.get("negative_marker"),
            known_positive=tuple(data.get("known_positive", [])),
            health=data.get("health"),
            last_tested=data.get("last_tested"),
        )

    def profile_url(self, username: str) -> str:
        return self.url.replace("{username}", quote(username, safe=""))

    def request_url(self, username: str) -> str:
        return (self.check_url or self.api_url or self.url).replace(
            "{username}", quote(username, safe="")
        )


def load_sites(*, wide: bool = False) -> list[Site]:
    content = files("osintmaster.data").joinpath("sites.json").read_text(encoding="utf-8")
    sites = [Site.from_dict(item) for item in json.loads(content)]
    if wide:
        catalog = files("osintmaster.data").joinpath("wmn_catalog.json").read_text(encoding="utf-8")
        sites.extend(Site.from_dict(item) for item in json.loads(catalog)["sites"])
    return sites


class ProfileParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.links: list[str] = []
        self.all_links: list[str] = []
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.canonical: str | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "meta":
            key = values.get("property") or values.get("name")
            content = values.get("content")
            if key and content:
                self.meta[key.lower()] = content.strip()
        elif tag == "a" and values.get("href") and "me" in (values.get("rel") or "").split():
            self.links.append(values["href"] or "")
        if tag == "a" and values.get("href"):
            self.all_links.append(values["href"] or "")
        if tag == "link" and "canonical" in (values.get("rel") or "").split():
            self.canonical = values.get("href")
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        self.text_parts.append(data)
        if self._in_title:
            self.title_parts.append(data)


class TelegramPageParser(HTMLParser):
    """Read only Telegram's public preview fields, without executing page scripts."""

    FIELDS = {
        "tgme_page_title",
        "tgme_page_extra",
        "tgme_page_description",
        "tgme_page_action",
        "tgme_page_context_link",
    }
    VOID = {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, list[str]] = {name: [] for name in self.FIELDS}
        self.description_links: list[str] = []
        self._active: list[set[str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = set((values.get("class") or "").split())
        active = (self._active[-1] if self._active else set()) | (classes & self.FIELDS)
        if "verified-icon" in classes:
            active = set()
        if "tgme_page_description" in active and tag == "a" and values.get("href"):
            self.description_links.append(values["href"] or "")
        if tag not in self.VOID:
            self._active.append(active)

    def handle_endtag(self, tag: str) -> None:
        if tag not in self.VOID and self._active:
            self._active.pop()

    def handle_data(self, data: str) -> None:
        if self._active:
            for name in self._active[-1]:
                self.fields[name].append(data)

    def value(self, name: str) -> str:
        return " ".join(" ".join(self.fields[name]).split())


def telegram_profile(
    body: str, username: str, url: str
) -> tuple[FindingStatus, Profile, list[Evidence]]:
    """A generic 200/Contact page is not evidence of an existing account."""
    generic = ProfileParser()
    generic.feed(body)
    page = TelegramPageParser()
    page.feed(body)
    title = " ".join(generic.title_parts).strip()
    exact_title = title.casefold() == f"telegram: view @{username}".casefold()
    display_name = page.value("tgme_page_title")
    if not exact_title or not display_name:
        return FindingStatus.UNKNOWN, Profile(), []

    extra = page.value("tgme_page_extra").casefold()
    context = page.value("tgme_page_context_link").casefold()
    action = page.value("tgme_page_action").casefold()
    if "subscribers" in extra or "preview channel" in context:
        account_type = "CHANNEL"
    elif "members" in extra or "preview group" in context:
        account_type = "GROUP"
    elif "send message" in action:
        account_type = "USER"
    else:
        account_type = "UNKNOWN"
    links: list[str] = []
    for href in page.description_links:
        try:
            absolute = urljoin(url, href)
            parsed = urlsplit(absolute)
        except ValueError:
            continue
        if parsed.scheme == "https" and parsed.hostname not in {"t.me", "telegram.org"}:
            if absolute not in links:
                links.append(absolute)
    image = generic.meta.get("og:image")
    profile = Profile(
        display_name=display_name,
        bio=page.value("tgme_page_description") or generic.meta.get("og:description"),
        links=links[:20],
        image_url=image if image and urlsplit(image).scheme == "https" else None,
        account_type=account_type,
    )
    evidence = [
        Evidence("telegram_public_preview", f"Exact public preview for @{username}", 0, url)
    ]
    return FindingStatus.CONFIRMED, profile, evidence


def detect_status(site: Site, status_code: int, body: str) -> FindingStatus:
    if status_code == 429:
        return FindingStatus.RATE_LIMITED
    if status_code == 401:
        return FindingStatus.AUTH_REQUIRED
    if status_code in {403, 451}:
        return FindingStatus.BLOCKED
    if status_code in site.not_found_status:
        return FindingStatus.NOT_FOUND
    if status_code not in site.expected_status:
        return FindingStatus.UNKNOWN if status_code < 500 else FindingStatus.ERROR
    normalized = normalize_text(body)
    if any(normalize_text(marker) in normalized for marker in site.negative_markers):
        return FindingStatus.NOT_FOUND
    if site.positive_markers and any(
        normalize_text(marker) in normalized for marker in site.positive_markers
    ):
        return FindingStatus.CONFIRMED
    # A successful HTTP response without identity evidence can be a generic page,
    # login wall or soft 404. It must not become an active profile lead.
    return FindingStatus.UNKNOWN


def extract_profile(body: str, profile_url: str) -> Profile:
    parser = ProfileParser()
    parser.feed(body)
    title = parser.meta.get("og:title") or " ".join(parser.title_parts).strip()
    bio = parser.meta.get("og:description") or parser.meta.get("description")
    hostname = urlsplit(profile_url).hostname
    links = []
    for href in parser.links:
        try:
            absolute = urljoin(profile_url, href)
            parsed = urlsplit(absolute)
        except ValueError:
            continue
        if parsed.scheme == "https" and parsed.hostname != hostname and absolute not in links:
            links.append(absolute)
    image = parser.meta.get("og:image")
    return Profile(display_name=title or None, bio=bio, links=links[:20], image_url=image)


def _field(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _public_link(value: str | None) -> str | None:
    if not value:
        return None
    if value.startswith(("/", "\\")) or (":" in value and "://" not in value):
        return None
    candidate = value if "://" in value else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    return candidate if parsed.scheme in {"http", "https"} and parsed.hostname else None


def _api_profile(site: Site, data: Any, username: str) -> tuple[FindingStatus, Profile, str | None]:
    kind = site.api_kind
    if kind is None:
        return FindingStatus.UNKNOWN, Profile(), None
    if kind == "gitlab":
        if not isinstance(data, list):
            return FindingStatus.UNKNOWN, Profile(), None
        matches = [
            item
            for item in data
            if isinstance(item, dict)
            and str(item.get("username", "")).casefold() == username.casefold()
        ]
        if not matches:
            return FindingStatus.NOT_FOUND, Profile(), None
        data = matches[0]
    elif kind == "hackernews" and data is None:
        return FindingStatus.NOT_FOUND, Profile(), None
    if not isinstance(data, dict):
        return FindingStatus.UNKNOWN, Profile(), None
    key = {
        "github": "login",
        "gitlab": "username",
        "codeberg": "login",
        "devto": "username",
        "hackernews": "id",
        "bluesky": "handle",
    }.get(kind)
    if key is None:
        return FindingStatus.UNKNOWN, Profile(), None
    actual = _field(data, key)
    expected = f"{username}.bsky.social" if kind == "bluesky" else username
    if kind == "hackernews":
        exact = actual == expected  # Hacker News IDs are case-sensitive.
    else:
        exact = actual is not None and actual.casefold() == expected.casefold()
    if not exact:
        return FindingStatus.UNKNOWN, Profile(), None

    name_key = {
        "github": "name",
        "gitlab": "name",
        "codeberg": "full_name",
        "devto": "name",
        "bluesky": "displayName",
    }.get(kind)
    bio_key = {
        "github": "bio",
        "gitlab": "bio",
        "codeberg": "description",
        "devto": "summary",
        "bluesky": "description",
    }.get(kind)
    image_key = {
        "github": "avatar_url",
        "gitlab": "avatar_url",
        "codeberg": "avatar_url",
        "devto": "profile_image",
        "bluesky": "avatar",
    }.get(kind)
    link_key = {
        "github": "blog",
        "gitlab": "website_url",
        "codeberg": "website",
        "devto": "website_url",
    }.get(kind)
    links = []
    link = _public_link(_field(data, link_key)) if link_key else None
    if link:
        links.append(link)
    bio = _field(data, bio_key) if bio_key else None
    if kind == "hackernews":
        parser = ProfileParser()
        parser.feed(_field(data, "about") or "")
        bio = " ".join(" ".join(parser.text_parts).split()) or None
        for href in parser.all_links:
            link = _public_link(href)
            if link and link not in links:
                links.append(link)
    raw_platform_id = data.get("did" if kind == "bluesky" else "id")
    platform_id = (
        str(raw_platform_id)
        if isinstance(raw_platform_id, (str, int))
        and not isinstance(raw_platform_id, bool)
        and str(raw_platform_id).strip()
        else None
    )
    return (
        FindingStatus.CONFIRMED,
        Profile(
            display_name=_field(data, name_key) if name_key else None,
            bio=bio,
            links=links[:20],
            image_url=_field(data, image_key) if image_key else None,
            location=_field(data, "location"),
            platform_id=platform_id,
        ),
        actual,
    )


class RegistryUsernameProvider(UsernameProvider):
    def __init__(self, site: Site) -> None:
        self.site = site
        self.name = site.name

    async def check(self, username: str, client: httpx.AsyncClient) -> Finding:
        url = self.site.profile_url(username)
        request_url = self.site.request_url(username)
        try:
            async with client.stream("GET", request_url, follow_redirects=False) as response:
                if response.status_code == 429 or (
                    response.status_code == 403
                    and response.headers.get("x-ratelimit-remaining") == "0"
                ):
                    return Finding(
                        self.name,
                        username,
                        url,
                        FindingStatus.RATE_LIMITED,
                        error=f"HTTP {response.status_code} rate limit",
                        http_status=response.status_code,
                    )
                if response.status_code in {401, 403, 451}:
                    return Finding(
                        self.name,
                        username,
                        url,
                        FindingStatus.AUTH_REQUIRED
                        if response.status_code == 401
                        else FindingStatus.BLOCKED,
                        evidence=[
                            Evidence(
                                "http_access_denied",
                                f"HTTP {response.status_code} refused the profile request",
                                0,
                                request_url,
                            )
                        ],
                        error=f"HTTP {response.status_code} refused access; account state unverified",
                        http_status=response.status_code,
                    )
                length = response.headers.get("content-length", "")
                if length.isdecimal() and int(length) > 1_000_000:
                    return Finding(
                        self.name, username, url, FindingStatus.UNKNOWN, error="Page too large"
                    )
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > 1_000_000:
                        return Finding(
                            self.name, username, url, FindingStatus.UNKNOWN, error="Page too large"
                        )
                    content.extend(chunk)
        except httpx.TimeoutException:
            return Finding(self.name, username, url, FindingStatus.ERROR, error="Request timed out")
        except httpx.RequestError:
            return Finding(
                self.name, username, url, FindingStatus.ERROR, error="Network request failed"
            )
        body = bytes(content)
        page_text = body.decode(response.encoding or "utf-8", errors="replace")
        if urlsplit(str(response.url)).hostname != urlsplit(request_url).hostname:
            return Finding(
                self.name,
                username,
                url,
                FindingStatus.UNKNOWN,
                error="Profile request redirected to another host",
                http_status=response.status_code,
            )
        if self.site.api_kind:
            if self.site.api_kind == "bluesky" and response.status_code == 400:
                try:
                    error_payload = json.loads(body)
                except ValueError:
                    error_payload = None
                if isinstance(error_payload, dict) and (
                    error_payload.get("error") == "InvalidRequest"
                    and error_payload.get("message") == "Profile not found"
                ):
                    return Finding(
                        self.name,
                        username,
                        url,
                        FindingStatus.NOT_FOUND,
                        evidence=[
                            Evidence(
                                "api_not_found",
                                "Public API reported profile not found",
                                0,
                                request_url,
                            )
                        ],
                        http_status=response.status_code,
                    )
            if response.status_code == 404:
                return Finding(
                    self.name,
                    username,
                    url,
                    FindingStatus.NOT_FOUND,
                    evidence=[
                        Evidence("api_not_found", "Public API returned HTTP 404", 0, request_url)
                    ],
                    http_status=response.status_code,
                )
            if response.status_code != 200:
                status = (
                    FindingStatus.ERROR if response.status_code >= 500 else FindingStatus.UNKNOWN
                )
                return Finding(
                    self.name,
                    username,
                    url,
                    status,
                    error=f"API returned HTTP {response.status_code}",
                    http_status=response.status_code,
                )
            try:
                payload = json.loads(body)
            except ValueError:
                return Finding(
                    self.name,
                    username,
                    url,
                    FindingStatus.UNKNOWN,
                    error="API returned invalid JSON",
                    http_status=response.status_code,
                )
            status, profile, actual = _api_profile(self.site, payload, username)
            evidence = (
                [
                    Evidence(
                        "api_username",
                        f"Public API returned exact username: {actual}",
                        0,
                        request_url,
                    )
                ]
                if status == FindingStatus.CONFIRMED
                else []
            )
            if status == FindingStatus.NOT_FOUND:
                evidence = [
                    Evidence(
                        "api_not_found", "Public API returned no matching account", 0, request_url
                    )
                ]
            return Finding(
                self.name,
                username,
                url,
                status,
                profile,
                evidence,
                error=(
                    "API response did not verify requested username"
                    if status == FindingStatus.UNKNOWN
                    else None
                ),
                http_status=response.status_code,
            )
        if self.site.page_kind == "catalog":
            positive_marker = self.site.positive_marker or ""
            negative_marker = self.site.negative_marker or ""
            positive = (
                response.status_code == self.site.positive_code
                and bool(positive_marker)
                and positive_marker in page_text
                and (not negative_marker or negative_marker not in page_text)
            )
            negative = (
                response.status_code == self.site.negative_code
                and (not negative_marker or negative_marker in page_text)
                and (not positive_marker or positive_marker not in page_text)
            )
            if positive and not negative:
                return Finding(
                    self.name,
                    username,
                    url,
                    FindingStatus.PROBABLE,
                    evidence=[
                        Evidence(
                            "catalog_positive_marker",
                            f"Matched public response marker: {positive_marker[:120]}",
                            0,
                            request_url,
                        )
                    ],
                    http_status=response.status_code,
                )
            if negative and not positive:
                return Finding(
                    self.name,
                    username,
                    url,
                    FindingStatus.NOT_FOUND,
                    evidence=[
                        Evidence(
                            "catalog_negative_marker"
                            if negative_marker
                            else "catalog_http_not_found",
                            "Public response matched the missing-account rule"
                            if negative_marker
                            else f"Public response returned HTTP {response.status_code}",
                            0,
                            request_url,
                        )
                    ],
                    http_status=response.status_code,
                )
            return Finding(
                self.name,
                username,
                url,
                FindingStatus.ERROR if response.status_code >= 500 else FindingStatus.UNKNOWN,
                error="Catalog rule did not resolve account state",
                http_status=response.status_code,
            )
        requested = urlsplit(url)
        final = urlsplit(str(response.url))
        if (
            final.scheme != "https"
            or final.hostname != requested.hostname
            or final.path.rstrip("/") != requested.path.rstrip("/")
        ):
            return Finding(
                self.name,
                username,
                url,
                FindingStatus.UNKNOWN,
                error="Profile request redirected to another page",
                http_status=response.status_code,
            )
        if self.site.page_kind == "telegram":
            if response.status_code != 200:
                status = (
                    FindingStatus.ERROR if response.status_code >= 500 else FindingStatus.UNKNOWN
                )
                return Finding(
                    self.name,
                    username,
                    url,
                    status,
                    error=f"Public preview returned HTTP {response.status_code}",
                    http_status=response.status_code,
                )
            status, profile, evidence = telegram_profile(page_text, username, url)
            return Finding(
                self.name,
                username,
                url,
                status,
                profile,
                evidence,
                error=(
                    "Public preview did not verify requested account"
                    if status == FindingStatus.UNKNOWN
                    else None
                ),
                http_status=response.status_code,
            )
        status = detect_status(self.site, response.status_code, page_text)
        if status == FindingStatus.CONFIRMED:
            parser = ProfileParser()
            parser.feed(page_text)
            canonical = parser.canonical or parser.meta.get("og:url")
            if canonical:
                parsed = urlsplit(urljoin(url, canonical))
                if parsed.hostname != requested.hostname or parsed.path.rstrip(
                    "/"
                ) != requested.path.rstrip("/"):
                    status = FindingStatus.UNKNOWN
            else:
                status = FindingStatus.UNKNOWN
        profile = (
            extract_profile(page_text, url)
            if status in {FindingStatus.CONFIRMED, FindingStatus.POSSIBLE}
            and "html" in response.headers.get("content-type", "").lower()
            else Profile()
        )
        evidence = []
        if status == FindingStatus.CONFIRMED:
            evidence.append(
                Evidence("profile_marker", "Profile marker and canonical URL match", 0, url)
            )
        elif status == FindingStatus.POSSIBLE:
            evidence.append(
                Evidence(
                    "http_status", "Public page returned success status; profile unverified", 0, url
                )
            )
        elif status == FindingStatus.NOT_FOUND:
            evidence.append(
                Evidence("profile_not_found", "Provider returned absence status or marker", 0, url)
            )
        return Finding(
            self.name,
            username,
            url,
            status,
            profile,
            evidence,
            error=(
                "Public page did not provide matching account evidence"
                if status == FindingStatus.UNKNOWN
                else None
            ),
            http_status=response.status_code,
        )
