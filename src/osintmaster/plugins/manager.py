"""Entry-point discovery without eagerly importing third-party code."""

from __future__ import annotations

import os
import shutil
from importlib.metadata import EntryPoint, entry_points
from typing import cast

from osintmaster.config import Config
from osintmaster.investigation.models import EventType
from osintmaster.investigation.providers import EventProvider, ProviderActivity, ProviderCost
from osintmaster.providers.base import ExternalToolProvider, SearchProvider, UsernameProvider
from osintmaster.providers.maigret import MaigretProvider
from osintmaster.providers.sherlock import SherlockProvider
from osintmaster.providers.username import load_sites

ENTRY_POINT_GROUP = "osintmaster.plugins"


def installed_plugins() -> list[EntryPoint]:
    return list(entry_points(group=ENTRY_POINT_GROUP))


def load_plugins(config: Config) -> tuple[list[UsernameProvider], list[SearchProvider], list[str]]:
    available = {point.name: point for point in installed_plugins()}
    usernames: list[UsernameProvider] = []
    searches: list[SearchProvider] = []
    errors: list[str] = []
    for name in config.plugin_names:
        point = available.get(name)
        if point is None:
            errors.append(f"Plugin {name}: not installed")
            continue
        try:
            entry = point.load()
            instance = entry() if isinstance(entry, type) else entry
        except Exception:
            errors.append(f"Plugin {name}: failed to load")
            continue
        if not isinstance(getattr(instance, "name", None), str) or not instance.name:
            errors.append(f"Plugin {name}: missing provider name")
            continue
        if isinstance(instance, UsernameProvider):
            usernames.append(instance)
        elif isinstance(instance, SearchProvider):
            searches.append(instance)
        else:
            errors.append(f"Plugin {name}: unsupported provider interface")
    return usernames, searches, errors


def load_event_plugins(config: Config) -> tuple[list[EventProvider], list[str]]:
    """Load enabled event providers; leave legacy plugin types to their commands."""
    available = {point.name: point for point in installed_plugins()}
    providers: list[EventProvider] = []
    errors: list[str] = []
    for name in config.plugin_names:
        point = available.get(name)
        if point is None:
            errors.append(f"Plugin {name}: not installed")
            continue
        try:
            entry = point.load()
            instance = entry() if isinstance(entry, type) else entry
        except Exception:
            errors.append(f"Plugin {name}: failed to load")
            continue
        if isinstance(instance, (UsernameProvider, SearchProvider)):
            continue
        if (
            not isinstance(getattr(instance, "name", None), str)
            or not instance.name
            or not isinstance(getattr(instance, "accepts", None), frozenset)
            or not all(isinstance(item, EventType) for item in instance.accepts)
            or not isinstance(getattr(instance, "produces", None), frozenset)
            or not all(isinstance(item, EventType) for item in instance.produces)
            or not isinstance(getattr(instance, "cost", None), ProviderCost)
            or not isinstance(getattr(instance, "activity", None), ProviderActivity)
            or not callable(getattr(instance, "run", None))
        ):
            errors.append(f"Plugin {name}: unsupported event provider interface")
            continue
        providers.append(cast(EventProvider, instance))
    return providers, errors


def external_providers(config: Config) -> list[ExternalToolProvider]:
    providers: list[ExternalToolProvider] = []
    if config.sherlock:
        providers.append(SherlockProvider())
    if config.maigret:
        providers.append(MaigretProvider())
    return providers


def plugin_status(config: Config) -> list[tuple[str, str]]:
    result = [(site.name, "enabled") for site in load_sites()]
    for name in ("sherlock", "maigret", "exiftool"):
        found = shutil.which(name) is not None
        enabled = getattr(config, name, False)
        status = "enabled" if found and enabled else "detected" if found else "not installed"
        result.append((name, status))
    result.append(
        (
            "Brave Search",
            "configured" if os.getenv("OSINTMASTER_BRAVE_API_KEY") else "not configured",
        )
    )
    result.extend(
        (point.name, "enabled" if point.name in config.plugin_names else "installed")
        for point in installed_plugins()
    )
    return result
