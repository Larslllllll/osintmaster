"""User configuration stored outside the repository."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from platformdirs import user_config_dir, user_data_dir

from osintmaster.constants import (
    DEFAULT_CONCURRENCY,
    DEFAULT_HOST_INTERVAL,
    DEFAULT_PER_HOST,
    DEFAULT_TIMEOUT,
)

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]


def config_path() -> Path:
    return Path(user_config_dir("osintmaster", appauthor=False, roaming=True)) / "config.toml"


def default_reports_dir() -> Path:
    return Path(user_data_dir("osintmaster", appauthor=False)) / "reports"


@dataclass
class Config:
    timeout: float = DEFAULT_TIMEOUT
    max_concurrency: int = DEFAULT_CONCURRENCY
    per_host_concurrency: int = DEFAULT_PER_HOST
    host_interval: float = DEFAULT_HOST_INTERVAL
    reports_dir: Path = field(default_factory=default_reports_dir)
    sherlock: bool = False
    maigret: bool = False
    plugin_names: tuple[str, ...] = ()

    def validate(self) -> None:
        if not 0.5 <= self.timeout <= 120:
            raise ValueError("timeout must be between 0.5 and 120 seconds")
        if not 1 <= self.max_concurrency <= 20:
            raise ValueError("max_concurrency must be between 1 and 20")
        if not 1 <= self.per_host_concurrency <= 5:
            raise ValueError("per_host_concurrency must be between 1 and 5")
        if not 0 <= self.host_interval <= 60:
            raise ValueError("host_interval must be between 0 and 60 seconds")


def load_config(path: Path | None = None) -> Config:
    location = path or config_path()
    raw: dict[str, Any] = {}
    if location.is_file():
        try:
            with location.open("rb") as handle:
                raw = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError("Invalid TOML configuration") from exc
    provider = raw.get("providers", {})
    if not isinstance(provider, dict):
        raise ValueError("[providers] must be a TOML table")
    if not all(isinstance(provider.get(name, False), bool) for name in ("sherlock", "maigret")):
        raise ValueError("provider flags must be booleans")
    plugins = raw.get("plugins", {})
    if (
        not isinstance(plugins, dict)
        or not isinstance(plugins.get("enabled", []), list)
        or not all(isinstance(name, str) and name for name in plugins.get("enabled", []))
    ):
        raise ValueError("[plugins].enabled must be a list of names")
    if len(plugins.get("enabled", [])) > 20:
        raise ValueError("At most 20 plugins can be enabled")
    reports = raw.get("reports_dir")
    if reports is not None:
        reports = Path(os.path.expandvars(str(reports))).expanduser()
        if not reports.is_absolute():
            reports = location.parent / reports
    config = Config(
        timeout=float(os.getenv("OSINTMASTER_TIMEOUT", raw.get("timeout", DEFAULT_TIMEOUT))),
        max_concurrency=int(raw.get("max_concurrency", DEFAULT_CONCURRENCY)),
        per_host_concurrency=int(raw.get("per_host_concurrency", DEFAULT_PER_HOST)),
        host_interval=float(raw.get("host_interval", DEFAULT_HOST_INTERVAL)),
        reports_dir=reports or default_reports_dir(),
        sherlock=provider.get("sherlock", False),
        maigret=provider.get("maigret", False),
        plugin_names=tuple(plugins.get("enabled", [])),
    )
    config.validate()
    return config
