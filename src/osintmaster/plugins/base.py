"""Public plugin interfaces."""

from __future__ import annotations

from abc import abstractmethod
from pathlib import Path
from typing import Any

from osintmaster.providers.base import (
    BaseProvider,
    ExternalToolProvider,
    SearchProvider,
    UsernameProvider,
)


class MetadataProvider(BaseProvider):
    @abstractmethod
    def analyze(self, path: Path) -> dict[str, Any]:
        """Analyze one local file."""


class ReportProvider(BaseProvider):
    @abstractmethod
    def render(self, report: dict[str, Any]) -> str:
        """Render a report without writing it."""


__all__ = [
    "BaseProvider",
    "ExternalToolProvider",
    "MetadataProvider",
    "ReportProvider",
    "SearchProvider",
    "UsernameProvider",
]
