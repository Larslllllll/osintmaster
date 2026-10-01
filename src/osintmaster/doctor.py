"""Non-mutating local environment checks."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import sys
from pathlib import Path

from osintmaster.config import Config, config_path


def _writable_directory(path: Path) -> bool:
    parent = path if path.exists() else path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    return parent.is_dir() and os.access(parent, os.W_OK)


def doctor_checks(config: Config, *, check_internet: bool = True) -> list[tuple[str, str, str]]:
    checks = [
        (
            "Python",
            platform.python_version(),
            "OK" if sys.version_info >= (3, 10) else "UNSUPPORTED",
        ),
        ("OS", platform.system(), "OK"),
        (
            "Config",
            str(config_path()),
            "OK" if _writable_directory(config_path().parent) else "UNWRITABLE",
        ),
        (
            "Reports",
            str(config.reports_dir),
            "OK" if _writable_directory(config.reports_dir) else "UNWRITABLE",
        ),
    ]
    for tool in ("sherlock", "maigret", "exiftool"):
        executable = shutil.which(tool)
        checks.append((tool, executable or "", "FOUND" if executable else "MISSING"))
    checks.append(
        (
            "API plugins",
            ", ".join(config.plugin_names) or "none",
            "CONFIGURED" if config.plugin_names else "OPTIONAL",
        )
    )
    checks.append(
        (
            "Brave Search API",
            "environment variable",
            "CONFIGURED" if os.getenv("OSINTMASTER_BRAVE_API_KEY") else "OPTIONAL",
        )
    )
    if check_internet:
        try:
            with socket.create_connection(("example.com", 443), timeout=3):
                checks.append(("Internet", "example.com:443", "OK"))
        except OSError:
            checks.append(("Internet", "example.com:443", "UNAVAILABLE"))
    return checks
