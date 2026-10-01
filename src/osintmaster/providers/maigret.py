"""Optional Maigret adapter using its NDJSON export."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from osintmaster.core.models import Finding, FindingStatus
from osintmaster.providers.base import ExternalToolProvider
from osintmaster.providers.external import is_profile_url


def _result_url(item: dict[str, Any]) -> str | None:
    for key in ("url", "profile_url", "url_user"):
        url = item.get(key)
        if isinstance(url, str) and url.startswith("https://"):
            return url
    return None


class MaigretProvider(ExternalToolProvider):
    name = "Maigret"

    async def scan(self, username: str, timeout: float) -> list[Finding]:
        executable = shutil.which("maigret")
        if executable is None:
            return [
                Finding(self.name, username, "", FindingStatus.ERROR, error="Maigret not installed")
            ]
        with TemporaryDirectory(prefix="osintmaster-maigret-") as directory:
            report_path = Path(directory) / f"report_{username}_ndjson.json"
            process = await asyncio.create_subprocess_exec(
                executable,
                username,
                "--json",
                "ndjson",
                "--timeout",
                str(timeout),
                "--folderoutput",
                directory,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=directory,
            )
            try:
                _stdout, _stderr = await asyncio.wait_for(
                    process.communicate(), max(90, min(300, timeout * 15))
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                return [
                    Finding(self.name, username, "", FindingStatus.ERROR, error="Maigret timed out")
                ]
            if process.returncode != 0:
                return [
                    Finding(
                        self.name,
                        username,
                        "",
                        FindingStatus.ERROR,
                        error=f"Maigret exited with code {process.returncode}",
                    )
                ]
            if not report_path.is_file():
                return [
                    Finding(
                        self.name,
                        username,
                        "",
                        FindingStatus.ERROR,
                        error="Maigret JSON report missing",
                    )
                ]
            content = report_path.read_text(encoding="utf-8", errors="replace")
        findings = []
        rejected = 0
        for line in content.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                rejected += 1
                continue
            if not isinstance(item, dict):
                rejected += 1
                continue
            if item.get("is_similar") is True:
                continue
            status = item.get("status")
            reported_username = status.get("username") if isinstance(status, dict) else None
            if (
                not isinstance(status, dict)
                or status.get("status") != "Claimed"
                or not isinstance(reported_username, str)
                or reported_username.casefold() != username.casefold()
            ):
                rejected += 1
                continue
            url = _result_url(item)
            if url and is_profile_url(url, username):
                findings.append(Finding(self.name, username, url, FindingStatus.POSSIBLE))
            else:
                rejected += 1
        if rejected:
            return findings[:499] + [
                Finding(
                    self.name,
                    username,
                    "",
                    FindingStatus.ERROR,
                    error=f"Maigret report contained {rejected} invalid or unverified record(s)",
                )
            ]
        return findings[:500]
