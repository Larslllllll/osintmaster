"""Optional Sherlock adapter. External output is corroboration only."""

from __future__ import annotations

import asyncio
import re
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from osintmaster.core.models import Finding, FindingStatus
from osintmaster.providers.base import ExternalToolProvider
from osintmaster.providers.external import is_profile_url

URL_RE = re.compile(r"https://[^\s\x00-\x1f\]\)<>]+")


class SherlockProvider(ExternalToolProvider):
    name = "Sherlock"

    async def scan(self, username: str, timeout: float) -> list[Finding]:
        executable = shutil.which("sherlock")
        if executable is None:
            return [
                Finding(
                    self.name, username, "", FindingStatus.ERROR, error="Sherlock not installed"
                )
            ]
        with TemporaryDirectory(prefix="osintmaster-sherlock-") as directory:
            output = Path(directory) / "results.txt"
            process = await asyncio.create_subprocess_exec(
                executable,
                username,
                "--print-found",
                "--no-color",
                "--timeout",
                str(timeout),
                "--output",
                str(output),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=directory,
            )
            try:
                stdout, _stderr = await asyncio.wait_for(
                    process.communicate(), max(90, min(300, timeout * 15))
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
                return [
                    Finding(
                        self.name, username, "", FindingStatus.ERROR, error="Sherlock timed out"
                    )
                ]
            if process.returncode != 0:
                return [
                    Finding(
                        self.name,
                        username,
                        "",
                        FindingStatus.ERROR,
                        error=f"Sherlock exited with code {process.returncode}",
                    )
                ]
            content = (
                output.read_text(encoding="utf-8", errors="replace")
                if output.exists()
                else (stdout.decode("utf-8", errors="replace"))
            )
            urls = list(
                dict.fromkeys(
                    url.rstrip(".,")
                    for url in URL_RE.findall(content)
                    if is_profile_url(url.rstrip(".,"), username)
                )
            )[:500]
            return [
                Finding(self.name, username, url.rstrip(".,"), FindingStatus.POSSIBLE)
                for url in urls
            ]
