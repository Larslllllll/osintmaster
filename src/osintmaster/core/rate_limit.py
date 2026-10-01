"""Bounded per-host request spacing."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from time import monotonic


class HostRateLimiter:
    def __init__(self, interval: float) -> None:
        self.interval = interval
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._next: dict[str, float] = {}

    async def wait(self, host: str) -> None:
        async with self._locks[host]:
            delay = self._next.get(host, 0) - monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self._next[host] = monotonic() + self.interval
