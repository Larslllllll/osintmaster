"""Shared hard budget for built-in network operations."""

from __future__ import annotations

import asyncio


class RequestBudget:
    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError("Request limit cannot be negative")
        self.limit = limit
        self.used = 0
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            if self.used >= self.limit:
                return False
            self.used += 1
            return True
