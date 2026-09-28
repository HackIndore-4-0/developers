"""Token bucket rate limiter for Acunetix REST API calls."""

import asyncio
import time


class AcunetixRateLimiter:
    """Limits outbound API request frequency to avoid overwhelming Acunetix daemon."""

    def __init__(self, rate_per_second: float = 10.0):
        self.rate = rate_per_second
        self.capacity = rate_per_second
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

            if self.tokens < 1.0:
                wait_time = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0
