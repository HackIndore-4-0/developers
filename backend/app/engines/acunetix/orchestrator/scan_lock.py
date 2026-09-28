"""Distributed scan lock and queue concurrency limiter."""

import asyncio


class AcunetixScanLock:
    """Throttles maximum active concurrent scan jobs on Acunetix engine."""

    def __init__(self, max_concurrent: int = 3):
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def acquire(self):
        await self.semaphore.acquire()

    def release(self):
        self.semaphore.release()
