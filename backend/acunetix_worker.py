"""Background worker daemon for continuous Acunetix scan management."""

import asyncio
from app.engines.acunetix.client import AcunetixClient


async def worker_loop():
    print("[Acunetix Worker] Starting background scan worker...")
    client = AcunetixClient()
    try:
        while True:
            # Poll every 60 seconds
            await asyncio.sleep(60)
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(worker_loop())
