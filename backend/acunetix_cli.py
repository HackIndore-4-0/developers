"""Standalone CLI tool for Acunetix automation and choke point discovery."""

import argparse
import asyncio
import json
from app.engines.acunetix.client import AcunetixClient
from app.engines.acunetix.graph.choke_point_bridge import build_acunetix_attack_graph
from app.engines.acunetix.graph.cut_analyzer import find_top_choke_points


async def main():
    parser = argparse.ArgumentParser(description="Acunetix Choke Point CLI")
    parser.add_argument("--targets", action="store_true", help="List all targets")
    parser.add_argument("--scans", action="store_true", help="List all scans")
    args = parser.parse_args()

    client = AcunetixClient()
    try:
        if args.targets:
            targets = await client.get_targets()
            print(json.dumps(targets, indent=2))
        elif args.scans:
            scans = await client.get_scans()
            print(json.dumps(scans, indent=2))
        else:
            print("Use --targets or --scans")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
