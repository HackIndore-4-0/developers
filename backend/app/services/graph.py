"""Neo4j security-graph service: org/asset/vuln/exposure sync + attack-path & blast-radius."""

import asyncio
from typing import Any

from neo4j import AsyncGraphDatabase

from app.core.config import settings

_graph = None
_lock = None


async def _drv():
    global _graph, _lock
    if _lock is None:
        _lock = asyncio.Lock()
    async with _lock:
        if _graph is None:
            _graph = AsyncGraphDatabase.driver(
                settings.neo4j_uri,
                auth=(settings.neo4j_user, settings.neo4j_password),
                connection_timeout=8,
            )
        return _graph


async def _close():
    global _graph
    if _graph:
        await _graph.close()
        _graph = None


async def ensure_schema() -> None:
    drv = await _drv()
    async with drv.session() as s:
        for stmt in (
            "CREATE CONSTRAINT org_id IF NOT EXISTS FOR (o:Org) REQUIRE o.id IS UNIQUE",
            "CREATE CONSTRAINT asset_key IF NOT EXISTS FOR (a:Asset) REQUIRE a.key IS UNIQUE",
            "CREATE CONSTRAINT vuln_key IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.key IS UNIQUE",
            "CREATE CONSTRAINT expo_key IF NOT EXISTS FOR (e:Exposure) REQUIRE e.key IS UNIQUE",
        ):
            await s.run(stmt)


async def upsert_org(org_id: str, name: str) -> None:
    drv = await _drv()
    async with drv.session() as s:
        await s.run(
            "MERGE (o:Org {id:$id}) SET o.name=$name, o.kind='org'",
            id=org_id, name=name,
        )


async def upsert_asset(org_id: str, asset_id: str, hostname: str, criticality: str, type_: str) -> None:
    drv = await _drv()
    key = f"{org_id}:{asset_id}"
    async with drv.session() as s:
        await s.run(
            """MERGE (a:Asset {key:$key})
               SET a.id=$aid, a.org_id=$org, a.hostname=$hostname,
                   a.criticality=$crit, a.type=$t, a.kind='asset'
               WITH a
               MATCH (o:Org {id:$org}) MERGE (o)-[:OWNS]->(a)""",
            key=key, aid=str(asset_id), org=org_id, hostname=hostname, crit=criticality, t=type_,
        )


async def upsert_vuln(org_id: str, asset_id: str, vuln_id: str, title: str, severity: str, cve: str | None) -> None:
    drv = await _drv()
    key = f"{org_id}:{vuln_id}"
    async with drv.session() as s:
        await s.run(
            """MERGE (v:Vulnerability {key:$key})
               SET v.id=$vid, v.org_id=$org, v.title=$title, v.severity=$sev, v.cve=$cve, v.kind='vuln'
               WITH v
               MATCH (a:Asset {key:$assetKey}) MERGE (a)-[:VULNERABLE_TO]->(v)""",
            key=key, vid=str(vuln_id), org=org_id, title=title, sev=severity, cve=cve,
            assetKey=f"{org_id}:{asset_id}",
        )


async def upsert_exposure(org_id: str, exp_id: str, identity: str, type_: str, severity: str) -> None:
    drv = await _drv()
    key = f"{org_id}:{exp_id}"
    async with drv.session() as s:
        await s.run(
            """MERGE (e:Exposure {key:$key})
               SET e.id=$eid, e.org_id=$org, e.identity=$ident, e.type=$t, e.severity=$sev, e.kind='exposure'
               WITH e
               MATCH (o:Org {id:$org}) MERGE (o)-[:LEAKED]->(e)""",
            key=key, eid=str(exp_id), org=org_id, ident=identity, t=type_, sev=severity,
        )


async def attack_path(org_id: str, source_asset_id: str, target_asset_id: str | None = None, depth: int = 4) -> list[dict]:
    drv = await _drv()
    src = f"{org_id}:{source_asset_id}"
    target = f"{org_id}:{target_asset_id}" if target_asset_id else None
    d = max(1, min(int(depth), 6))
    async with drv.session() as s:
        body = f"MATCH (a:Asset) WHERE a.key = $src MATCH p = (a)-[*1..{d}]-(b:Asset)"
        if target:
            body += " WHERE b.key = $target"
        body += " RETURN nodes(p) AS ns, relationships(p) AS rs LIMIT 5"
        result = await s.run(body, src=src, target=target)
        return [_serialize_path(r) for r in await result.data()]


async def blast_radius(org_id: str, asset_id: str, depth: int = 3) -> list[dict]:
    drv = await _drv()
    key = f"{org_id}:{asset_id}"
    d = max(1, min(int(depth), 5))
    async with drv.session() as s:
        result = await s.run(
            f"""MATCH (a:Asset) WHERE a.key = $key
               MATCH (a)-[*1..{d}]-(n)
               RETURN DISTINCT n.kind AS kind, labels(n) AS labels,
                      coalesce(n.hostname, n.title, n.identity) AS name,
                      n.id AS id, n.severity AS severity, n.criticality AS crit,
                      length(shortestPath((a)-[*..{d}]-(n))) AS hops
               ORDER BY hops LIMIT 100""",
            key=key,
        )
        return [dict(r) for r in await result.data()]


async def org_summary(org_id: str) -> dict:
    drv = await _drv()
    async with drv.session() as s:
        r = await s.run("MATCH (o:Org {id:$org}) RETURN o", org=org_id)
        rec = await r.single()
        if not rec:
            return {"synced": False, "assets": 0, "vulns": 0, "exposures": 0, "nodes": [], "edges": []}
        assets = await (await s.run("MATCH (o:Org {id:$org})-[:OWNS]->(a:Asset) RETURN a.hostname AS n, a.key AS key, a.criticality AS crit, 'asset' AS kind", org=org_id)).data()
        exps = await (await s.run("MATCH (o:Org {id:$org})-[:LEAKED]->(e:Exposure) RETURN e.identity AS n, e.key AS key, e.severity AS sev, 'exposure' AS kind", org=org_id)).data()
        vulns = await (await s.run("MATCH (a:Asset)-[:VULNERABLE_TO]->(v:Vulnerability) WHERE a.org_id=$org RETURN v.title AS n, v.key AS key, v.severity AS sev, 'vuln' AS kind", org=org_id)).data()
        edges = await (await s.run(
            "MATCH (a:Asset)-[:VULNERABLE_TO]->(v:Vulnerability) WHERE a.org_id=$org RETURN a.key AS src, v.key AS dst",
            org=org_id,
        )).data()
        edge_rows = [{"src": e["src"], "dst": e["dst"], "type": "VULNERABLE_TO"} for e in edges]
        exp_edges = await (await s.run(
            "MATCH (o:Org {id:$org})-[:LEAKED]->(e:Exposure) RETURN e.key AS dst", org=org_id,
        )).data()
        edge_rows += [{"src": f"org:{org_id}", "dst": r["dst"], "type": "LEAKED"} for r in exp_edges]
        edge_rows += [{"src": f"org:{org_id}", "dst": f"{org_id}:{a['key'].split(':')[-1]}", "type": "OWNS"} for a in assets]
        return {
            "synced": True,
            "assets": len(assets),
            "vulns": len(vulns),
            "exposures": len(exps),
            "nodes": [
                {"key": r["key"], "name": r["n"], "kind": r["kind"],
                 "severity": r.get("sev") or r.get("crit") or "info"} for r in (assets + vulns + exps)
            ],
            "edges": edge_rows,
        }


def _serialize_path(rec: dict) -> dict:
    ns = []
    for n in rec.get("ns", []) or []:
        if isinstance(n, dict):
            props = n
        elif hasattr(n, "keys"):
            props = {k: n.get(k) for k in n.keys()}
        elif isinstance(n, (tuple, list)) and len(n) >= 3:
            props = n[2] if isinstance(n[2], dict) else {}
        else:
            props = {}
        ns.append({
            "key": props.get("key"), "id": props.get("id"), "hostname": props.get("hostname"),
            "title": props.get("title"), "identity": props.get("identity"),
            "severity": props.get("severity"), "criticality": props.get("criticality"), "kind": props.get("kind"),
        })
    rels = []
    for r in rec.get("rs", []) or []:
        rel_type, props = _rel_info(r)
        rels.append({"type": rel_type, "props": props})
    return {"nodes": ns, "rels": rels}


def _rel_info(r) -> tuple:
    if isinstance(r, dict):
        return r.get("type"), r
    if isinstance(r, (tuple, list)):
        if len(r) >= 3:
            return r[2], (r[3] if len(r) > 3 and isinstance(r[3], dict) else {})
    if hasattr(r, "type"):  # neo4j Relationship object
        return r.type, {k: r.get(k) for k in r.keys()}
    return None, {}


async def delete_org(org_id: str) -> None:
    drv = await _drv()
    async with drv.session() as s:
        await s.run("MATCH (o:Org {id:$org}) DETACH DELETE o", org=org_id)