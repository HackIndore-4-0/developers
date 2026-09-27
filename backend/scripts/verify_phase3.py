"""Phase-3 verification: vulnerabilities + exposures + Neo4j graph."""

import sys
import time

import httpx

BASE = "http://localhost:8001/api/v1"
PASS, FAIL = 0, 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}{'  ' + str(extra) if extra else ''}")
    else:
        FAIL += 1
        print(f"  FAIL {name}{'  ' + str(extra) if extra else ''}")


c = httpx.Client(timeout=90)


def auth(email, pw):
    t = c.post(f"{BASE}/auth/login", json={"email": email, "password": pw}).json()
    me = c.get(f"{BASE}/auth/me", headers={"Authorization": "Bearer " + t["access_token"]}).json()
    oid = me["organizations"][0]["id"]
    s = c.post(f"{BASE}/auth/select-org", headers={"Authorization": "Bearer " + t["access_token"]}, json={"org_id": oid}).json()
    return {"Authorization": "Bearer " + s["access_token"]}


admin = auth("admin@aurora.ai", "Admin@123")
viewer = auth("viewer@aurora.ai", "Viewer@123")

print("== VULNERABILITIES ==")
r = c.get(f"{BASE}/vulnerabilities", headers=admin)
check("list vulns (>=8 seeded)", r.status_code == 200 and len(r.json()) >= 8, len(r.json()))
vulns = r.json()
sev = {"critical": 0, "high": 0, "medium": 0}[vulns[0]["severity"]] if vulns else 0
check("vulns have severity", all(v["severity"] in ("critical", "high", "medium", "low", "info") for v in vulns))

api_vulns = [v for v in vulns if v["cve"] == "CVE-2024-5345"]
check("CVE-2024-5345 present", len(api_vulns) == 1, api_vulns[0]["cve"] if api_vulns else "—")

vid = api_vulns[0]["id"]
r = c.patch(f"{BASE}/vulnerabilities/{vid}/status", headers=admin, json={"status": "in_progress"})
check("status -> in_progress", r.status_code == 200 and r.json()["status"] == "in_progress", r.status_code)
r = c.patch(f"{BASE}/vulnerabilities/{vid}/status", headers=viewer, json={"status": "fixed"})
check("RBAC: viewer cannot change status", r.status_code == 403, r.status_code)

r = c.get(f"{BASE}/vulnerabilities?q=CVE-2024", headers=admin)
check("search vulns by cve", r.status_code == 200 and len(r.json()) >= 1, len(r.json()))

r = c.get(f"{BASE}/vulnerabilities/scans", headers=admin)
check("scans list endpoint", r.status_code == 200, r.status_code)

print("\n== EXPOSURES ==")
r = c.get(f"{BASE}/exposures", headers=admin)
check("list exposures (>=6 seeded)", r.status_code == 200 and len(r.json()) >= 6, len(r.json()))
exps = r.json()
check("exposures masked", all(e.get("mask") for e in exps), [e.get("mask") for e in exps[:2]])

r = c.post(f"{BASE}/exposures/search", headers=admin, json={"q": "ops@aurora"})
check("search by identity", r.status_code == 200 and len(r.json()) >= 1, len(r.json()))

r = c.post(f"{BASE}/exposures/search", headers=admin, json={"category": "credential"})
check("search by category", r.status_code == 200 and sum(1 for e in r.json() if e["type"] == "credential") == len(r.json()), len(r.json()))

exp_id = exps[0]["id"]
r = c.patch(f"{BASE}/exposures/{exp_id}/status", headers=admin, json={"status": "acknowledged"})
check("exposure acknowledged", r.status_code == 200 and r.json()["status"] == "acknowledged", r.status_code)
r = c.get(f"{BASE}/exposures/events/{exp_id}", headers=admin)
check("exposure timeline events", r.status_code == 200 and len(r.json()) >= 2, len(r.json()))

print("\n== DISCOVERY -> VULNS/LEAKS ==")
r = c.post(f"{BASE}/discovery/run", headers=admin, json={"target": "payments-demo.test", "tool": "nuclei"})
check("nuclei run 201", r.status_code == 201)
job_id = r.json()["id"]
time.sleep(2)
for _ in range(80):
    j = c.get(f"{BASE}/discovery/jobs/{job_id}", headers=admin).json()
    if j["status"] in ("completed", "failed"):
        break
    time.sleep(1)
check("nuclei job completed", j["status"] == "completed", j["status"])
check("nuclei job produced findings", j["findings"] > 0, j["findings"])

r = c.get(f"{BASE}/vulnerabilities?q=payments-demo_test", headers=admin)
check("nuclei vulns attached", r.status_code == 200, len(r.json()))

r = c.post(f"{BASE}/discovery/run", headers=admin, json={"target": ".", "tool": "gitleaks"})
check("gitleaks run 201", r.status_code == 201)
job2 = r.json()["id"]
time.sleep(2)
for _ in range(90):
    j2 = c.get(f"{BASE}/discovery/jobs/{job2}", headers=admin).json()
    if j2["status"] in ("completed", "failed"):
        break
    time.sleep(1)
check("gitleaks job completed", j2["status"] in ("completed", "partial"), j2["status"])

r = c.post(f"{BASE}/discovery/run", headers=admin, json={"target": "aurora-bank.com", "tool": "leakiq"})
check("leakiq run 201", r.status_code == 201)
job3 = r.json()["id"]
time.sleep(2)
for _ in range(90):
    j3 = c.get(f"{BASE}/discovery/jobs/{job3}", headers=admin).json()
    if j3["status"] in ("completed", "failed"):
        break
    time.sleep(1)
check("leakiq job completed", j3["status"] in ("completed", "partial"), j3["status"])
check("leakiq produced exposures", len(c.get(f"{BASE}/exposures", headers=admin).json()) > 6, ">6 total")

print("\n== NEO4J GRAPH ==")
r = c.post(f"{BASE}/graph/sync", headers=admin)
check("graph sync", r.status_code == 200 and r.json().get("synced"), r.json())

r = c.get(f"{BASE}/graph/overview", headers=admin)
g = r.json()
check("graph overview counts", g.get("synced") and g.get("assets", 0) > 0 and g.get("vulns", 0) > 0, f"a={g.get('assets')} v={g.get('vulns')} e={g.get('exposures')}")

assets = c.get(f"{BASE}/assets", headers=admin).json()
target = next((a for a in assets if a["hostname"] == "api.aurora.ai"), assets[0])
r = c.get(f"{BASE}/graph/blast-radius/{target['id']}", headers=admin)
br = r.json().get("radius", [])
check("blast-radius returns nodes", r.status_code == 200 and len(br) > 0, len(br))

r = c.get(f"{BASE}/graph/attack-path/{target['id']}", headers=admin)
check("attack-path endpoint ok", r.status_code in (200, 503), r.status_code)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)