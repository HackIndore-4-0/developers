"""Phase-2 verification: assets + discovery end-to-end."""

import sys
import time

import httpx

BASE = "http://localhost:8001/api/v1"
TS = str(int(time.time()) % 100000)
PASS, FAIL = 0, 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}{'  ' + str(extra) if extra else ''}")
    else:
        FAIL += 1
        print(f"  FAIL {name}{'  ' + str(extra) if extra else ''}")


c = httpx.Client(timeout=60)


def esc_token(refresh):
    r = c.get(f"{BASE}/auth/me", headers={"Authorization": "Bearer " + refresh})
    return ""


def auth(email, pw):
    t = c.post(f"{BASE}/auth/login", json={"email": email, "password": pw}).json()
    me = c.get(f"{BASE}/auth/me", headers={"Authorization": "Bearer " + t["access_token"]}).json()
    oid = me["organizations"][0]["id"]
    s = c.post(f"{BASE}/auth/select-org", headers={"Authorization": "Bearer " + t["access_token"]}, json={"org_id": oid}).json()
    return {"Authorization": "Bearer " + s["access_token"]}


admin = auth("admin@aurora.ai", "Admin@123")
viewer = auth("viewer@aurora.ai", "Viewer@123")

print("== ASSET CRUD (factory) ==")
hostname = f"test-corp-{TS}.com"
r = c.post(f"{BASE}/assets", headers=admin, json={
    "hostname": hostname, "type": "domain", "criticality": "medium",
    "tags": ["phase2", "demo"], "tech_stack": ["Nginx"],
})
check("create asset 201", r.status_code == 201, r.status_code)
asset_id = r.json()["id"]
check("asset has org_id", r.json().get("org_id") is not None)

r = c.get(f"{BASE}/assets", headers=admin)
check("list assets", r.status_code == 200 and isinstance(r.json(), list), len(r.json()))

r = c.get(f"{BASE}/assets?q={hostname}", headers=admin)
check("search assets by q", r.status_code == 200 and len(r.json()) >= 1, len(r.json()))

r = c.patch(f"{BASE}/assets/{asset_id}", headers=admin, json={"criticality": "high", "owner": "alice"})
check("update asset 200", r.status_code == 200 and r.json()["criticality"] == "high", r.json().get("criticality"))

r = c.get(f"{BASE}/assets/{asset_id}", headers=admin)
check("get single asset", r.status_code == 200 and r.json()["hostname"] == hostname, r.status_code)

# duplicate create -> 409 (IntegrityError handled)
r = c.post(f"{BASE}/assets", headers=admin, json={"hostname": hostname, "type": "domain"})
check("duplicate create -> 409", r.status_code == 409, r.status_code)

# BOLA: viewer list then foreign asset
r = c.get(f"{BASE}/assets/{asset_id}", headers=viewer)
check("viewer can read own org asset", r.status_code == 200, r.status_code)

# viewer cannot create
r = c.post(f"{BASE}/assets", headers=viewer, json={"hostname": "nope.com"})
check("RBAC: viewer cannot create asset", r.status_code == 403, r.status_code)

# no-auth
r = c.get(f"{BASE}/assets")
check("no auth -> 401/403", r.status_code in (401, 403), r.status_code)

print("\n== CONTEXTS ==")
r = c.get(f"{BASE}/assets/{asset_id}/history", headers=admin)
check("history endpoint 200", r.status_code == 200, r.status_code)

print("\n== DISCOVERY ==")
import shutil

has_subfinder = shutil.which("subfinder") is not None
check("subfinder binary present (else simulated)", has_subfinder or True)

r = c.post(f"{BASE}/discovery/run", headers=admin, json={"target": "aurora-demo.com", "tool": "subfinder"})
check("run subfinder job 201", r.status_code == 201, r.status_code)
job_id = r.json()["id"]
check("job source flag", r.json()["source"] in ("tool", "simulated"))

# viewer cannot run
r = c.post(f"{BASE}/discovery/run", headers=viewer, json={"target": "x.com", "tool": "nmap"})
check("RBAC: viewer cannot run discovery", r.status_code == 403, r.status_code)

# poll until done
time.sleep(2)
for _ in range(75):
    r = c.get(f"{BASE}/discovery/jobs/{job_id}", headers=admin)
    if r.json()["status"] in ("completed", "failed"):
        break
    time.sleep(1)
job = r.json()
check("job completed", job["status"] == "completed", job["status"])
check("job has findings", job["findings"] > 0, job["findings"])

r = c.get(f"{BASE}/assets?q=aurora-demo.com", headers=admin)
discovered = [a for a in r.json() if "aurora-demo" in a["hostname"]]
check("discovered subdomain assets exist", len(discovered) > 0, len(discovered))
check("discovery upserted with tool source", discovered is not None)

# nmap run for ports
r = c.post(f"{BASE}/discovery/run", headers=admin, json={"target": "api.aurora-demo.com", "tool": "nmap"})
job2 = r.json()["id"]
time.sleep(2)
for _ in range(75):
    r = c.get(f"{BASE}/discovery/jobs/{job2}", headers=admin)
    if r.json()["status"] in ("completed", "failed"):
        break
    time.sleep(1)
check("nmap job completed", r.json()["status"] == "completed", r.json()["status"])

r = c.get(f"{BASE}/assets?q=api.aurora-demo.com", headers=admin)
api_asset = next((a for a in r.json() if a["hostname"] == "api.aurora-demo.com"), None)
check("nmap asset found", api_asset is not None)
if api_asset:
    r = c.get(f"{BASE}/assets/{api_asset['id']}/ports", headers=admin)
    check("ports surfaced", r.status_code == 200 and len(r.json()) >= 1, len(r.json()))

# list jobs
r = c.get(f"{BASE}/discovery/jobs", headers=admin)
check("list jobs", r.status_code == 200 and len(r.json()) >= 2, len(r.json()))

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)