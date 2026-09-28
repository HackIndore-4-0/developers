"""Phase-1 verification: auth + org + RBAC flows against a running API."""

import json
import sys
import time

import httpx

BASE = "http://localhost:8001/api/v1"
TS = str(int(time.time()) % 100000)
PASS = 0
FAIL = 0


def check(name: str, cond: bool, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}{'  ' + str(extra) if extra else ''}")
    else:
        FAIL += 1
        print(f"  FAIL {name}{'  ' + str(extra) if extra else ''}")


def login(email, password):
    r = httpx.post(f"{BASE}/auth/login", json={"email": email, "password": password})
    return r


c = httpx.Client()

print("== AUTH ==")
r = login("admin@aurora.ai", "Admin@123")
check("login admin 200", r.status_code == 200, r.status_code)
tokens = r.json()
admin_refresh = tokens["refresh_token"]

r2 = login("analyst@aurora.ai", "Analyst@123")
check("login analyst 200", r2.status_code == 200)
analyst_bare = r2.json()["access_token"]

r3 = login("viewer@aurora.ai", "Viewer@123")
check("login viewer 200", r3.status_code == 200)
viewer_bare = r3.json()["access_token"]

r4 = login("admin@aurora.ai", "wrongpass")
check("login wrong password 401", r4.status_code == 401, r4.status_code)

au = {"Authorization": f"Bearer {tokens['access_token']}"}
an = {"Authorization": f"Bearer {analyst_bare}"}
vw = {"Authorization": f"Bearer {viewer_bare}"}

r = c.get(f"{BASE}/auth/me", headers=au)
me = r.json()
check("me 200 admin", r.status_code == 200)
check("me shows member orgs (aurora-bank present)", any(o["slug"] == "aurora-bank" for o in me["organizations"]), me["organizations"])

r0 = c.post(f"{BASE}/auth/me", headers=au)
check("GET /auth/me only accepts GET (405 on POST)", r0.status_code == 405, r0.status_code)

print("\n== ORG SCOPING (select-org) ==")
r = c.post(f"{BASE}/auth/select-org", headers=au, json={"org_id": str(me["organizations"][0]["id"])})
check("select-org 200", r.status_code == 200)
admin_esc = r.json()["access_token"]
au_t = {"Authorization": f"Bearer {admin_esc}"}

r = c.get(f"{BASE}/auth/me", headers=au_t)
m = r.json()
check("me after select-org has roles", "admin" in m["roles"], m.get("roles"))
check("me active_org is aurora-bank", m["active_org"]["slug"] == "aurora-bank", m.get("active_org"))

r = c.post(f"{BASE}/auth/refresh", json={"refresh_token": admin_refresh})
check("refresh 200", r.status_code == 200, r.status_code)

r = c.post(f"{BASE}/auth/select-org", headers=au, json={"org_id": "not-a-uuid"})
check("select-org invalid id 400", r.status_code == 400, r.status_code)

print("\n== ORG CRUD ==")
r = c.post(f"{BASE}/organizations", headers=au, json={"name": "Triton Insurance", "slug": f"triton-insur-{TS}"})
check("create org 201", r.status_code == 201, r.status_code)
triton_id = r.json()["id"]

r = c.post(f"{BASE}/organizations", headers=au, json={"name": "Dup", "slug": "aurora-bank"})
check("create duplicate slug 409", r.status_code == 409, r.status_code)

r = c.get(f"{BASE}/organizations", headers=au)
check("list orgs >= 2 (aurora + triton)", r.status_code == 200 and len(r.json()) >= 2, len(r.json()))

r = c.patch(f"{BASE}/organizations/triton-insur-{TS}", headers=au_t, json={"description": "Insurance demo org"})
check("update org (admin in triton? no - 404/403)", r.status_code in (403, 404), r.status_code)

# give admin the org-scoped token for triton (admin created it -> admin automatically)
r = c.post(f"{BASE}/auth/select-org", headers=au, json={"org_id": triton_id})
triton_esc = r.json()["access_token"]
au_tr = {"Authorization": f"Bearer {triton_esc}"}
r = c.patch(f"{BASE}/organizations/triton-insur-{TS}", headers=au_tr, json={"description": "Insurance demo org"})
check("update org with triton scope 200", r.status_code == 200, r.status_code)

# BOLA: admin with aurora scoped token hits triton org slug
r = c.get(f"{BASE}/organizations/triton-insur-{TS}", headers=au_t)
check("BOLA: aurora-scope cannot read triton (404)", r.status_code == 404, r.status_code)

print("\n== MEMBERS + RBAC ==")
# viewer (bare, no org scope) tries member list -> 400 (needs org)
r = c.get(f"{BASE}/organizations/aurora-bank/members", headers=vw)
check("viewer no-org access blocked (400/403)", r.status_code in (400, 403), r.status_code)

# give viewer aurora scope
me_v = c.get(f"{BASE}/auth/me", headers=vw).json()["organizations"][0]["id"]
vx = c.post(f"{BASE}/auth/select-org", headers=vw, json={"org_id": me_v}).json()["access_token"]
vwt = {"Authorization": f"Bearer {vx}"}

r = c.get(f"{BASE}/organizations/aurora-bank/members", headers=vwt)
check("viewer list members 200", r.status_code == 200 and len(r.json()) == 4, len(r.json()) if r.status_code == 200 else r.status_code)

r = c.post(f"{BASE}/organizations/aurora-bank/members", headers=vwt,
           json={"email": "newuser@x.com", "role": "viewer"})
check("RBAC: viewer cannot add member (403)", r.status_code == 403, r.status_code)

r = c.get(f"{BASE}/organizations/aurora-bank/members", headers=au_t)
check("admin list members 200 (4)", r.status_code == 200 and len(r.json()) == 4)
member_ids = [m["user_id"] for m in r.json()]

r = c.post(f"{BASE}/organizations/aurora-bank/members", headers=au_t,
           json={"email": "newuser@x.com", "role": "viewer"})
check("add unknown user 404 (no open signup in P1)", r.status_code == 404, r.status_code)

r = c.patch(f"{BASE}/organizations/aurora-bank/members/{member_ids[1]}", headers=au_t, json={"role": "admin"})
check("promote member to admin 200", r.status_code == 200, (r.status_code, r.json().get("role") if r.status_code == 200 else ""))
r = c.patch(f"{BASE}/organizations/aurora-bank/members/{member_ids[1]}", headers=au_t, json={"role": "viewer"})
check("demote back to viewer 200", r.status_code == 200)

r = c.patch(f"{BASE}/organizations/aurora-bank/members/{member_ids[0]}", headers=au_t, json={"role": "viewer"})
check("cannot demote self 400", r.status_code == 400, r.status_code)

r = c.delete(f"{BASE}/organizations/aurora-bank/members/{member_ids[0]}", headers=au_t)
check("cannot remove self 400", r.status_code == 400, r.status_code)

r = c.post(f"{BASE}/auth/logout", json={"refresh_token": admin_refresh})
check("logout 204", r.status_code == 204, r.status_code)
r = c.post(f"{BASE}/auth/refresh", json={"refresh_token": admin_refresh})
check("refresh after logout 401", r.status_code in (401, 422), r.status_code)  # revoked session (or already superseded)

r = c.get(f"{BASE}/organizations")
check("no auth -> 401", r.status_code in (401, 403), r.status_code)

print(f"\nRESULT: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)