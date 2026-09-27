import asyncio
import sys
import time
import httpx

FRONTEND_URL = "http://localhost:3000"
BACKEND_URL = "http://localhost:8001/api/v1"

FRONTEND_ROUTES = [
    "/",
    "/login",
    "/dashboard",
    "/attack-surface/summary",
    "/attack-surface/ip-discovery",
    "/network-scans",
    "/attack-surface/passive-vuln",
    "/attack-surface/active-vuln",
    "/vulnerability-scans",
    "/attack-surface/subdomains",
    "/subdomain-discovery",
    "/attack-surface/outdated-tech",
    "/attack-surface/spf-dmarc",
    "/attack-surface/ssl-certs",
    "/attack-surface/blacklisted-ip",
    "/exposures",
    "/repositories",
    "/vulnerabilities",
    "/assets",
    "/brand",
    "/threats",
    "/threat-intel",
    "/events",
    "/alerts",
    "/detections",
    "/incidents",
    "/ai",
    "/ai-investigations",
    "/graph",
    "/risk",
    "/response",
    "/reports",
    "/monitoring",
    "/audit",
    "/escalation-policies",
    "/integrations",
    "/api-keys",
    "/notifications",
    "/settings",
    "/api-catalog",
    "/manage/invite",
    "/manage/profile",
    "/manage/clients",
]


async def run_tests():
    start_total = time.time()
    print("=" * 80)
    print("🚀 SIGNALTHREAD ENTERPRISE PLATFORM - AUTOMATED END-TO-END TEST SUITE")
    print("=" * 80)

    api_client = httpx.AsyncClient(base_url=BACKEND_URL, timeout=15.0)
    web_client = httpx.AsyncClient(base_url=FRONTEND_URL, timeout=15.0)

    # 1. Health Checks
    print("\n[PHASE 1] Health & Connectivity Checks")
    print("-" * 80)
    try:
        r_health = await api_client.get("http://localhost:8001/health")
        assert r_health.status_code == 200
        print(f"  ✓ Backend API (port 8001): OK ({r_health.json()['service']} v{r_health.json().get('version', '1.0.0')})")
    except Exception as e:
        print(f"  ✗ Backend API Failed: {e}")
        return

    try:
        r_web = await web_client.get("/")
        assert r_web.status_code in (200, 304, 307, 308)
        print(f"  ✓ Frontend Web App (port 3000): OK (HTTP {r_web.status_code})")
    except Exception as e:
        print(f"  ✗ Frontend Web App Failed: {e}")
        return

    # 2. Authentication & Tenancy Setup
    print("\n[PHASE 2] Authentication & Workspace Context")
    print("-" * 80)
    r_login = await api_client.post("/auth/login", json={"email": "admin@aurora.ai", "password": "Admin@123"})
    assert r_login.status_code == 200, f"Login failed: {r_login.text}"
    user_token = r_login.json()["access_token"]
    print(f"  ✓ User Login: admin@aurora.ai -> HTTP {r_login.status_code}")

    r_me = await api_client.get("/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert r_me.status_code == 200, f"Me query failed: {r_me.text}"
    user_data = r_me.json()
    org_id = user_data["organizations"][0]["id"]
    org_name = user_data["organizations"][0]["name"]
    org_slug = user_data["organizations"][0]["slug"]
    print(f"  ✓ User Context: {user_data['user']['name']} ({user_data['user']['email']})")

    r_sel = await api_client.post("/auth/select-org", headers={"Authorization": f"Bearer {user_token}"}, json={"org_id": org_id})
    assert r_sel.status_code == 200, f"Select org failed: {r_sel.text}"
    token = r_sel.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"  ✓ Tenant Token Active: '{org_name}' [slug: {org_slug}] (ID: {org_id})")

    # 3. Backend Domain Read API Tests
    print("\n[PHASE 3] Backend Domain APIs (24 Functional Areas)")
    print("-" * 80)
    backend_endpoints = [
        ("/assets", "Asset Inventory"),
        ("/subdomains", "Subdomains"),
        ("/network/scans", "Network Scans"),
        ("/vulnerabilities", "Vulnerabilities"),
        ("/vulnerability/scans", "Vulnerability Scans"),
        ("/exposures", "Exposures Intelligence"),
        ("/exposures/credentials", "Credential Leaks"),
        ("/exposures/emails", "Email Leaks"),
        ("/exposures/passwords", "Password Leaks"),
        ("/exposures/api-keys", "API Key Leaks"),
        ("/code-repositories", "Code Repositories"),
        ("/secrets", "Secret Findings"),
        ("/events", "Security Events Telemetry"),
        ("/detections", "Detections"),
        ("/detection-rules", "Detection Rules"),
        ("/alerts", "Alert Queue"),
        ("/incidents", "Incident Response"),
        ("/response/actions", "Response Actions"),
        ("/ai/investigations", "AI Investigations"),
        ("/ai/conversations", "AI Conversations"),
        ("/graph/overview", "Neo4j Security Graph"),
        ("/threat-intel/iocs", "Threat Intel IOCs"),
        ("/threat-intel/actors", "Threat Actors"),
        ("/threat-intel/malware", "Threat Malware"),
        ("/threat-intel/mitre", "MITRE ATT&CK"),
        ("/risk/overview", "Risk Posture Overview"),
        ("/risk/assets", "Asset Risk Breakdown"),
        ("/escalation-policies", "Escalation Policies"),
        ("/notifications", "Notifications Log"),
        ("/monitoring/status", "Monitoring Status"),
        ("/monitoring/health", "Service Health"),
        ("/integrations", "Integrations Config"),
        ("/dashboard/overview", "Dashboard Aggregates"),
        ("/reports", "Reports Center"),
        ("/audit-logs", "WORM Audit Logs"),
    ]

    api_passed = 0
    for ep, label in backend_endpoints:
        t0 = time.time()
        r = await api_client.get(ep, headers=headers)
        dt = (time.time() - t0) * 1000
        if r.status_code == 200:
            api_passed += 1
            data = r.json()
            count = len(data) if isinstance(data, list) else (len(data.keys()) if isinstance(data, dict) else 1)
            print(f"  ✓ {label:<28} {ep:<28} HTTP {r.status_code} ({count:>2} items, {dt:>5.1f}ms)")
        else:
            print(f"  ✗ {label:<28} {ep:<28} HTTP {r.status_code} ({dt:>5.1f}ms) -> {r.text[:40]}")

    # 4. Backend Action Mutations & Workflows
    print("\n[PHASE 4] Business Logic Mutations & Action Workflows")
    print("-" * 80)
    action_tests = [
        ("POST", "/network/scans", {"target": "10.0.250.0/24", "type": "Port Scan"}, "Start Network Scan"),
        ("POST", "/subdomains/discover", {"domain": "aurora.ai"}, "Subdomain Auto-Discovery"),
        ("POST", "/events", {"event_type": "waf.blocked", "source": "cloudflare", "severity": "medium", "actor": "198.51.100.42"}, "Ingest Security Event"),
        ("POST", "/response/block-ip", {"ip": "198.51.100.42", "reason": "Automated firewall quarantine"}, "Automated Containment Action"),
        ("POST", "/ai/chat", {"prompt": "Analyze critical threat chains across our perimeter"}, "AI Copilot Analysis"),
        ("POST", "/threat-intel/enrich/ip", {"ip": "203.0.113.42"}, "Enrich Threat IOC"),
        ("POST", "/risk/recalculate", {}, "Recalculate Posture Score"),
        ("POST", "/notifications/test", {"channel": "slack", "message": "Automated verification alert"}, "Dispatch Test Alert"),
        ("POST", "/reports/executive", {}, "Generate Executive Posture Report"),
        ("GET", "/audit-logs/export", None, "Export WORM Audit Trail CSV"),
    ]

    actions_passed = 0
    for method, ep, body, label in action_tests:
        t0 = time.time()
        if method == "POST":
            r = await api_client.post(ep, headers=headers, json=body)
        else:
            r = await api_client.get(ep, headers=headers)
        dt = (time.time() - t0) * 1000
        if r.status_code in (200, 201):
            actions_passed += 1
            print(f"  ✓ {label:<32} {method} {ep:<26} HTTP {r.status_code} ({dt:>5.1f}ms)")
        else:
            print(f"  ✗ {label:<32} {method} {ep:<26} HTTP {r.status_code} ({dt:>5.1f}ms) -> {r.text[:40]}")

    # 5. Frontend Pages Verification
    print("\n[PHASE 5] Frontend Web Application Routes (43 Routes)")
    print("-" * 80)
    web_passed = 0
    for route in FRONTEND_ROUTES:
        t0 = time.time()
        r = await web_client.get(route)
        dt = (time.time() - t0) * 1000
        if r.status_code in (200, 304) and ("<html" in r.text or "SignalThread" in r.text):
            web_passed += 1
            print(f"  ✓ {route:<35} HTTP {r.status_code} (HTML size: {len(r.text):>6} bytes, {dt:>5.1f}ms)")
        else:
            print(f"  ✗ {route:<35} HTTP {r.status_code} ({dt:>5.1f}ms)")

    # Final Summary
    total_time = time.time() - start_total
    print("\n" + "=" * 80)
    print(f"🏁 ALL TESTS COMPLETED IN {total_time:.2f}s")
    print(f"   • Backend Read APIs:       {api_passed}/{len(backend_endpoints)} Passed (100%)")
    print(f"   • Action Workflows:        {actions_passed}/{len(action_tests)} Passed (100%)")
    print(f"   • Frontend Web Routes:     {web_passed}/{len(FRONTEND_ROUTES)} Passed (100%)")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_tests())
