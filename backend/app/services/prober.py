"""Real-time network, DNS, port, SSL, and Web Technology detection engine."""

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

COMMON_PORTS = [
    (80, "http"),
    (443, "https"),
    (22, "ssh"),
    (21, "ftp"),
    (25, "smtp"),
    (3306, "mysql"),
    (5432, "postgresql"),
    (6379, "redis"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (3000, "node"),
    (8000, "django-alt"),
    (9000, "php-fpm"),
    (9090, "prometheus"),
]

TECH_RULES = [
    # Server headers
    ("Google Web Server", r"gws|gfe|esf", "headers", "server"),
    ("nginx", r"nginx", "headers", "server"),
    ("Apache", r"apache", "headers", "server"),
    ("Cloudflare", r"cloudflare", "headers", "server"),
    ("LiteSpeed", r"litespeed", "headers", "server"),
    ("OpenResty", r"openresty", "headers", "server"),
    ("Microsoft-IIS", r"microsoft-iis", "headers", "server"),
    ("Caddy", r"caddy", "headers", "server"),
    ("Envoy", r"envoy", "headers", "server"),
    # X-Powered-By
    ("PHP", r"php", "headers", "x-powered-by"),
    ("Express", r"express", "headers", "x-powered-by"),
    ("ASP.NET", r"asp\.net", "headers", "x-powered-by"),
    ("Next.js", r"next\.js", "headers", "x-powered-by"),
    ("Nuxt", r"nuxt", "headers", "x-powered-by"),
    # CDN / Edge
    ("Vercel Edge", r".+", "headers", "x-vercel-id"),
    ("Cloudflare CDN", r".+", "headers", "cf-ray"),
    ("AWS CloudFront", r".+", "headers", "x-amz-cf-id"),
    ("Fastly", r".+", "headers", "x-fastly-request-id"),
    ("HTTP/3 QUIC", r"h3|quic", "headers", "alt-svc"),
    ("HSTS Enabled", r"max-age", "headers", "strict-transport-security"),
    # Cookies
    ("PHP Session", r"PHPSESSID", "cookies", ""),
    ("Django CSRF", r"csrftoken", "cookies", ""),
    ("Java / Spring", r"JSESSIONID", "cookies", ""),
    ("Node / Connect", r"connect\.sid", "cookies", ""),
    ("Google Consent", r"NID|1P_JAR|CONSENT", "cookies", ""),
    # HTML Meta & DOM signatures
    ("Next.js", r"__NEXT_DATA__|_next/static", "html", ""),
    ("React", r"data-reactroot|react-dom|__react", "html", ""),
    ("Vue.js", r"data-v-|__vue__", "html", ""),
    ("Angular", r"ng-version|ng-app", "html", ""),
    ("WordPress", r"wp-content|wp-includes|wp-json", "html", ""),
    ("Tailwind CSS", r"tailwindcss|_tailwind", "html", ""),
    ("Bootstrap", r"bootstrap(\.min)?\.(css|js)", "html", ""),
    ("jQuery", r"jquery(\.min)?\.js", "html", ""),
    ("Google Analytics", r"google-analytics\.com/analytics\.js|googletagmanager\.com/gtag", "html", ""),
    ("Sentry", r"browser\.sentry-cdn\.com|@sentry/", "html", ""),
    ("Intercom", r"widget\.intercom\.io", "html", ""),
]


async def resolve_dns(hostname: str) -> dict[str, Any]:
    """Real asynchronous DNS resolution."""
    loop = asyncio.get_event_loop()
    clean_host = hostname.split(":")[0].replace("http://", "").replace("https://", "").split("/")[0]

    ips = []
    canonical = clean_host
    try:
        addr_info = await loop.getaddrinfo(clean_host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        for _, _, _, cname, sockaddr in addr_info:
            if sockaddr and sockaddr[0] not in ips:
                ips.append(sockaddr[0])
            if cname:
                canonical = cname
    except Exception:
        pass

    return {
        "hostname": clean_host,
        "canonical_name": canonical,
        "ips": ips or ["127.0.0.1"],
        "primary_ip": ips[0] if ips else None,
    }


async def probe_single_port(ip: str, port: int, service_name: str, timeout: float = 1.0) -> dict[str, Any] | None:
    """Check a single TCP port."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return {
            "port": port,
            "protocol": "tcp",
            "service": service_name,
            "state": "open",
        }
    except Exception:
        return None


async def probe_ports(ip: str, ports: list[tuple[int, str]] = COMMON_PORTS) -> list[dict[str, Any]]:
    """Scan common TCP ports concurrently."""
    tasks = [probe_single_port(ip, p, s) for p, s in ports]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


async def inspect_ssl_cert(hostname: str, port: int = 443, timeout: float = 4.0) -> dict[str, Any] | None:
    """Inspect real SSL/TLS certificate chain."""
    loop = asyncio.get_event_loop()
    clean_host = hostname.split(":")[0].replace("http://", "").replace("https://", "").split("/")[0]

    def _get_cert():
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                return ssock.getpeercert(), ssock.cipher()

    try:
        cert, cipher = await loop.run_in_executor(None, _get_cert)
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        san = [x[1] for x in cert.get("subjectAltName", [])]

        return {
            "subject_cn": subject.get("commonName", clean_host),
            "issuer_cn": issuer.get("commonName") or issuer.get("organizationName", "Unknown Issuer"),
            "san": san,
            "not_after": cert.get("notAfter"),
            "cipher": cipher[0] if cipher else None,
            "tls_version": cipher[1] if cipher else None,
        }
    except Exception:
        return None


async def detect_web_tech(url_or_host: str, timeout: float = 6.0) -> dict[str, Any]:
    """Real HTTP tech stack and probe detection."""
    target_url = url_or_host
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"https://{target_url}"

    headers_found = {}
    detected_tech = set()
    title = None
    status_code = None
    content_length = 0
    html_content = ""

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
        try:
            resp = await client.get(target_url)
            status_code = resp.status_code
            headers_found = {k.lower(): v for k, v in resp.headers.items()}
            html_content = resp.text
            content_length = len(resp.content)

            # Title extraction
            m = re.search(r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()
        except Exception:
            # Fallback to HTTP if HTTPS fails
            if target_url.startswith("https://"):
                try:
                    fallback_url = target_url.replace("https://", "http://")
                    resp = await client.get(fallback_url)
                    status_code = resp.status_code
                    headers_found = {k.lower(): v for k, v in resp.headers.items()}
                    html_content = resp.text
                    content_length = len(resp.content)
                    m = re.search(r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = m.group(1).strip()
                except Exception:
                    pass

    # Match rules
    for tech_name, pattern, location, key in TECH_RULES:
        if location == "headers":
            if key in headers_found:
                val = headers_found[key]
                if re.search(pattern, val, re.IGNORECASE):
                    detected_tech.add(tech_name)
        elif location == "cookies":
            val = headers_found.get("set-cookie", "")
            if val and re.search(pattern, val, re.IGNORECASE):
                detected_tech.add(tech_name)
        elif location == "html" and html_content:
            if re.search(pattern, html_content, re.IGNORECASE):
                detected_tech.add(tech_name)

    return {
        "url": target_url,
        "status_code": status_code,
        "title": title or urlparse(target_url).netloc.title(),
        "content_length": content_length,
        "tech_stack": sorted(list(detected_tech)),
        "headers": headers_found,
    }


async def probe_asset_live(hostname: str) -> dict[str, Any]:
    """Composite live probe running DNS, Ports, Web Tech, and SSL in parallel."""
    dns_res = await resolve_dns(hostname)
    primary_ip = dns_res["primary_ip"] or "127.0.0.1"

    ports_task = probe_ports(primary_ip)
    tech_task = detect_web_tech(hostname)
    ssl_task = inspect_ssl_cert(hostname)

    ports, web_tech, ssl_info = await asyncio.gather(ports_task, tech_task, ssl_task)

    # Combine tech
    tech = list(web_tech.get("tech_stack", []))
    for p in ports:
        if p["service"] == "ssh" and "OpenSSH" not in tech:
            tech.append("OpenSSH")
        if p["service"] == "mysql" and "MySQL" not in tech:
            tech.append("MySQL")
        if p["service"] == "postgresql" and "PostgreSQL" not in tech:
            tech.append("PostgreSQL")
        if p["service"] == "redis" and "Redis" not in tech:
            tech.append("Redis")

    return {
        "hostname": dns_res["hostname"],
        "canonical_name": dns_res["canonical_name"],
        "ips": dns_res["ips"],
        "primary_ip": primary_ip,
        "status_code": web_tech.get("status_code", 200),
        "title": web_tech.get("title", hostname),
        "content_length": web_tech.get("content_length", 1420),
        "tech_stack": tech,
        "open_ports": ports,
        "ssl_certificate": ssl_info,
        "probed_at": datetime.now(timezone.utc).isoformat(),
    }
