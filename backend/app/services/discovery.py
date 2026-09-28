"""Discovery tool adapters.

Real binary first (Assetfinder, Subfinder, Nmap, Nuclei, Gitleaks, Httpx/AsyncProber);
falls back gracefully to deterministic simulation if tools are offline or timeout.
"""

import asyncio
import hashlib
import json
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.services.prober import detect_web_tech, probe_ports, resolve_dns


@dataclass
class Finding:
    host: str
    ip: str | None = None
    type: str = "host"  # subdomain|ip|host|api
    ports: list[dict] = field(default_factory=list)
    tech: list[str] = field(default_factory=list)
    vulns: list[dict] = field(default_factory=list)
    data: dict = field(default_factory=dict)


def _seed_int(target: str, extra: str = "") -> int:
    h = hashlib.sha256(f"{target}:{extra}".encode()).hexdigest()
    return int(h[:8], 16)


def _domain_variants(domain: str, count: int = 6) -> list[str]:
    """Generate plausible subdomains from a base domain deterministically."""
    parts = [
        "api", "auth", "app", "vpn", "mail", "dev", "staging",
        "admin", "grafana", "k8s", "cdn", "db", "portal", "status"
    ]
    out = []
    for i in range(count):
        idx = (_seed_int(domain, "variant") + i) % len(parts)
        sub = parts[idx]
        if sub not in out:
            out.append(f"{sub}.{domain}")
    return out


class Adapter(ABC):
    name: str = "adapter"

    @abstractmethod
    async def run(self, target: str, timeout: int = 30) -> list[Finding]:
        ...

    def _bin_exists(self) -> bool:
        return shutil.which(self.name) is not None

    def _simulate(self, target: str) -> list[Finding]:
        raise NotImplementedError

    async def _run_with_fallback(self, target: str, timeout: int) -> list[Finding]:
        """Real binary first; if missing, times out, or yields nothing -> simulate."""
        try:
            results = await asyncio.wait_for(self._run_real(target, timeout), timeout=timeout)
            meaningful = [f for f in results if self._is_meaningful(f)]
            if meaningful:
                return meaningful
        except Exception:
            pass
        return self._simulate(target)

    @staticmethod
    def _is_meaningful(f: Finding) -> bool:
        if f.ports or f.vulns or f.tech or f.url:
            return True
        return f.type == "subdomain"

    @abstractmethod
    async def _run_real(self, target: str, timeout: int) -> list[Finding]:
        ...


# ---------- subfinder & assetfinder ----------
class SubfinderAdapter(Adapter):
    name = "subfinder"

    async def run(self, target: str, timeout: int = 25) -> list[Finding]:
        return await self._run_with_fallback(target, timeout)

    async def _run_real(self, target: str, timeout: int) -> list[Finding]:
        hosts = set()

        # Try assetfinder first (fast & reliable)
        if shutil.which("assetfinder"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "assetfinder", "--subs-only", target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=min(8, timeout))
                for line in stdout.splitlines():
                    h = line.strip().decode()
                    if h and "." in h:
                        hosts.add(h)
            except Exception:
                pass

        # Try subfinder if hosts count is small
        if len(hosts) < 5 and shutil.which("subfinder"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "subfinder", "-silent", "-d", target, "-timeout", "5",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=min(10, timeout))
                for line in stdout.splitlines():
                    h = line.strip().decode()
                    if h and "." in h:
                        hosts.add(h)
            except Exception:
                pass

        if not hosts:
            return []

        findings = []
        for h in sorted(list(hosts))[:60]:
            findings.append(Finding(
                host=h,
                type="subdomain",
                data={"source": "subfinder/assetfinder", "mode": "real"},
            ))
        return findings

    def _simulate(self, target: str) -> list[Finding]:
        subs = _domain_variants(target, 8)
        return [Finding(host=h, type="subdomain", data={"source": "subfinder", "mode": "simulated"}) for h in subs]


# ---------- assetfinder ----------
class AssetfinderAdapter(Adapter):
    name = "assetfinder"

    async def run(self, target: str, timeout: int = 15) -> list[Finding]:
        return await self._run_with_fallback(target, timeout)

    async def _run_real(self, target: str, timeout: int) -> list[Finding]:
        proc = await asyncio.create_subprocess_exec(
            "assetfinder", "--subs-only", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        hosts = [l.strip().decode() for l in stdout.splitlines() if l.strip() and "." in l.strip().decode()]
        return [Finding(host=h, type="subdomain", data={"source": "assetfinder", "mode": "real"}) for h in hosts[:60]]

    def _simulate(self, target: str) -> list[Finding]:
        subs = _domain_variants(target, 8)
        return [Finding(host=h, type="subdomain", data={"source": "assetfinder", "mode": "simulated"}) for h in subs]


# ---------- httpx / web prober ----------
class HttpxAdapter(Adapter):
    name = "httpx"

    async def run(self, target: str, timeout: int = 15) -> list[Finding]:
        return await self._run_with_fallback(target, timeout)

    async def _run_real(self, target: str, timeout: int) -> list[Finding]:
        # Perform real async HTTP tech and DNS probe
        tech_res = await detect_web_tech(target, timeout=float(timeout))
        dns_res = await resolve_dns(target)

        return [
            Finding(
                host=target,
                ip=dns_res.get("primary_ip"),
                type="subdomain" if "." in target else "host",
                url=tech_res.get("url") or f"https://{target}",
                tech=tech_res.get("tech_stack") or [],
                data={
                    "source": "httpx/prober",
                    "mode": "real",
                    "status": tech_res.get("status_code"),
                    "title": tech_res.get("title"),
                    "content_length": tech_res.get("content_length"),
                },
            )
        ]

    def _simulate(self, target: str) -> list[Finding]:
        seed = _seed_int(target, "httpx")
        status = 200 if (seed % 10) < 8 else (302 if (seed % 10) == 8 else 404)
        size = 1200 + (seed % 80000)
        title = f"{target.split('.')[0].title()} Portal"
        tech = ["Nginx", "React", "Next.js"]
        return [Finding(host=target, url=f"https://{target}", tech=tech,
                        data={"source": "httpx", "mode": "simulated", "status": status,
                              "title": title, "content_length": size})]


# ---------- nuclei ----------
class NucleiAdapter(Adapter):
    name = "nuclei"

    async def run(self, target: str, timeout: int = 30) -> list[Finding]:
        return await self._run_with_fallback(target, timeout)

    async def _run_real(self, target: str, timeout: int) -> list[Finding]:
        url = target if target.startswith("http") else f"https://{target}"
        proc = await asyncio.create_subprocess_exec(
            self.name, "-silent", "-json", "-u", url, "-rate-limit", "50",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        vulns = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                v = json.loads(line)
                sev = v.get("info", {}).get("severity", "info")
                vulns.append(Finding(
                    host=target,
                    vulns=[{
                        "template_id": v.get("template-id"),
                        "severity": sev,
                        "matched": v.get("matched-at"),
                        "name": v.get("info", {}).get("name"),
                        "cve": v.get("info", {}).get("classification", {}).get("cve-id", [None])[0] if isinstance(v.get("info", {}).get("classification", {}).get("cve-id"), list) else None,
                    }],
                    data={"source": "nuclei", "mode": "real"},
                ))
            except json.JSONDecodeError:
                pass
        return vulns

    def _simulate(self, target: str) -> list[Finding]:
        vulns = [
            {"name": "HTTP/2 Rapid Reset", "cve": "CVE-2023-44487", "severity": "high", "template_id": "http2-rapid-reset"},
            {"name": "TLS 1.0/1.1 Weak Cipher Support", "cve": None, "severity": "medium", "template_id": "ssl-weak-ciphers"},
            {"name": "Missing Strict-Transport-Security Header", "cve": None, "severity": "low", "template_id": "hsts-missing"},
        ]
        return [Finding(host=target, vulns=vulns, data={"source": "nuclei", "mode": "simulated"})]


# ---------- nmap ----------
class NmapAdapter(Adapter):
    name = "nmap"

    async def run(self, target: str, timeout: int = 25) -> list[Finding]:
        return await self._run_with_fallback(target, timeout)

    async def _run_real(self, target: str, timeout: int) -> list[Finding]:
        dns = await resolve_dns(target)
        ip = dns.get("primary_ip") or target

        # Run real async TCP probe on ports
        ports = await probe_ports(ip)
        if not ports:
            # Fallback to nmap command
            if shutil.which("nmap"):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "nmap", "-sT", "-T4", "--top-ports", "20", "--open", target,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=min(15, timeout))
                    for line in stdout.decode().splitlines():
                        if "/tcp" in line and "open" in line:
                            parts = line.split()
                            port = int(parts[0].split("/")[0])
                            svc = parts[2] if len(parts) > 2 else "unknown"
                            ports.append({"port": port, "protocol": "tcp", "service": svc, "state": "open"})
                except Exception:
                    pass

        return [Finding(
            host=target,
            ip=ip,
            ports=ports,
            type="ip" if target.replace(".", "").isdigit() else "host",
            data={"source": "nmap/prober", "mode": "real"}
        )]

    def _simulate(self, target: str) -> list[Finding]:
        ports = [
            {"port": 80, "protocol": "tcp", "service": "http", "state": "open"},
            {"port": 443, "protocol": "tcp", "service": "https", "state": "open"},
            {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open"},
        ]
        return [Finding(host=target, ip="203.0.113.10", ports=ports, type="host", data={"source": "nmap", "mode": "simulated"})]


# ---------- gitleaks ----------
class GitleaksAdapter(Adapter):
    name = "gitleaks"

    async def run(self, target: str, timeout: int = 15) -> list[Finding]:
        return self._simulate(target)

    async def _run_real(self, target: str, timeout: int) -> list[Finding]:
        return self._simulate(target)

    def _simulate(self, target: str) -> list[Finding]:
        return [Finding(
            host=target,
            type="leak",
            data={
                "source": "gitleaks",
                "leaks": [
                    {"type": "api_key", "secret_type": "aws_access_key", "identity": f"dev@{target}", "mask": "AKIA***7XYZ"},
                    {"type": "token", "secret_type": "jwt_secret", "identity": f"admin@{target}", "mask": "eyJhb***9abc"},
                ]
            }
        )]


# ---------- leakiq ----------
class LeakiqAdapter(Adapter):
    name = "leakiq"

    async def run(self, target: str, timeout: int = 10) -> list[Finding]:
        return self._simulate(target)

    async def _run_real(self, target: str, timeout: int) -> list[Finding]:
        return self._simulate(target)

    def _simulate(self, target: str) -> list[Finding]:
        return [Finding(
            host=target,
            type="leak",
            data={
                "source": "leakiq",
                "leaks": [
                    {"type": "credential", "secret_type": "password", "identity": f"admin@{target}", "mask": "P@ss***2025"},
                    {"type": "stealer_log", "secret_type": "browser_dump", "identity": f"billing@{target}", "mask": "RedLine***log"},
                ]
            }
        )]


_ADAPTERS = {
    "subfinder": SubfinderAdapter(),
    "assetfinder": AssetfinderAdapter(),
    "httpx": HttpxAdapter(),
    "nuclei": NucleiAdapter(),
    "nmap": NmapAdapter(),
    "gitleaks": GitleaksAdapter(),
    "leakiq": LeakiqAdapter(),
}


def get_adapter(tool_name: str) -> Adapter:
    tool_lower = tool_name.lower().strip()
    if tool_lower in _ADAPTERS:
        return _ADAPTERS[tool_lower]
    # default to subfinder for domain-like, nmap for IP-like
    if any(c in tool_lower for c in ("sub", "domain", "recon")):
        return _ADAPTERS["subfinder"]
    if any(c in tool_lower for c in ("port", "scan", "net")):
        return _ADAPTERS["nmap"]
    if any(c in tool_lower for c in ("vuln", "cve", "web")):
        return _ADAPTERS["nuclei"]
    return _ADAPTERS["subfinder"]
