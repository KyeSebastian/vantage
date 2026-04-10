import asyncio
import os
import subprocess

from .base import BaseAnalyzer, AnalysisResult, Finding

WELL_KNOWN: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle DB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter/Dev", 9200: "Elasticsearch", 27017: "MongoDB",
    2375: "Docker API", 2376: "Docker TLS",
}

# (severity, detail, recommendation)
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: (
        "high",
        "FTP transmits credentials and data in plaintext.",
        "Replace FTP with SFTP (SSH file transfer) or FTPS.",
    ),
    23: (
        "critical",
        "Telnet transmits all data, including credentials, in cleartext.",
        "Disable Telnet. Use SSH for remote administration.",
    ),
    161: (
        "medium",
        "SNMP may expose device configuration and network topology.",
        "Restrict SNMP access with ACLs; upgrade to SNMPv3 with auth+privacy.",
    ),
    3389: (
        "high",
        "RDP exposed to the internet is a common brute-force and exploit target.",
        "Place RDP behind a VPN; enforce Network Level Authentication and MFA.",
    ),
    5900: (
        "high",
        "VNC exposed publicly is often poorly authenticated.",
        "Restrict VNC with a firewall; require strong authentication.",
    ),
    2375: (
        "critical",
        "Docker daemon API exposed without TLS enables full container/host compromise.",
        "Never expose the Docker socket publicly. Use TLS mutual auth if remote access is required.",
    ),
    6379: (
        "high",
        "Redis exposed without authentication allows arbitrary data read/write.",
        "Bind Redis to localhost; require AUTH; use firewall rules.",
    ),
    27017: (
        "high",
        "MongoDB exposed publicly may lack authentication, exposing all databases.",
        "Bind to localhost; enable --auth; restrict with firewall.",
    ),
    9200: (
        "high",
        "Elasticsearch exposed publicly is commonly misconfigured with no access control.",
        "Enable X-Pack security; restrict access to trusted IPs only.",
    ),
}


class ReconAnalyzer(BaseAnalyzer):
    name = "recon"

    def __init__(self, ports: list[int], timeout: float = 1.0, concurrency: int = 500):
        self.ports = ports
        self.timeout = timeout
        self.concurrency = concurrency

    async def _probe(self, ip: str, port: int, sem: asyncio.Semaphore) -> tuple[int, bool, str]:
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout
                )
                banner = ""
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                    banner = data.decode("utf-8", errors="replace").strip()[:200]
                except Exception:
                    pass
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                return port, True, banner
            except Exception:
                return port, False, ""

    def _os_fingerprint(self, ip: str) -> str:
        """Guess OS from ICMP TTL."""
        try:
            cmd = (
                ["ping", "-n", "1", "-w", "1000", ip]
                if os.name == "nt"
                else ["ping", "-c", "1", "-W", "1", ip]
            )
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=4).stdout
            for line in out.splitlines():
                low = line.lower()
                if "ttl=" in low:
                    ttl_str = low.split("ttl=")[1].split()[0].rstrip(".")
                    ttl = int(ttl_str)
                    if ttl <= 64:
                        return "Linux / Unix"
                    if ttl <= 128:
                        return "Windows"
                    return "Network Device (Cisco / Juniper)"
        except Exception:
            pass
        return "Unknown"

    async def analyze(self, target) -> AnalysisResult:
        sem = asyncio.Semaphore(self.concurrency)
        raw = await asyncio.gather(*[self._probe(target.ip, p, sem) for p in self.ports])

        open_ports: dict[int, dict] = {}
        for port, is_open, banner in raw:
            if is_open:
                open_ports[port] = {
                    "service": WELL_KNOWN.get(port, "Unknown"),
                    "banner": banner,
                }

        findings: list[Finding] = []
        for port, (severity, detail, rec) in RISKY_PORTS.items():
            if port in open_ports:
                findings.append(Finding(
                    title=f"Risky service on port {port}/tcp — {WELL_KNOWN.get(port, 'Unknown')}",
                    severity=severity,
                    detail=detail,
                    recommendation=rec,
                    module=self.name,
                ))

        os_guess = self._os_fingerprint(target.ip)

        return AnalysisResult(
            module=self.name,
            target=target.raw,
            findings=findings,
            data={
                "open_ports": open_ports,
                "os_guess": os_guess,
                "port_count": len(open_ports),
            },
        )
