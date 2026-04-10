import asyncio
import re

import httpx

from .base import BaseAnalyzer, AnalysisResult, Finding

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# each entry is (regex, vendor, product), matched against the banner grabbed from each open port
BANNER_PATTERNS: list[tuple[str, str, str]] = [
    (r"OpenSSH[_\s]([\d.p]+)", "openssh", "openssh"),
    (r"Apache[/\s]([\d.]+)", "apache", "http_server"),
    (r"nginx[/\s]([\d.]+)", "nginx", "nginx"),
    (r"Microsoft-IIS[/\s]([\d.]+)", "microsoft", "iis"),
    (r"ProFTPD[/\s]([\d.]+)", "proftpd", "proftpd"),
    (r"vsftpd[/\s]([\d.]+)", "vsftpd", "vsftpd"),
    (r"Exim[/\s]([\d.]+)", "exim", "exim"),
    (r"Postfix", "postfix", "postfix"),
    (r"MySQL[/\s]([\d.]+)", "mysql", "mysql"),
    (r"PostgreSQL[/\s]([\d.]+)", "postgresql", "postgresql"),
    (r"OpenSSL[/\s]([\d.a-zA-Z]+)", "openssl", "openssl"),
    (r"Redis[/\s]([\d.]+)", "redis", "redis"),
    (r"MongoDB[/\s]([\d.]+)", "mongodb", "mongodb"),
    (r"Dovecot", "dovecot", "dovecot"),
    (r"lighttpd[/\s]([\d.]+)", "lighttpd", "lighttpd"),
]

_CVSS_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class VulnAnalyzer(BaseAnalyzer):
    name = "vuln"

    def __init__(self, api_key: str | None, services: dict):
        self.api_key = api_key
        # services is a dict of open ports to their service name and raw banner from recon
        self.services = services

    def _fingerprint_services(self) -> list[dict]:
        found: list[dict] = []
        seen: set[tuple] = set()
        for port, info in self.services.items():
            banner = info.get("banner", "")
            for pattern, vendor, product in BANNER_PATTERNS:
                m = re.search(pattern, banner, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex else ""
                    key = (vendor, product, version)
                    if key not in seen:
                        seen.add(key)
                        found.append({
                            "vendor": vendor,
                            "product": product,
                            "version": version,
                            "port": port,
                            "banner_snippet": banner[:120],
                        })
        return found

    async def _query_nvd(self, client: httpx.AsyncClient, vendor: str, product: str, version: str) -> list[dict]:
        keyword = f"{vendor} {product} {version}".strip()
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            resp = await client.get(NVD_API, params=params, headers=headers, timeout=20)
            resp.raise_for_status()
            cves = []
            for item in resp.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # pull CVSS score, prefer v3.1 then v3.0 then v2 as fallback
                score, severity = None, "low"
                metrics = cve.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(key, [])
                    if entries:
                        cv = entries[0].get("cvssData", {})
                        score = cv.get("baseScore")
                        raw_sev = cv.get("baseSeverity") or entries[0].get("baseSeverity", "LOW")
                        severity = _CVSS_SEVERITY.get(raw_sev.upper(), "low")
                        break

                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                    "",
                )[:400]

                cves.append({"id": cve_id, "score": score, "severity": severity, "description": desc})
            return cves
        except Exception:
            return []

    async def analyze(self, target) -> AnalysisResult:
        software = self._fingerprint_services()
        findings: list[Finding] = []
        data: dict = {"software": software, "cves": []}

        if not software:
            data["note"] = "No identifiable software versions found in service banners."
            return AnalysisResult(module=self.name, target=target.raw, findings=findings, data=data)

        # Rate limits: 5 req/30s without key, 50 req/30s with key
        delay = 0.1 if self.api_key else 0.7

        async with httpx.AsyncClient() as client:
            for sw in software:
                cves = await self._query_nvd(client, sw["vendor"], sw["product"], sw["version"])
                for cve in cves:
                    entry = {**cve, "software": f"{sw['vendor']} {sw['product']} {sw['version']}".strip()}
                    data["cves"].append(entry)
                    findings.append(Finding(
                        title=f"{cve['id']} — {sw['product']} {sw['version']}".strip(" —"),
                        severity=cve["severity"],
                        detail=f"CVSS {cve['score']}. {cve['description']}",
                        recommendation=f"Review patch notes and update. Details: https://nvd.nist.gov/vuln/detail/{cve['id']}",
                        module=self.name,
                    ))
                await asyncio.sleep(delay)

        # same CVE can match multiple banners, only keep the first occurrence
        seen_ids: set[str] = set()
        deduped: list[Finding] = []
        for f in findings:
            cve_id = f.title.split(" ")[0]
            if cve_id not in seen_ids:
                seen_ids.add(cve_id)
                deduped.append(f)

        return AnalysisResult(module=self.name, target=target.raw, findings=deduped, data=data)
