import asyncio
from typing import Optional

from modules.base import AnalysisResult
from modules.recon import ReconAnalyzer
from modules.tls import TLSAnalyzer
from modules.headers import HeadersAnalyzer
from modules.dns import DNSAnalyzer
from modules.vuln import VulnAnalyzer
from modules.risk import RiskScorer
from scanner.target import Target


def _guard(result, module: str, target_raw: str) -> AnalysisResult:
    # asyncio.gather returns exceptions as values when return_exceptions=True
    if isinstance(result, Exception):
        return AnalysisResult(module=module, target=target_raw, error=str(result))
    return result


class ScanEngine:
    def __init__(
        self,
        target: Target,
        ports: list[int],
        nvd_api_key: Optional[str] = None,
        timeout: float = 1.0,
        concurrency: int = 500,
    ):
        self.target = target
        self.ports = ports
        self.nvd_api_key = nvd_api_key
        self.timeout = timeout
        self.concurrency = concurrency

    @staticmethod
    def _ok(label: str, detail: str) -> None:
        print(f"  [+] {label:<26} {detail}")

    @staticmethod
    def _skip(label: str, reason: str) -> None:
        print(f"  [!] {label:<26} {reason}")

    async def run(self) -> dict[str, AnalysisResult]:
        results: dict[str, AnalysisResult] = {}
        t = self.target

        # phase 1 - recon and dns run concurrently, dns only needs the domain not port results
        phase1_coros = [
            ReconAnalyzer(self.ports, timeout=self.timeout, concurrency=self.concurrency).analyze(t),
        ]
        if not t.is_ip:
            phase1_coros.append(DNSAnalyzer().analyze(t))

        phase1 = await asyncio.gather(*phase1_coros, return_exceptions=True)
        results["recon"] = _guard(phase1[0], "recon", t.raw)
        if not t.is_ip:
            results["dns"] = _guard(phase1[1], "dns", t.raw)

        open_ports: set[int] = set(results["recon"].data.get("open_ports", {}).keys())
        services: dict = results["recon"].data.get("open_ports", {})

        if results["recon"].error:
            self._skip("Recon Engine", results["recon"].error)
        else:
            self._ok("Recon Engine", f"{len(open_ports)} open port(s) found")

        if not t.is_ip:
            dns_result = results.get("dns")
            if dns_result and dns_result.error:
                self._skip("DNS Analyzer", dns_result.error)
            else:
                finding_count = len(dns_result.findings) if dns_result else 0
                self._ok("DNS Analyzer", f"{finding_count} finding(s)")
        else:
            self._skip("DNS Analyzer", "skipped (raw IP)")

        # phase 2 - tls, headers, vuln all run concurrently once we have the open port list
        phase2_coros = []
        phase2_keys: list[str] = []

        has_https = bool(open_ports & {443, 8443})
        has_http = bool(open_ports & {80, 443, 8080, 8443})

        if has_https:
            phase2_coros.append(TLSAnalyzer().analyze(t))
            phase2_keys.append("tls")

        if has_http:
            phase2_coros.append(HeadersAnalyzer().analyze(t))
            phase2_keys.append("headers")

        if services:
            phase2_coros.append(VulnAnalyzer(self.nvd_api_key, services).analyze(t))
            phase2_keys.append("vuln")

        if phase2_coros:
            phase2 = await asyncio.gather(*phase2_coros, return_exceptions=True)
            for key, result in zip(phase2_keys, phase2):
                results[key] = _guard(result, key, t.raw)

        if "tls" in results:
            r = results["tls"]
            if r.error and not r.data:
                self._skip("TLS Inspector", r.error)
            else:
                proto = r.data.get("protocol", "unknown")
                days = r.data.get("days_until_expiry")
                cert_info = f"{proto}, cert valid {days}d" if days is not None else proto
                self._ok("TLS Inspector", cert_info)
        elif not has_https:
            self._skip("TLS Inspector", "no HTTPS port open")

        if "headers" in results:
            r = results["headers"]
            if r.error and not r.data:
                self._skip("HTTP Headers", r.error)
            else:
                self._ok("HTTP Headers", f"{len(r.findings)} finding(s)")
        elif not has_http:
            self._skip("HTTP Headers", "no HTTP port open")

        if "vuln" in results:
            r = results["vuln"]
            cve_count = len(r.data.get("cves", []))
            note = r.data.get("note", "")
            if note:
                self._skip("Vulnerability Mapper", note)
            else:
                self._ok("Vulnerability Mapper", f"{cve_count} CVE(s) matched")
        elif not services:
            self._skip("Vulnerability Mapper", "no open ports")

        # phase 3 - aggregate everything into a score
        results["risk"] = RiskScorer(results).score()
        grade = results["risk"].data.get("grade", "?")
        score = results["risk"].data.get("score", 0)
        total = results["risk"].data.get("total_findings", 0)
        self._ok("Risk Scorer", f"grade {grade}  ({score}/100)  {total} findings")

        return results
