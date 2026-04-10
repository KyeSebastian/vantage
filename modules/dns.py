import asyncio

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from .base import BaseAnalyzer, AnalysisResult, Finding


class DNSAnalyzer(BaseAnalyzer):
    name = "dns"

    async def analyze(self, target) -> AnalysisResult:
        if target.is_ip:
            return AnalysisResult(
                module=self.name,
                target=target.raw,
                error="DNS analysis skipped for raw IP addresses.",
            )

        host = target.hostname
        loop = asyncio.get_event_loop()
        findings: list[Finding] = []
        data: dict = {}

        checks = await asyncio.gather(
            loop.run_in_executor(None, self._check_spf, host),
            loop.run_in_executor(None, self._check_dmarc, host),
            loop.run_in_executor(None, self._check_dkim, host),
            loop.run_in_executor(None, self._check_zone_transfer, host),
            return_exceptions=True,
        )

        keys = ("spf", "dmarc", "dkim", "zone_transfer")
        for key, result in zip(keys, checks):
            if isinstance(result, Exception):
                data[key] = {"error": str(result)}
            else:
                data[key] = result["data"]
                for f in result["findings"]:
                    f.module = self.name
                findings.extend(result["findings"])

        return AnalysisResult(module=self.name, target=target.raw, findings=findings, data=data)

    # SPF check

    def _check_spf(self, host: str) -> dict:
        findings: list[Finding] = []
        data: dict = {}
        try:
            answers = dns.resolver.resolve(host, "TXT")
            spf_records = [
                r.to_text().strip('"')
                for r in answers
                if "v=spf1" in r.to_text()
            ]
            if not spf_records:
                findings.append(Finding(
                    title="No SPF record found",
                    severity="medium",
                    detail="No SPF TXT record exists. Attackers can spoof email from this domain.",
                    recommendation='Publish: v=spf1 include:your-provider.com ~all',
                ))
                data["record"] = None
            else:
                record = spf_records[0]
                data["record"] = record
                if len(spf_records) > 1:
                    findings.append(Finding(
                        title="Multiple SPF records found",
                        severity="high",
                        detail="Multiple TXT records with v=spf1 cause unpredictable evaluation and delivery failures.",
                        recommendation="Merge all SPF includes into a single record.",
                    ))
                if "-all" not in record and "~all" not in record:
                    findings.append(Finding(
                        title="SPF record has no enforcement qualifier",
                        severity="medium",
                        detail=f"Record: {record}. Missing -all or ~all means the policy does not reject spoofed mail.",
                        recommendation="End the SPF record with -all (hard fail) or ~all (soft fail).",
                    ))
        except dns.exception.DNSException as e:
            data["error"] = str(e)
        return {"findings": findings, "data": data}

    # DMARC check

    def _check_dmarc(self, host: str) -> dict:
        findings: list[Finding] = []
        data: dict = {}
        try:
            answers = dns.resolver.resolve(f"_dmarc.{host}", "TXT")
            records = [
                r.to_text().strip('"')
                for r in answers
                if "v=DMARC1" in r.to_text()
            ]
            if not records:
                findings.append(Finding(
                    title="No DMARC record found",
                    severity="high",
                    detail="Without DMARC, spoofed emails from this domain reach inboxes with no enforcement.",
                    recommendation='Publish: _dmarc.yourdomain.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com"',
                ))
                data["record"] = None
            else:
                record = records[0]
                data["record"] = record
                if "p=none" in record:
                    findings.append(Finding(
                        title="DMARC policy is set to 'none' (monitoring only)",
                        severity="medium",
                        detail=f"Record: {record}. p=none takes no action on failing mail.",
                        recommendation="Upgrade to p=quarantine then p=reject after reviewing aggregate reports.",
                    ))
                if "rua=" not in record:
                    findings.append(Finding(
                        title="DMARC aggregate reporting (rua) not configured",
                        severity="info",
                        detail="No rua= tag — you receive no reports about authentication failures.",
                        recommendation="Add rua=mailto:dmarc@yourdomain.com to receive aggregate reports.",
                    ))
        except dns.resolver.NXDOMAIN:
            findings.append(Finding(
                title="No DMARC record found",
                severity="high",
                detail="_dmarc DNS record does not exist for this domain.",
                recommendation='Publish a DMARC policy at _dmarc.yourdomain.com.',
            ))
            data["record"] = None
        except dns.exception.DNSException as e:
            data["error"] = str(e)
        return {"findings": findings, "data": data}

    # DKIM check

    def _check_dkim(self, host: str) -> dict:
        findings: list[Finding] = []
        data: dict = {}
        selectors = ["default", "google", "selector1", "selector2", "mail", "dkim", "k1", "smtp"]
        found = []
        for sel in selectors:
            try:
                answers = dns.resolver.resolve(f"{sel}._domainkey.{host}", "TXT")
                for r in answers:
                    txt = r.to_text().strip('"')
                    if "v=DKIM1" in txt:
                        found.append({"selector": sel, "record": txt[:300]})
            except dns.exception.DNSException:
                pass

        data["found_selectors"] = found
        data["checked_selectors"] = selectors
        if not found:
            findings.append(Finding(
                title="No DKIM records found (common selectors checked)",
                severity="medium",
                detail=f"Checked selectors: {', '.join(selectors)}. None returned a valid DKIM1 record.",
                recommendation="Configure DKIM signing in your mail provider and publish the public key TXT record.",
            ))
        return {"findings": findings, "data": data}

    # zone transfer check

    def _check_zone_transfer(self, host: str) -> dict:
        findings: list[Finding] = []
        data: dict = {"vulnerable_ns": [], "ns_servers": []}
        try:
            ns_answers = dns.resolver.resolve(host, "NS")
            ns_servers = [str(r.target).rstrip(".") for r in ns_answers]
            data["ns_servers"] = ns_servers
            for ns in ns_servers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, host, timeout=5))
                    names = [str(n) for n in zone.nodes.keys()]
                    data["vulnerable_ns"].append({"ns": ns, "record_count": len(names), "sample": names[:10]})
                    findings.append(Finding(
                        title=f"DNS zone transfer (AXFR) allowed by {ns}",
                        severity="high",
                        detail=f"AXFR query to {ns} succeeded, exposing {len(names)} DNS names.",
                        recommendation="Restrict AXFR to authorized secondary nameservers only.",
                    ))
                except Exception:
                    pass
        except dns.exception.DNSException as e:
            data["error"] = str(e)
        return {"findings": findings, "data": data}
