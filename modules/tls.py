import asyncio
import socket
import ssl
from datetime import datetime, timezone

from .base import BaseAnalyzer, AnalysisResult, Finding

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_KEYWORDS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5"}


class TLSAnalyzer(BaseAnalyzer):
    name = "tls"

    def _get_cert_info(self, host: str, verify: bool) -> dict:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, 443), timeout=8) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    cipher_name, proto, bits = tls.cipher()
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "protocol": proto,
                        "cipher_name": cipher_name,
                        "cipher_bits": bits,
                        "san": [v for _, v in cert.get("subjectAltName", [])],
                        "self_signed": subject == issuer,
                    }
        except ssl.SSLCertVerificationError:
            raise
        except Exception as e:
            return {"error": str(e)}

    async def analyze(self, target) -> AnalysisResult:
        host = target.hostname or target.ip
        loop = asyncio.get_running_loop()
        findings: list[Finding] = []
        data: dict = {}

        # First attempt with verification; on cert error retry without to gather info
        try:
            info = await loop.run_in_executor(None, self._get_cert_info, host, True)
        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                title="TLS certificate validation failed",
                severity="high",
                detail=str(e),
                recommendation="Ensure the certificate is valid and issued by a trusted CA.",
                module=self.name,
            ))
            try:
                info = await loop.run_in_executor(None, self._get_cert_info, host, False)
            except Exception:
                info = {"error": str(e)}

        if "error" in info and not any(k for k in info if k != "error"):
            data["error"] = info["error"]
            return AnalysisResult(module=self.name, target=target.raw, findings=findings, data=data)

        data.update(info)

        # certificate expiry
        not_after = info.get("not_after")
        if not_after:
            try:
                expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expires - datetime.now(timezone.utc)).days
                data["days_until_expiry"] = days_left
                if days_left < 0:
                    findings.append(Finding(
                        title="TLS certificate has expired",
                        severity="critical",
                        detail=f"Certificate expired {abs(days_left)} day(s) ago ({not_after}).",
                        recommendation="Renew the certificate immediately.",
                        module=self.name,
                    ))
                elif days_left < 14:
                    findings.append(Finding(
                        title="TLS certificate expiring within 14 days",
                        severity="high",
                        detail=f"Certificate expires in {days_left} day(s) ({not_after}).",
                        recommendation="Renew the certificate now.",
                        module=self.name,
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        title="TLS certificate expiring within 30 days",
                        severity="medium",
                        detail=f"Certificate expires in {days_left} day(s) ({not_after}).",
                        recommendation="Schedule certificate renewal.",
                        module=self.name,
                    ))
            except ValueError:
                pass

        # protocol version check
        proto = info.get("protocol", "")
        if proto in WEAK_PROTOCOLS:
            findings.append(Finding(
                title=f"Deprecated TLS protocol negotiated: {proto}",
                severity="high",
                detail=f"The server accepted a connection using {proto}, which has known vulnerabilities.",
                recommendation="Disable TLSv1.0 and TLSv1.1 in your server config; require TLSv1.2+.",
                module=self.name,
            ))

        # cipher suite check
        cipher_name = info.get("cipher_name", "")
        for keyword in WEAK_CIPHER_KEYWORDS:
            if keyword in cipher_name.upper():
                findings.append(Finding(
                    title=f"Weak cipher suite in use: {cipher_name}",
                    severity="high",
                    detail=f"Cipher contains {keyword!r}, which is cryptographically weak.",
                    recommendation="Configure server to prefer ECDHE+AES256+GCM suites.",
                    module=self.name,
                ))
                break

        # self-signed check
        if info.get("self_signed"):
            findings.append(Finding(
                title="Self-signed TLS certificate",
                severity="medium",
                detail="Certificate is signed by itself, not a trusted CA. Browsers will warn users.",
                recommendation="Obtain a certificate from a trusted CA (e.g., Let's Encrypt).",
                module=self.name,
            ))

        return AnalysisResult(module=self.name, target=target.raw, findings=findings, data=data)
