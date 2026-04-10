import httpx

from .base import BaseAnalyzer, AnalysisResult, Finding

# Header name → (severity, title, detail, recommendation)
REQUIRED_HEADERS: dict[str, tuple[str, str, str, str]] = {
    "strict-transport-security": (
        "medium",
        "Missing Strict-Transport-Security (HSTS)",
        "Browsers may connect over insecure HTTP; HSTS is not enforced.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    "x-frame-options": (
        "medium",
        "Missing X-Frame-Options",
        "Pages can be embedded in iframes, enabling clickjacking attacks.",
        "Add: X-Frame-Options: DENY  (or SAMEORIGIN if embedding is required internally)",
    ),
    "x-content-type-options": (
        "low",
        "Missing X-Content-Type-Options",
        "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    "content-security-policy": (
        "medium",
        "Missing Content-Security-Policy (CSP)",
        "No CSP defined. XSS attacks have maximum impact without a restrictive policy.",
        "Define a strict CSP suited to your application. Start with default-src 'self'.",
    ),
    "referrer-policy": (
        "low",
        "Missing Referrer-Policy",
        "Referrer information may leak to third-party origins.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "permissions-policy": (
        "info",
        "Missing Permissions-Policy",
        "Browser features (camera, microphone, geolocation) are unrestricted.",
        "Add a Permissions-Policy header to disable features your app does not use.",
    ),
}

# Headers whose presence leaks server info
DISCLOSURE_HEADERS: dict[str, str] = {
    "server": "Exposes server software and version, aiding targeted exploitation.",
    "x-powered-by": "Reveals application framework, enabling targeted vulnerability research.",
    "x-aspnet-version": "Reveals .NET runtime version.",
    "x-aspnetmvc-version": "Reveals ASP.NET MVC version.",
    "x-generator": "Reveals the CMS or framework used to generate the page.",
}


class HeadersAnalyzer(BaseAnalyzer):
    name = "headers"

    async def analyze(self, target) -> AnalysisResult:
        host = target.hostname or target.ip
        findings: list[Finding] = []
        data: dict = {}

        # Try HTTPS first, fall back to HTTP
        response = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
                    response = await client.get(url)
                data["url"] = str(response.url)
                data["status_code"] = response.status_code
                data["final_scheme"] = str(response.url).split("://")[0]
                data["headers_present"] = dict(response.headers)
                break
            except Exception as e:
                data["error"] = str(e)

        if response is None:
            return AnalysisResult(module=self.name, target=target.raw, findings=findings, data=data)

        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # check for missing security headers
        for header, (severity, title, detail, rec) in REQUIRED_HEADERS.items():
            if header not in headers_lower:
                findings.append(Finding(
                    title=title,
                    severity=severity,
                    detail=detail,
                    recommendation=rec,
                    module=self.name,
                ))

        # check for headers that leak server info
        for header, reason in DISCLOSURE_HEADERS.items():
            if header in headers_lower:
                findings.append(Finding(
                    title=f"Server information disclosed via {header!r} header",
                    severity="low",
                    detail=f"Value: {headers_lower[header]!r}. {reason}",
                    recommendation=f"Remove or suppress the {header!r} header in your server/proxy config.",
                    module=self.name,
                ))

        # flag if still on http after following redirects
        if data.get("final_scheme") == "http":
            findings.append(Finding(
                title="Site served over HTTP without redirect to HTTPS",
                severity="medium",
                detail="The server responded to an HTTP request without redirecting to HTTPS.",
                recommendation="Configure a permanent 301 redirect from HTTP to HTTPS.",
                module=self.name,
            ))

        return AnalysisResult(module=self.name, target=target.raw, findings=findings, data=data)
