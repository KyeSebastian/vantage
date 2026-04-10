# Vantage — External Security Assessment Tool

A Python CLI tool that runs a full external security assessment against a domain or IP address and produces a self-contained HTML findings report. One command, one report.

---

## What It Does

Vantage runs six assessment modules concurrently and aggregates the results into a prioritized findings list with a host security grade (A–F).

**Recon Engine**
Async TCP connect scan across the top 1000 ports. Banner grabbing on open ports for service identification. OS fingerprinting via ICMP TTL. Flags high-risk services exposed to the internet — Telnet, RDP, Redis, Docker API, MongoDB, and others — with severity ratings and remediation guidance.

**Vulnerability Mapper**
Parses service banners for software name and version. Queries the NIST National Vulnerability Database (NVD) API for matching CVEs. Returns CVSS v3 scores and severity for each match. Skips ports where no version can be identified — a query with no version returns noise, not signal.

**TLS Inspector**
Connects to HTTPS ports and extracts certificate and cipher details. Flags expired or self-signed certificates, deprecated protocol versions (TLS 1.0 / 1.1), and weak cipher suites (RC4, DES, NULL, EXPORT-grade). TLS 1.0 and 1.1 have known practical attacks — POODLE, BEAST — not just theoretical ones.

**HTTP Headers**
Issues a GET request to web ports and checks the response headers against a required set. Missing headers and what they allow:

| Header | Missing means |
|---|---|
| Strict-Transport-Security | SSL stripping via SSLstrip |
| Content-Security-Policy | XSS has maximum impact |
| X-Frame-Options | Clickjacking |
| X-Content-Type-Options | MIME sniffing attacks |
| Referrer-Policy | URL leakage to third parties |

Also flags information disclosure headers (`Server`, `X-Powered-By`, `X-Generator`) that hand attackers a starting point for targeted exploitation.

**DNS Analyzer**
Checks email authentication and zone security controls for the target domain:
- **SPF** — missing means anyone can spoof email from this domain
- **DMARC** — missing means spoofed emails reach inboxes with no enforcement. A direct path to business email compromise.
- **DKIM** — checks eight common selectors for a valid signing key
- **Zone Transfer (AXFR)** — if a nameserver responds, an attacker maps the entire infrastructure from one query

Skipped automatically when the target is a raw IP address.

**Risk Scorer**
Aggregates all findings across modules, applies a CVSS-weighted penalty model, and outputs a host security grade (A–F) with a 0–100 score. Findings are sorted by severity — Critical, High, Medium, Low, Info — so the report leads with what to fix first, not an alphabetical list of everything wrong.

---

## Sample Report

`sample-report.html` in this repo is a real scan of `scanme.nmap.org` — a host maintained by the Nmap project specifically for security tool testing. It is intentionally misconfigured. Open it in a browser to see full output without running the tool.

---

## Usage

```bash
pip install -r requirements.txt

# Basic scan
python vantage.py example.com

# Scan with custom ports
python vantage.py example.com --ports 22,80,443,8080

# Scan a port range
python vantage.py example.com --ports 1-1024

# Specify output path
python vantage.py example.com --out reports/example_scan.html

# Raw IP — DNS module is skipped automatically
python vantage.py 192.168.1.1

# With NVD API key (higher rate limit for CVE lookups)
python vantage.py example.com --nvd-key YOUR_KEY
```

NVD API keys are free at https://nvd.nist.gov/developers/request-an-api-key

---

## Project Structure

```
vantage.py          # CLI entry point — argument parsing, banner, report output
scanner/
  engine.py         # Orchestrator — runs modules in phases, collects results
  target.py         # Input parsing — resolves domain/IP, detects type
modules/
  base.py           # Shared dataclasses: Finding, AnalysisResult, BaseAnalyzer
  recon.py          # Port scan, banner grab, OS fingerprint, risky service flags
  vuln.py           # NVD API CVE lookup via banner fingerprinting
  tls.py            # Certificate inspection, protocol version, cipher suite
  headers.py        # HTTP security header checks, information disclosure
  dns.py            # SPF, DMARC, DKIM, zone transfer
  risk.py           # Penalty scoring, grade calculation, findings aggregation
  report.py         # Jinja2 HTML report renderer
templates/
  report.html.j2    # Self-contained report template — no external dependencies
reports/            # Scan output directory
tests/
  test_risk.py      # Adversarial tests — grade boundaries, scoring, attribution
  test_target.py    # Adversarial tests — input parsing, edge cases
```

---

## Tech Stack

- **Python 3.12** — asyncio for concurrent scanning and module execution
- **httpx** — async HTTP client for header checks and NVD API queries
- **dnspython** — DNS record resolution and zone transfer attempts
- **jinja2** — HTML report generation
- **asyncio** — three-phase concurrent execution: recon → assessment modules → scoring
