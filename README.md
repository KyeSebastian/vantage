# Vantage

A command line security assessment tool written in Python. Point it at a domain or IP, it runs six checks concurrently and outputs a self-contained HTML report with a security grade and prioritized list of findings.

Open `sample-report.html` in this repo to see real output without running anything. It is a scan of `scanme.nmap.org`, a host maintained by the Nmap project for exactly this purpose. It is intentionally misconfigured.

## What it checks

**Recon** scans the top 1000 ports using async TCP connects, grabs service banners, and guesses the OS from the ICMP TTL. It flags anything dangerous that is exposed publicly, things like Telnet, RDP, Redis without auth, the Docker API, and MongoDB, with severity ratings and remediation steps.

**Vulnerability Mapper** reads the service banners for software names and versions, then queries the NIST National Vulnerability Database for matching CVEs. If it cannot pull a version from the banner it skips that port because a versionless query returns thousands of results that mean nothing.

**TLS Inspector** connects to HTTPS ports and checks the certificate and cipher configuration. It flags expired or self-signed certs, deprecated protocol versions (TLS 1.0 and 1.1 have known real-world attacks, not just theoretical ones), and weak cipher suites like RC4 and DES.

**HTTP Headers** makes a GET request and checks the response against the headers that matter: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy. It also catches headers that leak server info because version strings in Server or X-Powered-By give attackers a starting point.

**DNS Analyzer** checks SPF, DMARC, DKIM, and whether any nameserver allows a full zone transfer. A missing DMARC record means spoofed emails from your domain land in inboxes with no enforcement. A zone transfer that succeeds gives an attacker your entire infrastructure map from one query. This module is skipped automatically on raw IPs.

**Risk Scorer** aggregates all findings, applies a penalty model by severity, and outputs a host grade from A to F with a score out of 100. The report leads with the worst findings first.

## Usage

```bash
pip install -r requirements.txt

python vantage.py scanme.nmap.org
python vantage.py scanme.nmap.org --ports 22,80,443
python vantage.py scanme.nmap.org --ports 1-1024
python vantage.py scanme.nmap.org --out results/scan.html
python vantage.py 192.168.1.1
```

NVD API keys are free at nvd.nist.gov/developers/request-an-api-key and raise the rate limit from 5 to 50 requests per 30 seconds.

```bash
python vantage.py scanme.nmap.org --nvd-key YOUR_KEY
```

## Stack

Python 3.12, asyncio, httpx, dnspython, jinja2

## Structure

```
vantage.py
scanner/
    engine.py       orchestrates the three-phase scan
    target.py       parses and resolves the input
modules/
    recon.py        port scan and service fingerprinting
    vuln.py         NVD CVE lookup
    tls.py          certificate and cipher inspection
    headers.py      HTTP security header checks
    dns.py          SPF, DMARC, DKIM, zone transfer
    risk.py         scoring and grade calculation
    report.py       HTML report renderer
templates/
    report.html.j2  report template
tests/
    test_risk.py    risk scorer tests
    test_target.py  input parser tests
```
