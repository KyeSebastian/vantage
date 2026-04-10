# Vantage

A command line security assessment tool written in Python. Point it at a domain or IP, it runs six checks concurrently and outputs a self-contained HTML report with a security grade and prioritized list of findings.

Open `sample-report.html` in this repo to see real output without running anything. It's a scan of `scanme.nmap.org`, a host maintained by the Nmap project for exactly this purpose — it's intentionally misconfigured.

## What it checks

**Recon** scans the top 1000 ports using async TCP connects, grabs service banners, and guesses the OS from the ICMP TTL. It flags anything dangerous that's exposed — Telnet, RDP, Redis without auth, the Docker API, MongoDB — with severity ratings and what to do about each one.

**Vulnerability Mapper** reads the service banners for software names and versions, then queries the NIST National Vulnerability Database for matching CVEs. If it can't pull a version from the banner it skips that port — a versionless query returns thousands of results that mean nothing.

**TLS Inspector** connects to HTTPS ports and checks the certificate and cipher configuration. It flags expired or self-signed certs, deprecated protocol versions (TLS 1.0 and 1.1 have known real-world attacks, not just theoretical ones), and weak cipher suites like RC4 and DES.

**HTTP Headers** makes a GET request and checks the response against the headers that matter: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy. It also catches headers that leak server info — version strings in `Server` or `X-Powered-By` hand attackers a starting point.

**DNS Analyzer** checks SPF, DMARC, DKIM, and whether any nameserver allows a full zone transfer. A missing DMARC record means spoofed emails from your domain land in inboxes with no enforcement. A zone transfer that succeeds hands an attacker your entire infrastructure map from one query. Skipped automatically on raw IPs.

**Risk Scorer** aggregates all findings, applies a penalty model by severity, and outputs a host grade from A to F with a 0 to 100 score. The report leads with the worst findings first.

## Usage

```bash
pip install -r requirements.txt

python vantage.py example.com
python vantage.py example.com --ports 22,80,443
python vantage.py example.com --ports 1-1024
python vantage.py example.com --out results/scan.html
python vantage.py 192.168.1.1
```

NVD API keys are free at nvd.nist.gov/developers/request-an-api-key and raise the rate limit from 5 to 50 requests per 30 seconds.

```bash
python vantage.py example.com --nvd-key YOUR_KEY
```

## Stack

Python 3.12, asyncio, httpx, dnspython, jinja2

## Structure

```
vantage.py            entry point
scanner/engine.py     orchestrates the three-phase scan
scanner/target.py     parses and resolves the input
modules/recon.py      port scan and service fingerprinting
modules/vuln.py       NVD CVE lookup
modules/tls.py        certificate and cipher inspection
modules/headers.py    HTTP security header checks
modules/dns.py        SPF, DMARC, DKIM, zone transfer
modules/risk.py       scoring and grade calculation
modules/report.py     HTML report renderer
templates/            jinja2 report template
tests/                unit tests for risk scorer and target parser
```
