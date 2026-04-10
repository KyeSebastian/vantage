# Vantage

A command line security assessment tool written in Python. Point it at a domain or IP, it runs six checks concurrently and outputs a self-contained HTML report with a security grade and prioritized list of findings.

Open `sample-report.html` in this repo to see real output without running anything. It is a scan of `scanme.nmap.org`, a host maintained by the Nmap project for exactly this purpose. It is intentionally misconfigured.

## What it checks

**Recon** scans the top 1000 ports, grabs service banners, and fingerprints the OS via ICMP TTL. Flags high-risk services exposed to the internet with severity ratings and remediation steps.

**Vulnerability Mapper** parses banners for software versions and queries the NVD API for matching CVEs. Skips any port where no version can be identified.

**TLS Inspector** checks certificate validity, protocol version, and cipher suite. Flags expired certs, TLS 1.0/1.1, and weak ciphers like RC4 and DES.

**HTTP Headers** checks the response headers against the standard security set and flags anything leaking server version info.

**DNS Analyzer** checks SPF, DMARC, DKIM, and zone transfer exposure. Skipped automatically on raw IPs.

**Risk Scorer** aggregates findings across all modules, scores by severity, and outputs a host grade from A to F.

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
