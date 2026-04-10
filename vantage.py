#!/usr/bin/env python3
import argparse
import asyncio
import sys
from datetime import datetime
from pathlib import Path

from modules.report import ReportGenerator
from scanner.engine import ScanEngine
from scanner.target import Target

TOP_100_PORTS = sorted({
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    636, 993, 995, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 5984,
    6379, 8080, 8443, 8888, 9000, 9200, 9300, 27017, 28017,
    2222, 4000, 4200, 4848, 5000, 5601, 7001, 7002, 8000, 8009, 8090,
    8161, 8500, 9090, 9443, 10000, 11211, 50070,
})


def _resolve_ports(spec: str) -> list[int]:
    if spec == "top100":
        return TOP_100_PORTS
    if spec == "top1000":
        return list(range(1, 1001))
    try:
        return sorted({int(p.strip()) for p in spec.split(",")})
    except ValueError:
        print(f"[!] Invalid port spec {spec!r}. Use 'top100', 'top1000', or '22,80,443'.")
        sys.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vantage",
        description="Vantage — External security assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vantage example.com
  vantage 192.168.1.1 --ports 22,80,443,8080
  vantage example.com --nvd-key YOUR_KEY --out reports/scan.html
  vantage example.com --ports top1000 --timeout 0.5
        """,
    )
    p.add_argument("target", help="Domain name or IP address to assess")
    p.add_argument(
        "--ports", "-p",
        default="top1000",
        metavar="SPEC",
        help="Ports to scan: 'top100' | 'top1000' | comma-separated list (default: top1000)",
    )
    p.add_argument(
        "--nvd-key",
        metavar="KEY",
        default=None,
        help="NVD API key — increases CVE lookup rate limit (optional)",
    )
    p.add_argument(
        "--out", "-o",
        metavar="FILE",
        default=None,
        help="HTML report output path (default: reports/<target>_<timestamp>.html)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        metavar="SEC",
        help="TCP connect timeout in seconds (default: 1.0)",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=500,
        metavar="N",
        help="Max concurrent port scan connections (default: 500)",
    )
    return p


async def main() -> None:
    args = _build_parser().parse_args()

    print()
    print("  +----------------------------------+")
    print("  |   Vantage - Security Assessment  |")
    print("  +----------------------------------+")
    print(f"  Target  : {args.target}")
    print(f"  Ports   : {args.ports}")
    print(f"  NVD API : {'keyed (higher rate limit)' if args.nvd_key else 'anonymous (rate limited)'}")
    print()

    try:
        target = Target.from_string(args.target)
    except ValueError as e:
        print(f"  [!] {e}")
        sys.exit(1)

    print(f"  Resolved  : {target.ip}" + (f"  ({target.hostname})" if target.hostname else ""))
    print(f"  DNS scan  : {'yes' if not target.is_ip else 'skipped (raw IP)'}")
    print()

    ports = _resolve_ports(args.ports)
    engine = ScanEngine(
        target,
        ports=ports,
        nvd_api_key=args.nvd_key,
        timeout=args.timeout,
        concurrency=args.concurrency,
    )

    results = await engine.run()

    # Determine output path
    if args.out:
        out_path = Path(args.out)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = args.target.replace(".", "_").replace(":", "_").replace("/", "_")
        out_path = Path("reports") / f"{safe}_{ts}.html"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    ReportGenerator().render(target, results, out_path)

    risk = results.get("risk")
    grade = risk.data.get("grade", "?") if risk else "?"
    score = risk.data.get("score", 0) if risk else 0
    total = risk.data.get("total_findings", 0) if risk else 0

    print()
    print(f"  Grade    : {grade}  ({score}/100)")
    print(f"  Findings : {total}")
    print(f"  Report   : {out_path}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
