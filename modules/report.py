from pathlib import Path
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportGenerator:
    def __init__(self, template_dir: str = "templates"):
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html"]),
        )

    def render(self, target, results: dict, out_path: Path) -> None:
        template = self.env.get_template("report.html.j2")
        html = template.render(
            target=target,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            risk=results.get("risk"),
            recon=results.get("recon"),
            tls=results.get("tls"),
            headers=results.get("headers"),
            dns=results.get("dns"),
            vuln=results.get("vuln"),
        )
        out_path.write_text(html, encoding="utf-8")
