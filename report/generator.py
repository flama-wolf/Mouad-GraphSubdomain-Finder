"""
Report generator logic.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.normalizer import Node
from core.correlator import Edge

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """Generates the final report."""

    def __init__(
        self,
        target:          str,
        nodes:           dict[str, Node],
        edges:           list[Edge],
        source_stats:    dict[str, int],
        type_counts:     dict[str, int],
        graph_html_path: Path,
        output_dir:      Path,
        elapsed:         float = 0.0,
    ):
        self.target          = target
        self.nodes           = nodes
        self.edges           = edges
        self.source_stats    = source_stats
        self.type_counts     = type_counts
        self.graph_html_path = Path(graph_html_path)
        self.output_dir      = Path(output_dir)
        self.elapsed         = elapsed
        self._ts             = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._generated_at   = self._ts

    def generate(self) -> Path:
        """Render and write the HTML report. Returns report path."""
        ctx = self._build_context()

        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        template = env.get_template("report.html")
        html     = template.render(**ctx)

        report_path = self.output_dir / "report.html"
        report_path.write_text(html, encoding="utf-8")

        json_path = self.output_dir / "data.json"
        self._write_json(json_path, ctx)

        logger.info("[report] HTML report saved: %s", report_path)
        logger.info("[report] JSON data saved: %s", json_path)
        return report_path


    def _build_context(self) -> dict:
        subdomains = []
        ips        = []
        urls       = []
        emails     = []
        leaks      = []

        for key, node in self.nodes.items():
            row = {
                "value":   node.value,
                "sources": ", ".join(node.sources),
                "meta":    node.metadata,
            }
            if node.type == "subdomain":
                row["ip"] = node.metadata.get("ip", "—")
                subdomains.append(row)
            elif node.type == "ip":
                row["resolved_from"] = node.metadata.get("resolved_from", "—")
                row["country"]       = node.metadata.get("country", "—")
                ips.append(row)
            elif node.type == "url":
                row["hostname"]      = node.metadata.get("hostname", "—")
                row["leak"]          = node.metadata.get("leak_indicator", False)
                urls.append(row)
                if node.metadata.get("leak_indicator"):
                    leaks.append(row)
            elif node.type == "email":
                emails.append(row)

        subdomains.sort(key=lambda x: x["value"])
        ips.sort(key=lambda x: x["value"])

        # Embed graph HTML inline (iframe-less approach)
        graph_html_content = ""
        try:
            graph_html_content = self.graph_html_path.read_text(encoding="utf-8")
        except OSError:
            logger.warning("[report] Could not read graph HTML: %s", self.graph_html_path)

        return {
            "target":             self.target,
            "generated_at":       self._generated_at,
            "elapsed":            f"{self.elapsed:.1f}",
            "total_nodes":        len(self.nodes),
            "total_edges":        len(self.edges),
            "subdomains":         subdomains,
            "ips":                ips,
            "urls":               urls[:200],   # cap for HTML performance
            "emails":             emails,
            "leaks":              leaks,
            "source_stats":       self.source_stats,
            "type_counts":        self.type_counts,
            "graph_html":         graph_html_content,
            "subdomain_count":    len(subdomains),
            "ip_count":           len(ips),
            "url_count":          len(urls),
            "email_count":        len(emails),
            "leak_count":         len(leaks),
        }

    def _write_json(self, path: Path, ctx: dict) -> None:
        export = {
            "meta": {
                "target":       ctx["target"],
                "generated_at": ctx["generated_at"],
                "elapsed_sec":  ctx["elapsed"],
                "total_nodes":  ctx["total_nodes"],
                "total_edges":  ctx["total_edges"],
            },
            "summary": {
                "subdomains": ctx["subdomain_count"],
                "ips":        ctx["ip_count"],
                "urls":       ctx["url_count"],
                "emails":     ctx["email_count"],
                "leaks":      ctx["leak_count"],
            },
            "source_stats":  ctx["source_stats"],
            "type_counts":   ctx["type_counts"],
            "subdomains":    ctx["subdomains"],
            "ips":           ctx["ips"],
            "emails":        ctx["emails"],
            "leaks":         ctx["leaks"],
        }
        path.write_text(json.dumps(export, indent=2, default=str), encoding="utf-8")
