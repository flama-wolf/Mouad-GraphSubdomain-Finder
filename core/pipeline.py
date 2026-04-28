"""
Main pipeline logic.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich import print as rprint
from typing import Optional, List

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

from collectors.crtsh      import CrtShCollector
from collectors.gau        import GauCollector
from collectors.passive_dns import CirclPDNSCollector
from collectors.certspotter import CertSpotterCollector
from collectors.hackertarget import HackerTargetCollector
from collectors.otx        import OTXCollector
from collectors.urlscan    import UrlScanCollector
from collectors.github_search import GitHubCollector

from core.cache      import Cache
from core.normalizer import Normalizer
from core.correlator import Correlator

from graph.builder  import GraphBuilder
from graph.exporter import GraphExporter
from report.generator import ReportGenerator

logger = logging.getLogger(__name__)
console = Console(highlight=False)

ALL_COLLECTORS = [
    CrtShCollector,
    GauCollector,
    CirclPDNSCollector,
    CertSpotterCollector,
    HackerTargetCollector,
    OTXCollector,
    UrlScanCollector,
    GitHubCollector,
]


class Pipeline:
    """
    Main pipeline for running collectors and processing results.
    """

    def __init__(
        self,
        target: str,
        collectors: Optional[List] = None,
        resolve_ips: bool = True,
        use_cache: bool = True,
        output_dir: Optional[Path] = None,
    ):
        self.target      = target.lower().strip()
        self.use_cache   = use_cache
        self.resolve_ips = resolve_ips

        # Each scan gets its own timestamped subfolder: output/{domain}_{ts}/
        from datetime import datetime
        self._ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_output = Path(output_dir or config.OUTPUT_DIR)
        self.output_dir = base_output / f"{self.target}_{self._ts}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._cache      = Cache()
        self._collector_classes = collectors or ALL_COLLECTORS

    async def run(self) -> dict:
        start_time = time.time()
        console.rule(f"[bold cyan]Mouad-Subdomain finder passive  >>  Target: {self.target}[/bold cyan]")

        # Collection
        all_raw: list[dict] = []
        source_stats: dict[str, int] = {}

        instances = [cls() for cls in self._collector_classes]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running collectors...", total=len(instances))

            semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_COLLECTORS)

            async def _run_one(collector):
                async with semaphore:
                    name = collector.name
                    try:
                        if self.use_cache:
                            cached = self._cache.get(name, self.target)
                            if cached is not None:
                                console.log(f"[dim]  <- [cyan]{name}[/cyan] (cached: {len(cached)} items)")
                                return name, cached

                        findings = await collector.run(self.target)
                        if self.use_cache:
                            self._cache.set(name, self.target, findings)
                        console.log(f"  [green]OK[/green] {name} -> {len(findings)} findings")
                        return name, findings
                    except Exception as exc:
                        console.log(f"  [red]FAIL {name}: {exc}[/red]")
                        return name, []
                    finally:
                        await collector.close()
                        progress.advance(task)

            results = await asyncio.gather(*[_run_one(c) for c in instances])

        for name, findings in results:
            source_stats[name] = len(findings)
            all_raw.extend(findings)

        console.print(f"\n[bold]Total raw findings:[/bold] {len(all_raw)}")

        # Normalization
        console.print("[cyan]Normalizing findings...[/cyan]")
        normalizer = Normalizer(root_domain=self.target)
        nodes = normalizer.normalize(all_raw)
        console.print(f"  -> {len(nodes)} nodes after normalization")

        # Correlation
        console.print("[cyan]Correlating and deduplicating...[/cyan]")
        correlator = Correlator(root_domain=self.target, resolve_ips=self.resolve_ips)
        correlator.ingest(nodes)

        if self.resolve_ips:
            console.print("[cyan]Resolving IPs for discovered subdomains...[/cyan]")
            await asyncio.get_event_loop().run_in_executor(
                None, correlator.resolve_subdomain_ips
            )

        edges = correlator.build_edges()
        final_nodes = correlator.nodes

        type_counts = {}
        for n in final_nodes.values():
            type_counts[n.type] = type_counts.get(n.type, 0) + 1

        console.print(f"  -> {len(final_nodes)} unique nodes, {len(edges)} edges")

        # Build graph
        console.print("[cyan]Building NetworkX graph...[/cyan]")
        builder = GraphBuilder(root_domain=self.target)
        builder.build(final_nodes, edges)
        G = builder.graph

        # Export
        console.print("[cyan]Exporting graph...[/cyan]")
        exporter = GraphExporter(G, self.target, self.output_dir)
        graph_html_path = exporter.export_pyvis()
        graph_json_path = exporter.export_json()

        # Report
        console.print("[cyan]Generating HTML report...[/cyan]")
        elapsed = time.time() - start_time
        generator = ReportGenerator(
            target=self.target,
            nodes=final_nodes,
            edges=edges,
            source_stats=source_stats,
            type_counts=type_counts,
            graph_html_path=graph_html_path,
            output_dir=self.output_dir,
            elapsed=elapsed,
        )
        report_path = generator.generate()

        # Output summary
        table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")

        table.add_row("Target", self.target)
        table.add_row("Total Nodes", str(len(final_nodes)))
        table.add_row("Total Edges", str(len(edges)))
        for t, count in sorted(type_counts.items()):
            table.add_row(f"  {t.capitalize()}s", str(count))
        table.add_row("Sources Used", str(len(source_stats)))
        table.add_row("Elapsed Time", f"{elapsed:.1f}s")
        table.add_row("Report", str(report_path))
        table.add_row("Graph JSON", str(graph_json_path))

        console.print(table)
        console.rule("[bold green]Scan Complete[/bold green]")

        return {
            "target":       self.target,
            "nodes":        final_nodes,
            "edges":        edges,
            "type_counts":  type_counts,
            "source_stats": source_stats,
            "report_path":  str(report_path),
            "graph_json":   str(graph_json_path),
            "graph_html":   str(graph_html_path),
            "elapsed":      elapsed,
        }
