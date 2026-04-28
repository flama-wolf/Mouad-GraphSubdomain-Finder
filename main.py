"""
Main entry point.
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

# Setup logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
)
logger = logging.getLogger(__name__)

console = Console()

# Collectors
from collectors.crtsh        import CrtShCollector
from collectors.gau          import GauCollector
from collectors.passive_dns  import CirclPDNSCollector
from collectors.certspotter  import CertSpotterCollector
from collectors.hackertarget import HackerTargetCollector
from collectors.otx          import OTXCollector
from collectors.urlscan      import UrlScanCollector
from collectors.github_search import GitHubCollector

COLLECTOR_MAP = {
    "crtsh":       CrtShCollector,
    "gau":         GauCollector,
    "passive_dns": CirclPDNSCollector,
    "certspotter": CertSpotterCollector,
    "hackertarget":HackerTargetCollector,
    "otx":         OTXCollector,
    "urlscan":     UrlScanCollector,
    "github":      GitHubCollector,
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="mouad-finder",
        description="Mouad-Subdomain finder passive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py tesla.com
  python main.py github.com --no-resolve
  python main.py example.com --collectors crtsh gau passive_dns
  python main.py target.com --verbose --no-cache
        """,
    )

    parser.add_argument("domain", help="Target domain (e.g. example.com)")

    parser.add_argument(
        "--collectors", "-c",
        nargs="+",
        choices=list(COLLECTOR_MAP.keys()),
        metavar="COLLECTOR",
        help=f"Specific collectors to run (default: all). Choices: {', '.join(COLLECTOR_MAP)}",
    )

    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="Skip DNS resolution of discovered subdomains",
    )

    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable caching (always fetch fresh data)",
    )

    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output directory for reports (default: ./output/)",
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose debug logging",
    )

    parser.add_argument(
        "--list-collectors",
        action="store_true",
        help="List all available collectors and exit",
    )

    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear the cache and exit",
    )

    return parser.parse_args()


async def main_async(args):
    from core.pipeline import Pipeline

    collectors = None
    if args.collectors:
        collectors = [COLLECTOR_MAP[c] for c in args.collectors]

    pipeline = Pipeline(
        target=args.domain,
        collectors=collectors,
        resolve_ips=not args.no_resolve,
        use_cache=not args.no_cache,
        output_dir=args.output,
    )

    result = await pipeline.run()

    console.print(f"\n[bold green]Report:[/bold green] {result['report_path']}")
    return result


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("collectors").setLevel(logging.DEBUG)
        logging.getLogger("core").setLevel(logging.DEBUG)
        logging.getLogger("graph").setLevel(logging.DEBUG)

    if args.list_collectors:
        console.print("\n[bold]Available collectors:[/bold]")
        for name, cls in COLLECTOR_MAP.items():
            c = cls()
            console.print(f"  [cyan]{name:<15}[/cyan] {c.description}")
        return

    if args.clear_cache:
        from core.cache import Cache
        removed = Cache().clear()
        console.print(f"[green]Cleared {removed} cache entries.[/green]")
        return

    if not args.domain:
        console.print("[red]Error: domain argument is required.[/red]")
        sys.exit(1)

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(0)


if __name__ == "__main__":
    main()
