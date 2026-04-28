"""
Wayback Machine collector.
"""

import logging
import re
from urllib.parse import urlparse

from .base import BaseCollector

logger = logging.getLogger(__name__)

CDX_URL = "http://web.archive.org/cdx/search/cdx"


class GauCollector(BaseCollector):
    name = "wayback-cdx"
    description = "Subdomain discovery via Wayback Machine CDX API (URL aggregation)"

    async def run(self, target: str) -> list[dict]:
        logger.info("[%s] Querying Wayback CDX for *.%s", self.name, target)

        params = {
            "url": f"*.{target}",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": "50000",
        }

        data = await self._get_json(CDX_URL, params=params)
        if not data:
            logger.warning("[%s] No data returned for %s", self.name, target)
            return []

        findings: list[dict] = []
        seen_subdomains: set[str] = set()
        seen_urls: set[str] = set()

        # First row is header ["original"]
        for row in data[1:]:
            if not row:
                continue
            raw_url = row[0]

            try:
                parsed = urlparse(raw_url)
                hostname = parsed.hostname or ""
            except Exception:
                continue

            hostname = hostname.lower().strip()

            # Emit URL node
            if raw_url not in seen_urls:
                seen_urls.add(raw_url)
                findings.append(
                    self.make_finding(
                        node_type="url",
                        value=raw_url,
                        source=self.name,
                        hostname=hostname,
                    )
                )

            # Emit subdomain node
            if hostname and hostname.endswith(f".{target}") and hostname not in seen_subdomains:
                seen_subdomains.add(hostname)
                findings.append(
                    self.make_finding(
                        node_type="subdomain",
                        value=hostname,
                        source=self.name,
                    )
                )

        logger.info(
            "[%s] Found %d subdomains, %d URLs for %s",
            self.name, len(seen_subdomains), len(seen_urls), target,
        )
        return findings
