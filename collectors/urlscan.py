"""
urlscan.io collector.
"""

import logging
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from .base import BaseCollector

logger = logging.getLogger(__name__)
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"


class UrlScanCollector(BaseCollector):
    name = "urlscan"
    description = "urlscan.io subdomain and URL discovery"

    async def run(self, target: str) -> list[dict]:
        logger.info("[%s] Querying urlscan.io for %s", self.name, target)
        headers: dict = {}
        if config.URLSCAN_API_KEY:
            headers["API-Key"] = config.URLSCAN_API_KEY

        params = {"q": f"domain:{target}", "size": "1000"}
        data = await self._get_json(URLSCAN_SEARCH, params=params, headers=headers)

        if not data or "results" not in data:
            logger.warning("[%s] No results for %s", self.name, target)
            return []

        findings: list[dict] = []
        seen_subs: set[str] = set()
        seen_urls: set[str] = set()

        for result in data["results"]:
            page = result.get("page", {})
            task = result.get("task", {})
            hostname = page.get("domain", "").lower().strip()
            url_val  = task.get("url", "")
            ip       = page.get("ip", "")
            country  = page.get("country", "")
            server   = page.get("server", "")

            if hostname and hostname.endswith(f".{target}") and hostname not in seen_subs:
                seen_subs.add(hostname)
                findings.append(self.make_finding(
                    node_type="subdomain", value=hostname, source=self.name,
                    ip=ip, country=country, server=server,
                ))

            if url_val and url_val not in seen_urls:
                seen_urls.add(url_val)
                findings.append(self.make_finding(
                    node_type="url", value=url_val, source=self.name,
                    hostname=hostname,
                ))

            if ip and ip not in seen_subs:
                findings.append(self.make_finding(
                    node_type="ip", value=ip, source=self.name,
                    country=country, resolved_from=hostname,
                ))

        logger.info("[%s] Found %d subdomains for %s", self.name, len(seen_subs), target)
        return findings
