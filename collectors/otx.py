"""
AlienVault OTX collector.
"""

import logging
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from .base import BaseCollector

logger = logging.getLogger(__name__)
OTX_BASE = "https://otx.alienvault.com/api/v1/indicators/domain"


class OTXCollector(BaseCollector):
    name = "otx"
    description = "AlienVault OTX Passive DNS"

    async def run(self, target: str) -> list[dict]:
        url = f"{OTX_BASE}/{target}/passive_dns"
        headers: dict = {}
        if config.OTX_API_KEY:
            headers["X-OTX-API-KEY"] = config.OTX_API_KEY

        logger.info("[%s] Querying OTX passive DNS for %s", self.name, target)
        data = await self._get_json(url, headers=headers)

        if not data or "passive_dns" not in data:
            logger.warning("[%s] No passive DNS data returned for %s", self.name, target)
            return []

        findings: list[dict] = []
        seen_subs: set[str] = set()
        seen_ips:  set[str] = set()

        for record in data["passive_dns"]:
            hostname    = record.get("hostname", "").lower().strip()
            address     = record.get("address", "").lower().strip()
            record_type = record.get("record_type", "")
            first_seen  = record.get("first", "")
            last_seen   = record.get("last", "")

            if hostname and hostname.endswith(f".{target}") and hostname not in seen_subs:
                seen_subs.add(hostname)
                findings.append(self.make_finding(
                    node_type="subdomain", value=hostname, source=self.name,
                    record_type=record_type, first_seen=first_seen, last_seen=last_seen,
                ))

            if address and record_type in ("A", "AAAA") and address not in seen_ips:
                seen_ips.add(address)
                findings.append(self.make_finding(
                    node_type="ip", value=address, source=self.name,
                    resolved_from=hostname,
                ))

        logger.info("[%s] Found %d subdomains, %d IPs for %s",
                    self.name, len(seen_subs), len(seen_ips), target)
        return findings
