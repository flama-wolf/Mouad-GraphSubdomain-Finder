"""
CIRCL Passive DNS collector.
"""

import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

CIRCL_URL = "https://www.circl.lu/pdns/query"


class CirclPDNSCollector(BaseCollector):
    name = "circl-pdns"
    description = "CIRCL Passive DNS — passive DNS history (no key required)"

    async def run(self, target: str) -> list[dict]:
        url = f"{CIRCL_URL}/{target}"
        logger.info("[%s] Querying CIRCL PDNS for %s", self.name, target)

        # CIRCL returns newline-delimited JSON objects
        text = await self._get_text(url)
        if not text:
            logger.warning("[%s] No data returned for %s", self.name, target)
            return []

        findings: list[dict] = []
        seen_subdomains: set[str] = set()
        seen_ips: set[str] = set()

        import json

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            rrtype = record.get("rrtype", "").upper()
            rrname = record.get("rrname", "").rstrip(".").lower()
            rdata  = record.get("rdata", "").rstrip(".").lower()
            time_first = record.get("time_first", "")
            time_last  = record.get("time_last", "")

            # Subdomain from rrname
            if rrname and rrname.endswith(f".{target}") and rrname not in seen_subdomains:
                seen_subdomains.add(rrname)
                findings.append(
                    self.make_finding(
                        node_type="subdomain",
                        value=rrname,
                        source=self.name,
                        rrtype=rrtype,
                        time_first=time_first,
                        time_last=time_last,
                    )
                )

            # IP from A/AAAA records
            if rrtype in ("A", "AAAA") and rdata:
                if rdata not in seen_ips:
                    seen_ips.add(rdata)
                    findings.append(
                        self.make_finding(
                            node_type="ip",
                            value=rdata,
                            source=self.name,
                            rrtype=rrtype,
                            resolved_from=rrname,
                        )
                    )

        logger.info(
            "[%s] Found %d subdomains, %d IPs for %s",
            self.name, len(seen_subdomains), len(seen_ips), target,
        )
        return findings
