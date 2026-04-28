"""
HackerTarget collector.
"""

import logging

from .base import BaseCollector

logger = logging.getLogger(__name__)

HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"


class HackerTargetCollector(BaseCollector):
    name = "hackertarget"
    description = "HackerTarget DNS host search (free, no key)"

    async def run(self, target: str) -> list[dict]:
        logger.info("[%s] Querying HackerTarget for %s", self.name, target)

        text = await self._get_text(HACKERTARGET_URL, params={"q": target})
        if not text:
            logger.warning("[%s] No data returned for %s", self.name, target)
            return []

        # API error responses start with "error" or "API count exceeded"
        if text.lower().startswith("error") or "api count exceeded" in text.lower():
            logger.warning("[%s] API limit reached: %s", self.name, text.strip())
            return []

        findings: list[dict] = []
        seen_subs: set[str] = set()
        seen_ips:  set[str] = set()

        for line in text.splitlines():
            line = line.strip()
            if not line or "," not in line:
                continue
            parts = line.split(",", 1)
            hostname = parts[0].strip().lower()
            ip       = parts[1].strip() if len(parts) > 1 else ""

            if hostname and hostname.endswith(f".{target}") and hostname not in seen_subs:
                seen_subs.add(hostname)
                findings.append(
                    self.make_finding(
                        node_type="subdomain",
                        value=hostname,
                        source=self.name,
                        ip=ip,
                    )
                )

            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                findings.append(
                    self.make_finding(
                        node_type="ip",
                        value=ip,
                        source=self.name,
                        resolved_from=hostname,
                    )
                )

        logger.info(
            "[%s] Found %d subdomains, %d IPs for %s",
            self.name, len(seen_subs), len(seen_ips), target,
        )
        return findings
