"""
crt.sh collector.
"""

import logging
import re

from .base import BaseCollector

logger = logging.getLogger(__name__)


class CrtShCollector(BaseCollector):
    name = "crt.sh"
    description = "Certificate Transparency logs via crt.sh"

    _WILDCARD_RE = re.compile(r"^\*\.")

    async def run(self, target: str) -> list[dict]:
        url = "https://crt.sh/"
        params = {"q": f"%.{target}", "output": "json"}

        logger.info("[%s] Querying CT logs for *.%s", self.name, target)
        data = await self._get_json(url, params=params)

        if not data:
            logger.warning("[%s] No data returned for %s", self.name, target)
            return []

        findings: list[dict] = []
        seen: set[str] = set()

        for entry in data:
            # name_value can contain newline-separated SANs
            name_value = entry.get("name_value", "")
            issuer = entry.get("issuer_name", "")
            serial = entry.get("serial_number", "")
            not_before = entry.get("not_before", "")
            not_after = entry.get("not_after", "")

            for name in name_value.splitlines():
                name = name.strip().lower()
                # Strip wildcard prefix
                name = self._WILDCARD_RE.sub("", name)
                if not name or name in seen:
                    continue
                if not name.endswith(f".{target}") and name != target:
                    continue

                seen.add(name)

                node_type = "subdomain" if name != target else "domain"
                findings.append(
                    self.make_finding(
                        node_type=node_type,
                        value=name,
                        source=self.name,
                        issuer=issuer,
                        serial=serial,
                        not_before=not_before,
                        not_after=not_after,
                    )
                )

        logger.info("[%s] Found %d unique entries for %s", self.name, len(findings), target)
        return findings
