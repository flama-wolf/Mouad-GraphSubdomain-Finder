"""
CertSpotter collector.
"""

import logging
import re

from .base import BaseCollector

logger = logging.getLogger(__name__)

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"


class CertSpotterCollector(BaseCollector):
    name = "certspotter"
    description = "Certificate Transparency via CertSpotter API"

    _WILDCARD_RE = re.compile(r"^\*\.")

    async def run(self, target: str) -> list[dict]:
        logger.info("[%s] Querying CertSpotter for %s", self.name, target)

        params = {
            "domain": target,
            "include_subdomains": "true",
            "expand": "dns_names",
            "after": "",
        }

        data = await self._get_json(CERTSPOTTER_URL, params=params)
        if not data:
            logger.warning("[%s] No data returned for %s", self.name, target)
            return []

        findings: list[dict] = []
        seen: set[str] = set()

        for cert in data:
            dns_names  = cert.get("dns_names", [])
            not_before = cert.get("not_before", "")
            not_after  = cert.get("not_after", "")
            issuer     = cert.get("issuer", {})
            tbs_sha256 = cert.get("tbs_sha256", "")

            for name in dns_names:
                name = self._WILDCARD_RE.sub("", name.strip().lower())
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
                        not_before=not_before,
                        not_after=not_after,
                        issuer=issuer.get("organization", "") if isinstance(issuer, dict) else "",
                        cert_hash=tbs_sha256,
                    )
                )

        logger.info("[%s] Found %d entries for %s", self.name, len(findings), target)
        return findings
