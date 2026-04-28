"""
GitHub search collector.
"""

import logging
import re
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from .base import BaseCollector

logger = logging.getLogger(__name__)
GITHUB_SEARCH_URL = "https://api.github.com/search/code"
SUBDOMAIN_RE = re.compile(
    r'([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*)',
    re.IGNORECASE
)


class GitHubCollector(BaseCollector):
    name = "github"
    description = "GitHub code search for domain leaks (requires GITHUB_TOKEN)"

    async def run(self, target: str) -> list[dict]:
        if not config.GITHUB_TOKEN:
            logger.info("[%s] No GITHUB_TOKEN set, skipping.", self.name)
            return []

        logger.info("[%s] Searching GitHub code for %s", self.name, target)
        headers = {
            "Authorization": f"token {config.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        }
        params = {"q": target, "per_page": "100"}
        data = await self._get_json(GITHUB_SEARCH_URL, params=params, headers=headers)

        if not data or "items" not in data:
            logger.warning("[%s] No GitHub results for %s", self.name, target)
            return []

        findings: list[dict] = []
        seen: set[str] = set()

        for item in data.get("items", []):
            repo_name    = item.get("repository", {}).get("full_name", "")
            html_url     = item.get("html_url", "")
            file_name    = item.get("name", "")
            file_path    = item.get("path", "")

            # Emit URL node for the GitHub file
            if html_url and html_url not in seen:
                seen.add(html_url)
                findings.append(self.make_finding(
                    node_type="url", value=html_url, source=self.name,
                    repo=repo_name, file=file_path,
                    leak_indicator=True,
                ))

        logger.info("[%s] Found %d GitHub code references for %s",
                    self.name, len(findings), target)
        return findings
