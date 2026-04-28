"""
Base collector class.
"""

import abc
import asyncio
import logging
from typing import Any, Optional

import aiohttp

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger(__name__)


class BaseCollector(abc.ABC):
    """Abstract base for every passive OSINT collector module."""

    name: str = "base"
    description: str = ""

    def __init__(self):
        self._session: aiohttp.ClientSession | None = None


    async def _get_session(self) -> aiohttp.ClientSession:  # type: ignore[return]
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=config.REQUEST_TIMEOUT)
            self._session = aiohttp.ClientSession(
                headers=config.DEFAULT_HEADERS,
                timeout=timeout,
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


    async def _get_json(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        retries: int = config.MAX_RETRIES,
    ) -> Any:
        """GET request with retry logic. Returns parsed JSON or None on failure."""
        session = await self._get_session()
        for attempt in range(1, retries + 1):
            try:
                async with session.get(url, params=params, headers=headers) as resp:
                    if resp.status == 429:
                        wait = 2 ** attempt
                        logger.warning(
                            "[%s] Rate limited. Waiting %ds (attempt %d/%d)",
                            self.name, wait, attempt, retries,
                        )
                        await asyncio.sleep(wait)
                        continue
                    if resp.status == 404:
                        return None
                    resp.raise_for_status()
                    return await resp.json(content_type=None)
            except aiohttp.ClientError as exc:
                logger.warning(
                    "[%s] HTTP error on attempt %d/%d: %s",
                    self.name, attempt, retries, exc,
                )
                if attempt < retries:
                    await asyncio.sleep(2 ** attempt)
        return None

    async def _get_text(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        retries: int = config.MAX_RETRIES,
    ) -> Optional[str]:
        """GET request returning plain text. Returns None on failure."""
        session = await self._get_session()
        for attempt in range(1, retries + 1):
            try:
                async with session.get(url, params=params, headers=headers) as resp:
                    if resp.status == 429:
                        wait = 2 ** attempt
                        logger.warning(
                            "[%s] Rate limited. Waiting %ds (attempt %d/%d)",
                            self.name, wait, attempt, retries,
                        )
                        await asyncio.sleep(wait)
                        continue
                    if resp.status == 404:
                        return None
                    resp.raise_for_status()
                    return await resp.text()
            except aiohttp.ClientError as exc:
                logger.warning(
                    "[%s] HTTP error on attempt %d/%d: %s",
                    self.name, attempt, retries, exc,
                )
                if attempt < retries:
                    await asyncio.sleep(2 ** attempt)
        return None


    @abc.abstractmethod
    async def run(self, target: str) -> list[dict]:
        """
        Run the collector against the target domain.

        Returns a list of finding dicts, each with at minimum:
          {"type": <node_type>, "value": <string>, "source": self.name}

        Node types: domain | subdomain | ip | url | email | cert
        """
        ...


    @staticmethod
    def make_finding(
        node_type: str,
        value: str,
        source: str,
        **metadata,
    ) -> dict:
        """Construct a normalized finding dict."""
        return {
            "type": node_type,
            "value": value.strip().lower(),
            "source": source,
            **metadata,
        }
