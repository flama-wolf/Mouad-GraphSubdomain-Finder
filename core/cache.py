"""
Disk-backed JSON cache.
"""

import json
import hashlib
import time
import logging
from pathlib import Path
from typing import Optional, List

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger(__name__)


class Cache:
    """Simple disk-backed cache for collector results."""

    def __init__(self, cache_dir: Optional[Path] = None, ttl: Optional[int] = None):
        self._dir = Path(cache_dir or config.CACHE_DIR)
        self._ttl = ttl if ttl is not None else config.CACHE_TTL_SECONDS
        self._dir.mkdir(parents=True, exist_ok=True)

    def _key_path(self, collector: str, target: str) -> Path:
        raw_key = f"{collector}::{target}"
        hashed  = hashlib.sha256(raw_key.encode()).hexdigest()[:16]
        return self._dir / f"{collector}_{hashed}.json"

    def get(self, collector: str, target: str) -> Optional[List[dict]]:
        path = self._key_path(collector, target)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - data["timestamp"] > self._ttl:
                logger.debug("[cache] Expired: %s / %s", collector, target)
                path.unlink(missing_ok=True)
                return None
            logger.debug("[cache] HIT: %s / %s", collector, target)
            return data["findings"]
        except (json.JSONDecodeError, KeyError, OSError):
            return None

    def set(self, collector: str, target: str, findings: List[dict]) -> None:
        path = self._key_path(collector, target)
        payload = {"timestamp": time.time(), "findings": findings}
        try:
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            logger.debug("[cache] STORED: %s / %s (%d items)", collector, target, len(findings))
        except OSError as exc:
            logger.warning("[cache] Could not write cache file: %s", exc)

    def clear(self, collector: Optional[str] = None) -> int:
        """Remove cached entries. If collector is None, clears all. Returns count removed."""
        removed = 0
        pattern = f"{collector}_*.json" if collector else "*.json"
        for p in self._dir.glob(pattern):
            p.unlink(missing_ok=True)
            removed += 1
        logger.info("[cache] Cleared %d cache entries.", removed)
        return removed
