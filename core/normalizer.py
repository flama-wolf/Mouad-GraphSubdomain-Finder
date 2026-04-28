"""
Normalizes raw data into Node objects.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional, List, Tuple, Dict

import tldextract

logger = logging.getLogger(__name__)

# Basic IP pattern for fast validation
_IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
    r'|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
)

VALID_TYPES = {"domain", "subdomain", "ip", "url", "email", "cert", "unknown"}


@dataclass
class Node:
    """OSINT graph node."""
    type:     str                     # domain | subdomain | ip | url | email | cert
    value:    str                     # canonical lowercase value
    sources:  List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash((self.type, self.value))

    def __eq__(self, other):
        return isinstance(other, Node) and self.type == other.type and self.value == other.value

    def add_source(self, source: str):
        if source not in self.sources:
            self.sources.append(source)

    def merge_metadata(self, extra: dict):
        for k, v in extra.items():
            if k not in ("type", "value", "source") and v:
                # Don't overwrite existing non-empty values
                if k not in self.metadata or not self.metadata[k]:
                    self.metadata[k] = v


class Normalizer:
    """
    Converts raw dicts into Node objects.
    """

    def __init__(self, root_domain: str):
        self.root_domain = root_domain.lower().strip()
        ext = tldextract.extract(self.root_domain)
        self.registered_domain = f"{ext.domain}.{ext.suffix}"

    def normalize(self, findings: list[dict]) -> list[Node]:
        nodes: list[Node] = []
        for raw in findings:
            node = self._normalize_one(raw)
            if node:
                nodes.append(node)
        return nodes

    def _normalize_one(self, raw: dict) -> Optional[Node]:
        raw_type  = raw.get("type", "unknown").lower().strip()
        raw_value = raw.get("value", "").strip()
        source    = raw.get("source", "unknown")

        if not raw_value:
            return None

        # Validate and clean based on type
        node_type, value = self._classify(raw_type, raw_value)

        if not value:
            return None

        meta = {k: v for k, v in raw.items() if k not in ("type", "value", "source") and v}

        node = Node(type=node_type, value=value, sources=[source], metadata=meta)
        return node

    def _classify(self, raw_type: str, raw_value: str) -> Tuple[str, str]:
        """Returns (canonical_type, canonical_value)."""
        v = raw_value.lower().strip().rstrip(".")

        if raw_type == "ip" or _IP_RE.match(v):
            return ("ip", v)

        if raw_type == "url" or v.startswith(("http://", "https://")):
            return ("url", v)

        if raw_type == "email" or "@" in v:
            return ("email", v)

        if raw_type in ("domain", "subdomain"):
            # Validate it's actually a subdomain of root
            if v == self.registered_domain or v == self.root_domain:
                return ("domain", v)
            if v.endswith(f".{self.registered_domain}"):
                return ("subdomain", v)
            # Could be an out-of-scope domain — skip
            return ("unknown", "")

        return (raw_type if raw_type in VALID_TYPES else "unknown", v)
