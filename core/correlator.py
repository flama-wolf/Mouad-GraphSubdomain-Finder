"""
Deduplication and relationship generation.
"""

from __future__ import annotations

import logging
import socket
from typing import NamedTuple

from .normalizer import Node

logger = logging.getLogger(__name__)


class Edge(NamedTuple):
    source: str      # node key: "type:value"
    target: str      # node key: "type:value"
    relation: str    # e.g. HAS_SUBDOMAIN, RESOLVES_TO, HAS_URL


def node_key(node: Node) -> str:
    return f"{node.type}:{node.value}"


class Correlator:
    """
    Deduplicates nodes and generates edges.
    """

    def __init__(self, root_domain: str, resolve_ips: bool = True):
        self.root_domain   = root_domain.lower().strip()
        self.resolve_ips   = resolve_ips
        self._nodes: dict[str, Node] = {}
        self._edges: list[Edge] = []


    def ingest(self, nodes: list[Node]) -> None:
        """Merge a list of nodes into the registry."""
        for node in nodes:
            key = node_key(node)
            if key in self._nodes:
                existing = self._nodes[key]
                for src in node.sources:
                    existing.add_source(src)
                existing.merge_metadata(node.metadata)
            else:
                self._nodes[key] = node

    def build_edges(self) -> list[Edge]:
        """Generate edges based on node types and relationships."""
        self._edges.clear()
        domain_key = f"domain:{self.root_domain}"

        for key, node in self._nodes.items():

            if node.type == "subdomain":
                # domain → subdomain
                self._add_edge(domain_key, key, "HAS_SUBDOMAIN")

                # subdomain → ip (from metadata)
                ip_val = node.metadata.get("ip", "")
                if ip_val:
                    ip_key = f"ip:{ip_val}"
                    if ip_key in self._nodes:
                        self._add_edge(key, ip_key, "RESOLVES_TO")

            elif node.type == "ip":
                # subdomain → ip (resolved_from metadata)
                resolved_from = node.metadata.get("resolved_from", "")
                if resolved_from:
                    sub_key = f"subdomain:{resolved_from}"
                    if sub_key in self._nodes:
                        self._add_edge(sub_key, key, "RESOLVES_TO")

            elif node.type == "url":
                # url → subdomain (hostname metadata)
                hostname = node.metadata.get("hostname", "")
                if hostname:
                    sub_key = f"subdomain:{hostname}"
                    if sub_key in self._nodes:
                        self._add_edge(key, sub_key, "BELONGS_TO")
                    else:
                        # url → domain
                        self._add_edge(key, domain_key, "BELONGS_TO")

            elif node.type == "email":
                # domain → email
                self._add_edge(domain_key, key, "HAS_EMAIL")

        return list(self._edges)

    def resolve_subdomain_ips(self) -> None:
        """
        Attempt passive-like DNS resolution for subdomains that have no IP.
        Uses socket.getaddrinfo (blocks briefly — intended for enrichment pass).
        """
        if not self.resolve_ips:
            return

        for key, node in list(self._nodes.items()):
            if node.type != "subdomain":
                continue
            if node.metadata.get("ip"):
                continue

            try:
                infos = socket.getaddrinfo(node.value, None, proto=socket.IPPROTO_TCP)
                ips = list({info[4][0] for info in infos})
                if ips:
                    ip_val = ips[0]
                    node.metadata["ip"] = ip_val
                    ip_node = Node(
                        type="ip",
                        value=ip_val,
                        sources=["dns-resolve"],
                        metadata={"resolved_from": node.value},
                    )
                    ip_key = node_key(ip_node)
                    if ip_key not in self._nodes:
                        self._nodes[ip_key] = ip_node
                    else:
                        self._nodes[ip_key].add_source("dns-resolve")
            except (socket.gaierror, OSError):
                pass

    @property
    def nodes(self) -> dict[str, Node]:
        return self._nodes

    @property
    def edges(self) -> list[Edge]:
        return self._edges


    def _add_edge(self, src: str, tgt: str, relation: str) -> None:
        edge = Edge(source=src, target=tgt, relation=relation)
        if edge not in self._edges:
            self._edges.append(edge)
