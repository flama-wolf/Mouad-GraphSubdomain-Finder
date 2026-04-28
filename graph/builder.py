"""
NetworkX graph builder.
"""

from __future__ import annotations

import logging
import networkx as nx

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from core.normalizer import Node
from core.correlator import Edge

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Constructs a NetworkX DiGraph from normalized nodes and edges."""

    def __init__(self, root_domain: str):
        self.root_domain = root_domain
        self._G: nx.DiGraph = nx.DiGraph(target=root_domain)

    def build(
        self,
        nodes: dict[str, Node],
        edges: list[Edge],
    ) -> nx.DiGraph:
        """Populate the graph and return it."""
        self._G.clear()
        self._G.graph["target"] = self.root_domain

        # Add nodes with all attributes
        for key, node in nodes.items():
            self._G.add_node(
                key,
                label=node.value,
                node_type=node.type,
                sources=node.sources,
                source_count=len(node.sources),
                **{k: str(v) for k, v in node.metadata.items()},
            )

        # Add edges
        for edge in edges:
            if edge.source in self._G and edge.target in self._G:
                self._G.add_edge(
                    edge.source,
                    edge.target,
                    relation=edge.relation,
                )
            else:
                logger.debug(
                    "[graph] Skipping edge %s → %s (node missing)",
                    edge.source, edge.target,
                )

        logger.info(
            "[graph] Built graph: %d nodes, %d edges",
            self._G.number_of_nodes(),
            self._G.number_of_edges(),
        )
        return self._G

    @property
    def graph(self) -> nx.DiGraph:
        return self._G

    def get_subdomains(self) -> list[str]:
        return [
            data["label"]
            for _, data in self._G.nodes(data=True)
            if data.get("node_type") == "subdomain"
        ]

    def get_ips(self) -> list[str]:
        return [
            data["label"]
            for _, data in self._G.nodes(data=True)
            if data.get("node_type") == "ip"
        ]

    def stats(self) -> dict:
        return {
            "nodes": self._G.number_of_nodes(),
            "edges": self._G.number_of_edges(),
            "density": nx.density(self._G),
            "components": nx.number_weakly_connected_components(self._G),
        }
